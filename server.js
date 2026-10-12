'use strict';

const express = require('express');
const multer = require('multer');
const http = require('node:http');
const crypto = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs');
const { DatabaseSync } = require('node:sqlite');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = Number(process.env.PORT || 3011);
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'tawasul.db');
const PAYMENT_EXEMPT_USER_ID = process.env.PAYMENT_EXEMPT_USER_ID || 'ABQ-4085029FADFB';
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new DatabaseSync(DB_PATH);

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS private_requests (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    payment_ref TEXT NOT NULL,
    fee INTEGER NOT NULL DEFAULT 200,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS private_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL REFERENCES private_requests(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
`);
const userColumns = db.prepare('PRAGMA table_info(users)').all().map(c => c.name);
if (!userColumns.includes('role')) {
  db.exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'client'");
}
const requestColumns = db.prepare('PRAGMA table_info(private_requests)').all().map(c => c.name);
if (!requestColumns.includes('lawyer_id')) {
  db.exec('ALTER TABLE private_requests ADD COLUMN lawyer_id TEXT REFERENCES users(id)');
}

app.use(express.json({ limit: '32kb' }));

const RECEIPT_DIR = path.join(__dirname, 'data', 'payment-receipts');
fs.mkdirSync(RECEIPT_DIR, { recursive: true });

const PRIVATE_FILE_DIR = path.join(__dirname, 'data', 'private-files');
fs.mkdirSync(PRIVATE_FILE_DIR, { recursive: true });

const privateColumns = db.prepare('PRAGMA table_info(private_requests)').all().map(c => c.name);
if (!privateColumns.includes('receipt_path')) {
  db.exec('ALTER TABLE private_requests ADD COLUMN receipt_path TEXT');
}

const privateMessageColumns = db.prepare('PRAGMA table_info(private_messages)').all().map(c => c.name);
const privateMessageMigrations = {
  message_type: "TEXT NOT NULL DEFAULT 'text'",
  attachment_id: 'TEXT',
  original_name: 'TEXT',
  mime_type: 'TEXT',
  file_size: 'INTEGER',
  stored_name: 'TEXT'
};
for (const [column, definition] of Object.entries(privateMessageMigrations)) {
  if (!privateMessageColumns.includes(column)) {
    db.exec('ALTER TABLE private_messages ADD COLUMN ' + column + ' ' + definition);
  }
}

const receiptUpload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, RECEIPT_DIR),
    filename: (_req, file, cb) => cb(null, crypto.randomUUID() + path.extname(file.originalname).toLowerCase())
  }),
  limits: { fileSize: 5 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const allowed = {
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.png': 'image/png',
      '.webp': 'image/webp',
      '.pdf': 'application/pdf'
    };
    if (!allowed[ext] || allowed[ext] !== file.mimetype) {
      return cb(new Error('يسمح فقط بملفات JPG وPNG وWEBP وPDF'));
    }
    cb(null, true);
  }
});

const privateUpload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, PRIVATE_FILE_DIR),
    filename: (_req, file, cb) => cb(null, crypto.randomUUID() + path.extname(file.originalname).toLowerCase())
  }),
  limits: { fileSize: 20 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const allowed = {
      '.jpg': ['image/jpeg'], '.jpeg': ['image/jpeg'],
      '.png': ['image/png'], '.webp': ['image/webp'], '.gif': ['image/gif'],
      '.pdf': ['application/pdf'], '.txt': ['text/plain'], '.csv': ['text/csv', 'application/vnd.ms-excel'],
      '.doc': ['application/msword'],
      '.docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
      '.xls': ['application/vnd.ms-excel'],
      '.xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
      '.ppt': ['application/vnd.ms-powerpoint'],
      '.pptx': ['application/vnd.openxmlformats-officedocument.presentationml.presentation'],
      '.zip': ['application/zip', 'application/x-zip-compressed'],
      '.mp3': ['audio/mpeg'], '.wav': ['audio/wav', 'audio/x-wav'],
      '.ogg': ['audio/ogg', 'application/ogg'], '.m4a': ['audio/mp4'],
      '.webm': ['audio/webm', 'video/webm'],
      '.mp4': ['video/mp4'], '.mov': ['video/quicktime']
    };
    if (!allowed[ext] || !allowed[ext].includes(file.mimetype)) {
      return cb(new Error('نوع الملف غير مسموح به'));
    }
    cb(null, true);
  }
});

function handleReceiptUpload(req, res, next) {
  receiptUpload.single('receipt')(req, res, err => {
    if (!err) return next();
    const tooLarge = err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE';
    return res.status(tooLarge ? 413 : 400).json({
      error: tooLarge ? 'حجم الإيصال يجب ألا يتجاوز 5 ميجابايت' :
        (err.message || 'تعذر رفع الإيصال')
    });
  });
}

app.use(express.static(path.join(__dirname, 'public')));

const hash = value =>
  crypto.createHash('sha256').update(value).digest('hex');

function getUser(token) {
  if (!token || typeof token !== 'string' || token.length > 200) return null;
  return db.prepare(
    'SELECT id, name, role FROM users WHERE token_hash = ?'
  ).get(hash(token)) || null;
}

function auth(req, res, next) {
  const header = req.get('authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  const user = getUser(token);
  if (!user) return res.status(401).json({ error: 'سجّل الدخول أولًا' });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'هذه الوظيفة متاحة للإدارة فقط' });
  }
  next();
}

app.post('/api/register', (req, res) => {
  const name = String(req.body?.name || '').trim();
  if (name.length < 3 || name.length > 100) {
    return res.status(400).json({ error: 'أدخل الاسم الكامل (3 إلى 100 حرف)' });
  }

  const id = 'ABQ-' + crypto.randomBytes(6).toString('hex').toUpperCase();
  const token = crypto.randomBytes(32).toString('hex');

  db.prepare(`
    INSERT INTO users (id, name, token_hash, created_at)
    VALUES (?, ?, ?, ?)
  `).run(id, name, hash(token), new Date().toISOString());

  res.json({ id, name, token });
});

app.get('/api/me', auth, (req, res) => {
  res.json({ user: req.user });
});

app.get('/api/messages', auth, (req, res) => {
  const messages = db.prepare(`
    SELECT id, user_id AS userId, name, body, created_at AS createdAt
    FROM messages ORDER BY id DESC LIMIT 100
  `).all().reverse();
  res.json({ messages });
});

app.post('/api/messages', auth, (req, res) => {
  const body = String(req.body?.body || '').trim();
  if (!body || body.length > 2000) {
    return res.status(400).json({ error: 'الرسالة مطلوبة وبحد أقصى 2000 حرف' });
  }

  const result = db.prepare(`
    INSERT INTO messages (user_id, name, body, created_at)
    VALUES (?, ?, ?, ?)
  `).run(req.user.id, req.user.name, body, new Date().toISOString());

  const message = db.prepare(`
    SELECT id, user_id AS userId, name, body, created_at AS createdAt
    FROM messages WHERE id = ?
  `).get(Number(result.lastInsertRowid));

  io.emit('public:message', message);
  res.json({ message });
});

app.post('/api/private/request', auth, handleReceiptUpload, (req, res) => {
  if (req.user.id === PAYMENT_EXEMPT_USER_ID) {
    const id = crypto.randomUUID();
    db.prepare(`
      INSERT INTO private_requests
        (id, user_id, payment_ref, fee, status, created_at, receipt_path)
      VALUES (?, ?, ?, 0, 'approved', ?, NULL)
    `).run(id, req.user.id, 'EXEMPT-ACCOUNT', new Date().toISOString());
    return res.status(201).json({
      id, status: 'approved', exempt: true,
      message: 'هذا الحساب معفى من الرسوم؛ لا يلزم دفع أو رفع إيصال.'
    });
  }
  const paymentRef = String(req.body?.paymentRef || '').trim();
  if (paymentRef.length < 3 || paymentRef.length > 200) {
    if (req.file) fs.unlink(req.file.path, () => {});
    return res.status(400).json({ error: 'أدخل مرجع التحويل أو رقمه' });
  }
  if (!req.file) {
    return res.status(400).json({ error: 'أرفق صورة أو ملف PDF لإيصال التحويل' });
  }

  const id = crypto.randomUUID();
  try {
    db.prepare(`
      INSERT INTO private_requests
        (id, user_id, payment_ref, fee, status, created_at, receipt_path)
      VALUES (?, ?, ?, 200, 'pending', ?, ?)
    `).run(id, req.user.id, paymentRef, new Date().toISOString(), path.basename(req.file.filename));

    res.status(201).json({
      id,
      status: 'pending',
      message: 'تم تسجيل الطلب وإرفاق الإيصال. الغرفة الخاصة مغلقة حتى مراجعة الدفع.'
    });
  } catch (err) {
    fs.unlink(req.file.path, () => {});
    console.error('private request insert failed:', err.message);
    res.status(500).json({ error: 'تعذر تسجيل الطلب؛ حاول مرة أخرى' });
  }
});

app.get('/api/private/status', auth, (req, res) => {
  if (req.user.id === PAYMENT_EXEMPT_USER_ID) {
    let request = db.prepare(`
      SELECT id, fee, status, created_at AS createdAt
      FROM private_requests
      WHERE user_id = ? AND status = 'approved'
      ORDER BY created_at DESC LIMIT 1
    `).get(req.user.id);

    if (!request) {
      const id = crypto.randomUUID();
      const createdAt = new Date().toISOString();
      db.prepare(`
        INSERT INTO private_requests
          (id, user_id, payment_ref, fee, status, created_at, receipt_path)
        VALUES (?, ?, 'EXEMPT-ACCOUNT', 0, 'approved', ?, NULL)
      `).run(id, req.user.id, createdAt);
      request = { id, fee: 0, status: 'approved', createdAt };
    }
    return res.json({ request: { ...request, exempt: true } });
  }
  const request = db.prepare(`
    SELECT id, fee, status, created_at AS createdAt
    FROM private_requests
    WHERE user_id = ?
    ORDER BY created_at DESC LIMIT 1
  `).get(req.user.id);
  res.json({ request: request || null });
});

// واجهات الإدارة: تتطلب تسجيل الدخول ودور admin المحفوظ في قاعدة البيانات.
app.get('/api/admin/users', auth, requireAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT id, name, role, created_at AS createdAt
    FROM users ORDER BY created_at DESC LIMIT 500
  `).all();
  res.json({ users });
});

app.post('/api/admin/users/:id/role', auth, requireAdmin, (req, res) => {
  const role = String(req.body?.role || '');
  if (!['client', 'lawyer'].includes(role)) {
    return res.status(400).json({ error: 'الدور المطلوب غير صالح' });
  }
  const result = db.prepare(`
    UPDATE users SET role = ?
    WHERE id = ? AND role != 'admin'
  `).run(role, req.params.id);
  if (!result.changes) {
    return res.status(404).json({ error: 'الحساب غير موجود أو لا يمكن تغيير دوره' });
  }
  res.json({ ok: true, id: req.params.id, role });
});

app.get('/api/admin/private-requests', auth, requireAdmin, (req, res) => {
  const requests = db.prepare(`
    SELECT r.id, r.user_id AS userId, u.name AS clientName,
           r.payment_ref AS paymentRef, r.fee, r.status,
           r.created_at AS createdAt, r.lawyer_id AS lawyerId,
           l.name AS lawyerName,
           CASE WHEN r.receipt_path IS NULL THEN 0 ELSE 1 END AS hasReceipt
    FROM private_requests r
    JOIN users u ON u.id = r.user_id
    LEFT JOIN users l ON l.id = r.lawyer_id
    ORDER BY r.created_at DESC LIMIT 300
  `).all();
  res.json({ requests });
});

app.get('/api/admin/private/:id/receipt', auth, requireAdmin, (req, res) => {
  const request = db.prepare(
    'SELECT receipt_path FROM private_requests WHERE id = ?'
  ).get(req.params.id);
  if (!request || !request.receipt_path) {
    return res.status(404).json({ error: 'إيصال الدفع غير موجود' });
  }
  const filePath = path.join(RECEIPT_DIR, path.basename(request.receipt_path));
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'ملف الإيصال غير موجود على الخادم' });
  }
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.download(filePath, path.basename(filePath));
});

app.post('/api/admin/private/:id/approve', auth, requireAdmin, (req, res) => {
  const result = db.prepare(`
    UPDATE private_requests SET status = 'approved'
    WHERE id = ? AND status = 'pending'
  `).run(req.params.id);
  if (!result.changes) {
    return res.status(404).json({ error: 'الطلب غير موجود أو تمت مراجعته' });
  }
  res.json({ status: 'approved' });
});

app.post('/api/admin/private/:id/assign', auth, requireAdmin, (req, res) => {
  const lawyerId = String(req.body?.lawyerId || '');
  const lawyer = db.prepare(
    "SELECT id FROM users WHERE id = ? AND role = 'lawyer'"
  ).get(lawyerId);
  if (!lawyer) {
    return res.status(400).json({ error: 'اختر حساب محامٍ معتمدًا' });
  }
  const result = db.prepare(`
    UPDATE private_requests SET lawyer_id = ?
    WHERE id = ? AND status = 'approved'
  `).run(lawyerId, req.params.id);
  if (!result.changes) {
    return res.status(404).json({ error: 'الطلب غير موجود أو لم يُعتمد بعد' });
  }
  res.json({ ok: true, lawyerId });
});


app.get('/api/lawyer/requests', auth, (req, res) => {
  if (req.user.role !== 'lawyer') {
    return res.status(403).json({ error: 'هذه الوظيفة للمحامين المعتمدين فقط' });
  }
  const requests = db.prepare(`
    SELECT r.id, r.user_id AS userId, u.name AS clientName,
           r.created_at AS createdAt, r.status
    FROM private_requests r
    JOIN users u ON u.id = r.user_id
    WHERE r.lawyer_id = ? AND r.status = 'approved'
    ORDER BY r.created_at DESC LIMIT 200
  `).all(req.user.id);
  res.json({ requests });
});

io.use((socket, next) => {
  const user = getUser(socket.handshake.auth?.token);
  if (!user) return next(new Error('يلزم تسجيل الدخول'));
  socket.user = user;
  next();
});

io.on('connection', socket => {
  socket.emit('session:ready', { userId: socket.user.id });

  socket.on('private:join', async requestId => {
    const request = approvedPrivateRequest(socket.user.id, requestId);
    if (!request) {
      socket.emit('private:error', {
        error: 'الغرفة غير متاحة قبل اعتماد الطلب'
      });
      return;
    }
    const room = 'private:' + request.id;
    const existing = await io.in(room).fetchSockets();
    const peers = existing
      .filter(peer => peer.id !== socket.id)
      .map(peer => ({ userId: peer.user.id }));
    socket.join(room);
    socket.emit('private:peers', peers);
    socket.to(room).emit('private:peer-joined', { userId: socket.user.id });
    socket.emit('private:joined', { requestId: request.id });
  });

  const relayPrivateRTC = (event, payload, maxLength) => {
    if (!payload || typeof payload.requestId !== 'string') return;
    const request = approvedPrivateRequest(socket.user.id, payload.requestId);
    const room = request && ('private:' + request.id);
    if (!request || !socket.rooms.has(room)) return;
    const value = payload.description ?? payload.candidate;
    if (typeof value !== 'object' || value === null) return;
    let encoded;
    try { encoded = JSON.stringify(value); } catch { return; }
    if (encoded.length > maxLength) return;
    socket.to(room).emit(event, { requestId: request.id, [payload.description ? 'description' : 'candidate']: value });
  };

  socket.on('private:rtc-offer', p => relayPrivateRTC('private:rtc-offer', p, 200000));
  socket.on('private:rtc-answer', p => relayPrivateRTC('private:rtc-answer', p, 200000));
  socket.on('private:rtc-ice', p => relayPrivateRTC('private:rtc-ice', p, 12000));
  socket.on('private:rtc-end', p => {
    if (!p || typeof p.requestId !== 'string') return;
    const r = approvedPrivateRequest(socket.user.id, p.requestId);
    if (r && socket.rooms.has('private:' + r.id))
      socket.to('private:' + r.id).emit('private:rtc-end', { requestId: r.id });
  });
  socket.on('disconnecting', () => {
    for (const room of socket.rooms) {
      if (room.startsWith('private:')) {
        socket.to(room).emit('private:peer-left', { userId: socket.user.id });
      }
    }
  });
});

function approvedPrivateRequest(userId, requestId) {
  if (typeof requestId !== 'string' || !requestId || requestId.length > 100) {
    return null;
  }
  return db.prepare(`
    SELECT r.id, r.user_id AS userId, r.lawyer_id AS lawyerId, r.status
    FROM private_requests r
    JOIN users u ON u.id = ?
    WHERE r.id = ? AND r.status = 'approved'
      AND (r.user_id = ? OR (u.role = 'lawyer' AND r.lawyer_id = u.id))
  `).get(userId, requestId, userId) || null;
}

app.get('/api/private/messages', auth, (req, res) => {
  const request = approvedPrivateRequest(req.user.id, req.query.requestId);
  if (!request) {
    return res.status(403).json({ error: 'الغرفة غير متاحة قبل اعتماد الطلب' });
  }
  const messages = db.prepare(`
    SELECT id, user_id AS userId, name, body, created_at AS createdAt,
           message_type AS messageType, attachment_id AS attachmentId,
           original_name AS originalName, mime_type AS mimeType,
           file_size AS fileSize
    FROM private_messages
    WHERE request_id = ?
    ORDER BY id DESC LIMIT 200
  `).all(request.id).reverse();
  res.json({ messages });
});

app.post('/api/private/messages', auth, (req, res) => {
  const request = approvedPrivateRequest(req.user.id, req.body?.requestId);
  if (!request) {
    return res.status(403).json({ error: 'الغرفة غير متاحة قبل اعتماد الطلب' });
  }
  const body = String(req.body?.body || '').trim();
  if (!body || body.length > 2000) {
    return res.status(400).json({ error: 'الرسالة مطلوبة وبحد أقصى 2000 حرف' });
  }

  const result = db.prepare(`
    INSERT INTO private_messages
      (request_id, user_id, name, body, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(
    request.id, req.user.id, req.user.name, body, new Date().toISOString()
  );

  const saved = db.prepare(`
    SELECT id, user_id AS userId, name, body, created_at AS createdAt,
           message_type AS messageType, attachment_id AS attachmentId,
           original_name AS originalName, mime_type AS mimeType,
           file_size AS fileSize
    FROM private_messages WHERE id = ?
  `).get(Number(result.lastInsertRowid));

  io.to('private:' + request.id).emit('private:message', { ...saved, requestId: request.id });
  res.status(201).json({ message: saved });
});

app.post('/api/private/attachments', auth, (req, res, next) => {
  const request = approvedPrivateRequest(req.user.id, req.query.requestId);
  if (!request) {
    return res.status(403).json({ error: 'الغرفة غير متاحة قبل اعتماد الطلب' });
  }
  req.privateRequest = request;
  next();
}, (req, res, next) => {
  privateUpload.single('file')(req, res, err => {
    if (!err) return next();
    const tooLarge = err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE';
    return res.status(tooLarge ? 413 : 400).json({
      error: tooLarge ? 'الحد الأقصى لحجم الملف 20 ميجابايت' :
        (err.message || 'تعذر رفع الملف')
    });
  });
}, (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'اختر ملفًا أولًا' });

  try {
    const attachmentId = crypto.randomUUID();
    const result = db.prepare(`
      INSERT INTO private_messages
        (request_id, user_id, name, body, created_at, message_type,
         attachment_id, original_name, mime_type, file_size, stored_name)
      VALUES (?, ?, ?, ?, ?, 'attachment', ?, ?, ?, ?, ?)
    `).run(
      req.privateRequest.id, req.user.id, req.user.name,
      req.file.originalname, new Date().toISOString(), attachmentId,
      path.basename(req.file.originalname), req.file.mimetype,
      req.file.size, req.file.filename
    );

    const saved = db.prepare(`
      SELECT id, user_id AS userId, name, body, created_at AS createdAt,
             message_type AS messageType, attachment_id AS attachmentId,
             original_name AS originalName, mime_type AS mimeType,
             file_size AS fileSize
      FROM private_messages WHERE id = ?
    `).get(Number(result.lastInsertRowid));

    const message = {
      ...saved,
      downloadUrl: '/api/private/attachments/' + attachmentId,
      requestId: req.privateRequest.id
    };
    io.to('private:' + req.privateRequest.id).emit('private:message', message);
    res.status(201).json({ message });
  } catch (err) {
    try { fs.unlinkSync(req.file.path); } catch {}
    res.status(500).json({ error: 'تعذر حفظ المرفق' });
  }
});

app.get('/api/private/attachments/:id', auth, (req, res) => {
  const file = db.prepare(`
    SELECT request_id AS requestId, stored_name AS storedName,
           original_name AS originalName, mime_type AS mimeType
    FROM private_messages
    WHERE attachment_id = ? AND message_type = 'attachment'
  `).get(req.params.id);

  if (!file || !approvedPrivateRequest(req.user.id, file.requestId)) {
    return res.status(404).json({ error: 'الملف غير موجود أو غير متاح' });
  }

  const filePath = path.join(PRIVATE_FILE_DIR, path.basename(file.storedName || ''));
  if (!file.storedName || !fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'الملف غير موجود على الخادم' });
  }
  res.download(filePath, path.basename(file.originalName || 'attachment'));
});

app.get('/api/health', (req, res) => {
  res.json({ ok: true, app: 'تواصل مع عبقرينو', database: 'connected' });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('تواصل مع عبقرينو يعمل على المنفذ ' + PORT);
});

function shutdown() {
  server.close(() => {
    try { db.close(); } finally { process.exit(0); }
  });
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
