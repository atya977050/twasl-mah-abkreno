'use strict';

const express = require('express');
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
`);

app.use(express.json({ limit: '32kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const hash = value =>
  crypto.createHash('sha256').update(value).digest('hex');

function getUser(token) {
  if (!token || typeof token !== 'string' || token.length > 200) return null;
  return db.prepare(
    'SELECT id, name FROM users WHERE token_hash = ?'
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

app.post('/api/private/request', auth, (req, res) => {
  const paymentRef = String(req.body?.paymentRef || '').trim();
  if (paymentRef.length < 3 || paymentRef.length > 200) {
    return res.status(400).json({ error: 'أدخل مرجع التحويل أو رقمه' });
  }

  const id = crypto.randomUUID();
  db.prepare(`
    INSERT INTO private_requests
      (id, user_id, payment_ref, fee, status, created_at)
    VALUES (?, ?, ?, 200, 'pending', ?)
  `).run(id, req.user.id, paymentRef, new Date().toISOString());

  res.status(201).json({
    id,
    status: 'pending',
    message: 'تم تسجيل الطلب. الغرفة الخاصة مغلقة حتى مراجعة الدفع.'
  });
});

app.get('/api/private/status', auth, (req, res) => {
  const request = db.prepare(`
    SELECT id, fee, status, created_at AS createdAt
    FROM private_requests
    WHERE user_id = ?
    ORDER BY created_at DESC LIMIT 1
  `).get(req.user.id);
  res.json({ request: request || null });
});

// اعتماد الدفع متاح فقط عند ضبط مفتاح إداري سري في بيئة الخادم.
app.post('/api/admin/private/:id/approve', (req, res) => {
  const key = process.env.ADMIN_KEY;
  if (!key || !req.get('x-admin-key') ||
      !crypto.timingSafeEqual(
        Buffer.from(hash(req.get('x-admin-key'))),
        Buffer.from(hash(key))
      )) {
    return res.status(403).json({ error: 'غير مصرح' });
  }

  const result = db.prepare(`
    UPDATE private_requests SET status = 'approved'
    WHERE id = ? AND status = 'pending'
  `).run(req.params.id);

  if (!result.changes) {
    return res.status(404).json({ error: 'الطلب غير موجود أو تمت مراجعته' });
  }
  res.json({ status: 'approved' });
});

io.use((socket, next) => {
  const user = getUser(socket.handshake.auth?.token);
  if (!user) return next(new Error('يلزم تسجيل الدخول'));
  socket.user = user;
  next();
});

io.on('connection', socket => {
  socket.emit('session:ready', { userId: socket.user.id });
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
