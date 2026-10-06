require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcrypt');
const session = require('express-session');
const Database = require('better-sqlite3');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const db = new Database('database.db');

const ADMIN_PHONE = process.env.ADMIN_PHONE || '+79266276629';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '18245091112';
const SESSION_SECRET = process.env.SESSION_SECRET || 'default-secret-change-me';
const ENCRYPT_KEY = process.env.ENCRYPT_KEY || 'default-encrypt-key-change-me';
const PORT = process.env.PORT || 3000;

// ===== ШИФРОВАНИЕ =====
const ALGORITHM = 'aes-256-cbc';
function getKey() { return crypto.createHash('sha256').update(ENCRYPT_KEY).digest(); }
function encrypt(text) {
  if (!text) return '';
  try {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(ALGORITHM, getKey(), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
  } catch(e) { return text; }
}
function decrypt(text) {
  if (!text) return '';
  try {
    if (!text.includes(':')) return text;
    const parts = text.split(':');
    if (parts.length !== 2) return text;
    const iv = Buffer.from(parts[0], 'hex');
    const decipher = crypto.createDecipheriv(ALGORITHM, getKey(), iv);
    let decrypted = decipher.update(parts[1], 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch(e) { return text; }
}

// ===== ЛОГИ =====
const LOG_FILE = path.join(__dirname, 'logs.txt');
function log(type, message) {
  const time = new Date().toLocaleString('ru-RU');
  const line = `[${time}] [${type}] ${message}\n`;
  try { fs.appendFileSync(LOG_FILE, line); } catch(e) {}
  console.log(line.trim());
}

// ===== АНТИБРУТФОРС =====
const ipAttempts = {};
const MAX_ATTEMPTS = 20;
const BAN_TIME = 60 * 60 * 1000;
function checkIPBan(ip) {
  const data = ipAttempts[ip];
  if (!data) return false;
  if (data.banUntil && Date.now() < data.banUntil) return true;
  if (data.banUntil && Date.now() >= data.banUntil) { delete ipAttempts[ip]; return false; }
  return false;
}
function addAttempt(ip) {
  if (!ipAttempts[ip]) ipAttempts[ip] = { count: 0 };
  ipAttempts[ip].count++;
  if (ipAttempts[ip].count >= MAX_ATTEMPTS) {
    ipAttempts[ip].banUntil = Date.now() + BAN_TIME;
    log('BAN', `IP ${ip} забанен на 1 час`);
  }
}
function resetAttempts(ip) { delete ipAttempts[ip]; }

// ===== ВАЛИДАЦИЯ =====
function cleanPhone(phone) {
  let p = String(phone || '').replace(/[^\d+]/g, '');
  if (p.startsWith('8') && p.length === 11) p = '+7' + p.slice(1);
  return p;
}
function sanitize(str, maxLen = 500) { return String(str || '').trim().slice(0, maxLen); }
function isValidPhone(phone) { return /^\+\d{10,15}$/.test(phone); }
function isValidPassword(password) { return typeof password === 'string' && password.length >= 4 && password.length <= 100; }

// ===== ЗАГРУЗКА ФАЙЛОВ =====
const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const allowed = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.mp4', '.webm', '.mov', '.mp3', '.wav', '.pdf', '.zip', '.rar', '.txt', '.doc', '.docx', '.xls', '.xlsx'];
    const safeExt = allowed.includes(ext) ? ext : '.bin';
    cb(null, Date.now() + '_' + crypto.randomBytes(4).toString('hex') + safeExt);
  }
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });
const avatarUpload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|gif|webp/i;
    const ok = allowed.test(file.mimetype);
    cb(ok ? null : new Error('Только изображения'), ok);
  }
});

// ===== БАЗА ДАННЫХ =====
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    banned INTEGER DEFAULT 0,
    status TEXT DEFAULT '',
    avatar TEXT DEFAULT '',
    last_seen DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    name TEXT,
    avatar TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS chat_members (
    chat_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    PRIMARY KEY (chat_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL,
    user_id INTEGER,
    name TEXT,
    text TEXT,
    msg_type TEXT DEFAULT 'text',
    file_url TEXT DEFAULT '',
    file_name TEXT DEFAULT '',
    file_size INTEGER DEFAULT 0,
    file_mime TEXT DEFAULT '',
    deleted INTEGER DEFAULT 0,
    deleted_for TEXT DEFAULT '',
    delivered INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS stories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    file_url TEXT NOT NULL,
    caption TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL
  );
  CREATE TABLE IF NOT EXISTS story_views (
    story_id INTEGER NOT NULL,
    viewer_id INTEGER NOT NULL,
    viewed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (story_id, viewer_id)
  );
  CREATE TABLE IF NOT EXISTS stickers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    file_url TEXT NOT NULL,
    emoji TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS custom_statuses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    emoji TEXT DEFAULT '',
    text TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS invitations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user_id INTEGER NOT NULL,
    to_user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    chat_name TEXT DEFAULT '',
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS blocks (
    blocker_id INTEGER NOT NULL,
    blocked_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (blocker_id, blocked_id)
  );
  CREATE TABLE IF NOT EXISTS blocked_phones (
    user_id INTEGER NOT NULL,
    phone TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, phone)
  );
  CREATE TABLE IF NOT EXISTS privacy_settings (
    user_id INTEGER PRIMARY KEY,
    last_seen TEXT DEFAULT 'all',
    online TEXT DEFAULT 'all',
    avatar TEXT DEFAULT 'all',
    status TEXT DEFAULT 'all',
    read_receipts TEXT DEFAULT 'all',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS news (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    text TEXT NOT NULL,
    delay INTEGER DEFAULT 3,
    for_new INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL
  );
  CREATE TABLE IF NOT EXISTS news_read (
    news_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    read_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (news_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS message_reads (
    message_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    read_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (message_id, user_id)
  );
`);

// Миграции (на случай старых баз)
try { db.exec('ALTER TABLE users ADD COLUMN banned INTEGER DEFAULT 0'); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN status TEXT DEFAULT \'\''); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT \'\''); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN last_seen DATETIME'); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN created_at DATETIME'); } catch(e) {}
try { db.exec('ALTER TABLE chats ADD COLUMN avatar TEXT DEFAULT \'\''); } catch(e) {}
try { db.exec('ALTER TABLE messages ADD COLUMN msg_type TEXT DEFAULT \'text\''); } catch(e) {}
try { db.exec('ALTER TABLE messages ADD COLUMN file_url TEXT DEFAULT \'\''); } catch(e) {}
try { db.exec('ALTER TABLE messages ADD COLUMN file_name TEXT DEFAULT \'\''); } catch(e) {}
try { db.exec('ALTER TABLE messages ADD COLUMN file_size INTEGER DEFAULT 0'); } catch(e) {}
try { db.exec('ALTER TABLE messages ADD COLUMN file_mime TEXT DEFAULT \'\''); } catch(e) {}
try { db.exec('ALTER TABLE messages ADD COLUMN deleted INTEGER DEFAULT 0'); } catch(e) {}
try { db.exec('ALTER TABLE messages ADD COLUMN deleted_for TEXT DEFAULT \'\''); } catch(e) {}
try { db.exec('ALTER TABLE messages ADD COLUMN delivered INTEGER DEFAULT 0'); } catch(e) {}

// ===== СТАТУСЫ ПО УМОЛЧАНИЮ =====
const statusCount = db.prepare('SELECT COUNT(*) as c FROM custom_statuses').get().c;
if (statusCount === 0) {
  const defaults = [
    { emoji: '🔥', text: 'Покоряю мир' }, { emoji: '💼', text: 'На работе' },
    { emoji: '😴', text: 'Отдыхаю' }, { emoji: '☕', text: 'Пью кофе' },
    { emoji: '🎮', text: 'Играю' }, { emoji: '📚', text: 'Учусь' },
    { emoji: '🚫', text: 'Не беспокоить' }
  ];
  const insert = db.prepare('INSERT INTO custom_statuses (emoji, text) VALUES (?, ?)');
  defaults.forEach(s => insert.run(s.emoji, s.text));
}

function ensureWelcomeNews() {
  const existing = db.prepare("SELECT id FROM news WHERE for_new = 1").get();
  if (existing) return;
  const title = '🔥 ДОБРО ПОЖАЛОВАТЬ В BLAZE! 🔥';
  const text = `Привет! 👋

Ты в мессенджере Blaze.

Здесь ты можешь:
💬 Общаться с друзьями
📷 Делить фото и видео
🎨 Отправлять стикеры
🌟 Ставить статусы
📩 Отправлять заявки
🚫 Блокировать нежелательных

Приятного общения! 🔥`;
  const expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO news (title, text, delay, for_new, expires_at) VALUES (?, ?, ?, ?, ?)').run(title, text, 3, 1, expiresAt);
  log('INFO', 'Создана приветственная новость');
}

// ===== ЗАЩИТА =====
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

const generalLimiter = rateLimit({ windowMs: 60 * 1000, max: 200, message: { ok: false, error: 'Слишком много запросов' }, standardHeaders: true, legacyHeaders: false });
const authLimiter = rateLimit({ windowMs: 60 * 1000, max: 5, message: { ok: false, error: '🚫 Слишком много попыток' }, standardHeaders: true, legacyHeaders: false });
app.use('/login', authLimiter);
app.use('/register', authLimiter);

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.static('public'));

// ===== CSRF =====
const csrfTokens = {};
function generateCsrfToken(sessionId) { const token = crypto.randomBytes(32).toString('hex'); csrfTokens[sessionId] = token; return token; }
function checkCsrf(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (req.path.startsWith('/chats/') && req.path.endsWith('/upload')) return next();
  if (req.path.startsWith('/chats/') && req.path.endsWith('/avatar')) return next();
  if (req.path.startsWith('/avatar/upload')) return next();
  if (req.path.startsWith('/stickers/upload')) return next();
  if (req.path.startsWith('/stories/upload')) return next();
  const sessionId = req.sessionID;
  const token = req.body._csrf || req.headers['x-csrf-token'];
  if (!sessionId || !csrfTokens[sessionId] || csrfTokens[sessionId] !== token) {
    return res.status(403).json({ ok: false, error: 'Ошибка безопасности (CSRF)' });
  }
  next();
}

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000, httpOnly: true, sameSite: 'lax' }
}));

app.use((req, res, next) => {
  if (req.sessionID && !csrfTokens[req.sessionID]) generateCsrfToken(req.sessionID);
  next();
});

app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  if (checkIPBan(ip)) return res.status(403).json({ ok: false, error: '🚫 Ваш IP забанен' });
  next();
});

app.use(generalLimiter);

// ===== ХЕЛПЕРЫ =====
function isBlocked(blockerId, blockedId) {
  const row = db.prepare('SELECT 1 FROM blocks WHERE blocker_id = ? AND blocked_id = ?').get(blockerId, blockedId);
  return !!row;
}
function isBlockedBetween(user1, user2) { return isBlocked(user1, user2) || isBlocked(user2, user1); }

function ensureSavedChat(userId) {
  const existing = db.prepare(`SELECT c.id FROM chats c JOIN chat_members m ON m.chat_id = c.id WHERE c.type = 'saved' AND m.user_id = ?`).get(userId);
  if (existing) return existing.id;
  const info = db.prepare("INSERT INTO chats (type, name) VALUES ('saved', 'Избранное')").run();
  const chatId = info.lastInsertRowid;
  db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(chatId, userId);
  return chatId;
}

function ensurePrivacy(userId) {
  const existing = db.prepare('SELECT user_id FROM privacy_settings WHERE user_id = ?').get(userId);
  if (!existing) {
    db.prepare('INSERT INTO privacy_settings (user_id) VALUES (?)').run(userId);
  }
}

function getPrivacy(userId) {
  ensurePrivacy(userId);
  return db.prepare('SELECT * FROM privacy_settings WHERE user_id = ?').get(userId);
}

// Проверка: имеет ли viewerId право видеть поле юзера targetId
function canSee(viewerId, targetId, setting) {
  if (viewerId === targetId) return true;
  const priv = getPrivacy(targetId);
  const value = priv[setting] || 'all';
  if (value === 'all') return true;
  if (value === 'nobody') return false;
  if (value === 'contacts') {
    // Контакт = есть общий чат (личный или группа)
    const common = db.prepare(`
      SELECT 1 FROM chat_members m1
      JOIN chat_members m2 ON m1.chat_id = m2.chat_id
      WHERE m1.user_id = ? AND m2.user_id = ?
      LIMIT 1
    `).get(viewerId, targetId);
    return !!common;
  }
  return true;
}

// Онлайн-пользователи
const onlineUsers = new Set();

function cleanExpiredStories() {
  const now = new Date().toISOString();
  const expired = db.prepare('SELECT id, file_url FROM stories WHERE expires_at < ?').all(now);
  for (const s of expired) {
    const filePath = path.join(__dirname, 'public', s.file_url.replace(/^\//, ''));
    if (fs.existsSync(filePath)) { try { fs.unlinkSync(filePath); } catch(e) {} }
    db.prepare('DELETE FROM stories WHERE id = ?').run(s.id);
    db.prepare('DELETE FROM story_views WHERE story_id = ?').run(s.id);
  }
}
setInterval(cleanExpiredStories, 60 * 60 * 1000);

app.get('/csrf', (req, res) => { res.json({ ok: true, token: csrfTokens[req.sessionID] }); });

// ===== РЕГИСТРАЦИЯ =====
app.post('/register', async (req, res) => {
  const ip = req.ip;
  const { phone: rawPhone, password, name } = req.body;
  if (!rawPhone || !password || !name) { addAttempt(ip); return res.json({ ok: false, error: 'Заполни все поля' }); }
  if (!isValidPassword(password)) { addAttempt(ip); return res.json({ ok: false, error: 'Пароль 4-100 символов' }); }
  const phone = cleanPhone(rawPhone);
  if (!isValidPhone(phone)) { addAttempt(ip); return res.json({ ok: false, error: 'Неверный формат номера' }); }
  if (db.prepare('SELECT id FROM users WHERE phone = ?').get(phone)) { addAttempt(ip); return res.json({ ok: false, error: 'Номер занят' }); }
  const cleanName = sanitize(name, 50);
  if (cleanName.length < 2) return res.json({ ok: false, error: 'Имя короткое' });
  const role = (phone === ADMIN_PHONE) ? 'creator' : 'user';
  const hash = await bcrypt.hash(password, 10);
  const info = db.prepare('INSERT INTO users (phone, password, name, role, created_at, last_seen) VALUES (?, ?, ?, ?, ?, ?)')
    .run(phone, hash, cleanName, role, new Date().toISOString(), new Date().toISOString());
  const newUserId = info.lastInsertRowid;
  ensureSavedChat(newUserId);
  ensurePrivacy(newUserId);

  // Проверяем: кто-то заблокировал этот номер?
  const blockers = db.prepare('SELECT user_id FROM blocked_phones WHERE phone = ?').all(phone);
  for (const b of blockers) {
    try {
      db.prepare('INSERT OR IGNORE INTO blocks (blocker_id, blocked_id) VALUES (?, ?)').run(b.user_id, newUserId);
    } catch(e) {}
  }

  req.session.userId = newUserId;
  req.session.userName = cleanName;
  req.session.role = role;
  resetAttempts(ip);
  log('REG', `Новый юзер: ${cleanName}`);
  res.json({ ok: true, name: cleanName, role });
});

// ===== ВХОД =====
app.post('/login', async (req, res) => {
  const ip = req.ip;
  const phone = cleanPhone(req.body.phone);
  const user = db.prepare('SELECT * FROM users WHERE phone = ?').get(phone);
  if (!user) { addAttempt(ip); return res.json({ ok: false, error: 'Неверный номер или пароль' }); }
  if (user.banned) return res.json({ ok: false, error: '🚫 Вы забанены' });
  const ok = await bcrypt.compare(req.body.password, user.password);
  if (!ok) { addAttempt(ip); return res.json({ ok: false, error: 'Неверный номер или пароль' }); }
  ensureSavedChat(user.id);
  ensurePrivacy(user.id);
  req.session.userId = user.id;
  req.session.userName = user.name;
  req.session.role = user.role;
  resetAttempts(ip);
  res.json({ ok: true, name: user.name, role: user.role });
});

app.post('/logout', (req, res) => {
  const userId = req.session.userId;
  if (userId) {
    db.prepare('UPDATE users SET last_seen = ? WHERE id = ?').run(new Date().toISOString(), userId);
    onlineUsers.delete(userId);
    io.emit('user_status', { userId, online: false, last_seen: new Date().toISOString() });
  }
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/me', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const user = db.prepare('SELECT id, name, role, banned, status, avatar FROM users WHERE id = ?').get(req.session.userId);
  if (!user || user.banned) return res.json({ ok: false, banned: true });
  ensureSavedChat(user.id);
  ensurePrivacy(user.id);
  res.json({ ok: true, id: user.id, name: user.name, role: user.role, status: user.status, avatar: user.avatar });
});

// ===== НАСТРОЙКИ КОНФИДЕНЦИАЛЬНОСТИ =====
app.get('/settings/privacy', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const priv = getPrivacy(req.session.userId);
  res.json({ ok: true, privacy: priv });
});

app.post('/settings/privacy', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const allowed = ['all', 'contacts', 'nobody'];
  const fields = ['last_seen', 'online', 'avatar', 'status', 'read_receipts'];
  ensurePrivacy(req.session.userId);

  for (const f of fields) {
    if (req.body[f] && allowed.includes(req.body[f])) {
      db.prepare(`UPDATE privacy_settings SET ${f} = ?, updated_at = ? WHERE user_id = ?`)
        .run(req.body[f], new Date().toISOString(), req.session.userId);
    }
  }
  res.json({ ok: true });
});

// ===== БЛОКИРОВКА НОМЕРОВ =====
app.get('/settings/blocked-phones', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const phones = db.prepare('SELECT phone, created_at FROM blocked_phones WHERE user_id = ? ORDER BY created_at DESC').all(req.session.userId);
  res.json({ ok: true, phones });
});

app.post('/settings/block-phone', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const phone = cleanPhone(req.body.phone);
  if (!isValidPhone(phone)) return res.json({ ok: false, error: 'Неверный номер' });
  if (phone === db.prepare('SELECT phone FROM users WHERE id = ?').get(req.session.userId)?.phone) {
    return res.json({ ok: false, error: 'Себя нельзя' });
  }
  try {
    db.prepare('INSERT OR IGNORE INTO blocked_phones (user_id, phone) VALUES (?, ?)').run(req.session.userId, phone);
    // Если этот номер уже зарегистрирован — блокируем юзера
    const target = db.prepare('SELECT id FROM users WHERE phone = ?').get(phone);
    if (target) {
      db.prepare('INSERT OR IGNORE INTO blocks (blocker_id, blocked_id) VALUES (?, ?)').run(req.session.userId, target.id);
      io.emit('block_update', {});
    }
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: 'Ошибка' }); }
});

app.post('/settings/unblock-phone', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const phone = cleanPhone(req.body.phone);
  db.prepare('DELETE FROM blocked_phones WHERE user_id = ? AND phone = ?').run(req.session.userId, phone);
  const target = db.prepare('SELECT id FROM users WHERE phone = ?').get(phone);
  if (target) {
    db.prepare('DELETE FROM blocks WHERE blocker_id = ? AND blocked_id = ?').run(req.session.userId, target.id);
    io.emit('block_update', {});
  }
  res.json({ ok: true });
});

// ===== СПИСОК ЗАБЛОКИРОВАННЫХ ЮЗЕРОВ =====
app.get('/settings/blocked-users', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const users = db.prepare(`
    SELECT u.id, u.name, u.phone, u.avatar, u.role, b.created_at
    FROM blocks b JOIN users u ON u.id = b.blocked_id
    WHERE b.blocker_id = ?
    ORDER BY b.created_at DESC
  `).all(req.session.userId);
  res.json({ ok: true, users });
});

// ===== НОВОСТИ =====
app.get('/news/unread', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = req.session.userId;
  const now = new Date().toISOString();
  const news = db.prepare(`SELECT n.id, n.title, n.text, n.delay, n.for_new, n.created_at FROM news n WHERE n.expires_at > ? AND n.id NOT IN (SELECT news_id FROM news_read WHERE user_id = ?) ORDER BY n.id ASC`).all(now, me);
  res.json({ ok: true, news });
});

app.post('/news/:id/read', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  try { db.prepare('INSERT OR IGNORE INTO news_read (news_id, user_id) VALUES (?, ?)').run(req.params.id, req.session.userId); res.json({ ok: true }); }
  catch(e) { res.json({ ok: false }); }
});

app.get('/statuses', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const statuses = db.prepare('SELECT id, emoji, text FROM custom_statuses ORDER BY id ASC').all();
  res.json({ ok: true, statuses });
});

app.post('/set-status', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  const isCreator = me && me.role === 'creator';
  let status = sanitize(req.body.status, 100);
  if (!isCreator && status) {
    const cleanStatus = status.replace(/^[^\w\s]+\s*/, '').trim();
    const found = db.prepare('SELECT id FROM custom_statuses WHERE text = ?').get(cleanStatus);
    if (!found) return res.json({ ok: false, error: 'Статус не разрешён' });
  }
  db.prepare('UPDATE users SET status = ? WHERE id = ?').run(status, req.session.userId);
  res.json({ ok: true, status });
});

// ===== ПРОФИЛЬ ЮЗЕРА (с учётом приватности) =====
app.get('/user/:id', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const targetId = parseInt(req.params.id);
  const user = db.prepare('SELECT id, name, role, status, avatar, last_seen FROM users WHERE id = ?').get(targetId);
  if (!user) return res.json({ ok: false, error: 'Не найден' });
  const me = req.session.userId;
  const iBlockedHim = isBlocked(me, targetId);
  const heBlockedMe = isBlocked(targetId, me);
  const isOnline = onlineUsers.has(targetId);

  // Приватность
  const canSeeAvatar = canSee(me, targetId, 'avatar');
  const canSeeStatus = canSee(me, targetId, 'status');
  const canSeeOnline = canSee(me, targetId, 'online');
  const canSeeLastSeen = canSee(me, targetId, 'last_seen');

  res.json({
    ok: true,
    user: {
      id: user.id,
      name: user.name,
      role: user.role,
      status: canSeeStatus ? user.status : '',
      avatar: canSeeAvatar ? user.avatar : '',
      last_seen: canSeeLastSeen ? user.last_seen : null
    },
    iBlockedHim, heBlockedMe,
    isOnline: canSeeOnline ? isOnline : false,
    hideOnline: !canSeeOnline,
    hideLastSeen: !canSeeLastSeen
  });
});

// ===== ОНЛАЙН-СТАТУС =====
app.get('/user/:id/online', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const targetId = parseInt(req.params.id);
  const me = req.session.userId;
  const user = db.prepare('SELECT last_seen FROM users WHERE id = ?').get(targetId);
  if (!user) return res.json({ ok: false });
  const canSeeOnline = canSee(me, targetId, 'online');
  const canSeeLastSeen = canSee(me, targetId, 'last_seen');
  const isOnline = onlineUsers.has(targetId);
  res.json({
    ok: true,
    online: canSeeOnline ? isOnline : false,
    hideOnline: !canSeeOnline,
    last_seen: canSeeLastSeen ? user.last_seen : null,
    hideLastSeen: !canSeeLastSeen
  });
});

// ===== АВАТАРКИ =====
app.post('/avatar/upload', avatarUpload.single('avatar'), (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  if (!req.file) return res.json({ ok: false, error: 'Файл не загружен' });
  const fileUrl = '/uploads/' + req.file.filename;
  const old = db.prepare('SELECT avatar FROM users WHERE id = ?').get(req.session.userId);
  if (old && old.avatar) { const oldPath = path.join(__dirname, 'public', old.avatar.replace(/^\//, '')); if (fs.existsSync(oldPath)) try { fs.unlinkSync(oldPath); } catch(e) {} }
  db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(fileUrl, req.session.userId);
  io.emit('avatar_update', { userId: req.session.userId, avatar: fileUrl });
  res.json({ ok: true, avatar: fileUrl });
});

app.delete('/avatar', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const old = db.prepare('SELECT avatar FROM users WHERE id = ?').get(req.session.userId);
  if (old && old.avatar) { const oldPath = path.join(__dirname, 'public', old.avatar.replace(/^\//, '')); if (fs.existsSync(oldPath)) try { fs.unlinkSync(oldPath); } catch(e) {} }
  db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run('', req.session.userId);
  io.emit('avatar_update', { userId: req.session.userId, avatar: '' });
  res.json({ ok: true });
});

// ===== УДАЛЕНИЕ АККАУНТА =====
app.post('/delete-account', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = req.session.userId;
  const myChats = db.prepare('SELECT chat_id FROM chat_members WHERE user_id = ?').all(me);
  for (const c of myChats) {
    const msgs = db.prepare('SELECT file_url FROM messages WHERE chat_id = ? AND file_url != \'\'').all(c.chat_id);
    for (const m of msgs) { const fp = path.join(__dirname, 'public', m.file_url.replace(/^\//, '')); if (fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch(e) {} }
    db.prepare('DELETE FROM messages WHERE chat_id = ?').run(c.chat_id);
    db.prepare('DELETE FROM chat_members WHERE chat_id = ?').run(c.chat_id);
    db.prepare('DELETE FROM chats WHERE id = ?').run(c.chat_id);
  }
  const myStories = db.prepare('SELECT id, file_url FROM stories WHERE user_id = ?').all(me);
  for (const s of myStories) { const fp = path.join(__dirname, 'public', s.file_url.replace(/^\//, '')); if (fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch(e) {} }
  db.prepare('DELETE FROM stories WHERE user_id = ?').run(me);
  const myStickers = db.prepare('SELECT file_url FROM stickers WHERE user_id = ?').all(me);
  for (const s of myStickers) { const fp = path.join(__dirname, 'public', s.file_url.replace(/^\//, '')); if (fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch(e) {} }
  db.prepare('DELETE FROM stickers WHERE user_id = ?').run(me);
  const meUser = db.prepare('SELECT avatar FROM users WHERE id = ?').get(me);
  if (meUser && meUser.avatar) { const fp = path.join(__dirname, 'public', meUser.avatar.replace(/^\//, '')); if (fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch(e) {} }
  db.prepare('DELETE FROM invitations WHERE from_user_id = ? OR to_user_id = ?').run(me, me);
  db.prepare('DELETE FROM blocks WHERE blocker_id = ? OR blocked_id = ?').run(me, me);
  db.prepare('DELETE FROM blocked_phones WHERE user_id = ?').run(me);
  db.prepare('DELETE FROM privacy_settings WHERE user_id = ?').run(me);
  db.prepare('DELETE FROM news_read WHERE user_id = ?').run(me);
  db.prepare('DELETE FROM message_reads WHERE user_id = ?').run(me);
  db.prepare('DELETE FROM users WHERE id = ?').run(me);
  onlineUsers.delete(me);
  req.session.destroy();
  res.json({ ok: true });
});

// ===== ПОИСК =====
app.post('/search', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const phone = cleanPhone(req.body.phone);
  if (!phone) return res.json({ ok: false, error: 'Введи номер' });
  const found = db.prepare('SELECT id, name, role, phone, status, avatar FROM users WHERE phone = ? AND id != ?').get(phone, req.session.userId);
  if (!found) return res.json({ ok: false, error: 'Пользователь не найден' });
  res.json({ ok: true, user: found });
});

// ===== ПОИСК ПО ИМЕНИ (только Creator) =====
app.post('/search/name', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false, error: 'Только для админа' });
  const query = sanitize(req.body.query, 50);
  if (!query || query.length < 2) return res.json({ ok: false, error: 'Введи минимум 2 буквы' });
  const users = db.prepare('SELECT id, name, role, phone, status, avatar FROM users WHERE name LIKE ? AND id != ? LIMIT 50')
    .all('%' + query + '%', req.session.userId);
  res.json({ ok: true, users });
});

// ===== БЛОКИРОВКА ЮЗЕРОВ =====
app.post('/block', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const { userId } = req.body;
  if (!userId || userId === req.session.userId) return res.json({ ok: false });
  try { db.prepare('INSERT OR IGNORE INTO blocks (blocker_id, blocked_id) VALUES (?, ?)').run(req.session.userId, userId); io.emit('block_update', {}); res.json({ ok: true }); }
  catch(e) { res.json({ ok: false }); }
});

app.post('/unblock', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const { userId } = req.body;
  db.prepare('DELETE FROM blocks WHERE blocker_id = ? AND blocked_id = ?').run(req.session.userId, userId);
  io.emit('block_update', {});
  res.json({ ok: true });
});

// ===== ЗАЯВКИ =====
app.post('/invitations/send', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const { toUserId, type } = req.body;
  if (!toUserId) return res.json({ ok: false, error: 'Не выбран юзер' });
  const me = req.session.userId;
  if (me === parseInt(toUserId)) return res.json({ ok: false, error: 'Себе нельзя' });
  if (isBlockedBetween(me, toUserId)) return res.json({ ok: false, error: 'Блокировка' });
  if (type === 'private') {
    const existingChat = db.prepare(`SELECT c.id FROM chats c JOIN chat_members m1 ON m1.chat_id = c.id AND m1.user_id = ? JOIN chat_members m2 ON m2.chat_id = c.id AND m2.user_id = ? WHERE c.type = 'private'`).get(me, toUserId);
    if (existingChat) return res.json({ ok: true, chatId: existingChat.id, alreadyExists: true });
  }
  const existing = db.prepare("SELECT id FROM invitations WHERE from_user_id = ? AND to_user_id = ? AND status = 'pending' AND type = ?").get(me, toUserId, type || 'private');
  if (existing) return res.json({ ok: false, error: 'Заявка уже отправлена' });
  const info = db.prepare('INSERT INTO invitations (from_user_id, to_user_id, type, status) VALUES (?, ?, ?, ?)').run(me, toUserId, type || 'private', 'pending');
  io.emit('new_invitation', { toUserId: parseInt(toUserId), invitationId: info.lastInsertRowid });
  res.json({ ok: true, invitationId: info.lastInsertRowid });
});

app.get('/invitations', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = req.session.userId;
  const incoming = db.prepare(`SELECT i.id, i.type, i.status, i.created_at, u.id as from_id, u.name as from_name, u.role as from_role, u.avatar as from_avatar, u.status as from_status FROM invitations i JOIN users u ON u.id = i.from_user_id WHERE i.to_user_id = ? AND i.status = 'pending' ORDER BY i.id DESC`).all(me);
  const outgoing = db.prepare(`SELECT i.id, i.type, i.status, i.created_at, u.id as to_id, u.name as to_name, u.role as to_role, u.avatar as to_avatar FROM invitations i JOIN users u ON u.id = i.to_user_id WHERE i.from_user_id = ? AND i.status = 'pending' ORDER BY i.id DESC`).all(me);
  res.json({ ok: true, incoming, outgoing });
});

app.post('/invitations/:id/accept', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const inv = db.prepare('SELECT * FROM invitations WHERE id = ?').get(req.params.id);
  if (!inv) return res.json({ ok: false, error: 'Не найдена' });
  if (inv.to_user_id !== req.session.userId) return res.json({ ok: false });
  if (inv.status !== 'pending') return res.json({ ok: false });
  if (isBlockedBetween(inv.from_user_id, inv.to_user_id)) return res.json({ ok: false });
  if (inv.type === 'private') {
    const existing = db.prepare(`SELECT c.id FROM chats c JOIN chat_members m1 ON m1.chat_id = c.id AND m1.user_id = ? JOIN chat_members m2 ON m2.chat_id = c.id AND m2.user_id = ? WHERE c.type = 'private'`).get(inv.from_user_id, inv.to_user_id);
    let chatId;
    if (existing) chatId = existing.id;
    else {
      const chatInfo = db.prepare("INSERT INTO chats (type) VALUES ('private')").run();
      chatId = chatInfo.lastInsertRowid;
      db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(chatId, inv.from_user_id);
      db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(chatId, inv.to_user_id);
    }
    db.prepare('UPDATE invitations SET status = ? WHERE id = ?').run('accepted', inv.id);
    io.emit('invitation_accepted', { fromUserId: inv.from_user_id, toUserId: inv.to_user_id, chatId });
    res.json({ ok: true, chatId });
  } else {
    db.prepare('UPDATE invitations SET status = ? WHERE id = ?').run('accepted', inv.id);
    res.json({ ok: true });
  }
});

app.post('/invitations/:id/decline', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const inv = db.prepare('SELECT * FROM invitations WHERE id = ?').get(req.params.id);
  if (!inv || inv.to_user_id !== req.session.userId) return res.json({ ok: false });
  db.prepare('UPDATE invitations SET status = ? WHERE id = ?').run('declined', inv.id);
  io.emit('invitation_declined', { fromUserId: inv.from_user_id, toUserId: inv.to_user_id });
  res.json({ ok: true });
});

app.post('/invitations/:id/cancel', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const inv = db.prepare('SELECT * FROM invitations WHERE id = ?').get(req.params.id);
  if (!inv || inv.from_user_id !== req.session.userId) return res.json({ ok: false });
  db.prepare('UPDATE invitations SET status = ? WHERE id = ?').run('cancelled', inv.id);
  res.json({ ok: true });
});

// ===== ЛИЧНЫЙ ЧАТ БЕЗ ЗАЯВОК (только Creator) =====
app.post('/chats/private/direct', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false, error: 'Только для админа' });
  const { userId } = req.body;
  if (!userId) return res.json({ ok: false });
  const existing = db.prepare(`SELECT c.id FROM chats c JOIN chat_members m1 ON m1.chat_id = c.id AND m1.user_id = ? JOIN chat_members m2 ON m2.chat_id = c.id AND m2.user_id = ? WHERE c.type = 'private'`).get(req.session.userId, userId);
  if (existing) return res.json({ ok: true, chatId: existing.id, alreadyExists: true });
  const info = db.prepare("INSERT INTO chats (type) VALUES ('private')").run();
  const chatId = info.lastInsertRowid;
  db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(chatId, req.session.userId);
  db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(chatId, userId);
  io.emit('new_chat_for_user', { userId: userId, chatId: chatId });
  res.json({ ok: true, chatId });
});

// ===== ЧАТЫ =====
app.post('/chats/group', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const { name, userIds } = req.body;
  if (!name || !name.trim()) return res.json({ ok: false, error: 'Введи название' });
  const cleanName = sanitize(name, 50);
  if (cleanName.length < 2) return res.json({ ok: false, error: 'Название короткое' });

  const info = db.prepare("INSERT INTO chats (type, name) VALUES ('group', ?)").run(cleanName);
  const chatId = info.lastInsertRowid;
  db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(chatId, req.session.userId);

  if (Array.isArray(userIds)) {
    for (const uid of userIds) {
      if (uid && uid !== req.session.userId) {
        try { db.prepare('INSERT OR IGNORE INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(chatId, uid); } catch(e) {}
      }
    }
  }
  res.json({ ok: true, chatId });
});

app.post('/chats/:id/avatar', avatarUpload.single('avatar'), (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  if (!req.file) return res.json({ ok: false, error: 'Файл не загружен' });
  const chatId = req.params.id;
  const me = req.session.userId;
  const inChat = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').get(chatId, me);
  if (!inChat) return res.json({ ok: false, error: 'Нет доступа' });
  const chat = db.prepare('SELECT type FROM chats WHERE id = ?').get(chatId);
  if (!chat || chat.type !== 'group') return res.json({ ok: false, error: 'Только группы' });
  const isCreator = db.prepare('SELECT role FROM users WHERE id = ?').get(me);
  const groupCreator = db.prepare('SELECT user_id FROM chat_members WHERE chat_id = ? ORDER BY user_id ASC LIMIT 1').get(chatId);
  const canEdit = (groupCreator && groupCreator.user_id === me) || (isCreator && isCreator.role === 'creator');
  if (!canEdit) return res.json({ ok: false, error: 'Нет прав' });
  const oldAvatar = db.prepare('SELECT avatar FROM chats WHERE id = ?').get(chatId);
  if (oldAvatar && oldAvatar.avatar) { const oldPath = path.join(__dirname, 'public', oldAvatar.avatar.replace(/^\//, '')); if (fs.existsSync(oldPath)) try { fs.unlinkSync(oldPath); } catch(e) {} }
  const fileUrl = '/uploads/' + req.file.filename;
  db.prepare('UPDATE chats SET avatar = ? WHERE id = ?').run(fileUrl, chatId);
  io.to('chat_' + chatId).emit('group_avatar_update', { chatId, avatar: fileUrl });
  res.json({ ok: true, avatar: fileUrl });
});

app.post('/chats/:id/add-members', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const chatId = req.params.id;
  const me = req.session.userId;
  const { userIds } = req.body;
  if (!userIds || userIds.length === 0) return res.json({ ok: false, error: 'Не выбраны' });
  const inChat = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').get(chatId, me);
  if (!inChat) return res.json({ ok: false, error: 'Нет доступа' });
  const chat = db.prepare('SELECT type FROM chats WHERE id = ?').get(chatId);
  if (!chat || chat.type !== 'group') return res.json({ ok: false, error: 'Только группы' });
  const isCreator = db.prepare('SELECT role FROM users WHERE id = ?').get(me);
  const groupCreator = db.prepare('SELECT user_id FROM chat_members WHERE chat_id = ? ORDER BY user_id ASC LIMIT 1').get(chatId);
  const canAdd = (groupCreator && groupCreator.user_id === me) || (isCreator && isCreator.role === 'creator');
  if (!canAdd) return res.json({ ok: false, error: 'Нет прав' });
  let added = [];
  for (const uid of userIds) {
    try {
      const exists = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').get(chatId, uid);
      if (!exists) {
        db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(chatId, uid);
        added.push(uid);
      }
    } catch(e) {}
  }
  io.emit('new_group_member', { chatId, userIds: added });
  res.json({ ok: true, added });
});

app.get('/chats/:id/members', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const chatId = req.params.id;
  const inChat = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').get(chatId, req.session.userId);
  if (!inChat) return res.json({ ok: false });
  const members = db.prepare(`
    SELECT u.id, u.name, u.role, u.avatar, u.status
    FROM users u JOIN chat_members m ON m.user_id = u.id
    WHERE m.chat_id = ?
  `).all(chatId);
  res.json({ ok: true, members });
});

app.get('/chats', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = req.session.userId;
  ensureSavedChat(me);
  const chats = db.prepare(`SELECT c.id, c.type, c.name, c.avatar FROM chats c JOIN chat_members m ON m.chat_id = c.id WHERE m.user_id = ? ORDER BY CASE c.type WHEN 'saved' THEN 0 ELSE 1 END, c.id DESC`).all(me);
  const result = chats.map(c => {
    if (c.type === 'saved') return { id: c.id, type: 'saved', title: 'Избранное', role: 'user', otherId: null, status: 'Заметки для себя', avatar: '', blocked: false, online: false, last_seen: null };
    if (c.type === 'private') {
      const other = db.prepare(`SELECT u.id, u.name, u.role, u.status, u.avatar, u.last_seen FROM users u JOIN chat_members m ON m.user_id = u.id WHERE m.chat_id = ? AND u.id != ?`).get(c.id, me);
      let blocked = false;
      if (other) blocked = isBlocked(me, other.id);
      const isOnline = other ? onlineUsers.has(other.id) : false;
      const canSeeOnline = other ? canSee(me, other.id, 'online') : false;
      const canSeeLastSeen = other ? canSee(me, other.id, 'last_seen') : false;
      return {
        id: c.id, type: c.type,
        title: other ? other.name : 'Личный чат',
        role: other ? other.role : 'user',
        otherId: other ? other.id : null,
        status: other ? other.status : '',
        avatar: other ? other.avatar : '',
        blocked,
        online: canSeeOnline ? isOnline : false,
        last_seen: canSeeLastSeen && other ? other.last_seen : null
      };
    }
    return { id: c.id, type: c.type, title: c.name || 'Группа', role: 'group', otherId: null, status: '', avatar: c.avatar || '', blocked: false, online: false, last_seen: null };
  });
  res.json({ ok: true, chats: result });
});

app.get('/chats/:id/messages', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const chatId = req.params.id;
  const me = req.session.userId;
  const inChat = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').get(chatId, me);
  if (!inChat) return res.json({ ok: false });
  const msgs = db.prepare(`SELECT m.id, m.name, m.text, m.created_at, m.msg_type, m.file_url, m.file_name, m.file_size, m.file_mime, m.deleted, m.deleted_for, m.user_id, m.delivered, u.role, u.status, u.avatar FROM messages m LEFT JOIN users u ON u.id = m.user_id WHERE m.chat_id = ? ORDER BY m.id ASC LIMIT 200`).all(chatId);
  const filtered = msgs.filter(m => {
    if (m.deleted) return false;
    const deletedFor = m.deleted_for ? m.deleted_for.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n)) : [];
    if (deletedFor.includes(me)) return false;
    return true;
  }).map(m => {
    const readBy = db.prepare('SELECT COUNT(*) as c FROM message_reads WHERE message_id = ?').get(m.id).c;
    return { ...m, text: decrypt(m.text), readBy };
  });
  res.json({ ok: true, messages: filtered });
});

// ===== ДОСТАВЛЕНО И ПРОЧИТАНО =====
app.post('/messages/:id/delivered', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(req.params.id);
  if (!msg || msg.user_id === req.session.userId) return res.json({ ok: false });
  const inChat = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').get(msg.chat_id, req.session.userId);
  if (!inChat) return res.json({ ok: false });
  db.prepare('UPDATE messages SET delivered = 1 WHERE id = ?').run(msg.id);
  io.to('chat_' + msg.chat_id).emit('message_delivered', { messageId: msg.id, chatId: msg.chat_id });
  res.json({ ok: true });
});

app.post('/messages/:id/read', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(req.params.id);
  if (!msg || msg.user_id === req.session.userId) return res.json({ ok: false });
  const inChat = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').get(msg.chat_id, req.session.userId);
  if (!inChat) return res.json({ ok: false });
  // Проверяем приватность автора — показывать ли ему прочтение
  const canSee = canSeeReadReceipt(msg.user_id, req.session.userId);
  db.prepare('INSERT OR IGNORE INTO message_reads (message_id, user_id) VALUES (?, ?)').run(msg.id, req.session.userId);
  db.prepare('UPDATE messages SET delivered = 1 WHERE id = ?').run(msg.id);
  if (canSee) {
    io.to('chat_' + msg.chat_id).emit('message_read', { messageId: msg.id, chatId: msg.chat_id, userId: req.session.userId });
  }
  res.json({ ok: true });
});

function canSeeReadReceipt(authorId, readerId) {
  const priv = getPrivacy(authorId);
  const value = priv.read_receipts || 'all';
  if (value === 'all') return true;
  if (value === 'nobody') return false;
  if (value === 'contacts') {
    const common = db.prepare(`
      SELECT 1 FROM chat_members m1
      JOIN chat_members m2 ON m1.chat_id = m2.chat_id
      WHERE m1.user_id = ? AND m2.user_id = ?
      LIMIT 1
    `).get(authorId, readerId);
    return !!common;
  }
  return true;
}

app.post('/chats/:id/read-all', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const chatId = req.params.id;
  const me = req.session.userId;
  const inChat = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').get(chatId, me);
  if (!inChat) return res.json({ ok: false });
  const msgs = db.prepare('SELECT id, user_id FROM messages WHERE chat_id = ? AND user_id != ? AND deleted = 0').all(chatId, me);
  for (const m of msgs) {
    db.prepare('INSERT OR IGNORE INTO message_reads (message_id, user_id) VALUES (?, ?)').run(m.id, me);
  }
  db.prepare('UPDATE messages SET delivered = 1 WHERE chat_id = ? AND user_id != ?').run(chatId, me);
  io.to('chat_' + chatId).emit('messages_read_all', { chatId, userId: me });
  res.json({ ok: true });
});

app.get('/messages/:id/readers', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(req.params.id);
  if (!msg || msg.user_id !== req.session.userId) return res.json({ ok: false });
  const readers = db.prepare(`SELECT u.id, u.name, u.role, u.avatar, r.read_at FROM message_reads r JOIN users u ON u.id = r.user_id WHERE r.message_id = ? ORDER BY r.read_at ASC`).all(req.params.id);
  res.json({ ok: true, readers });
});

// ===== ЗАГРУЗКА ФАЙЛА =====
app.post('/chats/:id/upload', upload.single('file'), (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  if (!req.file) return res.json({ ok: false, error: 'Файл не загружен' });
  const chatId = req.params.id;
  const inChat = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').get(chatId, req.session.userId);
  if (!inChat) return res.json({ ok: false });
  const user = db.prepare('SELECT name, role, banned, status, avatar FROM users WHERE id = ?').get(req.session.userId);
  if (!user || user.banned) return res.json({ ok: false });
  const fileUrl = '/uploads/' + req.file.filename;
  const fileName = sanitize(req.file.originalname, 200);
  const fileSize = req.file.size;
  const fileMime = req.file.mimetype;
  let msgType = 'file';
  if (fileMime.startsWith('image/')) msgType = 'image';
  else if (fileMime.startsWith('video/')) msgType = 'video';
  else if (fileMime.startsWith('audio/')) msgType = 'audio';
  const text = encrypt(sanitize(req.body.caption, 500));
  const info = db.prepare(`INSERT INTO messages (chat_id, user_id, name, text, msg_type, file_url, file_name, file_size, file_mime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(chatId, req.session.userId, user.name, text, msgType, fileUrl, fileName, fileSize, fileMime);
  const msg = { id: info.lastInsertRowid, chatId, userId: req.session.userId, name: user.name, role: user.role, text: decrypt(text), status: user.status, avatar: user.avatar, msgType, fileUrl, fileName, fileSize, fileMime, time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }), readBy: 0, delivered: 0 };
  io.to('chat_' + chatId).emit('message', msg);
  res.json({ ok: true, message: msg });
});

// ===== СТИКЕРЫ =====
app.post('/stickers/upload', upload.single('file'), (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  if (!req.file) return res.json({ ok: false });
  const fileUrl = '/uploads/' + req.file.filename;
  const emoji = sanitize(req.body.emoji, 10);
  const info = db.prepare('INSERT INTO stickers (user_id, file_url, emoji) VALUES (?, ?, ?)').run(req.session.userId, fileUrl, emoji);
  res.json({ ok: true, sticker: { id: info.lastInsertRowid, file_url: fileUrl, emoji } });
});

app.get('/stickers', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const stickers = db.prepare('SELECT id, file_url, emoji FROM stickers WHERE user_id = ? ORDER BY id DESC').all(req.session.userId);
  res.json({ ok: true, stickers });
});

app.delete('/stickers/:id', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const sticker = db.prepare('SELECT * FROM stickers WHERE id = ?').get(req.params.id);
  if (!sticker || sticker.user_id !== req.session.userId) return res.json({ ok: false });
  const fp = path.join(__dirname, 'public', sticker.file_url.replace(/^\//, ''));
  if (fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch(e) {}
  db.prepare('DELETE FROM stickers WHERE id = ?').run(sticker.id);
  res.json({ ok: true });
});

// ===== УДАЛЕНИЕ СООБЩЕНИЙ =====
app.post('/messages/:id/delete-for-me', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(req.params.id);
  if (!msg) return res.json({ ok: false });
  const inChat = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').get(msg.chat_id, req.session.userId);
  if (!inChat) return res.json({ ok: false });
  const list = msg.deleted_for ? msg.deleted_for.split(',').map(s => s.trim()).filter(s => s) : [];
  if (!list.includes(String(req.session.userId))) list.push(String(req.session.userId));
  db.prepare('UPDATE messages SET deleted_for = ? WHERE id = ?').run(list.join(','), msg.id);
  res.json({ ok: true });
});

app.post('/messages/:id/delete-for-all', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(req.params.id);
  if (!msg) return res.json({ ok: false });
  const inChat = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').get(msg.chat_id, req.session.userId);
  if (!inChat) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  const isCreator = me && me.role === 'creator';
  const isMine = msg.user_id === req.session.userId;
  if (!isMine && !isCreator) return res.json({ ok: false });
  if (msg.file_url) { const fp = path.join(__dirname, 'public', msg.file_url.replace(/^\//, '')); if (fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch(e) {} }
  db.prepare('UPDATE messages SET deleted = 1 WHERE id = ?').run(msg.id);
  io.to('chat_' + msg.chat_id).emit('message_deleted', { messageId: msg.id, chatId: msg.chat_id });
  res.json({ ok: true });
});

// ===== ИСТОРИИ =====
app.post('/stories/upload', upload.single('file'), (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  if (!req.file) return res.json({ ok: false });
  const type = req.file.mimetype.startsWith('video') ? 'video' : 'photo';
  const fileUrl = '/uploads/' + req.file.filename;
  const caption = sanitize(req.body.caption, 200);
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const info = db.prepare('INSERT INTO stories (user_id, type, file_url, caption, expires_at) VALUES (?, ?, ?, ?, ?)').run(req.session.userId, type, fileUrl, caption, expiresAt);
  io.emit('new_story');
  res.json({ ok: true, storyId: info.lastInsertRowid });
});

app.get('/stories', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = req.session.userId;
  const now = new Date().toISOString();
  const stories = db.prepare(`SELECT s.id, s.user_id, s.type, s.file_url, s.caption, s.created_at, u.name, u.role, u.avatar FROM stories s JOIN users u ON u.id = s.user_id WHERE s.expires_at > ? ORDER BY s.created_at DESC`).all(now);
  const byUser = {};
  for (const s of stories) {
    if (!byUser[s.user_id]) byUser[s.user_id] = { userId: s.user_id, userName: s.name, userRole: s.role, userAvatar: s.avatar, stories: [] };
    const views = db.prepare('SELECT COUNT(*) as c FROM story_views WHERE story_id = ?').get(s.id).c;
    const viewedByMe = db.prepare('SELECT 1 FROM story_views WHERE story_id = ? AND viewer_id = ?').get(s.id, me) ? true : false;
    byUser[s.user_id].stories.push({ id: s.id, type: s.type, fileUrl: s.file_url, caption: s.caption, createdAt: s.created_at, views, viewed: viewedByMe });
  }
  const result = Object.values(byUser);
  result.sort((a, b) => {
    if (a.userId === me) return -1;
    if (b.userId === me) return 1;
    const aUnviewed = a.stories.some(s => !s.viewed);
    const bUnviewed = b.stories.some(s => !s.viewed);
    if (aUnviewed && !bUnviewed) return -1;
    if (!aUnviewed && bUnviewed) return 1;
    return 0;
  });
  res.json({ ok: true, stories: result });
});

app.post('/stories/:id/view', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  try { db.prepare('INSERT OR IGNORE INTO story_views (story_id, viewer_id) VALUES (?, ?)').run(req.params.id, req.session.userId); res.json({ ok: true }); }
  catch(e) { res.json({ ok: false }); }
});

app.delete('/stories/:id', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const story = db.prepare('SELECT * FROM stories WHERE id = ?').get(req.params.id);
  if (!story) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (story.user_id !== req.session.userId && (!me || me.role !== 'creator')) return res.json({ ok: false });
  const fp = path.join(__dirname, 'public', story.file_url.replace(/^\//, ''));
  if (fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch(e) {}
  db.prepare('DELETE FROM stories WHERE id = ?').run(story.id);
  db.prepare('DELETE FROM story_views WHERE story_id = ?').run(story.id);
  io.emit('new_story');
  res.json({ ok: true });
});

app.get('/stories/:id/viewers', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const story = db.prepare('SELECT user_id FROM stories WHERE id = ?').get(req.params.id);
  if (!story || story.user_id !== req.session.userId) return res.json({ ok: false });
  const viewers = db.prepare(`SELECT u.name, u.role, u.avatar, v.viewed_at FROM story_views v JOIN users u ON u.id = v.viewer_id WHERE v.story_id = ? ORDER BY v.viewed_at DESC`).all(req.params.id);
  res.json({ ok: true, viewers });
});

// ===== АДМИНКА =====
app.post('/admin/check', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  if (req.body.password !== ADMIN_PASSWORD) { addAttempt(req.ip); return res.json({ ok: false, error: 'Неверный пароль' }); }
  res.json({ ok: true });
});

app.get('/admin/users', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const users = db.prepare('SELECT id, name, phone, role, banned, status, avatar, created_at FROM users ORDER BY id').all();
  const stats = { users: db.prepare('SELECT COUNT(*) as c FROM users').get().c, chats: db.prepare('SELECT COUNT(*) as c FROM chats').get().c, messages: db.prepare('SELECT COUNT(*) as c FROM messages WHERE deleted = 0').get().c, stories: db.prepare('SELECT COUNT(*) as c FROM stories').get().c, blocks: db.prepare('SELECT COUNT(*) as c FROM blocks').get().c, news: db.prepare('SELECT COUNT(*) as c FROM news').get().c };
  res.json({ ok: true, users, stats });
});

app.post('/admin/ban', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const { userId, banned } = req.body;
  if (userId === req.session.userId) return res.json({ ok: false });
  db.prepare('UPDATE users SET banned = ? WHERE id = ?').run(banned ? 1 : 0, userId);
  res.json({ ok: true });
});

app.get('/admin/blocks', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const blocks = db.prepare(`SELECT b.created_at, u1.id as blocker_id, u1.name as blocker_name, u1.avatar as blocker_avatar, u2.id as blocked_id, u2.name as blocked_name, u2.avatar as blocked_avatar FROM blocks b JOIN users u1 ON u1.id = b.blocker_id JOIN users u2 ON u2.id = b.blocked_id ORDER BY b.created_at DESC`).all();
  res.json({ ok: true, blocks });
});

app.post('/admin/unblock', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const { blockerId, blockedId } = req.body;
  db.prepare('DELETE FROM blocks WHERE blocker_id = ? AND blocked_id = ?').run(blockerId, blockedId);
  io.emit('block_update', {});
  res.json({ ok: true });
});

app.get('/admin/statuses', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const statuses = db.prepare('SELECT id, emoji, text FROM custom_statuses ORDER BY id ASC').all();
  res.json({ ok: true, statuses });
});

app.post('/admin/statuses', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const emoji = sanitize(req.body.emoji, 10);
  const text = sanitize(req.body.text, 50);
  if (!text) return res.json({ ok: false });
  const info = db.prepare('INSERT INTO custom_statuses (emoji, text) VALUES (?, ?)').run(emoji, text);
  res.json({ ok: true, id: info.lastInsertRowid });
});

app.delete('/admin/statuses/:id', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  db.prepare('DELETE FROM custom_statuses WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.post('/admin/give-status', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const { userId, status } = req.body;
  if (!userId) return res.json({ ok: false });
  db.prepare('UPDATE users SET status = ? WHERE id = ?').run(sanitize(status, 100), userId);
  io.emit('avatar_update', {});
  res.json({ ok: true });
});

app.get('/admin/chats', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const chats = db.prepare(`SELECT c.id, c.type, c.name, (SELECT GROUP_CONCAT(u.name, ', ') FROM chat_members m JOIN users u ON u.id = m.user_id WHERE m.chat_id = c.id) as members FROM chats c WHERE c.type != 'saved' ORDER BY c.id DESC`).all();
  res.json({ ok: true, chats });
});

app.get('/admin/chats/:id', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const msgs = db.prepare(`SELECT m.name, m.text, m.created_at, m.msg_type, m.file_url, m.file_name, u.role FROM messages m LEFT JOIN users u ON u.id = m.user_id WHERE m.chat_id = ? AND m.deleted = 0 ORDER BY m.id ASC`).all(req.params.id);
  res.json({ ok: true, messages: msgs.map(m => ({...m, text: decrypt(m.text)})) });
});

app.get('/admin/stories', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const stories = db.prepare(`SELECT s.id, s.user_id, s.type, s.file_url, s.caption, s.created_at, u.name, u.role, (SELECT COUNT(*) FROM story_views WHERE story_id = s.id) as views FROM stories s JOIN users u ON u.id = s.user_id ORDER BY s.created_at DESC`).all();
  res.json({ ok: true, stories });
});

app.get('/admin/news', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const now = new Date().toISOString();
  const news = db.prepare(`SELECT n.id, n.title, n.text, n.delay, n.for_new, n.created_at, n.expires_at, CASE WHEN n.expires_at < ? THEN 1 ELSE 0 END as expired, (SELECT COUNT(*) FROM news_read WHERE news_id = n.id) as read_count FROM news n ORDER BY n.id DESC`).all(now);
  res.json({ ok: true, news });
});

app.post('/admin/news', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const title = sanitize(req.body.title, 100);
  const text = sanitize(req.body.text, 2000);
  let delay = parseInt(req.body.delay) || 3;
  if (delay < 0) delay = 0;
  if (delay > 30) delay = 30;
  const forNew = req.body.forNew ? 1 : 0;
  if (!title || !text) return res.json({ ok: false });
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  const info = db.prepare('INSERT INTO news (title, text, delay, for_new, expires_at) VALUES (?, ?, ?, ?, ?)').run(title, text, delay, forNew, expiresAt);
  res.json({ ok: true, id: info.lastInsertRowid });
});

app.delete('/admin/news/:id', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  db.prepare('DELETE FROM news WHERE id = ?').run(req.params.id);
  db.prepare('DELETE FROM news_read WHERE news_id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ===== SOCKET.IO =====
io.on('connection', (socket) => {
  const userId = parseInt(socket.handshake.query.userId);
  const name = socket.handshake.query.name || 'Аноним';
  const role = socket.handshake.query.role || 'user';
  socket.userId = userId;
  socket.userName = name;
  socket.userRole = role;

  // Онлайн
  if (userId) {
    onlineUsers.add(userId);
    io.emit('user_status', { userId, online: true });
  }

  const myChats = db.prepare('SELECT chat_id FROM chat_members WHERE user_id = ?').all(userId);
  myChats.forEach(c => socket.join('chat_' + c.chat_id));
  socket.on('join_chat', (chatId) => socket.join('chat_' + chatId));

  socket.on('message', ({ chatId, text }) => {
    if (!chatId || !text || !text.trim()) return;
    const user = db.prepare('SELECT banned, status, avatar FROM users WHERE id = ?').get(userId);
    if (user && user.banned) return;
    const inChat = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').get(chatId, userId);
    if (!inChat) return;
    const chatInfo = db.prepare('SELECT type FROM chats WHERE id = ?').get(chatId);
    if (chatInfo && chatInfo.type === 'private') {
      const other = db.prepare('SELECT user_id FROM chat_members WHERE chat_id = ? AND user_id != ?').get(chatId, userId);
      if (other && isBlockedBetween(userId, other.user_id)) {
        socket.emit('blocked_message', { chatId });
        return;
      }
    }
    const cleanText = sanitize(text, 5000);
    const encrypted = encrypt(cleanText);
    const info = db.prepare('INSERT INTO messages (chat_id, user_id, name, text, msg_type) VALUES (?, ?, ?, ?, ?)').run(chatId, userId, name, encrypted, 'text');
    io.to('chat_' + chatId).emit('message', {
      id: info.lastInsertRowid, chatId, userId, name, role, text: cleanText,
      msgType: 'text', status: user ? user.status : '', avatar: user ? user.avatar : '',
      time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }),
      readBy: 0, delivered: 0
    });
  });

  socket.on('sticker', ({ chatId, url, emoji }) => {
    if (!chatId) return;
    const user = db.prepare('SELECT banned, status, avatar FROM users WHERE id = ?').get(userId);
    if (user && user.banned) return;
    const inChat = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').get(chatId, userId);
    if (!inChat) return;
    let msgType, fileUrl, text;
    if (emoji) { msgType = 'text'; fileUrl = ''; text = emoji; }
    else if (url) { msgType = 'sticker'; fileUrl = url; text = ''; }
    else return;
    const encrypted = encrypt(text);
    const info = db.prepare('INSERT INTO messages (chat_id, user_id, name, text, msg_type, file_url) VALUES (?, ?, ?, ?, ?, ?)').run(chatId, userId, name, encrypted, msgType, fileUrl);
    io.to('chat_' + chatId).emit('message', {
      id: info.lastInsertRowid, chatId, userId, name, role, text,
      msgType, fileUrl, status: user ? user.status : '', avatar: user ? user.avatar : '',
      time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }),
      readBy: 0, delivered: 0
    });
  });

  socket.on('disconnect', () => {
    if (userId) {
      onlineUsers.delete(userId);
      const now = new Date().toISOString();
      db.prepare('UPDATE users SET last_seen = ? WHERE id = ?').run(now, userId);
      io.emit('user_status', { userId, online: false, last_seen: now });
    }
  });
});

// ===== ЗАПУСК =====
function ensureAdmin() {
  const existing = db.prepare('SELECT id FROM users WHERE phone = ?').get(ADMIN_PHONE);
  if (existing) {
    db.prepare('UPDATE users SET role = ? WHERE phone = ?').run('creator', ADMIN_PHONE);
    ensureSavedChat(existing.id);
    ensurePrivacy(existing.id);
    log('ADMIN', 'Админ найден: ' + ADMIN_PHONE);
  } else {
    bcrypt.hash('admin123', 10).then(hash => {
      const info = db.prepare('INSERT INTO users (phone, password, name, role, created_at, last_seen) VALUES (?, ?, ?, ?, ?, ?)')
        .run(ADMIN_PHONE, hash, 'Superselester', 'creator', new Date().toISOString(), new Date().toISOString());
      ensureSavedChat(info.lastInsertRowid);
      ensurePrivacy(info.lastInsertRowid);
      log('ADMIN', 'Админ создан: ' + ADMIN_PHONE);
    });
  }
}

server.listen(PORT, () => {
  console.log('\n🔥 BLAZE запущен: http://localhost:' + PORT);
  console.log('🛡 Защита + галочки + авы + онлайн + конфиденциальность\n');
  ensureAdmin();
  ensureWelcomeNews();
  cleanExpiredStories();
});