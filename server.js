require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcrypt');
const session = require('express-session');
const { Pool } = require('pg');
const PgSession = require('connect-pg-simple')(session);
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// ===== POSTGRESQL (SUPABASE) =====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

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

// ===== ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ =====
async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      phone TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      name TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      banned INTEGER DEFAULT 0,
      status TEXT DEFAULT '',
      avatar TEXT DEFAULT '',
      last_seen TIMESTAMP,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS chats (
      id SERIAL PRIMARY KEY,
      type TEXT NOT NULL,
      name TEXT,
      avatar TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS chat_members (
      chat_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      PRIMARY KEY (chat_id, user_id)
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
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
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS stories (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      file_url TEXT NOT NULL,
      caption TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT NOW(),
      expires_at TIMESTAMP NOT NULL
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS story_views (
      story_id INTEGER NOT NULL,
      viewer_id INTEGER NOT NULL,
      viewed_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (story_id, viewer_id)
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS stickers (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      file_url TEXT NOT NULL,
      emoji TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS custom_statuses (
      id SERIAL PRIMARY KEY,
      emoji TEXT DEFAULT '',
      text TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS invitations (
      id SERIAL PRIMARY KEY,
      from_user_id INTEGER NOT NULL,
      to_user_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      chat_name TEXT DEFAULT '',
      status TEXT DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS blocks (
      blocker_id INTEGER NOT NULL,
      blocked_id INTEGER NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (blocker_id, blocked_id)
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS blocked_phones (
      user_id INTEGER NOT NULL,
      phone TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (user_id, phone)
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS privacy_settings (
      user_id INTEGER PRIMARY KEY,
      last_seen TEXT DEFAULT 'all',
      online TEXT DEFAULT 'all',
      avatar TEXT DEFAULT 'all',
      status TEXT DEFAULT 'all',
      read_receipts TEXT DEFAULT 'all',
      updated_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS news (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      text TEXT NOT NULL,
      delay INTEGER DEFAULT 3,
      for_new INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW(),
      expires_at TIMESTAMP NOT NULL
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS news_read (
      news_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      read_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (news_id, user_id)
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS message_reads (
      message_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      read_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (message_id, user_id)
    );
  `);

  // Статусы по умолчанию
  const statusCount = (await pool.query('SELECT COUNT(*) as c FROM custom_statuses')).rows[0].c;
  if (parseInt(statusCount) === 0) {
    const defaults = [
      { emoji: '🔥', text: 'Покоряю мир' }, { emoji: '💼', text: 'На работе' },
      { emoji: '😴', text: 'Отдыхаю' }, { emoji: '☕', text: 'Пью кофе' },
      { emoji: '🎮', text: 'Играю' }, { emoji: '📚', text: 'Учусь' },
      { emoji: '🚫', text: 'Не беспокоить' }
    ];
    for (const s of defaults) {
      await pool.query('INSERT INTO custom_statuses (emoji, text) VALUES ($1, $2)', [s.emoji, s.text]);
    }
  }
  console.log('✅ База данных PostgreSQL инициализирована');
}

async function ensureWelcomeNews() {
  const existing = (await pool.query("SELECT id FROM news WHERE for_new = 1")).rows[0];
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
  await pool.query('INSERT INTO news (title, text, delay, for_new, expires_at) VALUES ($1, $2, $3, $4, $5)', [title, text, 3, 1, expiresAt]);
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
  store: new PgSession({
    pool: pool,
    tableName: 'session',
    createTableIfMissing: true
  }),
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
async function isBlocked(blockerId, blockedId) {
  const row = (await pool.query('SELECT 1 FROM blocks WHERE blocker_id = $1 AND blocked_id = $2', [blockerId, blockedId])).rows[0];
  return !!row;
}
async function isBlockedBetween(user1, user2) {
  return (await isBlocked(user1, user2)) || (await isBlocked(user2, user1));
}

async function ensureSavedChat(userId) {
  const existing = (await pool.query(`SELECT c.id FROM chats c JOIN chat_members m ON m.chat_id = c.id WHERE c.type = 'saved' AND m.user_id = $1`, [userId])).rows[0];
  if (existing) return existing.id;
  const info = (await pool.query("INSERT INTO chats (type, name) VALUES ('saved', 'Избранное') RETURNING id")).rows[0];
  const chatId = info.id;
  await pool.query('INSERT INTO chat_members (chat_id, user_id) VALUES ($1, $2)', [chatId, userId]);
  return chatId;
}

async function ensurePrivacy(userId) {
  const existing = (await pool.query('SELECT user_id FROM privacy_settings WHERE user_id = $1', [userId])).rows[0];
  if (!existing) {
    await pool.query('INSERT INTO privacy_settings (user_id) VALUES ($1)', [userId]);
  }
}

async function getPrivacy(userId) {
  await ensurePrivacy(userId);
  return (await pool.query('SELECT * FROM privacy_settings WHERE user_id = $1', [userId])).rows[0];
}

async function canSee(viewerId, targetId, setting) {
  if (viewerId === targetId) return true;
  const priv = await getPrivacy(targetId);
  const value = priv[setting] || 'all';
  if (value === 'all') return true;
  if (value === 'nobody') return false;
  if (value === 'contacts') {
    const common = (await pool.query(`
      SELECT 1 FROM chat_members m1
      JOIN chat_members m2 ON m1.chat_id = m2.chat_id
      WHERE m1.user_id = $1 AND m2.user_id = $2
      LIMIT 1
    `, [viewerId, targetId])).rows[0];
    return !!common;
  }
  return true;
}

async function canSeeReadReceipt(authorId, readerId) {
  const priv = await getPrivacy(authorId);
  const value = priv.read_receipts || 'all';
  if (value === 'all') return true;
  if (value === 'nobody') return false;
  if (value === 'contacts') {
    const common = (await pool.query(`
      SELECT 1 FROM chat_members m1
      JOIN chat_members m2 ON m1.chat_id = m2.chat_id
      WHERE m1.user_id = $1 AND m2.user_id = $2
      LIMIT 1
    `, [authorId, readerId])).rows[0];
    return !!common;
  }
  return true;
}

const onlineUsers = new Set();

async function cleanExpiredStories() {
  const now = new Date().toISOString();
  const expired = (await pool.query('SELECT id, file_url FROM stories WHERE expires_at < $1', [now])).rows;
  for (const s of expired) {
    const filePath = path.join(__dirname, 'public', s.file_url.replace(/^\//, ''));
    if (fs.existsSync(filePath)) { try { fs.unlinkSync(filePath); } catch(e) {} }
    await pool.query('DELETE FROM stories WHERE id = $1', [s.id]);
    await pool.query('DELETE FROM story_views WHERE story_id = $1', [s.id]);
  }
}
setInterval(cleanExpiredStories, 60 * 60 * 1000);

app.get('/csrf', (req, res) => { res.json({ ok: true, token: csrfTokens[req.sessionID] }); });

// ===== РЕГИСТРАЦИЯ =====
app.post('/register', async (req, res) => {
  try {
    const ip = req.ip;
    const { phone: rawPhone, password, name } = req.body;
    if (!rawPhone || !password || !name) { addAttempt(ip); return res.json({ ok: false, error: 'Заполни все поля' }); }
    if (!isValidPassword(password)) { addAttempt(ip); return res.json({ ok: false, error: 'Пароль 4-100 символов' }); }
    const phone = cleanPhone(rawPhone);
    if (!isValidPhone(phone)) { addAttempt(ip); return res.json({ ok: false, error: 'Неверный формат номера' }); }
    const exist = (await pool.query('SELECT id FROM users WHERE phone = $1', [phone])).rows[0];
    if (exist) { addAttempt(ip); return res.json({ ok: false, error: 'Номер занят' }); }
    const cleanName = sanitize(name, 50);
    if (cleanName.length < 2) return res.json({ ok: false, error: 'Имя короткое' });
    const role = (phone === ADMIN_PHONE) ? 'creator' : 'user';
    const hash = await bcrypt.hash(password, 10);
    const now = new Date().toISOString();
    const info = (await pool.query('INSERT INTO users (phone, password, name, role, created_at, last_seen) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id', [phone, hash, cleanName, role, now, now])).rows[0];
    const newUserId = info.id;
    await ensureSavedChat(newUserId);
    await ensurePrivacy(newUserId);

    const blockers = (await pool.query('SELECT user_id FROM blocked_phones WHERE phone = $1', [phone])).rows;
    for (const b of blockers) {
      try {
        await pool.query('INSERT INTO blocks (blocker_id, blocked_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [b.user_id, newUserId]);
      } catch(e) {}
    }

    req.session.userId = newUserId;
    req.session.userName = cleanName;
    req.session.role = role;
    resetAttempts(ip);
    log('REG', `Новый юзер: ${cleanName}`);
    res.json({ ok: true, name: cleanName, role });
  } catch(e) {
    console.error('Ошибка регистрации:', e);
    res.json({ ok: false, error: 'Ошибка сервера' });
  }
});

// ===== ВХОД =====
app.post('/login', async (req, res) => {
  try {
    const ip = req.ip;
    const phone = cleanPhone(req.body.phone);
    const user = (await pool.query('SELECT * FROM users WHERE phone = $1', [phone])).rows[0];
    if (!user) { addAttempt(ip); return res.json({ ok: false, error: 'Неверный номер или пароль' }); }
    if (user.banned) return res.json({ ok: false, error: '🚫 Вы забанены' });
    const ok = await bcrypt.compare(req.body.password, user.password);
    if (!ok) { addAttempt(ip); return res.json({ ok: false, error: 'Неверный номер или пароль' }); }
    await ensureSavedChat(user.id);
    await ensurePrivacy(user.id);
    req.session.userId = user.id;
    req.session.userName = user.name;
    req.session.role = user.role;
    resetAttempts(ip);
    res.json({ ok: true, name: user.name, role: user.role });
  } catch(e) {
    console.error('Ошибка входа:', e);
    res.json({ ok: false, error: 'Ошибка сервера' });
  }
});

app.post('/logout', async (req, res) => {
  const userId = req.session.userId;
  if (userId) {
    await pool.query('UPDATE users SET last_seen = $1 WHERE id = $2', [new Date().toISOString(), userId]);
    onlineUsers.delete(userId);
    io.emit('user_status', { userId, online: false, last_seen: new Date().toISOString() });
  }
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/me', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const user = (await pool.query('SELECT id, name, role, banned, status, avatar FROM users WHERE id = $1', [req.session.userId])).rows[0];
  if (!user || user.banned) return res.json({ ok: false, banned: true });
  await ensureSavedChat(user.id);
  await ensurePrivacy(user.id);
  res.json({ ok: true, id: user.id, name: user.name, role: user.role, status: user.status, avatar: user.avatar });
});

// ===== НАСТРОЙКИ КОНФИДЕНЦИАЛЬНОСТИ =====
app.get('/settings/privacy', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const priv = await getPrivacy(req.session.userId);
  res.json({ ok: true, privacy: priv });
});

app.post('/settings/privacy', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const allowed = ['all', 'contacts', 'nobody'];
  const fields = ['last_seen', 'online', 'avatar', 'status', 'read_receipts'];
  await ensurePrivacy(req.session.userId);
  for (const f of fields) {
    if (req.body[f] && allowed.includes(req.body[f])) {
      await pool.query(`UPDATE privacy_settings SET ${f} = $1, updated_at = $2 WHERE user_id = $3`, [req.body[f], new Date().toISOString(), req.session.userId]);
    }
  }
  res.json({ ok: true });
});

// ===== БЛОКИРОВКА НОМЕРОВ =====
app.get('/settings/blocked-phones', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const phones = (await pool.query('SELECT phone, created_at FROM blocked_phones WHERE user_id = $1 ORDER BY created_at DESC', [req.session.userId])).rows;
  res.json({ ok: true, phones });
});

app.post('/settings/block-phone', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const phone = cleanPhone(req.body.phone);
  if (!isValidPhone(phone)) return res.json({ ok: false, error: 'Неверный номер' });
  const me = (await pool.query('SELECT phone FROM users WHERE id = $1', [req.session.userId])).rows[0];
  if (me && phone === me.phone) return res.json({ ok: false, error: 'Себя нельзя' });
  try {
    await pool.query('INSERT INTO blocked_phones (user_id, phone) VALUES ($1, $2) ON CONFLICT DO NOTHING', [req.session.userId, phone]);
    const target = (await pool.query('SELECT id FROM users WHERE phone = $1', [phone])).rows[0];
    if (target) {
      await pool.query('INSERT INTO blocks (blocker_id, blocked_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [req.session.userId, target.id]);
      io.emit('block_update', {});
    }
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: 'Ошибка' }); }
});

app.post('/settings/unblock-phone', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const phone = cleanPhone(req.body.phone);
  await pool.query('DELETE FROM blocked_phones WHERE user_id = $1 AND phone = $2', [req.session.userId, phone]);
  const target = (await pool.query('SELECT id FROM users WHERE phone = $1', [phone])).rows[0];
  if (target) {
    await pool.query('DELETE FROM blocks WHERE blocker_id = $1 AND blocked_id = $2', [req.session.userId, target.id]);
    io.emit('block_update', {});
  }
  res.json({ ok: true });
});

app.get('/settings/blocked-users', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const users = (await pool.query(`
    SELECT u.id, u.name, u.phone, u.avatar, u.role, b.created_at
    FROM blocks b JOIN users u ON u.id = b.blocked_id
    WHERE b.blocker_id = $1
    ORDER BY b.created_at DESC
  `, [req.session.userId])).rows;
  res.json({ ok: true, users });
});

// ===== НОВОСТИ =====
app.get('/news/unread', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = req.session.userId;
  const now = new Date().toISOString();
  const news = (await pool.query(`SELECT n.id, n.title, n.text, n.delay, n.for_new, n.created_at FROM news n WHERE n.expires_at > $1 AND n.id NOT IN (SELECT news_id FROM news_read WHERE user_id = $2) ORDER BY n.id ASC`, [now, me])).rows;
  res.json({ ok: true, news });
});

app.post('/news/:id/read', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  try {
    await pool.query('INSERT INTO news_read (news_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [req.params.id, req.session.userId]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false }); }
});

app.get('/statuses', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const statuses = (await pool.query('SELECT id, emoji, text FROM custom_statuses ORDER BY id ASC')).rows;
  res.json({ ok: true, statuses });
});

app.post('/set-status', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = (await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId])).rows[0];
  const isCreator = me && me.role === 'creator';
  let status = sanitize(req.body.status, 100);
  if (!isCreator && status) {
    const cleanStatus = status.replace(/^[^\w\s]+\s*/, '').trim();
    const found = (await pool.query('SELECT id FROM custom_statuses WHERE text = $1', [cleanStatus])).rows[0];
    if (!found) return res.json({ ok: false, error: 'Статус не разрешён' });
  }
  await pool.query('UPDATE users SET status = $1 WHERE id = $2', [status, req.session.userId]);
  res.json({ ok: true, status });
});

// ===== ПРОФИЛЬ ЮЗЕРА =====
app.get('/user/:id', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const targetId = parseInt(req.params.id);
  const user = (await pool.query('SELECT id, name, role, status, avatar, last_seen FROM users WHERE id = $1', [targetId])).rows[0];
  if (!user) return res.json({ ok: false, error: 'Не найден' });
  const me = req.session.userId;
  const iBlockedHim = await isBlocked(me, targetId);
  const heBlockedMe = await isBlocked(targetId, me);
  const isOnline = onlineUsers.has(targetId);

  const canSeeAvatar = await canSee(me, targetId, 'avatar');
  const canSeeStatus = await canSee(me, targetId, 'status');
  const canSeeOnline = await canSee(me, targetId, 'online');
  const canSeeLastSeen = await canSee(me, targetId, 'last_seen');

  res.json({
    ok: true,
    user: {
      id: user.id, name: user.name, role: user.role,
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

app.get('/user/:id/online', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const targetId = parseInt(req.params.id);
  const me = req.session.userId;
  const user = (await pool.query('SELECT last_seen FROM users WHERE id = $1', [targetId])).rows[0];
  if (!user) return res.json({ ok: false });
  const canSeeOnline = await canSee(me, targetId, 'online');
  const canSeeLastSeen = await canSee(me, targetId, 'last_seen');
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
app.post('/avatar/upload', avatarUpload.single('avatar'), async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  if (!req.file) return res.json({ ok: false, error: 'Файл не загружен' });
  const fileUrl = '/uploads/' + req.file.filename;
  const old = (await pool.query('SELECT avatar FROM users WHERE id = $1', [req.session.userId])).rows[0];
  if (old && old.avatar) {
    const oldPath = path.join(__dirname, 'public', old.avatar.replace(/^\//, ''));
    if (fs.existsSync(oldPath)) try { fs.unlinkSync(oldPath); } catch(e) {}
  }
  await pool.query('UPDATE users SET avatar = $1 WHERE id = $2', [fileUrl, req.session.userId]);
  io.emit('avatar_update', { userId: req.session.userId, avatar: fileUrl });
  res.json({ ok: true, avatar: fileUrl });
});

app.delete('/avatar', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const old = (await pool.query('SELECT avatar FROM users WHERE id = $1', [req.session.userId])).rows[0];
  if (old && old.avatar) {
    const oldPath = path.join(__dirname, 'public', old.avatar.replace(/^\//, ''));
    if (fs.existsSync(oldPath)) try { fs.unlinkSync(oldPath); } catch(e) {}
  }
  await pool.query('UPDATE users SET avatar = $1 WHERE id = $2', ['', req.session.userId]);
  io.emit('avatar_update', { userId: req.session.userId, avatar: '' });
  res.json({ ok: true });
});

// ===== УДАЛЕНИЕ АККАУНТА =====
app.post('/delete-account', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = req.session.userId;
  const myChats = (await pool.query('SELECT chat_id FROM chat_members WHERE user_id = $1', [me])).rows;
  for (const c of myChats) {
    const msgs = (await pool.query("SELECT file_url FROM messages WHERE chat_id = $1 AND file_url != ''", [c.chat_id])).rows;
    for (const m of msgs) {
      const fp = path.join(__dirname, 'public', m.file_url.replace(/^\//, ''));
      if (fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch(e) {}
    }
    await pool.query('DELETE FROM messages WHERE chat_id = $1', [c.chat_id]);
    await pool.query('DELETE FROM chat_members WHERE chat_id = $1', [c.chat_id]);
    await pool.query('DELETE FROM chats WHERE id = $1', [c.chat_id]);
  }
  const myStories = (await pool.query('SELECT id, file_url FROM stories WHERE user_id = $1', [me])).rows;
  for (const s of myStories) {
    const fp = path.join(__dirname, 'public', s.file_url.replace(/^\//, ''));
    if (fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch(e) {}
  }
  await pool.query('DELETE FROM stories WHERE user_id = $1', [me]);
  const myStickers = (await pool.query('SELECT file_url FROM stickers WHERE user_id = $1', [me])).rows;
  for (const s of myStickers) {
    const fp = path.join(__dirname, 'public', s.file_url.replace(/^\//, ''));
    if (fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch(e) {}
  }
  await pool.query('DELETE FROM stickers WHERE user_id = $1', [me]);
  const meUser = (await pool.query('SELECT avatar FROM users WHERE id = $1', [me])).rows[0];
  if (meUser && meUser.avatar) {
    const fp = path.join(__dirname, 'public', meUser.avatar.replace(/^\//, ''));
    if (fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch(e) {}
  }
  await pool.query('DELETE FROM invitations WHERE from_user_id = $1 OR to_user_id = $1', [me]);
  await pool.query('DELETE FROM blocks WHERE blocker_id = $1 OR blocked_id = $1', [me]);
  await pool.query('DELETE FROM blocked_phones WHERE user_id = $1', [me]);
  await pool.query('DELETE FROM privacy_settings WHERE user_id = $1', [me]);
  await pool.query('DELETE FROM news_read WHERE user_id = $1', [me]);
  await pool.query('DELETE FROM message_reads WHERE user_id = $1', [me]);
  await pool.query('DELETE FROM users WHERE id = $1', [me]);
  onlineUsers.delete(me);
  req.session.destroy();
  res.json({ ok: true });
});

// ===== ПОИСК =====
app.post('/search', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const phone = cleanPhone(req.body.phone);
  if (!phone) return res.json({ ok: false, error: 'Введи номер' });
  const found = (await pool.query('SELECT id, name, role, phone, status, avatar FROM users WHERE phone = $1 AND id != $2', [phone, req.session.userId])).rows[0];
  if (!found) return res.json({ ok: false, error: 'Пользователь не найден' });
  res.json({ ok: true, user: found });
});

app.post('/search/name', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = (await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId])).rows[0];
  if (!me || me.role !== 'creator') return res.json({ ok: false, error: 'Только для админа' });
  const query = sanitize(req.body.query, 50);
  if (!query || query.length < 2) return res.json({ ok: false, error: 'Введи минимум 2 буквы' });
  const users = (await pool.query('SELECT id, name, role, phone, status, avatar FROM users WHERE name ILIKE $1 AND id != $2 LIMIT 50', ['%' + query + '%', req.session.userId])).rows;
  res.json({ ok: true, users });
});

// ===== БЛОКИРОВКА ЮЗЕРОВ =====
app.post('/block', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const { userId } = req.body;
  if (!userId || userId === req.session.userId) return res.json({ ok: false });
  try {
    await pool.query('INSERT INTO blocks (blocker_id, blocked_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [req.session.userId, userId]);
    io.emit('block_update', {});
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false }); }
});

app.post('/unblock', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const { userId } = req.body;
  await pool.query('DELETE FROM blocks WHERE blocker_id = $1 AND blocked_id = $2', [req.session.userId, userId]);
  io.emit('block_update', {});
  res.json({ ok: true });
});

// ===== ЗАЯВКИ =====
app.post('/invitations/send', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const { toUserId, type } = req.body;
  if (!toUserId) return res.json({ ok: false, error: 'Не выбран юзер' });
  const me = req.session.userId;
  if (me === parseInt(toUserId)) return res.json({ ok: false, error: 'Себе нельзя' });
  if (await isBlockedBetween(me, toUserId)) return res.json({ ok: false, error: 'Блокировка' });
  if (type === 'private') {
    const existingChat = (await pool.query(`SELECT c.id FROM chats c JOIN chat_members m1 ON m1.chat_id = c.id AND m1.user_id = $1 JOIN chat_members m2 ON m2.chat_id = c.id AND m2.user_id = $2 WHERE c.type = 'private'`, [me, toUserId])).rows[0];
    if (existingChat) return res.json({ ok: true, chatId: existingChat.id, alreadyExists: true });
  }
  const existing = (await pool.query("SELECT id FROM invitations WHERE from_user_id = $1 AND to_user_id = $2 AND status = 'pending' AND type = $3", [me, toUserId, type || 'private'])).rows[0];
  if (existing) return res.json({ ok: false, error: 'Заявка уже отправлена' });
  const info = (await pool.query('INSERT INTO invitations (from_user_id, to_user_id, type, status) VALUES ($1, $2, $3, $4) RETURNING id', [me, toUserId, type || 'private', 'pending'])).rows[0];
  io.emit('new_invitation', { toUserId: parseInt(toUserId), invitationId: info.id });
  res.json({ ok: true, invitationId: info.id });
});

app.get('/invitations', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = req.session.userId;
  const incoming = (await pool.query(`SELECT i.id, i.type, i.status, i.created_at, u.id as from_id, u.name as from_name, u.role as from_role, u.avatar as from_avatar, u.status as from_status FROM invitations i JOIN users u ON u.id = i.from_user_id WHERE i.to_user_id = $1 AND i.status = 'pending' ORDER BY i.id DESC`, [me])).rows;
  const outgoing = (await pool.query(`SELECT i.id, i.type, i.status, i.created_at, u.id as to_id, u.name as to_name, u.role as to_role, u.avatar as to_avatar FROM invitations i JOIN users u ON u.id = i.to_user_id WHERE i.from_user_id = $1 AND i.status = 'pending' ORDER BY i.id DESC`, [me])).rows;
  res.json({ ok: true, incoming, outgoing });
});

app.post('/invitations/:id/accept', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const inv = (await pool.query('SELECT * FROM invitations WHERE id = $1', [req.params.id])).rows[0];
  if (!inv) return res.json({ ok: false, error: 'Не найдена' });
  if (inv.to_user_id !== req.session.userId) return res.json({ ok: false });
  if (inv.status !== 'pending') return res.json({ ok: false });
  if (await isBlockedBetween(inv.from_user_id, inv.to_user_id)) return res.json({ ok: false });
  if (inv.type === 'private') {
    const existing = (await pool.query(`SELECT c.id FROM chats c JOIN chat_members m1 ON m1.chat_id = c.id AND m1.user_id = $1 JOIN chat_members m2 ON m2.chat_id = c.id AND m2.user_id = $2 WHERE c.type = 'private'`, [inv.from_user_id, inv.to_user_id])).rows[0];
    let chatId;
    if (existing) chatId = existing.id;
    else {
      const chatInfo = (await pool.query("INSERT INTO chats (type) VALUES ('private') RETURNING id")).rows[0];
      chatId = chatInfo.id;
      await pool.query('INSERT INTO chat_members (chat_id, user_id) VALUES ($1, $2)', [chatId, inv.from_user_id]);
      await pool.query('INSERT INTO chat_members (chat_id, user_id) VALUES ($1, $2)', [chatId, inv.to_user_id]);
    }
    await pool.query('UPDATE invitations SET status = $1 WHERE id = $2', ['accepted', inv.id]);
    io.emit('invitation_accepted', { fromUserId: inv.from_user_id, toUserId: inv.to_user_id, chatId });
    res.json({ ok: true, chatId });
  } else {
    await pool.query('UPDATE invitations SET status = $1 WHERE id = $2', ['accepted', inv.id]);
    res.json({ ok: true });
  }
});

app.post('/invitations/:id/decline', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const inv = (await pool.query('SELECT * FROM invitations WHERE id = $1', [req.params.id])).rows[0];
  if (!inv || inv.to_user_id !== req.session.userId) return res.json({ ok: false });
  await pool.query('UPDATE invitations SET status = $1 WHERE id = $2', ['declined', inv.id]);
  io.emit('invitation_declined', { fromUserId: inv.from_user_id, toUserId: inv.to_user_id });
  res.json({ ok: true });
});

app.post('/invitations/:id/cancel', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const inv = (await pool.query('SELECT * FROM invitations WHERE id = $1', [req.params.id])).rows[0];
  if (!inv || inv.from_user_id !== req.session.userId) return res.json({ ok: false });
  await pool.query('UPDATE invitations SET status = $1 WHERE id = $2', ['cancelled', inv.id]);
  res.json({ ok: true });
});

// ===== ЛИЧНЫЙ ЧАТ БЕЗ ЗАЯВОК =====
app.post('/chats/private/direct', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = (await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId])).rows[0];
  if (!me || me.role !== 'creator') return res.json({ ok: false, error: 'Только для админа' });
  const { userId } = req.body;
  if (!userId) return res.json({ ok: false });
  const existing = (await pool.query(`SELECT c.id FROM chats c JOIN chat_members m1 ON m1.chat_id = c.id AND m1.user_id = $1 JOIN chat_members m2 ON m2.chat_id = c.id AND m2.user_id = $2 WHERE c.type = 'private'`, [req.session.userId, userId])).rows[0];
  if (existing) return res.json({ ok: true, chatId: existing.id, alreadyExists: true });
  const info = (await pool.query("INSERT INTO chats (type) VALUES ('private') RETURNING id")).rows[0];
  const chatId = info.id;
  await pool.query('INSERT INTO chat_members (chat_id, user_id) VALUES ($1, $2)', [chatId, req.session.userId]);
  await pool.query('INSERT INTO chat_members (chat_id, user_id) VALUES ($1, $2)', [chatId, userId]);
  io.emit('new_chat_for_user', { userId: userId, chatId: chatId });
  res.json({ ok: true, chatId });
});

// ===== ЧАТЫ =====
app.post('/chats/group', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const { name, userIds } = req.body;
  if (!name || !name.trim()) return res.json({ ok: false, error: 'Введи название' });
  const cleanName = sanitize(name, 50);
  if (cleanName.length < 2) return res.json({ ok: false, error: 'Название короткое' });

  const info = (await pool.query("INSERT INTO chats (type, name) VALUES ('group', $1) RETURNING id", [cleanName])).rows[0];
  const chatId = info.id;
  await pool.query('INSERT INTO chat_members (chat_id, user_id) VALUES ($1, $2)', [chatId, req.session.userId]);

  if (Array.isArray(userIds)) {
    for (const uid of userIds) {
      if (uid && uid !== req.session.userId) {
        try { await pool.query('INSERT INTO chat_members (chat_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [chatId, uid]); } catch(e) {}
      }
    }
  }
  res.json({ ok: true, chatId });
});

app.post('/chats/:id/avatar', avatarUpload.single('avatar'), async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  if (!req.file) return res.json({ ok: false, error: 'Файл не загружен' });
  const chatId = req.params.id;
  const me = req.session.userId;
  const inChat = (await pool.query('SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2', [chatId, me])).rows[0];
  if (!inChat) return res.json({ ok: false, error: 'Нет доступа' });
  const chat = (await pool.query('SELECT type FROM chats WHERE id = $1', [chatId])).rows[0];
  if (!chat || chat.type !== 'group') return res.json({ ok: false, error: 'Только группы' });
  const isCreator = (await pool.query('SELECT role FROM users WHERE id = $1', [me])).rows[0];
  const groupCreator = (await pool.query('SELECT user_id FROM chat_members WHERE chat_id = $1 ORDER BY user_id ASC LIMIT 1', [chatId])).rows[0];
  const canEdit = (groupCreator && groupCreator.user_id === me) || (isCreator && isCreator.role === 'creator');
  if (!canEdit) return res.json({ ok: false, error: 'Нет прав' });
  const oldAvatar = (await pool.query('SELECT avatar FROM chats WHERE id = $1', [chatId])).rows[0];
  if (oldAvatar && oldAvatar.avatar) {
    const oldPath = path.join(__dirname, 'public', oldAvatar.avatar.replace(/^\//, ''));
    if (fs.existsSync(oldPath)) try { fs.unlinkSync(oldPath); } catch(e) {}
  }
  const fileUrl = '/uploads/' + req.file.filename;
  await pool.query('UPDATE chats SET avatar = $1 WHERE id = $2', [fileUrl, chatId]);
  io.to('chat_' + chatId).emit('group_avatar_update', { chatId, avatar: fileUrl });
  res.json({ ok: true, avatar: fileUrl });
});

// ===== ПОКИНУТЬ ГРУППУ =====
app.post('/chats/:id/leave', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const chatId = req.params.id;
  const me = req.session.userId;
  const inChat = (await pool.query('SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2', [chatId, me])).rows[0];
  if (!inChat) return res.json({ ok: false, error: 'Ты не в группе' });
  const chat = (await pool.query('SELECT type FROM chats WHERE id = $1', [chatId])).rows[0];
  if (!chat || chat.type !== 'group') return res.json({ ok: false, error: 'Только для групп' });
  const groupCreator = (await pool.query('SELECT user_id FROM chat_members WHERE chat_id = $1 ORDER BY user_id ASC LIMIT 1', [chatId])).rows[0];
  const isCreator = groupCreator && groupCreator.user_id === me;
  await pool.query('DELETE FROM chat_members WHERE chat_id = $1 AND user_id = $2', [chatId, me]);
  if (isCreator) {
    const next = (await pool.query('SELECT user_id FROM chat_members WHERE chat_id = $1 ORDER BY user_id ASC LIMIT 1', [chatId])).rows[0];
    if (next) {
      io.to('chat_' + chatId).emit('group_creator_changed', { chatId, newCreatorId: next.user_id });
    } else {
      await pool.query('DELETE FROM messages WHERE chat_id = $1', [chatId]);
      await pool.query('DELETE FROM chats WHERE id = $1', [chatId]);
    }
  }
  io.to('chat_' + chatId).emit('member_left', { chatId, userId: me });
  res.json({ ok: true });
});

// ===== УДАЛИТЬ УЧАСТНИКА =====
app.post('/chats/:id/remove-member', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const chatId = req.params.id;
  const me = req.session.userId;
  const { userId } = req.body;
  if (!userId) return res.json({ ok: false, error: 'Не выбран участник' });
  if (userId === me) return res.json({ ok: false, error: 'Себя нельзя' });
  const inChat = (await pool.query('SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2', [chatId, me])).rows[0];
  if (!inChat) return res.json({ ok: false, error: 'Ты не в группе' });
  const chat = (await pool.query('SELECT type FROM chats WHERE id = $1', [chatId])).rows[0];
  if (!chat || chat.type !== 'group') return res.json({ ok: false, error: 'Только для групп' });
  const groupCreator = (await pool.query('SELECT user_id FROM chat_members WHERE chat_id = $1 ORDER BY user_id ASC LIMIT 1', [chatId])).rows[0];
  const isCreator = groupCreator && groupCreator.user_id === me;
  if (!isCreator) return res.json({ ok: false, error: 'Только создатель может удалять' });
  const target = (await pool.query('SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2', [chatId, userId])).rows[0];
  if (!target) return res.json({ ok: false, error: 'Пользователь не в группе' });
  await pool.query('DELETE FROM chat_members WHERE chat_id = $1 AND user_id = $2', [chatId, userId]);
  io.to('chat_' + chatId).emit('member_removed', { chatId, userId: userId });
  res.json({ ok: true });
});

// ===== УДАЛИТЬ ГРУППУ =====
app.delete('/chats/:id', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const chatId = req.params.id;
  const me = req.session.userId;
  const inChat = (await pool.query('SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2', [chatId, me])).rows[0];
  if (!inChat) return res.json({ ok: false, error: 'Нет доступа' });
  const chat = (await pool.query('SELECT type FROM chats WHERE id = $1', [chatId])).rows[0];
  if (!chat || chat.type !== 'group') return res.json({ ok: false, error: 'Только для групп' });
  const groupCreator = (await pool.query('SELECT user_id FROM chat_members WHERE chat_id = $1 ORDER BY user_id ASC LIMIT 1', [chatId])).rows[0];
  const isCreator = groupCreator && groupCreator.user_id === me;
  if (!isCreator) return res.json({ ok: false, error: 'Только создатель может удалить' });
  const msgs = (await pool.query("SELECT file_url FROM messages WHERE chat_id = $1 AND file_url != ''", [chatId])).rows;
  for (const m of msgs) {
    const fp = path.join(__dirname, 'public', m.file_url.replace(/^\//, ''));
    if (fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch(e) {}
  }
  await pool.query('DELETE FROM message_reads WHERE message_id IN (SELECT id FROM messages WHERE chat_id = $1)', [chatId]);
  await pool.query('DELETE FROM messages WHERE chat_id = $1', [chatId]);
  await pool.query('DELETE FROM chat_members WHERE chat_id = $1', [chatId]);
  await pool.query('DELETE FROM chats WHERE id = $1', [chatId]);
  io.to('chat_' + chatId).emit('group_deleted', { chatId });
  log('GROUP', `Удалена группа #${chatId} пользователем #${me}`);
  res.json({ ok: true });
});

app.post('/chats/:id/add-members', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const chatId = req.params.id;
  const me = req.session.userId;
  const { userIds } = req.body;
  if (!userIds || userIds.length === 0) return res.json({ ok: false, error: 'Не выбраны' });
  const inChat = (await pool.query('SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2', [chatId, me])).rows[0];
  if (!inChat) return res.json({ ok: false, error: 'Нет доступа' });
  const chat = (await pool.query('SELECT type FROM chats WHERE id = $1', [chatId])).rows[0];
  if (!chat || chat.type !== 'group') return res.json({ ok: false, error: 'Только группы' });
  const isCreator = (await pool.query('SELECT role FROM users WHERE id = $1', [me])).rows[0];
  const groupCreator = (await pool.query('SELECT user_id FROM chat_members WHERE chat_id = $1 ORDER BY user_id ASC LIMIT 1', [chatId])).rows[0];
  const canAdd = (groupCreator && groupCreator.user_id === me) || (isCreator && isCreator.role === 'creator');
  if (!canAdd) return res.json({ ok: false, error: 'Нет прав' });
  let added = [];
  for (const uid of userIds) {
    try {
      const exists = (await pool.query('SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2', [chatId, uid])).rows[0];
      if (!exists) {
        await pool.query('INSERT INTO chat_members (chat_id, user_id) VALUES ($1, $2)', [chatId, uid]);
        added.push(uid);
      }
    } catch(e) {}
  }
  io.emit('new_group_member', { chatId, userIds: added });
  res.json({ ok: true, added });
});

// ===== СИНХРОНИЗАЦИЯ КОНТАКТОВ =====
app.post('/contacts/sync', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = req.session.userId;
  const { phones } = req.body;
  if (!Array.isArray(phones) || phones.length === 0) return res.json({ ok: false, error: 'Нет номеров' });
  const cleanPhones = phones.map(p => cleanPhone(p)).filter(p => isValidPhone(p)).slice(0, 500);
  if (cleanPhones.length === 0) return res.json({ ok: false, error: 'Нет валидных номеров' });
  const placeholders = cleanPhones.map((_, i) => `$${i + 1}`).join(',');
  const matched = (await pool.query(`
    SELECT id, name, phone, avatar, role, status
    FROM users
    WHERE phone IN (${placeholders})
      AND id != $${cleanPhones.length + 1}
      AND banned = 0
  `, [...cleanPhones, me])).rows;
  const filtered = [];
  for (const u of matched) {
    if (!(await isBlocked(me, u.id))) filtered.push(u);
  }
  log('CONTACTS', `Синхронизация: ${cleanPhones.length} номеров → найдено ${filtered.length}`);
  res.json({ ok: true, matched: filtered });
});

app.get('/chats/:id/members', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const chatId = req.params.id;
  const inChat = (await pool.query('SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2', [chatId, req.session.userId])).rows[0];
  if (!inChat) return res.json({ ok: false });
  const members = (await pool.query(`
    SELECT u.id, u.name, u.role, u.avatar, u.status
    FROM users u JOIN chat_members m ON m.user_id = u.id
    WHERE m.chat_id = $1
  `, [chatId])).rows;
  res.json({ ok: true, members });
});

app.get('/chats/:id/members-info', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const chatId = req.params.id;
  const me = req.session.userId;
  const inChat = (await pool.query('SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2', [chatId, me])).rows[0];
  if (!inChat) return res.json({ ok: false });
  const chat = (await pool.query('SELECT type FROM chats WHERE id = $1', [chatId])).rows[0];
  if (!chat || chat.type !== 'group') return res.json({ ok: false });
  const groupCreator = (await pool.query('SELECT user_id FROM chat_members WHERE chat_id = $1 ORDER BY user_id ASC LIMIT 1', [chatId])).rows[0];
  const isCreatorMe = groupCreator && groupCreator.user_id === me;
  const members = (await pool.query(`
    SELECT u.id, u.name, u.role, u.avatar, u.status
    FROM users u JOIN chat_members m ON m.user_id = u.id
    WHERE m.chat_id = $1
  `, [chatId])).rows;
  res.json({ ok: true, members, isCreatorMe, creatorId: groupCreator ? groupCreator.user_id : null });
});

app.get('/chats', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = req.session.userId;
  await ensureSavedChat(me);
  const chats = (await pool.query(`SELECT c.id, c.type, c.name, c.avatar FROM chats c JOIN chat_members m ON m.chat_id = c.id WHERE m.user_id = $1 ORDER BY CASE c.type WHEN 'saved' THEN 0 ELSE 1 END, c.id DESC`, [me])).rows;
  const result = [];
  for (const c of chats) {
    if (c.type === 'saved') {
      result.push({ id: c.id, type: 'saved', title: 'Избранное', role: 'user', otherId: null, status: 'Заметки для себя', avatar: '', blocked: false, online: false, last_seen: null });
    } else if (c.type === 'private') {
      const other = (await pool.query(`SELECT u.id, u.name, u.role, u.status, u.avatar, u.last_seen FROM users u JOIN chat_members m ON m.user_id = u.id WHERE m.chat_id = $1 AND u.id != $2`, [c.id, me])).rows[0];
      let blocked = false;
      if (other) blocked = await isBlocked(me, other.id);
      const isOnline = other ? onlineUsers.has(other.id) : false;
      const canSeeOnline = other ? await canSee(me, other.id, 'online') : false;
      const canSeeLastSeen = other ? await canSee(me, other.id, 'last_seen') : false;
      result.push({
        id: c.id, type: c.type,
        title: other ? other.name : 'Личный чат',
        role: other ? other.role : 'user',
        otherId: other ? other.id : null,
        status: other ? other.status : '',
        avatar: other ? other.avatar : '',
        blocked,
        online: canSeeOnline ? isOnline : false,
        last_seen: canSeeLastSeen && other ? other.last_seen : null
      });
    } else {
      result.push({ id: c.id, type: c.type, title: c.name || 'Группа', role: 'group', otherId: null, status: '', avatar: c.avatar || '', blocked: false, online: false, last_seen: null });
    }
  }
  res.json({ ok: true, chats: result });
});

app.get('/chats/:id/messages', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const chatId = req.params.id;
  const me = req.session.userId;
  const inChat = (await pool.query('SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2', [chatId, me])).rows[0];
  if (!inChat) return res.json({ ok: false });
  const msgs = (await pool.query(`SELECT m.id, m.name, m.text, m.created_at, m.msg_type, m.file_url, m.file_name, m.file_size, m.file_mime, m.deleted, m.deleted_for, m.user_id, m.delivered, u.role, u.status, u.avatar FROM messages m LEFT JOIN users u ON u.id = m.user_id WHERE m.chat_id = $1 ORDER BY m.id ASC LIMIT 200`, [chatId])).rows;
  const filtered = [];
  for (const m of msgs) {
    if (m.deleted) continue;
    const deletedFor = m.deleted_for ? m.deleted_for.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n)) : [];
    if (deletedFor.includes(me)) continue;
    const readBy = (await pool.query('SELECT COUNT(*) as c FROM message_reads WHERE message_id = $1', [m.id])).rows[0].c;
    filtered.push({ ...m, text: decrypt(m.text), readBy: parseInt(readBy) });
  }
  res.json({ ok: true, messages: filtered });
});

// ===== ДОСТАВЛЕНО И ПРОЧИТАНО =====
app.post('/messages/:id/delivered', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const msg = (await pool.query('SELECT * FROM messages WHERE id = $1', [req.params.id])).rows[0];
  if (!msg || msg.user_id === req.session.userId) return res.json({ ok: false });
  const inChat = (await pool.query('SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2', [msg.chat_id, req.session.userId])).rows[0];
  if (!inChat) return res.json({ ok: false });
  await pool.query('UPDATE messages SET delivered = 1 WHERE id = $1', [msg.id]);
  io.to('chat_' + msg.chat_id).emit('message_delivered', { messageId: msg.id, chatId: msg.chat_id });
  res.json({ ok: true });
});

app.post('/messages/:id/read', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const msg = (await pool.query('SELECT * FROM messages WHERE id = $1', [req.params.id])).rows[0];
  if (!msg || msg.user_id === req.session.userId) return res.json({ ok: false });
  const inChat = (await pool.query('SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2', [msg.chat_id, req.session.userId])).rows[0];
  if (!inChat) return res.json({ ok: false });
  const canSeeRR = await canSeeReadReceipt(msg.user_id, req.session.userId);
  await pool.query('INSERT INTO message_reads (message_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [msg.id, req.session.userId]);
  await pool.query('UPDATE messages SET delivered = 1 WHERE id = $1', [msg.id]);
  if (canSeeRR) {
    io.to('chat_' + msg.chat_id).emit('message_read', { messageId: msg.id, chatId: msg.chat_id, userId: req.session.userId });
  }
  res.json({ ok: true });
});

app.post('/chats/:id/read-all', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const chatId = req.params.id;
  const me = req.session.userId;
  const inChat = (await pool.query('SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2', [chatId, me])).rows[0];
  if (!inChat) return res.json({ ok: false });
  const msgs = (await pool.query('SELECT id FROM messages WHERE chat_id = $1 AND user_id != $2 AND deleted = 0', [chatId, me])).rows;
  for (const m of msgs) {
    await pool.query('INSERT INTO message_reads (message_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [m.id, me]);
  }
  await pool.query('UPDATE messages SET delivered = 1 WHERE chat_id = $1 AND user_id != $2', [chatId, me]);
  io.to('chat_' + chatId).emit('messages_read_all', { chatId, userId: me });
  res.json({ ok: true });
});

app.get('/messages/:id/readers', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const msg = (await pool.query('SELECT * FROM messages WHERE id = $1', [req.params.id])).rows[0];
  if (!msg || msg.user_id !== req.session.userId) return res.json({ ok: false });
  const readers = (await pool.query(`SELECT u.id, u.name, u.role, u.avatar, r.read_at FROM message_reads r JOIN users u ON u.id = r.user_id WHERE r.message_id = $1 ORDER BY r.read_at ASC`, [req.params.id])).rows;
  res.json({ ok: true, readers });
});

// ===== ЗАГРУЗКА ФАЙЛА =====
app.post('/chats/:id/upload', upload.single('file'), async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  if (!req.file) return res.json({ ok: false, error: 'Файл не загружен' });
  const chatId = req.params.id;
  const inChat = (await pool.query('SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2', [chatId, req.session.userId])).rows[0];
  if (!inChat) return res.json({ ok: false });
  const user = (await pool.query('SELECT name, role, banned, status, avatar FROM users WHERE id = $1', [req.session.userId])).rows[0];
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
  const info = (await pool.query(`INSERT INTO messages (chat_id, user_id, name, text, msg_type, file_url, file_name, file_size, file_mime) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`, [chatId, req.session.userId, user.name, text, msgType, fileUrl, fileName, fileSize, fileMime])).rows[0];
  const msg = { id: info.id, chatId, userId: req.session.userId, name: user.name, role: user.role, text: decrypt(text), status: user.status, avatar: user.avatar, msgType, fileUrl, fileName, fileSize, fileMime, time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }), readBy: 0, delivered: 0 };
  io.to('chat_' + chatId).emit('message', msg);
  res.json({ ok: true, message: msg });
});

// ===== СТИКЕРЫ =====
app.post('/stickers/upload', upload.single('file'), async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  if (!req.file) return res.json({ ok: false });
  const fileUrl = '/uploads/' + req.file.filename;
  const emoji = sanitize(req.body.emoji, 10);
  const info = (await pool.query('INSERT INTO stickers (user_id, file_url, emoji) VALUES ($1, $2, $3) RETURNING id', [req.session.userId, fileUrl, emoji])).rows[0];
  res.json({ ok: true, sticker: { id: info.id, file_url: fileUrl, emoji } });
});

app.get('/stickers', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const stickers = (await pool.query('SELECT id, file_url, emoji FROM stickers WHERE user_id = $1 ORDER BY id DESC', [req.session.userId])).rows;
  res.json({ ok: true, stickers });
});

app.delete('/stickers/:id', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const sticker = (await pool.query('SELECT * FROM stickers WHERE id = $1', [req.params.id])).rows[0];
  if (!sticker || sticker.user_id !== req.session.userId) return res.json({ ok: false });
  const fp = path.join(__dirname, 'public', sticker.file_url.replace(/^\//, ''));
  if (fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch(e) {}
  await pool.query('DELETE FROM stickers WHERE id = $1', [sticker.id]);
  res.json({ ok: true });
});

// ===== УДАЛЕНИЕ СООБЩЕНИЙ =====
app.post('/messages/:id/delete-for-me', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const msg = (await pool.query('SELECT * FROM messages WHERE id = $1', [req.params.id])).rows[0];
  if (!msg) return res.json({ ok: false });
  const inChat = (await pool.query('SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2', [msg.chat_id, req.session.userId])).rows[0];
  if (!inChat) return res.json({ ok: false });
  const list = msg.deleted_for ? msg.deleted_for.split(',').map(s => s.trim()).filter(s => s) : [];
  if (!list.includes(String(req.session.userId))) list.push(String(req.session.userId));
  await pool.query('UPDATE messages SET deleted_for = $1 WHERE id = $2', [list.join(','), msg.id]);
  res.json({ ok: true });
});

app.post('/messages/:id/delete-for-all', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const msg = (await pool.query('SELECT * FROM messages WHERE id = $1', [req.params.id])).rows[0];
  if (!msg) return res.json({ ok: false });
  const inChat = (await pool.query('SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2', [msg.chat_id, req.session.userId])).rows[0];
  if (!inChat) return res.json({ ok: false });
  const me = (await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId])).rows[0];
  const isCreator = me && me.role === 'creator';
  const isMine = msg.user_id === req.session.userId;
  if (!isMine && !isCreator) return res.json({ ok: false });
  if (msg.file_url) {
    const fp = path.join(__dirname, 'public', msg.file_url.replace(/^\//, ''));
    if (fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch(e) {}
  }
  await pool.query('UPDATE messages SET deleted = 1 WHERE id = $1', [msg.id]);
  io.to('chat_' + msg.chat_id).emit('message_deleted', { messageId: msg.id, chatId: msg.chat_id });
  res.json({ ok: true });
});

// ===== ИСТОРИИ =====
app.post('/stories/upload', upload.single('file'), async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  if (!req.file) return res.json({ ok: false });
  const type = req.file.mimetype.startsWith('video') ? 'video' : 'photo';
  const fileUrl = '/uploads/' + req.file.filename;
  const caption = sanitize(req.body.caption, 200);
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const info = (await pool.query('INSERT INTO stories (user_id, type, file_url, caption, expires_at) VALUES ($1, $2, $3, $4, $5) RETURNING id', [req.session.userId, type, fileUrl, caption, expiresAt])).rows[0];
  io.emit('new_story');
  res.json({ ok: true, storyId: info.id });
});

app.get('/stories', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = req.session.userId;
  const now = new Date().toISOString();
  const stories = (await pool.query(`SELECT s.id, s.user_id, s.type, s.file_url, s.caption, s.created_at, u.name, u.role, u.avatar FROM stories s JOIN users u ON u.id = s.user_id WHERE s.expires_at > $1 ORDER BY s.created_at DESC`, [now])).rows;
  const byUser = {};
  for (const s of stories) {
    if (!byUser[s.user_id]) byUser[s.user_id] = { userId: s.user_id, userName: s.name, userRole: s.role, userAvatar: s.avatar, stories: [] };
    const views = (await pool.query('SELECT COUNT(*) as c FROM story_views WHERE story_id = $1', [s.id])).rows[0].c;
    const viewedByMe = (await pool.query('SELECT 1 FROM story_views WHERE story_id = $1 AND viewer_id = $2', [s.id, me])).rows[0] ? true : false;
    byUser[s.user_id].stories.push({ id: s.id, type: s.type, fileUrl: s.file_url, caption: s.caption, createdAt: s.created_at, views: parseInt(views), viewed: viewedByMe });
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

app.post('/stories/:id/view', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  try {
    await pool.query('INSERT INTO story_views (story_id, viewer_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [req.params.id, req.session.userId]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false }); }
});

app.delete('/stories/:id', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const story = (await pool.query('SELECT * FROM stories WHERE id = $1', [req.params.id])).rows[0];
  if (!story) return res.json({ ok: false });
  const me = (await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId])).rows[0];
  if (story.user_id !== req.session.userId && (!me || me.role !== 'creator')) return res.json({ ok: false });
  const fp = path.join(__dirname, 'public', story.file_url.replace(/^\//, ''));
  if (fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch(e) {}
  await pool.query('DELETE FROM stories WHERE id = $1', [story.id]);
  await pool.query('DELETE FROM story_views WHERE story_id = $1', [story.id]);
  io.emit('new_story');
  res.json({ ok: true });
});

app.get('/stories/:id/viewers', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const story = (await pool.query('SELECT user_id FROM stories WHERE id = $1', [req.params.id])).rows[0];
  if (!story || story.user_id !== req.session.userId) return res.json({ ok: false });
  const viewers = (await pool.query(`SELECT u.name, u.role, u.avatar, v.viewed_at FROM story_views v JOIN users u ON u.id = v.viewer_id WHERE v.story_id = $1 ORDER BY v.viewed_at DESC`, [req.params.id])).rows;
  res.json({ ok: true, viewers });
});

// ===== АДМИНКА =====
app.post('/admin/check', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = (await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId])).rows[0];
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  if (req.body.password !== ADMIN_PASSWORD) { addAttempt(req.ip); return res.json({ ok: false, error: 'Неверный пароль' }); }
  res.json({ ok: true });
});

app.get('/admin/users', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = (await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId])).rows[0];
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const users = (await pool.query('SELECT id, name, phone, role, banned, status, avatar, created_at FROM users ORDER BY id')).rows;
  const stats = {
    users: parseInt((await pool.query('SELECT COUNT(*) as c FROM users')).rows[0].c),
    chats: parseInt((await pool.query('SELECT COUNT(*) as c FROM chats')).rows[0].c),
    messages: parseInt((await pool.query('SELECT COUNT(*) as c FROM messages WHERE deleted = 0')).rows[0].c),
    stories: parseInt((await pool.query('SELECT COUNT(*) as c FROM stories')).rows[0].c),
    blocks: parseInt((await pool.query('SELECT COUNT(*) as c FROM blocks')).rows[0].c),
    news: parseInt((await pool.query('SELECT COUNT(*) as c FROM news')).rows[0].c)
  };
  res.json({ ok: true, users, stats });
});

app.post('/admin/ban', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = (await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId])).rows[0];
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const { userId, banned } = req.body;
  if (userId === req.session.userId) return res.json({ ok: false });
  await pool.query('UPDATE users SET banned = $1 WHERE id = $2', [banned ? 1 : 0, userId]);
  res.json({ ok: true });
});

app.get('/admin/blocks', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = (await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId])).rows[0];
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const blocks = (await pool.query(`SELECT b.created_at, u1.id as blocker_id, u1.name as blocker_name, u1.avatar as blocker_avatar, u2.id as blocked_id, u2.name as blocked_name, u2.avatar as blocked_avatar FROM blocks b JOIN users u1 ON u1.id = b.blocker_id JOIN users u2 ON u2.id = b.blocked_id ORDER BY b.created_at DESC`)).rows;
  res.json({ ok: true, blocks });
});

app.post('/admin/unblock', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = (await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId])).rows[0];
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const { blockerId, blockedId } = req.body;
  await pool.query('DELETE FROM blocks WHERE blocker_id = $1 AND blocked_id = $2', [blockerId, blockedId]);
  io.emit('block_update', {});
  res.json({ ok: true });
});

app.get('/admin/statuses', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = (await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId])).rows[0];
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const statuses = (await pool.query('SELECT id, emoji, text FROM custom_statuses ORDER BY id ASC')).rows;
  res.json({ ok: true, statuses });
});

app.post('/admin/statuses', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = (await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId])).rows[0];
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const emoji = sanitize(req.body.emoji, 10);
  const text = sanitize(req.body.text, 50);
  if (!text) return res.json({ ok: false });
  const info = (await pool.query('INSERT INTO custom_statuses (emoji, text) VALUES ($1, $2) RETURNING id', [emoji, text])).rows[0];
  res.json({ ok: true, id: info.id });
});

app.delete('/admin/statuses/:id', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = (await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId])).rows[0];
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  await pool.query('DELETE FROM custom_statuses WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

app.post('/admin/give-status', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = (await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId])).rows[0];
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const { userId, status } = req.body;
  if (!userId) return res.json({ ok: false });
  await pool.query('UPDATE users SET status = $1 WHERE id = $2', [sanitize(status, 100), userId]);
  io.emit('avatar_update', {});
  res.json({ ok: true });
});

app.get('/admin/chats', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = (await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId])).rows[0];
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const chats = (await pool.query(`SELECT c.id, c.type, c.name, (SELECT STRING_AGG(u.name, ', ') FROM chat_members m JOIN users u ON u.id = m.user_id WHERE m.chat_id = c.id) as members FROM chats c WHERE c.type != 'saved' ORDER BY c.id DESC`)).rows;
  res.json({ ok: true, chats });
});

app.get('/admin/chats/:id', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = (await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId])).rows[0];
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const msgs = (await pool.query(`SELECT m.name, m.text, m.created_at, m.msg_type, m.file_url, m.file_name, u.role FROM messages m LEFT JOIN users u ON u.id = m.user_id WHERE m.chat_id = $1 AND m.deleted = 0 ORDER BY m.id ASC`, [req.params.id])).rows;
  res.json({ ok: true, messages: msgs.map(m => ({...m, text: decrypt(m.text)})) });
});

app.get('/admin/stories', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = (await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId])).rows[0];
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const stories = (await pool.query(`SELECT s.id, s.user_id, s.type, s.file_url, s.caption, s.created_at, u.name, u.role, (SELECT COUNT(*) FROM story_views WHERE story_id = s.id) as views FROM stories s JOIN users u ON u.id = s.user_id ORDER BY s.created_at DESC`)).rows;
  res.json({ ok: true, stories });
});

app.get('/admin/news', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = (await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId])).rows[0];
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const now = new Date().toISOString();
  const news = (await pool.query(`SELECT n.id, n.title, n.text, n.delay, n.for_new, n.created_at, n.expires_at, CASE WHEN n.expires_at < $1 THEN 1 ELSE 0 END as expired, (SELECT COUNT(*) FROM news_read WHERE news_id = n.id) as read_count FROM news n ORDER BY n.id DESC`, [now])).rows;
  res.json({ ok: true, news });
});

app.post('/admin/news', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = (await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId])).rows[0];
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const title = sanitize(req.body.title, 100);
  const text = sanitize(req.body.text, 2000);
  let delay = parseInt(req.body.delay) || 3;
  if (delay < 0) delay = 0;
  if (delay > 30) delay = 30;
  const forNew = req.body.forNew ? 1 : 0;
  if (!title || !text) return res.json({ ok: false });
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  const info = (await pool.query('INSERT INTO news (title, text, delay, for_new, expires_at) VALUES ($1, $2, $3, $4, $5) RETURNING id', [title, text, delay, forNew, expiresAt])).rows[0];
  res.json({ ok: true, id: info.id });
});

app.delete('/admin/news/:id', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = (await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId])).rows[0];
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  await pool.query('DELETE FROM news WHERE id = $1', [req.params.id]);
  await pool.query('DELETE FROM news_read WHERE news_id = $1', [req.params.id]);
  res.json({ ok: true });
});

// ===== SOCKET.IO =====
io.on('connection', async (socket) => {
  const userId = parseInt(socket.handshake.query.userId);
  const name = socket.handshake.query.name || 'Аноним';
  const role = socket.handshake.query.role || 'user';
  socket.userId = userId;
  socket.userName = name;
  socket.userRole = role;

  if (userId) {
    onlineUsers.add(userId);
    io.emit('user_status', { userId, online: true });
  }

  const myChats = (await pool.query('SELECT chat_id FROM chat_members WHERE user_id = $1', [userId])).rows;
  myChats.forEach(c => socket.join('chat_' + c.chat_id));
  socket.on('join_chat', (chatId) => socket.join('chat_' + chatId));

  socket.on('message', async ({ chatId, text }) => {
    try {
      if (!chatId || !text || !text.trim()) return;
      const user = (await pool.query('SELECT banned, status, avatar FROM users WHERE id = $1', [userId])).rows[0];
      if (user && user.banned) return;
      const inChat = (await pool.query('SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2', [chatId, userId])).rows[0];
      if (!inChat) return;
      const chatInfo = (await pool.query('SELECT type FROM chats WHERE id = $1', [chatId])).rows[0];
      if (chatInfo && chatInfo.type === 'private') {
        const other = (await pool.query('SELECT user_id FROM chat_members WHERE chat_id = $1 AND user_id != $2', [chatId, userId])).rows[0];
        if (other && await isBlockedBetween(userId, other.user_id)) {
          socket.emit('blocked_message', { chatId });
          return;
        }
      }
      const cleanText = sanitize(text, 5000);
      const encrypted = encrypt(cleanText);
      const info = (await pool.query('INSERT INTO messages (chat_id, user_id, name, text, msg_type) VALUES ($1, $2, $3, $4, $5) RETURNING id', [chatId, userId, name, encrypted, 'text'])).rows[0];
      io.to('chat_' + chatId).emit('message', {
        id: info.id, chatId, userId, name, role, text: cleanText,
        msgType: 'text', status: user ? user.status : '', avatar: user ? user.avatar : '',
        time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }),
        readBy: 0, delivered: 0
      });
    } catch(e) { console.error('Socket message error:', e); }
  });

  socket.on('sticker', async ({ chatId, url, emoji }) => {
    try {
      if (!chatId) return;
      const user = (await pool.query('SELECT banned, status, avatar FROM users WHERE id = $1', [userId])).rows[0];
      if (user && user.banned) return;
      const inChat = (await pool.query('SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2', [chatId, userId])).rows[0];
      if (!inChat) return;
      let msgType, fileUrl, text;
      if (emoji) { msgType = 'text'; fileUrl = ''; text = emoji; }
      else if (url) { msgType = 'sticker'; fileUrl = url; text = ''; }
      else return;
      const encrypted = encrypt(text);
      const info = (await pool.query('INSERT INTO messages (chat_id, user_id, name, text, msg_type, file_url) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id', [chatId, userId, name, encrypted, msgType, fileUrl])).rows[0];
      io.to('chat_' + chatId).emit('message', {
        id: info.id, chatId, userId, name, role, text,
        msgType, fileUrl, status: user ? user.status : '', avatar: user ? user.avatar : '',
        time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }),
        readBy: 0, delivered: 0
      });
    } catch(e) { console.error('Socket sticker error:', e); }
  });

  socket.on('leave_group', ({ chatId }) => {
    socket.leave('chat_' + chatId);
  });

  socket.on('disconnect', async () => {
    if (userId) {
      onlineUsers.delete(userId);
      const now = new Date().toISOString();
      try {
        await pool.query('UPDATE users SET last_seen = $1 WHERE id = $2', [now, userId]);
      } catch(e) {}
      io.emit('user_status', { userId, online: false, last_seen: now });
    }
  });
});

// ===== ЗАПУСК =====
async function ensureAdmin() {
  const existing = (await pool.query('SELECT id FROM users WHERE phone = $1', [ADMIN_PHONE])).rows[0];
  if (existing) {
    await pool.query('UPDATE users SET role = $1 WHERE phone = $2', ['creator', ADMIN_PHONE]);
    await ensureSavedChat(existing.id);
    await ensurePrivacy(existing.id);
    log('ADMIN', 'Админ найден: ' + ADMIN_PHONE);
  } else {
    const hash = await bcrypt.hash('admin123', 10);
    const now = new Date().toISOString();
    const info = (await pool.query('INSERT INTO users (phone, password, name, role, created_at, last_seen) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id', [ADMIN_PHONE, hash, 'Superselester', 'creator', now, now])).rows[0];
    await ensureSavedChat(info.id);
    await ensurePrivacy(info.id);
    log('ADMIN', 'Админ создан: ' + ADMIN_PHONE);
  }
}

async function startServer() {
  try {
    await initDatabase();
    await ensureAdmin();
    await ensureWelcomeNews();
    await cleanExpiredStories();
    server.listen(PORT, () => {
      console.log('\n🔥 BLAZE запущен: http://localhost:' + PORT);
      console.log('🛡 Защита + галочки + авы + онлайн + конфиденциальность');
      console.log('🗄 База данных: PostgreSQL (Supabase)\n');
    });
  } catch(e) {
    console.error('❌ Ошибка запуска:', e);
    process.exit(1);
  }
}

startServer();