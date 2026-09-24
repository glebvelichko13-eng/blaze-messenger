const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcrypt');
const session = require('express-session');
const Database = require('better-sqlite3');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const db = new Database('database.db');

// 👑 НАСТРОЙКИ ВЛАДЕЛЬЦА
const ADMIN_PHONE = '+79266276629';        // твой номер (никто не видит)
const ADMIN_PASSWORD = '18245091112';      // пароль для админ-панели

// Хранилище кодов подтверждения (в памяти)
const confirmCodes = {};

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    banned INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    name TEXT,
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
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

try { db.exec('ALTER TABLE users ADD COLUMN banned INTEGER DEFAULT 0'); } catch(e) {}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: 'blaze-secret-key-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// ===== ЗАПРОС КОДА =====
app.post('/send-code', (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.json({ ok: false, error: 'Введи номер' });

  // Код отправляется ТОЛЬКО для админского номера
  if (phone !== ADMIN_PHONE) {
    return res.json({ ok: false, error: 'Код не требуется' });
  }

  // Генерируем код (6 цифр)
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  confirmCodes[phone] = { code, expires: Date.now() + 5 * 60 * 1000 }; // 5 минут

  // Печатаем в консоль сервера
  console.log('\n========================================');
  console.log('🔐 КОД ПОДТВЕРЖДЕНИЯ');
  console.log('📱 Номер: ' + phone);
  console.log('🔑 Код:   ' + code);
  console.log('⏰ Действует 5 минут');
  console.log('========================================\n');

  res.json({ ok: true, message: 'Код отправлен в консоль сервера' });
});

// ===== РЕГИСТРАЦИЯ =====
app.post('/register', async (req, res) => {
  const { phone, password, name, code } = req.body;
  if (!phone || !password || !name) return res.json({ ok: false, error: 'Заполни все поля' });
  if (password.length < 4) return res.json({ ok: false, error: 'Пароль минимум 4 символа' });
  if (db.prepare('SELECT id FROM users WHERE phone = ?').get(phone)) {
    return res.json({ ok: false, error: 'Номер уже занят' });
  }

  // Проверка кода для админского номера
  let role = 'user';
  if (phone === ADMIN_PHONE) {
    if (!code) return res.json({ ok: false, error: 'Введи код подтверждения' });
    const stored = confirmCodes[phone];
    if (!stored) return res.json({ ok: false, error: 'Код не запрошен. Нажми «Получить код»' });
    if (stored.expires < Date.now()) {
      delete confirmCodes[phone];
      return res.json({ ok: false, error: 'Код истёк. Запроси новый' });
    }
    if (stored.code !== code) return res.json({ ok: false, error: 'Неверный код' });
    delete confirmCodes[phone];
    role = 'creator';
  }

  const hash = await bcrypt.hash(password, 10);
  const info = db.prepare('INSERT INTO users (phone, password, name, role) VALUES (?, ?, ?, ?)')
    .run(phone, hash, name, role);
  req.session.userId = info.lastInsertRowid;
  req.session.userName = name;
  req.session.role = role;
  res.json({ ok: true, name, role });
});

// ===== ВХОД =====
app.post('/login', async (req, res) => {
  const { phone, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE phone = ?').get(phone);
  if (!user) return res.json({ ok: false, error: 'Неверный номер или пароль' });
  if (user.banned) return res.json({ ok: false, error: '🚫 Вы забанены' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.json({ ok: false, error: 'Неверный номер или пароль' });
  req.session.userId = user.id;
  req.session.userName = user.name;
  req.session.role = user.role;
  res.json({ ok: true, name: user.name, role: user.role });
});

app.post('/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/me', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const user = db.prepare('SELECT id, name, role, banned FROM users WHERE id = ?').get(req.session.userId);
  if (!user || user.banned) return res.json({ ok: false, banned: true });
  res.json({ ok: true, id: user.id, name: user.name, role: user.role });
});

// ===== ПОИСК =====
app.post('/search', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const { phone } = req.body;
  if (!phone) return res.json({ ok: false, error: 'Введи номер' });
  const found = db.prepare('SELECT id, name, role, phone FROM users WHERE phone = ? AND id != ?')
    .get(phone, req.session.userId);
  if (!found) return res.json({ ok: false, error: 'Пользователь не найден' });
  res.json({ ok: true, user: found });
});

app.get('/all-users', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false, error: 'Нет доступа' });
  const users = db.prepare('SELECT id, name, phone, role, banned FROM users WHERE id != ?').all(req.session.userId);
  res.json({ ok: true, users });
});

// ===== ЛИЧНЫЙ ЧАТ =====
app.post('/chats/private', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const { userId } = req.body;
  if (!userId) return res.json({ ok: false });
  const me = req.session.userId;
  const existing = db.prepare(`
    SELECT c.id FROM chats c
    JOIN chat_members m1 ON m1.chat_id = c.id AND m1.user_id = ?
    JOIN chat_members m2 ON m2.chat_id = c.id AND m2.user_id = ?
    WHERE c.type = 'private'
  `).get(me, userId);
  if (existing) return res.json({ ok: true, chatId: existing.id });

  const info = db.prepare("INSERT INTO chats (type) VALUES ('private')").run();
  const chatId = info.lastInsertRowid;
  db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(chatId, me);
  db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(chatId, userId);
  res.json({ ok: true, chatId });
});

// ===== ГРУППА =====
app.post('/chats/group', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const { name, userIds } = req.body;
  if (!name || !userIds || userIds.length === 0) return res.json({ ok: false, error: 'Заполни' });
  const info = db.prepare("INSERT INTO chats (type, name) VALUES ('group', ?)").run(name);
  const chatId = info.lastInsertRowid;
  db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(chatId, req.session.userId);
  for (const uid of userIds) {
    db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(chatId, uid);
  }
  res.json({ ok: true, chatId });
});

// ===== МОИ ЧАТЫ =====
app.get('/chats', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = req.session.userId;
  const chats = db.prepare(`
    SELECT c.id, c.type, c.name FROM chats c
    JOIN chat_members m ON m.chat_id = c.id
    WHERE m.user_id = ? ORDER BY c.id DESC
  `).all(me);

  const result = chats.map(c => {
    if (c.type === 'private') {
      const other = db.prepare(`
        SELECT u.name, u.role FROM users u
        JOIN chat_members m ON m.user_id = u.id
        WHERE m.chat_id = ? AND u.id != ?
      `).get(c.id, me);
      return { id: c.id, type: c.type, title: other ? other.name : 'Личный чат', role: other ? other.role : 'user' };
    }
    return { id: c.id, type: c.type, title: c.name || 'Группа', role: 'group' };
  });
  res.json({ ok: true, chats: result });
});

app.get('/chats/:id/messages', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const chatId = req.params.id;
  const inChat = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?')
    .get(chatId, req.session.userId);
  if (!inChat) return res.json({ ok: false });
  const msgs = db.prepare(`
    SELECT m.name, m.text, m.created_at, u.role FROM messages m
    LEFT JOIN users u ON u.id = m.user_id
    WHERE m.chat_id = ? ORDER BY m.id ASC LIMIT 200
  `).all(chatId);
  res.json({ ok: true, messages: msgs });
});

// ===== АДМИНКА =====
app.post('/admin/check', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  if (req.body.password !== ADMIN_PASSWORD) return res.json({ ok: false, error: 'Неверный пароль' });
  res.json({ ok: true });
});

app.get('/admin/users', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const users = db.prepare('SELECT id, name, phone, role, banned FROM users ORDER BY id').all();
  const stats = {
    users: db.prepare('SELECT COUNT(*) as c FROM users').get().c,
    chats: db.prepare('SELECT COUNT(*) as c FROM chats').get().c,
    messages: db.prepare('SELECT COUNT(*) as c FROM messages').get().c
  };
  res.json({ ok: true, users, stats });
});

app.post('/admin/ban', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const { userId, banned } = req.body;
  if (userId === req.session.userId) return res.json({ ok: false, error: 'Себя нельзя' });
  db.prepare('UPDATE users SET banned = ? WHERE id = ?').run(banned ? 1 : 0, userId);
  res.json({ ok: true });
});

app.get('/admin/chats', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const chats = db.prepare(`
    SELECT c.id, c.type, c.name,
      (SELECT GROUP_CONCAT(u.name, ', ') FROM chat_members m
       JOIN users u ON u.id = m.user_id WHERE m.chat_id = c.id) as members
    FROM chats c ORDER BY c.id DESC
  `).all();
  res.json({ ok: true, chats });
});

app.get('/admin/chats/:id', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false });
  const msgs = db.prepare(`
    SELECT m.name, m.text, m.created_at, u.role FROM messages m
    LEFT JOIN users u ON u.id = m.user_id
    WHERE m.chat_id = ? ORDER BY m.id ASC
  `).all(req.params.id);
  res.json({ ok: true, messages: msgs });
});

// ===== SOCKET =====
io.on('connection', (socket) => {
  const userId = parseInt(socket.handshake.query.userId);
  const name = socket.handshake.query.name || 'Аноним';
  const role = socket.handshake.query.role || 'user';

  socket.userId = userId;
  socket.userName = name;
  socket.userRole = role;

  const myChats = db.prepare('SELECT chat_id FROM chat_members WHERE user_id = ?').all(userId);
  myChats.forEach(c => socket.join('chat_' + c.chat_id));

  socket.on('join_chat', (chatId) => socket.join('chat_' + chatId));

  socket.on('message', ({ chatId, text }) => {
    if (!chatId || !text || !text.trim()) return;
    const user = db.prepare('SELECT banned FROM users WHERE id = ?').get(userId);
    if (user && user.banned) return;
    const inChat = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').get(chatId, userId);
    if (!inChat) return;
    db.prepare('INSERT INTO messages (chat_id, user_id, name, text) VALUES (?, ?, ?, ?)').run(chatId, userId, name, text);
    io.to('chat_' + chatId).emit('message', {
      chatId, name, role, text,
      time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })
    });
  });

  socket.on('disconnect', () => {});
});

server.listen(3000, () => {
  console.log('\n🔥 BLAZE запущен: http://localhost:3000');
  console.log('👑 Админ-панель активирована\n');
});