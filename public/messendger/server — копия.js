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

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT DEFAULT 'user'
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

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: 'secret-key-123',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// ===== РЕГИСТРАЦИЯ / ВХОД =====
app.post('/register', async (req, res) => {
  const { phone, password, name } = req.body;
  if (!phone || !password || !name) return res.json({ ok: false, error: 'Заполни все поля' });
  if (password.length < 4) return res.json({ ok: false, error: 'Пароль минимум 4 символа' });
  if (db.prepare('SELECT id FROM users WHERE phone = ?').get(phone)) {
    return res.json({ ok: false, error: 'Номер уже занят' });
  }
  const hash = await bcrypt.hash(password, 10);
  const role = (name.toLowerCase() === 'creator') ? 'creator' : 'user';
  const info = db.prepare('INSERT INTO users (phone, password, name, role) VALUES (?, ?, ?, ?)')
    .run(phone, hash, name, role);
  req.session.userId = info.lastInsertRowid;
  req.session.userName = name;
  req.session.role = role;
  res.json({ ok: true, name, role });
});

app.post('/login', async (req, res) => {
  const { phone, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE phone = ?').get(phone);
  if (!user) return res.json({ ok: false, error: 'Неверный номер или пароль' });
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
  res.json({ ok: true, id: req.session.userId, name: req.session.userName, role: req.session.role });
});

// ===== ПОЛЬЗОВАТЕЛИ =====
app.get('/users', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const users = db.prepare('SELECT id, name, role FROM users WHERE id != ?').all(req.session.userId);
  res.json({ ok: true, users });
});

// ===== СОЗДАТЬ ЛИЧНЫЙ ЧАТ =====
app.post('/chats/private', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const { userId } = req.body;
  if (!userId) return res.json({ ok: false, error: 'Не выбран пользователь' });

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

// ===== СОЗДАТЬ ГРУППУ =====
app.post('/chats/group', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const { name, userIds } = req.body;
  if (!name || !userIds || userIds.length === 0) {
    return res.json({ ok: false, error: 'Введите название и выберите участников' });
  }
  const info = db.prepare("INSERT INTO chats (type, name) VALUES ('group', ?)").run(name);
  const chatId = info.lastInsertRowid;
  db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(chatId, req.session.userId);
  for (const uid of userIds) {
    db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(chatId, uid);
  }
  res.json({ ok: true, chatId });
});

// ===== СПИСОК МОИХ ЧАТОВ =====
app.get('/chats', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = req.session.userId;

  const chats = db.prepare(`
    SELECT c.id, c.type, c.name
    FROM chats c
    JOIN chat_members m ON m.chat_id = c.id
    WHERE m.user_id = ?
    ORDER BY c.id DESC
  `).all(me);

  const result = chats.map(c => {
    if (c.type === 'private') {
      const other = db.prepare(`
        SELECT u.name, u.role FROM users u
        JOIN chat_members m ON m.user_id = u.id
        WHERE m.chat_id = ? AND u.id != ?
      `).get(c.id, me);
      return { id: c.id, type: c.type, title: other ? other.name : 'Личный чат', role: other ? other.role : 'user' };
    } else {
      return { id: c.id, type: c.type, title: c.name || 'Группа', role: 'group' };
    }
  });

  res.json({ ok: true, chats: result });
});

// ===== СООБЩЕНИЯ ЧАТА =====
app.get('/chats/:id/messages', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const chatId = req.params.id;

  const inChat = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?')
    .get(chatId, req.session.userId);
  if (!inChat) return res.json({ ok: false, error: 'Нет доступа' });

  const msgs = db.prepare(`
    SELECT m.name, m.text, m.created_at, u.role
    FROM messages m
    LEFT JOIN users u ON u.id = m.user_id
    WHERE m.chat_id = ?
    ORDER BY m.id ASC
    LIMIT 200
  `).all(chatId);

  res.json({ ok: true, messages: msgs });
});

// ===== SOCKET.IO =====
io.on('connection', (socket) => {
  const userId = parseInt(socket.handshake.query.userId);
  const name = socket.handshake.query.name || 'Аноним';
  const role = socket.handshake.query.role || 'user';

  socket.userId = userId;
  socket.userName = name;
  socket.userRole = role;

  const myChats = db.prepare('SELECT chat_id FROM chat_members WHERE user_id = ?').all(userId);
  myChats.forEach(c => socket.join('chat_' + c.chat_id));

  socket.on('join_chat', (chatId) => {
    socket.join('chat_' + chatId);
  });

  socket.on('message', ({ chatId, text }) => {
    if (!chatId || !text || !text.trim()) return;

    const inChat = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?')
      .get(chatId, userId);
    if (!inChat) return;

    db.prepare('INSERT INTO messages (chat_id, user_id, name, text) VALUES (?, ?, ?, ?)')
      .run(chatId, userId, name, text);

    io.to('chat_' + chatId).emit('message', {
      chatId,
      name,
      role,
      text,
      time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })
    });
  });

  socket.on('disconnect', () => {});
});

server.listen(3000, () => {
  console.log('✅ Сервер запущен: http://localhost:3000');
});