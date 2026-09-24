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

const ADMIN_PHONE = '+79266276629';
const ADMIN_PASSWORD = '18245091112';

function cleanPhone(phone) {
  let p = String(phone || '').replace(/[^\d+]/g, '');
  if (p.startsWith('8') && p.length === 11) p = '+7' + p.slice(1);
  return p;
}

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    banned INTEGER DEFAULT 0,
    status TEXT DEFAULT ''
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
try { db.exec('ALTER TABLE users ADD COLUMN status TEXT DEFAULT \'\''); } catch(e) {}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: 'blaze-secret-key-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// ===== РЕГИСТРАЦИЯ =====
app.post('/register', async (req, res) => {
  const { phone: rawPhone, password, name } = req.body;
  if (!rawPhone || !password || !name) return res.json({ ok: false, error: 'Заполни все поля' });
  if (password.length < 4) return res.json({ ok: false, error: 'Пароль минимум 4 символа' });

  const phone = cleanPhone(rawPhone);
  if (db.prepare('SELECT id FROM users WHERE phone = ?').get(phone)) {
    return res.json({ ok: false, error: 'Номер уже занят' });
  }

  const role = (phone === ADMIN_PHONE) ? 'creator' : 'user';
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
  const phone = cleanPhone(req.body.phone);
  const user = db.prepare('SELECT * FROM users WHERE phone = ?').get(phone);
  if (!user) return res.json({ ok: false, error: 'Неверный номер или пароль' });
  if (user.banned) return res.json({ ok: false, error: '🚫 Вы забанены' });

  const ok = await bcrypt.compare(req.body.password, user.password);
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
  const user = db.prepare('SELECT id, name, role, banned, status FROM users WHERE id = ?').get(req.session.userId);
  if (!user || user.banned) return res.json({ ok: false, banned: true });
  res.json({ ok: true, id: user.id, name: user.name, role: user.role, status: user.status });
});

// ===== УСТАНОВИТЬ СТАТУС =====
app.post('/set-status', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const { status } = req.body;
  const cleanStatus = String(status || '').slice(0, 100);
  db.prepare('UPDATE users SET status = ? WHERE id = ?').run(cleanStatus, req.session.userId);
  res.json({ ok: true, status: cleanStatus });
});

// ===== ПРОФИЛЬ ПОЛЬЗОВАТЕЛЯ =====
app.get('/user/:id', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const user = db.prepare('SELECT id, name, role, status FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.json({ ok: false, error: 'Не найден' });
  res.json({ ok: true, user });
});

// ===== УДАЛИТЬ АККАУНТ =====
app.post('/delete-account', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = req.session.userId;

  const myChats = db.prepare('SELECT chat_id FROM chat_members WHERE user_id = ?').all(me);
  for (const c of myChats) {
    db.prepare('DELETE FROM messages WHERE chat_id = ?').run(c.chat_id);
    db.prepare('DELETE FROM chat_members WHERE chat_id = ?').run(c.chat_id);
    db.prepare('DELETE FROM chats WHERE id = ?').run(c.chat_id);
  }
  db.prepare('DELETE FROM users WHERE id = ?').run(me);
  req.session.destroy();
  res.json({ ok: true });
});

// ===== ПОИСК =====
app.post('/search', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const phone = cleanPhone(req.body.phone);
  if (!phone) return res.json({ ok: false, error: 'Введи номер' });

  const found = db.prepare('SELECT id, name, role, phone, status FROM users WHERE phone = ? AND id != ?')
    .get(phone, req.session.userId);
  if (!found) return res.json({ ok: false, error: 'Пользователь не найден' });
  res.json({ ok: true, user: found });
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
        SELECT u.id, u.name, u.role, u.status FROM users u
        JOIN chat_members m ON m.user_id = u.id
        WHERE m.chat_id = ? AND u.id != ?
      `).get(c.id, me);
      return {
        id: c.id, type: c.type,
        title: other ? other.name : 'Личный чат',
        role: other ? other.role : 'user',
        otherId: other ? other.id : null,
        status: other ? other.status : ''
      };
    }
    return { id: c.id, type: c.type, title: c.name || 'Группа', role: 'group', otherId: null, status: '' };
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
    SELECT m.name, m.text, m.created_at, u.role, u.status FROM messages m
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

  const users = db.prepare('SELECT id, name, phone, role, banned, status FROM users ORDER BY id').all();
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
    const user = db.prepare('SELECT banned, status FROM users WHERE id = ?').get(userId);
    if (user && user.banned) return;

    const inChat = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').get(chatId, userId);
    if (!inChat) return;

    db.prepare('INSERT INTO messages (chat_id, user_id, name, text) VALUES (?, ?, ?, ?)').run(chatId, userId, name, text);
    io.to('chat_' + chatId).emit('message', {
      chatId, name, role, text,
      status: user ? user.status : '',
      time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })
    });
  });

  socket.on('disconnect', () => {});
});

// 👑 АВТО-АДМИН
function ensureAdmin() {
  const existing = db.prepare('SELECT id FROM users WHERE phone = ?').get(ADMIN_PHONE);
  if (existing) {
    db.prepare('UPDATE users SET role = ? WHERE phone = ?').run('creator', ADMIN_PHONE);
    console.log('✅ Админ найден: ' + ADMIN_PHONE);
  } else {
    bcrypt.hash('admin123', 10).then(hash => {
      db.prepare('INSERT INTO users (phone, password, name, role) VALUES (?, ?, ?, ?)')
        .run(ADMIN_PHONE, hash, 'Superselester', 'creator');
      console.log('✅ Админ создан: ' + ADMIN_PHONE);
    });
  }
}

server.listen(3000, () => {
  console.log('\n🔥 BLAZE запущен: http://localhost:3000');
  ensureAdmin();
});