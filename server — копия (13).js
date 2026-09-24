const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcrypt');
const session = require('express-session');
const Database = require('better-sqlite3');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

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

const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + '_' + Math.random().toString(36).slice(2, 8) + ext);
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
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
    msg_type TEXT DEFAULT 'text',
    file_url TEXT DEFAULT '',
    file_name TEXT DEFAULT '',
    file_size INTEGER DEFAULT 0,
    file_mime TEXT DEFAULT '',
    deleted INTEGER DEFAULT 0,
    deleted_for TEXT DEFAULT '',
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
`);

try { db.exec('ALTER TABLE users ADD COLUMN banned INTEGER DEFAULT 0'); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN status TEXT DEFAULT \'\''); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT \'\''); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN created_at DATETIME'); } catch(e) {}
try { db.exec('ALTER TABLE messages ADD COLUMN msg_type TEXT DEFAULT \'text\''); } catch(e) {}
try { db.exec('ALTER TABLE messages ADD COLUMN file_url TEXT DEFAULT \'\''); } catch(e) {}
try { db.exec('ALTER TABLE messages ADD COLUMN file_name TEXT DEFAULT \'\''); } catch(e) {}
try { db.exec('ALTER TABLE messages ADD COLUMN file_size INTEGER DEFAULT 0'); } catch(e) {}
try { db.exec('ALTER TABLE messages ADD COLUMN file_mime TEXT DEFAULT \'\''); } catch(e) {}
try { db.exec('ALTER TABLE messages ADD COLUMN deleted INTEGER DEFAULT 0'); } catch(e) {}
try { db.exec('ALTER TABLE messages ADD COLUMN deleted_for TEXT DEFAULT \'\''); } catch(e) {}

const statusCount = db.prepare('SELECT COUNT(*) as c FROM custom_statuses').get().c;
if (statusCount === 0) {
  const defaults = [
    { emoji: '🔥', text: 'Покоряю мир' },
    { emoji: '💼', text: 'На работе' },
    { emoji: '😴', text: 'Отдыхаю' },
    { emoji: '☕', text: 'Пью кофе' },
    { emoji: '🎮', text: 'Играю' },
    { emoji: '📚', text: 'Учусь' },
    { emoji: '🚫', text: 'Не беспокоить' }
  ];
  const insert = db.prepare('INSERT INTO custom_statuses (emoji, text) VALUES (?, ?)');
  defaults.forEach(s => insert.run(s.emoji, s.text));
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: 'blaze-secret-key-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

function ensureSavedChat(userId) {
  const existing = db.prepare(`
    SELECT c.id FROM chats c
    JOIN chat_members m ON m.chat_id = c.id
    WHERE c.type = 'saved' AND m.user_id = ?
  `).get(userId);
  if (existing) return existing.id;

  const info = db.prepare("INSERT INTO chats (type, name) VALUES ('saved', 'Избранное')").run();
  const chatId = info.lastInsertRowid;
  db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(chatId, userId);
  return chatId;
}

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
  const info = db.prepare('INSERT INTO users (phone, password, name, role, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(phone, hash, name, role, new Date().toISOString());

  ensureSavedChat(info.lastInsertRowid);

  req.session.userId = info.lastInsertRowid;
  req.session.userName = name;
  req.session.role = role;
  res.json({ ok: true, name, role });
});

app.post('/login', async (req, res) => {
  const phone = cleanPhone(req.body.phone);
  const user = db.prepare('SELECT * FROM users WHERE phone = ?').get(phone);
  if (!user) return res.json({ ok: false, error: 'Неверный номер или пароль' });
  if (user.banned) return res.json({ ok: false, error: '🚫 Вы забанены' });

  const ok = await bcrypt.compare(req.body.password, user.password);
  if (!ok) return res.json({ ok: false, error: 'Неверный номер или пароль' });

  ensureSavedChat(user.id);

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
  const user = db.prepare('SELECT id, name, role, banned, status, avatar FROM users WHERE id = ?').get(req.session.userId);
  if (!user || user.banned) return res.json({ ok: false, banned: true });
  ensureSavedChat(user.id);
  res.json({ ok: true, id: user.id, name: user.name, role: user.role, status: user.status, avatar: user.avatar });
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

  let status = String(req.body.status || '').slice(0, 100);

  if (!isCreator && status) {
    const cleanStatus = status.replace(/^[^\w\s]+\s*/, '').trim();
    const found = db.prepare('SELECT id FROM custom_statuses WHERE text = ?').get(cleanStatus);
    if (!found) return res.json({ ok: false, error: 'Такой статус не разрешён' });
  }

  db.prepare('UPDATE users SET status = ? WHERE id = ?').run(status, req.session.userId);
  res.json({ ok: true, status });
});

app.get('/user/:id', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const user = db.prepare('SELECT id, name, role, status, avatar FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.json({ ok: false, error: 'Не найден' });
  res.json({ ok: true, user });
});

app.post('/avatar/upload', avatarUpload.single('avatar'), (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  if (!req.file) return res.json({ ok: false, error: 'Файл не загружен' });

  const fileUrl = '/uploads/' + req.file.filename;
  const old = db.prepare('SELECT avatar FROM users WHERE id = ?').get(req.session.userId);
  if (old && old.avatar) {
    const oldPath = path.join(__dirname, 'public', old.avatar.replace(/^\//, ''));
    if (fs.existsSync(oldPath)) try { fs.unlinkSync(oldPath); } catch(e) {}
  }

  db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(fileUrl, req.session.userId);
  io.emit('avatar_update', { userId: req.session.userId, avatar: fileUrl });
  res.json({ ok: true, avatar: fileUrl });
});

app.delete('/avatar', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const old = db.prepare('SELECT avatar FROM users WHERE id = ?').get(req.session.userId);
  if (old && old.avatar) {
    const oldPath = path.join(__dirname, 'public', old.avatar.replace(/^\//, ''));
    if (fs.existsSync(oldPath)) try { fs.unlinkSync(oldPath); } catch(e) {}
  }
  db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run('', req.session.userId);
  io.emit('avatar_update', { userId: req.session.userId, avatar: '' });
  res.json({ ok: true });
});

app.post('/delete-account', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = req.session.userId;

  const myChats = db.prepare('SELECT chat_id FROM chat_members WHERE user_id = ?').all(me);
  for (const c of myChats) {
    const msgs = db.prepare('SELECT file_url FROM messages WHERE chat_id = ? AND file_url != \'\'').all(c.chat_id);
    for (const m of msgs) {
      const fp = path.join(__dirname, 'public', m.file_url.replace(/^\//, ''));
      if (fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch(e) {}
    }
    db.prepare('DELETE FROM messages WHERE chat_id = ?').run(c.chat_id);
    db.prepare('DELETE FROM chat_members WHERE chat_id = ?').run(c.chat_id);
    db.prepare('DELETE FROM chats WHERE id = ?').run(c.chat_id);
  }
  const myStories = db.prepare('SELECT id, file_url FROM stories WHERE user_id = ?').all(me);
  for (const s of myStories) {
    const fp = path.join(__dirname, 'public', s.file_url.replace(/^\//, ''));
    if (fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch(e) {}
  }
  db.prepare('DELETE FROM stories WHERE user_id = ?').run(me);

  const myStickers = db.prepare('SELECT file_url FROM stickers WHERE user_id = ?').all(me);
  for (const s of myStickers) {
    const fp = path.join(__dirname, 'public', s.file_url.replace(/^\//, ''));
    if (fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch(e) {}
  }
  db.prepare('DELETE FROM stickers WHERE user_id = ?').run(me);

  const meUser = db.prepare('SELECT avatar FROM users WHERE id = ?').get(me);
  if (meUser && meUser.avatar) {
    const fp = path.join(__dirname, 'public', meUser.avatar.replace(/^\//, ''));
    if (fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch(e) {}
  }

  db.prepare('DELETE FROM invitations WHERE from_user_id = ? OR to_user_id = ?').run(me, me);
  db.prepare('DELETE FROM users WHERE id = ?').run(me);
  req.session.destroy();
  res.json({ ok: true });
});

app.post('/search', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const phone = cleanPhone(req.body.phone);
  if (!phone) return res.json({ ok: false, error: 'Введи номер' });

  const found = db.prepare('SELECT id, name, role, phone, status, avatar FROM users WHERE phone = ? AND id != ?')
    .get(phone, req.session.userId);
  if (!found) return res.json({ ok: false, error: 'Пользователь не найден' });
  res.json({ ok: true, user: found });
});

// ===== ЗАЯВКИ =====
app.post('/invitations/send', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const { toUserId, type } = req.body;
  if (!toUserId) return res.json({ ok: false, error: 'Не выбран юзер' });

  const me = req.session.userId;
  if (me === parseInt(toUserId)) return res.json({ ok: false, error: 'Себе нельзя' });

  if (type === 'private') {
    const existingChat = db.prepare(`
      SELECT c.id FROM chats c
      JOIN chat_members m1 ON m1.chat_id = c.id AND m1.user_id = ?
      JOIN chat_members m2 ON m2.chat_id = c.id AND m2.user_id = ?
      WHERE c.type = 'private'
    `).get(me, toUserId);
    if (existingChat) return res.json({ ok: true, chatId: existingChat.id, alreadyExists: true });
  }

  const existing = db.prepare(`
    SELECT id FROM invitations
    WHERE from_user_id = ? AND to_user_id = ? AND status = 'pending' AND type = ?
  `).get(me, toUserId, type || 'private');
  if (existing) return res.json({ ok: false, error: 'Заявка уже отправлена' });

  const info = db.prepare('INSERT INTO invitations (from_user_id, to_user_id, type, status) VALUES (?, ?, ?, ?)')
    .run(me, toUserId, type || 'private', 'pending');

  io.emit('new_invitation', { toUserId: parseInt(toUserId), invitationId: info.lastInsertRowid });

  res.json({ ok: true, invitationId: info.lastInsertRowid });
});

app.get('/invitations', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = req.session.userId;

  const incoming = db.prepare(`
    SELECT i.id, i.type, i.status, i.created_at,
           u.id as from_id, u.name as from_name, u.role as from_role, u.avatar as from_avatar, u.status as from_status
    FROM invitations i
    JOIN users u ON u.id = i.from_user_id
    WHERE i.to_user_id = ? AND i.status = 'pending'
    ORDER BY i.id DESC
  `).all(me);

  const outgoing = db.prepare(`
    SELECT i.id, i.type, i.status, i.created_at,
           u.id as to_id, u.name as to_name, u.role as to_role, u.avatar as to_avatar
    FROM invitations i
    JOIN users u ON u.id = i.to_user_id
    WHERE i.from_user_id = ? AND i.status = 'pending'
    ORDER BY i.id DESC
  `).all(me);

  res.json({ ok: true, incoming, outgoing });
});

app.post('/invitations/:id/accept', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const inv = db.prepare('SELECT * FROM invitations WHERE id = ?').get(req.params.id);
  if (!inv) return res.json({ ok: false, error: 'Заявка не найдена' });
  if (inv.to_user_id !== req.session.userId) return res.json({ ok: false, error: 'Нет доступа' });
  if (inv.status !== 'pending') return res.json({ ok: false, error: 'Уже обработана' });

  if (inv.type === 'private') {
    const existing = db.prepare(`
      SELECT c.id FROM chats c
      JOIN chat_members m1 ON m1.chat_id = c.id AND m1.user_id = ?
      JOIN chat_members m2 ON m2.chat_id = c.id AND m2.user_id = ?
      WHERE c.type = 'private'
    `).get(inv.from_user_id, inv.to_user_id);

    let chatId;
    if (existing) {
      chatId = existing.id;
    } else {
      const chatInfo = db.prepare("INSERT INTO chats (type) VALUES ('private')").run();
      chatId = chatInfo.lastInsertRowid;
      db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(chatId, inv.from_user_id);
      db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(chatId, inv.to_user_id);
    }

    db.prepare('UPDATE invitations SET status = ? WHERE id = ?').run('accepted', inv.id);

    io.emit('invitation_accepted', {
      fromUserId: inv.from_user_id,
      toUserId: inv.to_user_id,
      chatId: chatId
    });

    res.json({ ok: true, chatId });
  } else {
    db.prepare('UPDATE invitations SET status = ? WHERE id = ?').run('accepted', inv.id);
    res.json({ ok: true });
  }
});

app.post('/invitations/:id/decline', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const inv = db.prepare('SELECT * FROM invitations WHERE id = ?').get(req.params.id);
  if (!inv) return res.json({ ok: false, error: 'Не найдена' });
  if (inv.to_user_id !== req.session.userId) return res.json({ ok: false, error: 'Нет доступа' });

  db.prepare('UPDATE invitations SET status = ? WHERE id = ?').run('declined', inv.id);

  io.emit('invitation_declined', {
    fromUserId: inv.from_user_id,
    toUserId: inv.to_user_id
  });

  res.json({ ok: true });
});

app.post('/invitations/:id/cancel', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const inv = db.prepare('SELECT * FROM invitations WHERE id = ?').get(req.params.id);
  if (!inv) return res.json({ ok: false, error: 'Не найдена' });
  if (inv.from_user_id !== req.session.userId) return res.json({ ok: false, error: 'Нет доступа' });

  db.prepare('UPDATE invitations SET status = ? WHERE id = ?').run('cancelled', inv.id);
  res.json({ ok: true });
});

// ===== ЧАТЫ =====
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

app.get('/chats', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = req.session.userId;
  ensureSavedChat(me);

  const chats = db.prepare(`
    SELECT c.id, c.type, c.name FROM chats c
    JOIN chat_members m ON m.chat_id = c.id
    WHERE m.user_id = ?
    ORDER BY CASE c.type WHEN 'saved' THEN 0 ELSE 1 END, c.id DESC
  `).all(me);

  const result = chats.map(c => {
    if (c.type === 'saved') {
      return { id: c.id, type: 'saved', title: 'Избранное', role: 'user', otherId: null, status: 'Заметки для себя', avatar: '' };
    }
    if (c.type === 'private') {
      const other = db.prepare(`
        SELECT u.id, u.name, u.role, u.status, u.avatar FROM users u
        JOIN chat_members m ON m.user_id = u.id
        WHERE m.chat_id = ? AND u.id != ?
      `).get(c.id, me);
      return {
        id: c.id, type: c.type,
        title: other ? other.name : 'Личный чат',
        role: other ? other.role : 'user',
        otherId: other ? other.id : null,
        status: other ? other.status : '',
        avatar: other ? other.avatar : ''
      };
    }
    return { id: c.id, type: c.type, title: c.name || 'Группа', role: 'group', otherId: null, status: '', avatar: '' };
  });
  res.json({ ok: true, chats: result });
});

app.get('/chats/:id/messages', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const chatId = req.params.id;
  const me = req.session.userId;

  const inChat = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?')
    .get(chatId, me);
  if (!inChat) return res.json({ ok: false });

  const msgs = db.prepare(`
    SELECT m.id, m.name, m.text, m.created_at, m.msg_type, m.file_url, m.file_name, m.file_size, m.file_mime,
           m.deleted, m.deleted_for, m.user_id,
           u.role, u.status, u.avatar
    FROM messages m
    LEFT JOIN users u ON u.id = m.user_id
    WHERE m.chat_id = ? ORDER BY m.id ASC LIMIT 200
  `).all(chatId);

  const filtered = msgs.filter(m => {
    if (m.deleted) return false;
    const deletedFor = m.deleted_for ? m.deleted_for.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n)) : [];
    if (deletedFor.includes(me)) return false;
    return true;
  });

  res.json({ ok: true, messages: filtered });
});

app.post('/chats/:id/upload', upload.single('file'), (req, res) => {
  if (!req.session.userId) return res.json({ ok: false, error: 'Не авторизован' });
  if (!req.file) return res.json({ ok: false, error: 'Файл не загружен' });

  const chatId = req.params.id;
  const inChat = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?')
    .get(chatId, req.session.userId);
  if (!inChat) return res.json({ ok: false, error: 'Нет доступа' });

  const user = db.prepare('SELECT name, role, banned, status, avatar FROM users WHERE id = ?').get(req.session.userId);
  if (!user || user.banned) return res.json({ ok: false, error: 'Забанен' });

  const fileUrl = '/uploads/' + req.file.filename;
  const fileName = req.file.originalname;
  const fileSize = req.file.size;
  const fileMime = req.file.mimetype;

  let msgType = 'file';
  if (fileMime.startsWith('image/')) msgType = 'image';
  else if (fileMime.startsWith('video/')) msgType = 'video';
  else if (fileMime.startsWith('audio/')) msgType = 'audio';

  const text = String(req.body.caption || '').slice(0, 500);

  const info = db.prepare(`INSERT INTO messages (chat_id, user_id, name, text, msg_type, file_url, file_name, file_size, file_mime)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(chatId, req.session.userId, user.name, text, msgType, fileUrl, fileName, fileSize, fileMime);

  const msg = {
    id: info.lastInsertRowid,
    chatId,
    userId: req.session.userId,
    name: user.name,
    role: user.role,
    text: text,
    status: user.status,
    avatar: user.avatar,
    msgType: msgType,
    fileUrl: fileUrl,
    fileName: fileName,
    fileSize: fileSize,
    fileMime: fileMime,
    time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })
  };

  io.to('chat_' + chatId).emit('message', msg);
  res.json({ ok: true, message: msg });
});

// ===== СТИКЕРЫ =====
app.post('/stickers/upload', upload.single('file'), (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  if (!req.file) return res.json({ ok: false, error: 'Файл не загружен' });

  const fileUrl = '/uploads/' + req.file.filename;
  const emoji = String(req.body.emoji || '').slice(0, 10);

  const info = db.prepare('INSERT INTO stickers (user_id, file_url, emoji) VALUES (?, ?, ?)')
    .run(req.session.userId, fileUrl, emoji);

  res.json({ ok: true, sticker: { id: info.lastInsertRowid, file_url: fileUrl, emoji } });
});

app.get('/stickers', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const stickers = db.prepare('SELECT id, file_url, emoji FROM stickers WHERE user_id = ? ORDER BY id DESC')
    .all(req.session.userId);
  res.json({ ok: true, stickers });
});

app.delete('/stickers/:id', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const sticker = db.prepare('SELECT * FROM stickers WHERE id = ?').get(req.params.id);
  if (!sticker) return res.json({ ok: false, error: 'Не найден' });
  if (sticker.user_id !== req.session.userId) return res.json({ ok: false, error: 'Нет доступа' });

  const fp = path.join(__dirname, 'public', sticker.file_url.replace(/^\//, ''));
  if (fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch(e) {}

  db.prepare('DELETE FROM stickers WHERE id = ?').run(sticker.id);
  res.json({ ok: true });
});

// ===== УДАЛЕНИЕ СООБЩЕНИЙ =====
app.post('/messages/:id/delete-for-me', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(req.params.id);
  if (!msg) return res.json({ ok: false, error: 'Не найдено' });

  const inChat = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?')
    .get(msg.chat_id, req.session.userId);
  if (!inChat) return res.json({ ok: false, error: 'Нет доступа' });

  const list = msg.deleted_for ? msg.deleted_for.split(',').map(s => s.trim()).filter(s => s) : [];
  if (!list.includes(String(req.session.userId))) {
    list.push(String(req.session.userId));
  }
  db.prepare('UPDATE messages SET deleted_for = ? WHERE id = ?').run(list.join(','), msg.id);
  res.json({ ok: true });
});

app.post('/messages/:id/delete-for-all', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(req.params.id);
  if (!msg) return res.json({ ok: false, error: 'Не найдено' });

  const inChat = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?')
    .get(msg.chat_id, req.session.userId);
  if (!inChat) return res.json({ ok: false, error: 'Нет доступа' });

  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  const isCreator = me && me.role === 'creator';
  const isMine = msg.user_id === req.session.userId;

  if (!isMine && !isCreator) return res.json({ ok: false, error: 'Можно удалять только свои' });

  if (msg.file_url) {
    const fp = path.join(__dirname, 'public', msg.file_url.replace(/^\//, ''));
    if (fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch(e) {}
  }

  db.prepare('UPDATE messages SET deleted = 1 WHERE id = ?').run(msg.id);
  io.to('chat_' + msg.chat_id).emit('message_deleted', { messageId: msg.id, chatId: msg.chat_id });
  res.json({ ok: true });
});

// ===== ИСТОРИИ =====
app.post('/stories/upload', upload.single('file'), (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  if (!req.file) return res.json({ ok: false, error: 'Файл не загружен' });

  const type = req.file.mimetype.startsWith('video') ? 'video' : 'photo';
  const fileUrl = '/uploads/' + req.file.filename;
  const caption = String(req.body.caption || '').slice(0, 200);
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  const info = db.prepare('INSERT INTO stories (user_id, type, file_url, caption, expires_at) VALUES (?, ?, ?, ?, ?)')
    .run(req.session.userId, type, fileUrl, caption, expiresAt);

  io.emit('new_story');
  res.json({ ok: true, storyId: info.lastInsertRowid });
});

app.get('/stories', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = req.session.userId;
  const now = new Date().toISOString();

  const stories = db.prepare(`
    SELECT s.id, s.user_id, s.type, s.file_url, s.caption, s.created_at,
           u.name, u.role, u.avatar
    FROM stories s
    JOIN users u ON u.id = s.user_id
    WHERE s.expires_at > ?
    ORDER BY s.created_at DESC
  `).all(now);

  const byUser = {};
  for (const s of stories) {
    if (!byUser[s.user_id]) {
      byUser[s.user_id] = { userId: s.user_id, userName: s.name, userRole: s.role, userAvatar: s.avatar, stories: [] };
    }
    const views = db.prepare('SELECT COUNT(*) as c FROM story_views WHERE story_id = ?').get(s.id).c;
    const viewedByMe = db.prepare('SELECT 1 FROM story_views WHERE story_id = ? AND viewer_id = ?').get(s.id, me) ? true : false;

    byUser[s.user_id].stories.push({
      id: s.id, type: s.type, fileUrl: s.file_url, caption: s.caption,
      createdAt: s.created_at, views: views, viewed: viewedByMe
    });
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
  try {
    db.prepare('INSERT OR IGNORE INTO story_views (story_id, viewer_id) VALUES (?, ?)')
      .run(req.params.id, req.session.userId);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false }); }
});

app.delete('/stories/:id', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const story = db.prepare('SELECT * FROM stories WHERE id = ?').get(req.params.id);
  if (!story) return res.json({ ok: false, error: 'Не найдена' });

  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (story.user_id !== req.session.userId && (!me || me.role !== 'creator')) {
    return res.json({ ok: false, error: 'Нет доступа' });
  }

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
  if (!story || story.user_id !== req.session.userId) {
    return res.json({ ok: false, error: 'Только свои истории' });
  }
  const viewers = db.prepare(`
    SELECT u.name, u.role, u.avatar, v.viewed_at
    FROM story_views v
    JOIN users u ON u.id = v.viewer_id
    WHERE v.story_id = ?
    ORDER BY v.viewed_at DESC
  `).all(req.params.id);
  res.json({ ok: true, viewers });
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

  const users = db.prepare('SELECT id, name, phone, role, banned, status, avatar, created_at FROM users ORDER BY id').all();
  const stats = {
    users: db.prepare('SELECT COUNT(*) as c FROM users').get().c,
    chats: db.prepare('SELECT COUNT(*) as c FROM chats').get().c,
    messages: db.prepare('SELECT COUNT(*) as c FROM messages WHERE deleted = 0').get().c,
    stories: db.prepare('SELECT COUNT(*) as c FROM stories').get().c
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

  const emoji = String(req.body.emoji || '').slice(0, 10);
  const text = String(req.body.text || '').trim().slice(0, 50);
  if (!text) return res.json({ ok: false, error: 'Введи текст' });

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
  if (!userId) return res.json({ ok: false, error: 'Выбери юзера' });

  db.prepare('UPDATE users SET status = ? WHERE id = ?').run(String(status || '').slice(0, 100), userId);
  io.emit('avatar_update', {});
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
    FROM chats c WHERE c.type != 'saved' ORDER BY c.id DESC
  `).all();
  res.json({ ok: true, chats });
});

app.get('/admin/chats/:id', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false });

  const msgs = db.prepare(`
    SELECT m.name, m.text, m.created_at, m.msg_type, m.file_url, m.file_name, u.role
    FROM messages m
    LEFT JOIN users u ON u.id = m.user_id
    WHERE m.chat_id = ? AND m.deleted = 0 ORDER BY m.id ASC
  `).all(req.params.id);
  res.json({ ok: true, messages: msgs });
});

app.get('/admin/stories', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const me = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!me || me.role !== 'creator') return res.json({ ok: false });

  const stories = db.prepare(`
    SELECT s.id, s.user_id, s.type, s.file_url, s.caption, s.created_at,
           u.name, u.role,
           (SELECT COUNT(*) FROM story_views WHERE story_id = s.id) as views
    FROM stories s
    JOIN users u ON u.id = s.user_id
    ORDER BY s.created_at DESC
  `).all();
  res.json({ ok: true, stories });
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
    const user = db.prepare('SELECT banned, status, avatar FROM users WHERE id = ?').get(userId);
    if (user && user.banned) return;

    const inChat = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').get(chatId, userId);
    if (!inChat) return;

    const info = db.prepare('INSERT INTO messages (chat_id, user_id, name, text, msg_type) VALUES (?, ?, ?, ?, ?)')
      .run(chatId, userId, name, text, 'text');

    io.to('chat_' + chatId).emit('message', {
      id: info.lastInsertRowid,
      chatId, userId, name, role, text,
      msgType: 'text',
      status: user ? user.status : '',
      avatar: user ? user.avatar : '',
      time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })
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

    const info = db.prepare('INSERT INTO messages (chat_id, user_id, name, text, msg_type, file_url) VALUES (?, ?, ?, ?, ?, ?)')
      .run(chatId, userId, name, text, msgType, fileUrl);

    io.to('chat_' + chatId).emit('message', {
      id: info.lastInsertRowid,
      chatId, userId, name, role, text,
      msgType: msgType,
      fileUrl: fileUrl,
      status: user ? user.status : '',
      avatar: user ? user.avatar : '',
      time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })
    });
  });

  socket.on('disconnect', () => {});
});

function ensureAdmin() {
  const existing = db.prepare('SELECT id FROM users WHERE phone = ?').get(ADMIN_PHONE);
  if (existing) {
    db.prepare('UPDATE users SET role = ? WHERE phone = ?').run('creator', ADMIN_PHONE);
    ensureSavedChat(existing.id);
    console.log('✅ Админ найден: ' + ADMIN_PHONE);
  } else {
    bcrypt.hash('admin123', 10).then(hash => {
      const info = db.prepare('INSERT INTO users (phone, password, name, role, created_at) VALUES (?, ?, ?, ?, ?)')
        .run(ADMIN_PHONE, hash, 'Superselester', 'creator', new Date().toISOString());
      ensureSavedChat(info.lastInsertRowid);
      console.log('✅ Админ создан: ' + ADMIN_PHONE);
    });
  }
}

server.listen(3000, () => {
  console.log('\n🔥 BLAZE запущен: http://localhost:3000');
  ensureAdmin();
  cleanExpiredStories();
});