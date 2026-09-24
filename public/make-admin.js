// 👑 АВТО-СОЗДАНИЕ АДМИНА
function ensureAdmin() {
  const ADMIN_PHONE = '+79266276629';
  const existing = db.prepare('SELECT id FROM users WHERE phone = ?').get(ADMIN_PHONE);

  if (existing) {
    db.prepare('UPDATE users SET role = ? WHERE phone = ?').run('creator', ADMIN_PHONE);
    console.log('✅ Админ найден и обновлён: ' + ADMIN_PHONE);
  } else {
    bcrypt.hash('admin123', 10).then(hash => {
      db.prepare('INSERT INTO users (phone, password, name, role) VALUES (?, ?, ?, ?)')
        .run(ADMIN_PHONE, hash, 'Superselester', 'creator');
      console.log('✅ Админ СОЗДАН автоматически!');
      console.log('📱 Номер: ' + ADMIN_PHONE);
      console.log('🔑 Пароль: admin123');
    });
  }
}

server.listen(3000, () => {
  console.log('\n🔥 BLAZE запущен: http://localhost:3000');
  ensureAdmin();
});