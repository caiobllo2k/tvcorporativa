// migrate-passwords.js
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const db = new sqlite3.Database('database.sqlite');

db.all('SELECT id, password FROM users', async (err, rows) => {
  if (err) throw err;
  for (const u of rows) {
    // pula se já for hash bcrypt
    if (u.password.startsWith('$2b$') || u.password.startsWith('$2a$')) continue;
    const hash = await bcrypt.hash(u.password, 10);
    db.run('UPDATE users SET password = ? WHERE id = ?', [hash, u.id]);
    console.log(`✔️ Usuário ${u.id} migrado`);
  }
  db.close(() => console.log('Migração concluída.'));
});
