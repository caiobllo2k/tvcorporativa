const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./database.sqlite');

// Cria tabela de usuários se não existir
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

module.exports = db;
