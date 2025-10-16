-- ================================
-- Tabela de Usuários
-- ================================
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT DEFAULT 'user'
);

-- ================================
-- Tabela de Configurações
-- ================================
CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER UNIQUE NOT NULL,
  disable_rss INTEGER DEFAULT 0,
  display_time INTEGER DEFAULT 15000,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ================================
-- Tabela de Uploads
-- ================================
CREATE TABLE IF NOT EXISTS uploads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  filename TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ================================
-- Usuário administrador padrão
-- ================================
INSERT INTO users (username, password, role) VALUES ('admin', '1234', 'admin');

-- ================================
-- Dois usuários comuns de exemplo
-- ================================
INSERT INTO users (username, password, role) VALUES ('usuario1', '1234', 'user');
INSERT INTO users (username, password, role) VALUES ('usuario2', '1234', 'user');

-- ================================
-- Configurações padrão para os usuários
-- ================================
INSERT INTO settings (user_id, disable_rss, display_time)
SELECT id, 0, 15000 FROM users;
