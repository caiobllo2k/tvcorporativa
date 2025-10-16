-- Adiciona a coluna role se não existir
PRAGMA table_info(users);

-- Se a coluna não existir, o comando abaixo pode falhar, mas não quebra o resto
ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user';

-- Define role padrão para todos que ainda estiverem NULL
UPDATE users SET role = 'user' WHERE role IS NULL;

-- Cria admin inicial se não existir
-- Senha: Admin123 (hash bcrypt)
INSERT INTO users (username, password, role)
SELECT 'admin',
       '$2a$10$X9o3t6q3pkkgVp0cT8nbjOyqek2V9V99bGv7TXexGItwE8B4UpmG6',
       'admin'
WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'admin');
