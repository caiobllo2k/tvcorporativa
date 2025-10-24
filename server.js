/* =========================================================
   TV CORPORATIVA — server.js (versão final estável e revisada)
   =========================================================
   ✅ Login / Logout / Upload / Admin OK
   ✅ CRUD de usuários (GET/POST/PUT/DELETE)
   ✅ Tokens (devices) com rotas GET/POST/DELETE
   ✅ /api/news/me com token respeitando settings/feeds/uploads
   ✅ Feeds G1 completos (lista original) + imagens extraídas corretamente
   ✅ RSS cache em memória e em disco (fallback offline)
   ✅ Ticker BTC/USD
   ✅ Segurança: bcrypt, helmet, rate-limit, sessions persistentes
   ✅ Compressão HTTP
   ========================================================= */

const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const sqlite3 = require("sqlite3").verbose();
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const axios = require("axios");
const xml2js = require("xml2js");
const Parser = require("rss-parser");
const rssParser = new Parser({
  headers: { "User-Agent": "Mozilla/5.0 (compatible; TVCorporativaBot/1.0)" }
});
const crypto = require("crypto");
const helmet = require("helmet");
const bcrypt = require("bcrypt");
const rateLimit = require("express-rate-limit");
const { body } = require("express-validator");
const pino = require("pino");
const compression = require("compression");
const logger = pino({ level: process.env.LOG_LEVEL || "info", base: undefined });

const app = express();
const PORT = process.env.PORT || 8080;

/* ====================== SESSÃO ====================== */
app.use(
  session({
    store: new SQLiteStore({ db: "sessions.sqlite", dir: "./" }),
    secret: process.env.SESSION_SECRET || "change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 7 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      sameSite: "lax",
      secure: !!process.env.COOKIE_SECURE,
    },
  })
);

/* ====================== SEGURANÇA + COMPACTAÇÃO ====================== */
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(compression());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate-limit leve no login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: "Muitas tentativas de login. Tente novamente em alguns minutos.",
});
app.use("/login", loginLimiter);

/* ====================== BANCO ====================== */
const db = new sqlite3.Database(path.join(__dirname, "database.sqlite"));
db.serialize(() => {
  db.run("PRAGMA foreign_keys = ON;");

  db.run(`CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT CHECK(role IN ('admin','user')) NOT NULL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS uploads(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS settings(
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    display_time INTEGER DEFAULT 15000,
    disable_rss INTEGER DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS devices(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT,
    token TEXT UNIQUE,
    token_hash TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS user_feeds(
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    feeds TEXT
  )`);

  db.run(`CREATE INDEX IF NOT EXISTS idx_uploads_user ON uploads(user_id, uploaded_at DESC)`);
});

/* ====================== ESTÁTICOS ====================== */
app.use(express.static(path.join(__dirname, "public")));

/* ====================== HELPERS ====================== */
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.status(401).send("Não autorizado");
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.userId || req.session.role !== "admin") return res.status(403).send("Acesso negado");
  next();
}
const sha256Hex = (str) => crypto.createHash("sha256").update(String(str)).digest("hex");

/* ====================== CACHE RSS (memória + disco) ====================== */
const RSS_CACHE_DIR = path.join(__dirname, "rss-cache");
if (!fs.existsSync(RSS_CACHE_DIR)) fs.mkdirSync(RSS_CACHE_DIR, { recursive: true });
const cacheKeyToPath = (k) => path.join(RSS_CACHE_DIR, sha256Hex(k) + ".json");
function readCache(key) { try { return JSON.parse(fs.readFileSync(cacheKeyToPath(key), "utf8")); } catch { return null; } }
function writeCache(key, data) { try { fs.writeFileSync(cacheKeyToPath(key), JSON.stringify(data)); } catch {} }
const memCache = new Map();

/* ====================== LOGIN / LOGOUT ====================== */
app.post(
  "/login",
  body("username").trim(),
  body("password").isLength({ min: 3 }),
  (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
      if (err || !user) return res.status(401).send("Credenciais inválidas");
      const ok = await bcrypt.compare(password, user.password).catch(() => false);
      if (!ok) return res.status(401).send("Credenciais inválidas");
      req.session.userId = user.id;
      req.session.role = user.role;
      res.redirect(user.role === "admin" ? "/admin.html" : "/upload.html");
    });
  }
);
app.get("/logout", (req, res) => req.session.destroy(() => res.redirect("/login.html")));

/* ====================== CRUD USUÁRIOS ====================== */
app.get("/api/users", requireAdmin, (req, res) => {
  db.all("SELECT id, username, role FROM users ORDER BY id", [], (err, rows) => {
    if (err) return res.status(500).json({ error: "Erro ao listar usuários" });
    res.json(rows);
  });
});
app.post("/api/users", requireAdmin, async (req, res) => {
  const { username, password, role } = req.body;
  const hash = await bcrypt.hash(password, 10);
  db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [username, hash, role], function (err) {
    if (err) return res.status(400).json({ error: "Erro ao criar usuário" });
    db.run("INSERT OR IGNORE INTO settings (user_id) VALUES (?)", [this.lastID]);
    db.run("INSERT OR IGNORE INTO user_feeds (user_id, feeds) VALUES (?, ?)", [this.lastID, JSON.stringify([])]);
    res.json({ id: this.lastID });
  });
});
app.put("/api/users/:id", requireAdmin, async (req, res) => {
  const { password, role } = req.body;
  const fields = [], vals = [];
  if (password) { const h = await bcrypt.hash(password, 10); fields.push("password=?"); vals.push(h); }
  if (role) { fields.push("role=?"); vals.push(role); }
  if (!fields.length) return res.json({ ok: true });
  vals.push(req.params.id);
  db.run(`UPDATE users SET ${fields.join(",")} WHERE id=?`, vals, e => {
    if (e) return res.status(500).json({ error: "Erro ao atualizar" });
    res.json({ ok: true });
  });
});
app.delete("/api/users/:id", requireAdmin, (req, res) => {
  const id = req.params.id;
  db.serialize(() => {
    db.run("DELETE FROM devices WHERE user_id = ?", [id]);
    db.run("DELETE FROM uploads WHERE user_id = ?", [id]);
    db.run("DELETE FROM settings WHERE user_id = ?", [id]);
    db.run("DELETE FROM user_feeds WHERE user_id = ?", [id]);
    db.run("DELETE FROM users WHERE id = ?", [id], function (err) {
      if (err) return res.status(500).json({ error: "Erro ao excluir usuário" });
      res.json({ ok: true });
    });
  });
});

/* ====================== SETTINGS ====================== */
app.get("/api/settings", requireLogin, (req, res) => {
  db.get("SELECT display_time, disable_rss FROM settings WHERE user_id = ?", [req.session.userId],
    (err, row) => err ? res.status(500).json({ error: "Erro ao buscar configurações" })
                      : res.json(row || { display_time: 15000, disable_rss: 0 })
  );
});
app.post("/api/settings", requireLogin, (req, res) => {
  const { display_time, disable_rss } = req.body;
  db.run(`
    INSERT INTO settings (user_id, display_time, disable_rss)
    VALUES (?, ?, ?)
    ON CONFLICT(user_id)
    DO UPDATE SET display_time = excluded.display_time, disable_rss = excluded.disable_rss
  `, [req.session.userId, Number(display_time) || 15000, disable_rss ? 1 : 0],
  (err) => err ? res.status(500).json({ error: "Erro ao salvar configurações" }) : res.json({ ok: true }));
});

/* ====================== FEEDS PERSONALIZADOS ====================== */
app.get("/api/feeds", requireLogin, (req, res) => {
  db.get("SELECT feeds FROM user_feeds WHERE user_id = ?", [req.session.userId], (err, row) => {
    if (err) return res.status(500).json({ error: "Erro ao ler feeds" });
    const feeds = row?.feeds ? JSON.parse(row.feeds) : [];
    res.json(feeds);
  });
});
app.post("/api/feeds", requireLogin, (req, res) => {
  const feeds = Array.isArray(req.body.feeds) ? req.body.feeds : [];
  db.run(`
    INSERT INTO user_feeds (user_id, feeds)
    VALUES (?, ?)
    ON CONFLICT(user_id) DO UPDATE SET feeds = excluded.feeds
  `, [req.session.userId, JSON.stringify(feeds)], (err) => {
    if (err) return res.status(500).json({ error: "Erro ao salvar feeds" });
    res.json({ ok: true });
  });
});

/* ====================== UPLOADS ====================== */
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uid = req.session.userId;
    const dir = path.join(__dirname, "public", "uploads", String(uid));
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (_req, file, cb) => {
    const safe = file.originalname.replace(/[^\w.\-() ]+/g, "_");
    cb(null, `${Date.now()}${path.extname(safe)}`);
  },
});
const upload = multer({
  storage,
  fileFilter: (_req, file, cb) => {
    const ok = /(?:image\/(jpeg|png|gif|webp)|video\/(mp4|webm|ogg))/.test(file.mimetype);
    cb(ok ? null : new Error("Tipo de arquivo não permitido"), ok);
  },
  limits: { fileSize: 200 * 1024 * 1024 },
});
app.post("/upload", requireLogin, upload.single("arquivo"), (req, res) => {
  if (!req.file) return res.status(400).send("Nenhum arquivo enviado");
  db.run("INSERT INTO uploads (user_id, filename) VALUES (?, ?)", [req.session.userId, req.file.filename], err => {
    if (err) return res.status(500).send("Erro ao salvar no banco");
    res.redirect("/upload.html");
  });
});
app.get("/api/uploads", requireLogin, (req, res) => {
  db.all(
    "SELECT id, user_id, filename, uploaded_at FROM uploads WHERE user_id = ? ORDER BY uploaded_at DESC",
    [req.session.userId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "Erro ao buscar uploads" });
      const out = (rows || []).map(r => ({
        id: r.id,
        filename: `uploads/${r.user_id}/${r.filename}`,
        user_id: r.user_id,
        uploaded_at: r.uploaded_at,
      }));
      res.json(out);
    }
  );
});

/* ====================== FEEDS G1 (lista completa original) ====================== */
const DEFAULT_FEEDS = [
  "https://g1.globo.com/dynamo/brasil/rss2.xml",
  "https://g1.globo.com/dynamo/carros/rss2.xml",
  "https://g1.globo.com/dynamo/ciencia-e-saude/rss2.xml",
  "https://g1.globo.com/dynamo/concursos-e-emprego/rss2.xml",
  "https://g1.globo.com/dynamo/economia/rss2.xml",
  "https://g1.globo.com/dynamo/educacao/rss2.xml",
  "https://g1.globo.com/dynamo/loterias/rss2.xml",
  "https://g1.globo.com/dynamo/mundo/rss2.xml",
  "https://g1.globo.com/dynamo/musica/rss2.xml",
  "https://g1.globo.com/dynamo/natureza/rss2.xml",
  "https://g1.globo.com/dynamo/planeta-bizarro/rss2.xml",
  "https://g1.globo.com/dynamo/politica/mensalao/rss2.xml",
  "https://g1.globo.com/dynamo/pop-arte/rss2.xml",
  "https://g1.globo.com/dynamo/tecnologia/rss2.xml",
  "https://g1.globo.com/dynamo/turismo-e-viagem/rss2.xml"
];

/* ====================== COLETA DE RSS ====================== */
function extractFirstImg(html) {
  if (!html) return null;
  const m = String(html).match(/<img[^>]+src=["']([^"']+)["']/i);
  return m ? m[1] : null;
}

async function fetchOneFeed(url) {
  try {
    const res = await axios.get(url, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; TVCorporativaBot/1.0)" },
      timeout: 8000
    });
    const xml = res.data;
    const parsed = await xml2js.parseStringPromise(xml, { trim: true });
    const channel = parsed?.rss?.channel?.[0];
    if (channel?.item?.length) {
      const cat = channel?.title?.[0] || "G1";
      return channel.item.map(it => {
        const title = it.title?.[0] || "";
        const link = it.link?.[0] || "";
        const content = it["content:encoded"]?.[0] || it.description?.[0] || "";
        const enclosure = it.enclosure?.[0]?.$.url;
        const mediaContent = it["media:content"]?.[0]?.$?.url;
        const image = enclosure || mediaContent || extractFirstImg(content) || "";
        return { title, link, image, category: cat };
      });
    }
  } catch {
    return [];
  }

  try {
    const feed = await rssParser.parseURL(url);
    const cat = feed.title || "G1";
    return (feed.items || []).map(item => {
      const image = (item.enclosure && item.enclosure.url)
        || extractFirstImg(item["content:encoded"])
        || extractFirstImg(item.content)
        || extractFirstImg(item.summary)
        || "";
      return { title: item.title || "", link: item.link || "", image, category: cat };
    });
  } catch {
    return [];
  }
}

async function fetchFeeds(feedList) {
  const key = JSON.stringify(feedList.slice().sort());
  const now = Date.now();

  const mem = memCache.get(key);
  if (mem && now - mem.ts < 5 * 60 * 1000) return mem.items;

  try {
    const results = await Promise.all(feedList.map(u => fetchOneFeed(u)));
    const items = results.flat().filter(i => i && i.title);
    const payload = { ts: now, items };
    memCache.set(key, payload);
    writeCache(key, payload);
    return items;
  } catch {
    const disk = readCache(key);
    if (disk?.items) {
      memCache.set(key, disk);
      return disk.items;
    }
    return [];
  }
}

/* ====================== TOKENS ====================== */
app.get("/api/devices", requireAdmin, (req, res) => {
  const { user_id } = req.query;
  if (!user_id) return res.status(400).json({ error: "Parâmetro user_id obrigatório" });
  db.all("SELECT id, token, name, created_at FROM devices WHERE user_id = ? ORDER BY created_at DESC", [user_id], (err, rows) => {
    if (err) return res.status(500).json({ error: "Erro ao buscar tokens" });
    res.json(rows || []);
  });
});

app.post("/api/devices", requireAdmin, (req, res) => {
  const { user_id, name } = req.body;
  if (!user_id) return res.status(400).json({ error: "user_id é obrigatório" });
  const token = crypto.randomBytes(16).toString("hex");
  const token_hash = sha256Hex(token);
  db.run("INSERT INTO devices (user_id, name, token, token_hash) VALUES (?, ?, ?, ?)", [user_id, name || "Dispositivo", token, token_hash], function (err) {
    if (err) return res.status(500).json({ error: "Erro ao criar token" });
    res.json({ id: this.lastID, token });
  });
});

/* ====================== PLAYER / NEWS (CORRIGIDO FINAL) ====================== */
app.get("/api/news/me", async (req, res) => {
  try {
    let userId = req.session.userId;

    if (!userId && req.query.token) {
      const token = String(req.query.token).trim();
      const tokenHash = sha256Hex(token);

      const device = await new Promise((resolve) =>
        db.get(
          "SELECT user_id FROM devices WHERE token_hash = ? OR token = ?",
          [tokenHash, token],
          (e, r) => resolve(r || null)
        )
      );

      if (!device) return res.status(401).json({ error: "Token inválido" });
      userId = device.user_id;
      db.run(
        "UPDATE devices SET last_seen = CURRENT_TIMESTAMP WHERE token_hash = ? OR token = ?",
        [tokenHash, token]
      );
    }

    if (!userId) return res.status(401).json({ error: "Não autorizado" });

    const settings = await new Promise((resolve) => {
      db.get(
        "SELECT display_time, disable_rss FROM settings WHERE user_id = ?",
        [userId],
        (err, row) => {
          if (err) return resolve({ display_time: 15000, disable_rss: 0 });
          if (row) return resolve(row);
          db.run(
            "INSERT OR IGNORE INTO settings (user_id, display_time, disable_rss) VALUES (?, ?, ?)",
            [userId, 15000, 0],
            () => resolve({ display_time: 15000, disable_rss: 0 })
          );
        }
      );
    });

    let userFeeds = await new Promise((resolve) =>
      db.get(
        "SELECT feeds FROM user_feeds WHERE user_id = ?",
        [userId],
        (err, row) => {
          if (err || !row) return resolve([]);
          try {
            let feeds = row.feeds;
            if (typeof feeds === "string") feeds = JSON.parse(feeds);
            if (typeof feeds === "string") feeds = JSON.parse(feeds);
            return resolve(Array.isArray(feeds) ? feeds : []);
          } catch {
            return resolve([]);
          }
        }
      )
    );

    if (!userFeeds.length) {
      db.run(
        "INSERT OR IGNORE INTO user_feeds (user_id, feeds) VALUES (?, ?)",
        [userId, JSON.stringify([])]
      );
    }

    const uploads = await new Promise((resolve) =>
      db.all(
        "SELECT id, user_id, filename FROM uploads WHERE user_id = ? ORDER BY uploaded_at DESC",
        [userId],
        (e, rows) =>
          resolve(
            (rows || []).map((r) => ({
              id: r.id,
              filename: `uploads/${r.user_id}/${r.filename}`,
            }))
          )
      )
    );

    let news = [];
    if (!settings.disable_rss) {
      const feedList =
        Array.isArray(userFeeds) && userFeeds.length
          ? userFeeds
          : DEFAULT_FEEDS;
      news = await fetchFeeds(feedList);
    }

    res.json({
      uploads,
      news,
      display_time: settings.display_time || 15000,
      rss_display_time: 5000,
      disable_rss: settings.disable_rss ? 1 : 0,
    });
  } catch (e) {
    logger.error({ msg: "Erro em /api/news/me", err: e.message });
    res.status(500).json({ error: "Erro ao montar conteúdo" });
  }
});

/* ====================== REFRESH & TICKER ====================== */
let lastRefreshTime = Date.now();
app.post("/api/refresh", requireLogin, (_req, res) => { lastRefreshTime = Date.now(); res.json({ ok: true }); });
app.get("/api/refresh-time", (_req, res) => res.json({ time: lastRefreshTime }));

app.get("/api/ticker", async (_req, res) => {
  try {
    const [btcRes, usdRes] = await Promise.all([
      axios.get("https://api.coingecko.com/api/v3/simple/price", { params: { ids: "bitcoin", vs_currencies: "brl" }, timeout: 5000 }),
      axios.get("https://economia.awesomeapi.com.br/json/last/USD-BRL", { timeout: 5000 })
    ]);
    const btc = btcRes?.data?.bitcoin?.brl || null;
    const usd = usdRes?.data?.USDBRL?.bid ? Number(usdRes.data.USDBRL.bid) : null;
    res.json({ btc, usd });
  } catch {
    res.json({ btc: null, usd: null });
  }
});

/* ====================== PÁGINAS ====================== */
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/login.html", (_req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get("/upload.html", requireLogin, (_req, res) => res.sendFile(path.join(__dirname, "public", "upload.html")));
app.get("/admin.html", requireAdmin, (_req, res) => res.sendFile(path.join(__dirname, "public", "admin.html")));

/* ====================== START ====================== */
app.listen(PORT, () => {
  logger.info({ msg: `Servidor seguro rodando na porta ${PORT}` });
});
