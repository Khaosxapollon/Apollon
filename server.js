const express = require("express");
const session = require("express-session");
const os = require("os");
const path = require("path");
const { DatabaseSync } = require("node:sqlite");
const bcrypt = require("bcryptjs");

const app = express();
const db = new DatabaseSync(path.join(__dirname, "apollon.db"));



db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL COLLATE NOCASE UNIQUE,
  password TEXT NOT NULL,
  blocked INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)
`);

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true, limit: "20kb" }));
app.use(express.static("public"));

app.use(session({
  secret: process.env.SESSION_SECRET || "apollon-secret-change-this",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

function requireAdmin(req, res, next) {
  if (!req.session.admin) return res.redirect("/admin");
  next();
}

function requireUser(req, res, next) {
  if (!req.session.userId) return res.redirect("/login");

  const user = db.prepare(
    "SELECT id, username, blocked FROM users WHERE id = ?"
  ).get(req.session.userId);

  if (!user || user.blocked) {
    req.session.destroy(() => res.redirect("/login"));
    return;
  }

  req.user = user;
  next();
}

app.get("/", (req, res) => {
  res.render("index");
});

// ÜYE KAYIT
app.get("/register", (req, res) => {
  res.render("register", { error: null });
});

app.post("/register", (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    return res.status(400).render("register", {
      error: "Kullanıcı adı 3-20 karakter olmalı. Harf, rakam ve _ kullan."
    });
  }

  if (password.length < 8 || password.length > 72) {
    return res.status(400).render("register", {
      error: "Şifre en az 8, en fazla 72 karakter olmalı."
    });
  }

  const exists = db.prepare(
    "SELECT id FROM users WHERE username = ?"
  ).get(username);

  if (exists) {
    return res.status(409).render("register", {
      error: "Bu kullanıcı adı zaten kullanılıyor."
    });
  }

  const hash = bcrypt.hashSync(password, 12);

  try {
    const result = db.prepare(
      "INSERT INTO users (username, password) VALUES (?, ?)"
    ).run(username, hash);

    req.session.regenerate(err => {
      if (err) return res.status(500).send("Oturum oluşturulamadı.");
      req.session.userId = Number(result.lastInsertRowid);
      res.redirect("/profile");
    });
  } catch (err) {
    res.status(500).render("register", {
      error: "Kayıt oluşturulamadı. Tekrar dene."
    });
  }
});

// ÜYE GİRİŞ
app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

app.post("/login", (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  const user = db.prepare(
    "SELECT * FROM users WHERE username = ?"
  ).get(username);

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).render("login", {
      error: "Kullanıcı adı veya şifre hatalı."
    });
  }

  if (user.blocked) {
    return res.status(403).render("login", {
      error: "Hesabın yönetici tarafından engellenmiş."
    });
  }

  req.session.regenerate(err => {
    if (err) return res.status(500).send("Oturum açılamadı.");
    req.session.userId = user.id;
    res.redirect("/profile");
  });
});

// ÜYE PROFİLİ
app.get("/profile", requireUser, (req, res) => {
  const user = db.prepare(
    "SELECT id, username, created_at FROM users WHERE id = ?"
  ).get(req.user.id);

  res.render("profile", { user });
});

// ÜYE ÇIKIŞ
app.post("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// ADMIN GİRİŞ
app.get("/admin", (req, res) => {
  res.render("admin/login");
});

app.post("/admin", (req, res) => {
  const username = String(req.body.username || "");
  const password = String(req.body.password || "");

  const adminUser = process.env.ADMIN_USER || "admin";
  const adminPass = process.env.ADMIN_PASSWORD || "Apollon123!";

  if (username !== adminUser || password !== adminPass) {
    return res.status(401).send("Hatalı kullanıcı adı veya şifre!");
  }

  req.session.regenerate(err => {
    if (err) return res.status(500).send("Oturum açılamadı.");
    req.session.admin = true;
    res.redirect("/admin/dashboard");
  });
});

// ADMIN DASHBOARD
app.get("/admin/dashboard", requireAdmin, (req, res) => {
  const memory = process.memoryUsage();

  const totalUsers = db.prepare(
    "SELECT COUNT(*) AS total FROM users"
  ).get().total;

  const activeUsers = db.prepare(
    "SELECT COUNT(*) AS total FROM users WHERE blocked = 0"
  ).get().total;

  const blockedUsers = db.prepare(
    "SELECT COUNT(*) AS total FROM users WHERE blocked = 1"
  ).get().total;

  res.render("admin/dashboard", {
    uptime: Math.floor(process.uptime()),
    ram: (memory.rss / 1024 / 1024).toFixed(1),
    totalRam: (os.totalmem() / 1024 / 1024 / 1024).toFixed(1),
    nodeVersion: process.version,
    platform: process.platform,
    hostname: os.hostname(),
    port: process.env.PORT || 3000,
    totalUsers,
    activeUsers,
    blockedUsers
  });
});

// ADMIN ÜYE YÖNETİMİ
app.get("/admin/users", requireAdmin, (req, res) => {
  const search = String(req.query.search || "").trim();

  const users = search
    ? db.prepare(`
        SELECT id, username, blocked, created_at
        FROM users
        WHERE username LIKE ?
        ORDER BY id DESC
      `).all(`%${search}%`)
    : db.prepare(`
        SELECT id, username, blocked, created_at
        FROM users
        ORDER BY id DESC
      `).all();

  res.render("admin/users", { users, search });
});

app.post("/admin/users/:id/toggle", requireAdmin, (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).send("Geçersiz üye numarası.");
  }

  db.prepare(`
    UPDATE users
    SET blocked = CASE WHEN blocked = 1 THEN 0 ELSE 1 END
    WHERE id = ?
  `).run(id);

  res.redirect("/admin/users");
});

app.get("/admin/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/admin"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log("APOLLON aktif: " + PORT);
});
