
"use strict";

const express = require("express");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const { rateLimit } = require("express-rate-limit");

const app = express();
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL || !process.env.JWT_SECRET) {
  throw new Error("DATABASE_URL and JWT_SECRET are required");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

app.use(helmet());
app.use(express.json({ limit: "1mb" }));
app.use(express.static(__dirname));

const authLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

// Database setup and migrations
async function setupDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(30) UNIQUE NOT NULL,
      display_name VARCHAR(60) NOT NULL,
      password_hash TEXT NOT NULL,
      bio VARCHAR(250) DEFAULT '',
      avatar TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS posts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      content TEXT NOT NULL,
      image_url TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS likes (
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY(user_id, post_id)
    );

    CREATE TABLE IF NOT EXISTS comments (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
      content VARCHAR(1000) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS follows (
      follower_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      following_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY(follower_id, following_id),
      CHECK(follower_id <> following_id)
    );
  `);

  // Fix existing databases without deleting user data
  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS bio VARCHAR(250) DEFAULT '';

    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS avatar TEXT DEFAULT '';
  `);
}

// JWT token
function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username
    },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

// Authentication middleware
function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  if (!token) {
    return res.status(401).json({
      error: "ابتدا وارد حساب شو"
    });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      error: "نشست نامعتبر یا منقضی شده"
    });
  }
}

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    app: "Scrool Social"
  });
});

// Register
app.post("/api/register", authLimit, async (req, res) => {
  try {
    const { username, displayName, password } = req.body || {};

    if (
      typeof username !== "string" ||
      !/^[a-zA-Z0-9_]{3,30}$/.test(username) ||
      typeof displayName !== "string" ||
      displayName.trim().length < 2 ||
      displayName.trim().length > 60 ||
      typeof password !== "string" ||
      password.length < 8 ||
      password.length > 72
    ) {
      return res.status(400).json({
        error: "اطلاعات نامعتبر است. رمز باید حداقل ۸ کاراکتر باشد."
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (username, display_name, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, username, display_name`,
      [username.toLowerCase(), displayName.trim(), hash]
    );

    const user = result.rows[0];

    return res.status(201).json({
      token: createToken(user),
      user
    });

  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({
        error: "این نام کاربری قبلاً ثبت شده"
      });
    }

    console.error("Register error:", err);

    return res.status(500).json({
      error: "خطای سرور"
    });
  }
});

// Login
app.post("/api/login", authLimit, async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (
      typeof username !== "string" ||
      typeof password !== "string" ||
      username.length > 30 ||
      password.length > 72
    ) {
      return res.status(400).json({
        error: "اطلاعات نامعتبر است"
      });
    }

    const result = await pool.query(
      `SELECT id, username, display_name, password_hash
       FROM users
       WHERE username = $1`,
      [username.toLowerCase()]
    );

    const user = result.rows[0];

    if (
      !user ||
      !(await bcrypt.compare(password, user.password_hash))
    ) {
      return res.status(401).json({
        error: "نام کاربری یا رمز عبور اشتباه است"
      });
    }

    return res.json({
      token: createToken(user),
      user: {
        id: user.id,
        username: user.username,
        display_name: user.display_name
      }
    });

  } catch (err) {
    console.error("Login error:", err);

    return res.status(500).json({
      error: "خطای سرور"
    });
  }
});

// Current user
app.get("/api/me", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, display_name, bio, avatar, created_at
       FROM users
       WHERE id = $1`,
      [req.user.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        error: "کاربر پیدا نشد"
      });
    }

    return res.json({
      user: result.rows[0]
    });

  } catch (err) {
    console.error("Current user error:", err);

    return res.status(500).json({
      error: "خطای سرور"
    });
  }
});

// API information
app.get("/api", (req, res) => {
  res.json({
    name: "Scrool Social",
    version: "1.0.0"
  });
});

// Start server
async function start() {
  await setupDatabase();

  app.listen(PORT, "0.0.0.0", () => {
    console.log("Scrool Social running on port " + PORT);
  });
}

start().catch(err => {
  console.error("Startup failed:", err);
  process.exit(1);
});
