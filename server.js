
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
    : { rejectUnauthorized: false },
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000
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

// ===============================
// DATABASE SETUP
// ===============================

async function setupDatabase() {
  // Users
  await pool.query(`
    CREATE TABLE IF NOT EXISTS public.users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(30) UNIQUE NOT NULL,
      display_name VARCHAR(60) NOT NULL,
      password_hash TEXT NOT NULL,
      bio VARCHAR(250) DEFAULT '',
      avatar TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Migrations for existing users table
  await pool.query(`
    ALTER TABLE public.users
    ADD COLUMN IF NOT EXISTS bio VARCHAR(250) DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE public.users
    ADD COLUMN IF NOT EXISTS avatar TEXT DEFAULT ''
  `);

  // Posts
  await pool.query(`
    CREATE TABLE IF NOT EXISTS public.posts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES public.users(id) ON DELETE CASCADE,
      content TEXT NOT NULL,
      image_url TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Likes
  await pool.query(`
    CREATE TABLE IF NOT EXISTS public.likes (
      user_id INTEGER REFERENCES public.users(id) ON DELETE CASCADE,
      post_id INTEGER REFERENCES public.posts(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY(user_id, post_id)
    )
  `);

  // Comments
  await pool.query(`
    CREATE TABLE IF NOT EXISTS public.comments (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES public.users(id) ON DELETE CASCADE,
      post_id INTEGER REFERENCES public.posts(id) ON DELETE CASCADE,
      content VARCHAR(1000) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Follows
  await pool.query(`
    CREATE TABLE IF NOT EXISTS public.follows (
      follower_id INTEGER REFERENCES public.users(id) ON DELETE CASCADE,
      following_id INTEGER REFERENCES public.users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY(follower_id, following_id),
      CHECK(follower_id <> following_id)
    )
  `);

  // Verify users table columns
  const check = await pool.query(`
    SELECT column_name
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'users'
    ORDER BY ordinal_position
  `);

  const columns = check.rows.map(row => row.column_name);

  console.log("Users table columns:", columns.join(", "));

  if (!columns.includes("bio") || !columns.includes("avatar")) {
    throw new Error("Required users columns are missing");
  }

  console.log("Database migrations completed successfully");
}

// ===============================
// JWT
// ===============================

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

// ===============================
// AUTHENTICATION
// ===============================

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

// ===============================
// HEALTH CHECK
// ===============================

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      status: "ok",
      database: "connected",
      app: "Scrool Social"
    });
  } catch (err) {
    console.error("Health error:", err);

    res.status(503).json({
      status: "error",
      database: "disconnected"
    });
  }
});

// ===============================
// REGISTER
// ===============================

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
      `INSERT INTO public.users
       (username, display_name, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, username, display_name, bio, avatar, created_at`,
      [
        username.toLowerCase(),
        displayName.trim(),
        hash
      ]
    );

    const user = result.rows[0];

    res.status(201).json({
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

    res.status(500).json({
      error: "خطای سرور"
    });
  }
});

// ===============================
// LOGIN
// ===============================

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
       FROM public.users
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

    res.json({
      token: createToken(user),
      user: {
        id: user.id,
        username: user.username,
        display_name: user.display_name
      }
    });

  } catch (err) {
    console.error("Login error:", err);

    res.status(500).json({
      error: "خطای سرور"
    });
  }
});

// ===============================
// CURRENT USER
// ===============================

app.get("/api/me", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
        id,
        username,
        display_name,
        bio,
        avatar,
        created_at
       FROM public.users
       WHERE id = $1`,
      [req.user.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        error: "کاربر پیدا نشد"
      });
    }

    res.json({
      user: result.rows[0]
    });

  } catch (err) {
    console.error("Current user error:", err);

    res.status(500).json({
      error: "خطای سرور"
    });
  }
});

// ===============================
// API INFORMATION
// ===============================

app.get("/api", (req, res) => {
  res.json({
    name: "Scrool Social",
    version: "1.0.0",
    status: "running"
  });
});

// ===============================
// ERROR HANDLER
// ===============================

app.use((err, req, res, next) => {
  console.error("Unexpected error:", err);

  res.status(500).json({
    error: "خطای داخلی سرور"
  });
});

// ===============================
// START SERVER
// ===============================

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
