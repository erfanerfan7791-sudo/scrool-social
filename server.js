
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
  connectionTimeoutMillis: 15000,
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

// =====================================
// DATABASE
// =====================================

async function setupDatabase() {
  const connection = await pool.query(`
    SELECT current_database() AS database_name,
           current_schema() AS schema_name
  `);

  console.log("DATABASE CONNECTION:", connection.rows[0]);

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

  await pool.query(`
    ALTER TABLE public.users
    ADD COLUMN IF NOT EXISTS bio VARCHAR(250) DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE public.users
    ADD COLUMN IF NOT EXISTS avatar TEXT DEFAULT ''
  `);

  await pool.query(`
    UPDATE public.users
    SET bio = ''
    WHERE bio IS NULL
  `);

  await pool.query(`
    UPDATE public.users
    SET avatar = ''
    WHERE avatar IS NULL
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS public.posts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES public.users(id) ON DELETE CASCADE,
      content TEXT NOT NULL,
      image_url TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS public.likes (
      user_id INTEGER REFERENCES public.users(id) ON DELETE CASCADE,
      post_id INTEGER REFERENCES public.posts(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (user_id, post_id)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS public.comments (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES public.users(id) ON DELETE CASCADE,
      post_id INTEGER REFERENCES public.posts(id) ON DELETE CASCADE,
      content VARCHAR(1000) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS public.follows (
      follower_id INTEGER REFERENCES public.users(id) ON DELETE CASCADE,
      following_id INTEGER REFERENCES public.users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (follower_id, following_id),
      CHECK (follower_id <> following_id)
    )
  `);

  const result = await pool.query(`
    SELECT column_name
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'users'
    ORDER BY ordinal_position
  `);

  const columns = result.rows.map(row => row.column_name);

  console.log("USERS COLUMNS:", columns.join(", "));

  if (!columns.includes("bio") || !columns.includes("avatar")) {
    throw new Error("Database migration failed");
  }

  console.log("Database migrations completed successfully");
}

// =====================================
// JWT
// =====================================

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

// =====================================
// AUTHENTICATION
// =====================================

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

// =====================================
// HEALTH
// =====================================

app.get("/api/health", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT current_database() AS database_name
    `);

    res.json({
      status: "ok",
      database: "connected",
      databaseName: result.rows[0].database_name,
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

// =====================================
// REGISTER
// =====================================

app.post("/api/register", authLimit, async (req, res) => {
  try {
    const { username, displayName, password } = req.body || {};

    if (typeof username !== "string") {
      return res.status(400).json({
        error: "نام کاربری را وارد کن."
      });
    }

    const cleanUsername = username.trim().toLowerCase();

    if (!/^[a-z0-9_]{3,30}$/.test(cleanUsername)) {
      return res.status(400).json({
        error: "نام کاربری باید ۳ تا ۳۰ کاراکتر و فقط شامل حروف انگلیسی، عدد یا _ باشد."
      });
    }

    if (
      typeof displayName !== "string" ||
      displayName.trim().length < 2 ||
      displayName.trim().length > 60
    ) {
      return res.status(400).json({
        error: "نام نمایشی باید بین ۲ تا ۶۰ کاراکتر باشد."
      });
    }

    if (
      typeof password !== "string" ||
      password.length < 8 ||
      password.length > 72
    ) {
      return res.status(400).json({
        error: "رمز عبور باید بین ۸ تا ۷۲ کاراکتر باشد."
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO public.users
       (username, display_name, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, username, display_name, bio, avatar, created_at`,
      [
        cleanUsername,
        displayName.trim(),
        hash
      ]
    );

    const user = result.rows[0];

    return res.status(201).json({
      token: createToken(user),
      user
    });

  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({
        error: "این نام کاربری قبلاً ثبت شده است."
      });
    }

    console.error("Register error:", err);

    return res.status(500).json({
      error: "خطای سرور"
    });
  }
});

// =====================================
// LOGIN
// =====================================

app.post("/api/login", authLimit, async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (
      typeof username !== "string" ||
      typeof password !== "string" ||
      password.length > 72
    ) {
      return res.status(400).json({
        error: "اطلاعات ورود نامعتبر است."
      });
    }

    const cleanUsername = username.trim().toLowerCase();

    if (!cleanUsername || cleanUsername.length > 30) {
      return res.status(400).json({
        error: "نام کاربری نامعتبر است."
      });
    }

    const result = await pool.query(
      `SELECT id, username, display_name, password_hash
       FROM public.users
       WHERE username = $1`,
      [cleanUsername]
    );

    const user = result.rows[0];

    if (
      !user ||
      !(await bcrypt.compare(password, user.password_hash))
    ) {
      return res.status(401).json({
        error: "نام کاربری یا رمز عبور اشتباه است."
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

// =====================================
// CURRENT USER
// =====================================

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

// =====================================
// API
// =====================================

app.get("/api", (req, res) => {
  res.json({
    name: "Scrool Social",
    version: "1.0.1",
    status: "running"
  });
});

// =====================================
// ERROR HANDLER
// =====================================

app.use((err, req, res, next) => {
  console.error("Unexpected error:", err);

  res.status(500).json({
    error: "خطای داخلی سرور"
  });
});

// =====================================
// START
// =====================================

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
