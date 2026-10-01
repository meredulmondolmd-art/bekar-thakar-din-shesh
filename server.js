import express from "express";
import session from "express-session";
import pg from "pg";
import pgSession from "connect-pg-simple";
import bcrypt from "bcryptjs";
import crypto from "crypto";

const { Pool } = pg;
const app = express();
const PORT = Number(process.env.PORT || 3000);

if (
  !process.env.DATABASE_URL ||
  !process.env.SESSION_SECRET ||
  !process.env.ADMIN_PASSWORD
) {
  console.error(
    "DATABASE_URL, SESSION_SECRET and ADMIN_PASSWORD are required"
  );
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,
});

const Store = pgSession(session);

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));

/* Render proxy/session support */
app.set("trust proxy", 1);

app.use(
  session({
    store: new Store({
      pool,
      tableName: "sessions",
      createTableIfMissing: true,
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: true,
      maxAge: 604800000,
    },
  })
);

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  next();
});

const q = async (text, params = []) => {
  const result = await pool.query(text, params);
  return result.rows;
};

const auth = (req, res, next) => {
  if (req.session.userId) return next();
  return res.status(401).json({ error: "login required" });
};

const admin = (req, res, next) => {
  if (req.session.isAdmin) return next();
  return res.status(401).json({ error: "admin required" });
};

async function init() {
  await q(`
    CREATE TABLE IF NOT EXISTS users(
      id BIGSERIAL PRIMARY KEY,
      login TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      balance NUMERIC(12,2) DEFAULT 70,
      referral_code TEXT UNIQUE NOT NULL,
      referred_by BIGINT REFERENCES users(id),
      created_at TIMESTAMPTZ DEFAULT now(),
      banned_until TIMESTAMPTZ
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS tasks(
      id BIGSERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      reward NUMERIC(12,2) NOT NULL,
      enabled BOOLEAN DEFAULT true
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS claims(
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
      task_id BIGINT REFERENCES tasks(id) ON DELETE CASCADE,
      UNIQUE(user_id,task_id)
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS ads(
      id BIGSERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      reward NUMERIC(12,2) DEFAULT 5,
      min_seconds INT DEFAULT 15,
      enabled BOOLEAN DEFAULT true
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS ad_views(
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
      ad_id BIGINT REFERENCES ads(id),
      viewed_at TIMESTAMPTZ DEFAULT now()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS videos(
      id BIGSERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      url TEXT NOT NULL,
      reward_per_minute NUMERIC(12,2) DEFAULT 1,
      enabled BOOLEAN DEFAULT true
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS withdrawals(
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES users(id),
      method TEXT NOT NULL,
      payout_number TEXT NOT NULL,
      amount NUMERIC(12,2) NOT NULL,
      status TEXT DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT now()
    )
  `);
}

app.get("/api/config", async (req, res) => {
  res.json({ name: "বেকার থাকার দিন শেষ" });
});

/* REGISTER */
app.post("/api/register", async (req, res) => {
  try {
    let {
      login,
      password,
      confirmPassword,
      referralCode = "",
    } = req.body;

    if (
      !login ||
      !password ||
      password !== confirmPassword ||
      password.length < 6
    ) {
      return res.status(400).json({
        error: "তথ্য ঠিকভাবে দিন",
      });
    }

    login = String(login).trim().toLowerCase();

    if ((await q("SELECT id FROM users WHERE login=$1", [login])).length) {
      return res.status(409).json({
        error: "এই নম্বর/ইমেইল আগে ব্যবহার হয়েছে",
      });
    }

    const ref =
      (
        await q(
          "SELECT id FROM users WHERE referral_code=$1",
          [String(referralCode).trim()]
        )
      )[0]?.id || null;

    const code = crypto.randomBytes(5).toString("hex");

    const u = (
      await q(
        `INSERT INTO users
        (login,password_hash,referral_code,referred_by)
        VALUES($1,$2,$3,$4)
        RETURNING id,login,balance,referral_code`,
        [login, await bcrypt.hash(password, 12), code, ref]
      )
    )[0];

    if (ref) {
      await q(
        "UPDATE users SET balance=balance+20 WHERE id=$1",
        [ref]
      );
    }

    req.session.userId = u.id;

    req.session.save((err) => {
      if (err) {
        console.error("Session save error:", err);
        return res.status(500).json({
          error: "session error",
        });
      }

      res.json({ user: u });
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: "server error",
    });
  }
});

/* LOGIN */
app.post("/api/login", async (req, res) => {
  try {
    const login = String(req.body.login || "")
      .trim()
      .toLowerCase();

    const u = (
      await q(
        "SELECT * FROM users WHERE login=$1",
        [login]
      )
    )[0];

    if (
      !u ||
      !(await bcrypt.compare(
        String(req.body.password || ""),
        u.password_hash
      ))
    ) {
      return res.status(401).json({
        error: "ভুল লগইন তথ্য",
      });
    }

    if (
      u.banned_until &&
      new Date(u.banned_until) > new Date()
    ) {
      return res.status(403).json({
        error: "account banned",
      });
    }

    req.session.userId = u.id;

    req.session.save((err) => {
      if (err) {
        console.error("Session save error:", err);
        return res.status(500).json({
          error: "session error",
        });
      }

      res.json({ ok: true });
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: "server error",
    });
  }
});

/* LOGOUT */
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

/* CURRENT USER */
app.get("/api/me", auth, async (req, res) => {
  const u = (
    await q(
      `SELECT id,login,balance,referral_code,banned_until
       FROM users WHERE id=$1`,
      [req.session.userId]
    )
  )[0];

  if (!u) {
    return res.status(401).json({
      error: "user not found",
    });
  }

  res.json({ user: u });
});

/* CONTENT */
app.get("/api/content", auth, async (req, res) => {
  res.json({
    tasks: await q(
      "SELECT * FROM tasks WHERE enabled=true ORDER BY id DESC"
    ),
    ads: await q(
      "SELECT * FROM ads WHERE enabled=true ORDER BY id DESC"
    ),
    videos: await q(
      "SELECT * FROM videos WHERE enabled=true ORDER BY id DESC"
    ),
  });
});

/* CLAIM TASK */
app.post("/api/tasks/:id/claim", auth, async (req, res) => {
  const t = (
    await q(
      "SELECT * FROM tasks WHERE id=$1 AND enabled=true",
      [Number(req.params.id)]
    )
  )[0];

  if (!t) {
    return res.status(404).json({
      error: "task not found",
    });
  }

  try {
    await q(
      "INSERT INTO claims(user_id,task_id) VALUES($1,$2)",
      [req.session.userId, t.id]
    );

    await q(
      "UPDATE users SET balance=balance+$1 WHERE id=$2",
      [t.reward, req.session.userId]
    );

    res.json({
      reward: t.reward,
    });
  } catch (e) {
    if (e.code === "23505") {
      return res.status(409).json({
        error: "এই task আগেই নেওয়া হয়েছে",
      });
    }

    res.status(500).json({
      error: "server error",
    });
  }
});

/* COMPLETE AD */
app.post("/api/ads/:id/complete", auth, async (req, res) => {
  const a = (
    await q(
      "SELECT * FROM ads WHERE id=$1 AND enabled=true",
      [Number(req.params.id)]
    )
  )[0];

  const seconds = Number(req.body.seconds || 0);

  if (!a || seconds < a.min_seconds) {
    return res.status(409).json({
      error: `কমপক্ষে ${a?.min_seconds || 15} সেকেন্ড দেখতে হবে`,
    });
  }

  const n = (
    await q(
      `SELECT count(*)::int n
       FROM ad_views
       WHERE user_id=$1
       AND viewed_at::date=current_date`,
      [req.session.userId]
    )
  )[0].n;

  if (n >= 25) {
    return res.status(429).json({
      error: "আজকের ২৫টি ad শেষ",
    });
  }

  await q(
    "INSERT INTO ad_views(user_id,ad_id) VALUES($1,$2)",
    [req.session.userId, a.id]
  );

  await q(
    "UPDATE users SET balance=balance+$1 WHERE id=$2",
    [a.reward, req.session.userId]
  );

  res.json({
    reward: a.reward,
  });
});

/* WITHDRAW */
app.post("/api/withdraw", auth, async (req, res) => {
  let { method, number, amount } = req.body;

  amount = Number(amount);

  if (
    !["bkash", "nagad", "rocket"].includes(method) ||
    !number ||
    amount < 1200 ||
    amount > 25000
  ) {
    return res.status(400).json({
      error: "উত্তোলনের সীমা ৳১২০০–৳২৫০০০",
    });
  }

  const c = await pool.connect();

  try {
    await c.query("BEGIN");

    const u = (
      await c.query(
        "SELECT balance FROM users WHERE id=$1 FOR UPDATE",
        [req.session.userId]
      )
    ).rows[0];

    if (Number(u.balance) < amount) {
      await c.query("ROLLBACK");

      return res.status(400).json({
        error: "আপনার account-এ পর্যাপ্ত balance নেই",
      });
    }

    await c.query(
      "UPDATE users SET balance=balance-$1 WHERE id=$2",
      [amount, req.session.userId]
    );

    await c.query(
      `INSERT INTO withdrawals
       (user_id,method,payout_number,amount)
       VALUES($1,$2,$3,$4)`,
      [
        req.session.userId,
        method,
        String(number).trim(),
        amount,
      ]
    );

    await c.query("COMMIT");

    res.json({
      ok: true,
    });
  } catch (e) {
    await c.query("ROLLBACK");

    console.error(e);

    res.status(500).json({
      error: "server error",
    });
  } finally {
    c.release();
  }
});

/* ADMIN LOGIN */
app.post("/api/admin/login", (req, res) => {
  if (
    String(req.body.password || "") !==
    process.env.ADMIN_PASSWORD
  ) {
    return res.status(401).json({
      error: "ভুল admin password",
    });
  }

  req.session.regenerate((e) => {
    if (e) {
      return res.status(500).json({
        error: "session error",
      });
    }

    req.session.isAdmin = true;

    req.session.save((err) => {
      if (err) {
        return res.status(500).json({
          error: "session error",
        });
      }

      res.json({
        ok: true,
      });
    });
  });
});

/* ADMIN DATA */
app.get("/api/admin/data", admin, async (req, res) => {
  res.json({
    users: await q(
      `SELECT id,login,balance,referral_code,banned_until
       FROM users ORDER BY id DESC`
    ),
    withdrawals: await q(
      "SELECT * FROM withdrawals ORDER BY id DESC"
    ),
    tasks: await q(
      "SELECT * FROM tasks ORDER BY id DESC"
    ),
    ads: await q(
      "SELECT * FROM ads ORDER BY id DESC"
    ),
    videos: await q(
      "SELECT * FROM videos ORDER BY id DESC"
    ),
  });
});

/* ADMIN ADD TASK */
app.post("/api/admin/tasks", admin, async (req, res) => {
  res.json({
    row: (
      await q(
        `INSERT INTO tasks
         (title,description,reward)
         VALUES($1,$2,$3)
         RETURNING *`,
        [
          req.body.title,
          req.body.description || "",
          Number(req.body.reward),
        ]
      )
    )[0],
  });
});

/* ADMIN ADD AD */
app.post("/api/admin/ads", admin, async (req, res) => {
  res.json({
    row: (
      await q(
        `INSERT INTO ads
         (title,reward,min_seconds)
         VALUES($1,$2,$3)
         RETURNING *`,
        [
          req.body.title,
          Number(req.body.reward || 5),
          Number(req.body.minSeconds || 15),
        ]
      )
    )[0],
  });
});

/* ADMIN ADD VIDEO */
app.post("/api/admin/videos", admin, async (req, res) => {
  res.json({
    row: (
      await q(
        `INSERT INTO videos
         (title,url,reward_per_minute)
         VALUES($1,$2,$3)
         RETURNING *`,
        [
          req.body.title,
          req.body.url,
          Number(req.body.rewardPerMinute || 1),
        ]
      )
    )[0],
  });
});

/* ADMIN BAN USER */
app.post("/api/admin/users/:id/ban", admin, async (req, res) => {
  await q(
    `UPDATE users
     SET banned_until=now()+interval '3 days'
     WHERE id=$1`,
    [Number(req.params.id)]
  );

  res.json({
    ok: true,
  });
});

/* ADMIN APPROVE WITHDRAWAL */
app.post(
  "/api/admin/withdrawals/:id/approve",
  admin,
  async (req, res) => {
    await q(
      `UPDATE withdrawals
       SET status='approved'
       WHERE id=$1 AND status='pending'`,
      [Number(req.params.id)]
    );

    res.json({
      ok: true,
    });
  }
);

/* ADMIN REJECT WITHDRAWAL */
app.post(
  "/api/admin/withdrawals/:id/reject",
  admin,
  async (req, res) => {
    const w = (
      await q(
        `SELECT * FROM withdrawals
         WHERE id=$1 AND status='pending'`,
        [Number(req.params.id)]
      )
    )[0];

    if (!w) {
      return res.status(404).json({
        error: "not found",
      });
    }

    await q(
      "UPDATE withdrawals SET status='rejected' WHERE id=$1",
      [w.id]
    );

    await q(
      "UPDATE users SET balance=balance+$1 WHERE id=$2",
      [w.amount, w.user_id]
    );

    res.json({
      ok: true,
    });
  }
);

/* START SERVER */
init()
  .then(() => {
    app.listen(PORT, () => {
      console.log("Server running on " + PORT);
    });
  })
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
