import express from "express";
import pg from "pg";
import bcrypt from "bcryptjs";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import crypto from "crypto";

const { Pool } = pg;
const PgSession = connectPgSimple(session);

const app = express();

app.set("trust proxy", 1);

app.use(express.json({ limit: "15mb" }));
app.use(express.urlencoded({ extended: true, limit: "15mb" }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

/* =========================
   SESSION TABLE
========================= */

async function createSessionTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_sessions (
      sid VARCHAR NOT NULL PRIMARY KEY,
      sess JSON NOT NULL,
      expire TIMESTAMP(6) NOT NULL
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS app_sessions_expire_idx
    ON app_sessions(expire)
  `);
}

app.use(
  session({
    store: new PgSession({
      pool,
      tableName: "app_sessions",
      createTableIfMissing: false
    }),
    secret: process.env.SESSION_SECRET || "change-this-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 30
    }
  })
);

app.use(express.static("public"));

/* =========================
   HELPERS
========================= */

const randomCode = () =>
  crypto.randomBytes(5).toString("hex").toUpperCase();

const isValidUrl = (u) =>
  /^https?:\/\//i.test(String(u || ""));

async function q(text, params = []) {
  return pool.query(text, params);
}

async function logAction(actor, action, details = "", userId = null) {
  try {
    await q(
      `INSERT INTO activity_logs(user_id, actor, action, details)
       VALUES($1,$2,$3,$4)`,
      [userId, actor, action, details]
    );
  } catch {}
}

/* =========================
   DATABASE
========================= */

async function initDb() {
  await q(`
    CREATE TABLE IF NOT EXISTS users(
      id SERIAL PRIMARY KEY,
      login TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      referral_code TEXT UNIQUE NOT NULL,
      referred_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      balance NUMERIC(12,2) NOT NULL DEFAULT 0,
      banned_until TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS tasks(
      id SERIAL PRIMARY KEY,
      type TEXT NOT NULL
        CHECK(type IN ('ad','facebook','youtube')),
      title TEXT NOT NULL,
      description TEXT,
      url TEXT,
      reference_image TEXT,
      reward NUMERIC(12,2) NOT NULL DEFAULT 0,
      min_seconds INTEGER NOT NULL DEFAULT 15,
      enabled BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS claims(
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
      task_id INTEGER NOT NULL
        REFERENCES tasks(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(user_id, task_id)
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS ad_sessions(
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
      task_id INTEGER NOT NULL
        REFERENCES tasks(id) ON DELETE CASCADE,
      token TEXT UNIQUE NOT NULL,
      started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      completed BOOLEAN NOT NULL DEFAULT FALSE
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS submissions(
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
      task_id INTEGER NOT NULL
        REFERENCES tasks(id) ON DELETE CASCADE,
      screenshot1 TEXT,
      screenshot2 TEXT,
      screenshot3 TEXT,
      screenshot4 TEXT,
      status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending','approved','rejected')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ
    )
  `);

  await q(`
    CREATE UNIQUE INDEX IF NOT EXISTS one_pending_submission
    ON submissions(user_id, task_id)
    WHERE status='pending'
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS withdrawals(
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
      method TEXT NOT NULL,
      payout_number TEXT NOT NULL,
      amount NUMERIC(12,2) NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS messages(
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
      sender TEXT NOT NULL
        CHECK(sender IN ('user','admin')),
      body TEXT NOT NULL,
      is_read BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS activity_logs(
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      actor TEXT NOT NULL,
      action TEXT NOT NULL,
      details TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

/* =========================
   AUTH
========================= */

async function getUser(id) {
  const r = await q(
    `SELECT id, login, referral_code, referred_by,
            balance, banned_until, created_at
     FROM users
     WHERE id=$1`,
    [id]
  );

  return r.rows[0];
}

function checkBan(user) {
  return (
    user?.banned_until &&
    new Date(user.banned_until) > new Date()
  );
}

function userOnly(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: "লগইন করুন"
    });
  }

  next();
}

function adminOnly(req, res, next) {
  if (!req.session.admin) {
    return res.status(401).json({
      error: "Admin login করুন"
    });
  }

  next();
}

/* =========================
   USER
========================= */

app.get("/api/me", userOnly, async (req, res) => {
  const user = await getUser(req.session.userId);

  if (!user) {
    return res.status(401).json({
      error: "Account পাওয়া যায়নি"
    });
  }

  if (checkBan(user)) {
    return res.status(403).json({
      error: "আপনার account সাময়িকভাবে banned"
    });
  }

  res.json({ user });
});

/* =========================
   REGISTER
========================= */

app.post("/api/register", async (req, res) => {
  const {
    login,
    password,
    confirmPassword,
    referralCode
  } = req.body;

  const cleanLogin = String(login || "").trim();

  if (cleanLogin.length < 4) {
    return res.status(400).json({
      error: "ফোন/Gmail দিন"
    });
  }

  if (String(password || "").length < 6) {
    return res.status(400).json({
      error: "পাসওয়ার্ড কমপক্ষে ৬ অক্ষরের দিন"
    });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({
      error: "পাসওয়ার্ড মিলছে না"
    });
  }

  try {
    const existing = await q(
      `SELECT id
       FROM users
       WHERE lower(login)=lower($1)`,
      [cleanLogin]
    );

    if (existing.rowCount) {
      return res.status(400).json({
        error: "এই account আগে থেকেই আছে"
      });
    }

    let referrer = null;

    if (referralCode) {
      const rr = await q(
        `SELECT id
         FROM users
         WHERE referral_code=$1`,
        [String(referralCode).trim().toUpperCase()]
      );

      if (rr.rowCount) {
        referrer = rr.rows[0].id;
      }
    }

    let code = randomCode();

    while (
      (
        await q(
          `SELECT 1
           FROM users
           WHERE referral_code=$1`,
          [code]
        )
      ).rowCount
    ) {
      code = randomCode();
    }

    const hash = await bcrypt.hash(password, 12);

    const inserted = await q(
      `INSERT INTO users(
        login,
        password_hash,
        referral_code,
        referred_by
      )
      VALUES($1,$2,$3,$4)
      RETURNING id`,
      [
        cleanLogin,
        hash,
        code,
        referrer
      ]
    );

    req.session.userId = inserted.rows[0].id;

    await new Promise((resolve, reject) => {
      req.session.save(err =>
        err ? reject(err) : resolve()
      );
    });

    await logAction(
      "user",
      "register",
      `login=${cleanLogin}`,
      inserted.rows[0].id
    );

    res.json({ ok: true });

  } catch (e) {
    console.error(e);

    res.status(500).json({
      error: "রেজিস্টার করা যায়নি"
    });
  }
});

/* =========================
   LOGIN
========================= */

app.post("/api/login", async (req, res) => {
  const login = String(req.body.login || "").trim();
  const password = String(req.body.password || "");

  const r = await q(
    `SELECT *
     FROM users
     WHERE lower(login)=lower($1)`,
    [login]
  );

  if (
    !r.rowCount ||
    !(await bcrypt.compare(
      password,
      r.rows[0].password_hash
    ))
  ) {
    return res.status(401).json({
      error: "Login তথ্য ভুল"
    });
  }

  if (checkBan(r.rows[0])) {
    return res.status(403).json({
      error: "আপনার account সাময়িকভাবে banned"
    });
  }

  req.session.userId = r.rows[0].id;

  await new Promise((resolve, reject) => {
    req.session.save(err =>
      err ? reject(err) : resolve()
    );
  });

  await logAction(
    "user",
    "login",
    `login=${login}`,
    r.rows[0].id
  );

  res.json({ ok: true });
});

/* =========================
   LOGOUT
========================= */

app.post("/api/logout", userOnly, async (req, res) => {
  const id = req.session.userId;

  await logAction(
    "user",
    "logout",
    "",
    id
  );

  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

/* =========================
   USER CONTENT
========================= */

app.get("/api/content", userOnly, async (req, res) => {
  const user = await getUser(req.session.userId);

  if (!user) {
    return res.status(401).json({
      error: "Account পাওয়া যায়নি"
    });
  }

  if (checkBan(user)) {
    return res.status(403).json({
      error: "আপনার account সাময়িকভাবে banned"
    });
  }

  const tasks = await q(`
    SELECT
      id,
      type,
      title,
      description,
      url,
      reference_image,
      reward,
      min_seconds,
      created_at
    FROM tasks
    WHERE enabled=true
    ORDER BY id DESC
  `);

  const submissions = await q(
    `SELECT
       s.id,
       s.task_id,
       s.status,
       s.created_at,
       t.title,
       t.type,
       t.reward
     FROM submissions s
     JOIN tasks t ON t.id=s.task_id
     WHERE s.user_id=$1
     ORDER BY s.id DESC`,
    [req.session.userId]
  );

  const referrals = await q(
    `SELECT COUNT(*)::int AS count
     FROM users
     WHERE referred_by=$1`,
    [req.session.userId]
  );

  const unread = await q(
    `SELECT COUNT(*)::int AS count
     FROM messages
     WHERE user_id=$1
     AND sender='admin'
     AND is_read=false`,
    [req.session.userId]
  );

  res.json({
    user,
    tasks: tasks.rows,
    submissions: submissions.rows,
    referralCount: referrals.rows[0].count,
    unreadMessages: unread.rows[0].count
  });
});

/* =========================
   AD START
========================= */
app.post(
  "/api/tasks/:id/start-ad",
  userOnly,
  async (req, res) => {
    const taskId = Number(req.params.id);

    const t = await q(
      `SELECT *
       FROM tasks
       WHERE id=$1
       AND type='ad'
       AND enabled=true`,
      [taskId]
    );

    if (!t.rowCount) {
      return res.status(404).json({
        error: "Ad পাওয়া যায়নি"
      });
    }

    const claimed = await q(
      `SELECT 1
       FROM claims
       WHERE user_id=$1
       AND task_id=$2`,
      [
        req.session.userId,
        taskId
      ]
    );

    if (claimed.rowCount) {
      return res.status(400).json({
        error: "এই Ad-এর reward আগে নেওয়া হয়েছে"
      });
    }

    const active = await q(
      `SELECT token
       FROM ad_sessions
       WHERE user_id=$1
       AND task_id=$2
       AND completed=false
       ORDER BY id DESC
       LIMIT 1`,
      [
        req.session.userId,
        taskId
      ]
    );

    if (active.rowCount) {
      return res.json({
        url: t.rows[0].url,
        seconds: Number(t.rows[0].min_seconds),
        token: active.rows[0].token
      });
    }

    const token = crypto
      .randomBytes(24)
      .toString("hex");

    await q(
      `INSERT INTO ad_sessions(
        user_id,
        task_id,
        token
      )
      VALUES($1,$2,$3)`,
      [
        req.session.userId,
        taskId,
        token
      ]
    );

    await logAction(
      "user",
      "ad_start",
      `task=${taskId}`,
      req.session.userId
    );

    res.json({
      url: t.rows[0].url,
      seconds: Number(t.rows[0].min_seconds),
      token
    });
  }
);

/* =========================
   AD COMPLETE
========================= */

app.post(
  "/api/tasks/:id/complete-ad",
  userOnly,
  async (req, res) => {
    const taskId = Number(req.params.id);
    const token = String(req.body.token || "");

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const a = await client.query(
        `SELECT
           a.*,
           t.reward,
           t.min_seconds,
           t.enabled
         FROM ad_sessions a
         JOIN tasks t ON t.id=a.task_id
         WHERE a.token=$1
         AND a.user_id=$2
         AND a.task_id=$3
         FOR UPDATE`,
        [
          token,
          req.session.userId,
          taskId
        ]
      );

      if (!a.rowCount) {
        throw new Error(
          "Ad session পাওয়া যায়নি"
        );
      }

      const row = a.rows[0];

      if (!row.enabled || row.completed) {
        throw new Error(
          "এই Ad আর ব্যবহার করা যাবে না"
        );
      }

      const elapsed =
        (
          Date.now() -
          new Date(row.started_at).getTime()
        ) / 1000;

      if (
        elapsed <
        Number(row.min_seconds)
      ) {
        throw new Error(
          `আরও ${Math.ceil(
            Number(row.min_seconds) - elapsed
          )} সেকেন্ড অপেক্ষা করুন`
        );
      }

      const exists = await client.query(
        `SELECT 1
         FROM claims
         WHERE user_id=$1
         AND task_id=$2`,
        [
          req.session.userId,
          taskId
        ]
      );

      if (exists.rowCount) {
        throw new Error(
          "Reward আগে নেওয়া হয়েছে"
        );
      }

      await client.query(
        `UPDATE users
         SET balance=balance+$1
         WHERE id=$2`,
        [
          row.reward,
          req.session.userId
        ]
      );

      await client.query(
        `INSERT INTO claims(
          user_id,
          task_id
        )
        VALUES($1,$2)`,
        [
          req.session.userId,
          taskId
        ]
      );

      await client.query(
        `UPDATE ad_sessions
         SET completed=true
         WHERE id=$1`,
        [row.id]
      );

      await client.query("COMMIT");

      await logAction(
        "user",
        "ad_reward",
        `task=${taskId}, reward=${row.reward}`,
        req.session.userId
      );

      res.json({
        ok: true,
        reward: Number(row.reward)
      });

    } catch (e) {
      await client.query("ROLLBACK");

      res.status(400).json({
        error:
          e.message ||
          "Reward দেওয়া যায়নি"
      });

    } finally {
      client.release();
    }
  }
);

/* =========================
   FACEBOOK / YOUTUBE SUBMIT
========================= */

app.post(
  "/api/tasks/:id/submit",
  userOnly,
  async (req, res) => {
    const taskId = Number(req.params.id);

    const t = await q(
      `SELECT *
       FROM tasks
       WHERE id=$1
       AND type IN ('facebook','youtube')
       AND enabled=true`,
      [taskId]
    );

    if (!t.rowCount) {
      return res.status(404).json({
        error: "কাজ পাওয়া যায়নি"
      });
    }

    const isYoutube =
      t.rows[0].type === "youtube";

    const {
      screenshot1,
      screenshot2,
      screenshot3,
      screenshot4
    } = req.body;

    if (!screenshot1) {
      return res.status(400).json({
        error: "Screenshot 1 দিন"
      });
    }

    if (
      isYoutube &&
      (
        !screenshot2 ||
        !screenshot3 ||
        !screenshot4
      )
    ) {
      return res.status(400).json({
        error:
          "YouTube কাজের জন্য ৪টি Screenshot দিন"
      });
    }

    for (
      const s of [
        screenshot1,
        screenshot2,
        screenshot3,
        screenshot4
      ].filter(Boolean)
    ) {
      if (
        !String(s).startsWith("data:image/")
      ) {
        return res.status(400).json({
          error:
            "শুধু image upload করা যাবে"
        });
      }
    }

    const claimed = await q(
      `SELECT 1
       FROM claims
       WHERE user_id=$1
       AND task_id=$2`,
      [
        req.session.userId,
        taskId
      ]
    );

    if (claimed.rowCount) {
      return res.status(400).json({
        error:
          "এই কাজের reward ইতিমধ্যে দেওয়া হয়েছে"
      });
    }

    try {
      await q(
        `INSERT INTO submissions(
          user_id,
          task_id,
          screenshot1,
          screenshot2,
          screenshot3,
          screenshot4
        )
        VALUES($1,$2,$3,$4,$5,$6)`,
        [
          req.session.userId,
          taskId,
          screenshot1,
          screenshot2 || null,
          screenshot3 || null,
          screenshot4 || null
        ]
      );

      await logAction(
        "user",
        "task_submit",
        `task=${taskId}`,
        req.session.userId
      );

      res.json({ ok: true });

    } catch {
      res.status(400).json({
        error:
          "এই কাজের একটি Pending submission ইতিমধ্যে আছে"
      });
    }
  }
);

/* =========================
   WITHDRAW
========================= */

app.post(
  "/api/withdraw",
  userOnly,
  async (req, res) => {
    const method =
      String(req.body.method || "");

    const number =
      String(req.body.number || "").trim();

    const amount =
      Number(req.body.amount);

    if (
      !["bkash", "nagad", "rocket"]
        .includes(method)
    ) {
      return res.status(400).json({
        error: "Payment method ভুল"
      });
    }

    if (!/^\d{10,15}$/.test(number)) {
      return res.status(400).json({
        error: "সঠিক payment number দিন"
      });
    }

    if (
      !Number.isFinite(amount) ||
      amount < 1200 ||
      amount > 25000
    ) {
      return res.status(400).json({
        error:
          "Withdraw 1200 থেকে 25000 টাকার মধ্যে হতে হবে"
      });
    }

    const client =
      await pool.connect();

    try {
      await client.query("BEGIN");

      const u = await client.query(
        `SELECT balance
         FROM users
         WHERE id=$1
         FOR UPDATE`,
        [req.session.userId]
      );

      if (
        !u.rowCount ||
        Number(u.rows[0].balance) < amount
      ) {
        throw new Error(
          "Balance যথেষ্ট নয়"
        );
      }

      await client.query(
        `UPDATE users
         SET balance=balance-$1
         WHERE id=$2`,
        [
          amount,
          req.session.userId
        ]
      );

      await client.query(
        `INSERT INTO withdrawals(
          user_id,
          method,
          payout_number,
          amount
        )
        VALUES($1,$2,$3,$4)`,
        [
          req.session.userId,
          method,
          number,
          amount
        ]
      );

      await client.query("COMMIT");

      await logAction(
        "user",
        "withdraw_request",
        `method=${method}, amount=${amount}`,
        req.session.userId
      );

      res.json({ ok: true });

    } catch (e) {
      await client.query("ROLLBACK");

      res.status(400).json({
        error: e.message
      });

    } finally {
      client.release();
    }
  }
);

/* =========================
   USER MESSAGES
========================= */

app.get(
  "/api/messages",
  userOnly,
  async (req, res) => {
    await q(
      `UPDATE messages
       SET is_read=true
       WHERE user_id=$1
       AND sender='admin'`,
      [req.session.userId]
    );

    const r = await q(
      `SELECT
         id,
         sender,
         body,
         created_at
       FROM messages
       WHERE user_id=$1
       ORDER BY id ASC`,
      [req.session.userId]
    );

    res.json({
      messages: r.rows
    });
  }
);

app.post(
  "/api/messages",
  userOnly,
  async (req, res) => {
    const body =
      String(req.body.body || "").trim();

    if (
      !body ||
      body.length > 2000
    ) {
      return res.status(400).json({
        error:
          "মেসেজ ১-২০০০ অক্ষরের মধ্যে দিন"
      });
    }

    await q(
      `INSERT INTO messages(
        user_id,
        sender,
        body
      )
      VALUES($1,'user',$2)`,
      [
        req.session.userId,
        body
      ]
    );

    await logAction(
      "user",
      "message_send",
      "User sent message",
      req.session.userId
    );

    res.json({ ok: true });
  }
);

/* =========================
   ADMIN LOGIN
========================= */

app.post(
  "/api/admin/login",
  async (req, res) => {
    if (
      String(req.body.password || "") !==
      String(process.env.ADMIN_PASSWORD || "")
    ) {
      await logAction(
        "admin",
        "admin_login_failed"
      );

      return res.status(401).json({
        error: "Admin password ভুল"
      });
    }

    req.session.admin = true;

    await new Promise((resolve, reject) => {
      req.session.save(err =>
        err ? reject(err) : resolve()
      );
    });

    await logAction(
      "admin",
      "admin_login"
    );

    res.json({ ok: true });
  }
);

/* =========================
   ADMIN LOGOUT
========================= */

app.post(
  "/api/admin/logout",
  adminOnly,
  async (req, res) => {
    await logAction(
      "admin",
      "admin_logout"
    );

    req.session.admin = false;

    req.session.save(() => {
      res.json({ ok: true });
    });
  }
);

/* =========================
   ADMIN DATA
========================= */

app.get(
  "/api/admin/data",
  adminOnly,
  async (req, res) => {
    const [
      tasks,
      submissions,
      users,
      withdrawals,
      messages,
      logs
    ] = await Promise.all([
      q(
        `SELECT *
         FROM tasks
         ORDER BY id DESC`
      ),

      q(
        `SELECT
           s.*,
           u.login,
           t.title,
           t.type,
           t.reward,
           t.reference_image
         FROM submissions s
         JOIN users u ON u.id=s.user_id
         JOIN tasks t ON t.id=s.task_id
         ORDER BY s.id DESC`
      ),

      q(
        `SELECT
           id,
           login,
           referral_code,
           balance,
           referred_by,
           banned_until,
           created_at
         FROM users
         ORDER BY id DESC`
      ),

      q(
        `SELECT
           w.*,
           u.login
         FROM withdrawals w
         JOIN users u ON u.id=w.user_id
         ORDER BY w.id DESC`
      ),

      q(
        `SELECT
           m.*,
           u.login
         FROM messages m
         JOIN users u ON u.id=m.user_id
         ORDER BY m.id DESC`
      ),

      q(
        `SELECT
           l.*,
           u.login
         FROM activity_logs l
         LEFT JOIN users u ON u.id=l.user_id
         ORDER BY l.id DESC
         LIMIT 300`
      )
    ]);

    const unread = await q(
      `SELECT COUNT(*)::int AS count
       FROM messages
       WHERE sender='user'
       AND is_read=false`
    );

    res.json({
      tasks: tasks.rows,
      submissions: submissions.rows,
      users: users.rows,
      withdrawals: withdrawals.rows,
      messages: messages.rows,
      logs: logs.rows,
      unreadMessages:
        unread.rows[0].count
    });
  }
);

/* =========================
   ADMIN CREATE TASK
========================= */

app.post(
  "/api/admin/tasks",
  adminOnly,
  async (req, res) => {
    const {
      type,
      title,
      description,
      url,
      referenceImage,
      reward,
      minSeconds
    } = req.body;

    if (
      !["ad", "facebook", "youtube"]
        .includes(type)
    ) {
      return res.status(400).json({
        error: "Task type ভুল"
      });
    }

    if (!String(title || "").trim()) {
      return res.status(400).json({
        error: "Title দিন"
      });
    }

    if (!isValidUrl(url)) {
      return res.status(400).json({
        error: "সঠিক URL দিন"
      });
    }

    if (
      !Number.isFinite(Number(reward)) ||
      Number(reward) <= 0
    ) {
      return res.status(400).json({
        error: "সঠিক reward দিন"
      });
    }

    if (
      type !== "ad" &&
      !String(referenceImage || "")
        .startsWith("data:image/")
    ) {
      return res.status(400).json({
        error: "Reference screenshot দিন"
      });
    }

    const sec =
      type === "ad"
        ? Math.max(
            1,
            Number(minSeconds || 15)
          )
        : 15;

    const r = await q(
      `INSERT INTO tasks(
        type,
        title,
        description,
        url,
        reference_image,
        reward,
        min_seconds
      )
      VALUES($1,$2,$3,$4,$5,$6,$7)
      RETURNING id`,
      [
        type,
        String(title).trim(),
        String(description || ""),
        String(url).trim(),
        type === "ad"
          ? null
          : referenceImage,
        Number(reward),
        sec
      ]
    );

    await logAction(
      "admin",
      "task_create",
      `task=${r.rows[0].id}`
    );

    res.json({
      ok: true,
      id: r.rows[0].id
    });
  }
);

/* =========================
   ADMIN DELETE TASK
========================= */

app.delete(
  "/api/admin/tasks/:id",
  adminOnly,
  async (req, res) => {
    const id =
      Number(req.params.id);

    await q(
      `DELETE FROM tasks
       WHERE id=$1`,
      [id]
    );

    await logAction(
      "admin",
      "task_delete",
      `task=${id}`
    );

    res.json({ ok: true });
  }
);

/* =========================
   ADMIN APPROVE
========================= */

app.post(
  "/api/admin/submissions/:id/approve",
  adminOnly,
  async (req, res) => {
    const id =
      Number(req.params.id);

    const client =
      await pool.connect();

    try {
      await client.query("BEGIN");

      const s = await client.query(
        `SELECT
           s.*,
           t.reward,
           t.title
         FROM submissions s
         JOIN tasks t ON t.id=s.task_id
         WHERE s.id=$1
         FOR UPDATE`,
        [id]
      );

      if (!s.rowCount) {
        throw new Error(
          "Submission পাওয়া যায়নি"
        );
      }

      if (
        s.rows[0].status !== "pending"
      ) {
        throw new Error(
          "এই submission আগে review হয়েছে"
        );
      }

      const row = s.rows[0];

      const already =
        await client.query(
          `SELECT 1
           FROM claims
           WHERE user_id=$1
           AND task_id=$2`,
          [
            row.user_id,
            row.task_id
          ]
        );

      if (!already.rowCount) {
        await client.query(
          `UPDATE users
           SET balance=balance+$1
           WHERE id=$2`,
          [
            row.reward,
            row.user_id
          ]
        );

        await client.query(
          `INSERT INTO claims(
            user_id,
            task_id
          )
          VALUES($1,$2)`,
          [
            row.user_id,
            row.task_id
          ]
        );
      }

      await client.query(
        `UPDATE submissions
         SET status='approved',
             reviewed_at=NOW()
         WHERE id=$1`,
        [id]
      );

      await client.query("COMMIT");

      await logAction(
        "admin",
        "submission_approve",
        `submission=${id}, reward=${row.reward}`,
        row.user_id
      );

      res.json({ ok: true });

    } catch (e) {
      await client.query("ROLLBACK");

      res.status(400).json({
        error: e.message
      });

    } finally {
      client.release();
    }
  }
);

/* =========================
   ADMIN REJECT
========================= */

app.post(
  "/api/admin/submissions/:id/reject",
  adminOnly,
  async (req, res) => {
    const id =
      Number(req.params.id);

    const r = await q(
      `UPDATE submissions
       SET status='rejected',
           reviewed_at=NOW()
       WHERE id=$1
       AND status='pending'
       RETURNING user_id`,
      [id]
    );

    if (!r.rowCount) {
      return res.status(400).json({
        error:
          "Submission পাওয়া যায়নি বা আগে review হয়েছে"
      });
    }

    await logAction(
      "admin",
      "submission_reject",
      `submission=${id}`,
      r.rows[0].user_id
    );

    res.json({ ok: true });
  }
);

/* =========================
   ADMIN BAN
========================= */

app.post(
  "/api/admin/users/:id/ban",
  adminOnly,
  async (req, res) => {
    const id =
      Number(req.params.id);

    await q(
      `UPDATE users
       SET banned_until=
         NOW()+INTERVAL '3 days'
       WHERE id=$1`,
      [id]
    );

    await logAction(
      "admin",
      "user_ban",
      "3 days",
      id
    );

    res.json({ ok: true });
  }
);

/* =========================
   ADMIN WITHDRAW APPROVE
========================= */

app.post(
  "/api/admin/withdrawals/:id/approve",
  adminOnly,
  async (req, res) => {
    const id =
      Number(req.params.id);

    const r = await q(
      `UPDATE withdrawals
       SET status='approved',
           reviewed_at=NOW()
       WHERE id=$1
       AND status='pending'
       RETURNING user_id`,
      [id]
    );

    if (!r.rowCount) {
      return res.status(400).json({
        error:
          "Withdraw request পাওয়া যায়নি বা আগে review হয়েছে"
      });
    }

    await logAction(
      "admin",
      "withdraw_approve",
      `withdrawal=${id}`,
      r.rows[0].user_id
    );

    res.json({ ok: true });
  }
);

/* =========================
   ADMIN WITHDRAW REJECT
========================= */

app.post(
  "/api/admin/withdrawals/:id/reject",
  adminOnly,
  async (req, res) => {
    const id =
      Number(req.params.id);

    const client =
      await pool.connect();

    try {
      await client.query("BEGIN");

      const r =
        await client.query(
          `UPDATE withdrawals
           SET status='rejected',
               reviewed_at=NOW()
           WHERE id=$1
           AND status='pending'
           RETURNING user_id,amount`,
          [id]
        );

      if (!r.rowCount) {
        throw new Error(
          "Withdraw request পাওয়া যায়নি বা আগে review হয়েছে"
        );
      }

      await client.query(
        `UPDATE users
         SET balance=balance+$1
         WHERE id=$2`,
        [
          r.rows[0].amount,
          r.rows[0].user_id
        ]
      );

      await client.query("COMMIT");

      await logAction(
        "admin",
        "withdraw_reject",
        `withdrawal=${id}, refunded=${r.rows[0].amount}`,
        r.rows[0].user_id
      );

      res.json({ ok: true });

    } catch (e) {
      await client.query("ROLLBACK");

      res.status(400).json({
        error: e.message
      });

    } finally {
      client.release();
    }
  }
);

/* =========================
   ADMIN REPLY MESSAGE
========================= */

app.post(
  "/api/admin/messages/:userId",
  adminOnly,
  async (req, res) => {
    const userId =
      Number(req.params.userId);

    const body =
      String(req.body.body || "").trim();

    if (
      !body ||
      body.length > 2000
    ) {
      return res.status(400).json({
        error:
          "মেসেজ ১-২০০০ অক্ষরের মধ্যে দিন"
      });
    }

    await q(
      `INSERT INTO messages(
        user_id,
        sender,
        body
      )
      VALUES($1,'admin',$2)`,
      [
        userId,
        body
      ]
    );

    await logAction(
      "admin",
      "message_reply",
      `user=${userId}`,
      userId
    );

    res.json({ ok: true });
  }
);

/* =========================
   ADMIN MARK MESSAGE READ
========================= */

app.post(
  "/api/admin/messages/:id/read",
  adminOnly,
  async (req, res) => {
    await q(
      `UPDATE messages
       SET is_read=true
       WHERE id=$1`,
      [Number(req.params.id)]
    );

    res.json({ ok: true });
  }
);

/* =========================
   FRONTEND FALLBACK
========================= */

app.use((req, res, next) => {
  if (req.method !== "GET") {
    return next();
  }

  res.sendFile(
    process.cwd() +
      "/public/index.html",
    err => {
      if (err) {
        next(err);
      }
    }
  );
});

/* =========================
   START SERVER
========================= */

const port =
  process.env.PORT || 10000;

async function startServer() {
  try {
    await createSessionTable();
    await initDb();

    app.listen(port, () => {
      console.log(
        `Server running on ${port}`
      );
    });

  } catch (err) {
    console.error(
      "Server startup error:",
      err
    );

    process.exit(1);
  }
}

startServer();
