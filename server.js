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

app.set("trust proxy", 1);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,
});

const Store = pgSession(session);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: false, limit: "10mb" }));
app.use(express.static("public"));

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
      maxAge: 7 * 24 * 60 * 60 * 1000,
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

/* =========================
   AUTH MIDDLEWARE
========================= */

const auth = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: "login required" });
  }
  next();
};

const admin = (req, res, next) => {
  if (!req.session.isAdmin) {
    return res.status(401).json({ error: "admin required" });
  }
  next();
};

/* =========================
   DATABASE
========================= */

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

  /*
    type:
    ad       = Ad দেখা
    facebook = Facebook কাজ
    youtube  = YouTube কাজ
  */

  await q(`
    CREATE TABLE IF NOT EXISTS tasks(
      id BIGSERIAL PRIMARY KEY,
      type TEXT NOT NULL DEFAULT 'facebook',
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      url TEXT DEFAULT '',
      reference_image TEXT DEFAULT '',
      reward NUMERIC(12,2) NOT NULL,
      min_seconds INT DEFAULT 15,
      enabled BOOLEAN DEFAULT true,
      created_at TIMESTAMPTZ DEFAULT now()
    )
  `);

  /*
    পুরোনো database থাকলেও নতুন column তৈরি হবে
  */

  await q(`
    ALTER TABLE tasks
    ADD COLUMN IF NOT EXISTS type TEXT DEFAULT 'facebook'
  `);

  await q(`
    ALTER TABLE tasks
    ADD COLUMN IF NOT EXISTS url TEXT DEFAULT ''
  `);

  await q(`
    ALTER TABLE tasks
    ADD COLUMN IF NOT EXISTS reference_image TEXT DEFAULT ''
  `);

  await q(`
    ALTER TABLE tasks
    ADD COLUMN IF NOT EXISTS min_seconds INT DEFAULT 15
  `);

  await q(`
    ALTER TABLE tasks
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT now()
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
    CREATE TABLE IF NOT EXISTS ad_sessions(
      id BIGSERIAL PRIMARY KEY,
      token TEXT UNIQUE NOT NULL,
      user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
      task_id BIGINT REFERENCES tasks(id) ON DELETE CASCADE,
      started_at TIMESTAMPTZ DEFAULT now(),
      completed BOOLEAN DEFAULT false
    )
  `);

  /*
    User submitted screenshots
  */

  await q(`
    CREATE TABLE IF NOT EXISTS submissions(
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
      task_id BIGINT REFERENCES tasks(id) ON DELETE CASCADE,
      screenshot1 TEXT DEFAULT '',
      screenshot2 TEXT DEFAULT '',
      screenshot3 TEXT DEFAULT '',
      screenshot4 TEXT DEFAULT '',
      status TEXT DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT now(),
      reviewed_at TIMESTAMPTZ
    )
  `);

  /*
    পুরোনো একই কাজের জন্য একাধিক pending submission আটকানো
  */

  await q(`
    CREATE UNIQUE INDEX IF NOT EXISTS one_pending_submission
    ON submissions(user_id, task_id)
    WHERE status = 'pending'
  `);

  /*
    Withdraw
  */

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

/* =========================
   REGISTER
========================= */

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

    const exists = await q(
      "SELECT id FROM users WHERE login=$1",
      [login]
    );

    if (exists.length) {
      return res.status(409).json({
        error: "এই নম্বর/ইমেইল আগে ব্যবহার হয়েছে",
      });
    }

    const ref = (
      await q(
        "SELECT id FROM users WHERE referral_code=$1",
        [String(referralCode).trim()]
      )
    )[0]?.id || null;

    const code = crypto.randomBytes(5).toString("hex");

    const hash = await bcrypt.hash(password, 12);

    const u = (
      await q(
        `
        INSERT INTO users
        (login,password_hash,referral_code,referred_by)
        VALUES($1,$2,$3,$4)
        RETURNING id,login,balance,referral_code
        `,
        [login, hash, code, ref]
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
        console.error(err);
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

/* =========================
   LOGIN
========================= */

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
        error: "আপনার account সাময়িকভাবে বন্ধ আছে",
      });
    }

    req.session.userId = u.id;

    req.session.save((err) => {
      if (err) {
        console.error(err);
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

/* =========================
   LOGOUT
========================= */

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

/* =========================
   USER INFO
========================= */

app.get("/api/me", auth, async (req, res) => {
  const u = (
    await q(
      `
      SELECT id,login,balance,referral_code,banned_until
      FROM users
      WHERE id=$1
      `,
      [req.session.userId]
    )
  )[0];

  res.json({ user: u });
});

/* =========================
   CONTENT
========================= */

app.get("/api/content", auth, async (req, res) => {
  const tasks = await q(`
    SELECT *
    FROM tasks
    WHERE enabled=true
    ORDER BY id DESC
  `);

  const submissions = await q(
    `
    SELECT task_id,status
    FROM submissions
    WHERE user_id=$1
    `,
    [req.session.userId]
  );

  res.json({
    tasks,
    submissions,
  });
});

/* =========================
   AD START
========================= */

app.post("/api/tasks/:id/start-ad", auth, async (req, res) => {
  try {
    const task = (
      await q(
        `
        SELECT *
        FROM tasks
        WHERE id=$1
        AND type='ad'
        AND enabled=true
        `,
        [Number(req.params.id)]
      )
    )[0];

    if (!task) {
      return res.status(404).json({
        error: "Ad পাওয়া যায়নি",
      });
    }

    const already = await q(
      `
      SELECT id
      FROM claims
      WHERE user_id=$1 AND task_id=$2
      `,
      [req.session.userId, task.id]
    );

    if (already.length) {
      return res.status(409).json({
        error: "এই Ad-এর টাকা আগেই নেওয়া হয়েছে",
      });
    }

    const token = crypto.randomBytes(32).toString("hex");

    await q(
      `
      INSERT INTO ad_sessions
      (token,user_id,task_id)
      VALUES($1,$2,$3)
      `,
      [token, req.session.userId, task.id]
    );

    res.json({
      token,
      url: task.url,
      seconds: Number(task.min_seconds || 15),
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: "server error",
    });
  }
});

/* =========================
   AD COMPLETE
========================= */

app.post("/api/tasks/:id/complete-ad", auth, async (req, res) => {
  try {
    const taskId = Number(req.params.id);
    const token = String(req.body.token || "");

    const sessionRow = (
      await q(
        `
        SELECT *
        FROM ad_sessions
        WHERE token=$1
        AND user_id=$2
        AND task_id=$3
        `,
        [token, req.session.userId, taskId]
      )
    )[0];

    if (!sessionRow) {
      return res.status(400).json({
        error: "Ad session পাওয়া যায়নি",
      });
    }

    if (sessionRow.completed) {
      return res.status(409).json({
        error: "এই Ad-এর টাকা আগেই দেওয়া হয়েছে",
      });
    }

    const task = (
      await q(
        `
        SELECT *
        FROM tasks
        WHERE id=$1
        AND type='ad'
        AND enabled=true
        `,
        [taskId]
      )
    )[0];

    if (!task) {
      return res.status(404).json({
        error: "Ad পাওয়া যায়নি",
      });
    }

    const elapsed =
      (Date.now() - new Date(sessionRow.started_at).getTime()) /
      1000;

    const required = Number(task.min_seconds || 15);

    if (elapsed < required) {
      return res.status(400).json({
        error:
          "পুরো সময় শেষ হয়নি। আরও " +
          Math.ceil(required - elapsed) +
          " সেকেন্ড অপেক্ষা করুন।",
      });
    }

    await q(
      `
      INSERT INTO claims(user_id,task_id)
      VALUES($1,$2)
      `,
      [req.session.userId, taskId]
    );

    await q(
      `
      UPDATE users
      SET balance=balance+$1
      WHERE id=$2
      `,
      [task.reward, req.session.userId]
    );

    await q(
      `
      UPDATE ad_sessions
      SET completed=true
      WHERE id=$1
      `,
      [sessionRow.id]
    );

    res.json({
      ok: true,
      reward: task.reward,
    });
  } catch (e) {
    if (e.code === "23505") {
      return res.status(409).json({
        error: "এই কাজের Reward আগেই নেওয়া হয়েছে",
      });
    }

    console.error(e);

    res.status(500).json({
      error: "server error",
    });
  }
});

/* =========================
   FACEBOOK / YOUTUBE
   SUBMISSION
========================= */

app.post(
  "/api/tasks/:id/submit",
  auth,
  async (req, res) => {
    try {
      const taskId = Number(req.params.id);

      const task = (
        await q(
          `
          SELECT *
          FROM tasks
          WHERE id=$1
          AND enabled=true
          AND type IN ('facebook','youtube')
          `,
          [taskId]
        )
      )[0];

      if (!task) {
        return res.status(404).json({
          error: "কাজ পাওয়া যায়নি",
        });
      }

      const oldClaim = await q(
        `
        SELECT id
        FROM claims
        WHERE user_id=$1 AND task_id=$2
        `,
        [req.session.userId, taskId]
      );

      if (oldClaim.length) {
        return res.status(409).json({
          error: "এই কাজের Reward আগেই নেওয়া হয়েছে",
        });
      }

      const {
        screenshot1 = "",
        screenshot2 = "",
        screenshot3 = "",
        screenshot4 = "",
      } = req.body;

      if (task.type === "facebook") {
        if (!screenshot1) {
          return res.status(400).json({
            error: "Screenshot দিন",
          });
        }
      }

      if (task.type === "youtube") {
        if (
          !screenshot1 ||
          !screenshot2 ||
          !screenshot3 ||
          !screenshot4
        ) {
          return res.status(400).json({
            error: "YouTube কাজের জন্য ৪টি Screenshot দিতে হবে",
          });
        }
      }

      await q(
        `
        INSERT INTO submissions
        (
          user_id,
          task_id,
          screenshot1,
          screenshot2,
          screenshot3,
          screenshot4,
          status
        )
        VALUES($1,$2,$3,$4,$5,$6,'pending')
        `,
        [
          req.session.userId,
          taskId,
          screenshot1,
          screenshot2,
          screenshot3,
          screenshot4,
        ]
      );

      res.json({
        ok: true,
        message:
          "আপনার কাজ জমা হয়েছে। Admin যাচাই করবে।",
      });
    } catch (e) {
      if (e.code === "23505") {
        return res.status(409).json({
          error: "এই কাজের একটি submission আগে থেকেই আছে",
        });
      }

      console.error(e);

      res.status(500).json({
        error: "server error",
      });
    }
  }
);

/* =========================
   WITHDRAW
========================= */

app.post("/api/withdraw", auth, async (req, res) => {
  try {
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
          `
          SELECT balance
          FROM users
          WHERE id=$1
          FOR UPDATE
          `,
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
        `
        UPDATE users
        SET balance=balance-$1
        WHERE id=$2
        `,
        [amount, req.session.userId]
      );

      await c.query(
        `
        INSERT INTO withdrawals
        (user_id,method,payout_number,amount)
        VALUES($1,$2,$3,$4)
        `,
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
  } catch (e) {
    console.error(e);

    res.status(500).json({
      error: "server error",
    });
  }
});

/* =========================
   ADMIN LOGIN
========================= */

app.post("/api/admin/login", (req, res) => {
  if (
    String(req.body.password || "") !==
    process.env.ADMIN_PASSWORD
  ) {
    return res.status(401).json({
      error: "ভুল admin password",
    });
  }

  req.session.regenerate((err) => {
    if (err) {
      return res.status(500).json({
        error: "session error",
      });
    }

    req.session.isAdmin = true;

    req.session.save((saveErr) => {
      if (saveErr) {
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

/* =========================
   ADMIN DATA
========================= */

app.get("/api/admin/data", admin, async (req, res) => {
  const users = await q(`
    SELECT id,login,balance,referral_code,banned_until
    FROM users
    ORDER BY id DESC
  `);

  const tasks = await q(`
    SELECT *
    FROM tasks
    ORDER BY id DESC
  `);

  const submissions = await q(`
    SELECT
      s.*,
      u.login,
      t.title,
      t.type,
      t.reward
    FROM submissions s
    JOIN users u ON u.id=s.user_id
    JOIN tasks t ON t.id=s.task_id
    ORDER BY s.id DESC
  `);

  const withdrawals = await q(`
    SELECT *
    FROM withdrawals
    ORDER BY id DESC
  `);

  res.json({
    users,
    tasks,
    submissions,
    withdrawals,
  });
});

/* =========================
   ADMIN ADD TASK
========================= */

app.post("/api/admin/tasks", admin, async (req, res) => {
  try {
    const {
      type,
      title,
      description = "",
      url = "",
      referenceImage = "",
      reward,
      minSeconds = 15,
    } = req.body;

    if (!["ad", "facebook", "youtube"].includes(type)) {
      return res.status(400).json({
        error: "ভুল কাজের ধরন",
      });
    }

    if (!title || !Number(reward)) {
      return res.status(400).json({
        error: "Title এবং Reward দিন",
      });
    }

    if (!url) {
      return res.status(400).json({
        error: "Link দিন",
      });
    }

    if (
      (type === "facebook" || type === "youtube") &&
      !referenceImage
    ) {
      return res.status(400).json({
        error: "Reference Screenshot দিন",
      });
    }

    const row = (
      await q(
        `
        INSERT INTO tasks
        (
          type,
          title,
          description,
          url,
          reference_image,
          reward,
          min_seconds
        )
        VALUES($1,$2,$3,$4,$5,$6,$7)
        RETURNING *
        `,
        [
          type,
          title,
          description,
          url,
          referenceImage,
          Number(reward),
          Number(minSeconds || 15),
        ]
      )
    )[0];

    res.json({
      row,
    });
  } catch (e) {
    console.error(e);

    res.status(500).json({
      error: "server error",
    });
  }
});

/* =========================
   ADMIN DELETE TASK
========================= */

app.delete(
  "/api/admin/tasks/:id",
  admin,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      await q(
        "DELETE FROM tasks WHERE id=$1",
        [id]
      );

      res.json({
        ok: true,
      });
    } catch (e) {
      console.error(e);

      res.status(500).json({
        error: "server error",
      });
    }
  }
);

/* =========================
   ADMIN APPROVE SUBMISSION
========================= */

app.post(
  "/api/admin/submissions/:id/approve",
  admin,
  async (req, res) => {
    const c = await pool.connect();

    try {
      await c.query("BEGIN");

      const s = (
        await c.query(
          `
          SELECT *
          FROM submissions
          WHERE id=$1
          FOR UPDATE
          `,
          [Number(req.params.id)]
        )
      ).rows[0];

      if (!s) {
        await c.query("ROLLBACK");

        return res.status(404).json({
          error: "submission not found",
        });
      }

      if (s.status !== "pending") {
        await c.query("ROLLBACK");

        return res.status(400).json({
          error: "এই submission ইতিমধ্যে review হয়েছে",
        });
      }

      const existingClaim = (
        await c.query(
          `
          SELECT id
          FROM claims
          WHERE user_id=$1 AND task_id=$2
          `,
          [s.user_id, s.task_id]
        )
      ).rows[0];

      if (!existingClaim) {
        const task = (
          await c.query(
            `
            SELECT reward
            FROM tasks
            WHERE id=$1
            `,
            [s.task_id]
          )
        ).rows[0];

        if (task) {
          await c.query(
            `
            UPDATE users
            SET balance=balance+$1
            WHERE id=$2
            `,
            [task.reward, s.user_id]
          );

          await c.query(
            `
            INSERT INTO claims(user_id,task_id)
            VALUES($1,$2)
            `,
            [s.user_id, s.task_id]
          );
        }
      }

      await c.query(
        `
        UPDATE submissions
        SET status='approved',
            reviewed_at=now()
        WHERE id=$1
        `,
        [s.id]
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
  }
);

/* =========================
   ADMIN REJECT SUBMISSION
========================= */

app.post(
  "/api/admin/submissions/:id/reject",
  admin,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      const result = await q(
        `
        UPDATE submissions
        SET status='rejected',
            reviewed_at=now()
        WHERE id=$1
        AND status='pending'
        RETURNING id
        `,
        [id]
      );

      if (!result.length) {
        return res.status(404).json({
          error: "submission not found",
        });
      }

      res.json({
        ok: true,
      });
    } catch (e) {
      console.error(e);

      res.status(500).json({
        error: "server error",
      });
    }
  }
);

/* =========================
   ADMIN BAN USER
========================= */

app.post(
  "/api/admin/users/:id/ban",
  admin,
  async (req, res) => {
    await q(
      `
      UPDATE users
      SET banned_until=now()+interval '3 days'
      WHERE id=$1
      `,
      [Number(req.params.id)]
    );

    res.json({
      ok: true,
    });
  }
);

/* =========================
   ADMIN WITHDRAW APPROVE
========================= */

app.post(
  "/api/admin/withdrawals/:id/approve",
  admin,
  async (req, res) => {
    await q(
      `
      UPDATE withdrawals
      SET status='approved'
      WHERE id=$1
      AND status='pending'
      `,
      [Number(req.params.id)]
    );

    res.json({
      ok: true,
    });
  }
);

/* =========================
   ADMIN WITHDRAW REJECT
========================= */

app.post(
  "/api/admin/withdrawals/:id/reject",
  admin,
  async (req, res) => {
    const c = await pool.connect();

    try {
      await c.query("BEGIN");

      const w = (
        await c.query(
          `
          SELECT *
          FROM withdrawals
          WHERE id=$1
          AND status='pending'
          FOR UPDATE
          `,
          [Number(req.params.id)]
        )
      ).rows[0];

      if (!w) {
        await c.query("ROLLBACK");

        return res.status(404).json({
          error: "withdrawal not found",
        });
      }

      await c.query(
        `
        UPDATE withdrawals
        SET status='rejected'
        WHERE id=$1
        `,
        [w.id]
      );

      await c.query(
        `
        UPDATE users
        SET balance=balance+$1
        WHERE id=$2
        `,
        [w.amount, w.user_id]
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
  }
);

/* =========================
   START SERVER
========================= */

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
