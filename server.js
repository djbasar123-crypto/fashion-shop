const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

// Keep 10mb because the store can save product/hero images as data URLs.
app.use(express.json({ limit: '10mb' }));

// Basic security headers. CSP is intentionally not added here because the current
// frontend uses inline JavaScript and styles.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// ---------- POSTGRESQL CONNECTION ----------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com')
    ? { rejectUnauthorized: false }
    : false
});

// ---------- ADMIN SESSION SECURITY ----------
// Add ADMIN_SESSION_SECRET in Render Environment for a permanent signing secret.
// If it is missing, a random secret is generated for this server run; that still
// protects the app, but all admin sessions expire when the service restarts.
const SESSION_SECRET = process.env.ADMIN_SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_TTL_SECONDS = 12 * 60 * 60;
const COOKIE_NAME = 'ibm_admin_session';

function base64url(value) {
  return Buffer.from(value).toString('base64url');
}

function signSession(payload) {
  const body = base64url(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  return body + '.' + sig;
}

function verifySession(token) {
  try {
    if (!token || typeof token !== 'string') return false;
    const parts = token.split('.');
    if (parts.length !== 2) return false;
    const [body, sig] = parts;
    const expected = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload || payload.role !== 'admin' || !payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return false;
    return true;
  } catch (e) {
    return false;
  }
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  for (const item of header.split(';')) {
    const idx = item.indexOf('=');
    if (idx === -1) continue;
    const key = item.slice(0, idx).trim();
    const val = item.slice(idx + 1).trim();
    if (key) out[key] = decodeURIComponent(val);
  }
  return out;
}

function requireSameOrigin(req, res, next) {
  const origin = req.get('Origin');
  if (!origin) return next();
  const expected = `${req.protocol}://${req.get('host')}`;
  if (origin !== expected) {
    return res.status(403).json({ ok: false, msg: 'Blocked cross-site request' });
  }
  next();
}

function requireAdmin(req, res, next) {
  const cookies = parseCookies(req);
  if (!verifySession(cookies[COOKIE_NAME])) {
    return res.status(401).json({ ok: false, msg: 'Admin login required' });
  }
  next();
}

// ---------- LOGIN RATE LIMIT ----------
const loginAttempts = new Map();
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 5;

function loginAllowed(ip) {
  const now = Date.now();
  const old = loginAttempts.get(ip);
  if (!old || now - old.first > LOGIN_WINDOW_MS) {
    loginAttempts.set(ip, { first: now, count: 0 });
    return true;
  }
  return old.count < MAX_LOGIN_ATTEMPTS;
}

function recordLoginFailure(ip) {
  const now = Date.now();
  const old = loginAttempts.get(ip);
  if (!old || now - old.first > LOGIN_WINDOW_MS) {
    loginAttempts.set(ip, { first: now, count: 1 });
  } else {
    old.count += 1;
  }
}

function clearLoginFailures(ip) {
  loginAttempts.delete(ip);
}

// ---------- PASSWORD HASHING ----------
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `scrypt$${salt}$${hash}`;
}

function verifyPassword(password, stored) {
  try {
    if (typeof stored !== 'string') return false;
    if (!stored.startsWith('scrypt$')) return String(password) === stored; // legacy migration
    const parts = stored.split('$');
    if (parts.length !== 3) return false;
    const [, salt, savedHex] = parts;
    const derived = crypto.scryptSync(String(password), salt, 64);
    const saved = Buffer.from(savedHex, 'hex');
    return saved.length === derived.length && crypto.timingSafeEqual(saved, derived);
  } catch (e) {
    return false;
  }
}

function setAdminCookie(res, user) {
  const now = Math.floor(Date.now() / 1000);
  const token = signSession({ role: 'admin', user, iat: now, exp: now + SESSION_TTL_SECONDS });
  res.setHeader(
    'Set-Cookie',
    `${COOKIE_NAME}=${encodeURIComponent(token)}; Max-Age=${SESSION_TTL_SECONDS}; Path=/; HttpOnly; SameSite=Lax; Secure`
  );
}

function clearAdminCookie(res) {
  res.setHeader(
    'Set-Cookie',
    `${COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure`
  );
}

// ---------- DEFAULT DATA ----------
const DEFAULT_DB = {
  settings: {
    siteName: 'Fashion Hub', logo: '🛍️', hero: 'New Season, New Style',
    tag: 'Premium quality T-Shirts, Shirts, Jeans, Jackets aur Track Pants — sab ek jagah!',
    color: '#ffc107', address: '📍 Address: Aapki shop ka pata yahan likhein',
    phone: '📞 Phone: +91 98765 43210', email: 'fashionhub@gmail.com', domain: ''
  },
  social: { instagram: '', facebook: '', whatsapp: '919876543210', youtube: '', twitter: '' },
  pay: { upiId: '', upiName: '', qrCode: '' },
  admin: { user: 'admin', pass: 'admin123' },
  categories: [
    { name: 'T-Shirt', icon: '👕' }, { name: 'Shirt', icon: '👔' },
    { name: 'Jeans', icon: '👖' }, { name: 'Jacket', icon: '🧥' }, { name: 'Track Pant', icon: '🏃' }
  ],
  products: [
    { name: 'Classic Cotton T-Shirt', price: 499, oldPrice: 799, cat: 't-shirt', icon: '👕', pimg: '', sizes: ['S','M','L','XL','XXL'] },
    { name: 'Polo T-Shirt', price: 699, oldPrice: 1099, cat: 't-shirt', icon: '👕', pimg: '', sizes: ['S','M','L','XL','XXL'] },
    { name: 'Graphic Print T-Shirt', price: 599, oldPrice: 999, cat: 't-shirt', icon: '👕', pimg: '', sizes: ['S','M','L','XL','XXL'] },
    { name: 'Formal White Shirt', price: 999, oldPrice: 1499, cat: 'shirt', icon: '👔', pimg: '', sizes: ['S','M','L','XL','XXL'] },
    { name: 'Checked Casual Shirt', price: 899, oldPrice: 1299, cat: 'shirt', icon: '👔', pimg: '', sizes: ['S','M','L','XL','XXL'] },
    { name: 'Slim Fit Blue Shirt', price: 1099, oldPrice: 1599, cat: 'shirt', icon: '👔', pimg: '', sizes: ['S','M','L','XL','XXL'] },
    { name: 'Skinny Fit Jeans', price: 1299, oldPrice: 1999, cat: 'jeans', icon: '👖', pimg: '', sizes: ['S','M','L','XL','XXL'] },
    { name: 'Ripped Denim Jeans', price: 1499, oldPrice: 2299, cat: 'jeans', icon: '👖', pimg: '', sizes: ['S','M','L','XL','XXL'] },
    { name: 'Classic Black Jeans', price: 1249, oldPrice: 1899, cat: 'jeans', icon: '👖', pimg: '', sizes: ['S','M','L','XL','XXL'] },
    { name: 'Denim Jacket', price: 1799, oldPrice: 2699, cat: 'jacket', icon: '🧥', pimg: '', sizes: ['S','M','L','XL','XXL'] },
    { name: 'Bomber Jacket', price: 1999, oldPrice: 2999, cat: 'jacket', icon: '🧥', pimg: '', sizes: ['S','M','L','XL','XXL'] },
    { name: 'Hooded Winter Jacket', price: 2199, oldPrice: 3299, cat: 'jacket', icon: '🧥', pimg: '', sizes: ['S','M','L','XL','XXL'] },
    { name: 'Comfort Track Pant', price: 699, oldPrice: 1099, cat: 'track-pant', icon: '🏃', pimg: '', sizes: ['S','M','L','XL','XXL'] },
    { name: 'Sports Running Pant', price: 799, oldPrice: 1299, cat: 'track-pant', icon: '🏃', pimg: '', sizes: ['S','M','L','XL','XXL'] },
    { name: 'Street Track Pant', price: 899, oldPrice: 1499, cat: 'track-pant', icon: '🏃', pimg: '', sizes: ['S','M','L','XL','XXL'] }
  ],
  orders: []
};

// ---------- DATABASE ----------
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_data (
      key TEXT PRIMARY KEY,
      value JSONB NOT NULL
    )
  `);

  for (const [k, v] of Object.entries(DEFAULT_DB)) {
    const result = await pool.query('SELECT 1 FROM app_data WHERE key = $1', [k]);
    if (result.rowCount === 0) {
      await pool.query('INSERT INTO app_data (key, value) VALUES ($1, $2)', [k, JSON.stringify(v)]);
    }
  }
  console.log('✅ Database ready (PostgreSQL)');
}

async function getData(key) {
  const result = await pool.query('SELECT value FROM app_data WHERE key = $1', [key]);
  return result.rowCount ? result.rows[0].value : null;
}

async function setData(key, value) {
  await pool.query(
    `INSERT INTO app_data (key, value) VALUES ($1, $2)
     ON CONFLICT (key) DO UPDATE SET value = $2`,
    [key, JSON.stringify(value)]
  );
}

async function publicCopy() {
  const [settings, social, pay, categories, products] = await Promise.all([
    getData('settings'), getData('social'), getData('pay'),
    getData('categories'), getData('products')
  ]);
  return { settings, social, pay, categories, products };
}

// ---------- ROUTES ----------

// Admin login: creates an HttpOnly signed session cookie.
app.post('/api/login', async (req, res) => {
  try {
    const ip = req.ip || 'unknown';
    if (!loginAllowed(ip)) {
      return res.status(429).json({ ok: false, msg: 'Bahut zyada login attempts. 15 minute baad try karein.' });
    }

    const { user, pass } = req.body || {};
    const admin = await getData('admin');
    const validUser = typeof user === 'string' && user === admin.user;
    const validPass = validUser && verifyPassword(pass, admin.pass);

    if (!validPass) {
      recordLoginFailure(ip);
      return res.status(401).json({ ok: false, msg: 'Galat username/password' });
    }

    clearLoginFailures(ip);

    // Upgrade the old plaintext password to a secure scrypt hash after a successful login.
    if (typeof admin.pass === 'string' && !admin.pass.startsWith('scrypt$')) {
      await setData('admin', { user: admin.user, pass: hashPassword(admin.pass) });
    }

    setAdminCookie(res, admin.user);
    res.setHeader('Cache-Control', 'no-store');
    res.json({ ok: true });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ ok: false, msg: 'Login service error' });
  }
});

app.post('/api/logout', (req, res) => {
  clearAdminCookie(res);
  res.json({ ok: true });
});

// Public store data. No admin password is returned.
app.get('/api/store', async (req, res) => {
  try {
    res.json(await publicCopy());
  } catch (err) {
    res.status(500).json({ ok: false, msg: 'Store data error' });
  }
});

// Customer order. This route remains public.
app.post('/api/orders', async (req, res) => {
  try {
    const o = req.body;
    if (!o || !o.name || !o.phone || !o.total) return res.status(400).json({ ok: false });
    o.id = 'ORD' + Date.now().toString().slice(-6);
    o.date = new Date().toLocaleString();
    o.status = 'pending';
    const orders = await getData('orders') || [];
    orders.unshift(o);
    await setData('orders', orders);
    res.json({ ok: true, id: o.id });
  } catch (err) {
    res.status(500).json({ ok: false, msg: 'Order save error' });
  }
});

// ---------- ADMIN-ONLY ROUTES ----------
app.use('/api/admin', requireSameOrigin, requireAdmin);

app.get('/api/admin/:key', async (req, res) => {
  const key = req.params.key;
  const allowed = ['orders'];
  if (!allowed.includes(key)) return res.status(400).json({ ok: false });
  res.setHeader('Cache-Control', 'no-store');
  res.json({ ok: true, data: (await getData(key)) || [] });
});

app.post('/api/admin/settings', async (req, res) => {
  const old = await getData('settings') || {};
  await setData('settings', { ...old, ...req.body });
  res.json({ ok: true });
});

app.post('/api/admin/social', async (req, res) => {
  const old = await getData('social') || {};
  await setData('social', { ...old, ...req.body });
  res.json({ ok: true });
});

app.post('/api/admin/pay', async (req, res) => {
  const old = await getData('pay') || {};
  await setData('pay', { ...old, ...req.body });
  res.json({ ok: true });
});

app.post('/api/admin/security', async (req, res) => {
  const { user, pass } = req.body || {};
  if (typeof user !== 'string' || user.trim().length < 3 || typeof pass !== 'string' || pass.length < 8) {
    return res.status(400).json({ ok: false, msg: 'Username 3+ characters aur password 8+ characters hona chahiye.' });
  }
  await setData('admin', { user: user.trim(), pass: hashPassword(pass) });
  res.json({ ok: true });
});

app.post('/api/admin/categories', async (req, res) => {
  await setData('categories', req.body);
  res.json({ ok: true });
});

app.post('/api/admin/products', async (req, res) => {
  await setData('products', req.body);
  res.json({ ok: true });
});

app.post('/api/admin/orders', async (req, res) => {
  await setData('orders', req.body);
  res.json({ ok: true });
});

// ---------- START ----------
const PORT = process.env.PORT || 3000;
initDB()
  .then(() => {
    app.listen(PORT, () => console.log('🚀 Store running on port ' + PORT));
  })
  .catch(err => {
    console.error('❌ Database connection failed:', err.message);
    console.log('DATABASE_URL check karo (Render > Service > Environment)');
    process.exit(1);
  });
