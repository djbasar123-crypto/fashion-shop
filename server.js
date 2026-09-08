const express = require('express');
const path = require('path');
const { Pool } = require('pg');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ---------- PostgreSQL CONNECTION ----------
// Render par: Service > Environment > DATABASE_URL me apna connection string daalo
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com')
    ? { rejectUnauthorized: false }
    : false
});

// ---------- DEFAULT DATA (pehli baar seed hoga) ----------
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

// ---------- DATABASE INIT (tables + seed) ----------
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_data (
      key TEXT PRIMARY KEY,
      value JSONB NOT NULL
    )
  `);

  // Pehli baar chale to default data daalo
  for (const [k, v] of Object.entries(DEFAULT_DB)) {
    const res = await pool.query('SELECT 1 FROM app_data WHERE key = $1', [k]);
    if (res.rowCount === 0) {
      await pool.query('INSERT INTO app_data (key, value) VALUES ($1, $2)', [k, JSON.stringify(v)]);
    }
  }
  console.log('✅ Database ready (PostgreSQL)');
}

// ---------- HELPERS ----------
async function getData(key) {
  const res = await pool.query('SELECT value FROM app_data WHERE key = $1', [key]);
  return res.rowCount ? res.rows[0].value : null;
}
async function setData(key, value) {
  await pool.query(
    `INSERT INTO app_data (key, value) VALUES ($1, $2)
     ON CONFLICT (key) DO UPDATE SET value = $2`,
    [key, JSON.stringify(value)]
  );
}

// Customer ko public copy (bina admin pass ke)
async function publicCopy() {
  const [settings, social, pay, categories, products] = await Promise.all([
    getData('settings'), getData('social'), getData('pay'),
    getData('categories'), getData('products')
  ]);
  return { settings, social, pay, categories, products };
}

// ---------- ROUTES ----------

// Admin login
app.post('/api/login', async (req, res) => {
  const { user, pass } = req.body;
  const admin = await getData('admin');
  if (user === admin.user && pass === admin.pass) return res.json({ ok: true });
  res.status(401).json({ ok: false, msg: 'Galat username/password' });
});

// Public store data
app.get('/api/store', async (req, res) => res.json(await publicCopy()));

// Customer order place kare
app.post('/api/orders', async (req, res) => {
  const o = req.body;
  if (!o || !o.name || !o.phone || !o.total) return res.status(400).json({ ok: false });
  o.id = 'ORD' + Date.now().toString().slice(-6);
  o.date = new Date().toLocaleString();
  o.status = 'pending';
  const orders = await getData('orders') || [];
  orders.unshift(o);
  await setData('orders', orders);
  res.json({ ok: true, id: o.id });
});

// Admin: data read
app.get('/api/admin/:key', async (req, res) => {
  const key = req.params.key;
  const allowed = ['orders'];
  if (!allowed.includes(key)) return res.status(400).json({ ok: false });
  res.json({ ok: true, data: (await getData(key)) || [] });
});

// Admin: settings save
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
  await setData('admin', { user: req.body.user, pass: req.body.pass });
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
