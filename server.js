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
  pay: { upiId: '', upiName: '', qrCode: '', prepaidDiscountPercent: 0, paymentInstruction: '', courierPartner: '', delhivery: {} },
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
async function sendWhatsAppOrderConfirmation(order) {
  const token = process.env.WHATSAPP_ACCESS_TOKEN;
  const phoneNumberId = process.env.WHATSAPP_PHONE_NUMBER_ID;
  const template = process.env.WHATSAPP_TEMPLATE_NAME;
  const lang = process.env.WHATSAPP_TEMPLATE_LANG || 'en_US';
  const graph = process.env.WHATSAPP_GRAPH_VERSION || 'v23.0';
  if (!token || !phoneNumberId || !template || !order.whatsappOptIn) return { sent: false, skipped: true };
  const to = String(order.phone || '').replace(/\D/g, '');
  if (!to) return { sent: false, skipped: true };
  const body = { messaging_product: 'whatsapp', to, type: 'template', template: { name: template, language: { code: lang }, components: [{ type: 'body', parameters: [{ type: 'text', text: String(order.name || 'Customer') }, { type: 'text', text: String(order.id || '') }, { type: 'text', text: '₹' + Number(order.total || 0).toFixed(2) }] }] } };
  const r = await fetch(`https://graph.facebook.com/${graph}/${phoneNumberId}/messages`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const text = await r.text();
  if (!r.ok) { console.error('WhatsApp send failed:', text.slice(0, 500)); return { sent: false, error: 'WhatsApp API error' }; }
  return { sent: true };
}

app.post('/api/orders', async (req, res) => {
  try {
    const o = req.body || {};
    if (!o.name || !o.phone || !o.total) return res.status(400).json({ ok: false, msg: 'Name, phone aur total required hain' });
    o.id = 'ORD' + Date.now().toString().slice(-6);
    o.date = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });
    o.status = 'pending';
    const orders = await getData('orders') || [];
    orders.unshift(o);
    await setData('orders', orders);
    const wa = await sendWhatsAppOrderConfirmation(o);
    res.json({ ok: true, id: o.id, whatsappSent: !!wa.sent });
  } catch (err) {
    console.error('Order save error:', err.message);
    res.status(500).json({ ok: false, msg: 'Order save error' });
  }
});

// ---------- OPTIONAL CASHFREE STATUS (keys can be added later) ----------
app.get('/api/cashfree/status', (req, res) => {
  const enabled = !!(process.env.CASHFREE_APP_ID && process.env.CASHFREE_SECRET_KEY);
  res.json({ ok: true, enabled, environment: process.env.CASHFREE_ENV || 'sandbox' });
});

// ---------- DELHIVERY INTEGRATION ----------
const DELHIVERY_BASE = process.env.DELHIVERY_SANDBOX === 'true'
  ? 'https://staging-express.delhivery.com'
  : 'https://track.delhivery.com';

function cleanDelhiveryText(v) {
  return String(v ?? '').replace(/[&#%;\\]/g, ' ').replace(/\s+/g, ' ').trim();
}

async function delhiveryRequest(pathname, options = {}) {
  const token = process.env.DELHIVERY_API_TOKEN;
  if (!token) throw new Error('DELHIVERY_API_TOKEN Render Environment mein missing hai');
  const headers = { Authorization: `Token ${token}`, Accept: 'application/json', ...(options.headers || {}) };
  const r = await fetch(DELHIVERY_BASE + pathname, { ...options, headers });
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  if (!r.ok) {
    const msg = typeof data === 'object' && data ? (data.error || data.message || data.detail || data.raw) : text;
    const err = new Error(String(msg || `Delhivery HTTP ${r.status}`));
    err.status = r.status; err.data = data; throw err;
  }
  return data;
}

function findDelhiveryWaybill(data) {
  const candidates = [
    data?.waybill, data?.wbns, data?.awb,
    data?.packages?.[0]?.waybill, data?.packages?.[0]?.wbns,
    data?.packages?.[0]?.awb, data?.shipment?.waybill,
    data?.shipments?.[0]?.waybill
  ];
  for (const x of candidates) {
    if (Array.isArray(x) && x.length) return String(x[0]);
    if (x) return String(x);
  }
  return '';
}

function orderAddressParts(order) {
  if (order.addressLine || order.city || order.pin) {
    return { add: order.addressLine || order.address || '', city: order.city || '', state: order.state || '', pin: order.pin || '' };
  }
  const raw = String(order.address || '');
  const m = raw.match(/^(.*?),\s*([^,-]+)\s*-\s*(\d{6})$/);
  if (m) return { add: m[1].trim(), city: m[2].trim(), state: '', pin: m[3] };
  const pin = (raw.match(/\b\d{6}\b/) || [''])[0];
  return { add: raw.replace(/\s*-\s*\d{6}\s*$/, '').trim(), city: '', state: '', pin };
}

app.use('/api/admin', requireSameOrigin, requireAdmin);

app.get('/api/admin/delhivery/status', async (req, res) => {
  const pay = await getData('pay') || {};
  const d = pay.delhivery || {};
  res.json({ ok: true, configured: !!(process.env.DELHIVERY_API_TOKEN && d.pickupName && d.pickupAddress && d.pickupCity && d.pickupPin && d.pickupPhone) });
});

app.post('/api/admin/delhivery/create-shipment', async (req, res) => {
  try {
    const index = Number(req.body?.index);
    const orders = await getData('orders') || [];
    const order = orders[index];
    if (!order) return res.status(404).json({ ok: false, msg: 'Order nahi mila' });
    if (order.delhivery?.waybill) return res.json({ ok: true, waybill: order.delhivery.waybill, existing: true });
    const pay = await getData('pay') || {};
    const d = pay.delhivery || {};
    const required = ['pickupName','pickupAddress','pickupCity','pickupPin','pickupPhone'];
    if (!process.env.DELHIVERY_API_TOKEN) return res.status(400).json({ ok: false, msg: 'Delhivery API token missing hai' });
    const missing = required.filter(k => !d[k]);
    if (missing.length) return res.status(400).json({ ok: false, msg: 'Delhivery setup incomplete: ' + missing.join(', ') });
    const a = orderAddressParts(order);
    if (!a.pin || !a.add || !order.phone) return res.status(400).json({ ok: false, msg: 'Customer address, PIN aur phone required hain' });
    const cod = String(order.paymentMethod || '').toUpperCase().includes('COD');
    const weight = Number(d.weight) || 500;
    const shipment = {
      order: cleanDelhiveryText(order.id),
      name: cleanDelhiveryText(order.name),
      phone: cleanDelhiveryText(order.phone).replace(/\D/g, '').slice(-10),
      add: cleanDelhiveryText(a.add), city: cleanDelhiveryText(a.city), state: cleanDelhiveryText(a.state), pin: cleanDelhiveryText(a.pin), country: 'India',
      products_desc: cleanDelhiveryText(order.items),
      payment_mode: cod ? 'COD' : 'Pre-paid',
      cod_amount: cod ? Number(order.total || 0) : 0,
      total_amount: Number(order.total || 0),
      quantity: 1, weight,
      shipment_length: Number(d.length) || 20, shipment_width: Number(d.width) || 15, shipment_height: Number(d.height) || 5,
      client: cleanDelhiveryText(d.clientName), seller_name: cleanDelhiveryText(pay.upiName || 'IBM COLLECTION'), source: 'IBM COLLECTION'
    };
    const payload = { pickup_location: { name: cleanDelhiveryText(d.pickupName), add: cleanDelhiveryText(d.pickupAddress), city: cleanDelhiveryText(d.pickupCity), state: cleanDelhiveryText(d.pickupState), pin: cleanDelhiveryText(d.pickupPin), phone: cleanDelhiveryText(d.pickupPhone).replace(/\D/g,'').slice(-10), country: 'India' }, shipments: [shipment] };
    const body = 'format=json&data=' + encodeURIComponent(JSON.stringify(payload));
    const result = await delhiveryRequest('/api/cmu/create.json', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
    const waybill = findDelhiveryWaybill(result);
    if (!waybill) return res.status(502).json({ ok: false, msg: 'Delhivery ne AWB return nahi kiya', detail: result });
    order.delhivery = { carrier: 'Delhivery', waybill, status: 'Ready to Ship', createdAt: new Date().toISOString(), mode: d.mode || 'Express' };
    order.status = 'confirmed';
    orders[index] = order;
    await setData('orders', orders);
    res.json({ ok: true, waybill, data: result });
  } catch (err) {
    console.error('Delhivery create error:', err.message);
    res.status(err.status || 500).json({ ok: false, msg: err.message || 'Delhivery shipment failed' });
  }
});

app.post('/api/admin/delhivery/track', async (req, res) => {
  try {
    const index = Number(req.body?.index); const orders = await getData('orders') || []; const order = orders[index];
    const waybill = order?.delhivery?.waybill; if (!waybill) return res.status(400).json({ ok:false, msg:'AWB nahi mila' });
    const result = await delhiveryRequest('/api/v1/packages/json/?waybill=' + encodeURIComponent(waybill));
    const pkg = result?.ShipmentData?.[0]?.Shipment || result?.packages?.[0] || result?.shipments?.[0] || {};
    const status = pkg?.Status?.Status || pkg?.status || pkg?.Status || order.delhivery.status || 'Updated';
    const location = pkg?.Status?.StatusLocation || pkg?.Status?.Location || pkg?.location || '';
    order.delhivery = { ...order.delhivery, status: String(status), location: String(location || ''), trackedAt: new Date().toISOString() };
    orders[index] = order; await setData('orders', orders);
    res.json({ ok:true, status:String(status), location:String(location||''), data:result });
  } catch (err) { res.status(err.status || 500).json({ ok:false, msg:err.message || 'Tracking failed' }); }
});

app.get('/api/admin/delhivery/label', async (req, res) => {
  try {
    const index = Number(req.query?.index); const orders = await getData('orders') || []; const order = orders[index]; const waybill=order?.delhivery?.waybill;
    if(!waybill) return res.status(400).send('AWB nahi mila');
    const token=process.env.DELHIVERY_API_TOKEN; if(!token) return res.status(400).send('Delhivery token missing');
    const r=await fetch(DELHIVERY_BASE+'/api/p/packing_slip/?wbns='+encodeURIComponent(waybill),{headers:{Authorization:`Token ${token}`,Accept:'*/*'}});
    const ct=r.headers.get('content-type')||'application/octet-stream'; const buf=Buffer.from(await r.arrayBuffer());
    if(!r.ok) return res.status(r.status).send(buf.toString('utf8').slice(0,1000));
    res.setHeader('Content-Type',ct); res.setHeader('Content-Disposition',`inline; filename="IBM-${waybill}-label"`); res.send(buf);
  } catch(err){res.status(500).send(err.message||'Label failed');}
});

app.post('/api/admin/delhivery/pickup', async (req,res)=>{
  try{
    const index=Number(req.body?.index); const orders=await getData('orders')||[]; const order=orders[index]; if(!order?.delhivery?.waybill)return res.status(400).json({ok:false,msg:'Pehle shipment create karo'});
    const pay=await getData('pay')||{}; const d=pay.delhivery||{}; if(!d.pickupName)return res.status(400).json({ok:false,msg:'Pickup location name missing hai'});
    const date=String(req.body?.pickupDate||''); const time=String(req.body?.pickupTime||''); if(!/^\\d{4}-\\d{2}-\\d{2}$/.test(date)||!/^\\d{2}:\\d{2}:\\d{2}$/.test(time))return res.status(400).json({ok:false,msg:'Pickup date/time format galat hai'});
    const body=new URLSearchParams({pickup_time:time,pickup_date:date,pickup_location:String(d.pickupName),expected_package_count:'1'}).toString();
    const result=await delhiveryRequest('/fm/request/new/',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});
    order.delhivery={...order.delhivery,pickup:{date,time,result},status:'Ready for Pickup'}; orders[index]=order; await setData('orders',orders); res.json({ok:true,data:result});
  }catch(err){res.status(err.status||500).json({ok:false,msg:err.message||'Pickup request failed'});}
});

// ---------- ADMIN-ONLY ROUTES ----------
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
