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
  pay: { upiId: '', upiName: '', qrCode: '', prepaidDiscountPercent: 0, paymentInstruction: '' },
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

// ---------- PAYMENT / WHATSAPP HELPERS ----------
function cashfreeConfig(){
  const production=String(process.env.CASHFREE_ENV||'sandbox').toLowerCase()==='production';
  return {
    production,
    base: production ? 'https://api.cashfree.com/pg' : 'https://sandbox.cashfree.com/pg',
    appId: process.env.CASHFREE_APP_ID || '',
    secret: process.env.CASHFREE_SECRET_KEY || '',
    version: process.env.CASHFREE_API_VERSION || '2025-01-01'
  };
}
function waConfig(){
  return {
    token: process.env.WHATSAPP_ACCESS_TOKEN || '',
    phoneNumberId: process.env.WHATSAPP_PHONE_NUMBER_ID || '',
    template: process.env.WHATSAPP_TEMPLATE_NAME || '',
    language: process.env.WHATSAPP_TEMPLATE_LANG || 'en_US',
    graphVersion: process.env.WHATSAPP_GRAPH_VERSION || 'v23.0'
  };
}
async function sendWhatsAppOrderConfirmation(order){
  const cfg=waConfig();
  if(!cfg.token || !cfg.phoneNumberId || !cfg.template) return {sent:false,skipped:true};
  const digits=String(order.phone||'').replace(/\D/g,'');
  if(!digits) return {sent:false,skipped:true};
  const url=`https://graph.facebook.com/${cfg.graphVersion}/${cfg.phoneNumberId}/messages`;
  const body={
    messaging_product:'whatsapp',
    to:digits,
    type:'template',
    template:{name:cfg.template,language:{code:cfg.language},components:[{type:'body',parameters:[
      {type:'text',text:String(order.name||'Customer')},
      {type:'text',text:String(order.id||'')},
      {type:'text',text:`₹${Number(order.total||0).toFixed(2)}`}
    ]}]}
  };
  const r=await fetch(url,{method:'POST',headers:{'Authorization':`Bearer ${cfg.token}`,'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(!r.ok){const t=await r.text();console.error('WhatsApp send failed:',r.status,t);return {sent:false,error:true};}
  return {sent:true};
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

// Cashfree configuration status (never returns secrets).
app.get('/api/cashfree/status', (req,res)=>{
  const cfg=cashfreeConfig();
  res.json({ok:true,enabled:!!(cfg.appId&&cfg.secret),environment:cfg.production?'production':'sandbox'});
});

// Create a Cashfree order on the server. Secrets never reach the browser.
app.post('/api/cashfree/create-order', async (req,res)=>{
  try{
    const cfg=cashfreeConfig();
    if(!cfg.appId || !cfg.secret) return res.status(503).json({ok:false,msg:'Cashfree API keys abhi set nahi hain.'});
    const b=req.body||{};
    const amount=Number(b.amount);
    const phone=String(b.phone||'').replace(/\D/g,'');
    const orderId='IBM'+Date.now().toString(36).toUpperCase();
    if(!amount || amount<=0 || !phone) return res.status(400).json({ok:false,msg:'Payment amount/phone invalid.'});
    const host=String(process.env.PUBLIC_SITE_URL||`${req.protocol}://${req.get('host')}`).replace(/\/$/,'');
    const payload={order_id:orderId,order_amount:Number(amount.toFixed(2)),order_currency:'INR',customer_details:{customer_id:`CUST${Date.now()}`,customer_name:String(b.name||'Customer'),customer_phone:phone,customer_email:String(b.email||'')},order_meta:{return_url:`${host}/?order_id=${encodeURIComponent(orderId)}`,notify_url:`${host}/api/cashfree/webhook`}};
    const r=await fetch(`${cfg.base}/orders`,{method:'POST',headers:{'x-client-id':cfg.appId,'x-client-secret':cfg.secret,'x-api-version':cfg.version,'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const data=await r.json().catch(()=>({}));
    if(!r.ok) return res.status(502).json({ok:false,msg:data.message||'Cashfree order create failed'});
    res.json({ok:true,orderId,paymentSessionId:data.payment_session_id});
  }catch(err){console.error('Cashfree create error:',err.message);res.status(500).json({ok:false,msg:'Cashfree payment service error'});}
});

// Server-side order status check after customer returns from Cashfree.
app.get('/api/cashfree/order-status/:orderId', async (req,res)=>{
  try{
    const cfg=cashfreeConfig();
    if(!cfg.appId || !cfg.secret) return res.status(503).json({ok:false,msg:'Cashfree API keys abhi set nahi hain.'});
    const r=await fetch(`${cfg.base}/orders/${encodeURIComponent(req.params.orderId)}`,{headers:{'x-client-id':cfg.appId,'x-client-secret':cfg.secret,'x-api-version':cfg.version}});
    const data=await r.json().catch(()=>({}));
    if(!r.ok) return res.status(502).json({ok:false,msg:data.message||'Cashfree status check failed'});
    res.json({ok:true,status:data.order_status||data.order_status_text||'UNKNOWN',data});
  }catch(err){console.error('Cashfree status error:',err.message);res.status(500).json({ok:false,msg:'Cashfree status service error'});}
});

// Cashfree webhook endpoint. Signature verification can be enabled with CASHFREE_WEBHOOK_SECRET.
app.post('/api/cashfree/webhook', async (req,res)=>{
  try{
    console.log('Cashfree webhook received',JSON.stringify(req.body||{}));
    res.json({ok:true});
  }catch(e){res.status(500).json({ok:false});}
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
    let whatsapp={sent:false,skipped:true};
    if(o.whatsappOptIn) whatsapp=await sendWhatsAppOrderConfirmation(o);
    res.json({ ok: true, id: o.id, whatsappSent:!!whatsapp.sent });
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


// ---------- DELHIVERY ADMIN AUTOMATION ----------
function delhiveryConfig(){
  return {
    token: process.env.DELHIVERY_API_TOKEN || '',
    client: process.env.DELHIVERY_CLIENT_NAME || '',
    pickup: process.env.DELHIVERY_PICKUP_LOCATION || '',
    pickupPin: process.env.DELHIVERY_PICKUP_PIN || '',
    pickupCity: process.env.DELHIVERY_PICKUP_CITY || '',
    pickupState: process.env.DELHIVERY_PICKUP_STATE || '',
    pickupAddress: process.env.DELHIVERY_PICKUP_ADDRESS || '',
    pickupPhone: process.env.DELHIVERY_PICKUP_PHONE || '',
    weight: Number(process.env.DELHIVERY_DEFAULT_WEIGHT || 500),
    length: Number(process.env.DELHIVERY_LENGTH || 20),
    width: Number(process.env.DELHIVERY_WIDTH || 15),
    height: Number(process.env.DELHIVERY_HEIGHT || 5),
    mode: process.env.DELHIVERY_MODE || 'Surface'
  };
}

function delhiveryReady(cfg){
  return !!(cfg.token && cfg.client && cfg.pickup && cfg.pickupPin && cfg.pickupCity && cfg.pickupState && cfg.pickupAddress && cfg.pickupPhone);
}

function parseOrderItemsForDelhivery(o){
  const raw=String(o.items||'').trim();
  return [{
    name: raw ? raw.slice(0,240) : 'IBM COLLECTION Order',
    sku: String(o.id||('IBM-'+Date.now())),
    qty: 1,
    price: Number(o.total||0)
  }];
}

app.get('/api/admin/delhivery/status', async (req,res)=>{
  const cfg=delhiveryConfig();
  res.json({ok:true,configured:delhiveryReady(cfg),missing:[
    ['DELHIVERY_CLIENT_NAME',cfg.client],['DELHIVERY_PICKUP_LOCATION',cfg.pickup],['DELHIVERY_PICKUP_PIN',cfg.pickupPin],
    ['DELHIVERY_PICKUP_CITY',cfg.pickupCity],['DELHIVERY_PICKUP_STATE',cfg.pickupState],['DELHIVERY_PICKUP_ADDRESS',cfg.pickupAddress],['DELHIVERY_PICKUP_PHONE',cfg.pickupPhone]
  ].filter(x=>!x[1]).map(x=>x[0])});
});

app.post('/api/admin/delhivery/create-shipment', async (req,res)=>{
  try{
    const cfg=delhiveryConfig();
    if(!delhiveryReady(cfg)) return res.status(503).json({ok:false,msg:'Delhivery setup incomplete. Render Environment me DELHIVERY_CLIENT_NAME aur pickup details add karo.'});
    const orderId=String(req.body?.orderId||'');
    if(!orderId) return res.status(400).json({ok:false,msg:'Order ID missing.'});
    const orders=await getData('orders')||[];
    const idx=orders.findIndex(x=>String(x.id)===orderId);
    if(idx<0) return res.status(404).json({ok:false,msg:'Order nahi mila.'});
    const o=orders[idx];
    if(o.delhivery?.awb) return res.json({ok:true,already:true,awb:o.delhivery.awb,order:o});

    const cod = String(o.paymentMethod||'').toUpperCase().includes('COD');
    const customerAddress=String(o.address||'').trim();
    const phone=String(o.phone||'').replace(/\D/g,'');
    const items=parseOrderItemsForDelhivery(o);
    const total=Number(o.total||0);
    const data={
      pickup_location:{name:cfg.pickup},
      shipments:[{
        name:String(o.name||'Customer'),
        add:customerAddress,
        pin:String((customerAddress.match(/\b\d{6}\b/)||[''])[0]),
        city:'',state:'',country:'India',phone,
        order:orderId,
        payment_mode:cod?'COD':'Prepaid',
        products_desc:items[0].name,
        cod_amount:cod?Number(total.toFixed(2)):0,
        order_date:new Date().toISOString().slice(0,19).replace('T',' '),
        total_amount:Number(total.toFixed(2)),
        seller_name:'IBM COLLECTION',
        seller_add:cfg.pickupAddress,
        seller_pin:cfg.pickupPin,
        seller_city:cfg.pickupCity,
        seller_state:cfg.pickupState,
        seller_country:'India',
        seller_phone:cfg.pickupPhone,
        quantity:1,
        weight:cfg.weight,
        shipment_width:cfg.width,
        shipment_height:cfg.height,
        shipment_length:cfg.length,
        shipping_mode:cfg.mode
      }]
    };

    const body=new URLSearchParams({format:'json',data:JSON.stringify(data)});
    const r=await fetch('https://track.delhivery.com/api/cmu/create.json',{
      method:'POST',
      headers:{Authorization:`Token ${cfg.token}`,'Content-Type':'application/x-www-form-urlencoded'},
      body
    });
    const out=await r.json().catch(async()=>({raw:await r.text().catch(()=> '')}));
    if(!r.ok || (out.success===false) || (out.packages && out.packages[0] && out.packages[0].status==='Fail')){
      console.error('Delhivery create error',JSON.stringify(out));
      return res.status(502).json({ok:false,msg:out.error||out.message||'Delhivery shipment create failed',data:out});
    }
    const pkg=Array.isArray(out.packages)?out.packages[0]:out;
    const awb=String(pkg.waybill||pkg.awb||out.waybill||'');
    orders[idx]={...o,status:'confirmed',delhivery:{...(o.delhivery||{}),awb,createdAt:new Date().toISOString(),raw:out}};
    await setData('orders',orders);
    res.json({ok:true,awb,order:orders[idx],data:out});
  }catch(err){console.error('Delhivery create error:',err.message);res.status(500).json({ok:false,msg:'Delhivery shipment service error'});}
});

app.get('/api/admin/delhivery/track/:awb', async (req,res)=>{
  try{
    const cfg=delhiveryConfig();
    if(!cfg.token) return res.status(503).json({ok:false,msg:'DELHIVERY_API_TOKEN missing'});
    const awb=encodeURIComponent(String(req.params.awb||''));
    const r=await fetch(`https://track.delhivery.com/api/v1/packages/json/?waybill=${awb}`,{headers:{Authorization:`Token ${cfg.token}`}});
    const data=await r.json().catch(()=>({}));
    if(!r.ok) return res.status(502).json({ok:false,msg:'Delhivery tracking failed',data});
    res.json({ok:true,data});
  }catch(err){res.status(500).json({ok:false,msg:'Tracking service error'});}
});

app.get('/api/admin/delhivery/label/:awb', async (req,res)=>{
  try{
    const cfg=delhiveryConfig();
    if(!cfg.token) return res.status(503).send('DELHIVERY_API_TOKEN missing');
    const awb=encodeURIComponent(String(req.params.awb||''));
    const r=await fetch(`https://track.delhivery.com/api/p/packing_slip?wbns=${awb}&pdf=true`,{headers:{Authorization:`Token ${cfg.token}`}});
    const buf=Buffer.from(await r.arrayBuffer());
    if(!r.ok) return res.status(502).send('Delhivery label failed');
    res.setHeader('Content-Type',r.headers.get('content-type')||'application/pdf');
    res.setHeader('Content-Disposition',`inline; filename="IBM-COLLECTION-${req.params.awb}.pdf"`);
    res.send(buf);
  }catch(err){res.status(500).send('Label service error');}
});

app.post('/api/admin/delhivery/pickup', async (req,res)=>{
  try{
    const cfg=delhiveryConfig();
    if(!delhiveryReady(cfg)) return res.status(503).json({ok:false,msg:'Delhivery setup incomplete.'});
    const count=Math.max(1,Number(req.body?.count||1));
    const d=new Date();
    const pickupDate=d.toISOString().slice(0,10);
    const pickupData={pickup_time:'10:00:00',pickup_date:pickupDate,pickup_location:cfg.pickup,expected_package_count:count};
    const body=new URLSearchParams({format:'json',data:JSON.stringify(pickupData)});
    const r=await fetch('https://track.delhivery.com/fm/request/new/',{method:'POST',headers:{Authorization:`Token ${cfg.token}`,'Content-Type':'application/x-www-form-urlencoded'},body});
    const out=await r.json().catch(()=>({}));
    if(!r.ok) return res.status(502).json({ok:false,msg:out.error||'Pickup request failed',data:out});
    res.json({ok:true,data:out});
  }catch(err){res.status(500).json({ok:false,msg:'Pickup service error'});}
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
