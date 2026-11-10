'use strict';
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const db = new Database(process.env.DB_FILE || path.join(ROOT, 'data', 'fixe.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE COLLATE NOCASE,
 phone TEXT NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user',
 paid_at TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS payments (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id),
 method TEXT NOT NULL CHECK(method IN ('mpesa','card')),
 tx_ref TEXT NOT NULL UNIQUE,
 amount INTEGER NOT NULL CHECK(amount IN (200,1000)),
 plan TEXT NOT NULL DEFAULT 'basic' CHECK(plan IN ('basic','premium')),
 currency TEXT NOT NULL DEFAULT 'KES',
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','paid','failed')),
 provider_checkout_id TEXT,
 provider_transaction_id TEXT,
 receipt TEXT,
 phone TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 paid_at TEXT,
 raw_result TEXT
);
CREATE INDEX IF NOT EXISTS payments_user_idx ON payments(user_id, created_at DESC);
`);

// Upgrade older installations that only accepted KSh 200 payments.
const paymentTableSql = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='payments'").get()?.sql || '';
if (!paymentTableSql.includes('1000')) {
  db.pragma('foreign_keys = OFF');
  db.exec(`DROP INDEX IF EXISTS payments_user_idx;
    ALTER TABLE payments RENAME TO payments_old;
    CREATE TABLE payments (
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id),
      method TEXT NOT NULL CHECK(method IN ('mpesa','card')), tx_ref TEXT NOT NULL UNIQUE,
      amount INTEGER NOT NULL CHECK(amount IN (200,1000)), plan TEXT NOT NULL DEFAULT 'basic' CHECK(plan IN ('basic','premium')),
      currency TEXT NOT NULL DEFAULT 'KES', status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','paid','failed')),
      provider_checkout_id TEXT, provider_transaction_id TEXT, receipt TEXT, phone TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, paid_at TEXT, raw_result TEXT);
    INSERT INTO payments(id,user_id,method,tx_ref,amount,plan,currency,status,provider_checkout_id,provider_transaction_id,receipt,phone,created_at,paid_at,raw_result)
      SELECT id,user_id,method,tx_ref,amount,'basic',currency,status,provider_checkout_id,provider_transaction_id,receipt,phone,created_at,paid_at,raw_result FROM payments_old;
    DROP TABLE payments_old;
    CREATE INDEX payments_user_idx ON payments(user_id, created_at DESC);`);
  db.pragma('foreign_keys = ON');
} else if (!db.prepare('PRAGMA table_info(payments)').all().some(c=>c.name==='plan')) {
  db.exec("ALTER TABLE payments ADD COLUMN plan TEXT NOT NULL DEFAULT 'basic'");
}
const userCols = db.prepare('PRAGMA table_info(users)').all();
if (!userCols.some(c=>c.name==='membership')) db.exec("ALTER TABLE users ADD COLUMN membership TEXT NOT NULL DEFAULT 'basic'");
const insertPayment = db.prepare(`INSERT INTO payments(user_id,method,tx_ref,amount,plan,currency,phone) VALUES(?,?,?,?,?,?,?)`);
const getPayment = db.prepare('SELECT * FROM payments WHERE tx_ref = ?');
const markPaid = db.prepare(`UPDATE payments SET status='paid', provider_transaction_id=COALESCE(?,provider_transaction_id), receipt=COALESCE(?,receipt), paid_at=CURRENT_TIMESTAMP, raw_result=COALESCE(?,raw_result) WHERE tx_ref=? AND status!='paid'`);
const markFailed = db.prepare(`UPDATE payments SET status='failed', raw_result=? WHERE tx_ref=? AND status='pending'`);
const activateUser = db.prepare(`UPDATE users SET paid_at=COALESCE(paid_at,CURRENT_TIMESTAMP), membership=? WHERE id=?`);

function requiredEnv(names) {
  const missing = names.filter(n => !process.env[n]);
  if (missing.length) throw new Error(`Missing server configuration: ${missing.join(', ')}`);
}
function randomRef() { return `FWFX-${Date.now()}-${crypto.randomBytes(5).toString('hex').toUpperCase()}`; }
function asyncRoute(fn) { return (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next); }
function ensureAuth(req,res,next) { if (!req.session.userId) return res.status(401).json({error:'Please log in first.'}); next(); }
function establishSession(req, userId) { return new Promise((resolve,reject)=>req.session.regenerate(err=>{ if(err) return reject(err); req.session.userId=userId; req.session.save(err2=>err2?reject(err2):resolve()); })); }
function currentUser(id) { return db.prepare('SELECT id,name,email,phone,role,paid_at,membership,created_at FROM users WHERE id=?').get(id); }
function planDetails(value) { const plan=String(value||'basic').toLowerCase(); if(plan==='basic') return {plan,amount:200,label:'Basic Class'}; if(plan==='premium') return {plan,amount:1000,label:'Premium Class'}; throw new Error('Choose a valid membership plan.'); }
function cleanPhone(value) {
  let p = String(value || '').replace(/[\s-]/g,'');
  if (p.startsWith('+')) p = p.slice(1);
  if (p.startsWith('0') && p.length === 10) p = '254' + p.slice(1);
  if (p.startsWith('7') && p.length === 9) p = '254' + p;
  if (!/^254[17]\d{8}$/.test(p)) throw new Error('Enter a valid Kenyan mobile number, e.g. 0712345678.');
  return p;
}
function darajaBase() { return process.env.DARAJA_ENV === 'production' ? 'https://api.safaricom.co.ke' : 'https://sandbox.safaricom.co.ke'; }
async function darajaToken() {
  requiredEnv(['DARAJA_CONSUMER_KEY','DARAJA_CONSUMER_SECRET']);
  const auth = Buffer.from(`${process.env.DARAJA_CONSUMER_KEY}:${process.env.DARAJA_CONSUMER_SECRET}`).toString('base64');
  const r = await fetch(`${darajaBase()}/oauth/v1/generate?grant_type=client_credentials`, {headers:{Authorization:`Basic ${auth}`}});
  const j = await r.json();
  if (!r.ok || !j.access_token) throw new Error('Could not authenticate with Daraja. Check sandbox credentials.');
  return j.access_token;
}
function darajaPassword(shortcode,passkey,timestamp) { return Buffer.from(`${shortcode}${passkey}${timestamp}`).toString('base64'); }
function timestamp() { const d = new Date(); const pad = n => String(n).padStart(2,'0'); return `${d.getFullYear()}${pad(d.getMonth()+1)}${pad(d.getDate())}${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`; }
async function darajaQuery(checkoutRequestId) {
  requiredEnv(['DARAJA_SHORTCODE','DARAJA_PASSKEY']);
  const token = await darajaToken(); const ts = timestamp(); const shortcode = process.env.DARAJA_SHORTCODE;
  const r = await fetch(`${darajaBase()}/mpesa/stkpushquery/v1/query`, {method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:JSON.stringify({BusinessShortCode:shortcode,Password:darajaPassword(shortcode,process.env.DARAJA_PASSKEY,ts),Timestamp:ts,CheckoutRequestID:checkoutRequestId})});
  const j = await r.json();
  if (!r.ok) throw new Error(j.errorMessage || 'Daraja status query failed.');
  return j;
}
async function verifyFlutterwave(transactionId, expectedRef) {
  requiredEnv(['FLW_SECRET_KEY']);
  const r = await fetch(`https://api.flutterwave.com/v3/transactions/${encodeURIComponent(transactionId)}/verify`, {headers:{Authorization:`Bearer ${process.env.FLW_SECRET_KEY}`}});
  const j = await r.json();
  if (!r.ok || j.status !== 'success' || !j.data) throw new Error('Card payment verification failed.');
  const d = j.data;
  const amount = Number(d.amount);
  const expected=getPayment.get(expectedRef);
  if (!expected || d.status !== 'successful' || d.tx_ref !== expectedRef || d.currency !== 'KES' || amount !== expected.amount) throw new Error('Payment details do not match the selected Fixe with FX plan price.');
  return d;
}
function applyPaid(txRef, providerId, receipt, raw) {
  const p = getPayment.get(txRef);
  if (!p) throw new Error('Unknown payment reference.');
  const tx = db.transaction(() => { markPaid.run(providerId || null, receipt || null, raw ? JSON.stringify(raw).slice(0,12000) : null, txRef); activateUser.run(p.plan,p.user_id); });
  tx();
}

if (process.env.NODE_ENV === 'production') {
  if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) throw new Error('Set SESSION_SECRET to a random value of at least 32 characters in production.');
  if (!process.env.PUBLIC_BASE_URL || !process.env.PUBLIC_BASE_URL.startsWith('https://')) throw new Error('PUBLIC_BASE_URL must be an HTTPS URL in production.');
  app.set('trust proxy', 1);
}
app.disable('x-powered-by');
app.use(express.json({limit:'30kb'}));
app.use(express.urlencoded({extended:false,limit:'10kb'}));
app.use((req,res,next)=>{res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','same-origin');res.setHeader('X-Frame-Options','DENY');next();});
app.use(session({store:new SQLiteStore({db:'sessions.sqlite',dir:path.join(ROOT,'data')}),secret:process.env.SESSION_SECRET || 'development-only-change-this-secret',resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:1000*60*60*8}}));

// Basic same-origin protection for browser-originated state changes.
app.use('/api', (req,res,next)=>{
  if (!['GET','HEAD','OPTIONS'].includes(req.method)) {
    const origin = req.get('origin');
    if (origin) {
      try { if (new URL(origin).host !== req.get('host')) return res.status(403).json({error:'Cross-origin request blocked.'}); }
      catch { return res.status(403).json({error:'Invalid request origin.'}); }
    }
  }
  next();
});

const authLimiter = require('express-rate-limit').rateLimit({windowMs:15*60*1000,limit:15,standardHeaders:true,legacyHeaders:false});
const paymentLimiter = require('express-rate-limit').rateLimit({windowMs:10*60*1000,limit:8,standardHeaders:true,legacyHeaders:false});

app.post('/api/register',authLimiter,asyncRoute(async(req,res)=>{
  const {name,email,phone,password}=req.body||{};
  if (!name || String(name).trim().length<2 || !email || !/^\S+@\S+\.\S+$/.test(String(email)) || !password || String(password).length<10) return res.status(400).json({error:'Enter your name, a valid email and a password of at least 10 characters.'});
  let normalizedPhone; try { normalizedPhone=cleanPhone(phone); } catch(e) { return res.status(400).json({error:e.message}); }
  const exists=db.prepare('SELECT id FROM users WHERE email=?').get(String(email).trim().toLowerCase());
  if(exists) return res.status(409).json({error:'An account with that email already exists.'});
  const hash=await bcrypt.hash(String(password),12);
  const info=db.prepare('INSERT INTO users(name,email,phone,password_hash) VALUES(?,?,?,?)').run(String(name).trim().slice(0,100),String(email).trim().toLowerCase(),normalizedPhone,hash);
  await establishSession(req, info.lastInsertRowid);
  res.status(201).json({user:currentUser(req.session.userId),plans:{basic:200,premium:1000},currency:'KES'});
}));
app.post('/api/login',authLimiter,asyncRoute(async(req,res)=>{
  const {email,password}=req.body||{}; const u=db.prepare('SELECT * FROM users WHERE email=?').get(String(email||'').trim().toLowerCase());
  if(!u || !(await bcrypt.compare(String(password||''),u.password_hash))) return res.status(401).json({error:'Incorrect email or password.'});
  await establishSession(req, u.id); res.json({user:currentUser(u.id)});
}));
app.post('/api/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/me',(req,res)=>{ if(!req.session.userId)return res.status(401).json({error:'Not signed in.'}); res.json({user:currentUser(req.session.userId)}); });
app.get('/api/payments',ensureAuth,(req,res)=>{const rows=db.prepare('SELECT tx_ref,method,amount,plan,currency,status,created_at,paid_at FROM payments WHERE user_id=? ORDER BY id DESC LIMIT 20').all(req.session.userId);res.json({payments:rows});});

app.post('/api/payments/mpesa',ensureAuth,paymentLimiter,asyncRoute(async(req,res)=>{
  let selected; try { selected=planDetails(req.body.plan); } catch(e) { return res.status(400).json({error:e.message}); }
  requiredEnv(['DARAJA_CONSUMER_KEY','DARAJA_CONSUMER_SECRET','DARAJA_SHORTCODE','DARAJA_PASSKEY','PUBLIC_BASE_URL','MPESA_CALLBACK_TOKEN']);
  const user=currentUser(req.session.userId); if(user.membership==='premium' || (selected.plan==='basic' && user.paid_at))return res.json({alreadyPaid:true});
  let phone; try {phone=cleanPhone(req.body.phone || user.phone);} catch(e){return res.status(400).json({error:e.message});}
  const pending=db.prepare("SELECT tx_ref FROM payments WHERE user_id=? AND method='mpesa' AND status='pending' AND created_at > datetime('now','-15 minutes') ORDER BY id DESC LIMIT 1").get(user.id);
  if(pending)return res.status(409).json({error:'An M-PESA payment is already pending. Wait for its confirmation before starting another payment.'});
  const txRef=randomRef(); insertPayment.run(user.id,'mpesa',txRef,selected.amount,selected.plan,'KES',phone);
  const token=await darajaToken(); const ts=timestamp(); const shortcode=process.env.DARAJA_SHORTCODE;
  const callback=`${process.env.PUBLIC_BASE_URL.replace(/\/$/,'')}/api/daraja/callback/${encodeURIComponent(process.env.MPESA_CALLBACK_TOKEN)}`;
  const payload={BusinessShortCode:shortcode,Password:darajaPassword(shortcode,process.env.DARAJA_PASSKEY,ts),Timestamp:ts,TransactionType:process.env.DARAJA_TRANSACTION_TYPE||'CustomerPayBillOnline',Amount:selected.amount,PartyA:phone,PartyB:shortcode,PhoneNumber:phone,CallBackURL:callback,AccountReference:txRef.slice(0,12),TransactionDesc:`Fixe with FX ${selected.label}`};
  const r=await fetch(`${darajaBase()}/mpesa/stkpush/v1/processrequest`,{method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:JSON.stringify(payload)}); const j=await r.json();
  if(!r.ok || !j.CheckoutRequestID){markFailed.run(JSON.stringify(j),txRef);return res.status(502).json({error:j.errorMessage||j.ResponseDescription||'Daraja could not start the payment.'});}
  db.prepare('UPDATE payments SET provider_checkout_id=? WHERE tx_ref=?').run(j.CheckoutRequestID,txRef);
  res.json({txRef,status:'pending',message:'STK Push requested. Check your phone and enter your M-PESA PIN to approve.'});
}));

app.post('/api/daraja/callback/:token',asyncRoute(async(req,res)=>{
  const suppliedToken=Buffer.from(String(req.params.token)); const expectedToken=Buffer.from(String(process.env.MPESA_CALLBACK_TOKEN||''));
  if(!expectedToken.length || suppliedToken.length!==expectedToken.length || !crypto.timingSafeEqual(suppliedToken,expectedToken)) return res.status(404).end();
  const body=req.body?.Body?.stkCallback; if(!body?.CheckoutRequestID)return res.json({ResultCode:0,ResultDesc:'Accepted'});
  const p=db.prepare('SELECT * FROM payments WHERE provider_checkout_id=?').get(body.CheckoutRequestID);
  if(!p || p.status==='paid')return res.json({ResultCode:0,ResultDesc:'Accepted'});
  if(Number(body.ResultCode)!==0){markFailed.run(JSON.stringify(body),p.tx_ref);return res.json({ResultCode:0,ResultDesc:'Recorded'});}
  // Do not trust the callback alone: independently query the STK request at Daraja.
  const q=await darajaQuery(body.CheckoutRequestID);
  const meta=body.CallbackMetadata?.Item||[]; const val=name=>meta.find(x=>x.Name===name)?.Value;
  if(Number(q.ResultCode)===0 && Number(val('Amount'))===p.amount){
    applyPaid(p.tx_ref,String(val('MpesaReceiptNumber')||body.CheckoutRequestID),String(val('MpesaReceiptNumber')||''),{callback:body,query:q});
  }
  res.json({ResultCode:0,ResultDesc:'Processed'});
}));

app.get('/api/payments/mpesa/status',ensureAuth,paymentLimiter,asyncRoute(async(req,res)=>{
  const txRef=String(req.query.tx_ref||''); const p=getPayment.get(txRef);
  if(!p || p.user_id!==req.session.userId || p.method!=='mpesa')return res.status(404).json({error:'M-PESA payment reference not found.'});
  // Activation is performed only by the authenticated Daraja callback after the server
  // independently queries the STK request and checks the callback amount against p.amount.
  // A status query alone is not enough to prove the exact amount paid.
  
  const latest=getPayment.get(txRef); res.json({status:latest.status});
}));

app.post('/api/payments/card',ensureAuth,paymentLimiter,asyncRoute(async(req,res)=>{
  let selected; try { selected=planDetails(req.body.plan); } catch(e) { return res.status(400).json({error:e.message}); }
  requiredEnv(['FLW_SECRET_KEY','PUBLIC_BASE_URL']);
  const user=currentUser(req.session.userId); if(user.membership==='premium' || (selected.plan==='basic' && user.paid_at))return res.json({alreadyPaid:true});
  const pending=db.prepare("SELECT tx_ref FROM payments WHERE user_id=? AND method='card' AND status='pending' AND created_at > datetime('now','-15 minutes') ORDER BY id DESC LIMIT 1").get(user.id);
  if(pending)return res.status(409).json({error:'A card payment is already pending. Wait 15 minutes or contact support before starting another payment.'});
  const txRef=randomRef(); insertPayment.run(user.id,'card',txRef,selected.amount,selected.plan,'KES',user.phone);
  const redirect=`${process.env.PUBLIC_BASE_URL.replace(/\/$/,'')}/payment-return.html`;
  const r=await fetch('https://api.flutterwave.com/v3/payments',{method:'POST',headers:{Authorization:`Bearer ${process.env.FLW_SECRET_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({tx_ref:txRef,amount:selected.amount,currency:'KES',redirect_url:redirect,payment_options:'card',customer:{email:user.email,name:user.name,phonenumber:user.phone},customizations:{title:'Fixe with FX',description:`${selected.label} forex training access`,logo:process.env.BRAND_LOGO_URL||''},configurations:{session_duration:10,max_retry_attempt:3}})});
  const j=await r.json(); if(!r.ok || j.status!=='success' || !j.data?.link){markFailed.run(JSON.stringify(j),txRef);return res.status(502).json({error:j.message||'Card checkout could not be created.'});}
  res.json({txRef,checkoutUrl:j.data.link,status:'pending'});
}));
app.get('/api/payments/card/verify',ensureAuth,asyncRoute(async(req,res)=>{
  const txRef=String(req.query.tx_ref||''); const transactionId=String(req.query.transaction_id||''); const p=getPayment.get(txRef);
  if(!p || p.user_id!==req.session.userId || p.method!=='card')return res.status(404).json({error:'Payment reference not found.'});
  if(p.status!=='paid'){
    const d=await verifyFlutterwave(transactionId,txRef);
    applyPaid(txRef,String(d.id),null,d);
  }
  res.json({status:'paid',user:currentUser(req.session.userId)});
}));
app.post('/api/flutterwave/webhook',asyncRoute(async(req,res)=>{
  const secret=process.env.FLW_WEBHOOK_SECRET_HASH;
  const supplied=req.get('verif-hash')||'';
  if(!secret || supplied.length!==secret.length || !crypto.timingSafeEqual(Buffer.from(supplied),Buffer.from(secret)))return res.status(401).send('Invalid webhook signature');
  const d=req.body?.data; if(d?.id && d?.tx_ref){
    const p=getPayment.get(String(d.tx_ref));
    if(p && p.method==='card' && p.status!=='paid'){
      try {const verified=await verifyFlutterwave(d.id,String(d.tx_ref));applyPaid(String(d.tx_ref),String(verified.id),null,verified);} catch(e) { /* Keep pending; reconciliation can retry. */ }
    }
  }
  res.sendStatus(200);
}));

app.get('/api/admin/payments',ensureAuth,(req,res)=>{const u=currentUser(req.session.userId);if(u.role!=='admin')return res.status(403).json({error:'Admin access required.'});res.json({payments:db.prepare('SELECT p.*,u.email FROM payments p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 200').all()});});
app.get('/health',(_req,res)=>res.json({ok:true,mode:process.env.PAYMENT_MODE||'sandbox'}));
app.use(express.static(path.join(ROOT,'public'),{extensions:['html'],dotfiles:'deny',index:'index.html'}));
app.use((err,req,res,next)=>{console.error(new Date().toISOString(),err.message);if(res.headersSent)return next(err);res.status(500).json({error:process.env.NODE_ENV==='production'?'Something went wrong. Please try again.':err.message});});

app.listen(PORT,()=>console.log(`Fixe with FX server listening on http://localhost:${PORT}`));
