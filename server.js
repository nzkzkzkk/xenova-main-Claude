'use strict';
/* XENOVA — server: static files + JSON API on top of SQLite */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const D = require('./db');

const PORT = Number(process.env.PORT) || 8765;
const HOST = process.env.HOST || '127.0.0.1';
const ALLOW_SIGNUP = process.env.XENOVA_ALLOW_SIGNUP !== '0';
const MAX_BODY = 12 * 1024 * 1024;

// ---------- static files (allowlist only — never serve server code or the DB) ----------
const STATIC = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/index.html': ['index.html', 'text/html; charset=utf-8'],
  '/app.js': ['app.js', 'application/javascript; charset=utf-8'],
  '/translations.js': ['translations.js', 'application/javascript; charset=utf-8'],
  '/styles.css': ['styles.css', 'text/css; charset=utf-8']
};
const UPLOAD_MIME = { png: 'image/png', jpg: 'image/jpeg', webp: 'image/webp', gif: 'image/gif' };
const UPLOAD_PATH_RE = /^\/uploads\/([a-f0-9]{32})\.(png|jpg|webp|gif)$/;

const SEC_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'same-origin'
};

// ---------- helpers ----------
function send(res, status, body, headers = {}) {
  const isBuf = Buffer.isBuffer(body) || typeof body === 'string';
  const payload = isBuf ? body : JSON.stringify(body);
  res.writeHead(status, {
    ...SEC_HEADERS,
    'Content-Type': isBuf ? (headers['Content-Type'] || 'text/plain; charset=utf-8') : 'application/json; charset=utf-8',
    ...headers
  });
  res.end(payload);
}
const fail = (res, status, msg) => send(res, status, { error: msg });

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > MAX_BODY) { reject(D.badRequest('Payload too large', 413)); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(D.badRequest('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}

function bearer(req) {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7).trim() : null;
}
function clientIp(req) { return req.socket.remoteAddress || 'unknown'; }

// ---------- login throttling (in memory) ----------
const attempts = new Map(); // key -> { n, until }
function throttleKey(req, email) { return clientIp(req) + '|' + String(email).toLowerCase(); }
function isLocked(key) { const a = attempts.get(key); return a && a.until > Date.now() ? Math.ceil((a.until - Date.now()) / 60000) : 0; }
function noteFail(key) {
  const a = attempts.get(key) || { n: 0, until: 0 };
  a.n += 1;
  if (a.n >= 5) { a.until = Date.now() + 5 * 60000; a.n = 0; }
  attempts.set(key, a);
}
setInterval(() => { const now = Date.now(); for (const [k, a] of attempts) if (a.until < now && a.n === 0) attempts.delete(k); D.purgeSessions(); }, 3600000).unref();

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const SETTING_KEYS = new Set(['theme', 'custom', 'brightness', 'compact']);

// ---------- API ----------
async function handleApi(req, res, url) {
  const route = `${req.method} ${url.pathname}`;

  // --- public auth endpoints ---
  if (route === 'POST /api/auth/login') {
    const body = await readJson(req);
    const email = String(body.email || '').trim();
    const key = throttleKey(req, email);
    const mins = isLocked(key);
    if (mins) return send(res, 429, { error: 'locked', minutes: mins });
    const user = email && D.findUserByEmail(email);
    const ok = user && await D.verifyPassword(String(body.password || ''), user.password_hash);
    if (!ok) { noteFail(key); return fail(res, 401, 'invalid_credentials'); }
    attempts.delete(key);
    const s = D.createSession(user.id, !!body.remember);
    return send(res, 200, { token: s.token, expiresAt: s.expiresAt, user: D.publicUser(user) });
  }

  if (route === 'POST /api/auth/register') {
    if (!ALLOW_SIGNUP) return fail(res, 403, 'signup_disabled');
    const b = await readJson(req);
    const name = String(b.name || '').trim().slice(0, 100);
    const email = String(b.email || '').trim().toLowerCase().slice(0, 200);
    const password = String(b.password || '');
    if (!name) return fail(res, 400, 'name_required');
    if (!EMAIL_RE.test(email)) return fail(res, 400, 'email_invalid');
    if (password.length < 6 || password.length > 200) return fail(res, 400, 'password_short');
    if (D.findUserByEmail(email)) return fail(res, 409, 'email_exists');
    const id = 'u_' + crypto.randomBytes(8).toString('hex');
    await D.createUser({ id, email, name, password });
    const colors = ['#3B82F6', '#8B5CF6', '#EC4899', '#10B981', '#F59E0B', '#EF4444', '#06B6D4'];
    D.applyOps({ id, role: 'admin' }, 'members', { upserts: [{
      id, name, position: 'Team Member', bio: '', responsibilities: [], skills: [], email, phone: '', photo: '',
      color: colors[crypto.randomInt(colors.length)], createdAt: new Date().toISOString()
    }] });
    const s = D.createSession(id, false);
    return send(res, 201, { token: s.token, expiresAt: s.expiresAt, user: D.publicUser(D.findUserById(id)) });
  }

  // --- everything below needs a valid session ---
  const token = bearer(req);
  const user = D.userFromToken(token);
  if (!user) return fail(res, 401, 'unauthorized');

  if (route === 'POST /api/auth/logout') { D.destroySession(token); return send(res, 200, { ok: true }); }
  if (route === 'GET /api/me') return send(res, 200, { user });

  if (route === 'GET /api/version') return send(res, 200, { v: D.getVersion() });

  if (route === 'GET /api/bootstrap') {
    const collections = {};
    for (const name of Object.keys(D.COLLECTIONS)) collections[name] = D.listCollection(name);
    const settings = {};
    for (const r of D.db.prepare('SELECT key,value FROM settings WHERE user_id = ?').all(user.id)) {
      try { settings[r.key] = JSON.parse(r.value); } catch { /* skip */ }
    }
    return send(res, 200, { user, collections, settings, v: D.getVersion() });
  }

  let m;
  if ((m = /^\/api\/collections\/([a-z]+)\/ops$/.exec(url.pathname)) && req.method === 'POST') {
    if (!D.COLLECTIONS[m[1]]) return fail(res, 404, 'unknown_collection');
    const body = await readJson(req);
    D.applyOps(user, m[1], body);
    return send(res, 200, { ok: true, v: D.getVersion(), rows: D.listCollection(m[1]) });
  }

  if ((m = /^\/api\/settings\/([a-z]+)$/.exec(url.pathname)) && req.method === 'PUT') {
    if (!SETTING_KEYS.has(m[1])) return fail(res, 404, 'unknown_setting');
    const body = await readJson(req);
    const val = JSON.stringify(body.value === undefined ? null : body.value);
    if (val.length > 10000) return fail(res, 413, 'too_large');
    D.db.prepare(`INSERT INTO settings(user_id,key,value) VALUES(?,?,?)
      ON CONFLICT(user_id,key) DO UPDATE SET value=excluded.value`).run(user.id, m[1], val);
    return send(res, 200, { ok: true });
  }
  if ((m = /^\/api\/settings\/([a-z]+)$/.exec(url.pathname)) && req.method === 'DELETE') {
    D.db.prepare('DELETE FROM settings WHERE user_id = ? AND key = ?').run(user.id, m[1]);
    return send(res, 200, { ok: true });
  }

  if (route === 'PATCH /api/me') {
    const b = await readJson(req);
    const name = String(b.name || '').trim().slice(0, 100);
    if (!name) return fail(res, 400, 'name_required');
    D.db.prepare('UPDATE users SET name = ? WHERE id = ?').run(name, user.id);
    // keep the team profile name in step with the account name
    const cur = D.COLLECTIONS.members.stmtGet.get(user.id);
    if (cur) D.applyOps(user, 'members', { upserts: [{ ...JSON.parse(cur.data), name }] });
    return send(res, 200, { user: D.publicUser(D.findUserById(user.id)) });
  }

  if (route === 'POST /api/auth/password') {
    const b = await readJson(req);
    const row = D.findUserById(user.id);
    const newPw = String(b.newPassword || '');
    if (newPw.length < 6 || newPw.length > 200) return fail(res, 400, 'password_short');
    if (!(await D.verifyPassword(String(b.oldPassword || ''), row.password_hash))) return fail(res, 403, 'invalid_credentials');
    D.db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(await D.hashPassword(newPw), user.id);
    // sign out every other session of this user
    D.db.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?')
      .run(user.id, crypto.createHash('sha256').update(token).digest('hex'));
    return send(res, 200, { ok: true });
  }

  if (route === 'DELETE /api/me') {
    if (user.role === 'admin') {
      const admins = D.db.prepare("SELECT COUNT(*) c FROM users WHERE role = 'admin'").get().c;
      if (admins <= 1) return fail(res, 409, 'last_admin');
    }
    D.db.prepare('DELETE FROM users WHERE id = ?').run(user.id); // sessions + settings cascade
    return send(res, 200, { ok: true });
  }

  return fail(res, 404, 'not_found');
}

// ---------- server ----------
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) {
      res.setHeader('Cache-Control', 'no-store');
      return await handleApi(req, res, url);
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') return fail(res, 405, 'method_not_allowed');

    const st = STATIC[url.pathname];
    if (st) {
      const data = fs.readFileSync(path.join(__dirname, st[0]));
      return send(res, 200, data, { 'Content-Type': st[1], 'Cache-Control': 'no-cache' });
    }
    const up = UPLOAD_PATH_RE.exec(url.pathname);
    if (up) {
      const file = path.join(D.UPLOAD_DIR, `${up[1]}.${up[2]}`);
      if (!fs.existsSync(file)) return fail(res, 404, 'not_found');
      return send(res, 200, fs.readFileSync(file), { 'Content-Type': UPLOAD_MIME[up[2]], 'Cache-Control': 'public, max-age=31536000, immutable' });
    }
    return send(res, 404, 'Not found');
  } catch (e) {
    if (e && e.status) return fail(res, e.status, e.message);
    console.error('Unhandled error:', e);
    if (!res.headersSent) fail(res, 500, 'server_error');
  }
});

// ---------- first run ----------
async function bootstrapFirstRun() {
  console.log('🗄️  database driver:', D.DB_DRIVER);
  const seeded = D.seedSampleData();
  if (seeded) console.log('🌱 Sample data created (4 members, meetings, projects, timetable)');
  const count = D.db.prepare('SELECT COUNT(*) c FROM users').get().c;
  if (count === 0) {
    const email = process.env.XENOVA_ADMIN_EMAIL || 'admin@xenova.local';
    let password = process.env.XENOVA_ADMIN_PASSWORD;
    const generated = !password;
    if (generated) password = crypto.randomBytes(9).toString('base64url');
    await D.createUser({ id: 'u_admin', email, name: 'XENOVA Administrator', password, role: 'admin', position: 'Platform Owner (Admin)' });
    console.log('\n┌──────────────────────────────────────────────────────────┐');
    console.log('│  ADMIN ACCOUNT CREATED (shown once)                      │');
    console.log('│  email:    ' + email.padEnd(46) + '│');
    console.log('│  password: ' + (generated ? password : '(from XENOVA_ADMIN_PASSWORD)').padEnd(46) + '│');
    console.log('│  change it later: node manage.js set-password EMAIL PASS │');
    console.log('└──────────────────────────────────────────────────────────┘\n');
  }
}

if (require.main === module) {
  bootstrapFirstRun().then(() => {
    server.listen(PORT, HOST, () => console.log(`✅ XENOVA พร้อมใช้งานที่ http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`));
  }).catch(e => { console.error(e); process.exit(1); });
}

module.exports = { server };
