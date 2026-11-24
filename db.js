'use strict';
/* XENOVA — database layer (SQLite via better-sqlite3) */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');

const scrypt = promisify(crypto.scrypt);

const DATA_DIR = process.env.XENOVA_DATA_DIR || path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

/* SQLite driver: better-sqlite3 if installed (npm install), otherwise Node's built-in
 * node:sqlite (Node 22.5+, no install needed). Both give the same API to the rest of the app. */
class NodeSqliteCompat {
  constructor(file) {
    const { DatabaseSync } = require('node:sqlite');
    this.d = new DatabaseSync(file);
    this.depth = 0;
  }
  exec(sql) { this.d.exec(sql); }
  pragma(s) { this.d.exec('PRAGMA ' + s); }
  prepare(sql) { return this.d.prepare(sql); }
  transaction(fn) {
    return (...args) => {
      const outer = this.depth === 0;
      const sp = 'sp' + this.depth;
      this.d.exec(outer ? 'BEGIN' : `SAVEPOINT ${sp}`);
      this.depth++;
      try {
        const r = fn(...args);
        this.depth--;
        this.d.exec(outer ? 'COMMIT' : `RELEASE ${sp}`);
        return r;
      } catch (e) {
        this.depth--;
        this.d.exec(outer ? 'ROLLBACK' : `ROLLBACK TO ${sp}; RELEASE ${sp}`);
        throw e;
      }
    };
  }
}

function openDatabase(file) {
  if (process.env.XENOVA_SQLITE !== 'node') {
    try {
      const Database = require('better-sqlite3');
      return { db: new Database(file), driver: 'better-sqlite3' };
    } catch (e) {
      const missing = e.code === 'MODULE_NOT_FOUND' || /better_sqlite3|NODE_MODULE_VERSION|dlopen/.test(String(e.message));
      if (!missing) throw e;
    }
  }
  try {
    return { db: new NodeSqliteCompat(file), driver: 'node:sqlite' };
  } catch (e) {
    throw new Error('No SQLite driver available. Run "npm install" in the project folder, or use Node 22.5+.\n' + e.message);
  }
}

const { db, driver: DB_DRIVER } = openDatabase(process.env.XENOVA_DB || path.join(DATA_DIR, 'xenova.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name          TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin','member')),
  position      TEXT DEFAULT 'Team Member',
  created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key     TEXT NOT NULL,
  value   TEXT NOT NULL,
  PRIMARY KEY (user_id, key)
);
CREATE TABLE IF NOT EXISTS members (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, position TEXT,
  data TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meetings (
  id TEXT PRIMARY KEY, title TEXT NOT NULL, date TEXT, time TEXT,
  data TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_meetings_when ON meetings(date, time);
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY, member_id TEXT, title TEXT,
  data TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_projects_member ON projects(member_id);
CREATE TABLE IF NOT EXISTS timetable (
  id TEXT PRIMARY KEY, title TEXT, day_of_week INTEGER,
  data TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS activity (
  id TEXT PRIMARY KEY, created_at TEXT, data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS folders (
  id TEXT PRIMARY KEY, parent_id TEXT, name TEXT NOT NULL,
  data TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(parent_id);
CREATE TABLE IF NOT EXISTS links (
  id TEXT PRIMARY KEY, url TEXT NOT NULL, added_by TEXT, created_at TEXT,
  data TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
`);

// ---------- meta / data version ----------
const getMeta = key => (db.prepare('SELECT value FROM meta WHERE key = ?').get(key) || {}).value;
const setMeta = (key, value) =>
  db.prepare('INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key, String(value));
const getVersion = () => Number(getMeta('data_version') || 0);
const bumpVersion = () => setMeta('data_version', getVersion() + 1);

// ---------- passwords ----------
async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const h = await scrypt(pw, salt, 64);
  return `scrypt$${salt.toString('hex')}$${h.toString('hex')}`;
}
async function verifyPassword(pw, stored) {
  try {
    const [alg, saltHex, hashHex] = String(stored).split('$');
    if (alg !== 'scrypt') return false;
    const expected = Buffer.from(hashHex, 'hex');
    const actual = await scrypt(pw, Buffer.from(saltHex, 'hex'), expected.length);
    return crypto.timingSafeEqual(actual, expected);
  } catch { return false; }
}

// ---------- sessions ----------
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
function createSession(userId, remember) {
  const token = crypto.randomBytes(32).toString('base64url');
  const ttl = (remember ? 30 : 1) * 86400000;
  db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)')
    .run(sha256(token), userId, Date.now() + ttl);
  return { token, expiresAt: Date.now() + ttl };
}
function userFromToken(token) {
  if (!token) return null;
  const row = db.prepare(`SELECT u.id,u.email,u.name,u.role,u.position,s.expires_at
    FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?`).get(sha256(token));
  if (!row) return null;
  if (row.expires_at < Date.now()) {
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
    return null;
  }
  const { expires_at, ...user } = row;
  return user;
}
const destroySession = token => db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
const purgeSessions = () => db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now());

// ---------- images (data URL -> file in data/uploads) ----------
const IMG_RE = /^data:image\/(png|jpeg|webp|gif);base64,([A-Za-z0-9+/=]+)$/;
const UPLOAD_URL_RE = /^\/uploads\/[a-f0-9]{32}\.(png|jpg|webp|gif)$/;
const MAX_IMAGE = 5 * 1024 * 1024;

function sniffExt(buf) {
  if (buf.length > 12 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) return 'png';
  if (buf.length > 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'jpg';
  if (buf.length > 12 && buf.toString('ascii', 0, 4) === 'RIFF' && buf.toString('ascii', 8, 12) === 'WEBP') return 'webp';
  if (buf.length > 6 && buf.toString('ascii', 0, 4) === 'GIF8') return 'gif';
  return null;
}
function saveImageBuffer(buf) {
  if (buf.length > MAX_IMAGE) { const e = new Error('Image too large (max 5MB)'); e.status = 413; throw e; }
  const ext = sniffExt(buf);
  if (!ext) { const e = new Error('Unsupported image type'); e.status = 400; throw e; }
  const name = crypto.createHash('sha256').update(buf).digest('hex').slice(0, 32) + '.' + ext;
  const file = path.join(UPLOAD_DIR, name);
  if (!fs.existsSync(file)) fs.writeFileSync(file, buf);
  return '/uploads/' + name;
}
/** Returns a safe image URL ('' if the value is unusable). */
function normalizeImage(value) {
  if (!value || typeof value !== 'string') return '';
  if (UPLOAD_URL_RE.test(value)) return value;
  const m = IMG_RE.exec(value);
  if (m) return saveImageBuffer(Buffer.from(m[2], 'base64'));
  return ''; // anything else (legacy names, quotes, javascript: ...) is dropped
}

// ---------- collections ----------
const str = v => (v == null ? null : String(v).slice(0, 500));
const ID_RE = /^[A-Za-z0-9_.:@-]{1,100}$/;
const MAX_FOLDER_DEPTH = 6;
const COLLECTIONS = {
  members: {
    table: 'members', order: 'rowid',
    cols: o => ({ name: str(o.name) || '', position: str(o.position) }),
    images: ['photo'],
    sanitize(o) { o.color = /^#[0-9a-fA-F]{3,8}$/.test(o.color || '') ? o.color : '#1A73E8'; },
    canWrite: (u, existing, next) => u.role === 'admin' || (!!existing && next.id === u.id),
    canDelete: u => u.role === 'admin'
  },
  meetings: {
    table: 'meetings', order: 'date, time, rowid',
    cols: o => ({ title: str(o.title) || '', date: str(o.date), time: str(o.time) }),
    images: [],
    canWrite: () => true, canDelete: () => true
  },
  projects: {
    table: 'projects', order: 'rowid',
    cols: o => ({ member_id: str(o.memberId), title: str(o.title) }),
    images: ['cover'],
    canWrite: (u, existing, next) =>
      u.role === 'admin' || (next.memberId === u.id && (!existing || existing.memberId === u.id)),
    canDelete: (u, existing) => u.role === 'admin' || existing.memberId === u.id
  },
  timetable: {
    table: 'timetable', order: 'rowid',
    cols: o => ({ title: str(o.title), day_of_week: Number.isInteger(o.dayOfWeek) ? o.dayOfWeek : null }),
    images: [],
    canWrite: () => true, canDelete: () => true
  },
  // Link vault: anyone signed in can ADD a link; only an admin can edit or delete.
  links: {
    table: 'links', order: 'created_at DESC, rowid DESC',
    cols: o => ({ url: str(o.url) || '', added_by: str(o.addedBy), created_at: str(o.createdAt) }),
    images: [],
    validate(o) {
      o.title = String(o.title || '').trim().slice(0, 200);
      o.note = String(o.note || '').trim().slice(0, 1000);
      if (!o.title) throw badRequest('title_required');
      let u;
      try { u = new URL(String(o.url || '').trim()); } catch { throw badRequest('url_invalid'); }
      if (u.protocol !== 'http:' && u.protocol !== 'https:') throw badRequest('url_invalid');
      o.url = u.href.slice(0, 2000);
      o.folderId = (o.folderId && ID_RE.test(String(o.folderId))) ? String(o.folderId) : null;
    },
    stamp(user, row, existing) { // the server decides who added it and when
      if (existing) { row.addedBy = existing.addedBy; row.addedByName = existing.addedByName; row.createdAt = existing.createdAt; }
      else { row.addedBy = user.id; row.addedByName = user.name || ''; row.createdAt = new Date().toISOString(); }
      if (row.folderId && !db.prepare('SELECT 1 FROM folders WHERE id = ?').get(row.folderId)) throw badRequest('folder_not_found');
    },
    canWrite: (u, existing) => u.role === 'admin' || !existing,
    canDelete: u => u.role === 'admin'
  },
  // Folders ("ช่องเก็บลิงก์") nest inside each other. Anyone can create one; only an admin can rename, move or delete.
  folders: {
    table: 'folders', order: 'name COLLATE NOCASE, rowid',
    cols: o => ({ name: str(o.name) || '', parent_id: str(o.parentId) }),
    images: [],
    validate(o) {
      o.name = String(o.name || '').trim().slice(0, 100);
      if (!o.name) throw badRequest('name_required');
      o.parentId = (o.parentId && ID_RE.test(String(o.parentId))) ? String(o.parentId) : null;
    },
    stamp(user, row, existing) {
      if (existing) { row.addedBy = existing.addedBy; row.addedByName = existing.addedByName; row.createdAt = existing.createdAt; }
      else { row.addedBy = user.id; row.addedByName = user.name || ''; row.createdAt = new Date().toISOString(); }
      // parent must exist, no cycles, limited depth (root folders are depth 1)
      let depth = 1, cur = row.parentId;
      const seen = new Set([row.id]);
      while (cur) {
        if (seen.has(cur)) throw badRequest('folder_cycle');
        seen.add(cur);
        const p = db.prepare('SELECT data FROM folders WHERE id = ?').get(cur);
        if (!p) throw badRequest('folder_not_found');
        cur = JSON.parse(p.data).parentId || null;
        if (++depth > MAX_FOLDER_DEPTH) throw badRequest('folder_too_deep');
      }
    },
    canWrite: (u, existing) => u.role === 'admin' || !existing,
    canDelete: u => u.role === 'admin'
  },
  activity: {
    table: 'activity', order: 'created_at DESC, rowid DESC',
    cols: o => ({ created_at: str(o.createdAt) }),
    images: [],
    canWrite: () => true, canDelete: () => true
  }
};

const MAX_ROW = 64 * 1024; // JSON size per row after images were moved to files

for (const [name, c] of Object.entries(COLLECTIONS)) {
  const extra = Object.keys(c.cols({}));
  const hasUpdated = name !== 'activity';
  const colList = ['id', ...extra, 'data', ...(hasUpdated ? ['updated_at'] : [])];
  const params = colList.map(k => '@' + k).join(',');
  const updates = colList.filter(k => k !== 'id').map(k => `${k}=excluded.${k}`).join(',');
  c.hasUpdated = hasUpdated;
  c.extra = extra;
  c.stmtUpsert = db.prepare(`INSERT INTO ${c.table}(${colList.join(',')}) VALUES(${params}) ON CONFLICT(id) DO UPDATE SET ${updates}`);
  c.stmtGet = db.prepare(`SELECT data FROM ${c.table} WHERE id = ?`);
  c.stmtDel = db.prepare(`DELETE FROM ${c.table} WHERE id = ?`);
  c.stmtAll = db.prepare(`SELECT data FROM ${c.table} ORDER BY ${c.order}`);
}

function badRequest(msg, status = 400) { const e = new Error(msg); e.status = status; return e; }

function cleanRow(name, o) {
  const c = COLLECTIONS[name];
  if (!o || typeof o !== 'object' || Array.isArray(o)) throw badRequest('Row must be an object');
  if (typeof o.id !== 'string' || !ID_RE.test(o.id)) throw badRequest('Invalid id');
  const row = JSON.parse(JSON.stringify(o)); // detach + drop functions/undefined
  for (const f of c.images) row[f] = normalizeImage(row[f]);
  if (c.sanitize) c.sanitize(row);
  if (c.validate) c.validate(row);
  if (JSON.stringify(row).length > MAX_ROW) throw badRequest('Row too large', 413);
  return row;
}

function listCollection(name) {
  return COLLECTIONS[name].stmtAll.all().map(r => JSON.parse(r.data));
}

/** Apply {upserts, deletes} for a user inside one transaction. */
function applyOps(user, name, body) {
  const c = COLLECTIONS[name];
  const ups = Array.isArray(body && body.upserts) ? body.upserts : [];
  const dels = Array.isArray(body && body.deletes) ? body.deletes : [];
  if (ups.length > 500 || dels.length > 500) throw badRequest('Too many operations', 413);
  const now = new Date().toISOString();
  const run = db.transaction(() => {
    for (const id of dels) {
      if (typeof id !== 'string') continue;
      const cur = c.stmtGet.get(id);
      if (!cur) continue;
      if (!c.canDelete(user, JSON.parse(cur.data))) throw badRequest('Forbidden', 403);
      c.stmtDel.run(id);
    }
    for (const raw of ups) {
      const row = cleanRow(name, raw);
      const cur = c.stmtGet.get(row.id);
      if (c.stamp) c.stamp(user, row, cur ? JSON.parse(cur.data) : null);
      if (!c.canWrite(user, cur ? JSON.parse(cur.data) : null, row)) throw badRequest('Forbidden', 403);
      const p = { id: row.id, ...c.cols(row), data: JSON.stringify(row) };
      if (c.hasUpdated) p.updated_at = now;
      c.stmtUpsert.run(p);
    }
    // keep the activity log short
    if (name === 'activity') {
      db.prepare(`DELETE FROM activity WHERE id NOT IN (SELECT id FROM activity ORDER BY created_at DESC, rowid DESC LIMIT 50)`).run();
    }
    bumpVersion();
  });
  run();
}

// ---------- users ----------
const USER_COLS = 'id,email,name,role,position';
const publicUser = u => (u ? { id: u.id, email: u.email, name: u.name, role: u.role, position: u.position } : null);
const findUserByEmail = email => db.prepare('SELECT * FROM users WHERE email = ?').get(String(email).trim());
const findUserById = id => db.prepare('SELECT * FROM users WHERE id = ?').get(id);

async function createUser({ id, email, name, password, role = 'member', position = 'Team Member' }) {
  const hash = await hashPassword(password);
  db.prepare('INSERT INTO users(id,email,name,password_hash,role,position,created_at) VALUES(?,?,?,?,?,?,?)')
    .run(id, email.trim(), name, hash, role, position, new Date().toISOString());
}

// ---------- first-run seeding ----------
function shiftDate(dateStr, days) {
  const d = new Date(dateStr + 'T00:00:00Z');
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}

function seedSampleData() {
  if (getMeta('seeded')) return false;
  const seedFile = path.join(__dirname, 'seed.json');
  if (!fs.existsSync(seedFile)) { setMeta('seeded', '1'); return false; }
  const seed = JSON.parse(fs.readFileSync(seedFile, 'utf8'));

  // Sample portraits (optional file shipped with the project). Mapping is by position in that file.
  const photoMap = { mem_aumim: 'p3', mem_taetae: 'p1', mem_proud: 'p2', mem_notebook: 'p4' };
  let photos = {};
  try { photos = JSON.parse(fs.readFileSync(path.join(__dirname, 'members_data.json'), 'utf8')); } catch { /* optional */ }
  const photoFor = id => (photos[photoMap[id]] ? normalizeImage(photos[photoMap[id]]) : '');

  // meetings in seed.json are relative to the day the seed was exported
  const base = seed.exportedOn || '2026-11-14';
  const todayStr = new Date().toISOString().slice(0, 10);
  const offset = Math.round((Date.parse(todayStr) - Date.parse(base)) / 86400000);

  const members = seed.members.map(m => ({ ...m, photo: photoFor(m.id) }));
  const projects = seed.projects.map(p => ({ ...p, cover: photoFor(p.memberId) }));
  const meetings = seed.meetings.map(m => ({ ...m, date: m.date ? shiftDate(m.date, offset) : m.date }));
  const admin = { id: 'system', role: 'admin' };
  db.transaction(() => {
    applyOps(admin, 'members', { upserts: members });
    applyOps(admin, 'projects', { upserts: projects });
    applyOps(admin, 'meetings', { upserts: meetings });
    applyOps(admin, 'timetable', { upserts: seed.timetable });
    setMeta('seeded', '1');
  })();
  return true;
}

module.exports = {
  db, DB_DRIVER, DATA_DIR, UPLOAD_DIR, COLLECTIONS, applyOps, listCollection, getVersion,
  hashPassword, verifyPassword, createSession, userFromToken, destroySession, purgeSessions,
  publicUser, findUserByEmail, findUserById, createUser, seedSampleData, normalizeImage,
  badRequest, getMeta, setMeta, USER_COLS
};
