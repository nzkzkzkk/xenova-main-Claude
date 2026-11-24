'use strict';
/* Run with:  npm test   — starts a throw-away server on a temp database. */
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const PORT = 9300 + Math.floor(Math.random() * 400);
const BASE = `http://127.0.0.1:${PORT}`;
const DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'xenova-test-'));
const ADMIN = { email: 'boss@test.dev', password: 'AdminPass-1' };
let proc;

function startServer() {
  return new Promise((resolve, reject) => {
    proc = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
      env: { ...process.env, PORT, XENOVA_DATA_DIR: DIR, XENOVA_ADMIN_EMAIL: ADMIN.email, XENOVA_ADMIN_PASSWORD: ADMIN.password },
      stdio: ['ignore', 'pipe', 'inherit']
    });
    proc.stdout.on('data', d => { if (String(d).includes('พร้อมใช้งาน')) resolve(); });
    proc.on('exit', c => reject(new Error('server exited ' + c)));
    setTimeout(() => reject(new Error('server start timeout')), 10000);
  });
}
const stopServer = () => new Promise(r => { proc.removeAllListeners('exit'); proc.on('exit', r); proc.kill(); });

async function call(method, url, { token, body } = {}) {
  const res = await fetch(BASE + url, {
    method,
    headers: { ...(token ? { Authorization: 'Bearer ' + token } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined
  });
  let data = null; try { data = await res.json(); } catch { /* not json */ }
  return { status: res.status, data, res };
}
const login = async (email, password) => (await call('POST', '/api/auth/login', { body: { email, password } }));

// tiny valid 1x1 PNG
const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';

before(startServer);
after(async () => { await stopServer(); fs.rmSync(DIR, { recursive: true, force: true }); });

test('static: only public files are served', async () => {
  for (const p of ['/', '/app.js', '/styles.css', '/translations.js']) assert.equal((await fetch(BASE + p)).status, 200, p);
  for (const p of ['/server.js', '/db.js', '/seed.json', '/members_data.json', '/package.json', '/manage.js', '/xenova.db', '/data/xenova.db']) {
    assert.equal((await fetch(BASE + p)).status, 404, p);
  }
  const trav = await fetch(BASE + '/uploads/..%2f..%2fserver.js');
  assert.equal(trav.status, 404);
});

test('api requires a session', async () => {
  assert.equal((await call('GET', '/api/bootstrap')).status, 401);
  assert.equal((await call('POST', '/api/collections/members/ops', { body: { upserts: [] } })).status, 401);
  assert.equal((await call('GET', '/api/bootstrap', { token: 'nope' })).status, 401);
});

test('login: wrong password rejected, right password works, lockout after 5 failures', async () => {
  assert.equal((await login(ADMIN.email, 'wrong')).status, 401);
  const ok = await login(ADMIN.email, ADMIN.password);
  assert.equal(ok.status, 200);
  assert.equal(ok.data.user.role, 'admin');
  for (let i = 0; i < 5; i++) await login('victim@test.dev', 'x');
  const locked = await login('victim@test.dev', 'x');
  assert.equal(locked.status, 429);
});

test('bootstrap returns seeded data from the database', async () => {
  const { data: { token } } = await login(ADMIN.email, ADMIN.password);
  const { status, data } = await call('GET', '/api/bootstrap', { token });
  assert.equal(status, 200);
  assert.equal(data.collections.members.length, 4);
  assert.ok(data.collections.meetings.length >= 3);
  assert.ok(data.collections.projects.length >= 1);
  assert.ok(data.collections.timetable.length >= 1);
  assert.ok(data.collections.members.every(m => m.photo === '' || m.photo.startsWith('/uploads/')), 'photos are files, not base64');
  const photo = data.collections.members.find(m => m.photo);
  if (photo) assert.equal((await fetch(BASE + photo.photo)).status, 200);
});

test('meetings: create, edit, reschedule, delete — and it survives a server restart', async () => {
  const { data: { token } } = await login(ADMIN.email, ADMIN.password);
  const m = { id: 'mt_test1', title: 'Sprint review', date: '2030-01-10', time: '10:00', duration: 45, location: 'Room A', description: 'x', attendeeIds: ['mem_aumim'] };
  assert.equal((await call('POST', '/api/collections/meetings/ops', { token, body: { upserts: [m] } })).status, 200);
  assert.equal((await call('POST', '/api/collections/meetings/ops', { token, body: { upserts: [{ ...m, date: '2030-01-12', title: 'Sprint review (moved)' }] } })).status, 200);

  await stopServer(); await startServer();
  const t2 = (await login(ADMIN.email, ADMIN.password)).data.token;
  const after = (await call('GET', '/api/bootstrap', { token: t2 })).data.collections.meetings.find(x => x.id === 'mt_test1');
  assert.equal(after.date, '2030-01-12');
  assert.equal(after.title, 'Sprint review (moved)');

  await call('POST', '/api/collections/meetings/ops', { token: t2, body: { deletes: ['mt_test1'] } });
  const gone = (await call('GET', '/api/bootstrap', { token: t2 })).data.collections.meetings.find(x => x.id === 'mt_test1');
  assert.equal(gone, undefined);
});

test('members: admin can add/edit/delete; photo upload becomes a file', async () => {
  const { data: { token } } = await login(ADMIN.email, ADMIN.password);
  const mem = { id: 'mem_new', name: 'New Person', position: 'Tester', bio: 'hi', responsibilities: ['a'], skills: ['b'], color: '#123456', photo: PNG };
  const r = await call('POST', '/api/collections/members/ops', { token, body: { upserts: [mem] } });
  assert.equal(r.status, 200);
  const saved = r.data.rows.find(x => x.id === 'mem_new');
  assert.match(saved.photo, /^\/uploads\/[a-f0-9]{32}\.png$/);
  assert.equal((await fetch(BASE + saved.photo)).headers.get('content-type'), 'image/png');
  assert.equal((await call('POST', '/api/collections/members/ops', { token, body: { deletes: ['mem_new'] } })).status, 200);
});

test('security: hostile photo/colour values are neutralised', async () => {
  const { data: { token } } = await login(ADMIN.email, ADMIN.password);
  const evil = { id: 'mem_evil', name: 'Evil', position: 'x', photo: 'x" onerror="alert(1)', color: 'red;background:url(//evil)' };
  const r = await call('POST', '/api/collections/members/ops', { token, body: { upserts: [evil] } });
  const row = r.data.rows.find(x => x.id === 'mem_evil');
  assert.equal(row.photo, '');
  assert.equal(row.color, '#1A73E8');
  const bad = await call('POST', '/api/collections/members/ops', { token, body: { upserts: [{ id: 'mem_bad', name: 'x', photo: 'data:image/png;base64,AAAA' }] } });
  assert.equal(bad.status, 400); // not a real image
  await call('POST', '/api/collections/members/ops', { token, body: { deletes: ['mem_evil'] } });
});

test('roles are enforced by the server, not the browser', async () => {
  const reg = await call('POST', '/api/auth/register', { body: { name: 'Mina', email: 'mina@test.dev', password: 'secret123' } });
  assert.equal(reg.status, 201);
  assert.equal(reg.data.user.role, 'member');
  const token = reg.data.token;

  const boot = (await call('GET', '/api/bootstrap', { token })).data;
  assert.ok(boot.collections.members.some(m => m.id === reg.data.user.id), 'registration creates a team profile');

  // own profile: ok
  const mine = boot.collections.members.find(m => m.id === reg.data.user.id);
  assert.equal((await call('POST', '/api/collections/members/ops', { token, body: { upserts: [{ ...mine, bio: 'my bio' }] } })).status, 200);
  // someone else's profile: forbidden
  const other = boot.collections.members.find(m => m.id === 'mem_aumim');
  assert.equal((await call('POST', '/api/collections/members/ops', { token, body: { upserts: [{ ...other, name: 'HACKED' }] } })).status, 403);
  // deleting a member: forbidden
  assert.equal((await call('POST', '/api/collections/members/ops', { token, body: { deletes: ['mem_aumim'] } })).status, 403);
  // creating a new member row: forbidden
  assert.equal((await call('POST', '/api/collections/members/ops', { token, body: { upserts: [{ id: 'mem_fake', name: 'Fake' }] } })).status, 403);
  // others' projects: forbidden; own: allowed
  const theirProject = boot.collections.projects[0];
  assert.equal((await call('POST', '/api/collections/projects/ops', { token, body: { upserts: [{ ...theirProject, title: 'stolen' }] } })).status, 403);
  assert.equal((await call('POST', '/api/collections/projects/ops', { token, body: { deletes: [theirProject.id] } })).status, 403);
  const own = { id: 'pr_mina', memberId: reg.data.user.id, title: 'Mine', desc: '', status: 'in_progress' };
  assert.equal((await call('POST', '/api/collections/projects/ops', { token, body: { upserts: [own] } })).status, 200);
  // a project claiming to belong to someone else: forbidden
  assert.equal((await call('POST', '/api/collections/projects/ops', { token, body: { upserts: [{ ...own, id: 'pr_x', memberId: 'mem_aumim' }] } })).status, 403);
  // members may schedule meetings
  assert.equal((await call('POST', '/api/collections/meetings/ops', { token, body: { upserts: [{ id: 'mt_mina', title: 'Mina sync', date: '2030-02-01', time: '09:00' }] } })).status, 200);

  // admin sees Mina's changes
  const at = (await login(ADMIN.email, ADMIN.password)).data.token;
  const adminView = (await call('GET', '/api/bootstrap', { token: at })).data.collections;
  assert.equal(adminView.members.find(m => m.id === reg.data.user.id).bio, 'my bio');
  assert.equal(adminView.members.find(m => m.id === 'mem_aumim').name, 'AUMIM');

  // duplicate e-mail
  assert.equal((await call('POST', '/api/auth/register', { body: { name: 'Mina2', email: 'MINA@test.dev', password: 'secret123' } })).status, 409);
  // password rules
  assert.equal((await call('POST', '/api/auth/register', { body: { name: 'S', email: 's@test.dev', password: '123' } })).status, 400);
});

test('theme settings are stored per user', async () => {
  const a = (await login(ADMIN.email, ADMIN.password)).data.token;
  const m = (await login('mina@test.dev', 'secret123')).data.token;
  await call('PUT', '/api/settings/theme', { token: a, body: { value: 'dark' } });
  await call('PUT', '/api/settings/brightness', { token: a, body: { value: 120 } });
  await call('PUT', '/api/settings/theme', { token: m, body: { value: 'pink' } });
  assert.equal((await call('PUT', '/api/settings/evil', { token: a, body: { value: 1 } })).status, 404);
  const sa = (await call('GET', '/api/bootstrap', { token: a })).data.settings;
  const sm = (await call('GET', '/api/bootstrap', { token: m })).data.settings;
  assert.equal(sa.theme, 'dark'); assert.equal(sa.brightness, 120);
  assert.equal(sm.theme, 'pink'); assert.equal(sm.brightness, undefined);
});

test('account: change name/password, logout invalidates the token', async () => {
  const s = (await login('mina@test.dev', 'secret123')).data.token;
  assert.equal((await call('POST', '/api/auth/password', { token: s, body: { oldPassword: 'bad', newPassword: 'newsecret1' } })).status, 403);
  assert.equal((await call('POST', '/api/auth/password', { token: s, body: { oldPassword: 'secret123', newPassword: 'newsecret1' } })).status, 200);
  assert.equal((await login('mina@test.dev', 'secret123')).status, 401);
  const s2 = (await login('mina@test.dev', 'newsecret1')).data.token;
  const me = await call('PATCH', '/api/me', { token: s2, body: { name: 'Mina R.' } });
  assert.equal(me.data.user.name, 'Mina R.');
  const members = (await call('GET', '/api/bootstrap', { token: s2 })).data.collections.members;
  assert.equal(members.find(x => x.id === me.data.user.id).name, 'Mina R.', 'team profile name follows account');
  await call('POST', '/api/auth/logout', { token: s2 });
  assert.equal((await call('GET', '/api/me', { token: s2 })).status, 401);
});

test('last admin cannot delete their own account; version counter moves on writes', async () => {
  const a = (await login(ADMIN.email, ADMIN.password)).data.token;
  assert.equal((await call('DELETE', '/api/me', { token: a })).status, 409);
  const v1 = (await call('GET', '/api/version', { token: a })).data.v;
  await call('POST', '/api/collections/activity/ops', { token: a, body: { upserts: [{ id: 'act1', message: 'hi', type: 'info', createdAt: new Date().toISOString() }] } });
  const v2 = (await call('GET', '/api/version', { token: a })).data.v;
  assert.ok(v2 > v1);
});


test('link vault: everyone can add, only admin can edit/delete, URLs are validated', async () => {
  const admin = (await login(ADMIN.email, ADMIN.password)).data.token;
  const reg = await call('POST', '/api/auth/register', { body: { name: 'Link User', email: 'linker@test.dev', password: 'secret123' } });
  const member = reg.data.token;
  const L = (over = {}) => ({ id: 'ln_' + Math.random().toString(16).slice(2, 10), title: 'Docs', url: 'https://example.com/a?b=1', note: 'n', ...over });

  // member adds a link; server stamps who/when (spoofing is ignored)
  const mine = L({ addedBy: 'u_admin', addedByName: 'Someone Else', createdAt: '1999-01-01T00:00:00Z' });
  const r = await call('POST', '/api/collections/links/ops', { token: member, body: { upserts: [mine] } });
  assert.equal(r.status, 200);
  const saved = r.data.rows.find(x => x.id === mine.id);
  assert.equal(saved.addedBy, reg.data.user.id);
  assert.equal(saved.addedByName, 'Link User');
  assert.notEqual(saved.createdAt, '1999-01-01T00:00:00Z');

  // everyone sees it
  const seen = (await call('GET', '/api/bootstrap', { token: admin })).data.collections.links;
  assert.ok(seen.some(x => x.id === mine.id));

  // bad URLs / missing title rejected
  for (const bad of ['javascript:alert(1)', 'ftp://x.org/f', 'not a url', '']) {
    assert.equal((await call('POST', '/api/collections/links/ops', { token: member, body: { upserts: [L({ url: bad })] } })).status, 400, bad);
  }
  assert.equal((await call('POST', '/api/collections/links/ops', { token: member, body: { upserts: [L({ title: '  ' })] } })).status, 400);

  // member cannot delete or edit (not even their own)
  assert.equal((await call('POST', '/api/collections/links/ops', { token: member, body: { deletes: [mine.id] } })).status, 403);
  assert.equal((await call('POST', '/api/collections/links/ops', { token: member, body: { upserts: [{ ...saved, title: 'changed' }] } })).status, 403);
  // anonymous cannot do anything
  assert.equal((await call('POST', '/api/collections/links/ops', { body: { upserts: [L()] } })).status, 401);

  // admin can delete
  assert.equal((await call('POST', '/api/collections/links/ops', { token: admin, body: { deletes: [mine.id] } })).status, 200);
  const after = (await call('GET', '/api/bootstrap', { token: admin })).data.collections.links;
  assert.ok(!after.some(x => x.id === mine.id));
});

test('link folders: nested, anyone can create, only admin can rename/move/delete, no cycles, depth limit', async () => {
  const admin = (await login(ADMIN.email, ADMIN.password)).data.token;
  const member = (await call('POST', '/api/auth/register', { body: { name: 'Folder User', email: 'folder@test.dev', password: 'secret123' } })).data.token;
  const F = (id, name, parentId = null) => ({ id, name, parentId });
  const ops = (token, body, coll = 'folders') => call('POST', `/api/collections/${coll}/ops`, { token, body });

  // member creates a folder, then a sub-folder inside it, then a sub-sub-folder
  assert.equal((await ops(member, { upserts: [F('fd_docs', 'เอกสาร')] })).status, 200);
  assert.equal((await ops(member, { upserts: [F('fd_design', 'ดีไซน์', 'fd_docs')] })).status, 200);
  const r = await ops(member, { upserts: [F('fd_ui', 'UI', 'fd_design')] });
  assert.equal(r.status, 200);
  const saved = r.data.rows.find(x => x.id === 'fd_ui');
  assert.equal(saved.parentId, 'fd_design');
  assert.ok(saved.addedBy && saved.createdAt, 'server stamps author');

  // a link can be filed inside a folder; unknown folder is rejected
  const link = { id: 'ln_f1', title: 'Figma', url: 'https://figma.com', folderId: 'fd_ui' };
  assert.equal((await ops(member, { upserts: [link] }, 'links')).status, 200);
  assert.equal((await ops(member, { upserts: [{ ...link, id: 'ln_f2', folderId: 'fd_nope' }] }, 'links')).status, 400);
  assert.equal((await ops(member, { upserts: [F('fd_x', 'X', 'fd_missing')] })).status, 400);
  assert.equal((await ops(member, { upserts: [F('fd_blank', '   ')] })).status, 400);

  // member cannot rename, move or delete
  assert.equal((await ops(member, { upserts: [F('fd_docs', 'renamed')] })).status, 403);
  assert.equal((await ops(member, { deletes: ['fd_docs'] })).status, 403);

  // admin: rename OK, cycle rejected, depth limit enforced
  assert.equal((await ops(admin, { upserts: [F('fd_docs', 'เอกสารทีม')] })).status, 200);
  assert.equal((await ops(admin, { upserts: [F('fd_docs', 'เอกสารทีม', 'fd_ui')] })).status, 400, 'moving a folder into its own child');
  assert.equal((await ops(admin, { upserts: [F('fd_self', 'Self', 'fd_self')] })).status, 400);
  let parent = 'fd_ui';
  for (let i = 4; i <= 6; i++) { assert.equal((await ops(admin, { upserts: [F('fd_d' + i, 'L' + i, parent)] })).status, 200, 'depth ' + i); parent = 'fd_d' + i; }
  assert.equal((await ops(admin, { upserts: [F('fd_d7', 'L7', parent)] })).status, 400, 'depth 7 rejected');

  // everyone sees the tree
  const tree = (await call('GET', '/api/bootstrap', { token: member })).data.collections.folders;
  assert.ok(tree.some(x => x.id === 'fd_docs' && x.name === 'เอกสารทีม'));

  // admin deletes
  assert.equal((await ops(admin, { deletes: ['fd_d6', 'fd_d5', 'fd_d4'] })).status, 200);
  assert.equal((await ops(admin, { deletes: ['fd_ui', 'fd_design', 'fd_docs'] })).status, 200);
});
