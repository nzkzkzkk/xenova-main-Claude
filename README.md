# XENOVA — Group Management & Meeting Platform

Node.js + SQLite. Data lives in `data/xenova.db` (created on first run), uploaded photos in `data/uploads/`.

## Run
```bash
npm install          # recommended (installs better-sqlite3)
npm start            # http://localhost:8765
```
No `npm install`? On Node 22.5+ the server falls back to Node's built-in `node:sqlite`, so `node server.js` (or F5 in VS Code) still works. The console line `database driver:` shows which one is used.
First run creates sample data and **prints the admin e-mail + password once** in the console.
Pick your own instead:
```bash
XENOVA_ADMIN_EMAIL=you@example.com XENOVA_ADMIN_PASSWORD='your-password' npm start
```
(Windows PowerShell: `$env:XENOVA_ADMIN_EMAIL="..."; $env:XENOVA_ADMIN_PASSWORD="..."; npm start`)

| Env var | Default | Meaning |
|---|---|---|
| `PORT` | 8765 | port |
| `HOST` | 127.0.0.1 | use `0.0.0.0` to open from phone/other PCs on the same Wi-Fi |
| `XENOVA_ALLOW_SIGNUP` | on | set `0` to close public sign-up |
| `XENOVA_DATA_DIR` | ./data | where the DB + uploads live |

## Accounts (CLI)
```bash
node manage.js list-users
node manage.js set-password you@example.com NewPass123
node manage.js add-user aumim@xenova.dev AUMIM Pass1234 member mem_aumim   # link login to team profile
node manage.js make-admin someone@example.com
```
Roles are enforced on the server: admin can edit everything; a member can edit only their own profile and projects. **Link vault:** links live in nested folders ("ช่อง", up to 6 levels). Everyone can add links and create folders; only admins can edit, move or delete them.

## Test
```bash
npm test             # API tests on a throw-away database
```

## Files
`server.js` HTTP + API · `db.js` schema/auth/seed · `manage.js` admin CLI · `app.js` / `index.html` / `styles.css` / `translations.js` front-end · `seed.json` + `members_data.json` first-run sample data · `legacy/` old files kept for reference.
