const { DatabaseSync } = require('node:sqlite');
const express  = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const path     = require('path');
const fs       = require('fs');
const webpush  = require('web-push');

const app        = express();
const JWT_SECRET = process.env.JWT_SECRET || 'sh_secret_cambia_esto_en_produccion';
const PORT       = process.env.PORT || 3000;
const DB_PATH    = process.env.DB_PATH || path.join(__dirname, 'data.db');

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

/* ─── SQLite ─── */
let db;
try {
  db = new DatabaseSync(DB_PATH);
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id            TEXT PRIMARY KEY,
      username      TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS user_data (
      user_id  TEXT PRIMARY KEY,
      subjects TEXT NOT NULL DEFAULT '[]',
      logs     TEXT NOT NULL DEFAULT '{}',
      settings TEXT NOT NULL DEFAULT '{}',
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS groups (
      id         TEXT PRIMARY KEY,
      name       TEXT NOT NULL,
      code       TEXT UNIQUE NOT NULL,
      created_by TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS group_members (
      group_id  TEXT NOT NULL,
      user_id   TEXT NOT NULL,
      PRIMARY KEY (group_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS config (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS push_subscriptions (
      id           TEXT PRIMARY KEY,
      user_id      TEXT NOT NULL,
      subscription TEXT NOT NULL,
      UNIQUE(user_id, subscription)
    );
    CREATE TABLE IF NOT EXISTS reactions (
      group_id     TEXT NOT NULL,
      from_user_id TEXT NOT NULL,
      to_user_id   TEXT NOT NULL,
      emoji        TEXT NOT NULL,
      week_key     TEXT NOT NULL,
      PRIMARY KEY (group_id, from_user_id, to_user_id, emoji, week_key)
    );
  `);
  // Migración: añadir columna settings a tablas existentes
  try { db.exec("ALTER TABLE user_data ADD COLUMN settings TEXT NOT NULL DEFAULT '{}'"); } catch {}
  console.log(`DB: ${DB_PATH}`);
} catch (e) {
  console.error('Error abriendo la base de datos:', e.message);
  process.exit(1);
}

/* ─── VAPID (claves persistentes en DB) ─── */
let VAPID_PUBLIC_KEY = null;
try {
  const stored = db.prepare("SELECT value FROM config WHERE key='vapid_keys'").get();
  let keys;
  if (stored) {
    keys = JSON.parse(stored.value);
  } else {
    keys = webpush.generateVAPIDKeys();
    db.prepare("INSERT INTO config (key,value) VALUES ('vapid_keys',?)").run(JSON.stringify(keys));
    console.log('Nuevas claves VAPID generadas y guardadas');
  }
  VAPID_PUBLIC_KEY = keys.publicKey;
  webpush.setVapidDetails(
    `mailto:${process.env.VAPID_EMAIL || 'admin@studyhours.app'}`,
    keys.publicKey,
    keys.privateKey
  );
} catch (e) {
  console.error('Error VAPID:', e.message);
}

/* ─── Helpers ─── */
function fmtDate(d) {
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
}
function fmtHours(h) {
  if (h === 0) return '0h';
  const hr = Math.floor(h), mn = Math.round((h - hr) * 60);
  if (mn === 60) return `${hr+1}h`;
  if (hr === 0)  return `${mn}m`;
  if (mn === 0)  return `${hr}h`;
  return `${hr}h ${mn}m`;
}
function currentWeekKeys() {
  const t = new Date(), dow = (t.getDay()+6)%7;
  const mon = new Date(t);
  mon.setDate(t.getDate() - dow);
  return Array.from({length:7}, (_,i) => {
    const d = new Date(mon);
    d.setDate(mon.getDate()+i);
    return fmtDate(d);
  });
}
function computeStats(logsJson, subjectsJson) {
  const logs     = JSON.parse(logsJson     || '{}');
  const subjects = JSON.parse(subjectsJson || '[]');
  const today    = fmtDate(new Date());
  const wKeys    = currentWeekKeys();
  const sum      = obj => Object.values(obj||{}).reduce((s,v)=>s+v, 0);

  const bySubject = {};
  subjects.forEach(sub => {
    const key = sub.name.trim().toLowerCase();
    bySubject[key] = {
      name:  sub.name,
      today: (logs[today]||{})[sub.id] || 0,
      week:  wKeys.reduce((s,k) => s + ((logs[k]||{})[sub.id]||0), 0),
      total: Object.values(logs).reduce((s,d) => s + (d[sub.id]||0), 0)
    };
  });

  return {
    today: sum(logs[today]),
    week:  wKeys.reduce((s,k) => s + sum(logs[k]), 0),
    total: Object.values(logs).reduce((s,d) => s + sum(d), 0),
    bySubject
  };
}
function generateCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code;
  do { code = Array.from({length:6}, () => chars[Math.floor(Math.random()*chars.length)]).join(''); }
  while (db.prepare('SELECT 1 FROM groups WHERE code=?').get(code));
  return code;
}

const VALID_EMOJIS = ['🔥','💀','😤','👑'];

/* ─── Middleware ─── */
app.use(express.json());
app.use(express.static(__dirname));

app.get('/health', (_req, res) => res.json({ ok: true }));

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'No autorizado' });
  try { req.user = jwt.verify(h.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Token inválido o expirado' }); }
}

/* ─── Auth ─── */
app.post('/api/auth/register', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)     return res.status(400).json({ error: 'Faltan campos' });
  if (username.trim().length < 3) return res.status(400).json({ error: 'El usuario debe tener al menos 3 caracteres' });
  if (password.length < 4)        return res.status(400).json({ error: 'La contraseña debe tener al menos 4 caracteres' });
  const key = username.trim().toLowerCase(), id = Date.now().toString();
  const hash = bcrypt.hashSync(password, 10);
  try {
    db.prepare('INSERT INTO users (id,username,password_hash) VALUES (?,?,?)').run(id, key, hash);
    db.prepare('INSERT INTO user_data (user_id) VALUES (?)').run(id);
    res.json({ token: jwt.sign({id,username:key}, JWT_SECRET, {expiresIn:'30d'}), username: key });
  } catch (e) {
    if (e.message?.includes('UNIQUE constraint failed')) return res.status(409).json({ error: 'Ese usuario ya existe' });
    console.error('Register error:', e.message);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Faltan campos' });
  const key  = username.trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE username=?').get(key);
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  res.json({ token: jwt.sign({id:user.id,username:user.username}, JWT_SECRET, {expiresIn:'30d'}), username: user.username });
});

/* ─── Study data ─── */
app.get('/api/data', auth, (req, res) => {
  const row = db.prepare('SELECT subjects,logs FROM user_data WHERE user_id=?').get(req.user.id);
  res.json({ subjects: JSON.parse(row?.subjects||'[]'), logs: JSON.parse(row?.logs||'{}') });
});

app.put('/api/data', auth, (req, res) => {
  const { subjects, logs } = req.body || {};
  if (!Array.isArray(subjects) || typeof logs !== 'object')
    return res.status(400).json({ error: 'Datos inválidos' });
  db.prepare('UPDATE user_data SET subjects=?,logs=? WHERE user_id=?')
    .run(JSON.stringify(subjects), JSON.stringify(logs), req.user.id);
  res.json({ ok: true });
});

/* ─── Settings ─── */
app.get('/api/settings', auth, (req, res) => {
  const row = db.prepare('SELECT settings FROM user_data WHERE user_id=?').get(req.user.id);
  res.json(JSON.parse(row?.settings || '{}'));
});

app.put('/api/settings', auth, (req, res) => {
  if (typeof req.body !== 'object' || Array.isArray(req.body))
    return res.status(400).json({ error: 'Datos inválidos' });
  db.prepare('UPDATE user_data SET settings=? WHERE user_id=?')
    .run(JSON.stringify(req.body), req.user.id);
  res.json({ ok: true });
});

/* ─── Push notifications ─── */
app.get('/api/push/key', (_req, res) => {
  if (!VAPID_PUBLIC_KEY) return res.status(503).json({ error: 'Push no disponible' });
  res.json({ publicKey: VAPID_PUBLIC_KEY });
});

app.post('/api/push/subscribe', auth, (req, res) => {
  const { subscription } = req.body || {};
  if (!subscription) return res.status(400).json({ error: 'Falta subscription' });
  const id  = Date.now().toString();
  const str = JSON.stringify(subscription);
  try {
    db.prepare('INSERT OR REPLACE INTO push_subscriptions (id,user_id,subscription) VALUES (?,?,?)')
      .run(id, req.user.id, str);
  } catch {}
  res.json({ ok: true });
});

app.delete('/api/push/subscribe', auth, (req, res) => {
  db.prepare('DELETE FROM push_subscriptions WHERE user_id=?').run(req.user.id);
  res.json({ ok: true });
});

/* ─── Groups ─── */
app.get('/api/groups', auth, (req, res) => {
  const groups = db.prepare(`
    SELECT g.id, g.name, g.code,
      (SELECT COUNT(*) FROM group_members WHERE group_id=g.id) as members
    FROM groups g
    JOIN group_members gm ON g.id=gm.group_id AND gm.user_id=?
  `).all(req.user.id);
  res.json(groups);
});

app.post('/api/groups', auth, (req, res) => {
  const { name } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error: 'Nombre requerido' });
  const id = Date.now().toString(), code = generateCode();
  db.prepare('INSERT INTO groups (id,name,code,created_by) VALUES (?,?,?,?)').run(id, name.trim(), code, req.user.id);
  db.prepare('INSERT INTO group_members (group_id,user_id) VALUES (?,?)').run(id, req.user.id);
  res.json({ id, name: name.trim(), code });
});

app.post('/api/groups/join', auth, (req, res) => {
  const { code } = req.body || {};
  if (!code) return res.status(400).json({ error: 'Código requerido' });
  const group = db.prepare('SELECT * FROM groups WHERE code=?').get(code.trim().toUpperCase());
  if (!group) return res.status(404).json({ error: 'Código inválido o grupo no encontrado' });
  if (db.prepare('SELECT 1 FROM group_members WHERE group_id=? AND user_id=?').get(group.id, req.user.id))
    return res.status(409).json({ error: 'Ya eres miembro de este grupo' });
  db.prepare('INSERT INTO group_members (group_id,user_id) VALUES (?,?)').run(group.id, req.user.id);
  res.json({ id: group.id, name: group.name, code: group.code });
});

app.get('/api/groups/:id/leaderboard', auth, (req, res) => {
  if (!db.prepare('SELECT 1 FROM group_members WHERE group_id=? AND user_id=?').get(req.params.id, req.user.id))
    return res.status(403).json({ error: 'No eres miembro de este grupo' });
  const group = db.prepare('SELECT name,code FROM groups WHERE id=?').get(req.params.id);
  if (!group) return res.status(404).json({ error: 'Grupo no encontrado' });

  const members = db.prepare(`
    SELECT u.id, u.username, COALESCE(ud.logs,'{}') as logs, COALESCE(ud.subjects,'[]') as subjects
    FROM users u
    JOIN group_members gm ON u.id=gm.user_id AND gm.group_id=?
    LEFT JOIN user_data ud ON u.id=ud.user_id
  `).all(req.params.id);

  const weekKey     = currentWeekKeys()[0];
  const allReactions = db.prepare(
    'SELECT from_user_id, to_user_id, emoji FROM reactions WHERE group_id=? AND week_key=?'
  ).all(req.params.id, weekKey);

  const board = members.map(m => {
    const received = {};
    VALID_EMOJIS.forEach(e => { received[e] = { count: 0, iMine: false }; });
    allReactions.filter(r => r.to_user_id === m.id).forEach(r => {
      if (received[r.emoji]) {
        received[r.emoji].count++;
        if (r.from_user_id === req.user.id) received[r.emoji].iMine = true;
      }
    });
    return {
      id: m.id,
      username: m.username,
      isMe: m.id === req.user.id,
      reactions: received,
      ...computeStats(m.logs, m.subjects)
    };
  });

  res.json({ group, board });
});

app.delete('/api/groups/:id/leave', auth, (req, res) => {
  db.prepare('DELETE FROM group_members WHERE group_id=? AND user_id=?').run(req.params.id, req.user.id);
  const { n } = db.prepare('SELECT COUNT(*) as n FROM group_members WHERE group_id=?').get(req.params.id);
  if (n === 0) db.prepare('DELETE FROM groups WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

/* ─── Reactions ─── */
app.post('/api/groups/:id/reactions', auth, (req, res) => {
  const { toUserId, emoji } = req.body || {};
  if (!toUserId || !VALID_EMOJIS.includes(emoji))
    return res.status(400).json({ error: 'Datos inválidos' });
  if (toUserId === req.user.id)
    return res.status(400).json({ error: 'No puedes reaccionar a ti mismo' });
  if (!db.prepare('SELECT 1 FROM group_members WHERE group_id=? AND user_id=?').get(req.params.id, req.user.id))
    return res.status(403).json({ error: 'No eres miembro' });

  const weekKey  = currentWeekKeys()[0];
  const existing = db.prepare(
    'SELECT 1 FROM reactions WHERE group_id=? AND from_user_id=? AND to_user_id=? AND emoji=? AND week_key=?'
  ).get(req.params.id, req.user.id, toUserId, emoji, weekKey);

  if (existing) {
    db.prepare('DELETE FROM reactions WHERE group_id=? AND from_user_id=? AND to_user_id=? AND emoji=? AND week_key=?')
      .run(req.params.id, req.user.id, toUserId, emoji, weekKey);
    res.json({ active: false });
  } else {
    db.prepare('INSERT INTO reactions (group_id,from_user_id,to_user_id,emoji,week_key) VALUES (?,?,?,?,?)')
      .run(req.params.id, req.user.id, toUserId, emoji, weekKey);
    res.json({ active: true });
  }
});

/* ─── Notificaciones semanales (domingo 20:00 UTC ≈ 21h España) ─── */
async function sendWeeklyNotifications() {
  const wk  = currentWeekKeys()[0];
  const key = `weekly_notif_${wk}`;
  if (db.prepare('SELECT 1 FROM config WHERE key=?').get(key)) return;
  db.prepare('INSERT OR REPLACE INTO config (key,value) VALUES (?,?)').run(key, '1');

  const allGroups = db.prepare('SELECT id FROM groups').all();
  for (const g of allGroups) {
    const members = db.prepare(`
      SELECT u.id, u.username, COALESCE(ud.logs,'{}') as logs, COALESCE(ud.subjects,'[]') as subjects
      FROM users u
      JOIN group_members gm ON u.id=gm.user_id AND gm.group_id=?
      LEFT JOIN user_data ud ON u.id=ud.user_id
    `).all(g.id);

    if (members.length < 2) continue;

    const board = members
      .map(m => ({ id: m.id, username: m.username, week: computeStats(m.logs, m.subjects).week }))
      .sort((a, b) => b.week - a.week);

    const leader = board[0];

    for (let rank = 0; rank < board.length; rank++) {
      const member = board[rank];
      const subs   = db.prepare('SELECT id, subscription FROM push_subscriptions WHERE user_id=?').all(member.id);
      if (!subs.length) continue;

      const isWinner = rank === 0 && leader.week > 0;
      const title = isWinner ? '🏆 ¡Ganaste la semana!' : '📊 Resumen semanal';
      const body  = isWinner
        ? `Estudiaste más que todos con ${fmtHours(leader.week)}. ¡A por la siguiente!`
        : `${leader.username} ganó con ${fmtHours(leader.week)}. Tú: ${fmtHours(member.week)}. ¡A por la próxima!`;

      const payload = JSON.stringify({ title, body });
      for (const sub of subs) {
        try {
          await webpush.sendNotification(JSON.parse(sub.subscription), payload);
        } catch (err) {
          if (err.statusCode === 410 || err.statusCode === 404) {
            db.prepare('DELETE FROM push_subscriptions WHERE id=?').run(sub.id);
          }
        }
      }
    }
  }
  console.log('Notificaciones semanales enviadas');
}

// Comprueba cada minuto; dispara el domingo a las 20:00 UTC
setInterval(() => {
  const now = new Date();
  if (now.getUTCDay() === 0 && now.getUTCHours() === 20 && now.getUTCMinutes() < 2) {
    sendWeeklyNotifications().catch(console.error);
  }
}, 60 * 1000);

/* ─── Error handling ─── */
process.on('uncaughtException', e => { console.error('Error no capturado:', e.message); process.exit(1); });

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Study Hours en http://localhost:${PORT}`);
}).on('error', e => {
  console.error(e.code === 'EADDRINUSE' ? `Puerto ${PORT} en uso.` : e);
  process.exit(1);
});
