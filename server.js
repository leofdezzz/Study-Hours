const { DatabaseSync } = require('node:sqlite');
const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const path    = require('path');

const app        = express();
const JWT_SECRET = process.env.JWT_SECRET || 'sh_secret_cambia_esto_en_produccion';
const PORT       = process.env.PORT || 3000;
const DB_PATH    = process.env.DB_PATH    || path.join(__dirname, 'data.db');

/* ─── SQLite ─── */
const db = new DatabaseSync(DB_PATH);
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
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

/* ─── Middleware ─── */
app.use(express.json());
app.use(express.static(__dirname));

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'No autorizado' });
  try {
    req.user = jwt.verify(h.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

/* ─── Register ─── */
app.post('/api/auth/register', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)     return res.status(400).json({ error: 'Faltan campos' });
  if (username.trim().length < 3) return res.status(400).json({ error: 'El usuario debe tener al menos 3 caracteres' });
  if (password.length < 4)        return res.status(400).json({ error: 'La contraseña debe tener al menos 4 caracteres' });

  const key  = username.trim().toLowerCase();
  const id   = Date.now().toString();
  const hash = bcrypt.hashSync(password, 10);

  try {
    db.prepare('INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)').run(id, key, hash);
    db.prepare('INSERT INTO user_data (user_id) VALUES (?)').run(id);
    const token = jwt.sign({ id, username: key }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, username: key });
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: 'Ese usuario ya existe' });
    console.error(e);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

/* ─── Login ─── */
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Faltan campos' });

  const key  = username.trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(key);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  }
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username: user.username });
});

/* ─── Get data ─── */
app.get('/api/data', auth, (req, res) => {
  const row = db.prepare('SELECT subjects, logs FROM user_data WHERE user_id = ?').get(req.user.id);
  res.json({
    subjects: JSON.parse(row?.subjects || '[]'),
    logs:     JSON.parse(row?.logs     || '{}')
  });
});

/* ─── Save data ─── */
app.put('/api/data', auth, (req, res) => {
  const { subjects, logs } = req.body || {};
  if (!Array.isArray(subjects) || typeof logs !== 'object') {
    return res.status(400).json({ error: 'Estructura de datos inválida' });
  }
  db.prepare('UPDATE user_data SET subjects = ?, logs = ? WHERE user_id = ?')
    .run(JSON.stringify(subjects), JSON.stringify(logs), req.user.id);
  res.json({ ok: true });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\nStudy Hours en http://localhost:${PORT}`);
  console.log(`Red local: http://<tu-IP>:${PORT}\n`);
}).on('error', e => {
  if (e.code === 'EADDRINUSE') {
    console.error(`\nError: el puerto ${PORT} ya está en uso.`);
    console.error(`Cierra el proceso anterior o usa otro puerto: PORT=3001 npm start\n`);
  } else {
    console.error(e);
  }
  process.exit(1);
});
