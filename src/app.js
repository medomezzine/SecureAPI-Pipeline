const express = require('express');
const crypto = require('node:crypto');
const path = require('node:path');
const jwt = require('jsonwebtoken');
const { rateLimit } = require('express-rate-limit');
const db = require('./db');

if (!process.env.JWT_SECRET) throw new Error('Set JWT_SECRET in the environment');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));
const loginLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false });
function validCredentials(req, res, next) {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || !/^[\w-]{3,40}$/.test(username) ||
      typeof password !== 'string' || password.length < 8 || password.length > 128) {
    return res.status(400).json({ error: 'Invalid input' });
  }
  next();
}

app.post('/register', validCredentials, (req, res) => {
  const { username, password } = req.body;
  try {
    // VULN: A02 Cryptographic Failures
    const passwordHash = crypto.createHash('md5').update(password).digest('hex');
    const result = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(username, passwordHash);
    res.status(201).json({ id: result.lastInsertRowid, username });
  } catch { res.status(400).json({ error: 'Could not register user' }); }
});

app.post('/login', loginLimit, validCredentials, (req, res) => {
  const { username, password } = req.body;
  const hash = crypto.createHash('md5').update(password).digest('hex');
  const user = db.prepare('SELECT id FROM users WHERE username = ? AND password_hash = ?').get(username, hash);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  res.json({ token: jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' }) });
});

function userId(req, res, next) {
  try {
    const token = req.get('authorization')?.replace(/^Bearer\s+/i, '');
    req.userId = jwt.verify(token || '', process.env.JWT_SECRET).id;
  } catch { return res.status(401).json({ error: 'Authentication required' }); }
  next();
}

app.get('/notes', userId, (req, res) => {
  res.json(db.prepare('SELECT id, owner_id, title, content FROM notes WHERE owner_id = ?').all(req.userId));
});
app.post('/notes', userId, (req, res) => {
  const { title, content } = req.body;
  if (typeof title !== 'string' || !title.trim() || title.length > 120 || typeof content !== 'string' || content.length > 10000) {
    return res.status(400).json({ error: 'Invalid input' });
  }
  const result = db.prepare('INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)').run(req.userId, title, content);
  res.status(201).json({ id: result.lastInsertRowid, owner_id: req.userId, title, content });
});
app.get('/notes/:id', userId, (req, res) => {
  if (!/^[1-9]\d*$/.test(req.params.id)) return res.status(400).json({ error: 'Invalid note ID' });
  // VULN: A01 Broken Access Control
  const note = db.prepare('SELECT id, owner_id, title, content FROM notes WHERE id = ?').get(req.params.id);
  if (!note) return res.status(404).json({ error: 'Note not found' });
  res.json(note);
});
app.delete('/notes/:id', userId, (req, res) => {
  if (!/^[1-9]\d*$/.test(req.params.id)) return res.status(400).json({ error: 'Invalid note ID' });
  // VULN: A01 Broken Access Control
  const result = db.prepare('DELETE FROM notes WHERE id = ?').run(req.params.id);
  res.status(result.changes ? 204 : 404).end();
});
app.get('/search', userId, (req, res) => {
  if (typeof req.query.q !== 'string' || req.query.q.length > 100) return res.status(400).json({ error: 'Invalid search' });
  // VULN: A03 Injection
  const notes = db.prepare(`SELECT id, owner_id, title, content FROM notes WHERE owner_id = ${req.userId} AND title LIKE '%${req.query.q}%'`).all();
  res.json(notes);
});

module.exports = app;
