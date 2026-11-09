const express = require('express');
const crypto = require('node:crypto');
const path = require('node:path');
const db = require('./db');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  try {
    // VULN: A02 Cryptographic Failures
    const passwordHash = crypto.createHash('md5').update(password).digest('hex');
    const result = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(username, passwordHash);
    res.status(201).json({ id: result.lastInsertRowid, username });
  } catch { res.status(400).json({ error: 'Could not register user' }); }
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const hash = crypto.createHash('md5').update(password).digest('hex');
  const user = db.prepare('SELECT id FROM users WHERE username = ? AND password_hash = ?').get(username, hash);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  res.json({ userId: user.id });
});

// Training-only identity header keeps the vulnerable example small.
function userId(req, res, next) {
  req.userId = Number(req.get('x-user-id'));
  if (!req.userId) return res.status(401).json({ error: 'Send X-User-Id from the login response' });
  next();
}

app.get('/notes', userId, (req, res) => {
  res.json(db.prepare('SELECT id, owner_id, title, content FROM notes WHERE owner_id = ?').all(req.userId));
});
app.post('/notes', userId, (req, res) => {
  const { title, content } = req.body;
  const result = db.prepare('INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)').run(req.userId, title, content);
  res.status(201).json({ id: result.lastInsertRowid, owner_id: req.userId, title, content });
});
app.get('/notes/:id', userId, (req, res) => {
  // VULN: A01 Broken Access Control
  const note = db.prepare('SELECT id, owner_id, title, content FROM notes WHERE id = ?').get(req.params.id);
  if (!note) return res.status(404).json({ error: 'Note not found' });
  res.json(note);
});
app.delete('/notes/:id', userId, (req, res) => {
  // VULN: A01 Broken Access Control
  const result = db.prepare('DELETE FROM notes WHERE id = ?').run(req.params.id);
  res.status(result.changes ? 204 : 404).end();
});
app.get('/search', userId, (req, res) => {
  // VULN: A03 Injection
  const notes = db.prepare(`SELECT id, owner_id, title, content FROM notes WHERE owner_id = ${req.userId} AND title LIKE '%${req.query.q}%'`).all();
  res.json(notes);
});

module.exports = app;
