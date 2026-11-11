const express = require('express');
const path = require('node:path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const { z } = require('zod');
const crypto = require('node:crypto');
const db = require('./db');

if (!process.env.JWT_SECRET || !process.env.NOTES_ENCRYPTION_KEY) {
  throw new Error('Set JWT_SECRET and NOTES_ENCRYPTION_KEY in the environment');
}
const key = Buffer.from(process.env.NOTES_ENCRYPTION_KEY, 'hex');
if (key.length !== 32) throw new Error('NOTES_ENCRYPTION_KEY must be 64 hex characters');

const app = express();
app.use(helmet()); // Helmet sets a CSP; the page uses a separate same-origin script.
app.use(express.json({ limit: '20kb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));
const credentials = z.object({ username: z.string().min(3).max(40).regex(/^[\w-]+$/), password: z.string().min(8).max(128) });
const noteInput = z.object({ title: z.string().trim().min(1).max(120), content: z.string().max(10000) });
const loginLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false });

// AES-GCM authenticates each encrypted note and gives it a fresh random nonce.
function encrypt(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), data].map(part => part.toString('base64')).join('.');
}
function decrypt(value) {
  const [iv, tag, data] = value.split('.').map(part => Buffer.from(part, 'base64'));
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
}
function present(note) { return { ...note, content: decrypt(note.content) }; }
function protect(handler) {
  return (req, res, next) => {
    let user;
    try {
      const token = req.get('authorization')?.replace(/^Bearer\s+/i, '');
      user = jwt.verify(token || '', process.env.JWT_SECRET);
    } catch { return res.status(401).json({ error: 'Authentication required' }); }
    req.user = user;
    handler(req, res, next);
  };
}
function valid(schema, source = 'body') {
  return (req, res, next) => {
    const parsed = schema.safeParse(req[source]);
    if (!parsed.success) return res.status(400).json({ error: 'Invalid input' });
    if (source === 'query') req.validatedQuery = parsed.data;
    else req[source] = parsed.data;
    next();
  };
}

app.post('/register', valid(credentials), (req, res) => {
  try {
    const passwordHash = bcrypt.hashSync(req.body.password, 12);
    const result = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(req.body.username, passwordHash);
    res.status(201).json({ id: result.lastInsertRowid, username: req.body.username });
  } catch { res.status(409).json({ error: 'Username is unavailable' }); }
});
app.post('/login', loginLimit, valid(credentials), (req, res) => {
  const user = db.prepare('SELECT id, password_hash FROM users WHERE username = ?').get(req.body.username);
  if (!user || !bcrypt.compareSync(req.body.password, user.password_hash)) return res.status(401).json({ error: 'Invalid credentials' });
  res.json({ token: jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' }) });
});
const owned = (req, res) => db.prepare('SELECT id, owner_id, title, content FROM notes WHERE id = ? AND owner_id = ?').get(req.params.id, req.user.id);
app.get('/notes', protect((req, res) => {
  res.json(db.prepare('SELECT id, owner_id, title, content FROM notes WHERE owner_id = ?').all(req.user.id).map(present));
}));
app.post('/notes', valid(noteInput), protect((req, res) => {
  const result = db.prepare('INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)').run(req.user.id, req.body.title, encrypt(req.body.content));
  res.status(201).json({ id: result.lastInsertRowid, owner_id: req.user.id, title: req.body.title, content: req.body.content });
}));
app.get('/notes/:id', protect((req, res) => {
  const note = owned(req, res);
  if (!note) return res.status(404).json({ error: 'Note not found' });
  res.json(present(note));
}));
app.delete('/notes/:id', protect((req, res) => {
  const result = db.prepare('DELETE FROM notes WHERE id = ? AND owner_id = ?').run(req.params.id, req.user.id);
  res.status(result.changes ? 204 : 404).end();
}));
app.get('/search', valid(z.object({ q: z.string().max(100).default('') }), 'query'), protect((req, res) => {
  const rows = db.prepare("SELECT id, owner_id, title, content FROM notes WHERE owner_id = ? AND title LIKE ?")
    .all(req.user.id, `%${req.validatedQuery.q}%`).map(present);
  res.json(rows);
}));

module.exports = app;
