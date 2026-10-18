const express = require('express');
const _ = require('lodash');
const { db, verifyPassword } = require('../db');
const { createSession, requireAuth } = require('../auth');
const { rateLimit } = require('../ratelimit');
const log = require('../log');

const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: 60_000,
  max: 5,
  key: (req) => `${req.ip}:${String((req.body || {}).username || '').toLowerCase()}`,
});

router.post('/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(String(username));
  if (!user || !verifyPassword(String(password), user.password_hash)) {
    log(`login failed user=${String(username).slice(0, 64)}`);
    return res.status(401).json({ error: 'invalid credentials' });
  }
  log(`login ok user=${user.username}`);
  res.json({ token: createSession(user) });
});

router.get('/api/me', requireAuth, (req, res) => {
  const row = db.prepare('SELECT id, username, balance FROM users WHERE id = ?').get(req.user.id);
  res.json(_.pick(row, ['id', 'username', 'balance']));
});

module.exports = router;
