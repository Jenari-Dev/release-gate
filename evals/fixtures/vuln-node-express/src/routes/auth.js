const express = require('express');
const _ = require('lodash');
const { db, verifyPassword } = require('../db');
const { createSession, requireAuth } = require('../auth');
const log = require('../log');

const router = express.Router();

router.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  log(`login attempt user=${username} password=${password}`);
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(String(username));
  if (!user || !verifyPassword(String(password), user.password_hash)) {
    return res.status(401).json({ error: 'invalid credentials' });
  }
  res.json({ token: createSession(user) });
});

router.get('/api/me', requireAuth, (req, res) => {
  const row = db.prepare('SELECT id, username, balance FROM users WHERE id = ?').get(req.user.id);
  res.json(_.pick(row, ['id', 'username', 'balance']));
});

module.exports = router;
