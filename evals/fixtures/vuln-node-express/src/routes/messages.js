const express = require('express');
const { db } = require('../db');
const { requireAuth } = require('../auth');

const router = express.Router();

router.get('/api/messages', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT id, body FROM messages WHERE owner_id = ?').all(req.user.id);
  res.json(rows);
});

router.get('/api/messages/:id', requireAuth, (req, res) => {
  const row = db.prepare('SELECT id, owner_id, body FROM messages WHERE id = ?').get(Number(req.params.id));
  if (!row) return res.status(404).json({ error: 'not found' });
  res.json(row);
});

module.exports = router;
