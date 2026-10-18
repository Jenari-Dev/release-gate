const express = require('express');
const { db } = require('../db');

const router = express.Router();

router.get('/api/search', (req, res) => {
  const q = String(req.query.q || '').slice(0, 100);
  const escaped = q.replace(/[\\%_]/g, (c) => `\\${c}`);
  const rows = db
    .prepare("SELECT id, name, price FROM items WHERE name LIKE ? ESCAPE '\\'")
    .all(`%${escaped}%`);
  res.json(rows);
});

module.exports = router;
