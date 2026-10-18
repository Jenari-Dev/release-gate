const express = require('express');
const { db } = require('../db');

const router = express.Router();

router.get('/api/search', (req, res) => {
  const q = req.query.q || '';
  try {
    const rows = db.prepare(`SELECT id, name, price FROM items WHERE name LIKE '%${q}%'`).all();
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
