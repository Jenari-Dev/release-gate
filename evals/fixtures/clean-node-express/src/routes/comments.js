const express = require('express');
const { db } = require('../db');
const { requireAuth } = require('../auth');

const router = express.Router();

const escapeHtml = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

router.post('/api/comments', requireAuth, (req, res) => {
  const body = String((req.body || {}).body || '').slice(0, 2000);
  db.prepare('INSERT INTO comments (author, body) VALUES (?, ?)').run(req.user.username, body);
  res.status(201).json({ ok: true });
});

router.get('/comments', (req, res) => {
  const rows = db.prepare('SELECT author, body FROM comments ORDER BY id').all();
  const items = rows.map((c) => `<li><b>${escapeHtml(c.author)}</b>: ${escapeHtml(c.body)}</li>`).join('\n');
  res.set('Content-Security-Policy', "default-src 'none'; style-src 'self'");
  res.set('X-Content-Type-Options', 'nosniff');
  res.type('html').send(`<!doctype html><html><head><title>Comments</title></head><body><h1>Comments</h1><ul>${items}</ul></body></html>`);
});

module.exports = router;
