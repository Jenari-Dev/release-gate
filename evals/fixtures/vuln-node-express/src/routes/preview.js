const express = require('express');
const { requireAuth } = require('../auth');

const router = express.Router();

// Fetch a URL server-side and return a short preview of it.
router.get('/api/fetch-preview', requireAuth, async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error: 'url required' });
  try {
    const r = await fetch(url);
    const text = await r.text();
    res.json({ status: r.status, preview: text.slice(0, 500) });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

module.exports = router;
