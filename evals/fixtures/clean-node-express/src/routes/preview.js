const express = require('express');
const dns = require('node:dns').promises;
const net = require('node:net');
const config = require('../config');
const { requireAuth } = require('../auth');

const router = express.Router();

function isPrivateIp(ip) {
  if (net.isIPv6(ip)) {
    const v = ip.toLowerCase();
    return v === '::1' || v === '::' || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80') || v.startsWith('::ffff:');
  }
  const [a, b] = ip.split('.').map(Number);
  return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a >= 224;
}

// Fetch a URL server-side and return a short preview of it.
// Only https URLs on an explicit hostname allowlist, never private addresses.
router.get('/api/fetch-preview', requireAuth, async (req, res) => {
  let u;
  try {
    u = new URL(String(req.query.url || ''));
  } catch {
    return res.status(400).json({ error: 'invalid url' });
  }
  if (u.protocol !== 'https:' || !config.PREVIEW_ALLOWED_HOSTS.includes(u.hostname.toLowerCase())) {
    return res.status(403).json({ error: 'host not allowed' });
  }
  try {
    const addrs = await dns.lookup(u.hostname, { all: true });
    if (addrs.length === 0 || addrs.some((a) => isPrivateIp(a.address))) {
      return res.status(403).json({ error: 'host not allowed' });
    }
    const r = await fetch(u, { redirect: 'error', signal: AbortSignal.timeout(3000) });
    const text = await r.text();
    res.json({ status: r.status, preview: text.slice(0, 500) });
  } catch {
    res.status(502).json({ error: 'fetch failed' });
  }
});

module.exports = router;
