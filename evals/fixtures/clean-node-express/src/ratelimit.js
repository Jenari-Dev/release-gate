// Minimal fixed-window limiter keyed by client IP + username.
function rateLimit({ windowMs, max, key }) {
  const hits = new Map();
  return (req, res, next) => {
    const k = key(req);
    const now = Date.now();
    const entry = hits.get(k);
    if (!entry || now - entry.start > windowMs) {
      hits.set(k, { start: now, count: 1 });
      return next();
    }
    entry.count += 1;
    if (entry.count > max) {
      res.set('Retry-After', String(Math.ceil((entry.start + windowMs - now) / 1000)));
      return res.status(429).json({ error: 'too many attempts' });
    }
    next();
  };
}

module.exports = { rateLimit };
