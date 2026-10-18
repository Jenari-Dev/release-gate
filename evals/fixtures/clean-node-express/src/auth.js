const crypto = require('node:crypto');

// token -> user row
const sessions = new Map();

function createSession(user) {
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, { id: user.id, username: user.username });
  return token;
}

function requireAuth(req, res, next) {
  const m = /^Bearer (.+)$/.exec(req.get('authorization') || '');
  const user = m && sessions.get(m[1]);
  if (!user) return res.status(401).json({ error: 'unauthenticated' });
  req.user = user;
  next();
}

module.exports = { createSession, requireAuth };
