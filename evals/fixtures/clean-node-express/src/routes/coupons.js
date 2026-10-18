const express = require('express');
const { db } = require('../db');
const { requireAuth } = require('../auth');

const router = express.Router();

// stand-in for an async fraud/risk check (runs before, never inside, the transaction)
const riskCheck = () => new Promise((resolve) => setTimeout(resolve, 150));

router.post('/api/coupons/redeem', requireAuth, async (req, res) => {
  const code = String((req.body || {}).code || '');
  await riskCheck();

  db.exec('BEGIN IMMEDIATE');
  try {
    const claimed = db
      .prepare('UPDATE coupons SET uses = uses + 1 WHERE code = ? AND uses < max_uses')
      .run(code);
    if (claimed.changes === 0) {
      db.exec('ROLLBACK');
      return res.status(409).json({ error: 'coupon unavailable' });
    }
    db.prepare('INSERT INTO redemptions (user_id, code) VALUES (?, ?)').run(req.user.id, code);
    const coupon = db.prepare('SELECT amount FROM coupons WHERE code = ?').get(code);
    db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(coupon.amount, req.user.id);
    db.exec('COMMIT');
    res.json({ ok: true, credited: coupon.amount });
  } catch (e) {
    db.exec('ROLLBACK');
    res.status(409).json({ error: 'coupon unavailable' });
  }
});

module.exports = router;
