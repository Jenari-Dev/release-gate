const express = require('express');
const { db } = require('../db');
const { requireAuth } = require('../auth');

const router = express.Router();

// stand-in for an async fraud/risk check
const riskCheck = () => new Promise((resolve) => setTimeout(resolve, 150));

router.post('/api/coupons/redeem', requireAuth, async (req, res) => {
  const code = String((req.body || {}).code || '');
  const coupon = db.prepare('SELECT * FROM coupons WHERE code = ?').get(code);
  if (!coupon) return res.status(404).json({ error: 'unknown coupon' });
  if (coupon.uses >= coupon.max_uses) return res.status(409).json({ error: 'coupon exhausted' });

  await riskCheck();

  db.prepare('UPDATE coupons SET uses = uses + 1 WHERE code = ?').run(code);
  db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(coupon.amount, req.user.id);
  res.json({ ok: true, credited: coupon.amount });
});

module.exports = router;
