const express = require('express');
const session = require('express-session');
const Stripe = require('stripe');
const { S3Client } = require('@aws-sdk/client-s3');
const analytics = require('./analytics');
const User = require('./models/user');

const app = express();
app.use(session({ secret: process.env.SESSION_SECRET, name: 'sid', cookie: { maxAge: 3600000 } }));

app.post('/signup', async (req, res) => {
  const { email, fullName, marketingOptIn } = req.body;
  const dob = req.body.dateOfBirth;
  console.log(`signup email=${email} ip=${req.ip}`);
  analytics.track('signup', { email, plan: req.body.plan });
  res.cookie('prefs', 'dark', { maxAge: 86400000 });
  await User.create({ email, fullName, dob });
  res.sendStatus(201);
});

app.delete('/account', async (req, res) => {
  await User.deleteOne({ _id: req.user.id });
  res.sendStatus(204);
});

module.exports = app;
