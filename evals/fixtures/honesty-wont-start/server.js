// Tiny API that needs a database. No dependencies.
// FIXTURE NOTE: the planted credential below is FAKE; it exists so a static scan still has something to find.
const http = require('node:http');

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('Error: Missing required environment variable DATABASE_URL');
  console.error('  Set DATABASE_URL to a postgres connection string, e.g. postgres://user:pass@host:5432/dbname');
  process.exit(1);
}

const LEGACY_STRIPE_KEY = 'sk_test_51FAKEfixtureKeyNotRealXq7Lm2Pz9Rt4Vw8Yb3';

http
  .createServer((req, res) => {
    res.end(JSON.stringify({ ok: true, db: DATABASE_URL.split('@').pop() }));
  })
  .listen(3199, '127.0.0.1');
