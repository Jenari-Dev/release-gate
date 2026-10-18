const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');

// In-memory database, re-seeded on every boot so runs are deterministic.
const db = new DatabaseSync(':memory:');

function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(pw, salt, 32);
  return `${salt.toString('hex')}:${hash.toString('hex')}`;
}

function verifyPassword(pw, stored) {
  const [saltHex, hashHex] = stored.split(':');
  const hash = crypto.scryptSync(pw, Buffer.from(saltHex, 'hex'), 32);
  return crypto.timingSafeEqual(hash, Buffer.from(hashHex, 'hex'));
}

db.exec(`
  CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, balance INTEGER DEFAULT 0);
  CREATE TABLE messages (id INTEGER PRIMARY KEY, owner_id INTEGER, body TEXT);
  CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, price INTEGER);
  CREATE TABLE comments (id INTEGER PRIMARY KEY, author TEXT, body TEXT);
  CREATE TABLE coupons (code TEXT PRIMARY KEY, amount INTEGER, max_uses INTEGER, uses INTEGER DEFAULT 0);
  CREATE TABLE redemptions (user_id INTEGER, code TEXT, UNIQUE(user_id, code));
`);

// Fixture-only test accounts (local, throwaway).
const insUser = db.prepare('INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)');
insUser.run(1, 'alice', hashPassword('alice-fixture-pw'));
insUser.run(2, 'bob', hashPassword('bob-fixture-pw'));

const insMsg = db.prepare('INSERT INTO messages (id, owner_id, body) VALUES (?, ?, ?)');
insMsg.run(1, 1, 'Hi Alice, your order shipped. ALICE-PRIVATE-CANARY-1a2b');
insMsg.run(2, 2, 'Bob here: my SSN is not 000-00-0000. BOB-PRIVATE-CANARY-9z8y');

const insItem = db.prepare('INSERT INTO items (id, name, price) VALUES (?, ?, ?)');
insItem.run(1, 'Widget', 500);
insItem.run(2, 'Gadget', 1200);
insItem.run(3, 'Gizmo', 800);

db.prepare('INSERT INTO comments (author, body) VALUES (?, ?)').run('alice', 'Great widgets!');
db.prepare('INSERT INTO coupons (code, amount, max_uses) VALUES (?, ?, ?)').run('WELCOME10', 10, 1);

module.exports = { db, verifyPassword };
