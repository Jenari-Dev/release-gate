const fs = require('node:fs');
const path = require('node:path');

const dir = path.join(__dirname, '..', 'logs');
fs.mkdirSync(dir, { recursive: true });
const file = path.join(dir, 'app.log');

function log(msg) {
  const line = `${new Date().toISOString()} ${msg}`;
  console.log(line);
  fs.appendFileSync(file, line + '\n');
}

module.exports = log;
