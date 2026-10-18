// Stand-in for an internal-only service (think cloud metadata endpoint) that the
// public app should never proxy to. Loopback-only; contains only fake data.
const http = require('node:http');

function startInternal(port) {
  const server = http.createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({
      service: 'internal-metadata',
      path: req.url,
      credentials: 'SSRF-CANARY-7f3a91c2-internal-only',
    }));
  });
  server.listen(port, '127.0.0.1');
  return server;
}

module.exports = { startInternal };
