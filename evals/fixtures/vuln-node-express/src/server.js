const express = require('express');
const config = require('./config');
const log = require('./log');
const { startInternal } = require('./internal');

const app = express();
app.use(express.json());

app.get('/health', (req, res) => res.json({ ok: true }));
app.use(require('./routes/auth'));
app.use(require('./routes/messages'));
app.use(require('./routes/search'));
app.use(require('./routes/comments'));
app.use(require('./routes/preview'));
app.use(require('./routes/coupons'));

startInternal(config.INTERNAL_PORT);
app.listen(config.PORT, config.HOST, () => {
  log(`vuln-node-express listening on http://${config.HOST}:${config.PORT}`);
});
