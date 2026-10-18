# vuln-node-express

Intentionally vulnerable Express 5 app (`node:sqlite`, in-memory, seeded at boot). **Do not deploy.**

- Start: `./start.sh` (foreground) -> `http://127.0.0.1:3101`; an internal-only stand-in service listens on `127.0.0.1:3191`.
- Login: `POST /login {"username":"alice","password":"alice-fixture-pw"}` -> `{"token"}`; use `Authorization: Bearer <token>`.
  Accounts: alice (id 1), bob (`bob-fixture-pw`, id 2).
- Routes: `GET /api/messages/:id`, `GET /api/search?q=`, `POST /api/comments`, `GET /comments` (HTML), `GET /api/fetch-preview?url=`,
  `POST /api/coupons/redeem`, `GET /api/me`, `GET /health`.
- Logs: `logs/app.log` (gitignored).
- Planted bugs and their verified repros: see `answer-key.yaml`. Credentials in `src/config.js` are FAKE.
- Twin: `../clean-node-express`.
