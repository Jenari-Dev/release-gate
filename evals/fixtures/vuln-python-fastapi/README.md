# vuln-python-fastapi

Intentionally vulnerable FastAPI app (`sqlite3`, in-memory, seeded at boot). **Do not deploy.**

- Start: `./start.sh` (foreground; creates `.venv` with uv on first run) -> `http://127.0.0.1:3103`.
  Sidecars inside the same process: internal-only stand-in service `127.0.0.1:3193`, fake third-party analytics vendor `127.0.0.1:3163` (`GET /_events` shows what it received).
- Login: `POST /login` with form fields `username`, `password` -> `{"token"}`; use `Authorization: Bearer <token>`.
  Accounts: alice (`alice-fixture-pw`, id 1), bob (`bob-fixture-pw`, id 2). Signup: `POST /api/register {"username","password","email"}`.
- Routes: `GET /api/messages/{id}`, `GET /api/search?q=`, `GET /api/fetch-preview?url=`, `DELETE /api/account`, `GET /privacy`, `GET /health`.
- Logs: `logs/app.log` (gitignored).
- Dependencies: `requirements.in` (direct) / `requirements.txt` (full freeze). `python-multipart==0.0.6` is the planted vulnerable pin.
- Planted bugs and verified repros: see `answer-key.yaml`. Credentials in `app/config.py` are FAKE.
- Twin: `../clean-python-fastapi`.
