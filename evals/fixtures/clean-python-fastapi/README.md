# clean-python-fastapi

Hardened twin of `../vuln-python-fastapi`: same routes, same seed data, same accounts, none of the planted bugs.

- Start: `./start.sh` (foreground; creates `.venv` with uv on first run) -> `http://127.0.0.1:3104`.
  Sidecars: internal stand-in service `127.0.0.1:3194`, analytics observation sink `127.0.0.1:3164` (the app never sends it anything; `GET /_events` stays `[]`).
- Secrets come from the environment (`STRIPE_SECRET_KEY` required; `start.sh` supplies a non-secret placeholder if unset).
- Link preview only fetches `https://` hosts in `PREVIEW_ALLOWED_HOSTS` (default `docs.example.test`, which does not resolve here), resolved to public addresses, no redirects.
- Account deletion really deletes the user, messages and sessions.
- Nothing here should be flagged: see `clean_must_not_flag` in `answer-key.yaml`.
