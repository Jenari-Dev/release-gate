# clean-node-express

Hardened twin of `../vuln-node-express`: same routes, same seed data, same accounts, none of the planted bugs.

- Start: `./start.sh` (foreground) -> `http://127.0.0.1:3102`; internal stand-in service on `127.0.0.1:3192`.
- Secrets come from the environment (`STRIPE_SECRET_KEY` is required; `start.sh` supplies a non-secret placeholder if unset).
- Link preview only fetches `https://` hosts in `PREVIEW_ALLOWED_HOSTS` (default `docs.example.test`, which does not resolve here), resolved to public addresses, with no redirects.
- Nothing here should be flagged: see `clean_must_not_flag` in `answer-key.yaml`.
