#!/usr/bin/env bash
# Boots clean-python-fastapi on 127.0.0.1:3104.
# Sidecars (same process): internal stand-in service 127.0.0.1:3194, analytics observation sink 127.0.0.1:3164
# (the app never sends the sink anything; it exists so evals can prove that).
# Secrets come from the environment; a non-secret local placeholder is used if unset.
set -euo pipefail
cd "$(dirname "$0")"
export STRIPE_SECRET_KEY="${STRIPE_SECRET_KEY:-local-dev-placeholder}"
if [ ! -x .venv/bin/uvicorn ]; then
  uv venv -q --python 3.14 .venv
  uv pip install -q -p .venv -r requirements.txt
fi
exec .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 3104 --log-level warning
