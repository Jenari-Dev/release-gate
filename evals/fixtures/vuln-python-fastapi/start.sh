#!/usr/bin/env bash
# Boots vuln-python-fastapi on 127.0.0.1:3103.
# Sidecars (same process): internal stand-in service 127.0.0.1:3193, fake analytics vendor 127.0.0.1:3163.
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -x .venv/bin/uvicorn ]; then
  uv venv -q --python 3.14 .venv
  uv pip install -q -p .venv -r requirements.txt
fi
exec .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 3103 --log-level warning
