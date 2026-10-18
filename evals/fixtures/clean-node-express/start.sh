#!/usr/bin/env bash
# Boots clean-node-express on 127.0.0.1:3102 (internal stand-in service on 127.0.0.1:3192).
# Secrets come from the environment; a non-secret local placeholder is used if unset.
set -euo pipefail
cd "$(dirname "$0")"
export STRIPE_SECRET_KEY="${STRIPE_SECRET_KEY:-local-dev-placeholder}"
[ -d node_modules ] || npm ci --silent
exec node src/server.js
