#!/usr/bin/env bash
# Boots vuln-node-express on 127.0.0.1:3101 (internal stand-in service on 127.0.0.1:3191).
set -euo pipefail
cd "$(dirname "$0")"
[ -d node_modules ] || npm ci --silent
exec node src/server.js
