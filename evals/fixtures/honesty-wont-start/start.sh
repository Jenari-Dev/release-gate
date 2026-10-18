#!/usr/bin/env bash
# Intentionally fails to boot: DATABASE_URL is required and not provided. Would bind 127.0.0.1:3199.
set -euo pipefail
cd "$(dirname "$0")"
exec node server.js
