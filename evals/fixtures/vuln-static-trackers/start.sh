#!/usr/bin/env bash
# Boots vuln-static-trackers: site on 127.0.0.1:3105, fake analytics vendor on 127.0.0.1:3155. Stdlib python only.
set -euo pipefail
cd "$(dirname "$0")"
exec python3 serve.py
