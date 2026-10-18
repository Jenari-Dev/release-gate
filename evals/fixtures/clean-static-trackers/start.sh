#!/usr/bin/env bash
# Boots clean-static-trackers: site on 127.0.0.1:3106, fake analytics vendor on 127.0.0.1:3156. Stdlib python only.
set -euo pipefail
cd "$(dirname "$0")"
exec python3 serve.py
