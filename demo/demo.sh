#!/usr/bin/env bash
# z402 demo: an agent tries to pay 5 sellers; z402 asks the z402 check API first.
# Real: the check API and its live lists, read-only, at $Z402_API_URL (default: the public API).
# Fake: the sellers run on this machine and the agent wallet is brand new, so no money moves anywhere.
# Needs: z402 installed with its test extra:
#   pip install -e "python[test]"
# No key is needed. Z402_API_KEY is optional (free key: https://zscreen.zeruai.org/app).
set -euo pipefail
cd "$(dirname "$0")"
PY="${PYTHON:-python3}"
exec "$PY" demo.py
