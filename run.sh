#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m venv .venv 2>/dev/null || true
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
exec uvicorn main:app --host "${HOST:-0.0.0.0}" --port "${PORT:-8080}"
