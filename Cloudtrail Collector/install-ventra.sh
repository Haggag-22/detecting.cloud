#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m venv .venv
./.venv/bin/pip install -e ".[dev]"
echo ""
echo "Installed. Use from anywhere in the parent repo:"
echo "  ../scripts/ventra collect cloudtrail --help"
echo "Or with venv active:"
echo "  source .venv/bin/activate && ventra collect cloudtrail --help"
