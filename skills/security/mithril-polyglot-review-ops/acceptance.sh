#!/usr/bin/env bash
# mithril-polyglot-review-ops acceptance (no live sources; synthetic fixtures).
set -euo pipefail
cd "$(dirname "$0")"
python3 -W ignore -m unittest discover -s tests -p 'test_*.py'
python3 -m py_compile scripts/polyglot_review_tick.py
node --check ../../bin/mithril-polyglot-review-ops.mjs
echo "ACCEPTANCE OK mithril-polyglot-review-ops"
