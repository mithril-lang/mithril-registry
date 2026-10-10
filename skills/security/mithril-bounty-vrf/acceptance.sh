#!/usr/bin/env bash
# mithril-bounty-vrf acceptance (no live sources; synthetic fixtures).
set -euo pipefail
cd "$(dirname "$0")"
python3 -W ignore -m unittest discover -s tests -p 'test_*.py'
python3 -m py_compile scripts/google_sheets_sync.py scripts/bounty_vrf_tick.py
echo "ACCEPTANCE OK mithril-bounty-vrf"
