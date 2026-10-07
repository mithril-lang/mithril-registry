"""Run the bundled stdio integration's behavior checks in Registry CI."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    'brand_bridge_tests',
    Path(__file__).resolve().parents[1] / 'skills/security/mithril-brand-protection/scripts/test_brand.py',
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
BridgeTest = module.BridgeTest
