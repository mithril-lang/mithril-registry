"""Behavior and Registry contract tests for agent-mediated catalog staging."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / "plugins/mithril-data-catalog/package/client.py"
SPEC = importlib.util.spec_from_file_location("mithril_catalog_client", CLIENT)
client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client)


class Response:
    def __init__(self, dataset): self.dataset = dataset
    def __enter__(self): return self
    def __exit__(self, *_args): return False
    def read(self, *_args):
        return json.dumps({"dataset": self.dataset, "state": "staged-for-iceberg", "batchId": "a" * 64}).encode()


class Opener:
    def __init__(self): self.request = None
    def open(self, request, timeout):
        self.request, self.timeout = request, timeout
        return Response(json.loads(request.data)["dataset"])


class DataCatalogTest(unittest.TestCase):
    def test_plugin_hashes_bounded_local_files_and_uses_only_canonical_api(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "actors.json").write_text('{"actors":[]}', encoding="utf-8")
            opener = Opener()
            result = json.loads(client.publish({
                "dataset": "actor", "root": str(root),
                "generated_at": "2026-10-07T00:00:00Z",
                "files": [{"path": "actors.json", "rows": 0}],
            }, "fixture-secret", opener=opener))
        self.assertEqual(opener.request.full_url, client.API_URL)
        self.assertEqual(opener.request.headers["Authorization"], "Bearer fixture-secret")
        payload = json.loads(opener.request.data)
        self.assertEqual(payload["files"][0]["sha256"],
                         "1925590408012373ea3cc6b9d02703527531492efb52aa39689d541a0581f840")
        self.assertEqual(result["state"], "staged-for-iceberg")

    def test_plugin_refuses_path_escape_and_missing_profile_secret(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            target = Path(outside) / "private.json"
            target.write_text("{}", encoding="utf-8")
            (root / "escape.json").symlink_to(target)
            with self.assertRaisesRegex(client.CatalogClientError, "outside root"):
                client.publish({"dataset": "actor", "root": str(root),
                                "files": [{"path": "escape.json"}]},
                               "fixture-secret", opener=Opener())
            with self.assertRaisesRegex(client.CatalogClientError, "not configured"):
                client.publish({"dataset": "actor", "root": str(root),
                                "files": [{"path": "escape.json"}]},
                               "", opener=Opener())

    def test_registry_artifacts_share_identity_and_never_advertise_cloudflare_access(self):
        mcp = json.loads((ROOT / "mcp/mithril-data-catalog/manifest.json").read_text())
        plugin = json.loads((ROOT / "plugins/mithril-data-catalog/manifest.json").read_text())
        skill = (ROOT / "skills/data/mithril-data-catalog/SKILL.md").read_text()
        package = (ROOT / "plugins/mithril-data-catalog/package/__init__.py").read_text()
        self.assertEqual(mcp["url"], "https://api.mithril.fund/v1/internal/data-catalog/mcp")
        self.assertEqual(mcp["tools"][0]["name"], "mithril_catalog_ingest_batch")
        self.assertEqual(plugin["tools"], ["mithril_catalog_publish"])
        self.assertIn("MITHRIL_CATALOG_API_TOKEN", package)
        combined = (json.dumps(mcp) + json.dumps(plugin) + skill).lower()
        self.assertNotIn("cloudflare_api_token", combined)
        self.assertNotIn("catalog.cloudflarestorage.com", combined)
        self.assertNotIn("mithril-api.cloud-kotoba.workers.dev", combined)


if __name__ == "__main__":
    unittest.main()
