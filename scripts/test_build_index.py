"""Registry trust-boundary checks for executable and non-executable entries."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import build_index


class RegistryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for dirname in ("skills", "mcp", "tools", "plugins", "scripts"):
            shutil.copytree(build_index.ROOT / dirname, self.root / dirname)
        self.root_patch = patch.object(build_index, "ROOT", self.root)
        self.skills_patch = patch.object(build_index, "SKILLS", self.root / "skills")
        self.root_patch.start()
        self.skills_patch.start()

    def tearDown(self):
        self.skills_patch.stop()
        self.root_patch.stop()
        self.temp.cleanup()

    def write_manifest(self, relative, change):
        path = self.root / relative
        data = json.loads(path.read_text())
        change(data)
        path.write_text(json.dumps(data))

    def test_public_tools_are_not_standalone_installs(self):
        index, categories = build_index.build()
        self.assertEqual(index["count"], 11)
        self.assertEqual({entry["type"] for entry in index["entries"]}, {"skill", "mcp", "tool", "plugin"})
        self.assertEqual(sum(entry["type"] == "skill" for entry in index["entries"]), 4)
        self.assertTrue(all(entry["installable"] for entry in index["entries"] if entry["type"] in {"mcp", "plugin"}))
        self.assertTrue(all(not entry["installable"] for entry in index["entries"] if entry["type"] == "tool"))
        self.assertEqual(sum(kind["count"] for kind in categories["types"]), 11)

    def test_runtime_dependency_cache_does_not_change_distribution_checksum(self):
        folder = self.root / 'skills/security/mithril-security-suite'
        before = build_index.package_checksum(folder)
        cache = folder / '.nbb/.cache/test-runtime'
        cache.mkdir(parents=True, exist_ok=True)
        (cache / 'dependency.jar').write_bytes(b'local cache')
        self.assertEqual(before, build_index.package_checksum(folder))

    def test_plugin_has_pinned_artifact_and_tested_client(self):
        index, _ = build_index.build()
        plugins = {entry["id"]: entry for entry in index["entries"] if entry["type"] == "plugin"}
        self.assertRegex(plugins["mithril-app"]["artifact"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(plugins["hermes-zap-proxy"]["artifact"]["commit"], r"^[0-9a-f]{40}$")
        self.assertEqual(plugins["hermes-zap-proxy"]["requirements"]["commands"], ["clojure"])
        self.assertEqual(plugins["hermes-zap-proxy"]["compatibility"]["clients"][0]["tested"], "0.21.4")

    def test_git_plugin_requires_full_commit(self):
        self.write_manifest(
            "plugins/hermes-zap-proxy/manifest.json",
            lambda data: data["artifact"].update(commit="main"),
        )
        with self.assertRaisesRegex(ValueError, "full lowercase Git commit"):
            build_index.build()

    def test_tool_catalog_binding_must_be_https(self):
        self.write_manifest("tools/knowledge-search/manifest.json", lambda data: data["catalog"].update(url="http://mithril.fund/.well-known/mcp.json"))
        with self.assertRaisesRegex(ValueError, "expected an HTTPS URL"):
            build_index.build()

    def test_no_entry_advertises_the_nonexistent_apex_mcp_endpoint(self):
        index, _ = build_index.build()
        self.assertNotIn("https://mithril.fund/mcp", json.dumps(index))
        self.assertFalse(any(entry["id"] == "mithril-cloud" for entry in index["entries"]))

    def test_tool_names_are_mithril_native(self):
        index, _ = build_index.build()
        text = json.dumps(
            [entry for entry in index["entries"] if entry["type"] == "tool"]
        ).lower()
        self.assertNotIn("kotoba", text)

    def test_mcp_endpoint_must_be_https(self):
        self.write_manifest("mcp/mithril-graph/manifest.json", lambda data: data.update(url="http://graph.mithril.fund/mcp"))
        with self.assertRaisesRegex(ValueError, "expected an HTTPS URL"):
            build_index.build()


if __name__ == "__main__":
    unittest.main()
