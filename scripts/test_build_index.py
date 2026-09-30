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
        for dirname in ("skills", "mcp", "tools", "plugins"):
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
        self.assertEqual(index["count"], 7)
        self.assertEqual({entry["type"] for entry in index["entries"]}, {"skill", "mcp", "tool", "plugin"})
        self.assertEqual(sum(entry["type"] == "skill" for entry in index["entries"]), 2)
        self.assertTrue(all(entry["installable"] for entry in index["entries"] if entry["type"] in {"mcp", "plugin"}))
        self.assertTrue(all(not entry["installable"] for entry in index["entries"] if entry["type"] == "tool"))
        self.assertEqual(sum(kind["count"] for kind in categories["types"]), 7)

    def test_plugin_has_pinned_artifact_and_tested_client(self):
        index, _ = build_index.build()
        plugin = next(entry for entry in index["entries"] if entry["type"] == "plugin")
        self.assertRegex(plugin["artifact"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(plugin["compatibility"]["clients"][0]["tested"], "0.21.4")

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
        text = json.dumps(index).lower()
        self.assertNotIn("kotoba", text)

    def test_mcp_endpoint_must_be_https(self):
        self.write_manifest("mcp/mithril-graph/manifest.json", lambda data: data.update(url="http://graph.mithril.fund/mcp"))
        with self.assertRaisesRegex(ValueError, "expected an HTTPS URL"):
            build_index.build()


if __name__ == "__main__":
    unittest.main()
