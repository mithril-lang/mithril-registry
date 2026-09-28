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
        for dirname in ("skills", "mcp", "tools"):
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
        self.assertEqual(index["count"], 6)
        self.assertEqual({entry["type"] for entry in index["entries"]}, {"skill", "mcp", "tool"})
        self.assertEqual(sum(entry["type"] == "skill" for entry in index["entries"]), 2)
        self.assertTrue(next(entry for entry in index["entries"] if entry["type"] == "mcp")["installable"])
        self.assertTrue(all(not entry["installable"] for entry in index["entries"] if entry["type"] == "tool"))
        self.assertEqual(sum(kind["count"] for kind in categories["types"]), 6)

    def test_tool_binding_must_match_real_mcp_tool(self):
        self.write_manifest("tools/knowledge-search/manifest.json", lambda data: data["mcp"].update(name="imaginary_tool"))
        with self.assertRaisesRegex(ValueError, "MCP tool contract does not match"):
            build_index.build()

    def test_mcp_endpoint_must_be_https(self):
        self.write_manifest("mcp/mithril-cloud/manifest.json", lambda data: data.update(url="http://mithril.fund/mcp"))
        with self.assertRaisesRegex(ValueError, "expected an HTTPS URL"):
            build_index.build()


if __name__ == "__main__":
    unittest.main()
