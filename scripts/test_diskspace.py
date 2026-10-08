import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "skills/productivity/mithril-diskspace-management/scripts/audit.py"
spec = importlib.util.spec_from_file_location("diskspace_audit", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class DiskspaceTests(unittest.TestCase):
    def test_groups_preserve_totals_and_links_are_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for i in range(15):
                folder = root / ("group-%s" % i)
                folder.mkdir()
                (folder / "file").write_bytes(b"x" * (i + 1))
            os.link(root / "group-14/file", root / "hardlink")
            os.symlink(root.parent, root / "outside")
            result = module.audit(str(root))
            self.assertEqual(len(result["groups"]), 13)
            self.assertEqual(result["groups"][-1]["kind"], "other")
            self.assertTrue(result["partial"])
            self.assertEqual(result["files"], 16)
            for key in ("files", "logicalBytes", "allocatedBytes"):
                self.assertEqual(sum(group[key] for group in result["groups"]), result[key])
            expected = sum((root / ("group-%s/file" % i)).stat().st_blocks * 512 for i in range(15))
            self.assertEqual(result["allocatedBytes"], expected)
            self.assertEqual((root / "group-14/file").read_bytes(), b"x" * 15)

    def test_limits_are_partial_and_do_not_change_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for i in range(8):
                (root / str(i)).write_bytes(b"preserve")
            result = module.audit(str(root), max_entries=2)
            self.assertTrue(result["partial"])
            self.assertLessEqual(result["files"], 1)
            self.assertEqual(len(list(root.iterdir())), 8)
            self.assertEqual((root / "0").read_bytes(), b"preserve")

    def test_rejects_symlink_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            os.symlink(root, root / "alias")
            with self.assertRaises(ValueError):
                module.audit(str(root / "alias"))
