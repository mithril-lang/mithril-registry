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


class DiagnosisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        script = SCRIPT.with_name("diagnose.py")
        spec = importlib.util.spec_from_file_location("diskspace_diagnose",script)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_balances_large_and_small_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()
            (root/"huge").mkdir()
            (root/"small").mkdir()
            for i in range(150):
                (root/"huge"/str(i)).write_bytes(b"x")
            (root/"small"/"keep").write_bytes(b"keep")
            result=module.audit(str(root),max_entries=80)
            self.assertTrue(result["partial"])
            self.assertTrue(any(g["name"]=="small" and g["logicalBytes"]==4 for g in result["groups"]))

    def test_requires_comparable_complete_observations(self):
        from copy import deepcopy
        report=dict(schemaVersion=1,root="/selected",volumeId="1",bounds=dict(entries=20,depth=16,seconds=15),partial=False,observedAt="2026-10-08T00:00:00+00:00",logicalBytes=10,freeBytes=100,groups=[dict(kind="folder",name="cache",logicalBytes=10)])
        later=deepcopy(report)
        later.update(observedAt="2026-10-08T01:00:00+00:00",logicalBytes=40,freeBytes=95)
        later["groups"][0]["logicalBytes"]=40
        result=self.module.compare(later,report)
        self.assertEqual(result["logicalDelta"],30)
        self.assertEqual(result["freeSpaceDelta"],-5)
        for change in (dict(partial=True),dict(root="/other"),dict(volumeId="2"),dict(bounds={}),dict(observedAt=report["observedAt"])):
            changed=deepcopy(later);changed.update(change)
            self.assertEqual(self.module.compare(changed,report)["state"],"unverified")
        self.assertEqual(self.module.compare(later,None)["state"],"unverified")

    def test_review_never_promotes_path_hints_to_deletion(self):
        report=dict(root="/selected",partial=True,largest=[dict(name="/selected/.hermes/cache.bin",bytes=500),dict(name="/selected/project/node_modules/pkg",bytes=400),dict(name="/outside/file",bytes=300)])
        result=self.module.diagnose(report)
        self.assertFalse(result["mutationSupported"])
        self.assertEqual(len(result["cleanupReview"]),2)
        protected, dependencies=result["cleanupReview"]
        self.assertEqual(protected["classification"],"preserve")
        self.assertEqual(dependencies["causeHypothesis"],"dependencies")
        self.assertEqual(dependencies["authorization"],"pending")
        self.assertEqual(dependencies["activeUse"],"unverified")
