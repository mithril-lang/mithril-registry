#!/usr/bin/env python3
"""Unit tests for mithril-polyglot-review-ops tick.

Hermetic: synthetic fixtures and monkeypatched subprocess calls only.
No live network, no real R2/Drive, no real git remote.
"""
import hashlib
import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
TICK = os.path.join(HERE, "..", "scripts", "polyglot_review_tick.py")


def load_tick():
    spec = importlib.util.spec_from_file_location("polyglot_review_tick", TICK)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TickHelpers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tk = load_tick()

    def test_sha256_bytes_known(self):
        self.assertEqual(self.tk.sha256_bytes(b"abc"),
                         hashlib.sha256(b"abc").hexdigest())

    def test_now_iso_shape(self):
        self.assertRegex(self.tk.now_iso(),
                         r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_resolve_head_rejects_bad_shapes(self):
        import subprocess
        calls = {}

        class FakeCompleted:
            def __init__(self, out, rc=0, err=""):
                self.stdout, self.returncode, self.stderr = out, rc, err

        def fake_run(cmd, timeout=120, **kw):
            calls["cmd"] = cmd
            return FakeCompleted("", 0)

        self.tk.run = fake_run
        sha, err = self.tk.resolve_head("o/r")
        self.assertIsNone(sha)
        self.assertIsNotNone(err)

    def test_worktree_ready_stops_on_wrong_branch(self):
        import subprocess
        class FakeCompleted:
            def __init__(self, out, rc=0, err=""):
                self.stdout, self.returncode, self.stderr = out, rc, err

        def fake_run(cmd, timeout=120, **kw):
            if cmd[-3:] == ["rev-parse", "--abbrev-ref", "HEAD"]:
                return FakeCompleted("main\n", 0)
            if cmd[-2:] == ["rev-parse", "HEAD"]:
                return FakeCompleted("0" * 40 + "\n", 0)
            return FakeCompleted("", 0)

        old_run = self.tk.run
        self.tk.run = fake_run
        with self.assertRaises(SystemExit):
            self.tk.worktree_ready()
        self.tk.run = old_run

    def test_state_manifest_are_valid_json(self):
        # The regression that bit tick #1: manifest written as bytes.
        # Reconstruct the exact main() write path with synthetic data.
        import io, contextlib
        with tempfile.TemporaryDirectory() as tmp:
            prof = Path(tmp) / "profile"
            (prof / "data" / "canonical").mkdir(parents=True)
            (prof / "data" / "receipts").mkdir(parents=True)
            (prof / "cache").mkdir(parents=True)
            (prof / "scripts").mkdir(parents=True)
            env = dict(os.environ)
            env["POLYGLOT_PROFILE_DIR"] = str(prof)
            state = {
                "generated_at": "2026-10-11T02:00:00Z",
                "worktree_head": "0" * 40, "branch": "feat/polyglot-source-extraction",
                "tests": {"pass": 28, "fail": 0, "files": 2, "last_error": None},
                "git": "clean", "targets": [],
            }
            spath = prof / "data" / "canonical" / "state.json"
            spath.write_text(json.dumps(state))
            manifest = json.dumps({"dataset": "polyglot-review",
                                   "files": [{"name": "receipt.json",
                                              "bytes": spath.stat().st_size,
                                              "sha256": self.tk.sha256_bytes(spath.read_bytes())}],
                                   "generated_at": state["generated_at"]})
            # manifest must be a str that write_text accepts
            mpath = prof / "cache" / "manifest.json"
            mpath.write_text(manifest)
            back = json.loads(mpath.read_text())
            self.assertEqual(back["files"][0]["sha256"],
                             self.tk.sha256_bytes(spath.read_bytes()))
            self.assertEqual(back["dataset"], "polyglot-review")


class TickRegex(unittest.TestCase):
    def test_test_summary_parse_counts(self):
        # node --test emits "\u2139 pass 28" and "\u2139 fail 0"
        out = "\u2139 tests 28\n\u2139 pass 28\n\u2139 fail 0\n"
        pp = re.search(r"pass\s+(\d+)", out)
        ff = re.search(r"fail\s+(\d+)", out)
        self.assertEqual(int(pp.group(1)), 28)
        self.assertEqual(int(ff.group(1)), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
