#!/usr/bin/env python3
"""Unit tests for the mithril-message-spam-watch classifier.

Synthetic fixtures only (in-memory chat.db, temp emlx files, temp corpus and
contacts); no live sources, no network.
"""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
_CANDIDATES = (
    os.environ.get("MWW_SCRIPT_UNDER_TEST"),
    os.path.join(HERE, "..", "scripts", "message_spam_watch.py"),
    os.path.join(HERE, "message_spam_watch.py"),
)
SCRIPT = next(p for p in _CANDIDATES if p and os.path.isfile(p))
APPLE_OFFSET = 978307200


def _env(tmp, **extra):
    env = {
        "MWW_CHAT_DB": os.path.join(tmp, "chat.db"),
        "MWW_MAIL_ROOT": os.path.join(tmp, "mail"),
        "MWW_CORPUS_FILE": os.path.join(tmp, "corpus.json"),
        "MWW_CONTACTS_FILE": os.path.join(tmp, "contacts.txt"),
        "MWW_LEDGER_FILE": os.path.join(tmp, "ledger.jsonl"),
        "MWW_PUBLISH_FILE": os.path.join(tmp, "observations.json"),
        "MWW_PROFILE_DIR": tmp,
    }
    env.update(extra)
    env.update(os.environ)
    return env


def _now_apple():
    return int((datetime.now(timezone.utc).timestamp() - APPLE_OFFSET) * 1_000_000_000)


def _make_chat_db(path, rows):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE handle (rowid INTEGER PRIMARY KEY, id TEXT)")
    conn.execute("CREATE TABLE message (rowid INTEGER PRIMARY KEY, text TEXT,"
                 " handle_id INTEGER, date INTEGER, is_from_me INTEGER, is_spam INTEGER)")
    for i, (handle, text, date_apple, is_spam) in enumerate(rows, start=1):
        conn.execute("INSERT INTO handle (rowid, id) VALUES (?, ?)", (i, handle))
        conn.execute("INSERT INTO message (rowid, text, handle_id, date,"
                     " is_from_me, is_spam) VALUES (?,?,?,?,?,?)",
                     (i, text, i, date_apple, 0, is_spam))
    conn.commit()
    conn.close()


def _emlx(path, from_addr, subject, body, date_iso, dmarc=None, spf=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    d = date_iso
    auth = "Authentication-Results: mx "
    if spf:
        auth += "spf=%s; " % spf
    if dmarc:
        auth += "dmarc=%s; " % dmarc
    body = ("From: %s\r\n"
            "To: me@example.com\r\n"
            "Subject: %s\r\n"
            "Date: %s\r\n"
            "Message-ID: <msg-%s@x>\r\n"
            "%s\r\n"
            "\r\n"
            "%s\r\n" % (from_addr, subject, d, subject, auth, body))
    # macOS Mail V10 .emlx format: line-count prefix before the real message
    lines = body.count("\r\n") + (1 if not body.endswith("\r\n") else 0)
    with open(path, "w", encoding="utf-8") as f:
        f.write("%d     \n%s" % (lines, body))


def _recent_iso(days_ago=0, minutes=0):
    return (datetime.now(timezone.utc) - timedelta(days=days_ago, minutes=minutes)
            ).strftime("%a, %d %b %Y %H:%M:%S +0000")


def _write_corpus(path):
    data = {"items": [{"domain": "evil-phish.jp", "status": "ok"},
                      {"domain": "bank.example", "status": "ok"}]}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)


def _write_contacts(path):
    with open(path, "w", encoding="utf-8") as f:
        f.write("<boss@example.com>\n<junkawasaki@gftd.jp>\n<no-email>\n")


def _run(args, env):
    return subprocess.run([sys.executable, SCRIPT] + args,
                          capture_output=True, text=True, env=env, timeout=120)


class TestMessageSpamWatch(unittest.TestCase):
    def _setup(self):
        if getattr(self, "tmp", None) is not None:
            return self.tmp.name
        self.tmp = tempfile.TemporaryDirectory(prefix="mww-test-")
        tmp = self.tmp.name
        self.env = _env(tmp)
        now = _now_apple()
        _make_chat_db(self.env["MWW_CHAT_DB"], [
            ("5551234", "認証コードは 1234 です", now, 0),
            ("5559999", "あなたのポイント進呈のため確認手続きが必要です。"
                        " https://pts.example.co/claim", now, 0),
        ])
        _emlx(os.path.join(tmp, "mail", "INBOX.mbox", "a", "Data", "m1.emlx"),
              "alerts@bank.example", "重要: 口座情報の確認",
              "口座情報の確認が必要です。 https://portal.bank.example/x",
              _recent_iso(0, 30), dmarc="fail")
        _emlx(os.path.join(tmp, "mail", "INBOX.mbox", "a", "Data", "m2.emlx"),
              "boss@example.com", "議事録", "来週の議題について共有します。",
              _recent_iso(0, 60))
        _emlx(os.path.join(tmp, "mail", "INBOX.mbox", "a", "Data", "m3.emlx"),
              "promovip@evil-phish.jp", "月額更新", "支払い方法の確認と更新が必要です。",
              _recent_iso(1, 0), spf="fail")
        _emlx(os.path.join(tmp, "mail", "INBOX.mbox", "a", "Data", "m4.emlx"),
              "old@veryold.org", "古いメール", "これは古い",
              _recent_iso(days_ago=300))
        _write_corpus(self.env["MWW_CORPUS_FILE"])
        _write_contacts(self.env["MWW_CONTACTS_FILE"])
        return tmp

    def _scan(self, **args):
        tmp = self._setup()
        args = {"days": 30, "limit": 100}
        args.update(args)
        r = _run(["scan", "--input", json.dumps(args)], self.env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        lines = r.stdout.strip().splitlines()
        self.assertTrue(lines[0].startswith("SCAN\twindow"), lines)
        self.assertIn("RECEIPT\t", "\n".join(lines))
        return lines

    def test_scan_verdicts(self):
        lines = self._scan()
        joined = "\n".join(lines)
        self.assertIn("VERDICT\tspam=3", joined)      # bank (dmarc-fail), evil-phish (corpus), imsg pts lure
        self.assertIn("VERDICT\tlegit=1", joined)     # boss contact, no signal
        self.assertIn("VERDICT\tunknown=1", joined)   # imsg otp short-code

    def test_scan_counts_detailed(self):
        lines = self._scan()
        counts = {}
        for ln in lines:
            if ln.startswith("COUNT\t"):
                for part in ln.split("\t")[1].split(" "):
                    k, v = part.split("=")
                    counts[k] = v
        # imessage 2 (both in window) + mail 3 (m4 out of 30d window) = 5 classified
        self.assertEqual(counts["classified"], "5")
        self.assertEqual(counts["ledgerAdded"], "5")
        verdicts = {}
        for ln in lines:
            if ln.startswith("VERDICT\t"):
                k, v = ln.split("\t")[1].split("=")
                verdicts[k] = int(v)
        self.assertEqual(sum(verdicts.values()), 5)
        # spam: m1 dmarc-fail, m3 corpus-host, imsg pts lure+host = 3
        self.assertEqual(verdicts.get("spam"), 3)
        # legit: m2 boss contact = 1
        self.assertEqual(verdicts.get("legit"), 1)
        # unknown: imsg otp short-code = 1
        self.assertEqual(verdicts.get("unknown"), 1)

    def test_ledger_is_idempotent(self):
        lines1 = self._scan()
        tmp = os.path.dirname(self.env["MWW_LEDGER_FILE"])
        ledger = os.path.join(tmp, "ledger.jsonl")
        with open(ledger, "rb") as f:
            first = f.read()
        lines2 = self._scan()
        joined2 = "\n".join(lines2)
        self.assertIn("ledgerAdded=0", joined2)
        with open(ledger, "rb") as f:
            self.assertEqual(f.read(), first)

    def test_corpus_beats_contact(self):
        # bank.example is in the corpus AND a contact domain; corpus wins (spam kept)
        tmp = self._setup()
        with open(self.env["MWW_CONTACTS_FILE"], "a", encoding="utf-8") as f:
            f.write("<someone@bank.example>\n")
        r = _run(["scan", "--input", json.dumps({"days": 30, "sources": ["mail"]})],
                 self.env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("VERDICT\tspam=2", r.stdout)  # m1 dmarc + m3 corpus

    def test_contact_without_signal_is_legit(self):
        lines = self._scan()
        self.assertIn("VERDICT\tlegit=1", "\n".join(lines))

    def test_out_of_window_excluded(self):
        lines = self._scan(days=30)
        joined = "\n".join(lines)
        self.assertIn("mailFilesScanned=4", joined)
        self.assertNotIn("古いメール", joined)

    def test_invalid_input(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mww-test-")
        env = _env(self.tmp.name)
        for bad in ({"days": 0}, {"days": 91}, {"limit": 0},
                    {"sources": ["nope"]}, {"publish": "yes"},
                    {"days": True}, {"unknownField": 1}):
            r = _run(["scan", "--input", json.dumps(bad)], env)
            self.assertEqual(r.returncode, 2, (bad, r.stdout))
            self.assertIn("SCAN\tFAILED", r.stdout)

    def test_report_aggregates(self):
        self._scan()
        tmp = os.path.dirname(self.env["MWW_LEDGER_FILE"])
        r = _run(["report"], self.env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        rep = json.loads(r.stdout)
        self.assertEqual(rep["ledgerEntries"], 5)
        self.assertEqual(rep["verdicts"].get("spam"), 3)
        self.assertEqual(rep["verdicts"].get("legit"), 1)
        self.assertEqual(rep["verdicts"].get("unknown"), 1)
        self.assertEqual(rep["corpus"]["available"], True)
        self.assertGreaterEqual(rep["hostsMatchingCorpus"], 2)
        self.assertIn("boundary", rep)

    def test_status_reports_sources(self):
        tmp = self._setup()
        r = _run(["status"], self.env)
        self.assertEqual(r.returncode, 0, r.stdout)
        st = json.loads(r.stdout)
        self.assertEqual(st["imessage"]["status"], "ok")
        self.assertEqual(st["mail"]["status"], "ok")
        self.assertEqual(st["corpus"]["count"], 2)
        self.assertEqual(st["contacts"]["count"], 2)
        self.assertIn("boundary", st)

    def test_scan_missing_sources(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mww-test-")
        env = _env(self.tmp.name)
        r = _run(["scan", "--input", json.dumps({"days": 7})], env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("SOURCE\timessage status=unavailable", r.stdout)
        self.assertIn("SOURCE\tmail status=unavailable", r.stdout)
        self.assertIn("VERDICT\tspam=0", r.stdout)

    def test_mcp_bridge_roundtrip(self):
        tmp = self._setup()
        init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18",
                           "clientInfo": {"name": "t", "version": "0"},
                           "capabilities": {}}}
        listed = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        called = {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                  "params": {"name": "spamwatch_status", "arguments": {}}}
        called_scan = {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                       "params": {"name": "spamwatch_scan",
                                  "arguments": {"days": 30, "limit": 50}}}
        bad = {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
               "params": {"name": "nope", "arguments": {}}}
        payload = "\n".join(json.dumps(x) for x in
                            (init, listed, called, called_scan, bad)) + "\n"
        r = subprocess.run([sys.executable, SCRIPT, "--mcp"],
                           input=payload, capture_output=True, text=True,
                           env=self.env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = [json.loads(x) for x in r.stdout.strip().splitlines()]
        self.assertEqual(len(lines), 5)
        self.assertIn("serverInfo", lines[0]["result"])
        names = [t["name"] for t in lines[1]["result"]["tools"]]
        self.assertEqual(names, ["spamwatch_status", "spamwatch_scan", "spamwatch_report"])
        self.assertTrue(lines[2]["result"]["isError"] is False)
        self.assertTrue(lines[3]["result"]["isError"] is False)
        self.assertEqual(lines[4]["error"]["code"], -32602)

    def test_stdlib_only(self):
        with open(SCRIPT, encoding="utf-8") as _f:
            src = _f.read()
        mods = set()
        for ln in src.splitlines():
            ln = ln.strip()
            if ln.startswith("import "):
                for part in ln[len("import "):].split(","):
                    mods.add(part.split(".")[0].strip().split(" as ")[0])
            elif ln.startswith("from "):
                mods.add(ln[len("from "):].split()[0].split(".")[0])
        std = {"argparse", "email", "hashlib", "json", "os", "re", "shutil",
               "sqlite3", "subprocess", "sys", "datetime"}
        for mod in mods:
            self.assertIn(mod, std, mod)

    def tearDown(self):
        if hasattr(self, "tmp"):
            self.tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
