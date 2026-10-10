#!/usr/bin/env python3
"""Unit tests for mithril-bounty-vrf scripts.

Synthetic fixtures only: a generated rclone.conf-style token block, an
in-process fake Drive/OAuth server (http.server), and a synthetic xlsx
built with openpyxl. No live sources, no network, no real keys.
"""
import base64
import hashlib
import http.server
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
SYNC = os.path.join(HERE, "..", "scripts", "google_sheets_sync.py")
TICK = os.path.join(HERE, "..", "scripts", "bounty_vrf_tick.py")

REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))


def env_with(tmp, **extra):
    env = dict(os.environ)
    env.update({
        "BBOPS_RC_CONF": os.path.join(tmp, "rclone.conf"),
        "BBOPS_TOKEN_CACHE": os.path.join(tmp, "sheets_token.json"),
        "BBOPS_PROFILE_DIR": tmp,
    })
    env.update(extra)
    return env


def rclone_conf_text(refresh="refresh-synthetic", access="acc-old",
                     scope="https://www.googleapis.com/auth/drive"):
    tok = json.dumps({"access_token": access, "refresh_token": refresh,
                      "scope": scope, "token_type": "Bearer",
                      "expires_in": 3599})
    return ("[gdrive]\n  type = drive\n  token = %s\n" % tok)


class FakeDriveHandler(http.server.BaseHTTPRequestHandler):
    """Serves OAuth token + Drive export/PATCH for one spreadsheet id."""

    state = {}

    def log_message(self, format, *args):
        pass

    def _send(self, code, body, ctype="application/octet-stream"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        if self.path == "/token":
            fields = dict(urllib.parse.parse_qsl(body))
            if fields.get("refresh_token") != "refresh-synthetic":
                self._send(401, json.dumps(
                    {"error": "invalid_grant"}), "application/json")
                return
            if fields.get("client_id") != "202264815644.apps.googleusercontent.com":
                self._send(401, json.dumps(
                    {"error": "invalid_client"}), "application/json")
                return
            self._send(200, json.dumps({
                "access_token": "acc-new", "refresh_token":
                "refresh-synthetic", "scope":
                "https://www.googleapis.com/auth/drive",
                "expires_in": 3599, "token_type": "Bearer"}),
                "application/json")
            return
        self._send(404, "unexpected POST %s" % self.path, "text/plain")

    def do_GET(self):
        qs = urllib.parse.urlparse(self.path)
        parts = qs.path.strip("/").split("/")
        if parts[0] == "drive" and parts[1] == "v3" \
                and parts[2] == "files" and parts[3] == "SHEET" \
                and parts[4] == "export":
            self._send(200, FakeDrive.state["xlsx"])
            return
        self._send(404, "unexpected GET %s" % self.path, "text/plain")

    def do_PATCH(self):
        if self.path.startswith("/upload/drive/v3/files/SHEET"):
            ctype = self.headers.get("Content-Type", "")
            m = re.search(r"boundary=\"?([A-Za-z0-9_-]+)\"?", ctype)
            if not m:
                self._send(400, "no boundary", "application/json")
                return
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            sep = ("\r\n--%s" % m.group(1)).encode()
            parts = body.split(sep)
            if len(parts) < 3:
                self._send(400, "bad multipart", "application/json")
                return
            xlsx = parts[1].split(b"\r\n\r\n", 1)[1]
            xlsx = xlsx[:-2] if xlsx.endswith(b"\r\n") else xlsx
            FakeDrive.state["xlsx"] = xlsx
            self._send(200, json.dumps({"id": "SHEET"}),
                       "application/json")
            return
        self._send(404, "unexpected PATCH %s" % self.path, "text/plain")


class FakeDrive:
    server = None
    state = {}

    @classmethod
    def start(cls, xlsx):
        cls.state = {"xlsx": xlsx, "boundary": "bops" + uuid.uuid4().hex}
        handler = type("H", (FakeDriveHandler,),
                       {"state": cls.state})
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), handler)
        port = cls.server.server_address[1]
        t = threading.Thread(target=cls.server.serve_forever, daemon=True)
        t.start()
        return "http://127.0.0.1:%d" % port

    @classmethod
    def stop(cls):
        if cls.server:
            cls.server.shutdown()
            cls.server.server_close()
            cls.server = None


class TestSheetsSync(unittest.TestCase):
    def _setup(self, tmp, fake=False):
        import openpyxl
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Challenge Log"
        for c, h in enumerate(["Case", "Program", "Status", "Date JST"], 1):
            ws.cell(1, c).value = h
        ws.cell(2, 1).value = "BB-0002"
        ws.cell(2, 2).value = "Mattermost Public"
        ws.cell(2, 3).value = "old"
        ws.cell(3, 1).value = "BB-0003"
        ws.cell(3, 3).value = "old2"
        buf = io.BytesIO()
        wb.save(buf)
        (Path := __import__("pathlib").Path)(
            os.path.join(tmp, "rclone.conf")
        ).write_text(rclone_conf_text())
        xlsx = buf.getvalue()
        if fake:
            base = FakeDrive.start(xlsx)
            env = env_with(tmp, BBOPS_DRIVE_API=base, BBOPS_UPLOAD_API=base,
                           BBOPS_OAUTH_URL=base + "/token",
                           BBOPS_SHEET_ID="SHEET")
        else:
            env = env_with(tmp)
        return xlsx, env

    def _run(self, env, *args):
        return subprocess.run(
            [sys.executable, SYNC] + list(args),
            capture_output=True, text=True, env=env, timeout=120)

    def test_recover_client_secret(self):
        mod = {}
        code = "import sys; sys.path.insert(0, %r); " \
               "import google_sheets_sync as g; " \
               "print(g.CLIENT_SECRET)" % os.path.join(
                   HERE, "..", "scripts")
        r = subprocess.run([sys.executable, "-c", code],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "X4Z3ca8xfWDb1Voo-F9a7ZxJ")

    def test_refresh_and_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._setup(tmp)
            env = env_with(tmp, BBOPS_OAUTH_URL="http://127.0.0.1:1/token")
            r = self._run(env, "refresh")
            # no fake server: refresh must fail cleanly (exit 1, no leak)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("SHEETS\tFAILED", r.stdout)
            cache = os.path.join(tmp, "sheets_token.json")
            self.assertFalse(os.path.exists(cache))
            with open(cache + ".tmp", "w") as f:
                f.write("{broken")

    def test_refresh_success_writes_0600_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self._setup(tmp, fake=True)[1]
            try:
                r = self._run(env, "refresh")
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("TOKEN\tok", r.stdout)
                cache = os.path.join(tmp, "sheets_token.json")
                self.assertTrue(os.path.exists(cache))
                mode = os.stat(cache).st_mode & 0o777
                self.assertEqual(mode, 0o600, oct(mode))
                data = json.load(open(cache))
                self.assertEqual(data["access_token"], "acc-new")
                # second refresh uses the cache (no network change needed)
                r2 = self._run(env, "refresh")
                self.assertEqual(r2.returncode, 0, r2.stdout)
            finally:
                FakeDrive.stop()

    def test_log_updates_cells_with_readback(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self._setup(tmp, fake=True)[1]
            try:
                r = self._run(env, "log", "--case", "BB-0002",
                              "--set", "Status=Reviewed ok; deterministic "
                                       "snapshot",
                              "--set", "Date JST=2026-10-10")
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("readback=match", r.stdout)
                self.assertIn("cells=2", r.stdout)
                # the fake stored the xlsx part; parse it
                import openpyxl
                wb = openpyxl.load_workbook(
                    io.BytesIO(FakeDrive.state["xlsx"]))
                ws = wb["Challenge Log"]
                self.assertEqual(ws.cell(2, 3).value,
                                 "Reviewed ok; deterministic snapshot")
                self.assertEqual(ws.cell(2, 4).value, "2026-10-10")
                # untouched row kept
                self.assertEqual(ws.cell(3, 3).value, "old2")
            finally:
                FakeDrive.stop()

    def test_log_unknown_case_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self._setup(tmp, fake=True)[1]
            try:
                r = self._run(env, "log", "--case", "BB-NOPE",
                              "--set", "Status=x")
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("SHEETS\tFAILED", r.stdout)
            finally:
                FakeDrive.stop()

    def test_log_unknown_column_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self._setup(tmp, fake=True)[1]
            try:
                r = self._run(env, "log", "--case", "BB-0002",
                              "--set", "Bogus=x")
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("unknown columns", r.stdout)
            finally:
                FakeDrive.stop()

    def test_read_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self._setup(tmp, fake=True)[1]
            try:
                out = os.path.join(tmp, "out.xlsx")
                r = self._run(env, "read", "--out", out)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("READ\t%s" % out, r.stdout)
                want = hashlib.sha256(
                    open(out, "rb").read()).hexdigest()
                self.assertIn(want, r.stdout)
            finally:
                FakeDrive.stop()


class TestTickBinding(unittest.TestCase):
    def _tick_env(self, tmp, profile_name):
        prof = os.path.join(tmp, profile_name)
        os.makedirs(os.path.join(prof, "data", "canonical"),
                    exist_ok=True)
        case = {"case_id": "BB-0002", "program": "Mattermost Public",
                "repository": "mattermost/mattermost-plugin-msteams",
                "commit_input": "d9ad4dd7030b052bf0fecce0e15a78cd08621975"}
        json.dump({"schema": "bounty-vrf-challenges/1",
                   "cases": {"BB-0002": case}},
                  open(os.path.join(prof, "data", "canonical",
                                    "challenges.json"), "w"))
        env = dict(os.environ, BBOPS_PROFILE_DIR=prof,
                   BBOPS_PROFILE_NAME=profile_name,
                   BBOPS_SKIP_SHEET="1")
        env["MITHRIL_SYSTEM_ONE_ROOT"] = os.path.join(
            tmp, "system-one")
        return prof

    def test_case_bound_from_profile_name(self):
        mod = {}
        with tempfile.TemporaryDirectory() as tmp:
            prof = self._tick_env(tmp, "mithril-bb-0002")
            code = (
                "import sys; sys.path.insert(0, %r); "
                "import bounty_vrf_tick as t; from pathlib import Path; "
                "print(t.bound_cases(Path(%r))); "
                "print(t.bound_cases(Path('mithril-bounty-vrf-ops')))"
                % (os.path.join(HERE, "..", "scripts"), prof))
            r = subprocess.run([sys.executable, "-c", code],
                               capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(
                r.stdout.strip(),
                "['BB-0002', 'BB-0002b']\n[]")

    def test_tick_fails_without_canonical(self):
        with tempfile.TemporaryDirectory() as tmp:
            prof = os.path.join(tmp, "mithril-bb-0002")
            os.makedirs(os.path.join(prof, "data", "canonical"))
            env = dict(os.environ, BBOPS_PROFILE_DIR=prof,
                       BBOPS_PROFILE_NAME="mithril-bb-0002",
                       BBOPS_SKIP_SHEET="1")
            r = subprocess.run([sys.executable, TICK],
                               capture_output=True, text=True, env=env,
                               timeout=120)
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
            self.assertIn("TICK\tFAILED", r.stdout)


if __name__ == "__main__":
    unittest.main()
