#!/usr/bin/env python3
"""Deterministic checks for the mithril-flame-sword local analyst.

Synthetic reports only; no live hosts, no network. Exercises the public CLI
and the stdio MCP bridge over the vendored rule-based analyst.
"""
import importlib.util
import json
import os
import re
import subprocess
import struct
import sys
import tempfile
import unittest
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
_CANDIDATES = (
    os.environ.get("FLAME_SWORD_SCRIPT_UNDER_TEST"),
    os.path.join(HERE, "..", "scripts", "flame_sword.py"),
    os.path.join(HERE, "flame_sword.py"),
)
SCRIPT = next(p for p in _CANDIDATES if p and os.path.isfile(p))

REPORT = {
    "domain": "example.com",
    "subdomains": [
        {"subdomain": "www.example.com", "http_status": 301, "https_status": 200},
        {"subdomain": "admin.example.com", "https_status": 403},
        {"subdomain": "staging.example.com", "http_status": 200},
    ],
}


def run_cli(args, payload=None):
    if payload is not None:
        args = list(args) + ["--input", "-"]
        return subprocess.run([sys.executable, SCRIPT] + args,
                              input=json.dumps(payload).encode(),
                              capture_output=True, timeout=120)
    return subprocess.run([sys.executable, SCRIPT] + args,
                          capture_output=True, timeout=120)


def run_mcp(requests):
    payload = "\n".join(json.dumps(r) for r in requests) + "\n"
    return subprocess.run([sys.executable, SCRIPT, "--mcp"],
                          input=payload.encode(), capture_output=True, timeout=120)


class TestFlameSwordCli(unittest.TestCase):
    def test_capabilities(self):
        r = run_cli(["--tool", "flame_sword_capabilities"])
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)
        self.assertEqual(data["name"], "mithril-flame-sword")
        self.assertEqual(data["version"], "0.2.0")
        self.assertEqual([op["id"] for op in data["operations"]],
                         ["report_validate", "report_analyze", "scan_domain"])
        by_id = {op["id"]: op for op in data["operations"]}
        self.assertFalse(by_id["report_validate"]["network"])
        self.assertFalse(by_id["report_analyze"]["network"])
        self.assertTrue(by_id["scan_domain"]["network"])
        self.assertGreaterEqual(len(data["modules"]), 8)
        for module in data["modules"]:
            self.assertIn("this skill", module["executedBy"])
        self.assertTrue(any("Bounded stdlib scan" in line for line in data["limitations"]))
        self.assertTrue(any("GET-only" in line for line in data["limitations"]))

    def test_validate_normalizes(self):
        r = run_cli(["--tool", "flame_sword_report_validate"], {"domain": "Example.COM",
                        "subdomains": [{"subdomain": "WWW.EXAMPLE.COM", "http_status": 301}]})
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)
        self.assertEqual(data["domain"], "example.com")
        self.assertIs(data["valid"], True)
        self.assertEqual(data["subdomains"][0]["subdomain"], "www.example.com")
        self.assertIsNone(data["subdomains"][0]["https_status"])

    def test_analyze_is_deterministic(self):
        first = run_cli(["--tool", "flame_sword_report_analyze"], REPORT)
        self.assertEqual(first.returncode, 0, first.stderr)
        second = run_cli(["--tool", "flame_sword_report_analyze"], REPORT)
        self.assertEqual(second.stdout, first.stdout)
        data = json.loads(first.stdout)
        self.assertEqual(data["execution"], "local-cli-vendored-analyst")
        self.assertEqual(data["evidence"], "user-supplied observations")
        self.assertIn("No network scan was performed by this analysis.", data["limitations"])
        summary = data["analysis"]["summary"]
        self.assertEqual(summary["total_subdomains"], 3)
        self.assertEqual(summary["analysis_timestamp"], "2026-01-01T00:00:00")
        self.assertIn(data["analysis"]["risk_assessment"]["level"],
                      ("Low", "Medium", "High", "Critical"))

    def test_analyze_recomputes_per_input(self):
        base = run_cli(["--tool", "flame_sword_report_analyze"], REPORT)
        changed = dict(REPORT, subdomains=[
            {"subdomain": "shop.example.com", "https_status": 200},
            {"subdomain": "mail.example.com", "http_status": 200}])
        other = run_cli(["--tool", "flame_sword_report_analyze"], changed)
        self.assertEqual(other.returncode, 0, other.stderr)
        self.assertNotEqual(other.stdout, base.stdout)
        self.assertEqual(json.loads(other.stdout)["analysis"]["summary"]["total_subdomains"], 2)

    def test_contract_failures_are_machine_readable(self):
        cases = [
            ({"subdomains": []}, "invalid_domain"),  # missing domain key
            ({"domain": "bad_domain", "subdomains": []}, "invalid_domain"),
            ({"domain": "example.com",
               "subdomains": [{"subdomain": "other.example.net"}]}, "domain_mismatch"),
            ({"domain": "example.com",
               "subdomains": [{"subdomain": "www.example.com", "http_status": "200"}]},
             "invalid_status"),
            ({"domain": "example.com",
               "subdomains": [{"subdomain": "www.example.com", "https_status": True}]},
             "invalid_status"),
            ({"domain": "example.com",
               "subdomains": [{"subdomain": f"h{i:03d}.example.com"} for i in range(501)]},
             "too_many_subdomains"),
        ]
        for payload, reason in cases:
            r = run_cli(["--tool", "flame_sword_report_analyze"], payload)
            self.assertEqual(r.returncode, 1, (payload, r.stderr))
            self.assertIn(reason, r.stderr.decode())
            self.assertNotIn("Traceback", r.stderr.decode())

    def test_missing_file_reason(self):
        with tempfile.TemporaryDirectory(prefix="flame-sword-test-") as tmp:
            r = run_cli(["--tool", "flame_sword_report_analyze",
                         "--input", os.path.join(tmp, "absent.json")])
            self.assertEqual(r.returncode, 1, r.stderr)
            self.assertIn("file_not_found", r.stderr.decode())
            self.assertNotIn("Traceback", r.stderr.decode())

    def test_oversized_input_reason(self):
        with tempfile.TemporaryDirectory(prefix="flame-sword-test-") as tmp:
            path = os.path.join(tmp, "big.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write('{"domain":"example.com","subdomains":[]}' + "x" * 40000)
            r = run_cli(["--tool", "flame_sword_report_analyze", "--input", path])
            self.assertEqual(r.returncode, 1, r.stderr)
            self.assertIn("request_too_large", r.stderr.decode())

    def test_tools_json_matches_dispatch(self):
        tools = json.loads(Path(SCRIPT).with_name("tools.json").read_text())
        self.assertEqual([t["name"] for t in tools],
                         ["flame_sword_capabilities",
                          "flame_sword_report_validate",
                          "flame_sword_report_analyze",
                          "flame_sword_scan"])
        self.assertFalse(any(t.get("write") for t in tools))
        for tool in tools:
            self.assertIsInstance(tool["inputSchema"], dict)
            self.assertIn(tool["inputSchema"].get("$schema", ""),
                          ("https://json-schema.org/draft/2020-12/schema",))


class TestFlameSwordMcp(unittest.TestCase):
    def test_bridge_roundtrip(self):
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18",
                        "clientInfo": {"name": "t", "version": "0"},
                        "capabilities": {}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "flame_sword_report_analyze", "arguments": REPORT}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
             "params": {"name": "nope", "arguments": {}}},
        ]
        r = run_mcp(requests)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = [json.loads(x) for x in r.stdout.strip().splitlines()]
        self.assertEqual([x["id"] for x in lines], [1, 2, 3, 4])
        self.assertEqual(lines[0]["result"]["protocolVersion"], "2025-06-18")
        names = [t["name"] for t in lines[1]["result"]["tools"]]
        self.assertEqual(names, ["flame_sword_capabilities",
                                 "flame_sword_report_validate",
                                 "flame_sword_report_analyze",
                                 "flame_sword_scan"])
        self.assertIs(lines[2]["result"]["isError"], False)
        self.assertEqual(lines[2]["result"]["content"][0]["type"], "text")
        # Unknown tool names surface as isError results, not JSON-RPC errors.
        self.assertIs(lines[3]["result"]["isError"], True)
        self.assertIn("invalid_tool", lines[3]["result"]["content"][0]["text"])

    def test_oversized_line_then_continues(self):
        spec = importlib.util.spec_from_file_location("flame_sword", SCRIPT)
        if spec is None:
            self.fail("could not build module spec for flame_sword")
        flame_sword = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(flame_sword)
        padded = b'{"jsonrpc":"2.0","id":99,"method":"ping","params":{}}' \
            + b"x" * flame_sword.MAX_ARG_BYTES
        nxt = json.dumps({"jsonrpc": "2.0", "id": 101, "method": "tools/list"}).encode()
        r = subprocess.run([sys.executable, SCRIPT, "--mcp"],
                           input=b"\n".join([padded, nxt]) + b"\n",
                           capture_output=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = [json.loads(x) for x in r.stdout.strip().splitlines()]
        self.assertEqual([x["id"] for x in lines], [None, 101])
        self.assertEqual(lines[0]["error"]["code"], -32600)
        self.assertTrue(lines[1]["result"]["tools"])

    def test_invalid_json_is_parse_error(self):
        raw = b'{"jsonrpc":"2.0","id":7,"method":ping\n'
        r = subprocess.run([sys.executable, SCRIPT, "--mcp"],
                           input=raw, capture_output=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = [json.loads(x) for x in r.stdout.strip().splitlines()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["error"]["code"], -32700)


class TestScannerOffline(unittest.TestCase):
    """In-process, network-independent tests of the bounded scanner core."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("flame_sword", SCRIPT)
        if spec is None:
            raise AssertionError("could not build module spec for flame_sword")
        cls.fs = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.fs)

    def test_scan_invalid_domain(self):
        with self.assertRaisesRegex(self.fs.FlameSwordFailure, "invalid_domain"):
            self.fs.scan_domain({"domain": "bad_domain"})

    def test_scan_invalid_options_key(self):
        with self.assertRaisesRegex(self.fs.FlameSwordFailure, "invalid_options"):
            self.fs.scan_domain({"domain": "example.com",
                                 "options": {"bogus": True}})

    def test_scan_invalid_options_type(self):
        with self.assertRaisesRegex(self.fs.FlameSwordFailure, "invalid_options"):
            self.fs.scan_domain({"domain": "example.com",
                                 "options": {"ai": "yes"}})

    def test_dns_read_name_with_compression_pointer(self):
        # name "a.b.example.com" followed by a pointer back to its start.
        name = self.fs._dns_name_bytes("a.b.example.com")
        record = name + struct.pack(">H", 0xC000 + 0)  # pointer to offset 0
        self.assertEqual(self.fs._dns_read_name(record, 0), "a.b.example.com")
        self.assertEqual(self.fs._dns_read_name(record, len(name)), "a.b.example.com")

    def test_dns_query_timeout_is_labeled_not_raised(self):
        # 0.0.0.0:53 must not raise; the failure comes back as a labeled error.
        result = self.fs._dns_query("unavailable.example", 1, resolver="0.0.0.0")
        self.assertIn("records", result)
        self.assertIsInstance(result["records"], list)

    def test_tcp_probe_closed_port_is_labeled(self):
        probe = self.fs._tcp_probe("127.0.0.1", 1)
        self.assertFalse(probe["open"])
        self.assertIsNotNone(probe["error"])

    def test_tech_detect_matches_header_and_body(self):
        signatures = [
            {"name": "nginx", "checks": [{"type": "header", "field": "server",
                                          "pattern": "nginx/\\d+"}]},
            {"name": "flask", "checks": [{"type": "body",
                                          "pattern": "<title>.*</title>"}]},
        ]
        probe = {"status": 200, "body": b"<title>Home</title>",
                 "headers": [("Server", "nginx/1.27")]
                 }
        self.assertEqual(self.fs._tech_detect(probe, signatures), ["nginx", "flask"])
        self.assertEqual(self.fs._tech_detect(None, signatures), [])

    def test_scan_ai_fail_soft_without_key(self):
        env = {"MITHRIL_API_KEY": "", "MITHRIL_API_KEY_REF": ""}
        options = {key: False for key in ("subdomains", "ports", "dns",
                                          "real_ip", "tls", "tech", "email")}
        options["ai"] = True
        import os as _os
        saved = {k: _os.environ.get(k) for k in env}
        try:
            for key in env:
                _os.environ.pop(key, None)
            scan = self.fs.scan_domain({"domain": "example.com", "options": options})
        finally:
            for key, value in saved.items():
                if value is None:
                    _os.environ.pop(key, None)
                else:
                    _os.environ[key] = value
        self.assertEqual(scan["domain"], "example.com")
        self.assertEqual(scan["observations"]["subdomains"][0]["subdomain"], "example.com")
        ai = scan["observations"]["ai"]
        if "mithril_key_unavailable" in ai.get("error", ""):
            pass
        else:
            self.assertIn("provider", ai)  # a real (failed) call is still labeled.

    def test_scan_rows_feed_analyst_contract(self):
        # report_scan's observation rows must satisfy report_analyze validation.
        options = {key: False for key in ("subdomains", "ports", "dns",
                                          "real_ip", "tls", "tech", "email")}
        scan = self.fs.scan_domain({"domain": "example.com", "options": options})
        observations = [{"subdomain": row["subdomain"],
                         "http_status": row.get("http_status"),
                         "https_status": row.get("https_status")}
                        for row in scan["observations"]["subdomains"]]
        domain, clean = self.fs.validate_observations(
            {"domain": scan["domain"], "subdomains": observations})
        self.assertEqual(domain, "example.com")
        self.assertEqual(clean, observations)


class TestVendorIntegrity(unittest.TestCase):
    def test_vendor_files_exist_with_expected_names(self):
        vendor = Path(SCRIPT).resolve().parent / "vendor"
        self.assertTrue((vendor / "FastAnalyst.py").is_file())
        self.assertTrue((vendor / "analysis.py").is_file())

    def test_vendor_is_stdlib_only(self):
        vendor = Path(SCRIPT).resolve().parent / "vendor"
        for name in ("FastAnalyst.py", "analysis.py"):
            src = (vendor / name).read_text(encoding="utf-8")
            mods = set()
            for line in src.splitlines():
                line = line.strip()
                if line.startswith("import "):
                    mods.update(part.split(".")[0].strip().split(" as ")[0]
                                for part in line[len("import "):].split(","))
                elif line.startswith("from "):
                    mods.add(line[len("from "):].split()[0].split(".")[0])
            for mod in mods:
                # FastAnalyst is the sibling vendor module, not a stdlib import.
                self.assertIn(mod, sys.stdlib_module_names | {"FastAnalyst"}, (name, mod))


if __name__ == "__main__":
    unittest.main()
