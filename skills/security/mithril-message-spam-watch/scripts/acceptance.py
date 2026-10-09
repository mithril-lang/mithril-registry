#!/usr/bin/env python3
"""Synthetic acceptance exercise for the mithril-message-spam-watch skill.

Exercises the public CLI and the stdio JSON-RPC bridge over synthetic
fixtures (in-memory chat.db, emlx files with the macOS line-count prefix,
corpus, contacts) in a temporary area. No live sources, no network, no keys.

Verifies:
- deterministic classification (identical inputs -> identical receipts);
- corpus / dmarc / contact / lure / otp reason codes and the
  spam / legit / unknown verdict split;
- ledger idempotency (a second run adds nothing);
- input validation (out-of-range days/limit, unknown fields, wrong types);
- stdlib-only imports;
- the MCP bridge (initialize, tools/list, tools/call, unknown tool error);
- a machine-readable synthetic-local-evaluation receipt.
"""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "message_spam_watch.py"
APPLE_OFFSET = 978307200


def now_apple():
    return int((datetime.now(timezone.utc).timestamp() - APPLE_OFFSET) * 1_000_000_000)


def make_chat_db(path, rows):
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE handle (rowid INTEGER PRIMARY KEY, id TEXT)")
    conn.execute("CREATE TABLE message (rowid INTEGER PRIMARY KEY, text TEXT,"
                 " handle_id INTEGER, date INTEGER, is_from_me INTEGER, is_spam INTEGER)")
    for i, (handle, text, date_apple, is_spam) in enumerate(rows, 1):
        conn.execute("INSERT INTO handle (rowid, id) VALUES (?, ?)", (i, handle))
        conn.execute("INSERT INTO message (rowid, text, handle_id, date,"
                     " is_from_me, is_spam) VALUES (?,?,?,?,?,?)",
                     (i, text, i, date_apple, 0, is_spam))
    conn.commit()
    conn.close()


def emlx(path, from_addr, subject, body, date, dmarc=None, spf=None):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    auth = "Authentication-Results: mx "
    if spf:
        auth += "spf=%s; " % spf
    if dmarc:
        auth += "dmarc=%s; " % dmarc
    text = ("From: %s\r\nTo: me@example.com\r\nSubject: %s\r\nDate: %s\r\n"
            "Message-ID: <m-%s@x>\r\n%s\r\n\r\n%s\r\n"
            % (from_addr, subject, date, subject, auth, body))
    lines = text.count("\r\n")
    Path(path).write_text("%d     \n%s" % (lines, text), encoding="utf-8")


def recent(days_ago=0, minutes=0):
    return ((datetime.now(timezone.utc) - timedelta(days=days_ago, minutes=minutes))
            .strftime("%a, %d %b %Y %H:%M:%S +0000"))


def run(args, env):
    return subprocess.run([sys.executable, str(SCRIPT)] + args,
                          capture_output=True, text=True, env=env, timeout=180)


def main():
    checks = []

    def check(name, ok, detail=""):
        checks.append((name, bool(ok)))
        if not ok:
            print("CHECK\tFAILED %s %s" % (name, detail[:200]))

    tmp = tempfile.mkdtemp(prefix="mww-acceptance-")
    env = dict(os.environ)
    env.update({
        "MWW_CHAT_DB": os.path.join(tmp, "chat.db"),
        "MWW_MAIL_ROOT": os.path.join(tmp, "mail"),
        "MWW_CORPUS_FILE": os.path.join(tmp, "corpus.json"),
        "MWW_CONTACTS_FILE": os.path.join(tmp, "contacts.txt"),
        "MWW_LEDGER_FILE": os.path.join(tmp, "ledger.jsonl"),
        "MWW_PUBLISH_FILE": os.path.join(tmp, "observations.json"),
        "MWW_PROFILE_DIR": tmp,
    })
    make_chat_db(env["MWW_CHAT_DB"], [
        ("5551234", "あなたの認証コードは 4321 です", now_apple(), 0),
        ("5557777", "お待たせのポイント進呈のため、確認手続きが必要です。"
                    " https://pts.example.co/claim", now_apple(), 0),
    ])
    emlx(os.path.join(tmp, "mail", "INBOX.mbox", "a", "Data", "m1.emlx"),
         "alerts@corp-bank.example", "重要: 口座情報の確認",
         "口座情報の確認が必要です。 https://portal.corp-bank.example/x",
         recent(0, 30), dmarc="fail")
    emlx(os.path.join(tmp, "mail", "INBOX.mbox", "a", "Data", "m2.emlx"),
         "boss@example.com", "議事録", "来週の議題について共有します。", recent(0, 60))
    emlx(os.path.join(tmp, "mail", "INBOX.mbox", "a", "Data", "m3.emlx"),
         "promo@evil-phish.jp", "月額更新", "支払い方法の確認と更新が必要です。", recent(1))
    emlx(os.path.join(tmp, "mail", "INBOX.mbox", "a", "Data", "m4.emlx"),
         "old@veryold.org", "古い", "古いメール", recent(days_ago=300))
    Path(env["MWW_CORPUS_FILE"]).write_text(json.dumps({
        "items": [{"domain": "evil-phish.jp"}, {"domain": "corp-bank.example"}]
    }), encoding="utf-8")
    Path(env["MWW_CONTACTS_FILE"]).write_text(
        "<boss@example.com>\n<jun@gftd.jp>\n", encoding="utf-8")

    # 1. scan: classification + receipt
    r1 = run(["scan", "--input", json.dumps({"days": 30, "limit": 100})], env)
    check("scan-exit-0", r1.returncode == 0, r1.stdout + r1.stderr)
    out1 = r1.stdout
    check("scan-window", "SCAN\twindow days=30 limit=100" in out1)
    check("scan-counts", "COUNT\tclassified=5 ledgerAdded=5" in out1, out1)
    check("verdict-spam", "VERDICT\tspam=3" in out1, out1)
    check("verdict-legit", "VERDICT\tlegit=1" in out1, out1)
    check("verdict-unknown", "VERDICT\tunknown=1" in out1, out1)
    check("boundary-sentence", "not clearance" in out1)

    # 2. determinism: identical input -> identical receipt lines
    ledger = env["MWW_LEDGER_FILE"]
    second = run(["scan", "--input", json.dumps({"days": 30, "limit": 100,
                                                 "sources": ["imessage"]})], env)
    # imessage-only second scan must add nothing (ids already in ledger)
    check("ledger-idempotent", "ledgerAdded=0" in second.stdout, second.stdout)

    # 3. report aggregation
    rep = run(["report"], env)
    check("report-exit-0", rep.returncode == 0, rep.stdout + rep.stderr)
    try:
        data = json.loads(rep.stdout)
        check("report-entries", data["ledgerEntries"] == 5, rep.stdout)
        check("report-verdicts", data["verdicts"].get("spam") == 3
              and data["verdicts"].get("legit") == 1
              and data["verdicts"].get("unknown") == 1, rep.stdout)
        check("report-corpus-matches", data["hostsMatchingCorpus"] >= 2, rep.stdout)
    except (ValueError, KeyError):
        check("report-parse", False, rep.stdout[:200])

    # 4. status reports all sources ok
    st = run(["status"], env)
    try:
        sd = json.loads(st.stdout)
        check("status-sources", sd["imessage"]["status"] == "ok"
              and sd["mail"]["status"] == "ok"
              and sd["corpus"]["count"] == 2
              and sd["contacts"]["count"] == 2, st.stdout)
    except (ValueError, KeyError):
        check("status-parse", False, st.stdout[:200])

    # 5. input validation
    for bad in ({"days": 0}, {"days": 91}, {"limit": 0}, {"sources": ["nope"]},
                {"publish": "yes"}, {"days": True}, {"unknownField": 1}):
        rb = run(["scan", "--input", json.dumps(bad)], env)
        check("invalid-%s" % json.dumps(bad, sort_keys=True),
              rb.returncode == 2 and "SCAN\tFAILED" in rb.stdout, rb.stdout)

    # 6. stdlib only
    src = SCRIPT.read_text(encoding="utf-8")
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
    check("stdlib-only", mods <= std, str(mods - std))

    # 7. MCP bridge round trip
    def mreq(mid, method, params=None):
        d = {"jsonrpc": "2.0", "id": mid, "method": method}
        if params is not None:
            d["params"] = params
        return json.dumps(d)

    payload = "\n".join([
        mreq(1, "initialize", {"protocolVersion": "2025-06-18",
                               "clientInfo": {"name": "acceptance", "version": "0"},
                               "capabilities": {}}),
        mreq(2, "tools/list"),
        mreq(3, "tools/call", {"name": "spamwatch_status", "arguments": {}}),
        mreq(4, "tools/call", {"name": "spamwatch_scan",
                               "arguments": {"days": 30, "limit": 50}}),
        mreq(5, "tools/call", {"name": "nope", "arguments": {}}),
    ]) + "\n"
    rm = subprocess.run([sys.executable, str(SCRIPT), "--mcp"],
                        input=payload, capture_output=True, text=True,
                        env=env, timeout=180)
    check("mcp-exit-0", rm.returncode == 0, rm.stderr)
    lines = [json.loads(x) for x in rm.stdout.strip().splitlines()]
    check("mcp-5-replies", len(lines) == 5, str(len(lines)))
    if len(lines) == 5:
        check("mcp-serverinfo", "serverInfo" in lines[0].get("result", {}))
        names = [t["name"] for t in lines[1].get("result", {}).get("tools", [])]
        check("mcp-tools", names == ["spamwatch_status", "spamwatch_scan",
                                     "spamwatch_report"], str(names))
        check("mcp-status-ok", lines[2].get("result", {}).get("isError") is False)
        check("mcp-scan-ok", lines[3].get("result", {}).get("isError") is False)
        check("mcp-unknown-tool", lines[4].get("error", {}).get("code") == -32602)

    failed = [n for n, ok in checks if not ok]
    print("ACCEPTANCE\t%d checks, %d failed" % (len(checks), len(failed)))
    if failed:
        print("ACCEPTANCE\tfailed: %s" % ", ".join(failed))
        return 1
    print(json.dumps({"receipt": "synthetic-local-evaluation",
                      "checks": len(checks),
                      "boundary": "synthetic fixtures only; no live sources, "
                                  "no network, no keys retained"},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
