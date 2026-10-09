#!/usr/bin/env python3
"""mithril-message-spam-watch: deterministic local spam/phishing triage.

Reads the operator's local iMessage database (chat.db), Mail mbox files
(.emlx), the Contacts.app cache, and the phishing_dns corpus, then classifies
each in-window message as spam / legit / unknown using deterministic rules.
No LLM inference. Publishes observations + manifest to R2 with read-back
sha256 verification, and archives both to Google Drive (warn-and-continue).

Read-only over sources: the script never sends messages, writes mail, or
mutates the address book. Failures are recorded, never marked safe.

Usage:
    python3 message_spam_watch.py status
    python3 message_spam_watch.py scan --input '{"days":30}'
    python3 message_spam_watch.py report
    python3 message_spam_watch.py refresh-contacts
    python3 message_spam_watch.py --mcp     # stdio JSON-RPC bridge

Environment overrides (fixtures):
    MWW_MAIL_ROOT, MWW_CHAT_DB, MWW_CONTACTS_FILE, MWW_CORPUS_FILE,
    MWW_LEDGER_FILE, MWW_PUBLISH_FILE
"""
import argparse
import email.utils
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from email.header import decode_header

# ---------------------------------------------------------------- constants

VERSION = "0.1.0"
SLUG = "message-spam-watch"
BUCKET = "internal-security-nvd"
CF_ACCOUNT = "62e1fda53188460698f8c66d3aef59c6"
APPLE_EPOCH_OFFSET = 978307200  # 2001-01-01 in Unix seconds
HEADER_BYTES = 65536
BODY_BYTES = 4096
SUBJECT_MAX = 200
RECEIPT_BOUNDARY = ("verdicts are deterministic local evidence observations; "
                    "unknown and not-spam are not clearance")

DEFAULT_MAIL_ROOT = os.path.expanduser("~/Library/Mail/V10")
DEFAULT_CHAT_DB = os.path.expanduser("~/Library/Messages/chat.db")
DEFAULT_CORPUS = os.path.expanduser("~/knowledge-datasets/phishing_dns/phishing_dns.json")
PROFILE_DIR = os.environ.get("MWW_PROFILE_DIR",
                             os.path.expanduser("~/.hermes/profiles/mithril-message-spam-watch"))
DATA_DIR = os.path.join(PROFILE_DIR, "data")
CANON_DIR = os.path.join(DATA_DIR, "canonical")
PERSIST = os.path.expanduser("~/.wrangler/remotepersist")

DEFAULT_CONTACTS_FILE = os.path.join(DATA_DIR, "contacts.json")
DEFAULT_LEDGER_FILE = os.path.join(CANON_DIR, "ledger.jsonl")
DEFAULT_PUBLISH_FILE = os.path.join(CANON_DIR, "observations.json")

CORPUS_MAX_DOMAINS = 2000
CONTACTS_MAX_LINES = 5000
PUBLISH_MAX_SUBJECTS = 2000

LURE_WORDS = [
    ("lure-points", ("ポイント", "進呈", "bonus points", "free points", "get your points")),
    ("lure-2fa", ("二段階認証", "2段階認証", "two-factor", "two factor")),
    ("lure-shipping", ("届出", "配達", "配送", "送料", "shipping", "delivery")),
    ("lure-balance", ("残高調整", "残高", "balance adjustment", "your balance")),
    ("lure-renewal", ("更新", "renewal", "renew")),
    ("lure-deadline", ("期限", "締切", "deadline")),
    ("lure-notice", ("お知らせ", "notification")),
    ("lure-action", ("確認してください", "確認手続き", "手続き", "登録", "変更",
                     "click here", "verify your", "confirm your")),
    ("lure-amount", ("振込", "送金", "transfer", "withdrawal")),
]
OTP_RE = re.compile(r"((?:ワンタイム|認証|確認|検証|セキュリティ)?\s*(?:コード|code)|"
                    r"verification code|one-time code|otp code)", re.IGNORECASE)
EMAIL_SNDER_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
URL_RE = re.compile(r"https?://[A-Za-z0-9.-]+", re.IGNORECASE)
PHONE_RE = re.compile(r"^\d{6,14}$")
DATE_WINDOW_MIN = 1
DATE_WINDOW_MAX = 90
LIMIT_MIN = 1
LIMIT_MAX = 5000
MAX_MAIL_FILES = 500
MAX_MSGS_PER_SOURCE = 2000


def env_or(name, default):
    return os.environ.get(name) or default


# ---------------------------------------------------------------- helpers

def now_utc():
    return datetime.now(timezone.utc)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                b = f.read(chunk)
                if not b:
                    break
                h.update(b)
        return h.hexdigest()
    except OSError:
        return None


def atomic_write_bytes(path, data):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def norm_host(s):
    s = (s or "").strip().lower().rstrip(".")
    s = s.split("/")[0].split("?")[0]
    s = s.split("@")[-1]
    if ":" in s:
        s = s.rsplit(":", 1)[0]
    return s


def extract_hosts(text):
    hosts = set()
    for m in URL_RE.findall(text or ""):
        host = norm_host(m[len("http://"):] if m.lower().startswith("http://") else
                          m[len("https://"):] if m.lower().startswith("https://") else m)
        if host:
            hosts.add(host)
    for m in re.findall(r"\b[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text or ""):
        host = norm_host(m)
        if host.count(".") >= 1 and host not in ("a.m",):
            hosts.add(host)
    return {h for h in hosts if len(h) >= 3 and re.search(r"[a-z]", h, re.I)}


def extract_email_addrs(text):
    return {a.lower() for a in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
                                          text or "")}


def decode_subject(raw, limit=SUBJECT_MAX):
    if raw is None:
        return ""
    parts = []
    for chunk, enc in decode_header(raw):
        if isinstance(chunk, bytes):
            try:
                parts.append(chunk.decode(enc or "utf-8", "replace"))
            except (LookupError, UnicodeDecodeError):
                parts.append(chunk.decode("utf-8", "replace"))
        else:
            parts.append(chunk)
    out = re.sub(r"\s+", " ", " ".join(parts)).strip()
    return out[:limit]


def text_of(raw_bytes):
    """Decode bounded raw bytes from an emlx file (headers + first body)."""
    if not raw_bytes:
        return ""
    if raw_bytes.startswith(b"\xff\xfe") or raw_bytes.startswith(b"\xfe\xff"):
        enc = "utf-16"
    elif b"\x00" in raw_bytes[:8]:
        enc = "utf-16"
    else:
        enc = "utf-8"
    try:
        return raw_bytes.decode(enc, "replace")
    except (LookupError, UnicodeDecodeError):
        return raw_bytes.decode("utf-8", "replace")


def parse_mail_date(raw):
    if not raw:
        return None
    try:
        d = email.utils.parsedate_to_datetime(raw)
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.astimezone(timezone.utc)
    except (TypeError, ValueError, IndexError):
        return None


# ---------------------------------------------------------------- sources

def corpus_load(path):
    p = env_or("MWW_CORPUS_FILE", path or DEFAULT_CORPUS)
    if not p or not os.path.isfile(p):
        return {"available": False, "domains": set(), "sha256": None, "count": 0, "path": p}
    sha = sha256_file(p)
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        items = data.get("items") if isinstance(data, dict) else data
        if not isinstance(items, list):
            items = []
    except (OSError, ValueError):
        return {"available": False, "domains": set(), "sha256": sha, "count": 0, "path": p}
    domains = set()
    for it in items:
        d = (it or {}).get("domain") if isinstance(it, dict) else None
        if isinstance(d, str) and d:
            domains.add(d.lower().strip().rstrip("."))
            if len(domains) >= CORPUS_MAX_DOMAINS:
                break
    return {"available": True, "domains": domains, "sha256": sha,
            "count": len(domains), "path": p}


def contacts_load(path):
    p = env_or("MWW_CONTACTS_FILE", path or DEFAULT_CONTACTS_FILE)
    if not p or not os.path.isfile(p):
        return {"available": False, "addresses": set(), "domains": set(), "count": 0, "path": p}
    try:
        with open(p, "r", encoding="utf-8") as f:
            lines = [ln for ln in f if ln.strip()][:CONTACTS_MAX_LINES]
    except OSError:
        return {"available": False, "addresses": set(), "domains": set(), "count": 0, "path": p}
    addresses = set()
    for ln in lines:
        m = re.match(r"^\s*<([^<>]+)>\s*$", ln)
        addr = (m.group(1) if m else ln).strip().lower()
        if re.fullmatch(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", addr):
            addresses.add(addr)
    domains = {a.split("@", 1)[1] for a in addresses if "@" in a}
    return {"available": True, "addresses": addresses, "domains": domains,
            "count": len(addresses), "path": p}


def chat_db_available(path):
    p = env_or("MWW_CHAT_DB", path or DEFAULT_CHAT_DB)
    return bool(p) and os.access(p, os.R_OK)


def imessage_scan(path, since, limit, corpus, contacts):
    p = env_or("MWW_CHAT_DB", path or DEFAULT_CHAT_DB)
    if not p or not os.path.isfile(p) or not os.access(p, os.R_OK):
        return {"status": "unavailable", "reason": "chat.db missing or unreadable (Full Disk Access?)",
                "items": [], "window_count": 0, "count": 0, "last_seen": None}
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % p, uri=True)
    except sqlite3.OperationalError as e:
        return {"status": "unavailable", "reason": "chat.db open failed: %s" % e,
                "items": [], "window_count": 0, "count": 0, "last_seen": None}
    since_apple = int((since.timestamp() - APPLE_EPOCH_OFFSET) * 1_000_000_000)
    items = []
    try:
        cur = conn.execute(
            "SELECT m.rowid, m.text, h.id, m.date, m.is_spam "
            "FROM message m JOIN handle h ON m.handle_id = h.rowid "
            "WHERE m.is_from_me = 0 AND m.text IS NOT NULL AND m.date >= ? "
            "ORDER BY m.date DESC LIMIT ?",
            (since_apple, limit))
        for rowid, text, handle, date_apple, is_spam in cur:
            ts = (date_apple / 1e9 + APPLE_EPOCH_OFFSET)
            items.append({
                "id": "imsg:%d" % rowid,
                "source": "imessage",
                "sender": handle or "",
                "subject": "",
                "text": text,
                "observedAt": datetime.fromtimestamp(ts, timezone.utc).isoformat(),
                "flags": {"is_spam": bool(is_spam)},
            })
    except sqlite3.Error as e:
        return {"status": "error", "reason": "chat.db query failed: %s" % e,
                "items": [], "window_count": 0, "count": 0, "last_seen": None}
    finally:
        conn.close()
    window_count = len(items)
    items = items[:MAX_MSGS_PER_SOURCE]
    last_seen = max((i["observedAt"] for i in items), default=None)
    return {"status": "ok", "reason": None, "items": items,
            "window_count": window_count, "count": len(items), "last_seen": last_seen}


def mail_linecount_prefix(raw):
    """macOS Mail V10 .emlx files begin with a '<linecount><spaces>\\n'
    prefix before the real message. Detect and skip it."""
    if not raw:
        return 0
    i = 0
    n = len(raw)
    while i < n and raw[i:i + 1].isdigit():
        i += 1
    j = i
    while j < n and raw[j:j + 1] == b" ":
        j += 1
    if j < n and raw[j:j + 1] == b"\n" and i > 0 and i < 12:
        return j + 1
    return 0


def mail_scan(root, since, limit):
    r = env_or("MWW_MAIL_ROOT", root or DEFAULT_MAIL_ROOT)
    if not r or not os.path.isdir(r):
        return {"status": "unavailable", "reason": "mail root missing", "items": [],
                "window_count": 0, "count": 0, "last_seen": None, "scanned": 0}
    files = []
    for dirpath, _dirs, names in os.walk(r):
        for n in names:
            if n.endswith(".emlx") and not n.endswith(".partial.emlx"):
                files.append(os.path.join(dirpath, n))
    if len(files) > MAX_MAIL_FILES:
        files.sort(key=os.path.getmtime, reverse=True)
        files = files[:MAX_MAIL_FILES]
    items = []
    for path in files:
        try:
            with open(path, "rb") as f:
                raw = f.read(HEADER_BYTES + BODY_BYTES)
        except OSError:
            continue
        text = text_of(raw[mail_linecount_prefix(raw):])
        try:
            msg = email.message_from_string(text[:HEADER_BYTES + BODY_BYTES])
        except Exception:
            continue
        sender_raw = msg.get("From") or ""
        sender = extract_email_addrs(sender_raw)
        sender = next(iter(sorted(sender)), None)
        subject = decode_subject(msg.get("Subject"))
        auth = (msg.get("Authentication-Results") or "").lower()
        date_raw = msg.get("Date")
        d = parse_mail_date(date_raw)
        if d is None:
            continue
        if d < since:
            continue
        # bounded body: everything after the header terminator
        head = text[:HEADER_BYTES]
        if "\r\n\r\n" in head:
            body = text.split("\r\n\r\n", 1)[1]
        elif "\n\n" in head:
            body = text.split("\n\n", 1)[1]
        else:
            body = ""
        body = body[:BODY_BYTES]
        text_all = subject + "\n" + body
        items.append({
            "id": "mail:%s" % msg.get("Message-ID", path).strip().strip("><"),
            "source": "mail",
            "sender": sender or "",
            "subject": subject,
            "text": text_all,
            "observedAt": d.isoformat(),
            "flags": {
                "spf_fail": "spf=fail" in auth,
                "dmarc_fail": ("dmarc=fail" in auth),
                "date": date_raw,
            },
        })
    items.sort(key=lambda i: i["observedAt"], reverse=True)
    items = items[:limit]
    return {"status": "ok", "reason": None, "items": items,
            "window_count": len(items), "count": len(items),
            "last_seen": max((i["observedAt"] for i in items), default=None),
            "scanned": len(files)}


# ---------------------------------------------------------------- classify

def corpus_match(hosts, corpus):
    out = set()
    for h in hosts:
        if h in corpus["domains"]:
            out.add(h)
        else:
            for dot in h.split("."):
                if dot and h.endswith("." + dot):
                    if dot in corpus["domains"]:
                        out.add(h)
                        break
    return out


def classify_item(item, corpus, contacts):
    sender = (item.get("sender") or "").strip().lower()
    hosts = extract_hosts(item.get("text") or "")
    sender_hosts = extract_hosts(sender)
    text = item.get("text") or ""
    lures = [name for name, words in LURE_WORDS
             if any(w.lower() in text.lower() for w in words)]
    reasons = []
    otp = bool(OTP_RE.search(text))
    corpus_hits = corpus_match(hosts | sender_hosts, corpus)
    verdict = "unknown"
    if corpus_hits:
        verdict = "spam"
        reasons.append("corpus-host")
    elif sender and EMAIL_SNDER_RE.fullmatch(sender) and lures:
        verdict = "spam"
        reasons.append("email-shaped-sender")
        reasons.extend("lure:" + r for r in lures)
    elif sender and EMAIL_SNDER_RE.fullmatch(sender) and (hosts or otp):
        verdict = "spam"
        reasons.append("email-shaped-sender")
        if hosts:
            reasons.append("url-host")
        if otp:
            reasons.append("otp-or-verification")
    elif lures and hosts:
        verdict = "spam"
        reasons.extend("lure:" + r for r in lures)
        reasons.append("url-host")
    elif lures and otp:
        verdict = "unknown"
        reasons.extend("lure:" + r for r in lures)
        reasons.append("otp-or-verification")
    elif item["source"] == "mail" and item["flags"].get("dmarc_fail"):
        verdict = "spam"
        reasons.append("dmarc-fail")
    elif item["source"] == "mail" and item["flags"].get("spf_fail"):
        reasons.append("spf-fail")
    # contact whitelisting: a contact sender with no spam signals is legit
    is_contact = False
    if contacts["available"]:
        if sender in contacts["addresses"]:
            is_contact = True
        elif item["source"] == "mail" and sender and \
                sender.split("@", 1)[1] in contacts["domains"]:
            is_contact = True
    if is_contact:
        if verdict == "spam":
            reasons.append("contact-sender-overrides")
            reasons.insert(0, "contact-sender")
            # corpus beats contact: keep spam, note both
            if "corpus-host" not in reasons:
                verdict = "unknown"
        else:
            if verdict == "unknown":
                verdict = "legit"
            reasons.insert(0, "contact-sender")
    if item["source"] == "imessage" and item["flags"].get("is_spam"):
        reasons.append("imessage-is_spam")
    if PHONE_RE.fullmatch(sender):
        reasons.append("short-code-sender" if len(sender) <= 6 else "phone-sender")
    if otp:
        reasons.append("otp-or-verification")
    if hosts and "url-host" not in reasons:
        reasons.append("url-host")
    for r in lures:
        reasons.append("lure:" + r)
    seen = set()
    dedup = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            dedup.append(r)
    if not hosts:
        reasons = [r for r in dedup if r != "url-host"]
    else:
        reasons = dedup
    if not reasons:
        reasons = ["no-signal"]
    return {
        "verdict": verdict,
        "reasonCodes": reasons[:12],
        "hosts": sorted(hosts | sender_hosts)[:20],
    }


def scan_items(items, corpus, contacts):
    out = []
    for item in items:
        c = classify_item(item, corpus, contacts)
        out.append({
            "id": item["id"],
            "source": item["source"],
            "sender": item["sender"],
            "subject": item.get("subject", ""),
            "observedAt": item["observedAt"],
            "verdict": c["verdict"],
            "reasonCodes": c["reasonCodes"],
            "hosts": c["hosts"],
        })
    return out


# ---------------------------------------------------------------- ledger

def ledger_load(path):
    p = env_or("MWW_LEDGER_FILE", path or DEFAULT_LEDGER_FILE)
    out = {}
    if not os.path.isfile(p):
        return out
    try:
        with open(p, "r", encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    rec = json.loads(ln)
                    if isinstance(rec, dict) and "id" in rec:
                        out[rec["id"]] = rec
                except ValueError:
                    continue
    except OSError:
        return out
    return out


def ledger_append(path, new_entries, observed_at):
    p = env_or("MWW_LEDGER_FILE", path or DEFAULT_LEDGER_FILE)
    cur = ledger_load(p)
    added = 0
    for e in new_entries:
        if e["id"] not in cur:
            rec = dict(e)
            rec["schema"] = SLUG + "/ledger/entry/v1"
            cur[e["id"]] = rec
            added += 1
    if cur or not os.path.isfile(p):
        lines = [json.dumps(cur[k], ensure_ascii=False, sort_keys=True)
                 for k in sorted(cur)]
        atomic_write_bytes(p, ("\n".join(lines) + "\n").encode("utf-8"))
    return added


def report_build(ledger_path, corpus_path):
    entries = list(ledger_load(ledger_path).values())
    corpus = corpus_load(corpus_path)
    verdicts = {}
    sources = {}
    hosts = {}
    for e in entries:
        v = e.get("verdict", "unknown")
        verdicts[v] = verdicts.get(v, 0) + 1
        s = e.get("source", "unknown")
        sources[s] = sources.get(s, 0) + 1
        for h in e.get("hosts") or []:
            hosts[h] = hosts.get(h, 0) + 1
    corpus_hits = 0
    doms = corpus["domains"]
    for h in hosts:
        if h in doms or any(h.endswith("." + d) for d in doms):
            corpus_hits += 1
    top_hosts = sorted(hosts.items(), key=lambda kv: (-kv[1], kv[0]))[:50]
    return {
        "schema": SLUG + "/report/v1",
        "ledgerEntries": len(entries),
        "verdicts": verdicts,
        "sources": sources,
        "topHosts": [{"host": h, "count": c} for h, c in top_hosts],
        "hostsMatchingCorpus": corpus_hits,
        "corpus": {"available": corpus["available"], "count": corpus["count"],
                   "sha256": corpus["sha256"]},
        "boundary": RECEIPT_BOUNDARY,
    }


# ---------------------------------------------------------------- publish

def publish(observations, manifest, dry_run):
    obs_bytes = json.dumps(observations, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    man_bytes = json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    obs_sha = sha256_bytes(obs_bytes)
    man_sha = sha256_bytes(man_bytes)
    os.makedirs(CANON_DIR, exist_ok=True)
    pfile = env_or("MWW_PUBLISH_FILE", DEFAULT_PUBLISH_FILE)
    atomic_write_bytes(pfile, obs_bytes)
    mfile = pfile + ".manifest"
    atomic_write_bytes(mfile, man_bytes)
    out = []
    out.append("PUBLISH\tlocal %s sha=%s" % (pfile, obs_sha[:12]))
    if dry_run:
        out.append("PUBLISH\tdry-run (no R2, no Drive)")
        return out
    if shutil.which("wrangler") is None:
        out.append("PUBLISH\tWARN wrangler not found; R2 skipped")
    else:
        ok = True
        for key, path, want in (
            ("%s/observations.json" % SLUG, pfile, obs_sha),
            ("%s/manifest.json" % SLUG, mfile, man_sha),
        ):
            rb = path + ".rb"
            env_pre = "CLOUDFLARE_ACCOUNT_ID=%s " % CF_ACCOUNT
            put = subprocess.run(
                ["bash", "-c", env_pre +
                 "wrangler r2 object put %s/%s --file %s "
                 "--content-type application/json --remote --persist-to=%s"
                 % (BUCKET, key, path, PERSIST)],
                capture_output=True, text=True, timeout=120, cwd="/tmp")
            if put.returncode != 0:
                out.append("READBACK\tFAILED %s put rc=%s %s"
                           % (key, put.returncode, (put.stderr or put.stdout)[:200]))
                ok = False
                break
            get = subprocess.run(
                ["bash", "-c", env_pre +
                 "wrangler r2 object get %s/%s --file %s --remote --persist-to=%s"
                 % (BUCKET, key, rb, PERSIST)],
                capture_output=True, text=True, timeout=120, cwd="/tmp")
            if get.returncode != 0:
                out.append("READBACK\tFAILED %s get rc=%s %s"
                           % (key, get.returncode, (get.stderr or get.stdout)[:200]))
                ok = False
                break
            got = sha256_bytes(open(rb, "rb").read())
            if os.path.exists(rb):
                os.unlink(rb)
            if got != want:
                out.append("READBACK\tFAILED %s sha mismatch local=%s remote=%s"
                           % (key, want[:8], got[:8]))
                ok = False
            else:
                out.append("READBACK\tMATCH %s" % key)
        if ok:
            out.append("PUBLISH\tR2 %s/%s ok" % (BUCKET, SLUG))
    # Drive archive (warn-and-continue)
    rconf = env_or("MWW_RCLONE_CONF", None)
    if not rconf:
        local_conf = os.path.join(DATA_DIR, "rclone.conf")
        legacy_conf = os.path.join(os.path.dirname(PROFILE_DIR),
                                   "mithril-phishing-watch-ops", "data", "rclone.conf")
        rconf = local_conf if os.path.isfile(local_conf) else legacy_conf
    if shutil.which("rclone") is not None and rconf and os.path.isfile(rconf):
        today = now_utc().strftime("%Y-%m-%d")
        dest = "jklux:%s_%s_%s" % (SLUG, SLUG.replace("mithril-", "mithril-"), today)
        for src in (pfile, mfile):
            c = subprocess.run(
                ["rclone", "--config", rconf, "copyto", src, dest + "/" + os.path.basename(src)],
                capture_output=True, text=True, timeout=180)
            if c.returncode != 0:
                out.append("DRIVE\tWARN copyto %s rc=%s %s"
                           % (os.path.basename(src), c.returncode, (c.stderr or c.stdout)[:120]))
            else:
                l = subprocess.run(
                    ["rclone", "--config", rconf, "lsf", dest + "/" + os.path.basename(src)],
                    capture_output=True, text=True, timeout=60)
                if os.path.basename(src) in (l.stdout or "").splitlines():
                    out.append("DRIVE\tMATCH %s (%s)" % (os.path.basename(src), dest))
                else:
                    out.append("DRIVE\tWARN read-back %s" % os.path.basename(src))
    else:
        out.append("PUBLISH\tWARN Drive step skipped (rclone or jklux conf missing)")
    return out


# ---------------------------------------------------------------- tools

def tool_status(args):
    args = args or {}
    db = env_or("MWW_CHAT_DB", DEFAULT_CHAT_DB)
    mail_root = env_or("MWW_MAIL_ROOT", DEFAULT_MAIL_ROOT)
    corpus = corpus_load(None)
    contacts = contacts_load(None)
    db_state = "ok" if (os.path.isfile(db) and os.access(db, os.R_OK)) else "unavailable"
    mail_files = 0
    if os.path.isdir(mail_root):
        for _dp, _dn, names in os.walk(mail_root):
            mail_files += sum(1 for n in names if n.endswith(".emlx") and
                              not n.endswith(".partial.emlx"))
            if mail_files > 100000:
                break
    return {
        "schema": SLUG + "/status/v1",
        "version": VERSION,
        "imessage": {"path": db, "status": db_state},
        "mail": {"root": mail_root, "status": "ok" if os.path.isdir(mail_root) else "unavailable",
                 "emlx_files": mail_files},
        "contacts": {"path": contacts["path"], "status": "ok" if contacts["available"] else "unavailable",
                     "count": contacts["count"]},
        "corpus": {"path": corpus["path"], "status": "ok" if corpus["available"] else "unavailable",
                   "count": corpus["count"], "sha256": corpus["sha256"]},
        "ledger": {"path": env_or("MWW_LEDGER_FILE", DEFAULT_LEDGER_FILE),
                   "entries": len(ledger_load(None))},
        "boundary": RECEIPT_BOUNDARY,
    }


SCAN_INPUT = {
    "sources": {"type": "array", "items": {"type": "string", "enum": ["imessage", "mail"]}},
    "days": {"type": "number", "minimum": DATE_WINDOW_MIN, "maximum": DATE_WINDOW_MAX},
    "limit": {"type": "integer", "minimum": LIMIT_MIN, "maximum": LIMIT_MAX},
    "corpusPath": {"type": "string", "maxLength": 512},
    "contactsPath": {"type": "string", "maxLength": 512},
    "mailRoot": {"type": "string", "maxLength": 512},
    "publish": {"type": "boolean"},
}


def validate_scan_input(a):
    if a is None:
        a = {}
    if not isinstance(a, dict):
        return "input must be an object"
    for k in a:
        if k not in SCAN_INPUT:
            return "unknown input field: %s" % k
    if "sources" in a:
        s = a["sources"]
        if not isinstance(s, list) or not s or not all(x in ("imessage", "mail") for x in s):
            return "sources must be a nonempty subset of [imessage, mail]"
    if "days" in a:
        d = a["days"]
        if isinstance(d, bool) or not isinstance(d, (int, float)) or \
                d < DATE_WINDOW_MIN or d > DATE_WINDOW_MAX:
            return "days must be a number in [%d, %d]" % (DATE_WINDOW_MIN, DATE_WINDOW_MAX)
    if "limit" in a:
        l = a["limit"]
        if not isinstance(l, int) or isinstance(l, bool) or l < LIMIT_MIN or l > LIMIT_MAX:
            return "limit must be an integer in [%d, %d]" % (LIMIT_MIN, LIMIT_MAX)
    if "publish" in a and not isinstance(a["publish"], bool):
        return "publish must be a boolean"
    for k in ("corpusPath", "contactsPath", "mailRoot"):
        if k in a and not isinstance(a[k], str):
            return "%s must be a string" % k
    return None


def tool_scan(args):
    err = validate_scan_input(args)
    if err:
        return {"ok": False, "error": "invalid_input", "detail": err}
    args = args or {}
    sources = args.get("sources") or ["imessage", "mail"]
    days = args.get("days") or 7
    limit = args.get("limit") or 500
    now = now_utc()
    since = now - timedelta(days=days)
    corpus = corpus_load(args.get("corpusPath"))
    contacts = contacts_load(args.get("contactsPath"))
    result = {"imessage": None, "mail": None}
    all_items = []
    for src in sources:
        if src == "imessage":
            r = imessage_scan(None, since, limit, corpus, contacts)
            result["imessage"] = r
            all_items.extend(r["items"])
        else:
            r = mail_scan(args.get("mailRoot"), since, limit)
            result["mail"] = r
            all_items.extend(r["items"])
    classified = scan_items(all_items, corpus, contacts)
    added = 0
    if classified:
        os.makedirs(CANON_DIR, exist_ok=True)
        added = ledger_append(None, classified, now.isoformat())
    verdicts = {}
    for c in classified:
        verdicts[c["verdict"]] = verdicts.get(c["verdict"], 0) + 1
    subjects = sorted({c["subject"] for c in classified if c["subject"]})[:PUBLISH_MAX_SUBJECTS]
    observations = {
        "schema": SLUG + "/observations/v1",
        "generatedAt": now.isoformat(),
        "window": {"since": since.isoformat(), "days": days, "limit": limit},
        "sources": {
            "imessage": {"status": (result["imessage"] or {}).get("status")},
            "mail": {"status": (result["mail"] or {}).get("status")},
        },
        "items": classified,
        "subjects": subjects,
        "boundary": RECEIPT_BOUNDARY,
    }
    obs_bytes = json.dumps(observations, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    obs_sha = sha256_bytes(obs_bytes)
    manifest = {
        "dataset": SLUG,
        "generatedAt": now.isoformat(),
        "files": [
            {"key": "%s/observations.json" % SLUG, "bytes": len(obs_bytes), "sha256": obs_sha},
        ],
    }
    man_bytes = json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    receipt = {
        "scanAt": now.isoformat(),
        "window": {"days": days, "limit": limit},
        "sourceStatus": {
            "imessage": (result["imessage"] or {}).get("status"),
            "mail": (result["mail"] or {}).get("status"),
        },
        "counts": {
            "imessage": (result["imessage"] or {}).get("count"),
            "mail": (result["mail"] or {}).get("count"),
            "mailFilesScanned": (result["mail"] or {}).get("scanned"),
            "classified": len(classified),
            "ledgerAdded": added,
        },
        "verdicts": verdicts,
        "corpus": {"available": corpus["available"], "count": corpus["count"],
                   "sha256": corpus["sha256"]},
        "observationsSha256": obs_sha,
        "boundary": RECEIPT_BOUNDARY,
    }
    out = {"ok": True, "receipt": receipt, "publish": None}
    if args.get("publish"):
        out["publish"] = publish(observations, manifest, dry_run=False)
    if not args.get("publish"):
        os.makedirs(CANON_DIR, exist_ok=True)
        pf = env_or("MWW_PUBLISH_FILE", DEFAULT_PUBLISH_FILE)
        atomic_write_bytes(pf, obs_bytes)
        atomic_write_bytes(pf + ".manifest", man_bytes)
    return out


def tool_report(args):
    args = args or {}
    return report_build(None, args.get("corpusPath"))


def refresh_contacts():
    os.makedirs(DATA_DIR, exist_ok=True)
    script = (
        'set out to ""\n'
        'tell application "Contacts"\n'
        '  repeat with p in people\n'
        '    repeat with ea in emails of p\n'
        '      set out to out & "<" & (value of ea) & ">" & linefeed\n'
        '    end repeat\n'
        '  end repeat\n'
        'end tell\n'
        'return out')
    try:
        r = subprocess.run(["osascript", "-e", script],
                           capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"ok": False, "error": "contacts_refresh_failed", "detail": str(e)}
    if r.returncode != 0:
        return {"ok": False, "error": "contacts_refresh_failed",
                "detail": (r.stderr or r.stdout)[:200]}
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()][:CONTACTS_MAX_LINES]
    p = env_or("MWW_CONTACTS_FILE", DEFAULT_CONTACTS_FILE)
    stamp = now_utc().isoformat()
    doc = {"schema": SLUG + "/contacts/v1", "refreshedAt": stamp,
           "lines": lines}
    atomic_write_bytes(p + ".json",
                       json.dumps(doc, ensure_ascii=False).encode("utf-8"))
    # also keep the plain-line file the loader reads
    atomic_write_bytes(p, ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8"))
    c = contacts_load(p)
    return {"ok": True, "count": c["count"], "path": p, "refreshedAt": stamp}


# ---------------------------------------------------------------- MCP bridge

MCP_TOOLS = [
    {
        "name": "spamwatch_status",
        "description": "Report availability of local sources: iMessage chat.db, "
                       "Mail mbox root, Contacts cache and phishing_dns corpus. "
                       "Read-only, no network.",
        "inputSchema": {
            "type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "spamwatch_scan",
        "description": "Classify in-window local iMessage and Mail as spam/legit/unknown "
                       "with deterministic rules. Read-only over sources; optional R2 "
                       "publish with read-back. unknown is not clearance.",
        "inputSchema": {
            "type": "object",
            "properties": {k: dict(v) for k, v in SCAN_INPUT.items()},
            "additionalProperties": False},
    },
    {
        "name": "spamwatch_report",
        "description": "Aggregate the local classification ledger: verdict counts, "
                       "source counts, top hosts, hosts matching the phishing corpus. "
                       "Read-only.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "corpusPath": {"type": "string", "maxLength": 512}},
            "additionalProperties": False},
    },
]


def mcp_handle(m):
    if not isinstance(m, dict) or m.get("jsonrpc") != "2.0" or \
            not isinstance(m.get("method"), str):
        return {"jsonrpc": "2.0", "id": m.get("id") if isinstance(m, dict) else None,
                "error": {"code": -32600, "message": "Invalid request"}}
    mid = m.get("id")
    method = m["method"]
    if "id" not in m:
        return None  # notification
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "mithril-message-spam-watch", "version": VERSION}}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid,
                "result": {"tools": MCP_TOOLS}}
    if method == "tools/call":
        name = (m.get("params") or {}).get("name")
        a = (m.get("params") or {}).get("arguments")
        by = {t["name"]: t for t in MCP_TOOLS}
        if name not in by:
            return {"jsonrpc": "2.0", "id": mid,
                    "error": {"code": -32602, "message": "Unknown tool"}}
        if name == "spamwatch_scan" and (err := validate_scan_input(a)):
            return {"jsonrpc": "2.0", "id": mid,
                    "result": {"content": [{"type": "text",
                                            "text": json.dumps({"ok": False,
                                                                "error": "invalid_input",
                                                                "detail": err})}],
                               "isError": True}}
        try:
            if name == "spamwatch_status":
                v = tool_status(a)
            elif name == "spamwatch_scan":
                v = tool_scan(a)
            else:
                v = tool_report(a)
            return {"jsonrpc": "2.0", "id": mid,
                    "result": {"content": [{"type": "text",
                                            "text": json.dumps(v, ensure_ascii=False)}],
                               "structuredContent": v, "isError": False}}
        except Exception as e:  # noqa: BLE001 - machine-readable failure
            return {"jsonrpc": "2.0", "id": mid,
                    "result": {"content": [{"type": "text",
                                            "text": json.dumps({"ok": False,
                                                                "error": "refused",
                                                                "detail": str(e)[:200]})}],
                               "isError": True}}
    return {"jsonrpc": "2.0", "id": mid,
            "error": {"code": -32601, "message": "Method not found"}}


def mcp_main():
    state = "new"
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        if len(line) > 2_097_152:
            sys.stderr.write("message-spam-watch MCP: line too large\n")
            sys.exit(1)
        try:
            m = json.loads(line)
        except ValueError:
            print(json.dumps({"jsonrpc": "2.0", "id": None,
                              "error": {"code": -32700, "message": "Parse error"}}))
            continue
        if method_of(m) == "initialize" and state == "new":
            state = "initializing"
        resp = mcp_handle(m)
        if resp is not None:
            print(json.dumps(resp))
            sys.stdout.flush()
        if method_of(m) == "initialize" and state == "initializing":
            state = "ready"


def method_of(m):
    return m.get("method") if isinstance(m, dict) else None


# ---------------------------------------------------------------- CLI

def print_receipt_lines(result):
    if not result.get("ok"):
        print("SCAN\tFAILED %s" % (result.get("detail") or result.get("error")))
        return
    r = result["receipt"]
    print("SCAN\twindow days=%s limit=%s" % (r["window"]["days"], r["window"]["limit"]))
    for k in ("imessage", "mail"):
        print("SOURCE\t%s status=%s" % (k, r["sourceStatus"].get(k)))
    c = r["counts"]
    print("COUNT\tclassified=%s ledgerAdded=%s mailFilesScanned=%s"
          % (c["classified"], c["ledgerAdded"], c["mailFilesScanned"]))
    for v in ("spam", "legit", "unknown"):
        print("VERDICT\t%s=%s" % (v, r["verdicts"].get(v, 0)))
    print("CORPUS\tavailable=%s count=%s sha=%s"
          % (r["corpus"]["available"], r["corpus"]["count"],
             (r["corpus"]["sha256"] or "")[:12]))
    print("RECEIPT\t%s %s" % (r["observationsSha256"], r["boundary"]))
    for pl in (result.get("publish") or []):
        print(pl)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="message_spam_watch")
    ap.add_argument("--mcp", action="store_true", help="run stdio MCP bridge")
    sub = ap.add_subparsers(dest="tool")
    sub.add_parser("status")
    sub.add_parser("report")
    sub.add_parser("refresh-contacts")
    p_scan = sub.add_parser("scan")
    p_scan.add_argument("--input", default="{}", help="JSON object of scan args")
    args = ap.parse_args(argv)
    if args.mcp:
        mcp_main()
        return 0
    if args.tool == "status":
        print(json.dumps(tool_status({}), ensure_ascii=False))
        return 0
    if args.tool == "report":
        print(json.dumps(tool_report({}), ensure_ascii=False))
        return 0
    if args.tool == "refresh-contacts":
        r = refresh_contacts()
        print(json.dumps(r, ensure_ascii=False))
        return 0 if r.get("ok") else 2
    if args.tool == "scan":
        try:
            data = json.loads(args.input or "{}")
        except ValueError as e:
            print("SCAN\tFAILED bad input json: %s" % e)
            return 2
        result = tool_scan(data)
        print_receipt_lines(result)
        return 0 if result.get("ok") else 2
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
