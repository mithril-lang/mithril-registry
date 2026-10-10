#!/usr/bin/env python3
"""Case-scoped bug bounty VRF tick (one profile per challenge).

Each owning profile runs this script on a schedule. It reviews every case
bound to the profile with the deterministic Mithril public review CLI,
keeps receipts and canonical state, publishes under its OWN R2 sub-prefix
(bounty-vrf/<case_id>/), archives to Google Drive jklux, and finally
writes a short status row back into the shared "Challenge Log" tab of the
bug bounty 360 spreadsheet via the Drive API (google_sheets_sync.py) —
no browser UI.

A profile may own several cases of one challenge (a program can list
several in-scope repositories); the secondary cases are denoted with a
trailing letter (BB-0002b). Secondary cases are reviewed + archived like
their primary case but are NOT written to the shared sheet (the sheet has
one row per challenge id, not per repository).

Environment:
  BBOPS_CASE             override the case binding (comma separated)
  BBOPS_PROFILE_DIR      owning profile dir (default: the script's parent)
  MITHRIL_SYSTEM_ONE_ROOT  reviewed checkout root
  BBOPS_SHEET_ID         spreadsheet id (default: the 360 sheet)
  BBOPS_SKIP_SHEET=1     disable the sheet write-back step (tests)
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
SYNC = HERE / "google_sheets_sync.py"

COMMIT_RE = re.compile(r"^[a-f0-9]{40}$")
SHORT_RE = re.compile(r"^[a-f0-9]{7,40}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REVIEW_TIMEOUT_S = 1800
RECOOLDOWN_S = 12 * 3600
R2_ACCOUNT = os.environ.get(
    "BOUNTY_VRF_R2_ACCOUNT", "62e1fda53188460698f8c66d3aef59c6")


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def profile_dir():
    env = os.environ.get("BBOPS_PROFILE_DIR")
    if env:
        return Path(env).expanduser()
    # the script lives in <profile>/scripts -> derive the profile from it
    return HERE.parent


def bound_cases(profile):
    """Return the list of case ids this profile owns.

    A challenge may span several in-scope repositories; the primary case
    carries the sheet row, the secondary cases (BB-0002b, ...) are
    reviewed + archived but not written to the shared sheet. Canonical
    ids keep the lowercase trailing suffix (BB-0002b).
    """
    env = os.environ.get("BBOPS_CASE", "").strip()
    if env:
        # env values must exactly match canonical ids (BB-0002, BB-0002b)
        return [c.strip() for c in env.split(",") if c.strip()]
    m = re.fullmatch(r"mithril-bb-([a-z0-9-]+)", profile.name, re.I)
    if not m:
        return []
    primary = ("BB-" + m.group(1)).upper()
    return [primary, primary + "b"]


def is_primary(case_id):
    """Primary challenge ids end in a digit/dash; secondaries carry a
    lowercase trailing letter suffix (BB-0002b)."""
    return re.fullmatch(r"BB-[A-Z0-9-]+[a-z]", case_id) is None


def sha256_bytes(b):
    import hashlib
    return hashlib.sha256(b).hexdigest()


def load_case(profile, case_id):
    """Load the case binding from canonical state (shared file, read-only)."""
    canonical = profile / "data" / "canonical" / "challenges.json"
    if canonical.is_file():
        try:
            data = json.loads(canonical.read_text())
            case = (data.get("cases") or {}).get(case_id)
            if isinstance(case, dict):
                return case
        except (OSError, ValueError):
            pass
    return None


def resolve_commit(repository, commit):
    if COMMIT_RE.match(commit):
        return commit, None
    req = urllib.request.Request(
        "https://api.github.com/repos/%s/git/commits/%s"
        % (repository, commit),
        headers={"User-Agent": "mithril-bounty-vrf/1.0",
                 "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            sha = json.loads(r.read()).get("sha")
        if COMMIT_RE.match(sha or ""):
            return sha, None
    except Exception:
        pass
    req = urllib.request.Request(
        "https://api.github.com/repos/%s/commits?per_page=100" % repository,
        headers={"User-Agent": "mithril-bounty-vrf/1.0",
                 "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            listed = json.loads(r.read())
        for entry in listed or []:
            sha = entry.get("sha")
            if COMMIT_RE.match(sha or "") and sha.startswith(commit):
                return sha, None
        return None, "short_commit_not_found_in_recent"
    except Exception as e:
        return None, "resolve_error:%s" % type(e).__name__


def run_review(repository, commit, review_root):
    cli = Path(review_root) / "bin" / "mithril-public-review.mjs"
    if not cli.is_file():
        return {"ok": False, "error": "review_cli_missing"}, "error"
    args = json.dumps({"repository": repository, "commit": commit}).encode()
    node = os.environ.get("MITHRIL_NODE_BIN", "node")
    try:
        proc = subprocess.run(
            [node, str(cli), "--stdin"], input=args.decode(),
            capture_output=True, text=True, timeout=REVIEW_TIMEOUT_S,
            cwd=review_root)
        out = (proc.stdout or "").strip().splitlines()
        payload = json.loads(out[-1]) if out else {"ok": False,
                                                  "error": "empty_stdout"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "review_timeout"}, "timeout"
    except Exception as e:
        return {"ok": False, "error": "review_error:%s"
                % type(e).__name__}, "error"
    outcome = "ok" if payload.get("ok") is True else "refused"
    if outcome == "refused":
        payload = diagnose_refusal(payload, repository, commit,
                                   review_root, node)
    return payload, outcome


def diagnose_refusal(payload, repository, commit, review_root, node):
    """Surface the underlying refusal reason (e.g. public_source_budget).

    The CLI collapses failures into public_review_refused; calling the
    library function directly yields the real message. The target commit
    is still not executed; only the public snapshot is re-fetched.
    """
    probe = ("import {reviewPublicRepository} from "
             "'" + review_root + "/lib/public-code-review.mjs';"
             "const a=JSON.parse(process.argv[1]);"
             "try{const o=await reviewPublicRepository(a);"
             "console.log(JSON.stringify({diagnostic:'ok'}))}"
             "catch(e){console.log(JSON.stringify("
             "{diagnostic_error:e&&e.message?e.message:String(e)}))}")
    args = json.dumps({"repository": repository, "commit": commit})
    try:
        proc = subprocess.run(
            [node, "--input-type=module", "-e", probe, args],
            capture_output=True, text=True, timeout=600,
            cwd=review_root)
        out = (proc.stdout or "").strip().splitlines()
        if out:
            detail = json.loads(out[-1])
            payload["diagnostic_error"] = detail.get(
                "diagnostic_error") or detail.get("diagnostic")
    except Exception:
        pass
    return payload


def sheet_summary(case, payload, outcome, now_jst, case_id=None):
    """Cells to write into the Challenge Log row for this case.

    Only the columns this bot owns are written; all other columns
    (Confirmed vulnerabilities, Submitted reports, Desktop result, ...)
    are left untouched.
    """
    case_id = case_id or case.get("case_id") or ""
    repo = case["repository"]
    commit = (case.get("commit_resolved") or payload.get("commit")
              or case.get("commit_input"))
    if outcome == "ok":
        acq = payload.get("acquisition", {}) or {}
        deps = payload.get("dependencies", {}) or {}
        assessment = payload.get("assessment", {}) or {}
        files = acq.get("files", []) if isinstance(acq, dict) else []
        dep_findings = (deps.get("findings", [])
                        if isinstance(deps, dict) else [])
        src_findings = (assessment.get("findings", [])
                        if isinstance(assessment, dict) else [])
        status = "Reviewed ok; deterministic snapshot"
        evaluation = ("%d files parsed; %d dependency candidates; "
                      "%d source-policy candidates"
                      % (len(files), len(dep_findings), len(src_findings)))
    else:
        status = "Review refused; retry pending"
        detail = (payload.get("diagnostic_error")
                  or payload.get("error") or "unknown")
        evaluation = "refused (%s); target not executed" % detail
    evidence = (
        "https://github.com/%s/commit/%s (receipt: R2 bounty-vrf/%s/receipt.json)"
        % (repo, commit, case_id))
    return {
        "Status": status,
        "Repository / commit": "%s @ %s" % (repo, commit),
        "Mithril evaluation": evaluation,
        "Local validation": "receipt sha256 + R2 read-back this tick",
        "Evidence": evidence,
        "Next step": "human triage of receipts",
        "Date JST": now_jst,
    }


def tick_case(profile, case_id, case, canonical_path, review_root,
              persist):
    """Run one case through resolve -> review -> receipt -> canonical ->
    R2 -> Drive -> sheet. Returns (outcome, published)."""
    repo, commit = case.get("repository"), case.get(
        "commit_input") or case.get("commit")
    receipts = profile / "data" / "receipts"
    receipts.mkdir(parents=True, exist_ok=True)
    receipt_path = receipts / ("%s.json" % case_id)

    last = case.get("last_review_at")
    if last:
        age = time.time() - datetime.strptime(
            last, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc).timestamp()
        if age < RECOOLDOWN_S and case.get(
                "last_review_status") in (
                "ok", "refused", "timeout", "resolve_failed"):
            print("TICK\tSKIP %s (%s within %dm)"
                  % (case_id, case["last_review_status"],
                     int(age // 60)))
            return "skip", True

    def save_canonical(state):
        tmp = canonical_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=1,
                                  sort_keys=True))
        os.replace(tmp, canonical_path)

    resolved, err = resolve_commit(repo, commit)
    if err or resolved is None or not COMMIT_RE.match(resolved):
        print("TICK\tRESOLVE-FAIL %s %s" % (case_id, err))
        receipt_path.write_text(json.dumps(
            {"case_id": case_id, "ok": False, "error": err,
             "resolved_at": now_iso()}, indent=1))
        # record in canonical so the cooldown + state are visible
        state = {"schema": "bounty-vrf-challenges/1", "cases": {}}
        if canonical_path.is_file():
            try:
                state = json.loads(canonical_path.read_text())
            except (OSError, ValueError):
                pass
        entry = dict(case)
        entry.update({"case_id": case_id, "last_review_status":
                     "resolve_failed", "last_review_error": err,
                     "last_review_at": now_iso(),
                     "receipt_sha256":
                     sha256_bytes(receipt_path.read_bytes())})
        state.setdefault("cases", {})[case_id] = entry
        save_canonical(state)
        return "resolve_failed", True

    payload, outcome = run_review(repo, resolved, review_root)
    payload["case_id"] = case_id
    payload["resolved_at"] = now_iso()
    receipt_path.write_text(json.dumps(payload, ensure_ascii=False,
                                       indent=1))
    print("REVIEW\t%s %s @ %s %s files=%d"
          % (case_id, repo, resolved[:12], outcome,
             len((payload.get("acquisition") or {}).get("files", []))))

    # canonical update (own keys only; the shared file is written
    # atomically and other cases' entries are preserved)
    state = {"schema": "bounty-vrf-challenges/1", "cases": {}}
    if canonical_path.is_file():
        try:
            state = json.loads(canonical_path.read_text())
        except (OSError, ValueError):
            pass
    state.setdefault("cases", {})[case_id] = dict(
        case, **{
            "case_id": case_id,
            "commit_input": case.get("commit_input") or case.get(
                "commit"),
            "commit_resolved": resolved,
            "last_review_status": outcome,
            "last_review_outcome": outcome if outcome == "ok" else None,
            "last_review_error": (None if outcome == "ok" else
                                  payload.get("error")),
            "last_review_at": payload["resolved_at"],
            "last_review_commit": resolved,
            "review_count": int(case.get("review_count", 0)) + 1,
            "receipt_sha256": sha256_bytes(receipt_path.read_bytes()),
        })
    save_canonical(state)

    # R2 publish under the case-owned sub-prefix
    prefix = "bounty-vrf/%s" % case_id
    receipt_b = receipt_path.read_bytes()
    manifest = json.dumps({
        "dataset": prefix, "case_id": case_id, "generated_at": now_iso(),
        "repository": repo, "commit": resolved, "outcome": outcome,
        "files": [{"name": "receipt.json", "bytes": len(receipt_b),
                   "sha256": sha256_bytes(receipt_b)}],
    }, ensure_ascii=False, indent=1).encode()
    env = dict(os.environ, CLOUDFLARE_ACCOUNT_ID=R2_ACCOUNT)

    def r2_put(key, path):
        p = subprocess.run(
            ["bash", "-c",
             "wrangler r2 object put internal-security-nvd/%s "
             "--file %s --content-type application/json --remote "
             "--persist-to=%s" % (key, path, persist)],
            capture_output=True, text=True, timeout=120, env=env)
        if p.returncode != 0:
            print("R2-PUT-FAIL %s %s"
                  % (key, (p.stderr or p.stdout)[:200]))
            return False
        out = profile / "cache" / "_rb.bin"
        out.parent.mkdir(parents=True, exist_ok=True)
        g = subprocess.run(
            ["bash", "-c",
             "wrangler r2 object get internal-security-nvd/%s -f %s "
             "--remote --persist-to=%s" % (key, out, persist)],
            capture_output=True, text=True, timeout=120, env=env)
        if g.returncode != 0 or not out.is_file():
            print("R2-READBACK-FAIL %s" % key)
            return False
        ok = sha256_bytes(out.read_bytes()) == \
            sha256_bytes(path.read_bytes())
        out.unlink(missing_ok=True)
        print("%s %s"
              % ("READBACK MATCH" if ok else "R2-SHA-MISMATCH", key))
        return ok

    case_dir = profile / "cache" / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    r = case_dir / "receipt.json"
    r.write_bytes(receipt_b)
    m = case_dir / "manifest.json"
    m.write_bytes(manifest)
    pub = r2_put(prefix + "/manifest.json", m) and \
        r2_put(prefix + "/receipt.json", r)
    print("PUBLISH %s %s" % (prefix, "OK" if pub else "FAILED"))

    # Drive archive (warn-and-continue)
    save = profile / "scripts" / "gdrive-save.sh"
    if save.is_file():
        d = subprocess.run(
            ["bash", str(save), "bounty-vrf-%s" % case_id.lower(),
             str(r), str(m)], capture_output=True, text=True, timeout=600)
        lines = (d.stdout or "").strip().splitlines()
        print(lines[-1] if lines else "DRIVE-FAIL %s"
              % ((d.stderr or "")[:200]))

    # Sheet write-back (the consistent Google approach; warn-and-continue).
    # Only the PRIMARY case of a challenge carries the sheet row.
    if os.environ.get("BBOPS_SKIP_SHEET") != "1" and is_primary(case_id):
        now_jst = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        sets = sheet_summary(case, payload, outcome, now_jst,
                             case_id=case_id)
        sheet_args = [sys.executable, str(SYNC), "--profile-dir",
                      str(profile), "log", "--case", case_id,
                      "--sheet-id", os.environ.get(
                          "BBOPS_SHEET_ID",
                          "1gJ-CfDviZZltpc2qIlsW5hxs386E9fCWhkS0vR_50yo")]
        for k, v in sets.items():
            sheet_args += ["--set", "%s=%s" % (k, v)]
        s = subprocess.run(sheet_args, capture_output=True, text=True,
                           timeout=900)
        out = (s.stdout or "").strip().splitlines()
        print(out[-1] if out else "SHEET-FAIL %s"
              % ((s.stderr or "")[:200]))

    print("TICK\tOK %s outcome=%s published=%s" % (case_id, outcome, pub))
    return outcome, pub


def main():
    profile = profile_dir()
    case_ids = bound_cases(profile)
    if not case_ids:
        print("TICK\tFAILED case not bound (profile %s)" % profile.name)
        return 2
    canonical_path = profile / "data" / "canonical" / "challenges.json"
    review_root = os.environ.get(
        "MITHRIL_SYSTEM_ONE_ROOT",
        "/Users/junkawasaki/github/mithril-lang/mithril-system-one")
    persist = str(Path.home() / ".wrangler" / "remotepersist")
    failed = False
    for case_id in case_ids:
        case = load_case(profile, case_id)
        if case is None:
            # a profile may legitimately own a secondary case that was
            # never queued; that is not an error
            if is_primary(case_id):
                print("TICK\tFAILED no canonical case %s in %s"
                      % (case_id, profile / "data" / "canonical"))
                return 2
            print("TICK\tSKIP %s (no canonical case)" % case_id)
            continue
        repo = case.get("repository")
        commit = case.get("commit_input") or case.get("commit")
        if not repo or not REPO_RE.match(repo) or not commit \
                or not SHORT_RE.match(commit):
            print("TICK\tFAILED bad binding %s" % case_id)
            failed = True
            continue
        outcome, _ = tick_case(profile, case_id, case, canonical_path,
                               review_root, persist)
        if outcome == "resolve_failed":
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
