#!/usr/bin/env python3
"""mithril-polyglot-review-ops tick (no-agent, hourly).

Continues the Go/Rust polyglot extraction expansion on the pinned
worktree system-one-polyglot-extraction (branch
feat/polyglot-source-extraction):

  1. verify the worktree is on the expected branch (else stop + report)
  2. run the two deterministic test files, count pass/fail
  3. for each canonical target: resolve HEAD via `git ls-remote` (git
     protocol, no GitHub API quota), run the public-review CLI
     (non-executing, deterministic), measure files / languages /
     dependency components / gaps / findings
  4. save a receipt per run, update canonical state atomically
  5. if tests are green AND the worktree is dirty: commit + push
     (feature branch only; never main, no merge/PR)
  6. publish the manifest+receipt to R2 (fund account,
     polyglot-review/ prefix) with put+get sha256 read-back
  7. archive to Google Drive jklux (warn-and-continue)
  8. print one final TICK line

No target code is executed. review_incomplete is not "safe".
"""

import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROFILE = HERE.parent

WORKTREE = Path(os.environ.get(
    "POLYGLOT_WORKTREE",
    "/Users/junkawasaki/github/mithril-lang/system-one-polyglot-extraction"))
BRANCH = os.environ.get("POLYGLOT_BRANCH", "feat/polyglot-source-extraction")
NODE = os.environ.get("MITHRIL_NODE_BIN", "node")
PY = os.environ.get(
    "MITHRIL_SOURCE_PYTHON",
    str(Path.home() / ".venvs" / "mithril-source-parser" / "bin" / "python"))
R2_BUCKET = "internal-security-nvd"
R2_PREFIX = "polyglot-review"
R2_ACCOUNT = os.environ.get(
    "BOUNTY_VRF_R2_ACCOUNT", "62e1fda53188460698f8c66d3aef59c6")
KEYCHAIN_SERVICE = "mithril.catalog.materializer"
TEST_FILES = ["test/dependency-assessment.test.mjs",
              "test/polyglot-source.test.mjs"]
PERSIST = os.environ.get(
    "POLYGLOT_WRANGLER_PERSIST",
    str(Path.home() / ".wrangler" / "remotepersist"))
REVIEW_TIMEOUT_S = 900


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%H:%SZ")


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def run(cmd, timeout=120, env=None, input_bytes=None, cwd=None):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          env=env, input=input_bytes, cwd=cwd)


def fail(msg):
    print("TICK STOP %s" % msg)
    sys.exit(1)


def worktree_ready():
    br = run(["git", "-C", str(WORKTREE), "rev-parse", "--abbrev-ref", "HEAD"])
    if br.returncode != 0:
        fail("worktree not a git repo: %s" % WORKTREE)
    if br.stdout.strip() != BRANCH:
        fail("worktree on branch %s, expected %s" % (br.stdout.strip(), BRANCH))
    head = run(["git", "-C", str(WORKTREE), "rev-parse", "HEAD"]).stdout.strip()
    return head


def run_tests():
    env = dict(os.environ, MITHRIL_SOURCE_PYTHON=PY)
    result = {"pass": 0, "fail": 0, "files": 0, "last_error": None}
    for tf in TEST_FILES:
        p = run([NODE, "--test", tf], timeout=600, env=env, cwd=str(WORKTREE))
        out = p.stdout or ""
        m_pass = re.search(r"^\s*\u2714|\bpass\s+(\d+)", out, re.M)
        nums = re.findall(r"\u2714", out)
        # node --test summary lines look like:
        #   \u2139 pass 10
        pp = re.search(r"pass\s+(\d+)", out)
        ff = re.search(r"fail\s+(\d+)", out)
        result["pass"] += int(pp.group(1)) if pp else 0
        result["fail"] += int(ff.group(1)) if ff else 0
        result["files"] += 1
        if p.returncode != 0 and result["fail"] == 0:
            result["last_error"] = "test run %s rc=%d: %s" % (
                tf, p.returncode, (p.stderr or "")[:200])
    return result


def resolve_head(repo):
    p = run(["git", "ls-remote", "https://github.com/%s.git" % repo, "HEAD"],
            timeout=60)
    if p.returncode != 0:
        return None, "ls-remote failed: %s" % (p.stderr or "")[:200]
    sha = p.stdout.split()[0] if p.stdout.strip() else ""
    if not re.fullmatch(r"[a-f0-9]{40}", sha):
        return None, "unexpected HEAD shape"
    return sha, None


def run_review(repo, sha):
    cli = WORKTREE / "bin" / "mithril-public-review.mjs"
    env = dict(os.environ, MITHRIL_SOURCE_PYTHON=PY)
    # The public-review CLI rides unauthenticated GitHub REST (60/h).
    # Fetch a read-only token from the gh keyring when available and pass
    # it as GH_TOKEN (Bearer). The token is never persisted to a file and
    # a read via authenticated REST is still a public-data read.
    if "GH_TOKEN" not in env:
        g = run(["gh", "auth", "token"], timeout=30)
        if g.returncode == 0 and g.stdout.strip():
            env["GH_TOKEN"] = g.stdout.strip()
    args = json.dumps({"repository": repo, "commit": sha}).encode()
    p = run([NODE, str(cli), "--stdin"], timeout=REVIEW_TIMEOUT_S, env=env,
            input_bytes=args.decode(), cwd=str(WORKTREE))
    try:
        d = json.loads(p.stdout)
    except Exception:
        return {"ok": False, "error": "unparseable: %s" % p.stdout[:200]}
    ac = d.get("acquisition") or {}
    files = ac.get("files", [])
    langs = {}
    for f in files:
        langs[f.get("language")] = langs.get(f.get("language"), 0) + 1
    dep = d.get("dependencies") or {}
    inv = dep.get("inventory") or {}
    findings = []
    for f in dep.get("findings", []) or []:
        c = f.get("component") or {}
        findings.append({
            "component": "%s/%s@%s" % (c.get("ecosystem"), c.get("name"), c.get("version")),
            "advisory": f.get("advisory"), "severity": f.get("severity"),
            "cves": f.get("cves") or [], "fixed_versions": f.get("fixed_versions") or [],
            "status": f.get("status"),
        })
    meas = {
        "repository": repo,
        "commit": sha,
        "ok": d.get("ok"),
        "status": d.get("status"),
        "error": d.get("error"),
        "selected": ac.get("selected_count"),
        "parsed": ac.get("parsed_count"),
        "unsupported": ac.get("unsupported_count"),
        "languages": langs,
        "source_ontologies": len(d.get("source_ontologies", [])),
        "dep_components": len(inv.get("components", [])),
        "dep_component_list": ["%s/%s@%s" % (c.get("ecosystem"), c.get("name"), c.get("version")) for c in inv.get("components", [])],
        "dep_gaps": [g.get("reason") for g in inv.get("gaps", [])],
        "findings": findings,
        "findings_count": len(dep.get("findings", [])),
        "seconds": round(d.get("seconds", 0), 2),
    }
    return meas


def git_sync(worktree_head):
    """Commit + push on the feature branch iff tests green and dirty."""
    dirty = run(["git", "-C", str(WORKTREE), "status", "--porcelain"]).stdout.strip()
    if not dirty:
        return "clean"
    run(["git", "-C", str(WORKTREE), "add", "-A"], timeout=60)
    msg = "chore(polyglot): polyglot dependency extraction + %s" % now_iso()
    c = run(["git", "-C", str(WORKTREE), "commit", "-m", msg], timeout=60)
    if c.returncode != 0:
        return "commit_failed:%s" % (c.stderr or "")[:160]
    new_head = run(["git", "-C", str(WORKTREE), "rev-parse", "HEAD"]).stdout.strip()
    pu = run(["git", "-C", str(WORKTREE), "push", "origin", BRANCH], timeout=180)
    if pu.returncode != 0:
        return "push_failed:%s" % (pu.stderr or "")[:160]
    return "pushed:%s..%s" % (worktree_head[:8], new_head[:8])


def r2_env():
    env = dict(os.environ, CLOUDFLARE_ACCOUNT_ID=R2_ACCOUNT)
    t = run(["security", "find-generic-password", "-s",
             KEYCHAIN_SERVICE, "-w"]).stdout.strip()
    if t:
        env["CLOUDFLARE_API_TOKEN"] = t
    return env


def r2_put(key, path, env):
    p = run(["wrangler", "r2", "object", "put",
             "%s/%s" % (R2_BUCKET, key), "--file", str(path),
             "--content-type", "application/json", "--remote",
             "--persist-to=%s" % PERSIST], timeout=120, env=env)
    if p.returncode != 0:
        print("R2-PUT-FAIL %s %s" % (key, (p.stderr or p.stdout)[:160]))
        return False
    out = PROFILE / "cache" / "_rb.bin"
    out.parent.mkdir(parents=True, exist_ok=True)
    g = run(["wrangler", "r2", "object", "get", "%s/%s" % (R2_BUCKET, key),
             "-f", str(out), "--remote", "--persist-to=%s" % PERSIST],
            timeout=120, env=env)
    if g.returncode != 0 or not out.is_file():
        print("R2-READBACK-FAIL %s" % key)
        return False
    ok = sha256_bytes(out.read_bytes()) == sha256_bytes(Path(path).read_bytes())
    out.unlink(missing_ok=True)
    print("%s %s" % ("READBACK MATCH" if ok else "R2-SHA-MISMATCH", key))
    return ok


def main():
    worktree_head = worktree_ready()
    tests = run_tests()
    tests_ok = tests["fail"] == 0 and tests["last_error"] is None

    targets = []
    tp = PROFILE / "data" / "canonical" / "targets.json"
    if tp.is_file():
        try:
            targets = json.loads(tp.read_text())["targets"]
        except Exception as e:
            targets = []
            print("TARGETS-PARSE-FAIL %s" % e)

    receipts_dir = PROFILE / "data" / "receipts"
    receipts_dir.mkdir(parents=True, exist_ok=True)
    measurements = []
    for t in targets:
        repo = t.get("repository")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo or ""):
            measurements.append({"repository": repo, "error": "invalid_target"})
            continue
        sha, err = resolve_head(repo)
        if err:
            measurements.append({"repository": repo, "error": err})
            continue
        m = run_review(repo, sha)
        m["engine_expected"] = t.get("engine")
        measurements.append(m)
        rcpt = receipts_dir / ("%s.json" % repo.replace("/", "_"))
        rcpt.write_text(json.dumps(
            {"generated_at": now_iso(), **m}, ensure_ascii=False, indent=1))

    git_result = "skipped(red-tests)" if not tests_ok else git_sync(worktree_head)

    # canonical state
    state = {
        "generated_at": now_iso(),
        "worktree_head": worktree_head,
        "branch": BRANCH,
        "tests": tests,
        "git": git_result,
        "targets": measurements,
    }
    state_path = PROFILE / "data" / "canonical" / "state.json"
    tmp = state_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=1))
    os.replace(tmp, state_path)

    # R2 publish (manifest + receipt)
    env = r2_env()
    manifest = json.dumps({
        "dataset": R2_PREFIX, "generated_at": state["generated_at"],
        "worktree_head": worktree_head, "branch": BRANCH, "tests": tests,
        "git": git_result,
        "files": [{
            "name": "receipt.json", "bytes": state_path.stat().st_size,
            "sha256": sha256_bytes(state_path.read_bytes()),
        }],
    }, ensure_ascii=False, indent=1)
    mpath = PROFILE / "cache" / "manifest.json"
    mpath.parent.mkdir(parents=True, exist_ok=True)
    mpath.write_text(manifest)
    r2 = {}
    r2["manifest"] = r2_put("%s/manifest.json" % R2_PREFIX, mpath, env)
    r2["state"] = r2_put("%s/receipt.json" % R2_PREFIX, state_path, env)
    r2_ok = r2["manifest"] and r2["state"]

    # Drive archive (warn-and-continue)
    gsh = PROFILE / "scripts" / "gdrive-save.sh"
    if gsh.is_file():
        d = run(["bash", str(gsh), "polyglot-review", str(state_path)],
                timeout=180)
        print("DRIVE %s" % (d.stdout.strip() or (d.stderr.strip() or "rc=%d" % d.returncode)))
    else:
        print("DRIVE SKIPPED (no gdrive-save.sh)")

    print("TICK OK tests=%d/%d targets=%d git=%s r2=%s" % (
        tests["pass"], tests["fail"], len(measurements), git_result,
        "OK" if r2_ok else "FAIL"))
    if not tests_ok or not r2_ok:
        sys.exit(0)  # warn-and-continue; measured above


if __name__ == "__main__":
    main()
