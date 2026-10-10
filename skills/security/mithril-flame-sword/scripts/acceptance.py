#!/usr/bin/env python3
"""Synthetic Flame Sword analyst acceptance exercise; no vendor/customer connection or keys retained.

Standard library only. Exercises the public CLI and stdio MCP bridge over
synthetic Flame Sword observation reports, and verifies:

- the vendored analyst files match the pinned flame-sword commit digests;
- report validation normalization and contract rejections (machine-readable
  reasons, never a stack trace);
- deterministic analysis: identical input bytes yield byte-identical output;
- no hidden state: changing the observations changes the analysis;
- the analysis is explicitly labeled (local-cli-vendored-analyst,
  user-supplied observations) and never claims a scan ran;
- stdlib-only (no third-party import) by scanning the CLI's own imports;
- the MCP bridge's oversized-line continuity (Request-too-large, then keeps
  serving).

It emits a machine-readable ``synthetic-local-evaluation`` receipt. Run it in a
temporary area; it retains no keys or fixtures.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import flame_sword  # sibling module in this scripts/ directory

SCRIPT_DIR = Path(__file__).resolve().parent
VENDOR_DIR = SCRIPT_DIR / 'vendor'
PIN = '6e969b247baa53ab49d4bd993aef8def3dff967a'
EXPECTED_DIGESTS = {
    'FastAnalyst.py': '97581c1ea299c281d08dac044ba18f6d77a6ac2f90e9f08d9e9f583866c6042e',
    'analysis.py': '482819debed84944baf93324d5331f97650dfd442e1e0e528b1c7c2fb8e320e1',
}

REPORT = {
    'domain': 'example.com',
    'subdomains': [
        {'subdomain': 'www.example.com', 'http_status': 301, 'https_status': 200},
        {'subdomain': 'admin.example.com', 'https_status': 403},
        {'subdomain': 'staging.example.com', 'http_status': 200},
    ],
}
REPORT_CHANGED = {
    'domain': 'example.com',
    'subdomains': [
        {'subdomain': 'www.example.com', 'http_status': 200, 'https_status': 200},
        {'subdomain': 'shop.example.com', 'https_status': 200},
    ],
}


def _run_cli(script, args, stdin_bytes=b''):
    return subprocess.run([sys.executable, str(script), *args],
                          input=stdin_bytes, capture_output=True, timeout=120)


def _stdlib_only(module_source):
    """Return top-level imported modules of the CLI that are not stdlib."""
    imported = set()
    for match in re.finditer(r'^(?:import|from)\s+([A-Za-z_][A-Za-z0-9_]*)', module_source, re.M):
        imported.add(match.group(1))
    stdlib = getattr(sys, 'stdlib_module_names', None)
    if stdlib is None:
        return imported - {'argparse', 'importlib', 'json', 'os', 're', 'sys', 'datetime', 'pathlib'}
    return {m for m in imported if m not in stdlib}


def verify_vendor_digests():
    digests = {}
    for name, expected in EXPECTED_DIGESTS.items():
        actual = hashlib.sha256((VENDOR_DIR / name).read_bytes()).hexdigest()
        digests[name] = actual
        if actual != expected:
            raise ValueError(f'vendor_digest_mismatch:{name}')
    return digests


def exercise():
    script = SCRIPT_DIR / 'flame_sword.py'
    non_stdlib = _stdlib_only(script.read_text(encoding='utf-8'))
    if non_stdlib:
        raise ValueError(f'expected_stdlib_only: {sorted(non_stdlib)}')
    digests = verify_vendor_digests()
    with tempfile.TemporaryDirectory(prefix='mithril-flame-sword-') as temporary:
        root = Path(temporary) / 'acceptance'
        root.mkdir(parents=True, mode=0o700)
        report = root / 'report.json'
        report.write_text(json.dumps(REPORT), encoding='utf-8')

        # Capabilities: the skill executes exactly two operations locally.
        caps = _run_cli(script, ['--tool', 'flame_sword_capabilities'])
        if caps.returncode:
            raise ValueError(f'capabilities_failed: {caps.stderr.decode(errors="replace")}')
        cap_data = json.loads(caps.stdout.decode())
        if [op['id'] for op in cap_data['operations']] != ['report_validate', 'report_analyze']:
            raise ValueError('capabilities_operations_changed')
        if any(op['network'] for op in cap_data['operations']) or not cap_data['limitations']:
            raise ValueError('capabilities_limits_changed')

        # Validation normalizes and is deterministic.
        validate = _run_cli(script, ['--tool', 'flame_sword_report_validate', '--input', str(report)])
        if validate.returncode:
            raise ValueError(f'validate_failed: {validate.stderr.decode(errors="replace")}')
        vdata = json.loads(validate.stdout.decode())
        if vdata['domain'] != 'example.com' or vdata['valid'] is not True \
                or vdata['subdomains'][0]['subdomain'] != 'www.example.com':
            raise ValueError('validate_normalization_changed')
        validate_repeat = _run_cli(script, ['--tool', 'flame_sword_report_validate', '--input', str(report)])
        if validate_repeat.returncode or validate_repeat.stdout != validate.stdout:
            raise ValueError('validate_not_deterministic')

        # Analysis is deterministic over identical bytes.
        first = _run_cli(script, ['--tool', 'flame_sword_report_analyze', '--input', str(report)])
        if first.returncode:
            raise ValueError(f'analyze_failed: {first.stderr.decode(errors="replace")}')
        base = json.loads(first.stdout.decode())
        if base['execution'] != 'local-cli-vendored-analyst' \
                or base['evidence'] != 'user-supplied observations' \
                or 'No network scan was performed by this analysis.' not in base['limitations']:
            raise ValueError('analysis_labels_changed')
        if base['analysis']['summary']['analysis_timestamp'] != flame_sword.FROZEN_NOW.isoformat():
            raise ValueError('analysis_not_frozen_clock')
        if base['analysis']['risk_assessment']['level'] not in ('Low', 'Medium', 'High', 'Critical'):
            raise ValueError('analysis_risk_level_missing')
        repeat = _run_cli(script, ['--tool', 'flame_sword_report_analyze', '--input', str(report)])
        if repeat.returncode or repeat.stdout != first.stdout:
            raise ValueError('analyze_not_deterministic')

        # No hidden state: different observations change the analysis.
        changed = _run_cli(script, ['--tool', 'flame_sword_report_analyze', '--input', '-'],
                           stdin_bytes=json.dumps(REPORT_CHANGED).encode())
        if changed.returncode:
            raise ValueError('analyze_changed_failed')
        if changed.stdout == first.stdout:
            raise ValueError('analysis_not_input_driven')
        if json.loads(changed.stdout.decode())['analysis']['summary']['total_subdomains'] != 2:
            raise ValueError('analysis_not_recomputed')

        # Machine-readable contract failures, never a stack trace.
        failures = {
            'domain_mismatch': {'domain': 'example.com', 'subdomains': [{'subdomain': 'other.example.net'}]},
            'invalid_status': {'domain': 'example.com', 'subdomains': [{'subdomain': 'www.example.com', 'http_status': '200'}]},
            'too_many_subdomains': {'domain': 'example.com', 'subdomains': [{'subdomain': f'h{i:03d}.example.com'} for i in range(501)]},
        }
        reasons = {}
        for reason, payload in failures.items():
            failed = _run_cli(script, ['--tool', 'flame_sword_report_analyze', '--input', '-'],
                              stdin_bytes=json.dumps(payload).encode())
            if failed.returncode != 1 or reason not in failed.stderr.decode() \
                    or 'Traceback' in failed.stderr.decode():
                raise ValueError(f'failure_reason_missing:{reason}')
            reasons[reason] = reason
        missing = root / 'absent.json'
        missing_run = _run_cli(script, ['--tool', 'flame_sword_report_analyze', '--input', str(missing)])
        if missing_run.returncode != 1 or 'file_not_found' not in missing_run.stderr.decode() \
                or 'Traceback' in missing_run.stderr.decode():
            raise ValueError('missing_file_reason_missing')

        # MCP bridge: an oversized line yields Request-too-large and the
        # bridge keeps serving the following request (exit code 0).
        padded = b'{"jsonrpc":"2.0","id":99,"method":"ping","params":{}}' + b'x' * flame_sword.MAX_ARG_BYTES
        next_call = json.dumps({'jsonrpc': '2.0', 'id': 101, 'method': 'tools/call',
                                'params': {'name': 'flame_sword_capabilities', 'arguments': {}}}).encode()
        bridge = subprocess.run([sys.executable, str(script), '--mcp'],
                                input=b'\n'.join([padded, next_call]) + b'\n',
                                capture_output=True, timeout=120)
        if bridge.returncode != 0:
            raise ValueError(f'mcp_continuity_failed: {bridge.stderr.decode(errors="replace")}')
        out = [json.loads(line) for line in bridge.stdout.decode().splitlines()]
        if [item['id'] for item in out] != [None, 101] or out[0]['error']['code'] != -32600:
            raise ValueError('mcp_oversized_line_handling_changed')
        if 'mithril-flame-sword' not in out[1]['result']['content'][0]['text']:
            raise ValueError('mcp_tool_dispatch_changed')

        return {
            'status': 'passed',
            'qualification': 'synthetic-local-evaluation',
            'version': flame_sword.VERSION,
            'pinnedCommit': PIN,
            'vendorDigests': digests,
            'dependencies': 'python-stdlib-only',
            'nonStdlibImports': 0,
            'networkCalls': 0,
            'operationsExecuted': ['report_validate', 'report_analyze'],
            'determinism': 'byte-identical-across-runs-frozen-clock',
            'failureReasons': dict(reasons, missing_file='file_not_found'),
            'mcp': {'oversizedLine': 'request-too-large-then-continues', 'exitCode': 0},
            'keysRetained': False,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    args = parser.parse_args()
    try:
        print(json.dumps(exercise(), ensure_ascii=False, indent=2))
    except Exception:
        print(json.dumps(dict(status='failed', reason='acceptance_failed')))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
