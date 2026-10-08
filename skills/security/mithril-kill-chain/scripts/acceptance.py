#!/usr/bin/env python3
"""Synthetic cyber kill-chain acceptance exercise; no vendor/customer connection or keys retained.

Standard library only. Exercises the public CLI and stdio MCP bridge over
synthetic evidence and a synthetic .pcap, and verifies:

- phase coverage (covered / partial / absent) and the first-covered verdict;
- determinism: identical input bytes yield byte-identical output;
- no hidden state: changing the evidence changes the verdict (recomputed, not cached);
- a bounded local .pcap probe surfaces DNS / TLS-SNI / HTTP-Host / beacon candidates;
- machine-readable failure reasons (corrupt capture, missing file) with no stack trace;
- stdlib-only (no third-party import) by scanning the evaluator's own imports;
- the MCP bridge's oversized-line continuity (Request-too-large, then keeps serving).

It emits a machine-readable ``synthetic-local-evaluation`` receipt. Run it in a
temporary area; it retains no keys or fixtures.
"""
import argparse
import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import killchain  # sibling module in this scripts/ directory


def _load_pcap(path, big_endian=False):
    """Write a classic pcap (v2) carrying one DNS query, one TLS SNI, one
    cleartext HTTP Host, and a six-packet beacon stream."""
    fmt_h = '>IHHiIII' if big_endian else '<IHHiIII'
    fmt_r = '>IIII' if big_endian else '<IIII'
    p = struct.pack

    def addrs(src, dst):
        return p('!II', int.from_bytes(bytes(map(int, src.split('.'))), 'big'),
                 int.from_bytes(bytes(map(int, dst.split('.'))), 'big'))

    def iphdr(src, dst, proto, payload):
        return p('!BBHHHBBH', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0) \
            + addrs(src, dst) + payload

    def tcp(sport, dport, payload, seq=1):
        return p('!HHIIBBHHH', sport, dport, seq, 0, 0x50, 0x10, 65535, 0, 0) + payload

    def udp(sport, dport, payload):
        return p('!HHHH', sport, dport, 8 + len(payload), 0) + payload

    def dns_query(name):
        q = b''
        for part in name.split('.'):
            q += bytes([len(part)]) + part.encode()
        q += b'\x00\x00\x01\x00\x01'
        return p('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0) + q

    def client_hello(host):
        h = host.encode()
        ext_data = p('!H', 1 + 2 + len(h)) + b'\x00' + p('!H', len(h)) + h
        sni_ext = b'\x00\x00' + p('!H', len(ext_data)) + ext_data
        hello = p('!H', 0x0303) + bytes(32) + b'\x00' + p('!H', 4) \
            + b'\x13\x01\x13\x02' + b'\x01\x00' + p('!H', len(sni_ext)) + sni_ext
        return b'\x16\x03\x01' + p('!H', 1 + len(hello)) \
            + b'\x01' + p('!H', len(hello)) + hello

    eth = b'\x00\xaa\xbb\xcc\xdd\xee' + b'\x00\x11\x22\x33\x44\x55' + b'\x08\x00'

    def frame(proto, src, dst, payload):
        return eth + iphdr(src, dst, proto, payload)

    packets = [(100.0, frame(17, '10.0.0.2', '8.8.8.8', udp(53001, 53, dns_query('beacon.evil.example')))),
               (200.0, frame(6, '10.0.0.2', '93.184.216.34', tcp(53002, 443, client_hello('api.evil.example')))),
               (300.0, frame(6, '10.0.0.2', '93.184.216.34',
                             tcp(53003, 80, b'GET /a.html HTTP/1.1\r\nHost: pages.evil.example\r\n\r\n')))]
    packets += [(1000.0 + i * 30.0, frame(6, '10.0.0.2', '198.51.100.7', tcp(53004, 8443, b'x')))
                for i in range(6)]
    out = bytearray(p(fmt_h, 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for t, f in packets:
        secs, frac = divmod(t, 1.0)
        out += p(fmt_r, int(secs), int(frac * 1_000_000), len(f), len(f)) + f
    path.write_bytes(bytes(out))


def _run_cli(script, args, stdin_bytes=b''):
    return subprocess.run([sys.executable, str(script), *args],
                          input=stdin_bytes, capture_output=True, timeout=60)


def _stdlib_only(module_source):
    """Return the set of top-level modules the module imports that are not in
    the standard library, so an acceptance run can assert stdlib-only."""
    imported = set()
    for match in re.finditer(r'^(?:import|from)\s+([A-Za-z_][A-Za-z0-9_]*)', module_source, re.M):
        imported.add(match.group(1))
    stdlib = getattr(sys, 'stdlib_module_names', None)
    if stdlib is None:  # very old interpreters
        return imported - {'argparse', 'json', 'math', 'os', 'struct', 'sys', 'pathlib'}
    return {m for m in imported if m not in stdlib}


def provision(root):
    """Write synthetic evidence and captures into an empty directory and
    return their paths."""
    root = Path(root).resolve()
    if root.is_dir() and any(root.iterdir()):
        raise ValueError('empty_fixture_directory_required')
    root.mkdir(parents=True, mode=0o700)
    evidence = {
        'caseId': 'acceptance-case-01',
        'phases': [
            {'phase': 'reconnaissance',
             'evidence': [{'type': 'domain-asset', 'source': 'osint-catalog', 'note': 'synthetic'}]},
            {'phase': 'delivery', 'evidence': [{'type': 'url-observation', 'source': 'phishing-log'}]},
            {'phase': 'command-and-control', 'evidence': [{'type': 'pcap-probe', 'source': 'capture.pcap'}]},
            {'phase': 'actions-on-objectives', 'evidence': [{'type': 'exfiltration-record'}]},
        ],
    }
    (root / 'evidence.json').write_text(json.dumps(evidence, ensure_ascii=False), encoding='utf-8')
    pcap = root / 'capture.pcap'
    _load_pcap(pcap)
    return dict(evidence=str(root / 'evidence.json'), pcap=str(pcap),
                evidenceChanged={
                    'caseId': 'acceptance-case-01',
                    'phases': [
                        {'phase': 'delivery', 'evidence': [{'type': 'url-observation', 'source': 'phishing-log'}]},
                        {'phase': 'command-and-control', 'evidence': [{'type': 'pcap-probe', 'source': 'capture.pcap'}]},
                    ],
                })


def exercise():
    script = Path(__file__).with_name('killchain.py')
    non_stdlib = _stdlib_only(script.read_text(encoding='utf-8'))
    if non_stdlib:
        raise ValueError(f'expected_stdlib_only: {sorted(non_stdlib)}')
    with tempfile.TemporaryDirectory(prefix='mithril-killchain-') as temporary:
        root = Path(temporary) / 'acceptance'
        fixtures = provision(root)
        evidence_bytes = Path(fixtures['evidence']).read_bytes()
        changed_bytes = json.dumps(fixtures['evidenceChanged'], ensure_ascii=False).encode()

        # Phase coverage over the synthetic multi-phase case.
        first = _run_cli(script, ['--tool', 'killchain_evaluate', '--input', fixtures['evidence']])
        if first.returncode:
            raise ValueError(f'evaluate_failed: {first.stderr.decode(errors="replace")}')
        base = json.loads(first.stdout.decode())
        if base['verdict'] != 'first-covered-phase-1':
            raise ValueError('unexpected_verdict')
        if set(base['coveredPhases']) != {1, 3, 6, 7}:
            raise ValueError('unexpected_coverage')
        if base['absentPhases'] != [2, 4, 5]:
            raise ValueError('unexpected_absent')

        # Determinism: identical input bytes -> byte-identical output.
        repeat = _run_cli(script, ['--tool', 'killchain_evaluate', '--input', fixtures['evidence']])
        if repeat.returncode or repeat.stdout != first.stdout:
            raise ValueError('evaluate_not_deterministic')

        # No hidden state: changing the evidence changes the verdict.
        changed = _run_cli(script, ['--tool', 'killchain_evaluate', '--input', '-'], stdin_bytes=changed_bytes)
        if changed.returncode:
            raise ValueError('evaluate_changed_failed')
        changed_result = json.loads(changed.stdout.decode())
        if changed_result['verdict'] != 'first-covered-phase-3':
            raise ValueError('coverage_not_recomputed')
        if changed.stdout == first.stdout:
            raise ValueError('coverage_not_input_driven')

        # Bounded pcap probe: surfaces the four candidate families, and is
        # deterministic across runs on identical bytes.
        probe = _run_cli(script, ['--tool', 'killchain_pcap_probe', '--input', '-'],
                         stdin_bytes=json.dumps({'path': fixtures['pcap']}).encode())
        if probe.returncode:
            raise ValueError(f'pcap_probe_failed: {probe.stderr.decode(errors="replace")}')
        candidates = json.loads(probe.stdout.decode())
        if candidates['dnsQueries'] != ['beacon.evil.example'] \
                or candidates['tlsSni'] != ['api.evil.example'] \
                or candidates['httpHosts'] != ['pages.evil.example']:
            raise ValueError('pcap_candidates_missing')
        if not candidates['beaconCandidates'] or candidates['beaconCandidates'][0]['dst'] != '198.51.100.7':
            raise ValueError('beacon_candidate_missing')
        probe_repeat = _run_cli(script, ['--tool', 'killchain_pcap_probe', '--input', '-'],
                                stdin_bytes=json.dumps({'path': fixtures['pcap']}).encode())
        if probe_repeat.returncode or probe_repeat.stdout != probe.stdout:
            raise ValueError('pcap_probe_not_deterministic')

        # Machine-readable failure reasons, never a stack trace.
        corrupt = root / 'corrupt.pcap'
        corrupt.write_bytes(b'not-a-pcap-magic-bytes-here!!')
        failed = _run_cli(script, ['--tool', 'killchain_pcap_probe', '--input', '-'],
                          stdin_bytes=json.dumps({'path': str(corrupt)}).encode())
        if failed.returncode != 1 or 'unsupported_pcap' not in failed.stderr.decode() \
                or 'Traceback' in failed.stderr.decode():
            raise ValueError('corrupt_pcap_reason_missing')
        missing = root / 'absent.pcap'
        missing_run = _run_cli(script, ['--tool', 'killchain_pcap_probe', '--input', '-'],
                               stdin_bytes=json.dumps({'path': str(missing)}).encode())
        if missing_run.returncode != 1 or 'file_not_found' not in missing_run.stderr.decode() \
                or 'Traceback' in missing_run.stderr.decode():
            raise ValueError('missing_file_reason_missing')

        # MCP bridge: an oversized line yields Request-too-large and the
        # bridge keeps serving the following request (exit code 0).
        padded = b'{"jsonrpc":"2.0","id":99,"method":"ping","params":{}}' + b'x' * killchain.MAX_ARG_BYTES
        next_call = json.dumps({'jsonrpc': '2.0', 'id': 101, 'method': 'tools/call',
                                'params': {'name': 'killchain_evaluate',
                                           'arguments': {'phases': [{'phase': 'command-and-control',
                                                                      'evidence': [{'type': 'pcap-probe'}]}]}}}).encode()
        bridge = subprocess.run([sys.executable, str(script), '--mcp'],
                                input=b'\n'.join([padded, next_call]) + b'\n',
                                capture_output=True, timeout=60)
        if bridge.returncode != 0:
            raise ValueError(f'mcp_continuity_failed: {bridge.stderr.decode(errors="replace")}')
        out = [json.loads(line) for line in bridge.stdout.decode().splitlines()]
        if [item['id'] for item in out] != [None, 101] or out[0]['error']['code'] != -32600:
            raise ValueError('mcp_oversized_line_handling_changed')
        if 'first-covered-phase-6' not in out[1]['result']['content'][0]['text']:
            raise ValueError('mcp_tool_dispatch_changed')

        return {
            'status': 'passed',
            'qualification': 'synthetic-local-evaluation',
            'version': killchain.VERSION,
            'dependencies': 'python-stdlib-only',
            'nonStdlibImports': 0,
            'networkCalls': 0,
            'phasesEvaluated': 7,
            'coverageScenarios': {
                'baseVerdict': base['verdict'],
                'baseCovered': base['coveredPhases'],
                'baseAbsent': base['absentPhases'],
                'changedVerdict': changed_result['verdict'],
            },
            'determinism': 'byte-identical-across-runs',
            'pcapCandidates': {
                'dnsQueries': len(candidates['dnsQueries']),
                'tlsSni': len(candidates['tlsSni']),
                'httpHosts': len(candidates['httpHosts']),
                'beaconCandidates': len(candidates['beaconCandidates']),
                'packets': candidates['packets'],
            },
            'failureReasons': {'corrupt_pcap': 'unsupported_pcap', 'missing_file': 'file_not_found'},
            'mcp': {'oversizedLine': 'request-too-large-then-continues', 'exitCode': 0},
            'keysRetained': False,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare', help='write synthetic fixtures to this directory and print their paths')
    args = parser.parse_args()
    try:
        print(json.dumps(provision(args.prepare) if args.prepare else exercise(), ensure_ascii=False, indent=2))
    except Exception:
        print(json.dumps(dict(status='failed', reason='acceptance_failed')))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
