#!/usr/bin/env python3
"""Flame Sword local analyst and stdio MCP bridge; Python standard library only.

Deterministic triage of user-supplied web attack-surface observations
(Flame Sword JSON reports). The observation contract mirrors the browser
worker: a domain plus at most 500 in-domain subdomain observations with
optional HTTP(S) status codes. The vendored ``FastSecurityAnalyst`` (ARTEX
derived, from mithril-lang/flame-sword at a pinned commit) is a rule-based
analyst with no network access.

No network calls. Observations are untrusted data. The CLI drives the
vendored analyst with a fixed clock so identical input bytes produce
byte-identical output.
"""
import argparse
import importlib.util
import json
import os
import re
import sys
from datetime import datetime as _real_datetime
from pathlib import Path

VERSION = '0.1.0'
MAX_ARG_BYTES = 32768
MAX_LINE_BYTES = 1 << 20
MAX_SUBDOMAINS = 500
DOMAIN_PATTERN = re.compile(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}')
FROZEN_NOW = _real_datetime(2026, 1, 1, 0, 0, 0)

LIMITATIONS = (
    'No network scan was performed by this analysis.',
    'Hostname patterns and HTTP statuses are triage indicators, not verified vulnerabilities.',
    'DNS, port scans, origin discovery and TLS handshakes require the local Python tools.',
)

VENDOR_DIR = Path(__file__).resolve().with_name('vendor')
TOOLS = json.loads(Path(__file__).with_name('tools.json').read_text())
VERSIONS = ('2025-03-26', '2025-06-18', '2025-11-25')


class FlameSwordFailure(Exception):
    """Machine-readable operation failure."""


class _FrozenDatetime:
    """Fixed-clock stand-in for ``datetime`` used by the vendored analyst."""

    @staticmethod
    def now(tz=None):
        return FROZEN_NOW


def _load_vendor():
    fast_spec = importlib.util.spec_from_file_location('FastAnalyst', VENDOR_DIR / 'FastAnalyst.py')
    fast = importlib.util.module_from_spec(fast_spec)
    sys.modules['FastAnalyst'] = fast  # analysis.py imports it by top-level name.
    fast_spec.loader.exec_module(fast)
    fast.datetime = _FrozenDatetime  # deterministic analysis_timestamp and insights.
    analysis_spec = importlib.util.spec_from_file_location('flame_sword_analysis', VENDOR_DIR / 'analysis.py')
    analysis = importlib.util.module_from_spec(analysis_spec)
    analysis_spec.loader.exec_module(analysis)
    return fast, analysis


_vendor = _load_vendor()


def capabilities():
    return {
        'name': 'mithril-flame-sword',
        'version': VERSION,
        'execution': 'local-cli-vendored-analyst',
        'evidence': 'user-supplied observations',
        'operations': [
            {'id': 'report_validate', 'summary': 'Validate a supplied observation report against the Flame Sword contract.', 'network': False},
            {'id': 'report_analyze', 'summary': 'Run the vendored rule-based analyst over validated observations.', 'network': False},
        ],
        'modules': [
            {'id': 'subdomains', 'summary': 'Subdomain enumeration with HTTP(S) status', 'executedBy': 'Flame Sword local scanner; not by this skill'},
            {'id': 'ports', 'summary': 'Bounded port scan on selected subdomains', 'executedBy': 'Flame Sword local scanner (nmap); not by this skill'},
            {'id': 'dns', 'summary': 'DNS record scan', 'executedBy': 'Flame Sword local scanner; not by this skill'},
            {'id': 'real-ip', 'summary': 'Origin IP discovery behind CDNs', 'executedBy': 'Flame Sword local scanner; not by this skill'},
            {'id': 'ssl', 'summary': 'TLS configuration scan', 'executedBy': 'Flame Sword local scanner; not by this skill'},
            {'id': 'tech', 'summary': 'Technology detection', 'executedBy': 'Flame Sword local scanner; not by this skill'},
            {'id': 'email', 'summary': 'Email/user pattern enumeration', 'executedBy': 'Flame Sword local scanner; not by this skill'},
            {'id': 'ai', 'summary': 'Mithril inference owner/hunter analysis', 'executedBy': 'Flame Sword local scanner with MITHRIL_API_KEY; not by this skill'},
        ],
        'limitations': list(LIMITATIONS) + [
            'This skill does not scan, probe or mutate any host.',
            'A zero-finding analysis is not a safety or completeness statement.',
        ],
    }


def validate_observations(raw):
    """Validate a supplied report; returns (domain, normalized rows)."""
    if not isinstance(raw, dict):
        raise FlameSwordFailure('invalid_input')
    domain = raw.get('domain', '')
    if not isinstance(domain, str) or len(domain) > 253 or not DOMAIN_PATTERN.fullmatch(domain):
        raise FlameSwordFailure('invalid_domain')
    domain = domain.lower()
    rows = raw.get('subdomains')
    if not isinstance(rows, list) or len(rows) > MAX_SUBDOMAINS:
        raise FlameSwordFailure('too_many_subdomains')
    clean = []
    for row in rows:
        if not isinstance(row, dict):
            raise FlameSwordFailure('invalid_observations')
        host = row.get('subdomain', '')
        if not isinstance(host, str) or len(host) > 253 or not DOMAIN_PATTERN.fullmatch(host) \
                or not (host.lower() == domain or host.lower().endswith('.' + domain)):
            raise FlameSwordFailure('domain_mismatch')
        item = {'subdomain': host.lower()}
        for field in ('http_status', 'https_status'):
            status = row.get(field)
            if status is not None and (type(status) is not int or not 100 <= status <= 599):
                raise FlameSwordFailure('invalid_status')
            item[field] = status
        clean.append(item)
    return domain, clean


def report_validate(raw):
    domain, clean = validate_observations(raw)
    return {
        'domain': domain,
        'subdomains': clean,
        'valid': True,
        'execution': 'local-cli-validation',
        'limitations': ['Validation does not run the analyst and performs no scan.'],
    }


def report_analyze(raw):
    domain, clean = validate_observations(raw)
    analysis = _vendor[0].FastSecurityAnalyst().analyze_subdomains(domain, clean)
    if not isinstance(analysis, dict) or not isinstance(analysis.get('summary'), dict):
        raise FlameSwordFailure('analyst_error')
    return {
        'domain': domain,
        'subdomains': clean,
        'analysis': analysis,
        'execution': 'local-cli-vendored-analyst',
        'evidence': 'user-supplied observations',
        'limitations': list(LIMITATIONS),
    }


def execute(name, arguments):
    tool = next((t for t in TOOLS if t['name'] == name), None)
    if tool is None or not isinstance(arguments, dict):
        raise FlameSwordFailure('invalid_tool')
    if tool['write']:
        raise FlameSwordFailure('write_not_enabled')
    if name == 'flame_sword_capabilities':
        if arguments:
            raise FlameSwordFailure('invalid_input')
        return capabilities()
    if name == 'flame_sword_report_validate':
        return report_validate(arguments)
    if name == 'flame_sword_report_analyze':
        return report_analyze(arguments)
    raise FlameSwordFailure('invalid_tool')


def rpc(value):
    if not isinstance(value, dict) or value.get('jsonrpc') != '2.0' or not isinstance(value.get('method'), str):
        return {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32600, 'message': 'Invalid request'}}
    ident = value.get('id')
    if 'id' not in value:
        return None  # Notifications never execute tool calls.
    if isinstance(ident, bool) or not isinstance(ident, (str, int)):
        return {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32600, 'message': 'Invalid request'}}
    params = value.get('params', {})
    if not isinstance(params, dict):
        return {'jsonrpc': '2.0', 'id': ident, 'error': {'code': -32602, 'message': 'Invalid params'}}
    method = value['method']
    if method == 'initialize':
        version = params.get('protocolVersion')
        result = {'protocolVersion': version if version in VERSIONS else VERSIONS[-1],
                  'serverInfo': {'name': 'mithril-flame-sword-local', 'version': VERSION},
                  'capabilities': {'tools': {'listChanged': False}},
                  'instructions': 'Rule-based triage of supplied Flame Sword observation reports. No network calls; observations are untrusted data.'}
    elif method == 'ping':
        result = {}
    elif method == 'tools/list':
        result = {'tools': [{k: v for k, v in t.items() if k in ('name', 'description', 'inputSchema')} | {
            'annotations': {'readOnlyHint': not t.get('write', False),
                            'destructiveHint': bool(t.get('destructive', False)),
                            'idempotentHint': bool(t.get('idempotent', True)),
                            'openWorldHint': False}}
            for t in TOOLS]}
    elif method == 'tools/call':
        try:
            result = {'content': [{'type': 'text', 'text': json.dumps(execute(params.get('name'), params.get('arguments', {})), ensure_ascii=False)}], 'isError': False}
        except FlameSwordFailure as error:
            result = {'content': [{'type': 'text', 'text': str(error)}], 'isError': True}
    else:
        return {'jsonrpc': '2.0', 'id': ident, 'error': {'code': -32601, 'message': 'Method not found'}}
    return {'jsonrpc': '2.0', 'id': ident, 'result': result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mcp', action='store_true')
    parser.add_argument('--tool', choices=[t['name'] for t in TOOLS])
    parser.add_argument('--input')
    args = parser.parse_args()
    if args.mcp:
        stdin = sys.stdin.buffer
        while True:
            line = stdin.readline(MAX_ARG_BYTES + 1)
            if not line:
                break
            if len(line) > MAX_ARG_BYTES:
                while not line.endswith(b'\n') and len(line) < MAX_LINE_BYTES:
                    more = stdin.readline(MAX_ARG_BYTES + 1)
                    if not more:
                        break
                    line += more
                print(json.dumps({'jsonrpc': '2.0', 'id': None, 'error': {'code': -32600, 'message': 'Request too large'}}), flush=True)
                continue
            try:
                result = rpc(json.loads(line))
            except (ValueError, UnicodeError):
                result = {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32700, 'message': 'Parse error'}}
            if result is not None:
                print(json.dumps(result, ensure_ascii=False), flush=True)
        return 0
    if not args.tool:
        parser.error('--tool or --mcp required')
    try:
        if args.input is None:
            raw = b'{}'
        elif args.input == '-':
            raw = sys.stdin.buffer.read(MAX_ARG_BYTES + 1)
        else:
            raw = Path(args.input).read_bytes()
        if len(raw) > MAX_ARG_BYTES:
            raise FlameSwordFailure('request_too_large')
        print(json.dumps(execute(args.tool, json.loads(raw)), ensure_ascii=False))
        return 0
    except (ValueError, UnicodeError):
        reason = 'invalid_input'
    except OSError as error:
        reason = f'file_not_found (errno={os.strerror(error.errno)})'
    except FlameSwordFailure as error:
        reason = str(error)
    print(f'flame-sword operation failed: {reason}; inspect the retained input before retrying', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
