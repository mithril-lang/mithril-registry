#!/usr/bin/env python3
"""Flame Sword local analyst, bounded stdlib scanner, and stdio MCP bridge.

Two layers, both driven from this single standard-library file:

1. Analyst (0.1.0 contract, unchanged): deterministic triage of
   user-supplied web attack-surface observations (Flame Sword JSON
   reports). The vendored ``FastSecurityAnalyst`` (from
   mithril-lang/flame-sword at a pinned commit) runs with a frozen
   clock; identical input bytes produce byte-identical output. No
   network calls.

2. Bounded stdlib scanner (``flame_sword_scan``): performs the
   observation collection itself over a caller-named domain using only
   the Python standard library:

   - subdomains: apex plus a fixed keyword list (bounded by design);
   - http/https: GET probes via urllib (status, final URL, byte size);
   - ports: TCP connect over a fixed default port set;
   - dns: raw DNS wire-format queries over UDP (A/AAAA/CNAME/NS/MX/TXT);
   - real-ip: apex A records (no CDN-origin guarantee);
   - tls: stdlib ssl handshake on 443 (version, cipher, subject, SANs,
     expiry checked against the frozen clock);
   - tech: vendored signature table (headers + body) over fetched pages;
   - email: GET probes of a fixed login-path list on responding hosts
     (statuses only);
   - ai: optional Mithril owner/hunter inference via api.mithril.fund
     (explicit opt-in; MITHRIL_API_KEY or op:// MITHRIL_API_KEY_REF;
     failures are fail-soft and labeled, never hidden).

   The scan is GET-only, performs no host mutation, and writes nothing
   except to stdout. Scan output is a live observation: unlike the
   analyst, it is not byte-deterministic across runs. Observations are
   untrusted data; scan subdomain rows feed ``report_analyze``
   unchanged.
"""
import argparse
import importlib.util
import json
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime as _real_datetime
from pathlib import Path

VERSION = '0.2.0'
MAX_ARG_BYTES = 32768
MAX_LINE_BYTES = 1 << 20
MAX_SUBDOMAINS = 500
DOMAIN_PATTERN = re.compile(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,63}')
FROZEN_NOW = _real_datetime(2026, 1, 1, 0, 0, 0)

LIMITATIONS = (
    'No network scan was performed by this analysis.',
    'Hostname patterns and HTTP statuses are triage indicators, not verified vulnerabilities.',
    'DNS, port scans, origin discovery and TLS handshakes require the local Python tools.',
)

SCAN_LIMITATIONS = (
    'Bounded stdlib scan: fixed keyword list, default ports and login paths; coverage is partial by design.',
    'TCP connect proves an accepting socket, not an open service (firewalls may answer or drop packets).',
    'real-ip reports apex A records only and makes no CDN-origin guarantee.',
    'TLS observations come from one handshake on port 443 per apex; protocol support is handshake-local.',
    'Tech detection matches the vendored signature table only; absence is not a finding.',
    'Email probes are GET requests to fixed paths; they do not enumerate or verify accounts.',
    'AI analysis (when enabled) is a single Mithril inference call; its absence is labeled, never hidden.',
    'Scan output is a live observation and is not byte-deterministic across runs.',
    'A zero-finding scan is not a safety or completeness statement.',
)

SCAN_KEYWORDS = (
    'www', 'api', 'app', 'admin', 'mail', 'ftp', 'blog', 'dev', 'staging',
    'beta', 'test', 'web', 'shop', 'docs', 'status', 'login', 'account',
)
DEFAULT_PORTS = (80, 443, 8080, 8443)
LOGIN_PATHS = ('/login', '/signin', '/admin', '/admin/login', '/wp-login.php', '/user/login')
BODY_LIMIT = 65536
DNS_TIMEOUT_S = 3.0
HTTP_TIMEOUT_S = 8.0
CONNECT_TIMEOUT_S = 2.0
MITHRIL_BASE_URL = 'https://api.mithril.fund/v1'
MITHRIL_MODEL = 'qwen/qwen3.8-27b'
EMAIL_PROBE_STATUSES = (200, 301, 302, 401, 403)

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


# --------------------------------------------------------------------------
# Bounded stdlib scanner
# --------------------------------------------------------------------------

def _load_tech_signatures():
    data = json.loads((VENDOR_DIR / 'tech_signatures.json').read_text(encoding='utf-8'))
    return data.get('signatures', [])


def _subdomain_candidates(domain):
    hosts = [domain]
    for keyword in SCAN_KEYWORDS:
        hosts.append(f'{keyword}.{domain}')
    return hosts


def _http_probe(url):
    """GET probe; returns a status/size/final-url observation (no mutation)."""
    request = urllib.request.Request(
        url, headers={'User-Agent': 'mithril-flame-sword/0.2 (+local-scan)',
                      'Accept': 'text/html,*/*'})
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_S) as response:
            body = response.read(BODY_LIMIT)
            headers = [(k, v) for k, v in response.headers.items()][:64]
            return {'status': response.status, 'final_url': response.geturl(),
                    'bytes': len(body), 'body': body, 'headers': headers, 'error': None}
    except urllib.error.HTTPError as error:
        try:
            body = error.read(BODY_LIMIT)
        except Exception:
            body = b''
        headers = [(k, v) for k, v in (error.headers or {}).items()] if error.headers else []
        return {'status': error.code, 'final_url': error.url, 'bytes': len(body),
                'body': body, 'headers': headers[:64], 'error': None}
    except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as error:
        reason = getattr(error, 'reason', None) or error
        return {'status': None, 'final_url': None, 'bytes': 0, 'body': b'', 'headers': [],
                'error': f'{type(error).__name__}:{reason}'}


def _tcp_probe(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT_S)
    started = time.monotonic()
    try:
        sock.connect((host, port))
        return {'port': port, 'open': True,
                'rtt_ms': round((time.monotonic() - started) * 1000)}
    except (OSError, socket.timeout) as error:
        return {'port': port, 'open': False, 'rtt_ms': None,
                'error': f'{type(error).__name__}:{getattr(error, "reason", error)}'}
    finally:
        sock.close()


def _dns_name_bytes(name):
    out = b''
    for label in name.split('.'):
        raw = label.encode('ascii')
        if not (1 <= len(raw) <= 63):
            raise FlameSwordFailure('invalid_dns_name')
        out += bytes([len(raw)]) + raw
    return out + b'\x00'


def _dns_read_name(data, offset):
    """Decode a (possibly compressed) DNS name starting at ``offset``."""
    labels = []
    hops = 0
    while hops < 64:
        length = data[offset]
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack('>H', data[offset:offset + 2])[0] & 0x3FFF
            hops += 2
            offset = pointer
            continue
        if length == 0:
            break
        labels.append(data[offset + 1:offset + 1 + length].decode('ascii', 'replace'))
        offset += 1 + length
        hops += 1
    return '.'.join(labels)


def _dns_query(host, qtype, resolver='1.1.1.1'):
    """Raw DNS query; tries UDP first, falls back to TCP (same wire format)."""
    packet = (struct.pack('>HHHHHH', 0x9c3d, 0x8400, 1, 0, 0, 0)
              + _dns_name_bytes(host.lower())
              + struct.pack('>HH', qtype, 1))
    raw = _dns_query_udp(packet, resolver)
    error = None
    if raw is None:
        error = 'udp_unreachable'
        raw = _dns_query_tcp(packet, resolver)
        if raw is None:
            return {'records': [], 'error': f'dns_unreachable ({error}; tcp fallback also failed)'}
    try:
        return _dns_decode(raw, qtype, first_error=error)
    except FlameSwordFailure as error:
        return {'records': [], 'error': str(error)}


def _dns_query_udp(packet, resolver):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(DNS_TIMEOUT_S)
    try:
        sock.sendto(packet, (resolver, 53))
        raw, _ = sock.recvfrom(4096)
        return raw
    except (OSError, socket.timeout):
        return None
    finally:
        sock.close()


def _dns_query_tcp(packet, resolver):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(DNS_TIMEOUT_S)
    try:
        sock.connect((resolver, 53))
        sock.sendall(struct.pack('>H', len(packet)) + packet)
        raw = sock.recv(2)
        if len(raw) < 2:
            return None
        length = struct.unpack('>H', raw)[0]
        data = b''
        while len(data) < length:
            chunk = sock.recv(min(4096, length - len(data)))
            if not chunk:
                break
            data += chunk
        return data
    except (OSError, socket.timeout):
        return None
    finally:
        sock.close()


def _dns_decode(raw, qtype, first_error=None):
    if len(raw) < 12:
        return {'records': [], 'error': first_error or 'dns_short_response'}
    _, qd, an, _, _ = struct.unpack('>HHHHH', raw[2:12])
    if qd != 1 or not an:
        return {'records': [], 'error': first_error or 'dns_no_answer'}
    values = []
    offset = 12
    while raw[offset] != 0:  # skip question name
        offset += 1 + raw[offset]
    offset += 1 + 4  # root label + qtype/qclass
    for _ in range(an):
        first = raw[offset]
        if first & 0xC0 == 0xC0:  # compression pointer
            offset += 2
        else:
            while raw[offset] != 0:
                offset += 1 + raw[offset]
            offset += 1
        rtype, _rclass, _ttl, rlen = struct.unpack('>HHIH', raw[offset:offset + 10])
        rdata_start = offset + 10
        rdata = raw[rdata_start:rdata_start + rlen]
        offset = rdata_start + rlen
        if rtype == 1 and len(rdata) == 4:  # A
            values.append('.'.join(str(b) for b in rdata))
        elif rtype == 28 and len(rdata) == 16:  # AAAA
            values.append('.'.join(str(b) for b in rdata))
        elif rtype in (5, 2):  # CNAME / NS
            values.append(_dns_read_name(raw, rdata_start))
        elif rtype == 15 and rlen >= 3:  # MX: preference(2) + exchange name
            values.append({'preference': struct.unpack('>H', rdata[:2])[0],
                           'exchange': _dns_read_name(raw, rdata_start + 2)})
        elif rtype == 16:  # TXT
            chunks, t = [], 0
            while t < rlen:
                ln = rdata[t]
                chunks.append(rdata[t + 1:t + 1 + ln].decode('utf-8', 'replace'))
                t += 1 + ln
            values.append(' '.join(chunks))
    return {'records': values, 'error': None}


def _tls_probe(host, port=443, now=FROZEN_NOW):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=HTTP_TIMEOUT_S) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
                not_after_value = cert.get('notAfter')
                if not isinstance(not_after_value, str):
                    not_after = None
                else:
                    not_after = _real_datetime.strptime(not_after_value, '%b %d %H:%M:%S %Y %Z')
                return {
                    'tls_version': tls.version(),
                    'cipher': tls.cipher()[0] if tls.cipher() else None,
                    'subject': dict(item[0] for item in cert.get('subject', ())).get('commonName'),
                    'san': [name for (_tag, name) in cert.get('subjectAltName', ())],
                    'not_after': not_after_value,
                    'expired_at_scan': (not_after < now) if not_after is not None else None,
                    'error': None,
                }
    except (ssl.SSLError, socket.timeout, ConnectionError, OSError) as error:
        return {'tls_version': None, 'cipher': None, 'subject': None, 'san': [],
                'not_after': None, 'expired_at_scan': None,
                'error': f'{type(error).__name__}:{getattr(error, "reason", error)}'}


def _tech_detect(probe, signatures):
    found = []
    if not probe or probe.get('status') is None:
        return found
    headers = {k.lower(): v for k, v in (probe.get('headers') or [])}
    body = (probe.get('body') or b'').decode('utf-8', 'replace')
    for signature in signatures:
        matched = False
        for check in signature.get('checks', []):
            if check.get('type') == 'header':
                value = headers.get(check.get('field', ''), '').lower()
                if value and re.search(check.get('pattern', ''), value, re.IGNORECASE):
                    matched = True
                    break
            elif body and re.search(check.get('pattern', ''), body, re.IGNORECASE):
                matched = True
                break
        if matched:
            found.append(signature['name'])
    return found


def _email_probe(host, scheme):
    results = []
    for path in LOGIN_PATHS:
        probe = _http_probe(f'{scheme}://{host}{path}')
        results.append({'path': path, 'status': probe['status'], 'error': probe['error']})
    return results


def _ai_analyze(scan, api_key):
    payload = {
        'model': MITHRIL_MODEL,
        'messages': [{'role': 'user', 'content': json.dumps({
            'task': 'flame-sword attack-surface owner/hunter analysis',
            'domain': scan['domain'],
            'observations': scan,
        }, ensure_ascii=False)}],
    }
    request = urllib.request.Request(
        f'{MITHRIL_BASE_URL}/chat/completions',
        data=json.dumps(payload).encode(),
        headers={'Content-Type': 'application/json',
                 'Authorization': f'Bearer {api_key}',
                 'User-Agent': 'flame-sword/0.2 (mithril-registry-skill)'},
        method='POST')
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            data = json.loads(response.read().decode('utf-8'))
        content = data['choices'][0]['message']['content']
        try:
            return {'raw': None, 'structured': json.loads(content),
                    'provider': 'Mithril', 'model': MITHRIL_MODEL, 'error': None}
        except ValueError:
            return {'raw': content, 'structured': None,
                    'provider': 'Mithril', 'model': MITHRIL_MODEL, 'error': None}
    except (urllib.error.URLError, socket.timeout, ConnectionError, OSError, ValueError) as error:
        reason = getattr(error, 'reason', None) or error
        return {'raw': None, 'structured': None, 'provider': 'Mithril',
                'model': MITHRIL_MODEL, 'error': f'{type(error).__name__}:{reason}'}


def _resolve_mithril_key():
    key = os.environ.get('MITHRIL_API_KEY')
    if key:
        return key
    ref = os.environ.get('MITHRIL_API_KEY_REF')
    if ref and ref.startswith('op://') and shutil.which('op'):
        try:
            proc = subprocess.run([shutil.which('op'), 'read', ref],
                                  capture_output=True, text=True, timeout=30, check=True)
            value = proc.stdout.strip()
            if value:
                os.environ['MITHRIL_API_KEY'] = value
                return value
        except (OSError, subprocess.SubprocessError):
            return None
    return None


def scan_domain(raw):
    """Bounded stdlib scan of a caller-named domain (GET-only, no mutation)."""
    if not isinstance(raw, dict):
        raise FlameSwordFailure('invalid_input')
    domain = raw.get('domain', '')
    if not isinstance(domain, str) or len(domain) > 253 or not DOMAIN_PATTERN.fullmatch(domain):
        raise FlameSwordFailure('invalid_domain')
    domain = domain.lower()
    options = raw.get('options', {})
    if not isinstance(options, dict):
        raise FlameSwordFailure('invalid_options')
    allowed = ('subdomains', 'ports', 'dns', 'real_ip', 'tls', 'tech', 'email', 'ai')
    for key, value in options.items():
        if key not in allowed or not isinstance(value, bool):
            raise FlameSwordFailure('invalid_options')

    wanted = {key: bool(options.get(key, True)) for key in allowed}
    wanted['ai'] = bool(options.get('ai', False))

    scan = {'domain': domain, 'execution': 'local-cli-stdlib-scanner',
            'options': wanted, 'observations': {}}

    signatures = _load_tech_signatures() if wanted['tech'] else []
    hosts = _subdomain_candidates(domain) if wanted['subdomains'] else [domain]
    rows = []
    for host in hosts:
        http = _http_probe(f'http://{host}')
        https = _http_probe(f'https://{host}')
        row = {'subdomain': host,
               'http_status': http['status'], 'https_status': https['status'],
               'http_error': http['error'], 'https_error': https['error'],
               'http_final_url': http['final_url'], 'https_final_url': https['final_url'],
               'http_bytes': http['bytes'], 'https_bytes': https['bytes']}
        primary = https if https['status'] is not None else http
        if signatures:
            row['tech'] = _tech_detect(primary, signatures)
        responding = (https['status'] in EMAIL_PROBE_STATUSES) or (http['status'] in EMAIL_PROBE_STATUSES)
        if wanted['email'] and responding:
            row['login_paths'] = _email_probe(host, 'https' if https['status'] is not None else 'http')
        if wanted['tls'] and host == domain:
            row['tls'] = _tls_probe(host, 443)
        rows.append(row)
    scan['observations']['subdomains'] = rows

    if wanted['ports']:
        scan['observations']['ports'] = [_tcp_probe(domain, port) for port in DEFAULT_PORTS]
    if wanted['dns']:
        scan['observations']['dns'] = {
            'A': _dns_query(domain, 1),
            'AAAA': _dns_query(domain, 28),
            'CNAME': _dns_query(domain, 5),
            'NS': _dns_query(domain, 2),
            'MX': _dns_query(domain, 15),
            'TXT': _dns_query(domain, 16),
        }
    if wanted['real_ip']:
        apex = _dns_query(domain, 1)
        scan['observations']['real_ip'] = {
            'records': apex['records'], 'error': apex['error'],
            'guarantee': 'apex A records only; no CDN-origin guarantee',
        }

    if wanted['ai']:
        api_key = _resolve_mithril_key()
        if api_key is None:
            scan['observations']['ai'] = {'error': 'mithril_key_unavailable'}
        else:
            scan['observations']['ai'] = _ai_analyze(scan, api_key)

    return scan


# --------------------------------------------------------------------------
# Analyst operations (0.1.0 contract, unchanged)
# --------------------------------------------------------------------------

def capabilities():
    return {
        'name': 'mithril-flame-sword',
        'version': VERSION,
        'execution': 'local-cli-vendored-analyst',
        'evidence': 'user-supplied observations or local stdlib scan',
        'operations': [
            {'id': 'report_validate', 'summary': 'Validate a supplied observation report against the Flame Sword contract.', 'network': False},
            {'id': 'report_analyze', 'summary': 'Run the vendored rule-based analyst over validated observations.', 'network': False},
            {'id': 'scan_domain', 'summary': 'Bounded stdlib scan (GET-only) of a caller-named domain: subdomains, HTTP(S), ports, DNS, real-ip, TLS, tech, email, optional Mithril AI.', 'network': True},
        ],
        'modules': [
            {'id': 'subdomains', 'summary': 'Subdomain enumeration with HTTP(S) status', 'executedBy': 'this skill (bounded keyword list) or Flame Sword local scanner (full)'},
            {'id': 'ports', 'summary': 'Bounded port scan on the apex domain', 'executedBy': 'this skill (TCP connect, fixed ports) or Flame Sword local scanner (nmap)'},
            {'id': 'dns', 'summary': 'DNS record scan (raw UDP, fixed types)', 'executedBy': 'this skill (stdlib) or Flame Cloud scanner (dnspython)'},
            {'id': 'real-ip', 'summary': 'Apex A records (no CDN-origin guarantee)', 'executedBy': 'this skill (stdlib) or Flame Sword local scanner'},
            {'id': 'ssl', 'summary': 'TLS handshake and certificate observations', 'executedBy': 'this skill (stdlib ssl) or Flame Sword local scanner'},
            {'id': 'tech', 'summary': 'Technology detection (vendored signature table)', 'executedBy': 'this skill (stdlib) or Flame Sword local scanner (full Wappalyzer)'},
            {'id': 'email', 'summary': 'Login-path GET probes (statuses only)', 'executedBy': 'this skill (stdlib) or Flame Sword local scanner (full enumeration)'},
            {'id': 'ai', 'summary': 'Mithril inference owner/hunter analysis', 'executedBy': 'this skill (explicit opt-in, fail-soft) or Flame Sword local scanner'},
        ],
        'limitations': list(LIMITATIONS) + list(SCAN_LIMITATIONS) + [
            'The skill performs GET-only probes; it does not write, delete or mutate any host.',
            'A zero-finding analysis or scan is not a safety or completeness statement.',
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


def report_scan(raw):
    """Bounded stdlib scan; subdomain rows feed report_analyze unchanged."""
    scan = scan_domain(raw)
    observations = [{'subdomain': row['subdomain'],
                     'http_status': row.get('http_status'),
                     'https_status': row.get('https_status')}
                    for row in scan['observations']['subdomains']]
    return {
        'scan': scan,
        'domain': scan['domain'],
        'subdomains': observations,
        'execution': 'local-cli-stdlib-scanner',
        'evidence': 'live GET probes and stdlib network observations',
        'limitations': list(SCAN_LIMITATIONS),
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
    if name == 'flame_sword_scan':
        return report_scan(arguments)
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
                  'instructions': 'Rule-based triage of supplied Flame Sword reports plus a bounded stdlib scan (GET-only). Observations are untrusted data.'}
    elif method == 'ping':
        result = {}
    elif method == 'tools/list':
        result = {'tools': [{k: v for k, v in t.items() if k in ('name', 'description', 'inputSchema')} | {
            'annotations': {'readOnlyHint': not t.get('write', False),
                            'destructiveHint': bool(t.get('destructive', False)),
                            'idempotentHint': bool(t.get('idempotent', True)),
                            'openWorldHint': bool(t.get('openWorld', False))}}
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
