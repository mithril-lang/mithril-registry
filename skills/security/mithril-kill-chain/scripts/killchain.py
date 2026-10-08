#!/usr/bin/env python3
"""Cyber kill-chain local evaluator and stdio MCP bridge; Python standard library only.

Deterministic phase coverage assessment over the seven Lockheed Martin cyber
kill-chain phases, plus a bounded local .pcap probe (classic pcap v2) that
surfaces C2 candidates: DNS queries, TLS SNI, cleartext HTTP hosts, and
beacon-like TCP periodicity. No network calls; supplied evidence is data.
"""
import argparse
import json
import math
import struct
import sys
from pathlib import Path

VERSION = '0.1.0'
MAX_ARG_BYTES = 32768
MAX_PCAP_BYTES = 16 * 1024 * 1024
MAX_INDICATORS = 50
BEACON_MIN_INTERVAL = 1.0
BEACON_MAX_INTERVAL = 3600.0
BEACON_CV = 0.25
BEACON_MIN_SAMPLES = 3

PHASES = (
    {
        'id': 1, 'key': 'reconnaissance',
        'ja': '偵察', 'en': 'Reconnaissance',
        'summary': 'Target information gathering: brand assets, domains, employee contact and public evidence.',
        'evidenceTypes': ['domain-asset', 'brand-asset', 'osint-record', 'email-identity'],
        'registryEntries': ['mithril-brand-protection', 'mithril-public-review'],
    },
    {
        'id': 2, 'key': 'weaponization',
        'ja': '武器化', 'en': 'Weaponization',
        'summary': 'Payload and message construction: sample hashes, attachment and template artifacts.',
        'evidenceTypes': ['sample-hash', 'email-artifact', 'template-artifact'],
        'registryEntries': ['mithril-security-suite', 'mithril-cybersecurity-products'],
    },
    {
        'id': 3, 'key': 'delivery',
        'ja': 'デリバリー', 'en': 'Delivery',
        'summary': 'Payload delivery to the target: email headers, URLs and domain observations.',
        'evidenceTypes': ['email-header', 'url-observation', 'domain-observation'],
        'registryEntries': ['mithril-brand-protection', 'mithril-cybersecurity-products'],
    },
    {
        'id': 4, 'key': 'exploitation',
        'ja': 'エクスプロイト', 'en': 'Exploitation',
        'summary': 'Attack code execution: process and security event records, DAST findings.',
        'evidenceTypes': ['security-event', 'dast-finding', 'process-record'],
        'registryEntries': ['mithril-security-suite', 'mithril-cybersecurity-products'],
    },
    {
        'id': 5, 'key': 'installation',
        'ja': 'インストール', 'en': 'Installation',
        'summary': 'Persistence and backdoors: host baseline deltas, service and account changes.',
        'evidenceTypes': ['host-baseline', 'service-change', 'account-change'],
        'registryEntries': ['mithril-security-suite'],
    },
    {
        'id': 6, 'key': 'command-and-control',
        'ja': '遠隔操作', 'en': 'Command and Control',
        'summary': 'C2 communication: beacon periodicity, DNS queries, TLS SNI, cleartext HTTP hosts.',
        'evidenceTypes': ['pcap-probe', 'beacon-record', 'dns-record', 'tls-record'],
        'registryEntries': ['mithril-kill-chain'],
    },
    {
        'id': 7, 'key': 'actions-on-objectives',
        'ja': '目的の実行', 'en': 'Actions on Objectives',
        'summary': 'Objective execution: data theft, alteration and destruction evidence.',
        'evidenceTypes': ['exfiltration-record', 'modification-record', 'destruction-record'],
        'registryEntries': ['mithril-forensic-evidence', 'mithril-cybersecurity-products'],
    },
)

TOOLS = json.loads(Path(__file__).with_name('tools.json').read_text())
VERSIONS = ('2025-03-26', '2025-06-18', '2025-11-25')
KEY_TO_PHASE = {p['key']: p for p in PHASES}
ID_TO_PHASE = {p['id']: p for p in PHASES}


class KillChainFailure(Exception):
    pass


def phase_definitions():
    return {'phases': [dict(p) for p in PHASES]}


def _bounded_uuid(value):
    return isinstance(value, str) and len(value) <= 128 and all(c.isalnum() or c in '-_' for c in value)


def evaluate(records):
    if not isinstance(records, dict):
        raise KillChainFailure('invalid_input')
    allowed = {'caseId', 'phases'}
    if set(records) - allowed:
        raise KillChainFailure('invalid_input')
    case_id = records.get('caseId')
    if case_id is not None and (not isinstance(case_id, str) or not _bounded_uuid(case_id)):
        raise KillChainFailure('invalid_input')
    phase_rows = records.get('phases', [])
    if not isinstance(phase_rows, list) or len(phase_rows) > 7:
        raise KillChainFailure('invalid_input')
    seen = set()
    results = []
    for row in phase_rows:
        if not isinstance(row, dict) or row.get('phase') not in KEY_TO_PHASE:
            raise KillChainFailure('invalid_input')
        phase = KEY_TO_PHASE[row['phase']]
        if row['phase'] in seen or set(row) - {'phase', 'evidence'}:
            raise KillChainFailure('invalid_input')
        seen.add(row['phase'])
        evidence = row.get('evidence', [])
        if not isinstance(evidence, list) or len(evidence) > 100:
            raise KillChainFailure('invalid_input')
        matched, unmatched = 0, 0
        for item in evidence:
            if not isinstance(item, dict) or set(item) - {'type', 'source', 'note'}:
                raise KillChainFailure('invalid_input')
            etype = item.get('type')
            if not isinstance(etype, str) or not etype:
                raise KillChainFailure('invalid_input')
            for field, limit in (('source', 512), ('note', 1024)):
                value = item.get(field)
                if value is not None and (not isinstance(value, str) or len(value) > limit):
                    raise KillChainFailure('invalid_input')
            if etype in phase['evidenceTypes']:
                matched += 1
            else:
                unmatched += 1
        status = 'covered' if matched else ('partial' if unmatched else 'absent')
        results.append({
            'phase': phase['id'], 'key': phase['key'], 'status': status,
            'matchedEvidence': matched, 'unmatchedEvidence': unmatched,
        })
    results.sort(key=lambda r: r['phase'])
    covered = [r for r in results if r['status'] == 'covered']
    first = min((r['phase'] for r in covered), default=None)
    counted = {r['phase'] for r in results if r['status'] in ('covered', 'partial')}
    absent_ids = [p['id'] for p in PHASES if p['id'] not in counted]
    return {
        'caseId': case_id,
        'verdict': (f'first-covered-phase-{first}' if first else 'no-covered-phase'),
        'coveredPhases': [r['phase'] for r in covered],
        'partialPhases': [r['phase'] for r in results if r['status'] == 'partial'],
        'absentPhases': absent_ids,
        'absentPhaseKeys': [ID_TO_PHASE[i]['key'] for i in absent_ids],
        'phases': results,
        'note': 'Coverage is an evidence-availability statement over supplied records, not an attack attribution or conclusion.',
    }


def _read_pcap(path):
    raw = Path(path).read_bytes()
    if len(raw) > MAX_PCAP_BYTES:
        raise KillChainFailure('file_too_large')
    if len(raw) < 24 or raw[:4] not in (b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1'):
        raise KillChainFailure('unsupported_pcap')
    big = raw[:4] == b'\xa1\xb2\xc3\xd4'
    fmt = '>' if big else '<'
    linktype = struct.unpack(fmt + 'I', raw[20:24])[0]
    if linktype not in (1, 12):
        raise KillChainFailure('unsupported_linktype')
    packets, offset = [], 24
    while offset + 16 <= len(raw):
        secs, usecs, incl, orig = struct.unpack(fmt + 'IIII', raw[offset:offset + 16])
        offset += 16
        if incl > orig or incl > len(raw) - offset:
            break
        packets.append((secs, usecs, raw[offset:offset + incl]))
        offset += incl
        if len(packets) >= 20000:
            break
    return linktype, packets


def _ipv4(payload, linktype):
    if linktype == 1:
        if len(payload) < 14:
            return None
        ethertype = (payload[12] << 8) | payload[13]
        if ethertype != 0x0800:
            return None
        payload = payload[14:]
    else:  # loopback
        if len(payload) < 4:
            return None
        if payload[0] != 4:
            return None
        payload = payload[4:]
    if len(payload) < 20 or payload[0] >> 4 != 4:
        return None
    ihl = (payload[0] & 0x0F) * 4
    if ihl < 20 or len(payload) < ihl:
        return None
    proto = payload[9]
    return {
        'src': '.'.join(str(b) for b in payload[12:16]),
        'dst': '.'.join(str(b) for b in payload[16:20]),
        'proto': proto, 'payload': payload[ihl:],
    }


def _ports(payload):
    if len(payload) < 6:
        return None
    return ((payload[0] << 8) | payload[1], (payload[2] << 8) | payload[3])


def _dns_name(raw, offset):
    parts = []
    for _ in range(64):
        if offset >= len(raw):
            return None
        length = raw[offset]
        if length == 0:
            return '.'.join(parts) if parts else None
        if length & 0xC0:
            return None
        offset += 1
        if offset + length > len(raw):
            return None
        parts.append(raw[offset:offset + length].decode('ascii', 'ignore'))
        offset += length
    return None


def _tcp_payload(tcp_segment):
    """Return the payload after the TCP segment header (data offset, in 32-bit words)."""
    if len(tcp_segment) < 20:
        return b''
    doff = (tcp_segment[12] >> 4) * 4
    if doff < 20 or doff > len(tcp_segment):
        return b''
    return tcp_segment[doff:]


def _tls_sni(payload):
    """Walk a TLS record starting at payload[0] and return the SNI hostname, if present."""
    if len(payload) < 5 or payload[0] != 0x16:
        return None
    if payload[5:6] != b'\x01':  # ClientHello handshake type
        return None
    pos = 8  # record header (5) + handshake type (1) + handshake length (2)
    if pos + 2 > len(payload):
        return None
    pos += 2  # legacy version
    pos += 32  # legacy random
    if pos + 1 > len(payload):
        return None
    pos += 1 + payload[pos]  # session id
    if pos + 2 > len(payload):
        return None
    pos += 2 + ((payload[pos] << 8) | payload[pos + 1])  # cipher suites
    if pos + 1 > len(payload):
        return None
    pos += 1 + payload[pos]  # compression methods
    if pos + 2 > len(payload):
        return None
    ext_len = (payload[pos] << 8) | payload[pos + 1]
    pos += 2
    ext_end = pos + ext_len
    while pos + 4 <= min(ext_end, len(payload)):
        ext_type = (payload[pos] << 8) | payload[pos + 1]
        ext_size = (payload[pos + 2] << 8) | payload[pos + 3]
        ext_data = payload[pos + 4:pos + 4 + ext_size]
        pos += 4 + ext_size
        if ext_type != 0 or len(ext_data) < 2:
            continue
        list_len = (ext_data[0] << 8) | ext_data[1]
        inner = ext_data[2:2 + list_len]
        if len(inner) < 3:
            return None
        if inner[0] != 0:
            return None
        name_len = (inner[1] << 8) | inner[2]
        if name_len < 1 or 3 + name_len > len(inner):
            return None
        return inner[3:3 + name_len].decode('ascii', 'ignore')
    return None


def _coefficient_of_variation(values):
    n = len(values)
    mean = sum(values) / n
    if mean <= 0:
        return math.inf
    variance = sum((v - mean) ** 2 for v in values) / n
    return math.sqrt(variance) / mean


def pcap_probe(path):
    linktype, packets = _read_pcap(path)
    dns, sni, hosts = [], [], []
    streams = {}
    for secs, usecs, raw in packets:
        time = secs + usecs / 1_000_000
        parsed = _ipv4(raw, linktype)
        if parsed is None:
            continue
        ports = _ports(parsed['payload'])
        if ports is None:
            continue
        if parsed['proto'] == 17 and (ports[0] == 53 or ports[1] == 53):
            # UDP header (8) + DNS header (12): question QNAME starts at 20.
            name = None
            if len(parsed['payload']) >= 20:
                name = _dns_name(parsed['payload'], 20)
            if name and name not in dns and len(dns) < MAX_INDICATORS:
                dns.append(name)
        elif parsed['proto'] == 6:
            tcp_data = _tcp_payload(parsed['payload'])
            if ports[1] == 443 and ports[0] != 443:
                sni_value = _tls_sni(tcp_data)
                if sni_value and sni_value not in sni and len(sni) < MAX_INDICATORS:
                    sni.append(sni_value)
            upper = tcp_data[:4096]
            idx = upper.find(b'Host: ')
            if idx >= 0:
                end = upper.find(b'\r', idx)
                chunk = upper[idx + 6: end if end >= 0 else len(upper)]
                host = chunk.split(b'\n', 1)[0].strip().decode('ascii', 'ignore')
                if host and host not in hosts and len(hosts) < MAX_INDICATORS:
                    hosts.append(host)
        key = (parsed['src'], parsed['dst'], ports[0], ports[1])
        streams.setdefault(key, []).append(time)
    beacons = []
    for (src, dst, sport, dport), times in streams.items():
        times.sort()
        intervals = [b - a for a, b in zip(times, times[1:]) if 0 < b - a]
        if len(intervals) < BEACON_MIN_SAMPLES:
            continue
        median = sorted(intervals)[len(intervals) // 2]
        if not (BEACON_MIN_INTERVAL <= median <= BEACON_MAX_INTERVAL):
            continue
        cv = _coefficient_of_variation(intervals)
        if cv <= BEACON_CV:
            beacons.append({'src': src, 'dst': dst, 'srcPort': sport, 'dstPort': dport,
                            'samples': len(intervals) + 1, 'medianInterval': round(median, 3),
                            'cv': round(cv, 3)})
        if len(beacons) >= MAX_INDICATORS:
            break
    beacons.sort(key=lambda b: (b['src'], b['dst'], b['dstPort']))
    return {
        'linkType': linktype, 'packets': len(packets),
        'dnsQueries': dns, 'tlsSni': sni, 'httpHosts': hosts,
        'beaconCandidates': beacons,
        'note': 'Beacon candidates are periodicity observations over supplied bytes, not confirmed C2 channels.',
    }


def execute(name, arguments):
    tool = next((t for t in TOOLS if t['name'] == name), None)
    if tool is None or not isinstance(arguments, dict):
        raise KillChainFailure('invalid_tool')
    if tool['write']:
        raise KillChainFailure('write_not_enabled')
    if name == 'killchain_phases':
        if arguments:
            raise KillChainFailure('invalid_input')
        return phase_definitions()
    if name == 'killchain_evaluate':
        return evaluate(arguments)
    if name == 'killchain_pcap_probe':
        if set(arguments) != {'path'} or not isinstance(arguments['path'], str) or not arguments['path']:
            raise KillChainFailure('invalid_input')
        if len(arguments['path']) > 512 or not Path(arguments['path']).is_file():
            raise KillChainFailure('file_not_found')
        return pcap_probe(arguments['path'])
    raise KillChainFailure('invalid_tool')


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
                  'serverInfo': {'name': 'mithril-kill-chain-local', 'version': VERSION},
                  'capabilities': {'tools': {'listChanged': False}},
                  'instructions': 'Seven-phase cyber kill-chain coverage over supplied evidence and bounded local .pcap probes. Coverage is not attribution. No network calls.'}
    elif method == 'ping':
        result = {}
    elif method == 'tools/list':
        result = {'tools': [{k: v for k, v in t.items() if k != 'write'} | {
            'annotations': {'readOnlyHint': True, 'destructiveHint': False,
                            'idempotentHint': True, 'openWorldHint': False}}
            for t in TOOLS]}
    elif method == 'tools/call':
        try:
            result = {'content': [{'type': 'text', 'text': json.dumps(execute(params.get('name'), params.get('arguments', {})), ensure_ascii=False)}], 'isError': False}
        except KillChainFailure as error:
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
        for line in iter(lambda: sys.stdin.buffer.readline(MAX_ARG_BYTES + 1), b''):
            if len(line) > MAX_ARG_BYTES:
                print(json.dumps({'jsonrpc': '2.0', 'id': None, 'error': {'code': -32600, 'message': 'Request too large'}}), flush=True)
                return 1
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
            raise KillChainFailure('request_too_large')
        print(json.dumps(execute(args.tool, json.loads(raw)), ensure_ascii=False))
        return 0
    except (KillChainFailure, ValueError, OSError):
        print('kill-chain operation failed; inspect the retained input before retrying', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
