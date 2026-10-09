#!/usr/bin/env python3
"""Local, case-scoped fraud evidence preparation. No network or device acquisition."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import xml.etree.ElementTree as ET

VERSION = '0.1.0'
MAX_BYTES = 16 * 1024 * 1024
ID = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$')
PATTERNS = {
    'evm-address-candidate': r'(?<![a-zA-Z0-9])0x[a-fA-F0-9]{40}(?![a-fA-F0-9])',
    'transaction-hash-candidate': r'(?<![a-zA-Z0-9])(?:0x)?[a-fA-F0-9]{64}(?![a-fA-F0-9])',
    'bitcoin-address-candidate': r'\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b',
    'tron-address-candidate': r'\bT[1-9A-HJ-NP-Za-km-z]{33}\b',
    'url-candidate': r'https?://[^\s<>"\x00-\x1f]+',
    'email-candidate': r'\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b',
}


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def safe_path(path):
    p = Path(path)
    if not p.is_absolute() or any(x.is_symlink() for x in [p, *p.parents]):
        raise ValueError('Expected an absolute path without symlink components')
    return p.resolve()


def read_bytes(path):
    p = safe_path(path)
    with p.open('rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError('Input exceeds 16 MiB; split exports explicitly')
    return raw


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def parse(raw, kind):
    """Return observations with original line/row locators; never infer timezone."""
    if kind == 'attachment':
        return [], ['Opaque attachment retained; content not analyzed']
    text = raw.decode('utf-8-sig', errors='strict')
    if kind == 'chain-json':
        value = json.loads(text)
        if not isinstance(value, dict) or not isinstance(value.get('transactions'), list):
            raise ValueError('Expected transactions list and acquisition provenance')
        for key in ('sourceUrl', 'observedAt', 'chain', 'coverage'):
            if not isinstance(value.get(key), str) or not value[key].strip():
                raise ValueError(f'Chain snapshot requires {key}')
        rows = []
        for i, tx in enumerate(value['transactions'], 1):
            if not isinstance(tx, dict) or any(not isinstance(tx.get(k), str) or not tx[k].strip()
                                                for k in ('txHash', 'from', 'to', 'amount', 'asset')):
                raise ValueError('Transactions require string txHash/from/to/amount/asset')
            rows.append({'locator': f'transaction-row:{i}', 'timeRaw': tx.get('timestamp'),
                         'timeUtc': None, 'senderClaim': None, 'text': json.dumps(tx),
                         'transaction': {k: tx[k] for k in ('txHash', 'from', 'to', 'amount', 'asset', 'timestamp') if k in tx},
                         'provenance': {k: value[k] for k in ('sourceUrl', 'observedAt', 'chain', 'coverage')}})
        return rows, ['Supplied chain snapshot only; chain authenticity, completeness and ownership unverified']
    if kind == 'sms-xml':
        if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
            raise ValueError('XML declarations/entities are unsupported')
        root = ET.fromstring(text)
        if root.tag != 'smses':
            raise ValueError('Expected an SMS Backup export with smses root')
        rows = []
        for i, sms in enumerate(root.findall('sms'), 1):
            millis = sms.get('date', '')
            stamp = None
            try:
                stamp = dt.datetime.fromtimestamp(int(millis) / 1000, dt.timezone.utc).isoformat()
            except (ValueError, OverflowError, OSError):
                pass
            rows.append({'locator': f'sms-row:{i}', 'timeRaw': millis, 'timeUtc': stamp,
                         'senderClaim': sms.get('address'), 'directionRaw': sms.get('type'),
                         'text': sms.get('body', '')})
        gaps = ['MMS, RCS, deleted records and provider completeness are unverified']
        if not rows:
            gaps.append('No SMS rows parsed; this is not evidence of no messages')
        return rows, gaps
    if kind not in ('line-text', 'message-text'):
        raise ValueError('Unsupported input format')
    rows, date = [], None
    for i, line in enumerate(text.splitlines(), 1):
        if re.match(r'^\d{4}[/-]\d{1,2}[/-]\d{1,2}', line):
            date = line
        parts = line.split('\t', 2)
        recognized = len(parts) == 3 and bool(re.fullmatch(r'\d{1,2}:\d{2}(?::\d{2})?', parts[0]))
        rows.append({'locator': f'line:{i}', 'timeRaw': f'{date or ""} {parts[0]}' if recognized else None,
                     'timeUtc': None, 'senderClaim': parts[1] if recognized else None,
                     'text': parts[2] if recognized else line})
    return rows, ['Export completeness, attachments, deleted records and sender identity unverified',
                  'Text timestamps retain source values; timezone is unknown']


class Cases:
    def __init__(self, root):
        self.root = safe_path(root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.root.stat().st_mode & 0o077:
            raise ValueError('Case root must be private (mode 0700)')

    def case(self, case_id):
        if not isinstance(case_id, str) or not ID.fullmatch(case_id):
            raise ValueError('Invalid case ID')
        return safe_path(str(self.root / case_id))

    def metadata(self, case_id):
        return json.loads(read_bytes(self.case(case_id) / 'case.json'))

    def create(self, args):
        cid = args['caseId']
        authority = args.get('authority')
        if not isinstance(authority, dict) or authority.get('authorized') is not True:
            raise ValueError('Record owner/representative authorization before creating an incident case')
        for k in ('basis', 'scope', 'operator'):
            if not isinstance(authority.get(k), str) or not authority[k].strip():
                raise ValueError(f'Authority requires {k}')
        roots = [str(safe_path(p)) for p in args['inputRoots']]
        if not roots or any(not Path(p).is_dir() for p in roots):
            raise ValueError('Specify existing authorized input directories')
        meta = {'schemaVersion': 1, 'caseId': cid, 'createdAt': now(), 'toolVersion': VERSION,
                'authority': authority, 'inputRoots': roots, 'jurisdiction': args.get('jurisdiction', 'unknown'),
                'timezone': args.get('timezone', 'unknown'), 'coverage': 'incomplete-or-unknown'}
        target = self.case(cid)
        target.mkdir(mode=0o700)
        (target / 'evidence').mkdir(mode=0o700)
        write_new(target / 'case.json', canonical(meta))
        return meta

    def ingest(self, args):
        meta = self.metadata(args['caseId'])
        source = safe_path(args['path'])
        if not any(source.is_relative_to(Path(p)) for p in meta['inputRoots']):
            raise ValueError('Input outside case-authorized roots')
        raw = read_bytes(source)
        rows, gaps = parse(raw, args['format'])
        sha = digest(raw)
        eid = 'ev-' + sha
        directory = self.case(args['caseId']) / 'evidence' / eid
        if directory.exists():
            raise ValueError('Evidence already retained; original is never overwritten')
        observed = now()
        receipt = {'evidenceId': eid, 'sha256': sha, 'bytes': len(raw), 'format': args['format'],
                   'sourceName': source.name, 'retainedAt': observed, 'toolVersion': VERSION,
                   'collection': args.get('collection', 'operator-supplied export'),
                   'parsedRows': len(rows), 'coverage': 'incomplete-or-unknown', 'gaps': gaps,
                   'authenticity': 'not-verified', 'status': 'partial' if gaps else 'success'}
        # Atomic directory promotion: an interruption never exposes a complete receipt.
        staging = Path(tempfile.mkdtemp(prefix='.staging-', dir=directory.parent))
        write_new(staging / 'original', raw)
        write_new(staging / 'receipt.json', canonical(receipt))
        staging.rename(directory)
        return receipt

    def inventory(self, case_id):
        self.metadata(case_id)
        out = []
        for directory in sorted((self.case(case_id) / 'evidence').iterdir()):
            safe_path(str(directory))
            if directory.name.startswith('.staging-'):
                raise ValueError('Interrupted staging requires operator reconciliation')
            receipt = json.loads(read_bytes(directory / 'receipt.json'))
            raw = read_bytes(directory / 'original')
            if receipt['sha256'] != digest(raw) or receipt['bytes'] != len(raw) or directory.name != 'ev-' + digest(raw):
                raise ValueError('Evidence byte integrity verification failed')
            out.append((receipt, raw))
        return out

    def analyze(self, case_id):
        identifiers, timeline, inventory, transactions = [], [], [], []
        for receipt, raw in self.inventory(case_id):
            inventory.append(receipt)
            rows, _ = parse(raw, receipt['format'])
            for row in rows:
                ref = {'evidenceId': receipt['evidenceId'], 'sha256': receipt['sha256'], 'locator': row['locator']}
                if 'transaction' in row:
                    transactions.append({**ref, **row['transaction'], 'provenance': row['provenance'],
                                         'status': 'supplied-unverified', 'ownership': 'unknown'})
                if row['timeRaw']:
                    timeline.append({**ref, 'timeRaw': row['timeRaw'], 'timeUtc': row['timeUtc'],
                                     'senderClaim': row['senderClaim'], 'identityVerified': False})
                for kind, pattern in PATTERNS.items():
                    for match in re.finditer(pattern, row['text']):
                        identifiers.append({**ref, 'kind': kind, 'value': match.group(),
                                            'characterSpan': [match.start(), match.end()],
                                            'verified': False, 'attribution': 'unknown'})
                if len(identifiers) > 2000 or len(timeline) > 20000 or len(transactions) > 2000:
                    raise ValueError('Analysis limit exceeded; split input with an explicit coverage record')
        return {'caseId': case_id, 'generatedAt': now(), 'toolVersion': VERSION, 'inventory': inventory,
                'identifiers': identifiers, 'timelineSourceOrder': timeline, 'suppliedTransactionEdges': transactions,
                'limitations': ['Candidates have no checksum, chain or ownership verification',
                                'Sender labels do not identify a real person',
                                'No live blockchain lookup or tracing performed',
                                'No-message output is not a clean finding',
                                'Source timestamps may be incomplete or inconsistent']}

    def draft(self, args):
        case_id = args['caseId']
        meta = self.metadata(case_id)
        analysis = self.analyze(case_id)
        # Draft contains references only; original chats remain inside the case vault.
        return {'caseId': case_id, 'status': 'draft-needs-human-review', 'executed': False,
                'generatedAt': now(), 'analysisDigest': digest(canonical(analysis['inventory'])),
                'jurisdiction': meta['jurisdiction'], 'authority': meta['authority'],
                'evidenceInventory': analysis['inventory'], 'candidateCount': len(analysis['identifiers']),
                'actions': [
                    {'purpose': 'police-report', 'recipient': None, 'state': 'not-submitted',
                     'needed': ['Victim statement', 'Loss amount/currency', 'Transaction receipts', 'Reviewed chronology', 'Official jurisdiction-specific reporting route']},
                    {'purpose': 'exchange-preservation-freeze-request', 'recipient': None, 'state': 'not-submitted',
                     'needed': ['Verified chain and transaction IDs', 'Exchange attribution source and observation time', 'Official desk', 'Selected/redacted evidence', 'Authority and legal basis', 'Exact-content recipient approval']},
                    {'purpose': 'legal-counsel-brief', 'recipient': None, 'state': 'not-submitted',
                     'needed': ['Jurisdiction', 'Ownership/representation', 'Loss schedule', 'Limitation/deadline review by counsel', 'Preservation or interim-relief assessment']}
                ], 'recoveryStatus': 'not-verified', 'limitations': analysis['limitations']}


OPS = {'fraud_case_create': 'create', 'fraud_import': 'ingest', 'fraud_inventory': 'inventory',
       'fraud_analyze': 'analyze', 'fraud_draft': 'draft'}


def execute(store, name, args):
    if name not in OPS or not isinstance(args, dict):
        raise ValueError('Unknown operation or invalid arguments')
    function = getattr(store, OPS[name])
    if name == 'fraud_inventory':
        return {'caseId': args['caseId'], 'evidence': [receipt for receipt, _ in store.inventory(args['caseId'])],
                'coverage': 'incomplete-or-unknown'}
    return function(args['caseId']) if name in ('fraud_inventory', 'fraud_analyze') else function(args)


def serve(store):
    tools = json.loads(Path(__file__).with_name('tools.json').read_text())
    while True:
        line = sys.stdin.buffer.readline(65537)
        if not line:
            break
        if len(line) > 65536:
            raise ValueError('MCP input exceeds 64 KiB')
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError('Expected JSON-RPC object')
        except ValueError:
            print(json.dumps({'jsonrpc': '2.0', 'id': None, 'error': {'code': -32700, 'message': 'Invalid JSON-RPC input'}}), flush=True)
            continue
        if 'id' not in request:
            continue
        result, error = None, None
        try:
            method, params = request['method'], request.get('params', {})
            if method == 'initialize':
                requested = params.get('protocolVersion')
                version = requested if requested in ('2025-03-26', '2025-06-18', '2025-11-25') else '2025-06-18'
                result = {'protocolVersion': version, 'capabilities': {'tools': {}},
                          'serverInfo': {'name': 'mithril-crypto-fraud-local', 'version': VERSION}}
            elif method == 'ping':
                result = {}
            elif method == 'tools/list':
                result = {'tools': tools}
            elif method == 'tools/call':
                try:
                    data = execute(store, params['name'], params.get('arguments', {}))
                    result = {'content': [{'type': 'text', 'text': json.dumps(data, ensure_ascii=False)}]}
                except (ValueError, KeyError, OSError, ET.ParseError) as exc:
                    result = {'isError': True, 'content': [{'type': 'text', 'text': str(exc)}]}
            else:
                error = {'code': -32601, 'message': 'Method not found'}
        except (ValueError, KeyError, OSError) as exc:
            error = {'code': -32602, 'message': str(exc)}
        response = {'jsonrpc': '2.0', 'id': request['id']}
        response['error' if error else 'result'] = error or result
        print(json.dumps(response, ensure_ascii=False), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, help='Private absolute case vault root')
    parser.add_argument('--mcp', action='store_true')
    parser.add_argument('--tool', choices=OPS)
    parser.add_argument('--input', help='JSON arguments; incident text is untrusted data')
    args = parser.parse_args()
    store = Cases(args.root)
    if args.mcp:
        serve(store)
    else:
        print(json.dumps(execute(store, args.tool, json.loads(args.input or '{}')), ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, ET.ParseError) as exc:
        print(json.dumps({'error': str(exc)}), file=sys.stderr)
        sys.exit(1)
