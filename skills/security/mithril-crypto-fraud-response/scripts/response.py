#!/usr/bin/env python3
"""Local, case-scoped fraud evidence preparation. No network or device acquisition."""
import argparse
import datetime as dt
from decimal import Decimal, InvalidOperation
from email import policy
from email.parser import BytesParser
import fcntl
from urllib.parse import urlsplit
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import xml.etree.ElementTree as ET

VERSION = '0.2.0'
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


def validate_timestamp(value):
    if not isinstance(value, str):
        raise ValueError('Timestamp must include an explicit timezone')
    try:
        stamp = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise ValueError('Invalid timestamp') from None
    if stamp.tzinfo is None:
        raise ValueError('Timestamp must include an explicit timezone')


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


    def evidence_refs(self, case_id, ids):
        if not isinstance(ids, list) or not ids or len(ids) != len(set(ids)):
            raise ValueError('Specify distinct retained evidence IDs')
        inventory = {r['evidenceId']: r for r, _ in self.inventory(case_id)}
        if any(eid not in inventory for eid in ids):
            raise ValueError('Evidence reference is not retained in this case')
        return [{'evidenceId': eid, 'sha256': inventory[eid]['sha256']} for eid in ids]

    def action_prepare(self, args):
        cid = args['caseId']
        self.metadata(cid)
        recipient = args['recipient']
        validate_timestamp(args['routeVerifiedAt'])
        route = urlsplit(recipient['officialUrl'])
        if route.scheme != 'https' or not route.hostname or route.username or route.password or route.query or route.fragment:
            raise ValueError('Use a public official HTTPS route without credentials, tokens or query parameters')
        for value in (recipient['name'], args['purpose'], args['legalBasis'], args['reporterRole'], args['routeVerifiedAt']):
            if not isinstance(value, str) or not value.strip():
                raise ValueError('Recipient, purpose, role, legal basis and route verification time are required')
        # Selected/redacted payload is an imported original, not an arbitrary path.
        refs = self.evidence_refs(cid, [args['payloadEvidenceId'], *args['supportingEvidenceIds']])
        record = {'caseId': cid, 'recipient': recipient, 'purpose': args['purpose'],
                  'reporterRole': args['reporterRole'], 'legalBasis': args['legalBasis'],
                  'routeVerifiedAt': args['routeVerifiedAt'], 'payload': refs[0], 'supportingEvidence': refs[1:],
                  'externalExecution': False, 'authorityVerification': 'operator-declared'}
        aid = 'action-' + digest(canonical(record))
        directory = safe_path(str(self.case(cid) / 'actions'))
        directory.mkdir(mode=0o700, exist_ok=True)
        target = directory / (aid + '.json')
        if target.exists():
            if read_bytes(target) != canonical(record):
                raise ValueError('Action integrity failed')
        else:
            write_new(target, canonical(record))
        events = self.action_events(cid, aid)
        state = events[-1]['state'] if events else 'prepared'
        sent_states = {'submitted', 'acknowledged', 'under-review', 'frozen', 'declined', 'returned-and-reconciled'}
        return {'actionId': aid, **record, 'state': state,
                'submittedObservationRecorded': any(e['state'] in sent_states for e in events),
                'retryBlocked': state in ('dispatch-started', 'unknown')}

    def action_load(self, cid, aid):
        self.metadata(cid)
        if not isinstance(aid, str) or not re.fullmatch(r'action-[a-f0-9]{64}', aid):
            raise ValueError('Invalid action ID')
        record = json.loads(read_bytes(self.case(cid) / 'actions' / (aid + '.json')))
        if record.get('caseId') != cid or aid != 'action-' + digest(canonical(record)):
            raise ValueError('Action integrity failed')
        refs = [record['payload'], *record['supportingEvidence']]
        if refs != self.evidence_refs(cid, [r['evidenceId'] for r in refs]):
            raise ValueError('Action evidence integrity failed')
        return record

    def action_events(self, cid, aid):
        directory = safe_path(str(self.case(cid) / 'actions' / aid))
        if not directory.exists():
            return []
        events, previous = [], None
        for i, path in enumerate(sorted(directory.glob('*.json')), 1):
            event = json.loads(read_bytes(path))
            if path.name != f'{i:06d}.json' or event['sequence'] != i or event['previousDigest'] != previous or event['actionId'] != aid:
                raise ValueError('Event chain integrity failed')
            if event['evidence'] != self.evidence_refs(cid, [r['evidenceId'] for r in event['evidence']]):
                raise ValueError('Event evidence integrity failed')
            events.append(event)
            previous = digest(canonical(event))
        return events

    def action_event(self, args):
        cid, aid = args['caseId'], args['actionId']
        validate_timestamp(args['observedAt'])
        record = self.action_load(cid, aid)
        directory = safe_path(str(self.case(cid) / 'actions' / aid))
        directory.mkdir(mode=0o700, exist_ok=True)
        lock = safe_path(str(directory.parent / '.lock'))
        fd = os.open(lock, os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(fd, 'r+') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            events = self.action_events(cid, aid)
            state = events[-1]['state'] if events else 'prepared'
            target = args['state']
            transitions = {
                'prepared': {'dispatch-started'},
                'reconciled-not-submitted': {'dispatch-started'},
                'dispatch-started': {'submitted', 'unknown', 'acknowledged', 'reconciled-not-submitted'},
                'unknown': {'submitted', 'acknowledged', 'reconciled-not-submitted'},
                'submitted': {'acknowledged', 'under-review', 'frozen', 'declined', 'returned-and-reconciled'},
                'acknowledged': {'under-review', 'frozen', 'declined', 'returned-and-reconciled'},
                'under-review': {'under-review', 'frozen', 'declined', 'returned-and-reconciled'},
                'frozen': {'under-review', 'declined', 'returned-and-reconciled'},
                'declined': set(), 'returned-and-reconciled': set()}
            if target not in transitions.get(state, set()):
                raise ValueError('Invalid transition; reconcile uncertain dispatch before retrying')
            refs = self.evidence_refs(cid, args['evidenceIds'])
            note = args['note']
            if not isinstance(note, str) or not note.strip() or len(note) > 4000:
                raise ValueError('Provide a bounded observation and source locator')
            approval = args.get('approval')
            if target == 'dispatch-started':
                if not isinstance(approval, dict) or approval.get('authorized') is not True or approval.get('actionId') != aid:
                    raise ValueError('Disclosure/external action approval must bind this exact action ID')
                for key in ('basis', 'operator'):
                    if not isinstance(approval.get(key), str) or not approval[key].strip():
                        raise ValueError('External action approval requires basis and operator')
                # A changed payload must not bypass an unresolved attempt to this desk.
                for sibling in directory.parent.glob('action-*.json'):
                    other_id = sibling.stem
                    if other_id == aid:
                        continue
                    other = self.action_load(cid, other_id)
                    history = self.action_events(cid, other_id)
                    if other['recipient']['officialUrl'] == record['recipient']['officialUrl'] and other['purpose'] == record['purpose'] and history and history[-1]['state'] in ('dispatch-started', 'unknown'):
                        raise ValueError('Another dispatch to this recipient is unresolved; reconcile first')
            amount = args.get('amount')
            currency = args.get('currency')
            if target in ('frozen', 'returned-and-reconciled'):
                if not isinstance(amount, str) or len(amount) > 64 or not re.fullmatch(r'(?:0|[1-9][0-9]*)(?:\.[0-9]+)?', amount):
                    raise ValueError('Use an exact positive decimal amount')
                try:
                    number = Decimal(amount) if isinstance(amount, str) else Decimal('NaN')
                except InvalidOperation:
                    raise ValueError('Use an exact positive decimal amount') from None
                if not number.is_finite() or number <= 0 or not isinstance(currency, str) or not re.fullmatch(r'[A-Z]{3,10}', currency):
                    raise ValueError('Use a positive amount and explicit currency')
            elif amount is not None or currency is not None:
                raise ValueError('Only confirmed freeze/return observations carry amounts')
            event = {'actionId': aid, 'sequence': len(events)+1, 'previousDigest': digest(canonical(events[-1])) if events else None,
                     'recordedAt': now(), 'observedAt': args['observedAt'], 'state': target, 'evidence': refs,
                     'note': note, 'approval': approval if target == 'dispatch-started' else None,
                     'amount': amount, 'currency': currency, 'authenticity': 'operator-observed-not-independently-verified'}
            write_new(directory / f"{event['sequence']:06d}.json", canonical(event))
            return event

    def action_status(self, args):
        cid = args['caseId']
        self.metadata(cid)
        out = []
        directory = safe_path(str(self.case(cid) / 'actions'))
        if directory.exists():
            for path in sorted(directory.glob('action-*.json')):
                aid = path.stem
                record = self.action_load(cid, aid)
                events = self.action_events(cid, aid)
                state = events[-1]['state'] if events else 'prepared'
                out.append({'actionId': aid, 'recipient': record['recipient'], 'purpose': record['purpose'],
                            'state': state, 'events': events, 'retryBlocked': state in ('dispatch-started', 'unknown'),
                            'receiptRecorded': any(e['state'] == 'acknowledged' for e in events),
                            'freezeObservationRecorded': any(e['state'] == 'frozen' for e in events),
                            'returnObservationRecorded': any(e['state'] == 'returned-and-reconciled' for e in events)})
        return {'caseId': cid, 'actions': out, 'externalExecution': False,
                'limitations': ['Local operator records, not bank/police authentication',
                                'Do not sum overlapping frozen/returned amounts or currencies',
                                'Receipt is not a freeze, reimbursement or formal complaint acceptance']}

    def receipt_decode(self, args):
        cid, eid = args['caseId'], args['evidenceId']
        inventory = {r['evidenceId']: (r, raw) for r, raw in self.inventory(cid)}
        if eid not in inventory or inventory[eid][0]['format'] != 'attachment':
            raise ValueError('Import the original RFC822 email as an attachment first')
        receipt, raw = inventory[eid]
        message = BytesParser(policy=policy.default).parsebytes(raw)
        if message.defects:
            raise ValueError('Malformed RFC822 email requires manual review')
        parts = []
        for part in message.walk():
            if part.get_content_type() == 'text/plain' and part.get_content_disposition() != 'attachment':
                if part.defects:
                    raise ValueError('Malformed MIME requires manual review')
                parts.append({'charset': part.get_content_charset(), 'text': part.get_content()})
        return {'evidenceId': eid, 'sha256': receipt['sha256'], 'headers': {
                k: str(message.get(k, '')) for k in ('From', 'To', 'Subject', 'Date', 'Message-ID')},
                'plainTextParts': parts, 'status': 'decoded-only', 'senderAuthenticated': False,
                'receiptConfirmed': False, 'externalExecution': False}


OPS = {'fraud_case_create': 'create', 'fraud_import': 'ingest', 'fraud_inventory': 'inventory',
       'fraud_analyze': 'analyze', 'fraud_draft': 'draft',
       'fraud_action_prepare': 'action_prepare', 'fraud_action_event': 'action_event',
       'fraud_action_status': 'action_status', 'fraud_receipt_decode': 'receipt_decode'}


def validate_args(value, schema):
    kind = schema.get('type')
    if kind == 'object':
        if not isinstance(value, dict) or any(k not in value for k in schema.get('required', [])):
            raise ValueError('Missing required object arguments')
        properties = schema.get('properties', {})
        if schema.get('additionalProperties') is False and set(value) - set(properties):
            raise ValueError('Unexpected arguments')
        for key in value:
            if key in properties:
                validate_args(value[key], properties[key])
    elif kind == 'array':
        if not isinstance(value, list) or len(value) < schema.get('minItems', 0):
            raise ValueError('Invalid array arguments')
        if schema.get('uniqueItems') and len({canonical(v) for v in value}) != len(value):
            raise ValueError('Array arguments must be distinct')
        for item in value:
            validate_args(item, schema['items'])
    elif kind == 'string':
        if not isinstance(value, str) or not schema.get('minLength', 0) <= len(value) <= schema.get('maxLength', MAX_BYTES):
            raise ValueError('Invalid string argument')
        if 'pattern' in schema and not re.search(schema['pattern'], value):
            raise ValueError('String argument does not match pattern')
    elif kind == 'boolean' and not isinstance(value, bool):
        raise ValueError('Invalid boolean argument')
    if 'enum' in schema and value not in schema['enum']:
        raise ValueError('Unsupported argument value')
    if 'const' in schema and value != schema['const']:
        raise ValueError('Invalid constant argument')


def execute(store, name, args):
    if name not in OPS or not isinstance(args, dict):
        raise ValueError('Unknown operation or invalid arguments')
    schemas = json.loads(Path(__file__).with_name('tools.json').read_text())
    validate_args(args, next(t['inputSchema'] for t in schemas if t['name'] == name))
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
                except (ValueError, KeyError, TypeError, LookupError, OSError, ET.ParseError) as exc:
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
    except (ValueError, KeyError, TypeError, LookupError, OSError, ET.ParseError) as exc:
        print(json.dumps({'error': str(exc)}), file=sys.stderr)
        sys.exit(1)
