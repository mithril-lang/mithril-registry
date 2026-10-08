#!/usr/bin/env python3
"""Private, supervised LinkedIn CRM. No network, credentials or automated sends."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
from datetime import datetime, timezone
from urllib.parse import urlsplit
from uuid import UUID

OPS = ('lead', 'draft', 'approve', 'handoff', 'cancel', 'receipt', 'reply', 'suppress', 'opportunity', 'status', 'followups')

def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))

def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()

def text(data, key, limit=4000):
    value = data.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > limit or '\x00' in value:
        raise ValueError('invalid ' + key)
    return value.strip()

def instant(value):
    if not isinstance(value, str):
        raise ValueError('timestamp required')
    d = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if d.tzinfo is None:
        raise ValueError('timestamp requires timezone')
    return d.astimezone(timezone.utc).isoformat()

def now():
    return datetime.now(timezone.utc).isoformat()

def profile(value):
    u = urlsplit(value)
    if u.scheme != 'https' or u.netloc != 'www.linkedin.com' or u.query or u.fragment or not re.fullmatch(r'/in/[A-Za-z0-9_\-]+/?', u.path):
        raise ValueError('recipient must be a canonical https://www.linkedin.com/in/ profile URL')
    return 'https://www.linkedin.com' + u.path.rstrip('/').casefold()

class CRM:
    def __init__(self, path, owner):
        if not isinstance(owner, str) or not re.fullmatch(r'[A-Za-z0-9_.@-]{1,160}', owner):
            raise ValueError('explicit owner required')
        self.owner = owner
        path = Path(path).absolute()
        if path.is_symlink() or path.parent.is_symlink():
            raise ValueError('database symlinks are not allowed')
        if not path.parent.is_dir():
            raise ValueError('create a private workspace directory first')
        if path.parent.stat().st_mode & 0o077:
            raise ValueError('workspace directory must have mode 0700')
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        os.close(fd)
        if path.stat().st_mode & 0o077:
            raise ValueError('database must have mode 0600')
        self.db = sqlite3.connect(path, timeout=5, isolation_level=None)
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS meta(owner TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS leads(id TEXT PRIMARY KEY, data TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS messages(id TEXT PRIMARY KEY, lead_id TEXT NOT NULL REFERENCES leads(id), data TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY, digest TEXT NOT NULL, result TEXT NOT NULL, at TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY, operation_id TEXT NOT NULL, owner TEXT NOT NULL, operation TEXT NOT NULL, at TEXT NOT NULL);
        ''')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            rows = self.db.execute('SELECT owner FROM meta').fetchall()
            if not rows:
                self.db.execute('INSERT INTO meta VALUES (?)', (owner,))
            elif rows != [(owner,)]:
                raise ValueError('workspace owner mismatch')
            self.db.execute('COMMIT')
        except Exception:
            self.db.execute('ROLLBACK')
            self.db.close()
            raise

    def get(self, table, id):
        row = self.db.execute('SELECT data FROM ' + table + ' WHERE id=?', (id,)).fetchone()
        if not row:
            raise ValueError('unknown record')
        return json.loads(row[0])

    def save(self, table, item):
        self.db.execute('UPDATE ' + table + ' SET data=? WHERE id=?', (canonical(item), item['id']))
        return item

    def run(self, op, data):
        if op not in OPS or not isinstance(data, dict):
            raise ValueError('unsupported operation or input')
        if op in ('status', 'followups'):
            self.db.execute('BEGIN')
            try:
                return self.read(op, data)
            finally:
                self.db.execute('ROLLBACK')
        operation_id = str(UUID(text(data, 'operationId', 36)))
        fingerprint = digest({'owner': self.owner, 'operation': op, 'input': data})
        self.db.execute('BEGIN IMMEDIATE')
        try:
            prior = self.db.execute('SELECT digest,result FROM operations WHERE id=?', (operation_id,)).fetchone()
            if prior:
                if prior[0] != fingerprint:
                    raise ValueError('operationId reused with different payload')
                self.db.execute('COMMIT')
                return json.loads(prior[1])
            result = self.mutate(op, data, operation_id)
            self.db.execute('INSERT INTO operations VALUES (?,?,?,?)', (operation_id, fingerprint, canonical(result), now()))
            self.db.execute('INSERT INTO audit(operation_id,owner,operation,at) VALUES (?,?,?,?)', (operation_id, self.owner, op, now()))
            self.db.execute('COMMIT')
            return result
        except Exception:
            self.db.execute('ROLLBACK')
            raise

    def read(self, op, data):
        leads = [json.loads(r[0]) for r in self.db.execute('SELECT data FROM leads ORDER BY id')]
        messages = [json.loads(r[0]) for r in self.db.execute('SELECT data FROM messages ORDER BY id')]
        if op == 'status':
            return {'owner': self.owner, 'leads': leads, 'messages': messages, 'externalSendReady': False, 'networkCalls': 0}
        at = instant(data.get('at', now()))
        due = []
        for lead in leads:
            if lead['suppressed'] or not lead.get('nextReviewAt') or lead['nextReviewAt'] > at or lead['stage'] in ('won', 'lost'):
                continue
            linked = [m for m in messages if m['leadId'] == lead['id']]
            if any(m['state'] in ('handed-off', 'unknown') for m in linked):
                continue
            due.append({'leadId': lead['id'], 'nextReviewAt': lead['nextReviewAt'], 'action': 'review-only'})
        return {'due': due, 'automaticSend': False}

    def mutate(self, op, data, operation_id):
        if op == 'lead':
            item = {'id': operation_id, 'owner': self.owner, 'profileUrl': profile(text(data, 'profileUrl', 500)),
                    'name': text(data, 'name', 160), 'company': text(data, 'company', 160),
                    'source': text(data, 'source', 1000), 'observedAt': instant(data.get('observedAt')),
                    'outreachBasis': text(data, 'outreachBasis', 1000), 'fitReason': text(data, 'fitReason', 1000),
                    'suppressed': False, 'stage': 'qualified', 'nextReviewAt': None, 'revision': 1}
            if data.get('authorizedInput') is not True:
                raise ValueError('authorized supplied input required; no scraping')
            for row in self.db.execute('SELECT data FROM leads'):
                if json.loads(row[0])['profileUrl'] == item['profileUrl']:
                    raise ValueError('profile already registered; suppression cannot be bypassed')
            self.db.execute('INSERT INTO leads VALUES (?,?)', (item['id'], canonical(item)))
            return item
        if op in ('reply', 'suppress', 'opportunity', 'draft'):
            lead = self.get('leads', text(data, 'leadId', 36))
        else:
            msg = self.get('messages', text(data, 'messageId', 36))
            lead = self.get('leads', msg['leadId'])
        if op == 'suppress':
            lead.update(suppressed=True, suppressionReason=text(data, 'reason', 1000), nextReviewAt=None, revision=lead['revision'] + 1)
            return self.save('leads', lead)
        if op == 'reply':
            # Supplied reply only; never infer that a conversation was read from LinkedIn.
            reply = {'body': text(data, 'body'), 'observedAt': instant(data.get('observedAt')), 'evidence': text(data, 'evidence', 1000), 'operationId': operation_id}
            lead.setdefault('replies', []).append(reply)
            lead['nextReviewAt'] = None
            if data.get('optOut') is True:
                lead['suppressed'] = True
                lead['suppressionReason'] = 'recipient opt-out'
            lead['revision'] += 1
            return self.save('leads', lead)
        if op == 'opportunity':
            if data.get('expectedRevision') != lead['revision']:
                raise ValueError('lead revision conflict')
            stage = data.get('stage')
            if stage not in ('qualified', 'replied', 'meeting', 'proposal', 'won', 'lost'):
                raise ValueError('invalid opportunity stage')
            if lead['suppressed'] and data.get('nextReviewAt'):
                raise ValueError('suppressed contact cannot have follow-up')
            lead.update(stage=stage, stageEvidence=text(data, 'evidence', 1000),
                        nextReviewAt=instant(data['nextReviewAt']) if data.get('nextReviewAt') else None,
                        revision=lead['revision'] + 1)
            return self.save('leads', lead)
        if lead['suppressed'] and op != 'receipt':
            raise ValueError('recipient is suppressed')
        if op == 'draft':
            if any(json.loads(r[0])['state'] in ('handed-off', 'unknown') for r in self.db.execute('SELECT data FROM messages WHERE lead_id=?', (lead['id'],))):
                raise ValueError('reconcile outstanding handoff before another message')
            kind = data.get('kind')
            if kind not in ('dm', 'inmail', 'connection-note'):
                raise ValueError('unsupported message kind')
            item = {'id': operation_id, 'leadId': lead['id'], 'owner': self.owner, 'recipient': lead['profileUrl'], 'senderProfileUrl': profile(text(data, 'senderProfileUrl', 500)),
                    'kind': kind, 'subject': data.get('subject', ''), 'body': text(data, 'body'),
                    'attachments': [], 'state': 'draft', 'revision': 1, 'contentRevision': 1, 'createdAt': now()}
            if not isinstance(item['subject'], str) or len(item['subject']) > 200 or '\x00' in item['subject']:
                raise ValueError('invalid subject')
            if data.get('attachments'):
                raise ValueError('attachments are unavailable in this version')
            if data.get('incentive') or re.search(r'<[^>]+>', item['body'] + item['subject']):
                raise ValueError('HTML and message incentives are unsupported')
            item['digest'] = digest({k: item[k] for k in ('id', 'leadId', 'owner', 'recipient', 'senderProfileUrl', 'kind', 'subject', 'body', 'attachments', 'contentRevision')})
            self.db.execute('INSERT INTO messages VALUES (?,?,?)', (item['id'], lead['id'], canonical(item)))
            return item
        if data.get('expectedRevision') != msg['revision'] or data.get('digest') != msg['digest']:
            raise ValueError('exact message digest and revision required')
        if op == 'approve':
            if msg['state'] != 'draft' or data.get('memberAction') != 'approve-draft' or data.get('actor') != self.owner:
                raise ValueError('owner must explicitly approve exact draft')
            msg.update(state='approved', approvedAt=now())
        elif op == 'cancel':
            if msg['state'] not in ('draft', 'approved'):
                raise ValueError('only untransferred messages can be cancelled')
            msg.update(state='cancelled', cancellationReason=text(data, 'reason', 1000))
        elif op == 'handoff':
            if any(json.loads(r[0])['state'] in ('handed-off', 'unknown') for r in self.db.execute('SELECT data FROM messages WHERE lead_id=? AND id<>?', (lead['id'], msg['id']))):
                raise ValueError('reconcile outstanding handoff first')
            if msg['state'] != 'approved' or data.get('memberAction') != 'prepare-screen-send' or data.get('actor') != self.owner:
                raise ValueError('explicit owner screen handoff required')
            msg.update(state='handed-off', handedOffAt=now(), handoffId=operation_id, mode='supervised-screen')
            msg['revision'] += 1
            self.save('messages', msg)
            return {'handoffId': operation_id, 'message': msg, 'profileUrl': msg['recipient'], 'instruction': 'Inspect account, recipient and editable text in the selected LinkedIn screen. Send only with specific user authorization for this message. Record the observed outcome; do not retry unknowns.', 'sent': False}
        elif op == 'receipt':
            if msg['state'] not in ('handed-off', 'unknown') or data.get('handoffId') != msg.get('handoffId'):
                raise ValueError('matching outstanding handoff required')
            outcome = data.get('outcome')
            if outcome not in ('screen-observed-sent', 'not-sent', 'unknown'):
                raise ValueError('invalid outcome')
            msg.update(state=outcome, receipt={'evidence': text(data, 'evidence', 1000), 'observedAt': instant(data.get('observedAt')), 'qualification': 'screen-observation-reported', 'actualBody': text(data, 'actualBody') if outcome == 'screen-observed-sent' else None, 'actualSubject': text(data, 'actualSubject', 200) if outcome == 'screen-observed-sent' and data.get('actualSubject') else '', 'attachments': []})
            if data.get('actualAttachments'):
                raise ValueError('cannot record unmodeled attachments')
        else:
            raise ValueError('unsupported mutation')
        msg['revision'] += 1
        return self.save('messages', msg)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', required=True)
    parser.add_argument('--owner', required=True)
    parser.add_argument('--operation', choices=OPS, required=True)
    parser.add_argument('--input', help='JSON file; defaults to stdin')
    args = parser.parse_args()
    crm = None
    os.umask(0o077)
    try:
        raw = Path(args.input).read_bytes() if args.input else sys.stdin.buffer.read(65537)
        if len(raw) > 65536:
            raise ValueError('input exceeds 64 KiB')
        data = json.loads(raw)
        crm = CRM(args.db, args.owner)
        print(canonical(crm.run(args.operation, data)))
    except (ValueError, OSError, sqlite3.Error):
        print(canonical({'error': 'Operation rejected; check input, owner, permissions, state, revision and digest.'}), file=sys.stderr)
        return 1
    finally:
        if crm:
            crm.db.close()
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
