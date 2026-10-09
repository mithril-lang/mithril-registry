"""Public-path checks using synthetic evidence only, with isolated profile/vault roots."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from email.message import EmailMessage
from email import policy

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'skills/security/mithril-crypto-fraud-response/scripts/response.py'
INSTALL = SCRIPT.with_name('install_profile.py')
spec = importlib.util.spec_from_file_location('crypto_response', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ResponseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.inputs = self.base / 'exports'
        self.inputs.mkdir()
        self.store = module.Cases(str(self.base / 'vault'))
        self.creation = {'caseId': 'fixture', 'authority': {'authorized': True, 'basis': 'synthetic acceptance',
                         'scope': 'fixtures only', 'operator': 'tester'}, 'inputRoots': [str(self.inputs)]}
        self.store.create(self.creation)

    def ingest(self, text, kind='line-text', filename='chat.txt'):
        source = self.inputs / filename
        source.write_bytes(text.encode())
        return self.store.ingest({'caseId': 'fixture', 'path': str(source), 'format': kind})

    def test_line_source_references_and_integrity(self):
        addr = '0x' + 'a' * 40
        receipt = self.ingest('2026/10/09 Friday\n10:10\tSender claim\tPay ' + addr + '\ncontinuation https://example.test/pay\n')
        analysis = self.store.analyze('fixture')
        self.assertEqual(analysis['identifiers'][0]['locator'], 'line:2')
        self.assertEqual(analysis['identifiers'][0]['sha256'], receipt['sha256'])
        self.assertEqual(analysis['timelineSourceOrder'][0]['senderClaim'], 'Sender claim')
        self.assertIsNone(analysis['timelineSourceOrder'][0]['timeUtc'])
        original = self.store.case('fixture') / 'evidence' / receipt['evidenceId'] / 'original'
        self.assertEqual(original.read_bytes(), (self.inputs / 'chat.txt').read_bytes())
        original.write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'integrity'):
            self.store.draft({'caseId': 'fixture'})

    def test_authority_root_traversal_symlinks_duplicates(self):
        with self.assertRaises(ValueError):
            self.store.create({**self.creation, 'caseId': 'no-authority', 'authority': {'authorized': False}})
        with self.assertRaises(ValueError):
            self.store.case('../escape')
        outside = self.base / 'outside.txt'
        outside.write_text('private')
        with self.assertRaisesRegex(ValueError, 'outside'):
            self.store.ingest({'caseId': 'fixture', 'path': str(outside), 'format': 'message-text'})
        with self.assertRaisesRegex(ValueError, 'outside'):
            self.store.ingest({'caseId': 'fixture', 'path': str(self.inputs / '..' / 'outside.txt'), 'format': 'message-text'})
        link = self.inputs / 'link.txt'
        link.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.store.ingest({'caseId': 'fixture', 'path': str(link), 'format': 'message-text'})
        self.ingest('retained')
        with self.assertRaisesRegex(ValueError, 'already retained'):
            self.store.ingest({'caseId': 'fixture', 'path': str(self.inputs / 'chat.txt'), 'format': 'line-text'})

    def test_sms_empty_and_malformed(self):
        self.ingest('<smses><sms address="claim" date="0" type="1" body="hello"/></smses>', 'sms-xml')
        self.assertTrue(self.store.analyze('fixture')['timelineSourceOrder'][0]['timeUtc'].startswith('1970-01-01'))
        with self.assertRaises(ValueError):
            module.parse(b'<!DOCTYPE smses><smses/>', 'sms-xml')
        rows, gaps = module.parse(b'<smses/>', 'sms-xml')
        self.assertEqual(rows, [])
        self.assertTrue(any('No SMS rows' in gap for gap in gaps))

    def test_supplied_edges_do_not_override_provenance_or_identify(self):
        snapshot = {'sourceUrl': 'https://example.test/tx', 'observedAt': '2026-10-09T00:00:00Z',
                    'chain': 'ethereum', 'coverage': 'one supplied tx', 'transactions': [
                        {'txHash': '0x'+'b'*64, 'from': '0x'+'a'*40, 'to': '0x'+'c'*40,
                         'amount': '1.25', 'asset': 'ETH', 'evidenceId': 'forged', 'ownership': 'confirmed'}]}
        receipt = self.ingest(json.dumps(snapshot), 'chain-json')
        edge = self.store.analyze('fixture')['suppliedTransactionEdges'][0]
        self.assertEqual(edge['evidenceId'], receipt['evidenceId'])
        self.assertEqual(edge['ownership'], 'unknown')
        self.assertEqual(edge['amount'], '1.25')
        draft = self.store.draft({'caseId': 'fixture'})
        self.assertFalse(draft['executed'])
        self.assertTrue(all(a['state'] == 'not-submitted' for a in draft['actions']))
        self.assertEqual(draft['recoveryStatus'], 'not-verified')

    def test_private_root_and_interrupted_staging(self):
        public = self.base / 'public'
        public.mkdir(mode=0o755)
        with self.assertRaisesRegex(ValueError, 'private'):
            module.Cases(str(public))
        (self.store.case('fixture') / 'evidence' / '.staging-interrupted').mkdir()
        with self.assertRaisesRegex(ValueError, 'Interrupted'):
            self.store.analyze('fixture')

    def test_profile_installed_mcp_public_path_and_no_credentials(self):
        home = self.base / 'home'
        home.mkdir()
        (home / '.env').write_text('DO_NOT_COPY=synthetic-secret\n')
        subprocess.run([sys.executable, str(INSTALL), '--home', str(home), '--apply'], check=True, capture_output=True)
        profile = home / 'profiles' / 'crypto-fraud-response'
        self.assertFalse((profile / '.env').exists())
        self.assertFalse((home / 'active_profile').exists())
        cfg = json.loads((profile / 'config.yaml').read_text())
        server = cfg['mcp_servers']['crypto-fraud-local']
        requests = [
            {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-06-18'}},
            {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
            {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'},
            {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call', 'params': {'name': 'fraud_case_create', 'arguments': self.creation}},
            {'jsonrpc': '2.0', 'id': 4, 'method': 'tools/call', 'params': {'name': 'fraud_inventory', 'arguments': {'caseId': 'fixture'}}},
            {'jsonrpc': '2.0', 'id': 5, 'method': 'tools/call', 'params': {'name': 'fraud_analyze', 'arguments': {'caseId': '../escape'}}},
        ]
        process = subprocess.run([server['command'], *server['args']], input='\n'.join(json.dumps(r) for r in requests)+'\n',
                                 text=True, capture_output=True, check=True)
        replies = [json.loads(line) for line in process.stdout.splitlines()]
        self.assertEqual(replies[0]['result']['protocolVersion'], '2025-06-18')
        self.assertEqual(len(replies[1]['result']['tools']), 9)
        self.assertEqual(json.loads(replies[3]['result']['content'][0]['text'])['evidence'], [])
        self.assertTrue(replies[4]['result']['isError'])
        rerun = subprocess.run([sys.executable, str(INSTALL), '--home', str(home), '--apply'], capture_output=True)
        self.assertNotEqual(rerun.returncode, 0)

    def prepare(self, text='Synthetic reviewed disclosure'):
        payload = self.ingest(text, 'attachment', 'payload.txt')
        support = self.ingest('Synthetic authority declaration', 'attachment', 'authority.txt') if not hasattr(self, 'support') else self.support
        self.support = support
        args = {'caseId': 'fixture', 'recipient': {'name': 'Synthetic desk', 'officialUrl': 'https://example.test/report'},
                'purpose': 'bank-investigation', 'reporterRole': 'delegated-representative', 'legalBasis': 'Synthetic delegation',
                'routeVerifiedAt': '2026-10-09T00:00:00Z', 'payloadEvidenceId': payload['evidenceId'],
                'supportingEvidenceIds': [support['evidenceId']]}
        result = module.execute(self.store, 'fraud_action_prepare', args)
        self.assertEqual(module.execute(self.store, 'fraud_action_prepare', args)['actionId'], result['actionId'])
        return result, args

    def event(self, action, state, **kwargs):
        args = {'caseId': 'fixture', 'actionId': action['actionId'], 'state': state,
                'evidenceIds': [self.support['evidenceId']], 'note': 'Synthetic observation, source line 1',
                'observedAt': '2026-10-09T00:00:00Z', **kwargs}
        return module.execute(self.store, 'fraud_action_event', args)

    def dispatch(self, action):
        return self.event(action, 'dispatch-started', approval={'authorized': True, 'actionId': action['actionId'],
                           'basis': 'Synthetic exact-action authorization', 'operator': 'tester'})

    def test_unknown_dispatch_and_changed_payload_do_not_bypass_reconciliation(self):
        first, args = self.prepare()
        with self.assertRaisesRegex(ValueError, 'approval'):
            self.event(first, 'dispatch-started')
        self.dispatch(first)
        self.event(first, 'unknown')
        with self.assertRaisesRegex(ValueError, 'reconcile'):
            self.dispatch(first)
        second, _ = self.prepare('Changed synthetic disclosure')
        with self.assertRaisesRegex(ValueError, 'unresolved'):
            self.dispatch(second)
        self.event(first, 'reconciled-not-submitted')
        self.dispatch(second)
        self.event(second, 'acknowledged')
        status = module.execute(self.store, 'fraud_action_status', {'caseId': 'fixture'})
        observed = next(a for a in status['actions'] if a['actionId'] == second['actionId'])
        self.assertTrue(observed['receiptRecorded'])
        self.assertFalse(observed['freezeObservationRecorded'])
        self.assertFalse(observed['returnObservationRecorded'])
        self.assertFalse(status['externalExecution'])

    def test_outcomes_require_sources_and_explicit_valid_amounts(self):
        action, args = self.prepare()
        with self.assertRaisesRegex(ValueError, 'transition'):
            self.event(action, 'frozen', amount='1', currency='JPY')
        self.dispatch(action)
        self.event(action, 'submitted')
        with self.assertRaisesRegex(ValueError, 'retained'):
            self.event(action, 'acknowledged', evidenceIds=['ev-'+'0'*64])
        for amount in ['NaN', 'Infinity', '-1', '0']:
            with self.assertRaises(ValueError):
                self.event(action, 'frozen', amount=amount, currency='JPY')
        self.event(action, 'frozen', amount='100.25', currency='JPY')
        self.event(action, 'returned-and-reconciled', amount='50.25', currency='JPY')
        with self.assertRaisesRegex(ValueError, 'transition'):
            self.event(action, 'returned-and-reconciled', amount='50.25', currency='JPY')
        original = self.store.case('fixture') / 'evidence' / self.support['evidenceId'] / 'original'
        original.write_bytes(b'altered source')
        with self.assertRaisesRegex(ValueError, 'integrity'):
            module.execute(self.store, 'fraud_action_status', {'caseId': 'fixture'})

    def test_schema_timestamp_and_token_routes_rejected(self):
        _, args = self.prepare()
        for url in ['http://example.test', 'https://user:secret@example.test', 'https://example.test/?token=secret']:
            with self.assertRaises(ValueError):
                module.execute(self.store, 'fraud_action_prepare', {**args, 'recipient': {'name': 'desk', 'officialUrl': url}})
        with self.assertRaisesRegex(ValueError, 'timezone'):
            module.execute(self.store, 'fraud_action_prepare', {**args, 'routeVerifiedAt': '2026-10-09T00:00:00'})
        with self.assertRaisesRegex(ValueError, 'Unexpected'):
            module.execute(self.store, 'fraud_action_prepare', {**args, 'send': True})

    def test_japanese_original_email_decode_is_not_authenticated_receipt(self):
        mail = EmailMessage(policy=policy.SMTP)
        mail['From'] = 'desk@example.test'
        mail['To'] = 'reporter@example.test'
        mail['Subject'] = '合成受付通知'
        mail.set_content('合成テストの受付通知です。', charset='iso-2022-jp')
        source = self.inputs / 'receipt.eml'
        source.write_bytes(mail.as_bytes())
        receipt = self.store.ingest({'caseId': 'fixture', 'path': str(source), 'format': 'attachment'})
        decoded = module.execute(self.store, 'fraud_receipt_decode', {'caseId': 'fixture', 'evidenceId': receipt['evidenceId']})
        self.assertIn('合成テスト', decoded['plainTextParts'][0]['text'])
        self.assertEqual(decoded['sha256'], receipt['sha256'])
        self.assertFalse(decoded['senderAuthenticated'])
        self.assertFalse(decoded['receiptConfirmed'])


if __name__ == '__main__':
    unittest.main()
