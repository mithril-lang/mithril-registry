"""Synthetic state/authority tests; never access LinkedIn."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / 'skills/sales/mithril-linkedin-sales'
spec = importlib.util.spec_from_file_location('linkedin_sales', PKG / 'scripts/sales.py')
sales = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sales)

class SalesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'crm.sqlite'
        self.crm = sales.CRM(self.path, 'owner-a')
        self.lead = self.call('lead', name='Synthetic Person', company='Example', profileUrl='https://www.linkedin.com/in/synthetic-test', source='user-supplied fixture', observedAt='2026-10-08T12:00:00+09:00', outreachBasis='synthetic authorized introduction', fitReason='fixture fit', authorizedInput=True)

    def tearDown(self):
        self.crm.db.close()
        self.temp.cleanup()

    def call(self, operation, **data):
        return self.crm.run(operation, dict(operationId=str(uuid4()), **data))

    def draft(self, **extra):
        return self.call('draft', leadId=self.lead['id'], kind='dm', senderProfileUrl='https://www.linkedin.com/in/synthetic-sender', body='A synthetic introduction.', **extra)

    def transition(self, operation, msg, **extra):
        return self.call(operation, messageId=msg['id'], digest=msg['digest'], expectedRevision=msg['revision'], **extra)

    def handoff(self):
        msg = self.draft()
        msg = self.transition('approve', msg, actor='owner-a', memberAction='approve-draft')
        return self.transition('handoff', msg, actor='owner-a', memberAction='prepare-screen-send')

    def test_complete_screen_workflow_and_actual_wording(self):
        handoff = self.handoff()
        self.assertFalse(handoff['sent'])
        msg = handoff['message']
        msg = self.transition('receipt', msg, handoffId=handoff['handoffId'], outcome='screen-observed-sent', evidence='private screenshot reference', observedAt='2026-10-08T13:00:00+09:00', actualBody='A synthetic introduction.')
        self.assertEqual(msg['receipt']['qualification'], 'screen-observation-reported')
        self.assertEqual(msg['receipt']['actualBody'], 'A synthetic introduction.')
        lead = self.call('reply', leadId=self.lead['id'], body='Please arrange a meeting.', evidence='supplied reply', observedAt='2026-10-08T14:00:00+09:00')
        lead = self.call('opportunity', leadId=lead['id'], expectedRevision=lead['revision'], stage='meeting', evidence='supplied meeting request', nextReviewAt='2026-10-09T00:00:00Z')
        self.assertEqual(self.crm.run('followups', {'at':'2026-10-10T00:00:00Z'})['due'][0]['leadId'], lead['id'])
        self.assertFalse(self.crm.run('status', {})['externalSendReady'])

    def test_exact_approval_and_stale_state(self):
        msg = self.draft()
        for field, value in [('digest', 'wrong'), ('expectedRevision', 99), ('actor', 'other')]:
            args = dict(messageId=msg['id'], digest=msg['digest'], expectedRevision=msg['revision'], actor='owner-a', memberAction='approve-draft')
            args[field] = value
            with self.assertRaises(ValueError):
                self.call('approve', **args)
        approved = self.transition('approve', msg, actor='owner-a', memberAction='approve-draft')
        with self.assertRaises(ValueError):
            self.transition('handoff', msg, actor='owner-a', memberAction='prepare-screen-send')
        self.assertEqual(approved['revision'], 2)

    def test_no_unapproved_transfer(self):
        with self.assertRaises(ValueError):
            self.transition('handoff', self.draft(), actor='owner-a', memberAction='prepare-screen-send')

    def test_suppression_invalidates_approval_but_allows_reconciliation(self):
        handoff = self.handoff()
        self.call('suppress', leadId=self.lead['id'], reason='do not contact')
        with self.assertRaises(ValueError):
            self.draft()
        msg = self.transition('receipt', handoff['message'], handoffId=handoff['handoffId'], outcome='not-sent', evidence='no submit performed', observedAt='2026-10-08T12:00:00Z')
        self.assertEqual(msg['state'], 'not-sent')

    def test_optout_blocks_preapproved_message(self):
        msg = self.transition('approve', self.draft(), actor='owner-a', memberAction='approve-draft')
        self.call('reply', leadId=self.lead['id'], body='Stop contacting me.', evidence='supplied reply', observedAt='2026-10-08T00:00:00Z', optOut=True)
        with self.assertRaises(ValueError):
            self.transition('handoff', msg, actor='owner-a', memberAction='prepare-screen-send')

    def test_unknown_blocks_retries_and_followups(self):
        h = self.handoff()
        msg = self.transition('receipt', h['message'], handoffId=h['handoffId'], outcome='unknown', evidence='window closed after submit', observedAt='2026-10-08T00:00:00Z')
        with self.assertRaises(ValueError):
            self.draft()
        self.call('opportunity', leadId=self.lead['id'], expectedRevision=1, stage='qualified', evidence='review needed', nextReviewAt='2026-10-08T00:00:00Z')
        self.assertEqual(self.crm.run('followups', {'at':'2026-10-09T00:00:00Z'})['due'], [])
        with self.assertRaises(ValueError):
            self.transition('receipt', msg, handoffId=str(uuid4()), outcome='not-sent', evidence='wrong', observedAt='2026-10-08T00:00:00Z')
        self.transition('receipt', msg, handoffId=h['handoffId'], outcome='not-sent', evidence='conversation inspected; no message', observedAt='2026-10-08T00:00:00Z')
        self.draft()

    def test_idempotency_and_audit_once(self):
        data = dict(operationId=str(uuid4()), leadId=self.lead['id'], reason='opt-out')
        first = self.crm.run('suppress', data)
        self.assertEqual(first, self.crm.run('suppress', data))
        with self.assertRaises(ValueError):
            self.crm.run('suppress', dict(data, reason='changed'))
        self.assertEqual(self.crm.db.execute('SELECT count(*) FROM audit WHERE operation_id=?', (data['operationId'],)).fetchone()[0], 1)

    def test_owner_isolation_and_permissions(self):
        with self.assertRaises(ValueError):
            sales.CRM(self.path, 'owner-b')
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            sales.CRM(self.path, 'owner-a')
        self.path.chmod(0o600)

    def test_duplicate_profile_cannot_bypass_suppression(self):
        self.call('suppress', leadId=self.lead['id'], reason='opt-out')
        with self.assertRaises(ValueError):
            self.call('lead', name='Other name', company='Example', profileUrl=self.lead['profileUrl'].replace('synthetic-test','SYNTHETIC-TEST')+'/', source='supplied', observedAt='2026-10-08T00:00:00Z', outreachBasis='supplied', fitReason='fit', authorizedInput=True)

    def test_one_unresolved_handoff_across_preexisting_drafts(self):
        a, b = self.draft(), self.draft()
        a = self.transition('approve', a, actor='owner-a', memberAction='approve-draft')
        b = self.transition('approve', b, actor='owner-a', memberAction='approve-draft')
        self.transition('handoff', a, actor='owner-a', memberAction='prepare-screen-send')
        with self.assertRaises(ValueError):
            self.transition('handoff', b, actor='owner-a', memberAction='prepare-screen-send')

    def test_cancel_and_no_network_contract(self):
        msg = self.transition('cancel', self.draft(), reason='edit requested')
        with self.assertRaises(ValueError):
            self.transition('approve', msg, actor='owner-a', memberAction='approve-draft')
        contract = json.loads((ROOT / 'integrations/linkedin-sales.json').read_text())
        self.assertFalse(contract['runtime']['network'])
        self.assertFalse(contract['provider']['externalSendReady'])
        self.assertFalse(contract['screenAdapter']['retryUnknown'])
        self.assertFalse(contract['coverage']['scheduledSending'])
        self.assertEqual(contract['skill'], PKG.relative_to(ROOT).as_posix())

    def test_validation_failures_do_not_create_records(self):
        for body in ('<b>hello</b>', '', 'a'*4001):
            with self.assertRaises(ValueError):
                self.call('draft', leadId=self.lead['id'], senderProfileUrl='https://www.linkedin.com/in/sender', kind='dm', body=body)
        with self.assertRaises(ValueError):
            sales.profile('https://www.linkedin.com.evil.example/in/target')
        with self.assertRaises(ValueError):
            sales.instant('2026-10-08T00:00:00')
        self.assertEqual(self.crm.db.execute('SELECT count(*) FROM messages').fetchone()[0], 0)

if __name__ == '__main__':
    unittest.main()
