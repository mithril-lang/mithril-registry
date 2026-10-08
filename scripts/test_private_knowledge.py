"""Private client routing, credential and mutation boundaries with synthetic HTTP."""
import importlib.util
import json
from email.message import Message
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / 'skills/data/mithril-private-knowledge/scripts/client.py'
spec = importlib.util.spec_from_file_location('private_client', CLIENT)
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)
DOC = '10000000-0000-4000-8000-000000000001'
ORG = '20000000-0000-4000-8000-000000000001'
OP = '30000000-0000-4000-8000-000000000001'


class Response:
    def __init__(self, url, data):
        self.url, self.data = url, data
        self.headers = Message()
        self.headers['Content-Type'] = 'application/json'
    def __enter__(self): return self
    def __exit__(self, *_args): return False
    def geturl(self): return self.url
    def read(self, count): return self.data[:count]


class Transport:
    def __init__(self, data=None):
        self.data = data or {'documents': [], 'nextCursor': DOC, 'scanned': 20}
        self.requests = []
    def open(self, request, timeout):
        self.requests.append(request)
        assert timeout == 30
        return Response(request.full_url, json.dumps(self.data).encode())


class PrivateKnowledgeTest(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict('os.environ', {'MITHRIL_PRIVATE_KNOWLEDGE_TOKEN': 'synthetic-token'})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_scoped_search_preserves_empty_page_cursor_and_encodes_query(self):
        transport = Transport()
        result = client.execute('search', {'scope': 'organization', 'organizationId': ORG,
                                          'q': 'private & 日本語', 'cursor': DOC, 'limit': 50}, opener=transport)
        req = transport.requests[0]
        url = urllib.parse.urlsplit(req.full_url)
        self.assertEqual(url.netloc, 'api.mithril.fund')
        self.assertEqual(url.path, '/v1/knowledge/private/organizations/' + ORG + '/documents')
        self.assertEqual(urllib.parse.parse_qs(url.query)['q'], ['private & 日本語'])
        self.assertEqual(result['nextCursor'], DOC)
        self.assertEqual(result['documents'], [])
        self.assertEqual(req.get_header('Authorization'), 'Bearer synthetic-token')
        self.assertEqual(req.get_header('Cache-control'), 'no-store')
        self.assertEqual(req.get_header('User-agent'), 'Mithril-Private-Knowledge/1.0.1')

    def test_put_and_delete_keep_exact_revision_and_operation_identity(self):
        transport = Transport({'revision': 4})
        payload = {'scope': 'account', 'documentId': DOC, 'operationId': OP,
                   'expectedRevision': 3, 'title': 'Private', 'body': '{"data":"日本語"}'}
        for _ in range(2):
            client.execute('put', payload, True, opener=transport)
        self.assertEqual(transport.requests[0].data, transport.requests[1].data)
        self.assertEqual(json.loads(transport.requests[0].data)['operationId'], OP)
        self.assertEqual(transport.requests[0].method, 'PUT')
        client.execute('delete', {k: v for k, v in payload.items() if k not in ('title', 'body')}, True, opener=transport)
        self.assertEqual(transport.requests[-1].method, 'DELETE')
        self.assertEqual(set(json.loads(transport.requests[-1].data)), {'operationId', 'expectedRevision'})

    def test_graph_provisioning_uses_separate_owner_derived_endpoint(self):
        transport = Transport({'created': True})
        client.execute('provision', {'scope': 'account'}, True, opener=transport)
        self.assertEqual(transport.requests[-1].full_url, client.ORIGIN + '/v1/knowledge/graphs/account')
        self.assertEqual(transport.requests[-1].data, b'{}')
        client.execute('provision', {'scope': 'organization', 'organizationId': ORG}, True, opener=transport)
        self.assertEqual(json.loads(transport.requests[-1].data), {'organizationId': ORG})
        client.execute('get', {'scope': 'account', 'documentId': DOC}, opener=transport)
        self.assertTrue(transport.requests[-1].full_url.endswith('/account/documents/' + DOC))

    def test_rejects_scope_escape_unknown_fields_and_bounds_before_network(self):
        transport = Transport()
        for payload in ({}, {'scope': 'organization', 'organizationId': '../account'},
                        {'scope': 'account', 'userId': DOC}, {'scope': 'account', 'url': 'https://other.invalid'},
                        {'scope': 'account', 'limit': True}, {'scope': 'account', 'limit': 51},
                        {'scope': 'account', 'q': '😀' * 101}):
            with self.assertRaises(client.Failure):
                client.execute('search', payload, opener=transport)
        payload = {'scope': 'account', 'documentId': DOC, 'operationId': OP,
                   'expectedRevision': 0, 'title': 'Private', 'body': 'x'}
        with self.assertRaisesRegex(client.Failure, 'write_not_enabled'):
            client.execute('put', payload, opener=transport)
        for change in ({'body': '😀' * 8001}, {'expectedRevision': True}, {'operationId': 'bad'},
                       {'title': ' '}, {'body': '\x00' * 16000}):
            with self.assertRaises(client.Failure):
                client.execute('put', payload | change, True, opener=transport)
        self.assertEqual(transport.requests, [])

    def test_token_is_required_and_never_taken_from_arguments(self):
        transport = Transport()
        for token in ('', 'secret\nheader', 'secret space'):
            with patch.dict('os.environ', {'MITHRIL_PRIVATE_KNOWLEDGE_TOKEN': token}):
                with self.assertRaisesRegex(client.Failure, 'credential_required'):
                    client.execute('graphs', {}, opener=transport)
        with self.assertRaisesRegex(client.Failure, 'unexpected_fields'):
            client.execute('graphs', {'token': 'other-profile-secret'}, opener=transport)
        self.assertEqual(transport.requests, [])

    def test_redirects_provider_errors_and_oversized_responses_fail_closed(self):
        with self.assertRaisesRegex(client.Failure, 'redirect_refused'):
            client.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.invalid')
        transport = Transport()
        error = urllib.error.HTTPError(client.ORIGIN, 409, 'private-body-and-token', {}, None)
        with patch.object(transport, 'open', side_effect=error), self.assertRaisesRegex(client.Failure, '^http_409$'):
            client.execute('graphs', {}, opener=transport)
        self.assertEqual(transport.requests, [])  # No automatic retry.
        response = Response('https://other.invalid', b'{}')
        with patch.object(transport, 'open', return_value=response), self.assertRaisesRegex(client.Failure, 'unexpected_response_origin'):
            client.execute('graphs', {}, opener=transport)
        response.url = client.ORIGIN + '/v1/knowledge/graphs'
        response.data = b'x' * (client.MAX_RESPONSE + 1)
        with patch.object(transport, 'open', return_value=response), self.assertRaisesRegex(client.Failure, 'response_too_large'):
            client.execute('graphs', {}, opener=transport)

    def test_cli_errors_do_not_echo_private_input(self):
        proc = subprocess.run([sys.executable, str(CLIENT), 'put'], input=b'{"private":"secret-not-for-log"}', capture_output=True)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stdout, b'')
        self.assertEqual(json.loads(proc.stderr), {'error': 'write_not_enabled'})

    def test_skill_is_generated_as_installable_with_bounded_contract(self):
        index = json.loads((ROOT / 'index.json').read_text())
        entry = next(e for e in index['entries'] if e['id'] == 'mithril-private-knowledge')
        self.assertEqual(entry['type'], 'skill')
        self.assertTrue(entry['installable'])
        self.assertEqual(entry['version'], '1.0.1')
        contract = (CLIENT.parents[1] / 'references/contract.md').read_text()
        self.assertIn('37728020539', contract)
        self.assertIn('No full', contract)


if __name__ == '__main__':
    unittest.main()
