"""Context contracts, actual loopback transport, receipts and MCP end-to-end."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch
import urllib.request
from io import BytesIO
from email.message import Message
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'skills/security/mithril-cybersecurity-products/scripts/products.py'
spec = importlib.util.spec_from_file_location('context_products', SCRIPT)
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
FIXTURES = {
    'runzero': [{'id': 'asset-1', 'organization_id': 'org-1', 'os': 'Linux', 'addresses': ['8.8.8.8'], 'last_seen': 1791244800}],
    'okta-system-log': [{'uuid': 'event-1', 'displayMessage': 'Synthetic login', 'severity': 'INFO', 'published': '2026-10-06T00:00:00Z', 'client': {'ipAddress': '8.8.8.8'}, 'actor': {'id': 'user-1'}, 'eventType': 'user.session.start'}],
    'censys-platform': {'result': {'resource': {'ip': '8.8.8.8', 'services': [{'port': 53}]}}},
}
POLICIES = {
    'runzero': dict(origin='https://console.runzero.com', tokenEnv='FIXTURE_TOKEN', credentialScope='export-read'),
    'okta-system-log': dict(origin='https://fixture.okta.com', tokenEnv='FIXTURE_TOKEN', since='2026-10-05T00:00:00Z', until='2026-10-06T00:00:00Z'),
    'censys-platform': dict(origin='https://api.platform.censys.io', tokenEnv='FIXTURE_TOKEN', ip='8.8.8.8', organizationId='12345678-1234-1234-1234-123456789012'),
}


class ContextTests(unittest.TestCase):
    def seed(self, root, product):
        output = Path(root) / product
        receipt = p.persist(product, json.dumps(FIXTURES[product]).encode(), output, 'operator-export')
        return str(output), receipt

    def test_context_observations_and_no_invented_host_time(self):
        for product, data in FIXTURES.items():
            result = p.normalize(product, json.dumps(data).encode())
            self.assertEqual(result['findings'][0]['observedIPs'], ['8.8.8.8'])
            self.assertIn('coverage-not-complete', result['gaps'])
        host = p.normalize('censys-platform', json.dumps(FIXTURES['censys-platform']).encode())
        self.assertIsNone(host['findings'][0]['reportedTime'])

    def test_malformed_context_and_limits_fail_closed(self):
        for product, data in [('runzero', {}), ('okta-system-log', [{'uuid': 'x', 'client': {'ipAddress': 'bad'}}]), ('censys-platform', {'result': {'resource': {}}}), ('runzero', [{'id': 'x', 'addresses': ['fe80::1%en0']}]), ('okta-system-log', [{'uuid': 'x', 'actor': 'bad'}])]:
            with self.subTest(product=product), self.assertRaises(p.Refusal):
                p.normalize(product, json.dumps(data).encode())
        with self.assertRaises(p.Refusal):
            p.normalize('runzero', json.dumps(FIXTURES['runzero'] * 1001).encode())

    def test_fixed_read_requests_auth_and_scope(self):
        with patch.dict(os.environ, FIXTURE_TOKEN='synthetic-token'):
            for product, policy in POLICIES.items():
                req = p.request_for(dict(product=product, **policy))
                self.assertEqual(req.method, 'GET')
                self.assertEqual(req.get_header('Authorization'), 'Bearer synthetic-token')
            req = p.request_for(dict(product='okta-system-log', **POLICIES['okta-system-log']))
            query = parse_qs(urlsplit(req.full_url).query)
            self.assertEqual(query['until'], ['2026-10-06T00:00:00Z'])
            self.assertEqual(query['limit'], ['100'])
            self.assertEqual(query['sortOrder'], ['ASCENDING'])
            req = p.request_for(dict(product='censys-platform', **POLICIES['censys-platform']))
            self.assertEqual(req.get_header('Accept'), 'application/vnd.censys.api.v3.host.v1+json')
            self.assertEqual(parse_qs(urlsplit(req.full_url).query)['organization_id'], [POLICIES['censys-platform']['organizationId']])

    def test_foreign_origins_custom_pins_windows_and_operation_injection(self):
        bad = [
            ('okta-system-log', dict(origin='https://fixture.okta.com.evil.invalid')),
            ('okta-system-log', dict(origin='https://user@fixture.okta.com')),
            ('okta-system-log', dict(until='2026-10-04T00:00:00Z')),
            ('okta-system-log', dict(since='2026-01-01T00:00:00Z')),
            ('okta-system-log', dict(since='2026-02-30T00:00:00Z')),
            ('okta-system-log', dict(limit=True)),
            ('okta-system-log', dict(after='https://evil.invalid/steal')),
            ('okta-system-log', dict(filter='arbitrary-query')),
            ('runzero', dict(origin='https://inventory.example.test')),
            ('runzero', dict(credentialScope='account-write')),
            ('censys-platform', dict(ip='127.0.0.1')),
            ('censys-platform', dict(ip='8.8.8.8/../../scan')),
            ('censys-platform', dict(organizationId=None)),
        ]
        with patch.dict(os.environ, FIXTURE_TOKEN='synthetic-token'):
            for product, changes in bad:
                with self.subTest(product=product, changes=changes), self.assertRaises(p.Refusal):
                    p.request_for(dict(product=product, **dict(POLICIES[product], **changes)))
            req = p.request_for(dict(product='runzero', **dict(POLICIES['runzero'], origin='https://inventory.example.test', approvedOrigin='https://inventory.example.test')))
            self.assertEqual(req.selector, '/api/v1.0/export/org/assets.json')

    def test_actual_http_collection_retains_header_coverage_not_credentials(self):
        seen = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                route = urlsplit(self.path).path
                product = {'/api/v1.0/export/org/assets.json': 'runzero', '/api/v1/logs': 'okta-system-log', '/v3/global/asset/host/8.8.8.8': 'censys-platform'}[route]
                seen.append((self.command, self.path, self.headers['Authorization']))
                self.send_response(200)
                self.send_header('Link', '<https://evil.invalid/steal>; rel="next"')
                self.end_headers()
                self.wfile.write(json.dumps(FIXTURES[product]).encode())
        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = Thread(target=server.serve_forever)
        thread.start()
        real = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        class Opener:
            def open(self, req, timeout):
                return real.open(urllib.request.Request(f'http://127.0.0.1:{server.server_port}' + req.selector, headers=req.headers, method=req.method), timeout=timeout)
        try:
            with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, FIXTURE_TOKEN='synthetic-token'), patch.object(p.urllib.request, 'build_opener', return_value=Opener()):
                for product, policy in POLICIES.items():
                    file = Path(root) / (product + '.json')
                    file.write_text(json.dumps(dict(product=product, **policy)))
                    result = p.execute('cybersecurity_collect', dict(policy=str(file), output=str(Path(root) / product)), network=True)
                    self.assertEqual(result['coverage']['collection']['httpStatus'], 200)
                    self.assertEqual(result['coverage']['collection']['responseBytes'], (Path(root) / product / 'source.json').stat().st_size)
                    self.assertEqual(result['coverage']['status'], 'incomplete-or-unknown')
                    self.assertNotIn('synthetic-token', json.dumps(result))
                    self.assertNotIn('evil.invalid', json.dumps(result))
                    if product == 'okta-system-log':
                        self.assertEqual(result['coverage']['continuation'], 'present')
            self.assertEqual(len(seen), 3)
        finally:
            server.shutdown(); thread.join(); server.server_close()

    def test_correlation_keeps_claims_scoped_and_requires_verified_bytes(self):
        with tempfile.TemporaryDirectory() as root:
            runs = [self.seed(root, product)[0] for product in FIXTURES]
            result = p.execute('cybersecurity_correlate', dict(runs=runs, address='8.8.8.8', limit=2))
            self.assertEqual(result['total'], 3)
            self.assertEqual(len(result['data']), 2)
            self.assertEqual(result['identityConclusion'], 'not-established')
            self.assertEqual(len({x['sourceSha256'] for x in result['data']}), 2)
            self.assertEqual(result['sources'][0]['coverageAttestation'], 'unsigned-local-receipt')
            timeline = p.execute('cybersecurity_timeline', dict(runs=runs))
            self.assertEqual(timeline['unknownTimeCount'], 1)
            (Path(runs[0]) / 'source.json').write_text('[]')
            with self.assertRaises(p.Refusal):
                p.execute('cybersecurity_correlate', dict(runs=runs, address='8.8.8.8'))

    def test_failure_and_mismatched_host_produce_no_successful_run(self):
        class Response(BytesIO):
            status = 200
            headers = Message()
        for raw in [b'{"result":{"resource":{"ip":"1.1.1.1"}}}', b'{"error":"denied"}', b'x' * (p.MAX_BYTES + 1)]:
            with self.subTest(length=len(raw)), tempfile.TemporaryDirectory() as root, patch.dict(os.environ, FIXTURE_TOKEN='synthetic-token'):
                policy = Path(root) / 'policy.json'
                policy.write_text(json.dumps(dict(product='censys-platform', **POLICIES['censys-platform'])))
                class Opener:
                    def open(self, req, timeout): return Response(raw)
                with patch.object(p.urllib.request, 'build_opener', return_value=Opener()), self.assertRaises((p.Refusal, ValueError)):
                    p.execute('cybersecurity_collect', dict(policy=str(policy), output=str(Path(root) / 'output')), network=True)
                self.assertFalse((Path(root) / 'output').exists())

    def test_ipv6_overlap_is_canonical_and_never_a_merge(self):
        with tempfile.TemporaryDirectory() as root:
            run = Path(root) / 'ipv6'
            p.persist('runzero', b'[{"id":"v6","addresses":["2001:4860:4860:0:0:0:0:8888"]}]', run, 'fixture')
            result = p.execute('cybersecurity_correlate', dict(runs=[str(run)], address='2001:4860:4860::8888'))
            self.assertEqual(result['total'], 1)
            self.assertEqual(result['identityConclusion'], 'not-established')

    def test_legacy_receipt_is_explicitly_unknown(self):
        with tempfile.TemporaryDirectory() as root:
            run, receipt = self.seed(root, 'runzero')
            receipt.pop('coverage')
            receipt['schemaVersion'] = 1
            (Path(run) / 'receipt.json').write_text(json.dumps(receipt))
            result = p.execute('cybersecurity_search', dict(runs=[run], query='Linux'))
            self.assertIn('legacy-receipt-no-coverage', result['sources'][0]['coverageClaims']['gaps'])

    def test_tampered_receipt_cannot_promote_collection_claims_to_complete(self):
        with tempfile.TemporaryDirectory() as root:
            run, receipt = self.seed(root, 'runzero')
            receipt['coverage']['status'] = 'complete'
            receipt['coverage']['retainedRecords'] = 999
            (Path(run) / 'receipt.json').write_text(json.dumps(receipt))
            source = p.execute('cybersecurity_search', dict(runs=[run], query='Linux'))['sources'][0]
            self.assertEqual(source['coverage']['status'], 'incomplete-or-unknown')
            self.assertEqual(source['coverage']['retainedRecords'], 1)
            self.assertEqual(source['coverageClaims']['status'], 'complete')
            self.assertEqual(source['coverageAttestation'], 'unsigned-local-receipt')

    def test_stdio_mcp_resources_discovery_and_correlation(self):
        with tempfile.TemporaryDirectory() as root:
            run, _ = self.seed(root, 'runzero')
            messages = [dict(jsonrpc='2.0', id=1, method='initialize', params=dict(protocolVersion='2025-11-25')),
                        dict(jsonrpc='2.0', id=2, method='resources/list'),
                        dict(jsonrpc='2.0', id=3, method='resources/read', params=dict(uri='cybersecurity://contracts')),
                        dict(jsonrpc='2.0', id=4, method='tools/list'),
                        dict(jsonrpc='2.0', id=5, method='tools/call', params=dict(name='cybersecurity_correlate', arguments=dict(runs=[run], address='8.8.8.8'))),
                        dict(jsonrpc='2.0', id=6, method='resources/read', params=dict(uri='file:///etc/passwd'))]
            result = subprocess.run(['python3', str(SCRIPT), '--mcp'], input='\n'.join(map(json.dumps, messages)) + '\n', text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            replies = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual(replies[0]['result']['serverInfo']['version'], '0.3.0')
            self.assertEqual(len(replies[1]['result']['resources']), 2)
            self.assertEqual(len(json.loads(replies[2]['result']['contents'][0]['text'])['products']), 10)
            self.assertEqual(len(replies[3]['result']['tools']), 7)
            self.assertFalse(replies[4]['result']['isError'])
            self.assertEqual(replies[4]['result']['structuredContent']['total'], 1)
            self.assertIn('error', replies[5])


if __name__ == '__main__':
    unittest.main()
