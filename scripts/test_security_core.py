"""Explicit installed-engine integration. Never queries a live external target."""
import json
import os
import http.server
import threading
import unittest
from urllib.parse import unquote
from unittest.mock import patch

from test_security_suite import suite, request


def advisory(ecosystem='npm', name='demo', version='1.0.0'):
    return {'id': 'TEST-ADVISORY', 'affected': [{'package': {'ecosystem': ecosystem, 'name': name},
                                             'versions': [version]}]}


@unittest.skipUnless(os.environ.get('MITHRIL_SECURITY_ENGINE_ROOT'), 'operator engine checkouts not configured')
class CoreIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.core = suite.CoreHost(os.environ['MITHRIL_SECURITY_ENGINE_ROOT'])

    def test_vm_affected_and_negative_versions(self):
        result = suite.run(request('vm', {'components': [{'name': 'demo', 'version': '1.0.0', 'ecosystem': 'npm'},
                                                        {'name': 'demo', 'version': '2.0.0', 'ecosystem': 'npm'}],
                                          'advisories': [advisory()]}), core=self.core)
        self.assertEqual(len(result['reports'][0]['findings']), 1)
        self.assertEqual(result['reports'][0]['summary']['advisoryScope'], 'caller-supplied-only')

    def test_vm_semver_ranges_and_missing_versions(self):
        record = advisory()
        record['affected'][0].pop('versions')
        record['affected'][0]['ranges'] = [{'type': 'SEMVER', 'events': [{'introduced': '0'}, {'fixed': '1.1.0'}]}]
        result = suite.run(request('vm', {'components': [{'name': 'demo', 'version': '1.0.0', 'ecosystem': 'npm'},
                                                       {'name': 'demo', 'ecosystem': 'npm'}],
                                         'advisories': [record]}), core=self.core)
        self.assertEqual(len(result['reports'][0]['findings']), 1)
        self.assertTrue(result['reports'][0]['gaps'])

    def test_sca_manifest_and_unsupported_formats(self):
        result = suite.run(request('sca', {'files': [{'path': 'requirements.txt', 'content': 'requests==2.19.1\n'},
                                                    {'path': 'pom.xml', 'content': '<project/>'}],
                                           'advisories': [advisory('PyPI', 'requests', '2.19.1')]}), core=self.core)
        self.assertEqual(len(result['reports'][0]['findings']), 1)
        self.assertTrue(result['reports'][0]['gaps'])

    def test_container_debian_inventory(self):
        result = suite.run(request('container', {'extracted': {'var/lib/dpkg/status':
            'Package: demo\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\n'},
            'os-release': {'os/id': 'debian', 'os/version': '12'},
            'advisories': [advisory('Debian:12', 'demo', '1.0')]}), core=self.core)
        self.assertEqual(len(result['reports'][0]['findings']), 1)
        self.assertTrue(result['reports'][0]['gaps'])

    def test_cspm_uses_real_rules_and_preserves_resource_id(self):
        result = suite.run(request('cspm', {'resources': [{'resource/id': 'sg-test',
             'resource/provider': 'aws', 'resource/type': 'firewall-rule',
             'resource/config': {'world-open-admin-port?': True}}]}), core=self.core)
        self.assertTrue(result['reports'][0]['findings'])
        self.assertEqual(result['reports'][0]['findings'][0]['asset'], 'sg-test')
        self.assertIn('attackPaths', result['reports'][0]['summary'])

    def test_dast_preserves_distinct_header_findings(self):
        headers = {'X-Content-Type-Options': ['nosniff']}
        result = suite.run(request('dast', {'responses': [{'url': 'https://example.test/',
                  'status': 200, 'headers': headers, 'body': ''}]}), core=self.core)
        self.assertEqual(len(result['reports'][0]['findings']), 3)

    def test_active_plan_and_actual_core_evidence(self):
        url = 'http://127.0.0.1:8080/?q=1'
        plan = self.core.assess('dast-plan', {'url': url})['requests']
        self.assertTrue(plan)
        result = self.core.assess('dast-probes', {'url': url, 'baseline': 'baseline',
                   'probes': {target: {'body': 'SQL syntax error'} for target in plan}})
        self.assertTrue(any(f['rule-id'] == '40018' for f in result['findings']))

    def test_dirty_or_wrong_engine_identity_refused(self):
        with patch.object(suite.subprocess, 'check_output', return_value='0' * 40):
            with self.assertRaises(suite.Refusal):
                suite.CoreHost(os.environ['MITHRIL_SECURITY_ENGINE_ROOT'])

    def test_live_loopback_active_host_and_engine_pipeline(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                text = 'SQL syntax error' if "'" in unquote(self.path) else 'baseline'
                self.wfile.write(text.encode())

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        origin = f'http://127.0.0.1:{server.server_address[1]}'
        try:
            host = suite.NetworkHost([origin], active=True, budget=32)
            result = suite.run(request('dast', {'target': origin + '/?q=1', 'active': True}),
                               core=self.core, network=host)
            self.assertTrue(any(f['rule'] == '40018' for f in result['reports'][0]['findings']))
            self.assertFalse(result['productionVerified'])
        finally:
            server.shutdown()
            server.server_close()
            worker.join()


if __name__ == '__main__':
    unittest.main()
