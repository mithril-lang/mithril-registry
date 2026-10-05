import copy
import http.server
import importlib.util
import json
import shutil
import tempfile
import threading
import unittest
import os
from pathlib import Path
from unittest.mock import patch

import security_catalog
import compile_security

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / security_catalog.RELATIVE
spec = importlib.util.spec_from_file_location('mithril_security_suite', PACKAGE / 'runtime/suite.py')
suite = importlib.util.module_from_spec(spec)
spec.loader.exec_module(suite)


def request(name, data, tenant='tenant-a'):
    return {'schemaVersion': '1', 'tenant': tenant, 'operations': [{'id': name, 'input': data}]}


class AdmissionTest(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('MITHRIL_SECURITY_COMPILER_ROOT'), 'compiler checkout not configured')
    def test_real_mithril_compiler_rejects_unknown_export_kind(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / 'package'
            shutil.copytree(PACKAGE, target)
            source = target / 'source/lib/fund/mithril/security/vm/v1.mith'
            source.write_text(source.read_text().replace('mith:analyzer', 'mith:execute-shell'))
            with patch.object(compile_security, 'PACKAGE', target), self.assertRaises(suite.subprocess.CalledProcessError):
                compile_security.compile_suite(Path(os.environ['MITHRIL_SECURITY_COMPILER_ROOT']))

    def test_catalog_contains_only_compiled_operations(self):
        result = security_catalog.build(ROOT)
        self.assertEqual(len(result['operations']), 10)
        self.assertEqual(result['policyDigest'], suite.digest(suite.policy()[0]))

    def test_source_drift_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / 'package'
            shutil.copytree(PACKAGE, target)
            with (target / 'source/suite.mith').open('a') as f:
                f.write('\n; changed\n')
            with patch.object(suite, 'PACKAGE', target), self.assertRaisesRegex(suite.Refusal, 'differs'):
                suite.policy()

    def test_unknown_operations_fields_and_duplicates_refused(self):
        samples = [request('shell', {}), request('sast', {'files': [], 'command': 'x'})]
        duplicate = request('sast', {'files': [{'path': 'a.py', 'content': ''}]})
        duplicate['operations'] *= 2
        samples.append(duplicate)
        for data in samples:
            with self.subTest(data=data), self.assertRaises(suite.Refusal):
                suite.run(data)

    def test_core_unavailable_does_not_substitute(self):
        with self.assertRaisesRegex(suite.Refusal, 'pinned core'):
            suite.run(request('vm', {'components': [], 'advisories': []}))

    def test_bounds_refused(self):
        with self.assertRaises(suite.Refusal):
            suite.run(request('sast', {'files': [{'path': 'a.py', 'content': 'x' * 65537}]}))
        with self.assertRaises(suite.Refusal):
            suite.bounded([0] * 129)

    def test_catalog_rejects_invented_live_maturity_and_mutable_engine(self):
        for change in ('maturity', 'engine', 'tests'):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                shutil.copytree(PACKAGE, root / security_catalog.RELATIVE)
                path = root / security_catalog.RELATIVE / 'capabilities.json'
                value = json.loads(path.read_text())
                if change == 'maturity':
                    value['operations'][0]['maturity'] = 'production'
                elif change == 'engine':
                    value['engines']['vm']['commit'] = 'main'
                else:
                    value['operations'][0]['tests'] = ['../../outside.py']
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    security_catalog.build(root)


class NativeTest(unittest.TestCase):
    def test_sast_tracks_aliases_and_assignment_to_sinks(self):
        source = 'import os as system\nfrom flask import request\nx = request.args.get("q")\ny = x\nsystem.system(y)\n'
        result = suite.run(request('sast', {'files': [{'path': 'a.py', 'content': source}]}))
        finding = result['reports'][0]['findings'][0]
        self.assertEqual(finding['rule'], 'python-tainted-shell')
        self.assertEqual(finding['line'], 5)
        self.assertNotIn(source, json.dumps(result))

    def test_sql_parameters_do_not_taint_query_text(self):
        source = 'x = input()\ncur.execute("select * from t where x=?", (x,))\n'
        result = suite.run(request('sast', {'files': [{'path': 'a.py', 'content': source}]}))
        self.assertEqual(result['reports'][0]['findings'], [])
        self.assertEqual(result['reports'][0]['coverage'], 'partial')

    def test_subprocess_argument_vector_is_not_shell_sink(self):
        source = 'import subprocess\nx = input()\nsubprocess.run(["echo", x], shell=False)\n'
        result = suite.run(request('sast', {'files': [{'path': 'a.py', 'content': source}]}))
        self.assertEqual(result['reports'][0]['findings'], [])

    def test_syntax_and_unsupported_language_are_gaps(self):
        result = suite.run(request('sast', {'files': [{'path': 'a.py', 'content': 'def'},
                                                      {'path': 'a.js', 'content': 'eval(input)'}]}))
        self.assertEqual(len(result['reports'][0]['gaps']), 2)

    def test_finding_ids_are_stable_and_tenant_separated(self):
        data = {'files': [{'path': 'a.py', 'content': 'eval(input())'}]}
        a, b = [suite.run(request('sast', data, tenant)) for tenant in ('a', 'b')]
        c = suite.run(request('sast', data, 'a'))
        self.assertEqual(a, c)
        self.assertNotEqual(a['reports'][0]['findings'][0]['id'], b['reports'][0]['findings'][0]['id'])

    def test_baseline_absence_is_unmeasured(self):
        result = suite.run(request('infra', {'baseline': {'firewallEnabled': True, 'rootLogin': False},
                                            'assets': [{'id': 'host1', 'settings': {'rootLogin': True}}]}))
        self.assertEqual(len(result['reports'][0]['findings']), 1)
        self.assertEqual(result['reports'][0]['gaps'][0]['reason'], 'unmeasured-firewallEnabled')

    def test_templates_have_positive_negative_and_unknown_rule_cases(self):
        data = {'responses': [{'url': 'https://example.test/?token=SECRET', 'headers': {}}]}
        result = suite.run(request('templates', data))
        self.assertEqual(len(result['reports'][0]['findings']), 2)
        self.assertNotIn('SECRET', json.dumps(result))
        data['responses'][0]['headers'] = {'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'self'"}
        self.assertFalse(suite.run(request('templates', data))['reports'][0]['findings'])
        data['rules'] = ['execute-shell']
        with self.assertRaises(suite.Refusal):
            suite.run(request('templates', data))

    def test_iac_and_secrets_do_not_echo_values(self):
        config = {'resource': {'aws_security_group': {'admin': {'ingress': [
            {'from_port': 22, 'to_port': 22, 'cidr_blocks': ['0.0.0.0/0']}]}}}}
        secret = 'AKIA' + 'Z' * 16
        data = {'files': [{'path': 'infra.tf.json', 'content': json.dumps(config)},
                          {'path': 'credential.txt', 'content': secret}]}
        result = suite.run(request('iac', data))
        self.assertEqual(len(result['reports'][0]['findings']), 2)
        self.assertNotIn(secret, json.dumps(result))

    def test_kubernetes_and_unknown_resources(self):
        pod = {'kind': 'Pod', 'spec': {'containers': [{'name': 'app', 'securityContext': {'privileged': True}}]}}
        result = suite.run(request('iac', {'files': [{'path': 'pod.json', 'content': json.dumps(pod)},
                                                     {'path': 'other.json', 'content': '{}'}]}))
        self.assertEqual(len(result['reports'][0]['findings']), 1)
        self.assertEqual(len(result['reports'][0]['gaps']), 1)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/redirect'):
            self.send_response(302)
            self.send_header('Location', 'http://192.0.2.1/outside')
        else:
            self.send_response(200)
        self.end_headers()
        self.wfile.write(b'ok')

    def log_message(self, *args):
        pass


class NetworkTest(unittest.TestCase):
    def test_insufficient_total_budget_refuses_before_first_effect(self):
        host = self.host(budget=1)
        target = f'tcp://127.0.0.1:{self.port}'
        with patch.object(host, 'connect') as connect, self.assertRaises(suite.Refusal):
            suite.run(request('network', {'targets': [target, target]}), network=host)
        connect.assert_not_called()

    def test_invalid_later_pure_operation_refuses_before_network(self):
        host = self.host()
        data = request('network', {'targets': [f'tcp://127.0.0.1:{self.port}']})
        data['operations'].append({'id': 'infra', 'input': {'assets': [{'id': 'host', 'settings': {}}], 'baseline': {'unexpected': True}}})
        with patch.object(host, 'connect') as connect, self.assertRaises(suite.Refusal):
            suite.run(data, network=host)
        connect.assert_not_called()

    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def host(self, **kwargs):
        return suite.NetworkHost([f'tcp://127.0.0.1:{self.port}', f'http://127.0.0.1:{self.port}'], **kwargs)

    def test_real_loopback_connect_and_http(self):
        host = self.host()
        result = suite.run(request('network', {'targets': [f'tcp://127.0.0.1:{self.port}']}), network=host)
        self.assertEqual(result['reports'][0]['summary']['observations'][0]['state'], 'open')
        self.assertEqual(host.fetch(f'http://127.0.0.1:{self.port}/')['body'], 'ok')

    def test_scope_redirect_credentials_and_active_refused(self):
        host = self.host()
        for target in (f'http://127.0.0.1:{self.port}/redirect',
                       f'http://user:secret@127.0.0.1:{self.port}/', 'http://192.0.2.1/'):
            with self.subTest(target=target), self.assertRaises(suite.Refusal):
                host.fetch(target)
        with self.assertRaises(suite.Refusal):
            host.fetch(f'http://127.0.0.1:{self.port}/', active=True)
        with self.assertRaises(suite.Refusal):
            suite.NetworkHost(['http://example.test'])
        with self.assertRaises(suite.Refusal):
            self.host(active='false')
        with self.assertRaises(suite.Refusal):
            host.fetch(f'http://127.0.0.1:{self.port}/?' + 'x' * 4096)

    def test_budget_is_total_and_timeouts_unmeasured(self):
        host = self.host(budget=1)
        url = f'http://127.0.0.1:{self.port}/'
        host.fetch(url)
        with self.assertRaises(suite.Refusal):
            host.fetch(url)
        host = self.host()
        with patch.object(suite.socket, 'create_connection', side_effect=TimeoutError):
            self.assertEqual(host.connect(f'tcp://127.0.0.1:{self.port}'), 'unmeasured')

    def test_all_targets_admitted_before_connect(self):
        host = self.host()
        with patch.object(host, 'connect') as connect, self.assertRaises(suite.Refusal):
            suite.run(request('network', {'targets': [f'tcp://127.0.0.1:{self.port}', 'tcp://192.0.2.1:22']}), network=host)
        connect.assert_not_called()

    def test_active_refusal_occurs_before_baseline_fetch(self):
        host = self.host()
        with patch.object(host, 'fetch') as fetch, self.assertRaises(suite.Refusal):
            suite.run(request('dast', {'target': f'http://127.0.0.1:{self.port}/?q=1', 'active': True}),
                      core=object(), network=host)
        fetch.assert_not_called()


if __name__ == '__main__':
    unittest.main()
