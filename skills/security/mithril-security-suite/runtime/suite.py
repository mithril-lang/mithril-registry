"""Bounded, tenant-bound security operations admitted by compiled Mithril exports.

The caller's request never grants effects. Host policy is constructed separately.
Installed private engines are pinned and called via JSON stdin, never eval/shell.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote, urlsplit

PACKAGE = Path(__file__).resolve().parents[1]
MAX_BYTES = 2 * 1024 * 1024
MAX_ITEMS = 128
SEVERITIES = {'critical', 'high', 'medium', 'low', 'info'}


class Refusal(ValueError):
    pass


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False).encode()).hexdigest()


def bounded(value):
    if len(json.dumps(value).encode()) > MAX_BYTES:
        raise Refusal('input exceeds 2 MiB')
    if isinstance(value, list):
        if len(value) > MAX_ITEMS:
            raise Refusal('array exceeds 128 items')
        for item in value:
            bounded(item)
    elif isinstance(value, dict):
        if len(value) > MAX_ITEMS:
            raise Refusal('object exceeds 128 keys')
        for item in value.values():
            bounded(item)


def policy():
    compiled = json.loads((PACKAGE / 'compiled.json').read_text())
    actual = {p.relative_to(PACKAGE).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted((PACKAGE / 'source').rglob('*.mith'))}
    if compiled.get('sources') != actual:
        raise Refusal('Mithril source differs from compiled composition')
    catalog = json.loads((PACKAGE / 'capabilities.json').read_text())
    exports = {e['symbol'] for e in compiled['composition']['exports']}
    for op in catalog['operations']:
        if op['symbol'] not in exports:
            raise Refusal('operation is not exported by Mithril composition')
    return compiled, catalog


def objects(data, key):
    values = data.get(key)
    if not isinstance(values, list) or not values or not all(isinstance(x, dict) for x in values):
        raise Refusal(f'{key} must be a nonempty array of objects')
    return values


def finding(rule, asset, severity, evidence, remediation, line=None):
    if severity not in SEVERITIES:
        severity = 'info'
    asset = str(asset)
    if asset.startswith(('http://', 'https://')):
        parsed = urlsplit(asset)
        authority = parsed.hostname or ''
        if ':' in authority:
            authority = '[' + authority + ']'
        if parsed.port:
            authority += ':' + str(parsed.port)
        asset = f'{parsed.scheme}://{authority}{parsed.path}'
    result = {'rule': str(rule), 'asset': asset, 'severity': severity,
              'evidenceDigest': digest(evidence), 'remediation': remediation,
              'verdict': 'candidate'}
    if line is not None:
        result['line'] = line
    return result


class CoreHost:
    def __init__(self, root):
        self.root = Path(root).resolve()
        _, catalog = policy()
        for repo, spec in catalog['engines'].items():
            path = self.root / repo
            try:
                head = subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'],
                                               text=True, stderr=subprocess.DEVNULL).strip()
                dirty = subprocess.check_output(['git', '-C', str(path), 'status', '--porcelain'], text=True)
            except subprocess.CalledProcessError as exc:
                raise Refusal('required engine checkout is unavailable') from exc
            if head != spec['commit'] or dirty:
                raise Refusal(f'{repo} must be clean at its declared commit')
        self.classpath = ':'.join(str(self.root / repo / 'src')
                                  for repo in catalog['engines'])

    def assess(self, operation, data):
        result = subprocess.run(['kbb', '--backend', 'sci', '--classpath', self.classpath,
                                 str(PACKAGE / 'runtime/core.cljk')], cwd=PACKAGE,
                                input=json.dumps({'operation': operation, 'input': data}),
                                capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise Refusal('installed engine refused the request')
        if len(result.stdout.encode()) > 8 * MAX_BYTES:
            raise Refusal('installed engine output exceeds limit')
        try:
            response = json.loads(result.stdout)
        except ValueError as exc:
            raise Refusal('installed engine returned invalid JSON') from exc
        if response.get('ok') is False or (response.get('match') or {}).get('ok') is False:
            raise Refusal('installed engine refused the input contract')
        return response


class NetworkHost:
    """Operator-owned finite IP:port scope. No DNS, redirects, cookies or ambient proxy."""
    def __init__(self, endpoints, active=False, budget=64, timeout=3):
        if not isinstance(endpoints, list) or not endpoints or len(endpoints) > MAX_ITEMS:
            raise Refusal('operator must supply finite endpoint scope')
        self.endpoints = set()
        for endpoint in endpoints:
            if not isinstance(endpoint, str) or len(endpoint.encode()) > 4096:
                raise Refusal('invalid scoped endpoint')
            parsed = urlsplit(endpoint)
            if parsed.scheme not in ('http', 'https', 'tcp') or parsed.username or parsed.password:
                raise Refusal('invalid scoped endpoint')
            try:
                address = str(ipaddress.ip_address(parsed.hostname))
                port = parsed.port or {'http': 80, 'https': 443}.get(parsed.scheme)
            except ValueError as exc:
                raise Refusal('scope requires literal IP addresses') from exc
            if not isinstance(port, int) or not 1 <= port <= 65535:
                raise Refusal('scope requires a valid port')
            if parsed.path not in ('', '/') or parsed.query or parsed.fragment:
                raise Refusal('scope must name an origin')
            self.endpoints.add((parsed.scheme, address, port))
        if type(active) is not bool or type(budget) is not int or not 1 <= budget <= 128 or type(timeout) not in (int, float) or not 0 < timeout <= 10:
            raise Refusal('invalid host budget or timeout')
        self.active, self.remaining, self.timeout = active, budget, timeout

    def check(self, url, active=False):
        if not isinstance(url, str) or len(url.encode()) > 4096:
            raise Refusal('target URL exceeds 4 KiB')
        parsed = urlsplit(url)
        if parsed.username or parsed.password or parsed.fragment:
            raise Refusal('URL contains credentials or fragment')
        try:
            address = str(ipaddress.ip_address(parsed.hostname))
            port = parsed.port or {'http': 80, 'https': 443}.get(parsed.scheme)
        except ValueError as exc:
            raise Refusal('target must use a scoped literal IP') from exc
        if (parsed.scheme, address, port) not in self.endpoints:
            raise Refusal('target is outside operator scope')
        if active and not self.active:
            raise Refusal('active probing is not granted by operator policy')
        return parsed, address, port

    def admit(self, url, active=False):
        parsed, address, port = self.check(url, active)
        if self.remaining <= 0:
            raise Refusal('host request budget exhausted')
        self.remaining -= 1
        return parsed, address, port

    def connect(self, url):
        parsed, address, port = self.admit(url)
        if parsed.scheme != 'tcp' or parsed.path not in ('', '/') or parsed.query:
            raise Refusal('TCP target must name only an endpoint')
        try:
            with socket.create_connection((address, port), timeout=self.timeout):
                return 'open'
        except ConnectionRefusedError:
            return 'closed'
        except OSError:
            return 'unmeasured'

    def fetch(self, url, active=False):
        parsed, address, port = self.admit(url, active)
        if parsed.scheme not in ('http', 'https'):
            raise Refusal('HTTP probing requires an HTTP origin')
        cls = http.client.HTTPSConnection if parsed.scheme == 'https' else http.client.HTTPConnection
        connection = cls(address, port, timeout=self.timeout)
        try:
            path = quote(parsed.path or '/', safe='/%:@')
            if parsed.query:
                path += '?' + quote(parsed.query, safe='=&%')
            connection.request('GET', path, headers={'User-Agent': 'MithrilSecurity/0.1'})
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise Refusal('redirects require separate scoped observations')
            body = response.read(65537)
            if len(body) > 65536:
                raise Refusal('HTTP response exceeds 64 KiB')
            headers = {}
            for key, value in response.getheaders():
                headers.setdefault(key.lower(), []).append(value)
            return {'url': url, 'status': response.status, 'headers': headers,
                    'body': body.decode('utf-8', errors='replace')}
        finally:
            connection.close()


class PythonFlow(ast.NodeVisitor):
    """Conservative intraprocedural candidate analysis; no source execution."""
    def __init__(self, path):
        self.path, self.tainted, self.aliases, self.findings = path, set(), {}, []

    def name(self, node):
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return self.name(node.value) + '.' + node.attr
        return ''

    def is_tainted(self, node):
        for part in ast.walk(node):
            name = self.name(part)
            if isinstance(part, ast.Name) and part.id in self.tainted:
                return True
            if name.startswith(('request.args', 'request.form', 'request.json',
                                'request.GET', 'request.POST', 'request.query_params',
                                'flask.request.args', 'flask.request.form', 'flask.request.json')):
                return True
            if isinstance(part, ast.Call) and self.name(part.func) in ('input', 'flask.request.get_json'):
                return True
        return False

    def visit_Import(self, node):
        for item in node.names:
            self.aliases[item.asname or item.name] = item.name

    def visit_ImportFrom(self, node):
        for item in node.names:
            self.aliases[item.asname or item.name] = (node.module or '') + '.' + item.name

    def visit_FunctionDef(self, node):
        previous = self.tainted.copy()
        self.generic_visit(node)
        self.tainted = previous

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node):
        if self.is_tainted(node.value):
            for target in node.targets:
                self.tainted.update(x.id for x in ast.walk(target) if isinstance(x, ast.Name))
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        if self.is_tainted(node.value):
            self.tainted.update(x.id for x in ast.walk(node.target) if isinstance(x, ast.Name))
        self.generic_visit(node)

    def visit_Call(self, node):
        name = self.name(node.func)
        shell = any(k.arg == 'shell' and isinstance(k.value, ast.Constant)
                    and k.value.value is True for k in node.keywords)
        rule = None
        if name in ('eval', 'exec', 'builtins.eval', 'builtins.exec'):
            rule = 'python-tainted-eval'
        elif name in ('os.system', 'os.popen') or name.startswith('subprocess.') and shell:
            rule = 'python-tainted-shell'
        elif name.endswith('.execute'):
            rule = 'python-tainted-sql'
        if rule and node.args and self.is_tainted(node.args[0]):
            self.findings.append(finding(rule, self.path, 'high',
                {'line': node.lineno, 'sink': name},
                'Validate the dataflow; use parameterized SQL or avoid shell/eval.', node.lineno))
        self.generic_visit(node)


def sast(data):
    findings, gaps = [], []
    for file in objects(data, 'files'):
        path, content = file.get('path'), file.get('content')
        if not isinstance(path, str) or not isinstance(content, str):
            raise Refusal('source files require path and content strings')
        if not path.endswith('.py'):
            gaps.append({'asset': path, 'reason': 'unsupported-language'})
            continue
        try:
            tree = ast.parse(content)
        except SyntaxError:
            gaps.append({'asset': path, 'reason': 'syntax-error'})
            continue
        analyzer = PythonFlow(path)
        analyzer.visit(tree)
        findings.extend(analyzer.findings)
    return findings, gaps, {'analysis': 'intraprocedural-candidates'}


def infra(data):
    baseline = data.get('baseline')
    if not isinstance(baseline, dict) or not baseline:
        raise Refusal('nonempty baseline is required')
    supported = {'sshPasswordAuthentication', 'rootLogin', 'firewallEnabled', 'automaticUpdates'}
    if not set(baseline) <= supported or not all(type(v) is bool for v in baseline.values()):
        raise Refusal('baseline contains unsupported controls')
    findings, gaps = [], []
    for asset in objects(data, 'assets'):
        if not isinstance(asset.get('id'), str) or not isinstance(asset.get('settings'), dict):
            raise Refusal('asset requires id and settings')
        for control, expected in baseline.items():
            actual = asset['settings'].get(control)
            if type(actual) is not bool:
                gaps.append({'asset': asset['id'], 'reason': 'unmeasured-' + control})
            elif actual != expected:
                findings.append(finding('baseline-' + control, asset['id'], 'medium',
                                        {'observed': actual, 'expected': expected},
                                        'Apply the declared baseline after reviewing host impact.'))
    return findings, gaps, {'controls': sorted(baseline)}


def templates(data):
    selected = data.get('rules', ['content-type-options', 'content-security-policy'])
    known = {'content-type-options': 'x-content-type-options',
             'content-security-policy': 'content-security-policy'}
    if not isinstance(selected, list) or not selected or not set(selected) <= set(known):
        raise Refusal('unknown or empty template selection')
    findings = []
    for response in objects(data, 'responses'):
        headers = response.get('headers')
        if not isinstance(headers, dict) or not isinstance(response.get('url'), str):
            raise Refusal('response requires URL and headers')
        headers = {k.lower(): v for k, v in headers.items()}
        for rule in selected:
            value = headers.get(known[rule])
            values = value if isinstance(value, list) else [value]
            if not value or rule == 'content-type-options' and not any(
                    isinstance(v, str) and v.lower() == 'nosniff' for v in values):
                findings.append(finding('http-' + rule, response['url'], 'low',
                                        {'header': known[rule], 'present': bool(value)},
                                        'Review and configure the response security header.'))
    return findings, [], {'templates': sorted(set(selected))}


def iac(data):
    findings, gaps = [], []
    for file in objects(data, 'files'):
        path, content = file.get('path'), file.get('content')
        if not isinstance(path, str) or not isinstance(content, str):
            raise Refusal('files require path and content')
        for number, line in enumerate(content.splitlines(), 1):
            if re.search(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bAKIA[A-Z0-9]{16}\b', line):
                findings.append(finding('secret-material-candidate', path, 'high',
                                        {'line': number, 'fileDigest': digest(content)},
                                        'Review the candidate; revoke exposed credentials and remove material.', number))
        if not path.endswith('.json'):
            gaps.append({'asset': path, 'reason': 'IaC parser supports JSON only'})
            continue
        try:
            config = json.loads(content)
        except ValueError:
            gaps.append({'asset': path, 'reason': 'invalid-JSON'})
            continue
        if not isinstance(config, dict):
            raise Refusal('IaC JSON must be an object')
        measured = False
        if config.get('kind') == 'Pod':
            measured = True
            for container in config.get('spec', {}).get('containers', []):
                if container.get('securityContext', {}).get('privileged') is True:
                    findings.append(finding('kubernetes-privileged-container', path, 'high',
                                            {'container': container.get('name')},
                                            'Remove privileged mode or document a constrained exception.'))
        for group in config.get('resource', {}).get('aws_security_group', {}).values():
            measured = True
            for ingress in group.get('ingress', []):
                if '0.0.0.0/0' in ingress.get('cidr_blocks', []) or '::/0' in ingress.get('ipv6_cidr_blocks', []):
                    low, high = ingress.get('from_port'), ingress.get('to_port')
                    if ingress.get('protocol') == '-1' or isinstance(low, int) and isinstance(high, int) and any(low <= p <= high for p in (22, 3389)):
                        findings.append(finding('terraform-public-admin-ingress', path, 'high',
                                                {'ports': [low, high]},
                                                'Restrict administrative ingress to approved networks.'))
        if not measured:
            gaps.append({'asset': path, 'reason': 'no-supported-resource-types'})
    return findings, gaps, {'formats': ['Terraform JSON', 'Kubernetes Pod JSON'],
                            'secrets': 'candidate-patterns; values are never returned'}


def normalize_core(operation, result):
    findings, gaps = [], []
    match = result.get('match') if operation in ('sca', 'container') else result if operation == 'vm' else None
    if match:
        for component in match.get('components', []):
            for vuln in component.get('vulnerabilities', []):
                findings.append(finding(vuln.get('advisory/id', 'advisory'), component['purl'],
                                        vuln.get('advisory/severity', 'info'),
                                        vuln, 'Review the advisory and apply a supported fixed version.'))
            if component.get('verdict') == 'undecided':
                gaps.append({'asset': component['purl'], 'reason': 'version-match-undecided'})
        for kind, values in match.get('unparsed', {}).items():
            if values:
                gaps.append({'reason': 'unparsed-' + kind, 'count': len(values)})
    inventory = result.get('inventory', {})
    for key in ('manifest/gaps', 'image/gaps'):
        for gap in inventory.get(key, []):
            gaps.append({'reason': 'inventory-gap', 'evidenceDigest': digest(gap)})
    if operation in ('sca', 'container') and not match:
        gaps.append({'reason': 'no-components-matched'})
    if operation == 'cspm':
        for f in result.get('findings', []):
            findings.append(finding(f.get('finding/rule', f.get('rule', 'cloud-posture')),
                                    f.get('finding/resource', 'cloud-resource'),
                                    f.get('finding/severity', f.get('severity', 'medium')), f,
                                    f.get('finding/remediation', 'Review the cloud posture rule remediation.')))
            findings[-1]['priority'] = f.get('finding/score', 0)
        if result.get('coverage'):
            gaps.append({'reason': 'provider-and-rule-coverage', 'coverage': result['coverage']})
        if result.get('inventory', {}).get('errors'):
            gaps.append({'reason': 'invalid-cloud-resources', 'count': len(result['inventory']['errors'])})
    if operation in ('dast', 'dast-probes'):
        for f in result.get('findings', []):
            findings.append(finding(f.get('rule-id', 'web-rule'), f.get('url', 'web-response'),
                                    f.get('severity', 'info'), f,
                                    f.get('solution', 'Review and remediate the observed Web weakness.')))
            findings[-1]['location'] = f.get('param') or f.get('title', '')
    summary = {'advisoryScope': 'caller-supplied-only'} if match else {}
    if match:
        summary['suppressedByVex'] = len(match.get('suppressed', []))
    if operation == 'cspm':
        summary['attackPaths'] = result.get('attackPaths', {})
    if operation == 'container':
        gaps.append({'reason': 'extracted-files-only; image digest and layer verification not performed'})
    return findings, gaps, summary


def run(request, core=None, network=None):
    bounded(request)
    if not isinstance(request, dict) or set(request) != {'schemaVersion', 'tenant', 'operations'} or request['schemaVersion'] != '1':
        raise Refusal('unknown or missing request field')
    if not isinstance(request['tenant'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', request['tenant']):
        raise Refusal('tenant must be a bounded opaque identifier')
    operations = objects(request, 'operations')
    if len(operations) > 10 or len({o.get('id') for o in operations}) != len(operations):
        raise Refusal('operation ids must be unique and bounded')
    compiled, catalog = policy()
    admitted = {o['id']: o for o in catalog['operations']}
    for operation in operations:
        if set(operation) != {'id', 'input'} or operation['id'] not in admitted or not isinstance(operation['input'], dict):
            raise Refusal('unknown operation or input contract')
        if admitted[operation['id']]['engine'] == 'core' and core is None:
            raise Refusal('operation requires the explicitly installed pinned core')
        if operation['id'] == 'network' and network is None:
            raise Refusal('network operation requires operator-owned scope')
        validate_input(operation['id'], operation['input'], network)
    # Validate/compute every pure operation before initiating an external effect.
    prepared, plans, effect_count = {}, {}, 0
    for operation in operations:
        name, data = operation['id'], operation['input']
        if name in ('sast', 'infra', 'templates', 'iac'):
            prepared[name] = globals()[name](data)
        elif name == 'network':
            effect_count += len(data['targets'])
        elif name == 'dast' and 'target' in data:
            effect_count += 1
            if data.get('active'):
                plans[name] = core.assess('dast-plan', {'url': data['target']})['requests']
                for url in plans[name]:
                    network.check(url, True)
                effect_count += len(plans[name])
        else:
            prepared[name] = normalize_core(name, core.assess(name, data))
    if network is not None and effect_count > network.remaining:
        raise Refusal('host request budget is too small for the complete request')
    reports = []
    for operation in operations:
        name, data = operation['id'], operation['input']
        if name in ('sast', 'infra', 'templates', 'iac'):
            findings, gaps, summary = prepared[name]
        elif name == 'network':
            targets = data.get('targets')
            if not isinstance(targets, list) or not targets or not all(isinstance(t, str) for t in targets):
                raise Refusal('targets must be a finite URL list')
            observations = [{'target': target, 'state': network.connect(target)} for target in targets]
            findings = [finding('open-tcp-port', o['target'], 'info', o,
                                'Confirm that this listening service is intended.')
                        for o in observations if o['state'] == 'open']
            gaps = [{'asset': o['target'], 'reason': 'connection-unmeasured'}
                    for o in observations if o['state'] == 'unmeasured']
            summary = {'observations': observations}
        else:
            if name == 'dast' and 'target' in data:
                if network is None:
                    raise Refusal('live DAST requires operator-owned scope')
                baseline = network.fetch(data['target'])
                result = core.assess('dast', {'responses': [baseline]})
                findings, gaps, summary = normalize_core(name, result)
                if data.get('active') is True:
                    if not network.active:
                        raise Refusal('active DAST is not granted')
                    urls = plans[name]
                    if not urls:
                        gaps.append({'reason': 'no-query-parameters-for-active-probes'})
                    probes = {url: network.fetch(url, active=True) for url in urls}
                    result = core.assess('dast-probes', {'url': data['target'],
                                        'baseline': baseline['body'], 'probes': probes})
                    active_findings, active_gaps, _ = normalize_core('dast-probes', result)
                    findings += active_findings
                    gaps += active_gaps
                summary['transport'] = 'operator-scoped-literal-IP'
            else:
                findings, gaps, summary = prepared[name]
        for item in findings:
            item['operation'] = name
            item['id'] = digest({'tenant': request['tenant'], 'operation': name,
                                 'rule': item['rule'], 'asset': item['asset'], 'line': item.get('line'),
                                 'location': item.get('location')})
        findings = sorted({f['id']: f for f in findings}.values(), key=lambda f: f['id'])
        reports.append({'operation': name, 'symbol': admitted[name]['symbol'],
                        'findings': findings, 'gaps': gaps, 'summary': summary,
                        'coverage': 'partial', 'limitations': admitted[name]['gaps']})
    return {'schemaVersion': '1', 'tenant': request['tenant'], 'inputDigest': digest(request),
            'policyDigest': digest(compiled), 'reports': reports,
            'status': 'evaluated-with-limits', 'productionVerified': False}


def validate_input(name, data, network):
    fields = {'vm': {'components', 'sbom', 'advisories', 'vex'},
              'cspm': {'resources', 'provider', 'account', 'region', 'responses'},
              'dast': {'responses', 'target', 'active'}, 'sast': {'files'},
              'sca': {'files', 'advisories', 'vex'},
              'container': {'extracted', 'os-release', 'unreadable-layers', 'advisories', 'vex'},
              'infra': {'assets', 'baseline'}, 'network': {'targets'},
              'templates': {'responses', 'rules'}, 'iac': {'files'}}
    if not set(data) <= fields[name] or not data:
        raise Refusal('unknown or empty operation input')
    if 'files' in fields[name]:
        for file in objects(data, 'files'):
            if set(file) != {'path', 'content'} or not all(isinstance(v, str) for v in file.values()):
                raise Refusal('files require only path and content strings')
            if len(file['content'].encode()) > 65536:
                raise Refusal('source file exceeds 64 KiB')
    if name == 'network':
        targets = data.get('targets')
        if not isinstance(targets, list) or not targets or not all(isinstance(t, str) for t in targets):
            raise Refusal('targets must be URL strings')
        for target in targets:
            parsed, _, _ = network.check(target)
            if parsed.scheme != 'tcp' or parsed.path not in ('', '/') or parsed.query:
                raise Refusal('TCP target must name an endpoint')
    if name == 'dast':
        if 'target' in data:
            if set(data) - {'target', 'active'} or not isinstance(data['target'], str) or network is None:
                raise Refusal('live DAST requires only target and optional active flag')
            if 'active' in data and type(data['active']) is not bool:
                raise Refusal('active must be boolean')
            parsed, _, _ = network.check(data['target'], data.get('active', False))
            if parsed.scheme not in ('http', 'https'):
                raise Refusal('DAST requires HTTP')
        else:
            if set(data) != {'responses'}:
                raise Refusal('offline DAST requires only responses')
            for response in objects(data, 'responses'):
                if set(response) != {'url', 'status', 'headers', 'body'} or not isinstance(response['url'], str) or not isinstance(response['body'], str) or not isinstance(response['headers'], dict) or type(response['status']) is not int:
                    raise Refusal('invalid observed HTTP response')
    if name in ('vm', 'sca', 'container') and not isinstance(data.get('advisories'), list):
        raise Refusal('caller-supplied advisory array is required')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('request', type=Path)
    parser.add_argument('--engine-root', type=Path)
    parser.add_argument('--scope', type=Path, help='operator-owned JSON; not part of the scan request')
    args = parser.parse_args()
    try:
        if args.request.stat().st_size > MAX_BYTES:
            raise Refusal('input exceeds 2 MiB')
        request = json.loads(args.request.read_text())
        core = CoreHost(args.engine_root) if args.engine_root else None
        network = NetworkHost(**json.loads(args.scope.read_text())) if args.scope else None
        print(json.dumps(run(request, core, network), indent=2))
    except (ValueError, OSError, subprocess.SubprocessError, TypeError, KeyError, RecursionError) as exc:
        # No input strings, response bodies, credential values or upstream errors in refusal receipts.
        print(json.dumps({'ok': False, 'error': type(exc).__name__, 'reason': 'request-refused'}))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
