"""Validate the executable suite and emit its capability catalog separately."""
import hashlib
import json
import re
from pathlib import Path

RELATIVE = Path('skills/security/mithril-security-suite')
MATURITY = {'experimental', 'local-conformance', 'live-verified', 'production'}
VERIFICATION = {'unverified', 'unit', 'local-conformance', 'live-service'}
OPERATIONS = {'vm', 'cspm', 'dast', 'sast', 'sca', 'container', 'infra', 'network', 'templates', 'iac'}


def build(root):
    package = root / RELATIVE
    catalog = json.loads((package / 'capabilities.json').read_text())
    compiled = json.loads((package / 'compiled.json').read_text())
    hashes = {p.relative_to(package).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted((package / 'source').rglob('*.mith'))}
    if not hashes or compiled.get('sources') != hashes:
        raise ValueError('security Mithril source/compiled composition drift')
    if catalog.get('schemaVersion') != '1' or catalog.get('runtime') != 'mithril-security-suite/v1':
        raise ValueError('invalid security capability schema')
    if not re.fullmatch(r'\d+\.\d+\.\d+', catalog.get('version', '')):
        raise ValueError('invalid security capability version')
    compiler = compiled.get('compiler', {})
    if not re.fullmatch(r'[0-9a-f]{40}', compiler.get('commit', '')) or set(compiler.get('files', {})) != {'src/mithril/form.cljk', 'src/mithril/components.cljk', 'bin/mithril-components.cljk'}:
        raise ValueError('security compiler must be pinned')
    for value in compiler['files'].values():
        if not re.fullmatch(r'[0-9a-f]{64}', value):
            raise ValueError('invalid security compiler file digest')
    exports = compiled['composition']['exports']
    symbols = {e['symbol'] for e in exports if e['kind'] == 'mith:analyzer'}
    ops = catalog['operations']
    if len(ops) != len(OPERATIONS) or {op['id'] for op in ops} != OPERATIONS:
        raise ValueError('security operation ids must be unique and complete')
    if symbols != {op['symbol'] for op in ops}:
        raise ValueError('security operations differ from Mithril analyzer exports')
    for op in ops:
        if op['symbol'] != f"https://mithril.fund/lib/fund/mithril/security/{op['id']}/v1/analyzer/assess":
            raise ValueError('security operation symbol belongs to another domain')
        if op.get('engine') not in {'core', 'native'} or not op.get('gaps'):
            raise ValueError('security operation must declare engine and limitations')
        if op.get('maturity') not in MATURITY or op.get('verification') not in VERIFICATION:
            raise ValueError('unknown security maturity or verification')
        if op['maturity'] != 'experimental' and not op.get('tests'):
            raise ValueError('security maturity requires evidence')
        for path in op.get('tests', []):
            target = (root / path).resolve()
            if not target.is_relative_to(root.resolve()) or not target.is_file():
                raise ValueError('missing security test evidence')
        if op['maturity'] in {'live-verified', 'production'} or op['verification'] == 'live-service':
            raise ValueError('live security maturity requires a future dated receipt contract')
        if op['maturity'] == 'local-conformance' and op['verification'] != 'local-conformance':
            raise ValueError('local maturity must have local verification')
    if set(catalog.get('engines', {})) != {'security-core', 'vm', 'cspm', 'zap-proxy'}:
        raise ValueError('missing security engine identity')
    for spec in catalog['engines'].values():
        if not re.fullmatch(r'[0-9a-f]{40}', spec.get('commit', '')):
            raise ValueError('security engine must use an immutable commit')
    for path in ('runtime/suite.py', 'runtime/core.cljk', 'nbb.edn', 'contracts.md', 'SKILL.md'):
        if not (package / path).is_file():
            raise ValueError('security executable package is incomplete')
    return {**catalog, 'distribution': {'type': 'skill', 'id': 'mithril-security-suite',
                                       'path': RELATIVE.as_posix()},
            'policyDigest': hashlib.sha256(json.dumps(compiled, sort_keys=True,
                                                       separators=(',', ':')).encode()).hexdigest()}
