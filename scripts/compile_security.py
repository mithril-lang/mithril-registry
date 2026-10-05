"""Compile the suite with the existing Mithril Form/component admission path."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'skills/security/mithril-security-suite'


def source_hashes():
    return {p.relative_to(PACKAGE).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted((PACKAGE / 'source').rglob('*.mith'))}


def compile_suite(compiler_root):
    compiler_root = compiler_root.resolve()
    subprocess.run(['git', '-C', str(compiler_root), 'diff', '--exit-code', 'HEAD', '--',
                    'src/mithril/form.cljk', 'src/mithril/components.cljk',
                    'bin/mithril-components.cljk'], check=True, capture_output=True)
    result = subprocess.run(
        ['kbb', '--backend', 'sci', '--classpath', 'src',
         'bin/mithril-components.cljk', str(PACKAGE / 'source/lib'),
         str(PACKAGE / 'source/suite.mith')], cwd=compiler_root,
        capture_output=True, text=True, check=True, timeout=60)
    return {'schemaVersion': '1', 'kind': 'mithril-security-composition/v1',
            'sources': source_hashes(),
            'compiler': {'commit': subprocess.check_output(
                ['git', '-C', str(compiler_root), 'rev-parse', 'HEAD'], text=True).strip(),
                'files': {p: hashlib.sha256((compiler_root / p).read_bytes()).hexdigest()
                          for p in ['src/mithril/form.cljk', 'src/mithril/components.cljk',
                                    'bin/mithril-components.cljk']}},
            'composition': json.loads(result.stdout)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--compiler-root', required=True, type=Path)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    value = json.dumps(compile_suite(args.compiler_root), indent=2, sort_keys=True) + '\n'
    target = PACKAGE / 'compiled.json'
    if args.check:
        if target.read_text() != value:
            raise SystemExit('security composition is stale')
    else:
        target.write_text(value)
