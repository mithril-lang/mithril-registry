#!/usr/bin/env python3
"""Build a deterministic source/evaluation ZIP with verified wheel inventory; no keys/data."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile
from email.parser import BytesParser
import re

ROOT = Path(__file__).resolve().parents[1]
PINS = {'cryptography':'50.0.2','cffi':'2.0.0','pycparser':'2.23','typing-extensions':'4.16.0'}

def sha(raw): return hashlib.sha256(raw).hexdigest()

def build(output, wheelhouse=None):
    output = Path(output)
    if output.exists(): raise ValueError('output_exists')
    files = {}
    for name in ('mithril-forensic-evidence','mithril-cybersecurity-products'):
        folder = ROOT/'skills/security'/name
        for path in sorted(folder.rglob('*')):
            if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc':
                if path.is_symlink(): raise ValueError('symlink_source')
                files[path.relative_to(ROOT).as_posix()] = path.read_bytes()
    for name in ('LICENSE','docs/security-integrations/agency-evaluation.md','docs/security-integrations/forensic-validation.md'):
        files[name] = (ROOT/name).read_bytes()
    components = []; installed = {}; locked = []
    if wheelhouse:
        for path in sorted(Path(wheelhouse).iterdir()):
            if path.is_symlink() or path.suffix != '.whl': raise ValueError('wheel_files_only')
            raw = path.read_bytes()
            if len(raw) > 32*1024*1024: raise ValueError('wheel_size_limit')
            with zipfile.ZipFile(path) as wheel:
                metadata = [n for n in wheel.namelist() if n.endswith('.dist-info/METADATA')]
                if len(metadata) != 1: raise ValueError('wheel_metadata')
                if wheel.getinfo(metadata[0]).file_size > 65536: raise ValueError('wheel_metadata_limit')
                info = BytesParser().parsebytes(wheel.read(metadata[0]))
            name = re.sub(r'[-_.]+','-',info['Name']).lower(); version = info['Version']
            if name not in PINS or version != PINS[name] or name in installed: raise ValueError('unexpected_wheel')
            installed[name] = version
            files['wheels/'+path.name] = raw
            locked.append(f'{name}=={version} --hash=sha256:{sha(raw)}')
            components.append(dict(type='library',name=name,version=version,purl=f'pkg:pypi/{name}@{version}',
                                   hashes=[dict(alg='SHA-256',content=sha(raw))],
                                   properties=[dict(name='mithril:wheel',value=path.name)]))
        if installed != PINS: raise ValueError('incomplete_wheelhouse')
        files['offline-requirements.txt'] = ('\n'.join(sorted(locked))+'\n').encode()
    else:
        components = [dict(type='library',name=k,version=v,purl=f'pkg:pypi/{k}@{v}') for k,v in PINS.items()]
    files['sbom.json'] = json.dumps(dict(bomFormat='CycloneDX',specVersion='1.5',version=1,components=components),sort_keys=True).encode()
    files['distribution.json'] = json.dumps(dict(schemaVersion=1,version='0.1.0',purpose='supervised-local-evaluation',
                                                offlineDependencies=bool(wheelhouse),publisherSignature='not-provided',
                                                sbomScope='Python-runtime-wheels-only-not-vendored-native-or-OS-components',
                                                files=[dict(path=n,bytes=len(v),sha256=sha(v)) for n,v in sorted(files.items())]),sort_keys=True).encode()
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('xb') as stream:
        with zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_DEFLATED) as archive:
            for name,raw in sorted(files.items()):
                entry = zipfile.ZipInfo(name,(2026,10,7,0,0,0)); entry.compress_type=zipfile.ZIP_DEFLATED
                entry.external_attr = 0o100644 << 16; archive.writestr(entry,raw)
    return dict(path=str(output),bytes=output.stat().st_size,sha256=sha(output.read_bytes()),offlineDependencies=bool(wheelhouse),publisherSignature='not-provided')

def main():
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--output',required=True); parser.add_argument('--wheelhouse')
    args=parser.parse_args(); print(json.dumps(build(args.output,args.wheelhouse)))

if __name__ == '__main__': main()
