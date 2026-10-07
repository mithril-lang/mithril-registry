#!/usr/bin/env python3
"""Install reviewed contact profiles into an explicit native Hermes home.

No credentials, channels, cron jobs, active-profile selection or tool grants
are copied. Existing profiles are never overwritten, even on a partial run.
"""
import argparse
import json
import os
from pathlib import Path
from solution_catalog import build


def install(root, home, apply=False):
    data = build(root)
    home = Path(home).expanduser()
    if not home.is_absolute() or home.is_symlink():
        raise ValueError('use an absolute, non-symlink Hermes home')
    directory = home / 'profiles'
    if directory.is_symlink():
        raise ValueError('profiles directory must not be a symlink')
    # Reject existing files/symlinks before making any changes; idempotent reruns
    # accept byte-identical generated files only, and never touch user additions.
    plan = []
    for p in data['botProfiles']:
        target = directory / p['id']
        files = {
            'SOUL.md': p['instructions'] + '\n',
            'profile-meta.json': json.dumps({'name': p['name']}, ensure_ascii=False, indent=2) + '\n',
            'contact.json': json.dumps({'id': p['id'], 'solutionId': p['solutionId'], 'persona': p['persona'], 'catalogVersion': data['version']}, ensure_ascii=False, indent=2) + '\n',
            'config.yaml': '# Contact assistant. Configure an approved provider separately.\ngateway:\n  standalone: true\n',
            'profile.yaml': json.dumps({'display_name': p['name'], 'description': p['persona'] + ' / ' + p['solutionId'], 'description_auto': False, 'ui_meta': {'hermes-bots': {'title': p['name']}}}, ensure_ascii=False, indent=2) + '\n',
        }
        if target.is_symlink() or (target.exists() and not target.is_dir()):
            raise ValueError('unsafe profile destination')
        for name, value in files.items():
            f = target / name
            if f.is_symlink() or (f.exists() and (not f.is_file() or f.read_text() != value)):
                raise ValueError(f'preserving existing profile: {p["id"]}/{name}')
        plan.append((target, files))
    if apply:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        for target, files in plan:
            target.mkdir(exist_ok=True, mode=0o700)
            for name, value in files.items():
                f = target / name
                if not f.exists():
                    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, 'w') as stream:
                        stream.write(value)
    return {'applied': apply, 'profiles': [p['id'] for p in data['botProfiles']]}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    print(json.dumps(install(Path(__file__).resolve().parents[1], args.home, args.apply), indent=2))
