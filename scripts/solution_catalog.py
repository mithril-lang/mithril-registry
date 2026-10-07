"""Role-based discovery; a solution is not an executable registry entry."""
import json
import re
from pathlib import Path


def build(root: Path, entry_ids=None):
    data = json.loads((root / 'solutions/agency.json').read_text())
    if data.get('schemaVersion') != 1:
        raise ValueError('unsupported solution schema')
    solutions, profiles = data['solutions'], data['botProfiles']
    solution_ids = [s['id'] for s in solutions]
    profile_ids = [p['id'] for p in profiles]
    if len(set(solution_ids)) != len(solution_ids) or len(set(profile_ids)) != len(profile_ids):
        raise ValueError('duplicate solution or profile')
    for value in solution_ids + profile_ids:
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', value):
            raise ValueError('invalid portable id')
    for s in solutions:
        if s['status'] not in ('planned', 'local-evaluation') or s['blog']['status'] != 'brief-only':
            raise ValueError('unqualified availability or publication')
        if s['status'] == 'planned' and s['registryEntries']:
            raise ValueError('planned modules must not advertise executable entries')
        if entry_ids is not None and not set(s['registryEntries']) <= set(entry_ids):
            raise ValueError('unknown registry entry')
        matched = [p['id'] for p in profiles if p['solutionId'] == s['id']]
        if sorted(matched) != sorted(s['contactProfileIds']) or not matched:
            raise ValueError('profile routing mismatch')
        if s['blog']['audience'] != s['id']:
            raise ValueError('blog audience mismatch')
    for p in profiles:
        if p['solutionId'] not in solution_ids or set(p) != {'id', 'solutionId', 'persona', 'name', 'instructions', 'userContext'}:
            raise ValueError('invalid contact profile')
        if len(p['instructions']) > 16000 or len(p['name']) > 80:
            raise ValueError('profile exceeds Desktop limits')
    return data


def document(solution, profiles):
    contacts = [p for p in profiles if p['solutionId'] == solution['id']]
    return '\n'.join([
        '# ' + solution['title']['ja'], '',
        'Generated role brief from solutions/agency.json. Needs are planning hypotheses; agency adoption is unverified.', '',
        '| 項目 | 定義 |', '| --- | --- |',
        *[f'| {label} | {solution[key]} |' for label, key in [('対象部門','targetOrganization'),('担当者','persona'),('ニーズ','needs'),('入力','inputs'),('提供区分','status'),('現在の範囲','available'),('追加が必要','gaps'),('判断の境界','guardrail'),('合否条件','acceptance')]], '',
        '## Registry', '',
        'Existing entry IDs: ' + (', '.join(solution['registryEntries']) or 'none; planned domain module is not installable.') + '', '',
        '## 窓口 profiles', '',
        *[f'- `{p["id"]}` — {p["name"]} / {p["persona"]}' for p in contacts], '',
        '## Blog targeting', '',
        'Audience: `' + solution['blog']['audience'] + '`. Brief only; no published article claimed.', '',
        '記事案: ' + solution['blog']['topic'], '',
        'CTA: ' + solution['blog']['cta'], '',
    ])
