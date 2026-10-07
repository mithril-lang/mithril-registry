#!/usr/bin/env python3
"""Standalone verifier: no collector, model, workspace policy or private key needed."""
import argparse
import json
from pathlib import Path
import re
from format import MAX_FILE, MAX_TOTAL, Refusal, canonical, checked_dir, decode, digest, identifier, read_file, unseal

def verify(package, trusted_key, expected_case=None):
    root = checked_dir(package)
    envelope = decode(read_file(root / 'manifest.json', 262144))
    manifest = unseal(envelope, trusted_key)
    if (not isinstance(manifest, dict) or manifest.get('schema') != 'mithril-evidence-package-v1'
            or manifest.get('canonicalization') != 'python-json-sort-ascii-v1'):
        raise Refusal('unsupported_manifest')
    identifier(manifest['caseId']); identifier(manifest['evidenceId'])
    if expected_case is not None and manifest['caseId'] != expected_case: raise Refusal('different_case')
    entries = manifest['files']
    if not isinstance(entries, list) or not 1 <= len(entries) <= 64: raise Refusal('inventory_limit')
    expected = {'manifest.json'}; total = 0; inventory = {}
    for item in entries:
        if not isinstance(item, dict) or set(item) != {'path','bytes','sha256','kind'}:
            raise Refusal('invalid_inventory')
        name = item['path']
        if not isinstance(name, str) or not re.fullmatch(r'payload/[0-9]{2}/(?:source|findings|receipt-claims)\.json', name):
            raise Refusal('invalid_inventory_path')
        if name in expected: raise Refusal('duplicate_inventory_path')
        expected.add(name)
        kind = {'source.json':'original-bytes','findings.json':'recomputed-vendor-claims','receipt-claims.json':'unsigned-operator-receipt-claims'}[name.rsplit('/',1)[1]]
        if item['kind'] != kind: raise Refusal('invalid_inventory_kind')
        inventory[name] = item
        path = root / name
        checked_dir(path.parent)
        raw = read_file(path, MAX_FILE)
        if type(item['bytes']) is not int or item['bytes'] != len(raw) or item['sha256'] != digest(raw):
            raise Refusal('payload_integrity_failed')
        total += len(raw)
        if total > MAX_TOTAL: raise Refusal('package_size_limit')
    observations = manifest.get('observations')
    if not isinstance(observations, list) or not 1 <= len(observations) <= 16 or len(entries) != 3*len(observations):
        raise Refusal('invalid_observations')
    for index, observation in enumerate(observations):
        original = f'payload/{index:02d}/source.json'; findings = f'payload/{index:02d}/findings.json'
        if (not isinstance(observation, dict) or observation.get('originalPath') != original
                or observation.get('findingsPath') != findings or original not in inventory or findings not in inventory
                or f'payload/{index:02d}/receipt-claims.json' not in inventory
                or observation.get('sourceSha256') != inventory[original]['sha256']
                or observation.get('coverage') != 'incomplete-or-unknown'):
            raise Refusal('invalid_observation_binding')
    actual = set()
    for index, path in enumerate(root.rglob('*')):
        if index >= 128: raise Refusal('package_entry_limit')
        if path.is_symlink(): raise Refusal('symlink_payload')
        if path.is_file(): actual.add(path.relative_to(root).as_posix())
        elif not path.is_dir(): raise Refusal('unexpected_payload_type')
    if actual != expected: raise Refusal('inventory_mismatch')
    return dict(status='verified', caseId=manifest['caseId'], evidenceId=manifest['evidenceId'],
                manifestSha256=digest(read_file(root / 'manifest.json', 262144)), files=len(entries), bytes=total,
                keyId=envelope['keyId'], authenticity='operator-signed-package-not-vendor-attestation',
                coverage='incomplete-or-unknown', custody='verify-separately-with-external-checkpoint')

def verify_custody(ledger, trusted_key, expected_case, checkpoint=None):
    identifier(expected_case)
    envelopes = [decode(line) for line in read_file(ledger, MAX_FILE).splitlines()]
    if not 1 <= len(envelopes) <= 1000: raise Refusal('custody_limit')
    previous = None
    for index, envelope in enumerate(envelopes):
        value = unseal(envelope, trusted_key)
        if (value.get('schema') != 'mithril-custody-v1' or value.get('caseId') != expected_case
                or value.get('sequence') != index+1 or value.get('previousSha256') != previous):
            raise Refusal('custody_chain_failed')
        if index == 0 and value.get('action') != 'case-create': raise Refusal('custody_genesis_failed')
        previous = digest(canonical(envelope))
    count = 0
    if checkpoint is not None:
        anchor = unseal(decode(read_file(checkpoint, 16384)), trusted_key)
        count = anchor.get('count')
        if (anchor.get('schema') != 'mithril-custody-checkpoint-v1' or anchor.get('caseId') != expected_case
                or type(count) is not int or not 1 <= count <= len(envelopes)
                or anchor.get('tailSha256') != digest(canonical(envelopes[count-1]))):
            raise Refusal('external_checkpoint_mismatch')
    return dict(status='verified', caseId=expected_case, events=len(envelopes), anchoredEvents=count,
                unanchoredEvents=len(envelopes)-count, checkpointState='matched-prefix' if count else 'unanchored-local-chain',
                authenticity='institutional-signature-not-actor-identity-or-action-attestation')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', nargs='?'); parser.add_argument('--trusted-key', required=True)
    parser.add_argument('--case'); parser.add_argument('--custody'); parser.add_argument('--checkpoint')
    args = parser.parse_args()
    try:
        if args.custody:
            if args.package or not args.case: raise Refusal('custody_case_required')
            result = verify_custody(args.custody, args.trusted_key, args.case, args.checkpoint)
        else:
            if not args.package or args.checkpoint: raise Refusal('package_required')
            result = verify(args.package, args.trusted_key, args.case)
        print(json.dumps(result))
    except Exception:
        print(json.dumps(dict(status='refused', reason='verification_failed')))
        raise SystemExit(1)

if __name__ == '__main__': main()
