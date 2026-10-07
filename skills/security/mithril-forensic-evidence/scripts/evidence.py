#!/usr/bin/env python3
"""Local, policy-scoped evidence operations. No network or remote identity claim."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from format import VERSION, Refusal, canonical, checked_dir, decode, digest, identifier, read_file, seal, unseal, write_new
from verify import verify

ROLE_ACTIONS = {
    'reviewer': {'inventory','verify','custody','checkpoint','report-approve'},
    'analyst': {'inventory','verify','custody','checkpoint','pack','report'},
    'custodian': {'inventory','verify','custody','checkpoint','case-create','transfer','hold'},
}
ROLE_ACTIONS['supervisor'] = set().union(*ROLE_ACTIONS.values())
SCHEMAS = {
    'case-create': ({'caseId','purpose'}, set()),
    'pack': ({'caseId','evidenceId','runs','authorityRef'}, set()),
    'verify': ({'caseId','evidenceId'}, set()),
    'inventory': ({'caseId'}, set()),
    'custody': ({'caseId'}, {'checkpoint'}),
    'checkpoint': ({'caseId'}, set()),
    'transfer': ({'caseId','evidenceId','recipient','reason'}, set()),
    'hold': ({'caseId','active','reason'}, set()),
    'report': ({'caseId','reportId','evidenceIds','question'}, set()),
    'report-approve': ({'caseId','reportId','notes'}, set()),
}

def utc(): return datetime.now(timezone.utc).isoformat()

def bounded_text(value, maximum=1024):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise Refusal('invalid_text')
    return value

def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)

def replace_private(path, raw):
    fd, temporary = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path); sync_dir(path.parent)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)

class Workspace:
    def __init__(self, policy_path, principal):
        policy_path = Path(policy_path)
        if policy_path.stat().st_mode & 0o022: raise Refusal('writable_policy')
        policy = decode(read_file(policy_path, 32768))
        if not isinstance(policy, dict) or set(policy) - {'schemaVersion','workspace','trustedKey','signingKey','grants'} or type(policy.get('schemaVersion')) is not int or policy.get('schemaVersion') != 1:
            raise Refusal('invalid_policy')
        self.principal = identifier(principal)
        self.grant = policy['grants'].get(principal)
        if (not isinstance(self.grant, dict) or set(self.grant) != {'role','cases','inputRoots'}
                or self.grant['role'] not in ROLE_ACTIONS or not isinstance(self.grant['cases'], list)):
            raise Refusal('principal_not_granted')
        for case in self.grant['cases']: identifier(case)
        self.inputs = self.grant['inputRoots']
        if not isinstance(self.inputs, dict) or set(self.inputs) - set(self.grant['cases']): raise Refusal('invalid_input_roots')
        for roots in self.inputs.values():
            if not isinstance(roots, list) or not all(isinstance(x, str) and Path(x).is_absolute() for x in roots):
                raise Refusal('invalid_input_roots')
            for root in roots: checked_dir(root)
        self.root = checked_dir(policy['workspace'])
        checked_dir(policy_path.absolute().parent)
        if policy_path.absolute().is_relative_to(self.root): raise Refusal('policy_must_be_external')
        if self.root.stat().st_mode & 0o077 or self.root.stat().st_uid != os.getuid():
            raise Refusal('private_workspace_required')
        self.trusted = Path(policy['trustedKey']).absolute()
        self.signing = Path(policy['signingKey']).absolute() if policy.get('signingKey') else None
        checked_dir(self.trusted.parent)
        if self.signing: checked_dir(self.signing.parent)
        for path in (self.trusted, self.signing):
            if path and path.is_relative_to(self.root): raise Refusal('keys_must_be_external')
        # Capture a trust pin; replacing an external key during a session is not a rotation.
        self.trust_pin = digest(read_file(self.trusted, 32))

    @contextmanager
    def locked(self):
        fd = os.open(self.root / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'rb+') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            if digest(read_file(self.trusted, 32)) != self.trust_pin: raise Refusal('trust_pin_changed')
            yield

    def sign(self, value):
        if not self.signing: raise Refusal('signing_key_required')
        return seal(value, self.signing, self.trusted)

    def case(self, case_id):
        path = checked_dir(self.root / identifier(case_id))
        header = unseal(decode(read_file(path / 'case.json', 16384)), self.trusted)
        if header.get('caseId') != case_id or header.get('schema') != 'mithril-case-v1': raise Refusal('case_integrity_failed')
        return path

    def events(self, case):
        raw = read_file(case / 'custody.jsonl', 8 * 1024 * 1024)
        envelopes = [decode(line) for line in raw.splitlines()]
        if not envelopes or len(envelopes) > 1000: raise Refusal('custody_limit')
        previous = None; values = []
        for index, envelope in enumerate(envelopes):
            value = unseal(envelope, self.trusted)
            if (value.get('caseId') != case.name or value.get('sequence') != index + 1
                    or value.get('previousSha256') != previous or value.get('schema') != 'mithril-custody-v1'):
                raise Refusal('custody_chain_failed')
            previous = digest(canonical(envelope)); values.append(value)
        if values[0]['action'] != 'case-create': raise Refusal('custody_genesis_failed')
        return envelopes, values

    def append(self, case, action, details):
        envelopes, _ = self.events(case) if (case / 'custody.jsonl').exists() else ([], [])
        if len(envelopes) >= 1000: raise Refusal('custody_limit')
        previous = digest(canonical(envelopes[-1])) if envelopes else None
        value = dict(schema='mithril-custody-v1', caseId=case.name, sequence=len(envelopes)+1,
                     previousSha256=previous, action=action, actorClaim=self.principal, at=utc(), details=details)
        envelope = self.sign(value)
        replace_private(case / 'custody.jsonl', b'\n'.join(canonical(x) for x in [*envelopes, envelope])+b'\n')

    def package(self, case, evidence_id):
        path = checked_dir(case / 'evidence' / identifier(evidence_id))
        result = verify(path, self.trusted, case.name)
        if result['evidenceId'] != evidence_id: raise Refusal('different_evidence')
        _, values = self.events(case)
        if not any(v['action'] == 'pack' and v['details'].get('evidenceId') == evidence_id
                   and v['details'].get('manifestSha256') == result['manifestSha256'] for v in values):
            raise Refusal('package_not_registered')
        return path, result

    def execute(self, operation, args):
        if operation not in SCHEMAS or not isinstance(args, dict): raise Refusal('invalid_operation')
        required, optional = SCHEMAS[operation]
        if not required <= set(args) or set(args) - required - optional: raise Refusal('invalid_arguments')
        case_id = identifier(args['caseId'])
        if case_id not in self.grant['cases'] or operation not in ROLE_ACTIONS[self.grant['role']]:
            raise Refusal('access_denied')
        with self.locked():
            if operation == 'case-create': return self.create(case_id, bounded_text(args['purpose']))
            case = self.case(case_id)
            if operation == 'pack': return self.attempt(case, operation, lambda: self.pack(case, args))
            if operation == 'verify': return self.package(case, args['evidenceId'])[1]
            if operation == 'inventory':
                packages = checked_dir(case / 'evidence')
                names = sorted(p.name for p in packages.iterdir())
                if len(names) > 16: raise Refusal('case_package_limit')
                _, events = self.events(case)
                registered = {event['details']['evidenceId'] for event in events if event['action'] == 'pack'}
                if set(names) != registered: raise Refusal('registered_package_inventory_mismatch')
                return dict(caseId=case_id, packages=[self.package(case, name)[1] for name in names])
            envelopes, values = self.events(case)
            if operation == 'custody':
                state = 'unanchored-local-chain'
                anchor_count = 0
                if 'checkpoint' in args:
                    checkpoint = unseal(args['checkpoint'], self.trusted)
                    anchor_count = checkpoint['count']
                    if (checkpoint.get('schema') != 'mithril-custody-checkpoint-v1' or checkpoint.get('caseId') != case_id
                            or type(anchor_count) is not int or not 1 <= anchor_count <= len(envelopes)
                            or checkpoint.get('tailSha256') != digest(canonical(envelopes[anchor_count-1]))):
                        raise Refusal('external_checkpoint_mismatch')
                    state = 'external-checkpoint-matched-prefix'
                return dict(caseId=case_id, events=values, checkpointState=state, anchoredEvents=anchor_count,
                            unanchoredEvents=len(values)-anchor_count, actorIdentity='operator-claim-not-remote-authentication')
            if operation == 'checkpoint':
                return self.sign(dict(schema='mithril-custody-checkpoint-v1', caseId=case_id, count=len(envelopes),
                                      tailSha256=digest(canonical(envelopes[-1])), at=utc()))
            if operation == 'transfer':
                _, result = self.package(case, args['evidenceId'])
                self.append(case, 'transfer-recorded', dict(evidenceId=args['evidenceId'], manifestSha256=result['manifestSha256'],
                            recipientClaim=bounded_text(args['recipient'], 128), reason=bounded_text(args['reason'])))
                return dict(status='recorded', recipientAcceptance='not-attested', physicalTransfer='not-performed')
            if operation == 'hold':
                if type(args['active']) is not bool: raise Refusal('invalid_hold')
                self.append(case, 'hold', dict(active=args['active'], reason=bounded_text(args['reason'])))
                return dict(active=args['active'], enforcement='recorded-no-delete-operation-in-toolkit')
            if operation == 'report': return self.attempt(case, operation, lambda: self.report(case, args))
            if operation == 'report-approve': return self.attempt(case, operation, lambda: self.approve(case, args))

    def attempt(self, case, operation, function):
        try: return function()
        except Exception as error:
            # Never place exception messages, paths, credentials or evidence text in the failure ledger.
            try: self.append(case, 'operation-failed', dict(operation=operation, errorType=type(error).__name__, successfulOutput=False))
            except Exception: pass  # Disk/key/ledger failures cannot promise a durable audit entry.
            raise

    def create(self, case_id, purpose):
        target = self.root / case_id
        if target.exists() or target.is_symlink(): raise Refusal('case_exists')
        # Use final case directory name in signed events; remove incomplete creation on handled errors.
        target.mkdir(mode=0o700)
        try:
            (target / 'evidence').mkdir(mode=0o700); (target / 'reports').mkdir(mode=0o700)
            write_new(target / 'case.json', canonical(self.sign(dict(schema='mithril-case-v1', caseId=case_id, purpose=purpose, createdAt=utc()))))
            self.append(target, 'case-create', dict(purpose=purpose)); sync_dir(target)
        except Exception:
            shutil.rmtree(target); raise
        return dict(caseId=case_id, status='created', isolation='local-policy-and-OS-account')

    def pack(self, case, args):
        evidence_id = identifier(args['evidenceId']); authority = bounded_text(args['authorityRef'])
        runs = args['runs']
        if not isinstance(runs, list) or not 1 <= len(runs) <= 16 or not all(isinstance(x, str) for x in runs):
            raise Refusal('invalid_runs')
        if len(set(runs)) != len(runs): raise Refusal('duplicate_runs')
        target = case / 'evidence' / evidence_id
        checked_dir(target.parent)
        if target.exists() or target.is_symlink(): raise Refusal('evidence_exists')
        _, events = self.events(case)
        if any(event['action'] == 'pack' and event['details'].get('evidenceId') == evidence_id for event in events):
            raise Refusal('evidence_id_already_registered')
        if len(list(target.parent.iterdir())) >= 16: raise Refusal('case_package_limit')
        # Existing product normalizers are invoked only during packing, never by independent verify.
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'mithril-cybersecurity-products' / 'scripts'))
        import products
        stage = Path(tempfile.mkdtemp(prefix='.pack-', dir=case))
        files = []; observations = []; total = 0
        try:
            (stage / 'payload').mkdir(mode=0o700)
            for index, run in enumerate(runs):
                root = checked_dir(run)
                if root.is_relative_to(self.root) or not any(root.is_relative_to(Path(p)) for p in self.inputs.get(case.name, [])):
                    raise Refusal('input_outside_case_roots')
                raw = read_file(root / 'source.json', 2 * 1024 * 1024)
                receipt_raw = read_file(root / 'receipt.json', 16384)
                receipt = decode(receipt_raw)
                if not isinstance(receipt, dict) or receipt.get('sourceSha256') != digest(raw): raise Refusal('source_integrity_failed')
                normalized = products.normalize(receipt['product'], raw)
                directory = stage / 'payload' / f'{index:02d}'; directory.mkdir(mode=0o700)
                for name, data, kind in [('source.json', raw, 'original-bytes'), ('findings.json', canonical(normalized), 'recomputed-vendor-claims'),
                                         ('receipt-claims.json', receipt_raw, 'unsigned-operator-receipt-claims')]:
                    if len(data) > 8*1024*1024: raise Refusal('file_size_limit')
                    total += len(data)
                    if total > 64*1024*1024: raise Refusal('package_size_limit')
                    path = directory / name; write_new(path, data)
                    files.append(dict(path=path.relative_to(stage).as_posix(), bytes=len(data), sha256=digest(data), kind=kind))
                observations.append(dict(product=receipt['product'], sourceSha256=digest(raw), retainedRecords=len(normalized['findings']),
                                         originalPath=f'payload/{index:02d}/source.json', findingsPath=f'payload/{index:02d}/findings.json',
                                         normalizerVersion='0.3.0', coverage='incomplete-or-unknown'))
            manifest = dict(schema='mithril-evidence-package-v1', canonicalization='python-json-sort-ascii-v1',
                            version=VERSION, caseId=case.name, evidenceId=evidence_id, packagedAt=utc(), actorClaim=self.principal,
                            authorityReferenceClaim=authority, files=files, observations=observations,
                            limits=['no-vendor-authenticity-attestation','no-tenant-completeness-attestation','prior-receipt-claims-unsigned'])
            write_new(stage / 'manifest.json', canonical(self.sign(manifest)))
            result = verify(stage, self.trusted, case.name)
            os.rename(stage, target); sync_dir(target.parent)
            try: self.append(case, 'pack', dict(evidenceId=evidence_id, manifestSha256=result['manifestSha256'], sources=len(runs)))
            except Exception:
                shutil.rmtree(target); raise
            return result
        finally:
            if stage.exists(): shutil.rmtree(stage)

    def report(self, case, args):
        report_id = identifier(args['reportId']); question = bounded_text(args['question'])
        ids = args['evidenceIds']
        if not isinstance(ids, list) or not 1 <= len(ids) <= 16 or len(set(ids)) != len(ids): raise Refusal('invalid_evidence_ids')
        target = case / 'reports' / report_id
        checked_dir(target.parent)
        if target.exists() or target.is_symlink(): raise Refusal('report_exists')
        _, events = self.events(case)
        if any(event['action'] == 'report-draft' and event['details'].get('reportId') == report_id for event in events):
            raise Refusal('report_id_already_registered')
        sources = []; findings = []; unknown = 0
        for evidence_id in ids:
            path, verified = self.package(case, evidence_id)
            manifest = unseal(decode(read_file(path / 'manifest.json', 262144)), self.trusted)
            sources.append(verified)
            for observation in manifest['observations']:
                data = decode(read_file(path / observation['findingsPath']))
                for row in data['findings']:
                    if len(findings) >= 1000: raise Refusal('report_record_limit')
                    findings.append(dict(evidenceId=evidence_id, product=data['product'], sourceSha256=observation['sourceSha256'],
                                         sourceRow=row['sourceRow'], originalPath=observation['originalPath'], claim=row))
                    if row.get('reportedTime') is None: unknown += 1
        body = dict(schema='mithril-report-draft-v1', caseId=case.name, reportId=report_id, question=question,
                    status='draft-requires-human-review', authorClaim=self.principal, generatedAt=utc(), generatorVersion=VERSION, sources=sources,
                    observations=findings, unknownTimeCount=unknown, conclusions=[],
                    limits=['claims-not-proven-facts','coverage-incomplete-or-unknown','no-identity-or-guilt-inference'])
        raw = canonical(self.sign(body))
        if len(raw) > 8*1024*1024: raise Refusal('report_size_limit')
        stage = Path(tempfile.mkdtemp(prefix='.report-', dir=case))
        try:
            write_new(stage / 'report.json', raw)
            # Do not render untrusted evidence or names into Markdown/HTML.
            summary = '# Forensic report draft\n\nHuman review required.\n\n' + f'Case: {case.name}\nReport: {report_id}\nObservations: {len(findings)}\n\n' + 'See signed report.json for the question, claims, sources and limitations. No conclusion is automatically generated.\n'
            write_new(stage / 'report.md', summary.encode())
            os.rename(stage, target); sync_dir(target.parent)
            try: self.append(case, 'report-draft', dict(reportId=report_id, sha256=digest(raw), evidenceIds=ids))
            except Exception:
                shutil.rmtree(target); raise
        finally:
            if stage.exists(): shutil.rmtree(stage)
        return dict(status=body['status'], caseId=case.name, reportId=report_id, observations=len(findings), sha256=digest(raw))

    def approve(self, case, args):
        report_id = identifier(args['reportId']); notes = bounded_text(args['notes'])
        root = checked_dir(case / 'reports' / report_id)
        raw = read_file(root / 'report.json')
        body = unseal(decode(raw), self.trusted)
        if (body.get('schema') != 'mithril-report-draft-v1' or body.get('caseId') != case.name
                or body.get('reportId') != report_id or body.get('authorClaim') == self.principal):
            raise Refusal('independent_reviewer_required')
        _, events = self.events(case)
        if not any(e['action'] == 'report-draft' and e['details'].get('reportId') == report_id
                   and e['details'].get('sha256') == digest(raw) for e in events): raise Refusal('report_not_registered')
        for source in body['sources']:
            _, verified = self.package(case, source['evidenceId'])
            if verified['manifestSha256'] != source['manifestSha256']: raise Refusal('report_source_changed')
        approval = self.sign(dict(schema='mithril-report-approval-v1', caseId=case.name, reportId=report_id,
                                  reportSha256=digest(raw), reviewerClaim=self.principal, at=utc(), notes=notes,
                                  scope='human-claims-and-limitations-review-not-judicial-admissibility'))
        path = root / 'approval.json'
        write_new(path, canonical(approval))
        try: self.append(case, 'report-approved', dict(reportId=report_id, reportSha256=digest(raw), approvalSha256=digest(canonical(approval))))
        except Exception:
            path.unlink(); raise
        return dict(status='review-recorded', reportId=report_id, reportSha256=digest(raw))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', required=True); parser.add_argument('--principal', required=True)
    parser.add_argument('--operation', choices=SCHEMAS); parser.add_argument('--args')
    parser.add_argument('--mcp', action='store_true')
    args = parser.parse_args()
    try:
        workspace = Workspace(args.policy, args.principal)
        if args.mcp:
            from mcp import serve
            serve(workspace)
        else:
            if not args.operation or not args.args: raise Refusal('operation_arguments_required')
            print(json.dumps(workspace.execute(args.operation, decode(read_file(args.args, 32768)))))
    except Exception:
        print(json.dumps(dict(status='refused', reason='operation_failed')), file=sys.stderr)
        raise SystemExit(1)

if __name__ == '__main__': main()
