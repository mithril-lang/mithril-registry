#!/usr/bin/env python3
"""Synthetic agency acceptance exercise; no vendor/customer connection or keys retained."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from evidence import Workspace
from format import canonical, digest, write_new

def provision(root):
    root = Path(root).resolve()
    if any(root.iterdir()): raise ValueError('empty_fixture_directory_required')
    workspace = root/'workspace'; workspace.mkdir(mode=0o700)
    inputs = root/'inputs'; inputs.mkdir(mode=0o700)
    key = Ed25519PrivateKey.generate()
    signer = root/'signer.raw'; write_new(signer,key.private_bytes_raw())
    trusted = root/'trusted.raw'; trusted.write_bytes(key.public_key().public_bytes_raw())
    policy = root/'policy.json'
    write_new(policy,canonical(dict(schemaVersion=1,workspace=str(workspace),trustedKey=str(trusted),signingKey=str(signer),
                                     grants={name:dict(role=role,cases=['training-case'],inputRoots={'training-case':[str(inputs)]})
                                             for name,role in [('examiner','supervisor'),('reviewer','reviewer')]})))
    fixtures = {'runzero':[dict(id='fixture-asset',addresses=['8.8.8.8'],last_seen=1791244800)],
                'okta-system-log':[dict(uuid='fixture-event',published='2026-10-06T00:00:00Z',client=dict(ipAddress='8.8.8.8'))],
                'censys-platform':dict(result=dict(resource=dict(ip='8.8.8.8')))}
    runs = []
    for product,data in fixtures.items():
        run = inputs/product; run.mkdir(mode=0o700)
        raw = canonical(data)
        (run/'source.json').write_bytes(raw)
        (run/'receipt.json').write_bytes(canonical(dict(schemaVersion=1,product=product,sourceSha256=digest(raw))))
        runs.append(str(run))
    return dict(policy=str(policy),runs=runs,workspace=str(workspace),trustedKey=str(trusted))

def exercise():
    with tempfile.TemporaryDirectory(prefix='mithril-agency-') as temporary:
        config = provision(temporary)
        w = Workspace(config['policy'],'examiner'); reviewer = Workspace(config['policy'],'reviewer')
        case_id = 'training-case'
        w.execute('case-create',dict(caseId=case_id,purpose='Synthetic agency acceptance'))
        packed = w.execute('pack',dict(caseId=case_id,evidenceId='evidence-1',runs=config['runs'],authorityRef='synthetic-local-evaluation'))
        package = Path(config['workspace'])/case_id/'evidence/evidence-1'
        verifier = Path(__file__).with_name('verify.py')
        command = [sys.executable,str(verifier),str(package),'--trusted-key',config['trustedKey'],'--case',case_id]
        success = subprocess.run(command,capture_output=True,text=True,timeout=10)
        if success.returncode: raise ValueError('independent_verification_failed')
        w.execute('report',dict(caseId=case_id,reportId='report-1',evidenceIds=['evidence-1'],question='Which observations were retained?'))
        approval = reviewer.execute('report-approve',dict(caseId=case_id,reportId='report-1',notes='Synthetic source rows and limits reviewed'))
        checkpoint = w.execute('checkpoint',dict(caseId=case_id))
        custody = reviewer.execute('custody',dict(caseId=case_id,checkpoint=checkpoint))
        if custody['unanchoredEvents'] != 0: raise ValueError('checkpoint_failed')
        payload = package/'payload/00/source.json'; payload.write_bytes(payload.read_bytes()+b' ')
        refused = subprocess.run(command,capture_output=True,text=True,timeout=10)
        if refused.returncode == 0: raise ValueError('tamper_not_detected')
        return dict(status='passed',qualification='synthetic-local-evaluation',vendorConnections=0,
                    originalSources=3,verifiedFiles=packed['files'],reportReview=approval['status'],
                    custodyEvents=len(custody['events']),externalCheckpointTest='matched',tamperedPayload='refused',keysRetained=False)

def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--prepare')
    args = parser.parse_args()
    try: print(json.dumps(provision(args.prepare) if args.prepare else exercise()))
    except Exception:
        print(json.dumps(dict(status='failed',reason='acceptance_failed'))); raise SystemExit(1)

if __name__ == '__main__': main()
