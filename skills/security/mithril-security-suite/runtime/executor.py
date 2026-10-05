"""Provisioned executor for Registry jobs. UI requests never define scope or credentials."""
from __future__ import annotations
import argparse
import json
import os
import re
import sqlite3
import subprocess
import time
import tempfile
from edn_wire import encode, decode, Keyword
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit
from suite import CoreHost, NetworkHost, Refusal, digest, finding, run, PACKAGE, MAX_BYTES

IDENT = re.compile(r'^[a-zA-Z0-9_-]{1,128}$')
ENV = re.compile(r'^[A-Z][A-Z0-9_]{0,127}$')

class Journal:
    def __init__(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)
        os.chmod(path, 0o600)
        self.db = sqlite3.connect(path)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('CREATE TABLE IF NOT EXISTS runs(tenant TEXT,id TEXT,target TEXT,policy TEXT,status TEXT,result TEXT,lease TEXT,ack INTEGER DEFAULT 0,PRIMARY KEY(tenant,id))')
        self.db.commit()
    def begin(self, tenant, job):
        try:
            with self.db:
                self.db.execute("INSERT INTO runs(tenant,id,target,policy,status,lease) VALUES(?,?,?,?,'running',?)", (tenant,job['id'],job['targetId'],job['policyDigest'],job.get('lease')))
        except sqlite3.IntegrityError:
            raise Refusal('job has already been attempted; reconcile its journal')
    def finish(self, tenant, id_, result):
        with self.db:
            self.db.execute('UPDATE runs SET status=?,result=? WHERE tenant=? AND id=? AND status=?', ('completed' if result is not None else 'failed',json.dumps(result),tenant,id_,'running'))
    def pending(self, tenant):
        return self.db.execute("SELECT id,lease,result FROM runs WHERE tenant=? AND ack=0 AND status IN ('completed','failed') AND lease IS NOT NULL",(tenant,)).fetchall()
    def acknowledge(self, tenant, id_):
        with self.db:
            self.db.execute('UPDATE runs SET ack=1,lease=NULL WHERE tenant=? AND id=?',(tenant,id_))
    def close(self):
        self.db.close()

class Executor:
    def __init__(self, config, journal):
        if config.get('schemaVersion') != 1 or not IDENT.fullmatch(config.get('tenant','')) or not IDENT.fullmatch(config.get('executorId','')):
            raise Refusal('invalid executor identity')
        self.config, self.journal = config, journal
        self.targets = {}
        for t in config.get('targets',[]):
            if not IDENT.fullmatch(t.get('id','')) or t.get('mode') not in ('sandbox','live') or t['id'] in self.targets:
                raise Refusal('invalid target')
            # Freeze the entire host-owned policy, including credential reference names, into job identity.
            if t['mode']=='sandbox' and t['provider']=='suite':
                for endpoint in t.get('scope',{}).get('endpoints',[]):
                    if urlsplit(endpoint).hostname!='127.0.0.1':
                        raise Refusal('sandbox network effects require loopback')
            self.targets[t['id']] = dict(t, policyDigest=digest({'executorId':config['executorId'],'target':t}))
        if not self.targets or len(self.targets)>100:
            raise Refusal('finite target policy required')
    def descriptor(self, target):
        return {'id':target['id'],'name':target['name'],'provider':target['provider'],'mode':target['mode'],'policyDigest':target['policyDigest'],'executorId':self.config['executorId'],'availableUntil':0}
    def execute(self, job):
        target = self.targets.get(job['targetId'])
        if not target or target['policyDigest']!=job['policyDigest']:
            raise Refusal('provisioned target policy differs from job')
        self.journal.begin(self.config['tenant'],job)
        try:
            if target['provider']=='suite':
                # HTTP credentials resolve from host policy, never from the scan request.
                network=NetworkHost(**target['scope']) if target.get('scope') else None
                result=run(dict(target['request'],tenant=self.config['tenant']),CoreHost(self.config['engineRoot']) if self.config.get('engineRoot') else None,network)
                findings=[{k:f[k] for k in ('id','rule','asset','severity','evidenceDigest','remediation')} for report in result['reports'] for f in report['findings']]
                gaps=sum(len(report['gaps']) for report in result['reports'])
            else:
                result=self.cloud(target)
                findings=[]
                for raw in result.get('cloud/findings',[]):
                    f=finding(raw['finding/rule'],raw['finding/resource'],raw['finding/severity'],raw,raw.get('finding/remediation','Review the observed cloud configuration.'))
                    f={k:f[k] for k in ('rule','asset','severity','evidenceDigest','remediation')}
                    f['id']=digest([self.config['tenant'],target['id'],f['rule'],f['asset']])
                    findings.append(f)
                gaps=len(result.get('cloud/gaps') or [])+len(result.get('cloud/inventory-errors') or [])
            findings=sorted({f['id']:f for f in findings}.values(),key=lambda f:f['id'])
            if len(findings)>128:
                raise Refusal('receipt finding capacity exceeded')
            receipt={'mode':target['mode'],'coverage':'partial','productionVerified':False,'findings':findings,'gapCount':gaps}
            self.journal.finish(self.config['tenant'],job['id'],receipt)
            return receipt
        except Exception:
            self.journal.finish(self.config['tenant'],job['id'],None)
            raise
    def cloud(self, target):
        provider=target['provider']
        if provider not in ('aws','azure','gcp'):
            raise Refusal('cloud provider has no admitted connector')
        host=CoreHost(self.config['engineRoot'])
        # No ambient provider credentials, proxy settings, endpoint overrides or web-identity files.
        child_env={k:os.environ[k] for k in ('PATH','HOME','TMPDIR') if k in os.environ}
        allowed={'aws':{'AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN'},'azure':{'AZURE_ACCESS_TOKEN'},'gcp':{'GCP_ACCESS_TOKEN'}}[provider]
        for dest,ref in target.get('credentials',{}).items():
            if dest not in allowed or not ENV.fullmatch(ref) or not os.environ.get(ref):
                raise Refusal('credential reference unavailable')
            child_env[dest]=os.environ[ref]
        required={'aws':{'AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY'},'azure':{'AZURE_ACCESS_TOKEN'},'gcp':{'GCP_ACCESS_TOKEN'}}[provider]
        if not required <= child_env.keys():
            raise Refusal('explicit connector credentials required')
        inputs=target['input']
        fields={'aws':{'account','region','regions','services'},'azure':{'subscription','subscriptions'},'gcp':{'project','projects','zone'}}[provider]
        if not set(inputs)<=fields or not inputs:
            raise Refusal('unbounded cloud input')
        if provider=='aws' and (not inputs.get('account') or not inputs.get('region') or not inputs.get('services')):
            raise Refusal('AWS account region and finite services required')
        if provider=='azure' and not (inputs.get('subscription') or inputs.get('subscriptions')):
            raise Refusal('Azure subscription scope required')
        if provider=='gcp' and not (inputs.get('project') or inputs.get('projects')):
            raise Refusal('GCP project scope required')
        overrides={'aws':['AI_GFTD_AWS_ENDPOINT'],'azure':['AI_GFTD_AZURE_ENDPOINT'],'gcp':['AI_GFTD_GCP_COMPUTE_ENDPOINT','AI_GFTD_GCP_STORAGE_ENDPOINT','AI_GFTD_GCP_RESOURCE_ENDPOINT']}[provider]
        if target['mode']=='sandbox':
            parsed=urlsplit(target.get('endpoint',''))
            if parsed.scheme!='http' or parsed.hostname!='127.0.0.1' or not parsed.port or parsed.path not in ('','/') or parsed.query or parsed.fragment or parsed.username is not None or parsed.password is not None:
                raise Refusal('sandbox requires a loopback emulator origin')
            for key in overrides:
                child_env[key]=target['endpoint']
        elif 'endpoint' in target:
            raise Refusal('live endpoints cannot be overridden')
        # Execute the checked-in, immutable first-party agent rather than recompiling its host at scan time.
        core=host.root/'security-core'
        with tempfile.TemporaryDirectory(prefix='mithril-security-agent-') as directory:
            task_inputs=dict(inputs)
            if provider=='aws':
                if not set(inputs['services']) <= {'ec2','s3','iam','rds','kms'}:
                    raise Refusal('cloud service is not admitted')
                task_inputs['services']=[Keyword(v) for v in inputs['services']]
            task_inputs['provider']=Keyword(provider)
            task={'task/id':'registry-cloud','task/status':Keyword('pending'),'task/command':Keyword('cloud/posture'),'task/initiator':'operator','task/input':task_inputs}
            task_path=Path(directory)/'task.edn';task_path.write_text(encode(task))
            child_env.update({'AI_GFTD_AGENT_ROOT':directory,'AI_GFTD_AGENT_ALLOW':'cloud/posture','AI_GFTD_DRIVER_CATALOG':str(core/'resources/operations/drivers.edn'),'AI_GFTD_POSTURE_RULES':str(core/'resources/cloud/posture-rules.edn')})
            if target['mode']=='sandbox':child_env['MITHRIL_ALLOWED_CLOUD_ORIGIN']='http://127.0.0.1:'+str(urlsplit(target['endpoint']).port)
            proc=subprocess.run(['node','--require',str(PACKAGE/'runtime/cloud-guard.cjs'),str(core/'products/agent/bin/agent.cjs'),'--task',str(task_path)],cwd=core,env=child_env,text=True,capture_output=True,timeout=180)
        if proc.returncode or len(proc.stdout.encode())>8*MAX_BYTES:
            raise Refusal('cloud collector refused')
        receipt=decode(proc.stdout)
        if receipt.get('task/status')!='success' or receipt.get('task/id')!='registry-cloud':
            raise Refusal('cloud collector refused')
        result=receipt['task/result']
        return result
    def api(self, action, body=None):
        cfg=self.config['api'];origin=urlsplit(cfg['origin'])
        if origin.username is not None or origin.password is not None or origin.path not in ('','/') or origin.query or origin.fragment or (origin.scheme!='https' and not (origin.scheme=='http' and origin.hostname=='127.0.0.1')):
            raise Refusal('invalid ledger API origin')
        token=os.environ.get(cfg['tokenEnv'])
        if not token or any(c in token for c in '\r\n'):
            raise Refusal('ledger token unavailable')
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args,**kwargs): return None
        request=urllib.request.Request(cfg['origin'].rstrip('/')+'/v1/security'+action,data=json.dumps(body).encode() if body is not None else None,headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
        with urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect()).open(request,timeout=20) as response:
            raw=response.read(MAX_BYTES+1)
            if len(raw)>MAX_BYTES:raise Refusal('ledger response too large')
            value=json.loads(raw)
        if value.get('schemaVersion')!=1 or value.get('userId')!=self.config['tenant']:
            raise Refusal('ledger owner mismatch')
        return value
    def synchronize(self):
        # Retry acknowledgements from completed local results without repeating scan effects.
        for id_,lease,body in self.journal.pending(self.config['tenant']):
            self.api('/complete',{'id':id_,'lease':lease,'result':json.loads(body)})
            self.journal.acknowledge(self.config['tenant'],id_)
        for target in self.targets.values():self.api('/target',self.descriptor(target))
        value=self.api('/claim',{'executorId':self.config['executorId']})
        job=value.get('job')
        if job:
            if not IDENT.fullmatch(job.get('id','')):raise Refusal('invalid job identity')
            try:self.execute(job)
            except Exception:pass  # The failure is journaled; no upstream exception or secret is emitted.
            for id_,lease,body in self.journal.pending(self.config['tenant']):
                self.api('/complete',{'id':id_,'lease':lease,'result':json.loads(body)})
                self.journal.acknowledge(self.config['tenant'],id_)
        return {'ok':True,'claimed':bool(job)}

def main():
    p=argparse.ArgumentParser();p.add_argument('config',type=Path);p.add_argument('--journal',type=Path,required=True);p.add_argument('--target');p.add_argument('--id');p.add_argument('--serve',action='store_true');p.add_argument('--poll-seconds',type=int,default=30);args=p.parse_args()
    journal=None
    try:
        journal=Journal(args.journal);executor=Executor(json.loads(args.config.read_text()),journal)
        if args.target:
            if args.serve:raise Refusal('local target cannot run as a recurring service')
            target=executor.targets[args.target]
            if not args.id or not IDENT.fullmatch(args.id):raise Refusal('explicit local operation ID required')
            result=executor.execute({'id':args.id,'targetId':args.target,'policyDigest':target['policyDigest']})
        else:
            if not 5<=args.poll_seconds<=60:raise Refusal('invalid polling interval')
            if args.serve:
                while True:
                    print(json.dumps(executor.synchronize()),flush=True)
                    time.sleep(args.poll_seconds)
            result=executor.synchronize()
        print(json.dumps(result));return 0
    except Exception:
        print(json.dumps({'ok':False,'reason':'executor-refused','productionVerified':False}));return 1
    finally:
        if journal:journal.close()
if __name__=='__main__':raise SystemExit(main())
