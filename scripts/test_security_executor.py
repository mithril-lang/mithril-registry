import http.server
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib.parse import urlsplit
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
RUNTIME=ROOT/'skills/security/mithril-security-suite/runtime'
sys.path.insert(0,str(RUNTIME))
from executor import Executor,Journal
from suite import NetworkHost,Refusal
from edn_wire import encode,decode,Keyword
EMULATOR_COMMIT='b9b9e3f23fda1da0879a074a3c4e166531342ef8'

class AuthHandler(http.server.BaseHTTPRequestHandler):
    seen=[]
    def do_GET(self):
        self.seen.append(self.headers.get('Authorization'))
        ok=self.headers.get('Authorization')=='Bearer synthetic-session'
        self.send_response(200 if ok else 401);self.end_headers();self.wfile.write(b'signed-in private test page' if ok else b'login required')
    def log_message(self,*args):pass

class ExecutorTest(unittest.TestCase):
    def test_agent_wire_is_data_only_and_rejects_ambiguous_receipts(self):
        data={'task/status':Keyword('success'),'text':'quoted " and newline\n','items':[True,None,3.5]}
        self.assertEqual(decode(encode(data)),dict(data,**{'task/status':'success'}))
        for source in ('#=(shell "x")','{:a 1 :a 2}','{:a 1} {:b 2}','{:x tagged/value}','[[[[[[[['):
            with self.subTest(source=source),self.assertRaises(ValueError):decode(source)
    def test_persistent_intent_refuses_replay_and_preserves_result(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'journal.sqlite'
            c={'schemaVersion':1,'tenant':'a','executorId':'x','targets':[{'id':'sast','name':'Test code','provider':'suite','mode':'sandbox','request':{'schemaVersion':'1','operations':[{'id':'sast','input':{'files':[{'path':'x.py','content':'eval(input())'}]}}]}}]}
            j=Journal(path);e=Executor(c,j);t=e.targets['sast'];job={'id':'one','targetId':t['id'],'policyDigest':t['policyDigest'],'lease':'synthetic-lease'}
            r=e.execute(job);self.assertEqual(len(r['findings']),1);self.assertFalse(r['productionVerified']);j.close()
            j=Journal(path);e=Executor(c,j)
            with self.assertRaises(Refusal):e.execute(job)
            self.assertEqual(json.loads(j.pending('a')[0][2]),r)
            self.assertEqual(j.pending('b'),[]);self.assertEqual(path.stat().st_mode&0o777,0o600);j.close()
    def test_sandbox_rejects_non_loopback_and_policy_drift(self):
        with tempfile.TemporaryDirectory() as d:
            j=Journal(Path(d)/'journal.sqlite')
            c={'schemaVersion':1,'tenant':'a','executorId':'x','targets':[{'id':'test','name':'Test','provider':'suite','mode':'sandbox','scope':{'endpoints':['https://192.0.2.1']}}]}
            with self.assertRaises(Refusal):Executor(c,j)
            c['targets'][0].pop('scope');e=Executor(c,j)
            with self.assertRaises(Refusal):e.execute({'id':'one','targetId':'test','policyDigest':'a'*64})
            j.close()
    def test_authentication_is_origin_bound_and_login_page_is_refused(self):
        AuthHandler.seen=[];server=http.server.ThreadingHTTPServer(('127.0.0.1',0),AuthHandler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            origin='http://127.0.0.1:'+str(server.server_port)
            auth={'origin':origin,'header':'Authorization','env':'MITH_TEST_AUTH','expectedStatus':200,'bodyContains':'signed-in'}
            with patch.dict(os.environ,{'MITH_TEST_AUTH':'Bearer synthetic-session'}):
                h=NetworkHost([origin],authentication=[auth]);self.assertEqual(h.fetch(origin+'/private')['status'],200)
                with self.assertRaises(Refusal):h.fetch('http://127.0.0.1:1/private')
            with patch.dict(os.environ,{'MITH_TEST_AUTH':'Bearer wrong-session'}):
                with self.assertRaises(Refusal):NetworkHost([origin],authentication=[auth]).fetch(origin+'/private')
            self.assertEqual(AuthHandler.seen,['Bearer synthetic-session','Bearer wrong-session'])
        finally:server.shutdown();server.server_close();thread.join()

@unittest.skipUnless(os.environ.get('MITHRIL_SECURITY_EMULATOR_ROOT') and os.environ.get('MITHRIL_SECURITY_ENGINE_ROOT'),'pinned emulator and engines not configured')
class CloudConformanceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root=Path(os.environ['MITHRIL_SECURITY_EMULATOR_ROOT'])
        head=subprocess.check_output(['git','-C',str(cls.root),'rev-parse','HEAD'],text=True).strip()
        dirty=subprocess.check_output(['git','-C',str(cls.root),'status','--porcelain'],text=True).strip()
        if head!=EMULATOR_COMMIT or dirty:raise RuntimeError('emulator must be clean at pinned commit')
        if os.environ.get('MITHRIL_SECURITY_EMULATOR_ENDPOINT'):
            parsed=urlsplit(os.environ['MITHRIL_SECURITY_EMULATOR_ENDPOINT'])
            if parsed.scheme!='http' or parsed.hostname!='127.0.0.1' or not parsed.port:raise RuntimeError('invalid external emulator endpoint')
            cls.port=parsed.port;cls.proc=None;return
        with socket.socket() as s:s.bind(('127.0.0.1',0));cls.port=s.getsockname()[1]
        cls.temp=tempfile.TemporaryDirectory(prefix='mithril-cloud-emulator-')
        work=Path(cls.temp.name);(work/'resources').symlink_to(cls.root/'resources',target_is_directory=True)
        deps=Path(os.environ.get('MITHRIL_SECURITY_DEPS_ROOT',str(Path.home()/'.gitlibs/libs/io.github.kotoba-lang')))
        versions={'text':'73bdb13ae7a3d004b44bca08be03a3191157a38f','bytes':'d5259f35ab7c4f5a66e63ca29ed4dcf7ba3f1ac5','coll':'f74e248f0a07e8ae572885f50fab6bdb39dc24be','edn':'250f4dafa5f5c7fb3109703496a52866e2a62dcd'}
        paths=[cls.root/'src',cls.root/'resources']+[deps/name/sha/'src' for name,sha in versions.items()]
        if not all(p.is_dir() for p in paths):raise RuntimeError('pinned emulator dependencies not installed')
        cls.proc=subprocess.Popen(['kbb','--backend','sci','--classpath',':'.join(str(p) for p in paths),'-m','opencloud.server','--port',str(cls.port)],cwd=work,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(1200):
            if cls.proc.poll() is not None:raise RuntimeError('emulator refused startup')
            try:
                with socket.create_connection(('127.0.0.1',cls.port),timeout=.1):return
            except OSError:time.sleep(.1)
        cls.proc.terminate();raise RuntimeError('emulator startup timed out')
    @classmethod
    def tearDownClass(cls):
        if cls.proc:cls.proc.terminate();cls.proc.wait(timeout=10);cls.temp.cleanup()
    def config(self,provider):
        data={'aws':({'account':'123456789012','region':'us-east-1','services':['ec2','s3','iam','rds','kms']},{'AWS_ACCESS_KEY_ID':'MITH_TEST_AWS_KEY','AWS_SECRET_ACCESS_KEY':'MITH_TEST_AWS_SECRET'}),'azure':({'subscription':'00000000-0000-0000-0000-00000000dead'},{'AZURE_ACCESS_TOKEN':'MITH_TEST_AZURE'}),'gcp':({'project':'opencloud-example','zone':'us-central1-a'},{'GCP_ACCESS_TOKEN':'MITH_TEST_GCP'})}
        inputs,creds=data[provider]
        return {'schemaVersion':1,'tenant':'test-owner','executorId':'test-executor','engineRoot':os.environ['MITHRIL_SECURITY_ENGINE_ROOT'],'targets':[{'id':provider,'name':provider+' sandbox','provider':provider,'mode':'sandbox','endpoint':'http://127.0.0.1:'+str(self.port),'credentials':creds,'input':inputs}]}
    def test_authenticated_provider_collection_and_shared_posture(self):
        env={'MITH_TEST_AWS_KEY':'AKIAOPENCLOUDEXAMPLE','MITH_TEST_AWS_SECRET':'opencloudExampleSecretKeyNotUsableAnywhereReal','MITH_TEST_AZURE':'opencloud-azure-token','MITH_TEST_GCP':'opencloud-gcp-token'}
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,env):
            j=Journal(Path(d)/'journal.sqlite')
            for provider in ('aws','azure','gcp'):
                with self.subTest(provider=provider):
                    e=Executor(self.config(provider),j);t=e.targets[provider];result=e.execute({'id':provider+'-one','targetId':provider,'policyDigest':t['policyDigest']})
                    self.assertGreater(len(result['findings']),0);self.assertEqual(result['mode'],'sandbox');self.assertFalse(result['productionVerified'])
                    self.assertNotIn(env['MITH_TEST_AWS_SECRET'],json.dumps(result));self.assertNotIn('opencloud-azure-token',json.dumps(result))
            j.close()
    def test_bad_cloud_authentication_is_not_a_clean_assessment(self):
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,{'MITH_TEST_AZURE':'wrong-synthetic-token'}):
            j=Journal(Path(d)/'journal.sqlite');e=Executor(self.config('azure'),j);t=e.targets['azure']
            with self.assertRaises(Refusal):e.execute({'id':'wrong-auth','targetId':'azure','policyDigest':t['policyDigest']})
            self.assertEqual(j.db.execute('SELECT status FROM runs').fetchone()[0],'failed');j.close()
