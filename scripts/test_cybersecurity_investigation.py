import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.request
from http.server import HTTPServer,BaseHTTPRequestHandler
from threading import Thread
ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/'skills/security/mithril-cybersecurity-products/scripts/products.py'
spec=importlib.util.spec_from_file_location('investigation_products',SCRIPT);p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
NEW={
 'microsoft-defender':{'value':[{'id':'a','title':'Synthetic alert','severity':'high','createdDateTime':'2026-10-06T00:00:00Z','machineId':'asset-1'}],'@odata.nextLink':'https://evil.invalid'},
 'crowdstrike-falcon':{'resources':[{'composite_id':'a','name':'Synthetic alert','severity':70,'timestamp':'2026-10-06T00:00:01Z','device':{'device_id':'asset-1'}}]},
 'wazuh':{'timed_out':False,'_shards':{'failed':0},'hits':{'total':{'value':1,'relation':'eq'},'hits':[{'_id':'a','_source':{'rule':{'description':'Synthetic alert','level':10},'timestamp':'2026-10-06T09:00:02+09:00','agent':{'id':'001'}}}]}},
 'tenable-vm':[{'plugin':{'id':1,'name':'Synthetic vulnerability','cve':['CVE-2026-12345']},'severity':3,'last_found':1791244803,'asset':{'uuid':'asset-1'}}]
}
POLICIES={
 'microsoft-defender':dict(origin='https://graph.microsoft.com',tokenEnv='FIXTURE_TOKEN'),
 'crowdstrike-falcon':dict(origin='https://api.crowdstrike.com',tokenEnv='FIXTURE_TOKEN',compositeIds=['a']),
 'wazuh':dict(origin='https://indexer.example.test:9200',approvedOrigin='https://indexer.example.test:9200',usernameEnv='FIXTURE_USER',passwordEnv='FIXTURE_PASSWORD'),
 'tenable-vm':dict(origin='https://cloud.tenable.com',accessKeyEnv='FIXTURE_ACCESS',secretKeyEnv='FIXTURE_SECRET',exportUuid='12345678-1234-1234-1234-123456789012',chunkId=1)
}
class InvestigationTests(unittest.TestCase):
 def seed(self,root,product,data=None,suffix=''):
  output=Path(root)/(product+suffix);p.persist(product,json.dumps(NEW[product] if data is None else data).encode(),output,'fixture');return str(output)
 def test_new_product_normalizers_preserve_claims(self):
  for product,data in NEW.items():
   rows=p.normalize(product,json.dumps(data).encode())['findings'];self.assertEqual(len(rows),1);self.assertIsNotNone(rows[0]['assetId'])
  self.assertEqual(p.normalize('tenable-vm',json.dumps(NEW['tenable-vm']).encode())['findings'][0]['cves'],['CVE-2026-12345'])
  with self.assertRaises(p.Refusal):p.normalize('microsoft-defender',b'{"value":[],"error":{"code":"Denied"}}')
  with self.assertRaises(p.Refusal):p.normalize('wazuh',b'{"timed_out":true,"hits":{"hits":[]}}')
  with self.assertRaises(p.Refusal):p.decode(b'{"value":1e999}')
 def test_all_four_read_contracts_over_actual_http_simulator(self):
  seen=[]
  route_to_product={'/v1.0/security/alerts_v2?$top=100':'microsoft-defender','/alerts/entities/alerts/v2':'crowdstrike-falcon','/wazuh-alerts*/_search':'wazuh','/vulns/export/12345678-1234-1234-1234-123456789012/chunks/1':'tenable-vm'}
  class Handler(BaseHTTPRequestHandler):
   def log_message(self,*args):pass
   def handle_request(self):
    body=self.rfile.read(int(self.headers.get('Content-Length','0')));seen.append((self.command,self.path,json.loads(body) if body else None,dict(self.headers)))
    self.send_response(200);self.end_headers();self.wfile.write(json.dumps(NEW[route_to_product[self.path]]).encode())
   do_GET=handle_request;do_POST=handle_request
  server=HTTPServer(('127.0.0.1',0),Handler);thread=Thread(target=server.serve_forever);thread.start();real=urllib.request.build_opener(urllib.request.ProxyHandler({}))
  class Opener:
   def open(self,req,timeout):return real.open(urllib.request.Request(f'http://127.0.0.1:{server.server_port}'+req.selector,req.data,req.headers,method=req.method),timeout=timeout)
  try:
   with patch.dict(os.environ,FIXTURE_TOKEN='synthetic-token',FIXTURE_USER='readonly',FIXTURE_PASSWORD='synthetic-password',FIXTURE_ACCESS='synthetic-access',FIXTURE_SECRET='synthetic-secret'),patch.object(p.urllib.request,'build_opener',return_value=Opener()):
    for product,policy in POLICIES.items():self.assertEqual(json.loads(p.collect(dict(product=product,**policy))),NEW[product])
   self.assertEqual([r[0] for r in seen],['GET','POST','POST','GET'])
   self.assertEqual(seen[1][2],{'composite_ids':['a']});self.assertEqual(seen[2][2]['size'],100)
   self.assertEqual(seen[0][3]['Authorization'],'Bearer synthetic-token');self.assertIn('X-Apikeys',seen[3][3])
  finally:server.shutdown();thread.join();server.server_close()
 def test_rejects_foreign_origins_and_unpinned_wazuh(self):
  for product,policy in POLICIES.items():
   with self.assertRaises(p.Refusal):p.request_for(dict(product=product,**dict(policy,origin='https://evil.invalid')))
  with self.assertRaises(p.Refusal):p.request_for(dict(product='wazuh',**dict(POLICIES['wazuh'],approvedOrigin='https://different.invalid')))
 def test_search_timeline_export_reference_verified_bytes(self):
  with tempfile.TemporaryDirectory() as root:
   paths=[self.seed(root,product) for product in NEW]
   search=p.execute('cybersecurity_search',dict(runs=paths,query='Synthetic',limit=2));self.assertEqual(search['total'],4);self.assertEqual(len(search['data']),2)
   timeline=p.execute('cybersecurity_timeline',dict(runs=paths));self.assertEqual(timeline['total'],4);self.assertEqual(timeline['unknownTimeCount'],0)
   self.assertEqual(timeline['data'][0]['product'],'microsoft-defender')
   result=p.execute('cybersecurity_export',dict(runs=paths,output=str(Path(root)/'export')));self.assertEqual(result['count'],4)
   exported=json.loads(Path(result['output']).read_text());self.assertEqual(len(exported['sources']),4)
   (Path(paths[0])/'source.json').write_text('{}')
   with self.assertRaises(p.Refusal):p.execute('cybersecurity_search',dict(runs=paths,query='Synthetic'))
 def test_compare_reports_sample_changes_without_clearance(self):
  with tempfile.TemporaryDirectory() as root:
   before=self.seed(root,'microsoft-defender');after=self.seed(root,'microsoft-defender',{'value':[]},'-after')
   result=p.execute('cybersecurity_compare',dict(before=before,after=after));self.assertEqual(len(result['sampleAbsent']),1);self.assertIn('sample-absence-not-resolution',result['gaps'])
   duplicate=self.seed(root,'microsoft-defender',{'value':NEW['microsoft-defender']['value']*2},'-duplicate')
   with self.assertRaises(p.Refusal):p.execute('cybersecurity_compare',dict(before=duplicate,after=after))
 def test_unknown_time_and_input_bounds(self):
  with tempfile.TemporaryDirectory() as root:
   path=self.seed(root,'microsoft-defender',{'value':[{'id':'a','createdDateTime':'2026-02-30T00:00:00Z'}]})
   r=p.execute('cybersecurity_timeline',dict(runs=[path]));self.assertEqual(r['unknownTimeCount'],1);self.assertEqual(r['data'],[])
   with self.assertRaises(p.Refusal):p.execute('cybersecurity_search',dict(runs=[path],query='x',limit=201))
   with self.assertRaises(p.Refusal):p.execute('cybersecurity_timeline',dict(runs=[path]*17))
if __name__=='__main__':unittest.main()
