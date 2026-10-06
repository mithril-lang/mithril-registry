import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT/'skills/security/mithril-cybersecurity-products/scripts/products.py'
spec = importlib.util.spec_from_file_location('cyberproducts', SCRIPT)
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
FIXTURES = {
 'paloalto-cortex-xdr': {'reply': {'alerts': [{'alert_id':'1','name':'fixture','severity':'high','detection_timestamp':42}], 'total_count':101}},
 'wiz': {'data': {'issues': {'nodes':[{'id':'1','description':'fixture','severity':'HIGH','createdAt':'2026-10-06T00:00:00Z'}], 'pageInfo':{'hasNextPage':True}}}},
 'trendmicro-vision-one': {'items':[{'id':'1','model':'fixture','severity':'high','createdDateTime':'2026-10-06T00:00:00Z'}], 'nextLink':'https://evil.invalid/steal'}
}

class ProductTests(unittest.TestCase):
 def test_retains_raw_bytes_digest_and_permissions_for_all_products(self):
  import hashlib
  with tempfile.TemporaryDirectory() as root:
   for product, data in FIXTURES.items():
    raw=json.dumps(data).encode(); output=Path(root)/product
    receipt=p.persist(product,raw,output,'operator-export')
    self.assertEqual((output/'source.json').read_bytes(),raw)
    self.assertEqual(receipt['sourceSha256'],hashlib.sha256(raw).hexdigest())
    self.assertEqual(json.loads((output/'findings.json').read_text())['findings'][0]['vendorId'],'1')
    self.assertEqual(output.stat().st_mode & 0o777,0o700)
    self.assertEqual((output/'source.json').stat().st_mode & 0o777,0o600)
    with self.assertRaises(FileExistsError): p.persist(product,raw,output,'operator-export')
 def test_does_not_claim_clearance_or_complete_coverage(self):
  r=p.normalize('trendmicro-vision-one',b'{"items":[]}')
  self.assertIn('empty-is-not-clearance',r['gaps'])
  self.assertIn('coverage-not-complete',r['gaps'])
  self.assertEqual(p.normalize('paloalto-cortex-xdr',json.dumps(FIXTURES['paloalto-cortex-xdr']).encode())['findings'][0]['reportedTime'],42)
 def test_rejects_error_payloads_duplicates_and_limits(self):
  for raw in [b'{"items":[],"error":"failed"}', b'{"items":[],"items":[]}', b'{"items":[null]}', b'{"items":NaN}', b'{}',b'x'*(p.MAX_BYTES+1)]:
   with self.assertRaises((p.Refusal, ValueError)): p.normalize('trendmicro-vision-one',raw)
  with self.assertRaises(p.Refusal): p.normalize('wiz',json.dumps({'data':{'issues':{'nodes':[{}]*1001}}}).encode())
 def test_fixed_vendor_requests_and_credentials(self):
  with patch.dict(os.environ, FIXTURE_KEY='synthetic-secret',FIXTURE_ID='1'):
   cortex=dict(product='paloalto-cortex-xdr',origin='https://api-fixture.xdr.us.paloaltonetworks.com',authMode='basic',tokenEnv='FIXTURE_KEY',keyIdEnv='FIXTURE_ID',offset=100)
   req=p.request_for(cortex)
   self.assertEqual(req.method,'POST'); self.assertEqual(json.loads(req.data)['request_data'],{'search_from':100,'search_to':200})
   self.assertEqual(req.get_header('Authorization'),'synthetic-secret')
   for origin in ['https://evil.invalid','http://api.xdr.trendmicro.com','https://api.xdr.trendmicro.com/','https://api.xdr.trendmicro.com.evil.invalid','https://user@api.xdr.trendmicro.com']:
    with self.assertRaises(p.Refusal): p.request_for(dict(product='trendmicro-vision-one',origin=origin,tokenEnv='FIXTURE_KEY'))
   req=p.request_for(dict(product='trendmicro-vision-one',origin='https://api.xdr.trendmicro.com',tokenEnv='FIXTURE_KEY'))
   self.assertEqual(req.method,'GET'); self.assertEqual(req.full_url,'https://api.xdr.trendmicro.com/v3.0/workbench/alerts')
   cortex['authMode']='advanced'
   with self.assertRaises(p.Refusal): p.request_for(cortex)
 def test_bounded_transport_and_never_follows_next_link(self):
  from http.server import BaseHTTPRequestHandler,HTTPServer
  from threading import Thread
  import urllib.request
  seen=[]
  class Handler(BaseHTTPRequestHandler):
   def log_message(self,*args): pass
   def do_GET(self):
    seen.append(self.path);self.send_response(200);self.end_headers();self.wfile.write(json.dumps(FIXTURES['trendmicro-vision-one']).encode())
  server=HTTPServer(('127.0.0.1',0),Handler); thread=Thread(target=server.serve_forever);thread.start()
  class Opener:
   def open(self,req,timeout):
    # Test-only mapping to an owned loopback simulator; production origins stay strict.
    local=urllib.request.Request(f'http://127.0.0.1:{server.server_port}'+req.selector,headers=req.headers)
    return real.open(local,timeout=timeout)
  try:
   with patch.dict(os.environ,FIXTURE_KEY='synthetic-secret'),patch.object(p.urllib.request,'build_opener',return_value=Opener()):
    raw=p.collect(dict(product='trendmicro-vision-one',origin='https://api.xdr.trendmicro.com',tokenEnv='FIXTURE_KEY'))
    self.assertEqual(json.loads(raw)['nextLink'],'https://evil.invalid/steal')
   self.assertEqual(seen,['/v3.0/workbench/alerts'])
  finally: server.shutdown();thread.join();server.server_close()
 def test_network_opt_in_and_wiz_live_refused(self):
  with self.assertRaises(p.Refusal):p.execute('cybersecurity_collect',{'policy':'missing','output':'missing'})
  with self.assertRaises(p.Refusal):p.request_for({'product':'wiz'})
  with self.assertRaises(p.Refusal):p.NoRedirect().redirect_request(None,None,None,None,None,None)
 def test_stdio_mcp_import_and_ignored_write_notification(self):
  with tempfile.TemporaryDirectory() as root:
   source=Path(root)/'source.json';source.write_text(json.dumps(FIXTURES['wiz']))
   args={'product':'wiz','input':str(source),'output':str(Path(root)/'output')}
   messages=[{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-06-18'}},{'jsonrpc':'2.0','id':2,'method':'tools/list'},{'jsonrpc':'2.0','method':'tools/call','params':{'name':'cybersecurity_import','arguments':args}},{'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'cybersecurity_import','arguments':args}}]
   run=subprocess.run(['python3',str(SCRIPT),'--mcp'],input='\n'.join(map(json.dumps,messages))+'\n',text=True,capture_output=True,timeout=10)
   self.assertEqual(run.returncode,0); replies=[json.loads(v) for v in run.stdout.splitlines()]
   self.assertEqual(len(replies),3);self.assertEqual(len(replies[1]['result']['tools']),2)
   self.assertFalse(replies[2]['result']['isError']);self.assertEqual(replies[2]['result']['structuredContent']['count'],1)

real = p.urllib.request.build_opener(p.urllib.request.ProxyHandler({}))
if __name__=='__main__':unittest.main()
