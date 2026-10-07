import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('brand', Path(__file__).with_name('brand.py'))
brand = importlib.util.module_from_spec(spec)
spec.loader.exec_module(brand)


class BridgeTest(unittest.TestCase):
    def test_offline_initialization_and_read_only_discovery(self):
        result = brand.rpc({'jsonrpc':'2.0','id':1,'method':'initialize'})
        self.assertEqual(result['result']['serverInfo']['name'],'mithril-brand-protection-local')
        result = brand.rpc({'jsonrpc':'2.0','id':2,'method':'tools/list'})
        self.assertEqual({t['name'] for t in result['result']['tools']},{'brand_list','brand_get'})
        self.assertEqual(len(brand.rpc({'jsonrpc':'2.0','id':3,'method':'tools/list'},True)['result']['tools']),5)

    def test_notifications_and_disabled_writes_never_transfer(self):
        with patch.object(brand,'request_api') as request:
            self.assertIsNone(brand.rpc({'jsonrpc':'2.0','method':'tools/call','params':{'name':'brand_observe','arguments':{}}},True))
            result = brand.rpc({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'brand_observe','arguments':{}}})
            self.assertTrue(result['result']['isError'])
            request.assert_not_called()

    def test_exact_payload_and_operation_id_are_forwarded_once(self):
        arguments={'operationId':'retained-operation','brandId':'retained-brand'}
        with patch.object(brand,'request_api',return_value={'id':'receipt'}) as request:
            self.assertEqual(brand.execute('brand_observe',arguments,True),{'id':'receipt'})
            request.assert_called_once_with('/v1/brand/observations',arguments)

    def test_credential_and_redirect_fail_closed(self):
        with patch.dict(brand.os.environ,{},clear=True):
            with self.assertRaises(brand.BrandFailure):
                brand.request_api('/v1/brand/profiles')
        with self.assertRaises(brand.BrandFailure):
            brand.NoRedirect().redirect_request(None,None,302,'',{},'https://other.test')

    def test_stdio_notification_and_malformed_input(self):
        result=subprocess.run([sys.executable,str(Path(__file__).with_name('brand.py')),'--mcp'],input=b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"brand_observe"}}\n{bad}\n{"jsonrpc":"2.0","id":7,"method":"ping"}\n',capture_output=True)
        self.assertEqual(result.returncode,0)
        self.assertEqual(len(result.stdout.splitlines()),2)
        self.assertNotIn(b'Authorization',result.stdout)


if __name__=='__main__':
    unittest.main()
