"""Deterministic kill-chain evaluation and pcap probe checks, run in Registry CI."""
import importlib.util
import json
import struct
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/security/mithril-kill-chain/scripts'


def load_pcap(path, big_endian=False):
    """Build a classic pcap with DNS, TLS-SNI, HTTP-Host and beacon packets."""
    fmt_h = '>IHHiIII' if big_endian else '<IHHiIII'
    fmt_r = '>IIII' if big_endian else '<IIII'
    pack_h, pack_r = struct.pack, struct.pack

    def ipv4addrs(src, dst):
        return pack_h('!II', int.from_bytes(bytes(map(int, src.split('.'))), 'big'),
                      int.from_bytes(bytes(map(int, dst.split('.'))), 'big'))

    def iphdr(src, dst, proto, payload):
        return pack_h('!BBHHHBBH', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0) \
            + ipv4addrs(src, dst) + payload

    def tcp(sport, dport, payload, seq=1):
        return pack_h('!HHIIBBHHH', sport, dport, seq, 0, 0x50, 0x10, 65535, 0, 0) + payload

    def udp(sport, dport, payload):
        return pack_h('!HHHH', sport, dport, 8 + len(payload), 0) + payload

    def dns_query(name):
        q = b''
        for part in name.split('.'):
            q += bytes([len(part)]) + part.encode()
        q += b'\x00\x00\x01\x00\x01'
        return pack_h('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0) + q

    def client_hello(host):
        h = host.encode()
        ext_data = pack_h('!H', 1 + 2 + len(h)) + b'\x00' + pack_h('!H', len(h)) + h
        sni_ext = b'\x00\x00' + pack_h('!H', len(ext_data)) + ext_data
        hello = pack_h('!H', 0x0303) + bytes(32) + b'\x00' + pack_h('!H', 4) \
            + b'\x13\x01\x13\x02' + b'\x01\x00' + pack_h('!H', len(sni_ext)) + sni_ext
        return b'\x16\x03\x01' + pack_h('!H', 1 + len(hello)) \
            + b'\x01' + pack_h('!H', len(hello)) + hello

    eth = b'\x00\xaa\xbb\xcc\xdd\xee' + b'\x00\x11\x22\x33\x44\x55' + b'\x08\x00'

    def frame(proto, src, dst, payload):
        return eth + iphdr(src, dst, proto, payload)

    packets = [(100.0, frame(17, '10.0.0.2', '8.8.8.8', udp(53001, 53, dns_query('beacon.evil.example')))),
               (200.0, frame(6, '10.0.0.2', '93.184.216.34', tcp(53002, 443, client_hello('api.evil.example')))),
               (300.0, frame(6, '10.0.0.2', '93.184.216.34',
                             tcp(53003, 80, b'GET /a.html HTTP/1.1\r\nHost: pages.evil.example\r\n\r\n')))]
    packets += [(1000.0 + i * 30.0, frame(6, '10.0.0.2', '198.51.100.7', tcp(53004, 8443, b'x')))
                for i in range(6)]
    out = bytearray(pack_h(fmt_h, 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for t, f in packets:
        secs, frac = divmod(t, 1.0)
        out += pack_r(fmt_r, int(secs), int(frac * 1_000_000), len(f), len(f)) + f
    path.write_bytes(bytes(out))


spec = importlib.util.spec_from_file_location('killchain', SCRIPTS / 'killchain.py')
assert spec is not None
killchain = importlib.util.module_from_spec(spec)
spec.loader.exec_module(killchain)


class PhaseTest(unittest.TestCase):
    def test_seven_phases_and_registry_references(self):
        result = killchain.execute('killchain_phases', {})
        self.assertEqual([p['id'] for p in result['phases']], list(range(1, 8)))
        self.assertEqual(result['phases'][5]['key'], 'command-and-control')
        self.assertEqual(result['phases'][5]['ja'], '遠隔操作')
        self.assertTrue(all(p['evidenceTypes'] and p['registryEntries'] for p in result['phases']))
        with self.assertRaises(killchain.KillChainFailure):
            killchain.execute('killchain_phases', {'extra': 1})
        with self.assertRaises(killchain.KillChainFailure):
            killchain.execute('killchain_unknown', {})

    def test_evaluate_covered_partial_absent(self):
        result = killchain.evaluate({'caseId': 'case-01', 'phases': [
            {'phase': 'reconnaissance', 'evidence': [{'type': 'domain-asset', 'source': 'osint'}]},
            {'phase': 'installation', 'evidence': [{'type': 'unknown-type'}]},
        ]})
        self.assertEqual(result['verdict'], 'first-covered-phase-1')
        self.assertEqual(result['coveredPhases'], [1])
        self.assertEqual(result['partialPhases'], [5])
        self.assertEqual(result['absentPhases'], [2, 3, 4, 6, 7])
        self.assertIn('not an attack attribution', result['note'])

    def test_evaluate_no_covered_phase(self):
        result = killchain.evaluate({'phases': []})
        self.assertEqual(result['verdict'], 'no-covered-phase')
        self.assertEqual(result['absentPhases'], [1, 2, 3, 4, 5, 6, 7])
        self.assertEqual(result['absentPhaseKeys'], [p['key'] for p in killchain.PHASES])
        self.assertIsNone(result['caseId'])

    def test_evaluate_rejects_malformed(self):
        bad = [
            {'phases': [{'phase': 'nope'}]},
            {'phases': [{'phase': 'reconnaissance', 'evidence': [{'type': 'x', 'bogus': 1}]}]},
            {'phases': [{'phase': 'delivery'}, {'phase': 'delivery'}]},
            {'caseId': 5, 'phases': []},
            {'phases': [{'phase': 'delivery', 'evidence': [{'type': 'url-observation'}] * 101}]},
            {'phases': [{'phase': 'delivery', 'evidence': [{'type': 'url-observation', 'source': 'x' * 513}]}]},
            {'phases': 'delivery'},
            None,
        ]
        for payload in bad:
            with self.assertRaises(killchain.KillChainFailure, msg=repr(payload)):
                killchain.evaluate(payload)


class PcapTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(__file__).resolve().parent
        self.le = self.tmp / 'killchain_fixture_le.pcap'
        self.be = self.tmp / 'killchain_fixture_be.pcap'
        load_pcap(self.le)
        load_pcap(self.be, big_endian=True)
        self.addCleanup(self.le.unlink, missing_ok=True)
        self.addCleanup(self.be.unlink, missing_ok=True)

    def test_little_endian(self):
        result = killchain.pcap_probe(str(self.le))
        self.assertEqual(result['dnsQueries'], ['beacon.evil.example'])
        self.assertEqual(result['tlsSni'], ['api.evil.example'])
        self.assertEqual(result['httpHosts'], ['pages.evil.example'])
        beacons = result['beaconCandidates']
        self.assertEqual(len(beacons), 1)
        self.assertEqual(beacons[0]['src'], '10.0.0.2')
        self.assertEqual(beacons[0]['dst'], '198.51.100.7')
        self.assertEqual(beacons[0]['srcPort'], 53004)
        self.assertEqual(beacons[0]['dstPort'], 8443)
        self.assertEqual(beacons[0]['medianInterval'], 30.0)
        self.assertLessEqual(beacons[0]['cv'], 0.25)
        self.assertEqual(result['packets'], 9)

    def test_big_endian(self):
        result = killchain.pcap_probe(str(self.be))
        self.assertEqual(result['dnsQueries'], ['beacon.evil.example'])
        self.assertEqual(result['tlsSni'], ['api.evil.example'])
        self.assertEqual(len(result['beaconCandidates']), 1)

    def test_rejects_unsupported(self):
        with self.assertRaises(killchain.KillChainFailure):
            killchain.pcap_probe(str(Path(__file__)))
        missing = self.tmp / 'killchain_missing.pcap'
        with self.assertRaises(killchain.KillChainFailure):
            killchain.execute('killchain_pcap_probe', {'path': str(missing)})


class BridgeTest(unittest.TestCase):
    def test_initialize_and_tools_list(self):
        result = killchain.rpc({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                                'params': {'protocolVersion': '2025-06-18'}})
        self.assertEqual(result['result']['protocolVersion'], '2025-06-18')
        self.assertEqual(result['result']['serverInfo']['name'], 'mithril-kill-chain-local')
        result = killchain.rpc({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'})
        names = {t['name'] for t in result['result']['tools']}
        self.assertEqual(names, {'killchain_phases', 'killchain_evaluate', 'killchain_pcap_probe'})
        self.assertTrue(all(t['annotations']['readOnlyHint'] for t in result['result']['tools']))

    def test_unknown_method_and_notification(self):
        self.assertEqual(killchain.rpc({'jsonrpc': '2.0', 'id': 9, 'method': 'nope'})['error']['code'], -32601)
        self.assertIsNone(killchain.rpc({'jsonrpc': '2.0', 'method': 'notifications/initialized'}))
        self.assertEqual(killchain.rpc({'jsonrpc': '1.0', 'id': 1, 'method': 'ping'})['error']['code'], -32600)

    def test_stdio_round_trip(self):
        script = SCRIPTS / 'killchain.py'
        fixture = Path(__file__).resolve().parent / 'killchain_stdio_fixture.pcap'
        load_pcap(fixture)
        try:
            lines = [
                json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}}),
                json.dumps({'jsonrpc': '2.0', 'method': 'notifications/initialized'}),
                json.dumps({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
                            'params': {'name': 'killchain_pcap_probe', 'arguments': {'path': str(fixture)}}}),
                json.dumps({'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
                            'params': {'name': 'killchain_evaluate',
                                       'arguments': {'phases': [{'phase': 'command-and-control',
                                                                  'evidence': [{'type': 'pcap-probe'}]}]}}}),
            ]
            result = subprocess.run([sys.executable, str(script), '--mcp'],
                                    input=('\n'.join(lines) + '\n').encode(),
                                    capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            out = [json.loads(line) for line in result.stdout.decode().splitlines()]
            self.assertEqual([item['id'] for item in out], [1, 2, 3])
            probe = json.loads(out[1]['result']['content'][0]['text'])
            self.assertFalse(out[1]['result']['isError'])
            self.assertEqual(probe['tlsSni'], ['api.evil.example'])
            self.assertFalse(out[2]['result']['isError'])
            self.assertIn('first-covered-phase-6', out[2]['result']['content'][0]['text'])
        finally:
            fixture.unlink(missing_ok=True)

    def test_cli_tool_dispatch(self):
        script = SCRIPTS / 'killchain.py'
        result = subprocess.run([sys.executable, str(script), '--tool', 'killchain_phases'],
                                capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"phases"', result.stdout.decode())
        result = subprocess.run([sys.executable, str(script), '--tool', 'killchain_evaluate', '--input', '-'],
                                input=json.dumps({'phases': []}).encode(), capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('no-covered-phase', result.stdout.decode())
        self.assertIn('weaponization', result.stdout.decode())
        result = subprocess.run([sys.executable, str(script), '--tool', 'killchain_evaluate', '--input', '-'],
                                input=json.dumps({'caseId': 5, 'phases': []}).encode(), capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 1, result.stdout)
        with self.assertRaises(killchain.KillChainFailure):
            killchain.execute('killchain_evaluate', {'caseId': 5, 'phases': []})


if __name__ == '__main__':
    unittest.main()
