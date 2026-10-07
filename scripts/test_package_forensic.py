import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('package_forensic',ROOT/'scripts/package_forensic.py')
package=importlib.util.module_from_spec(spec); spec.loader.exec_module(package)

class PackagingTests(unittest.TestCase):
    def test_deterministic_source_kit_inventory_and_no_keys(self):
        with tempfile.TemporaryDirectory() as root:
            first=Path(root)/'one.zip'; second=Path(root)/'two.zip'
            a=package.build(first); b=package.build(second)
            self.assertEqual(a['sha256'],b['sha256'])
            self.assertFalse(a['offlineDependencies'])
            with zipfile.ZipFile(first) as archive:
                self.assertFalse(any(name.endswith('.raw') for name in archive.namelist()))
                inventory=json.loads(archive.read('distribution.json'))
                for item in inventory['files']:
                    data=archive.read(item['path'])
                    self.assertEqual(len(data),item['bytes']); self.assertEqual(package.sha(data),item['sha256'])
            with self.assertRaisesRegex(ValueError,'output_exists'): package.build(first)

    def test_missing_or_unapproved_wheels_are_not_offline_ready(self):
        with tempfile.TemporaryDirectory() as root:
            wheels=Path(root)/'wheels'; wheels.mkdir()
            with self.assertRaisesRegex(ValueError,'incomplete_wheelhouse'): package.build(Path(root)/'kit.zip',wheels)
            (wheels/'signer.raw').write_bytes(b'not a wheel')
            with self.assertRaisesRegex(ValueError,'wheel_files_only'): package.build(Path(root)/'kit.zip',wheels)

    def test_wrong_dependency_version_refused(self):
        with tempfile.TemporaryDirectory() as root:
            wheels=Path(root)/'wheels'; wheels.mkdir()
            with zipfile.ZipFile(wheels/'cryptography-0.0.0-test.whl','w') as wheel:
                wheel.writestr('cryptography-0.0.0.dist-info/METADATA','Name: cryptography\nVersion: 0.0.0\n')
            with self.assertRaisesRegex(ValueError,'unexpected_wheel'): package.build(Path(root)/'kit.zip',wheels)

if __name__=='__main__': unittest.main()
