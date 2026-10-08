import copy
import json
import tempfile
import unittest
from pathlib import Path
from solution_catalog import build
from install_agency_profiles import install
ROOT = Path(__file__).resolve().parents[1]

class SolutionsTest(unittest.TestCase):
    def test_catalog_routing_and_availability(self):
        data = build(ROOT, [e['id'] for e in json.loads((ROOT/'index.json').read_text())['entries']])
        self.assertEqual(len(data['solutions']), 12)
        self.assertEqual(len(data['botProfiles']), 15)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root/'solutions').mkdir()
            broken = copy.deepcopy(data)
            broken['solutions'][0]['registryEntries'] = ['mithril-forensic-evidence']
            (root/'solutions/agency.json').write_text(json.dumps(broken))
            with self.assertRaisesRegex(ValueError, 'planned'):
                build(root)
    def test_install_preserves_selection_and_rejects_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            (home/'active_profile').write_text('default\n')
            install(ROOT, home)
            self.assertFalse((home/'profiles').exists())
            install(ROOT, home, True)
            install(ROOT, home, True)
            self.assertEqual((home/'active_profile').read_text(), 'default\n')
            self.assertEqual(len(list((home/'profiles').iterdir())),15)
            target=home/'profiles/mithril-contact-cyber/SOUL.md'
            target.write_text('user customization')
            with self.assertRaisesRegex(ValueError, 'preserving'):
                install(ROOT, home, True)
            self.assertEqual(target.read_text(),'user customization')
    def test_refuses_symlink_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp); (home/'destination').mkdir()
            (home/'profiles').symlink_to(home/'destination',target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'symlink'):
                install(ROOT,home,True)
