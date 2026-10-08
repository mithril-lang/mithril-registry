import json
from pathlib import Path
import unittest
import build_index

ROOT = Path(__file__).resolve().parents[1]


class TermsRegistryTest(unittest.TestCase):
    def test_importable_surfaces_share_immutable_runtime_and_private_boundaries(self):
        index, _ = build_index.build()
        rows = [r for r in index['entries'] if r['id'] == 'mithril-terms-review']
        self.assertEqual({r['type'] for r in rows}, {'skill','agent','workflow','plugin'})
        pins = {r['artifact']['commit'] for r in rows if 'artifact' in r}
        self.assertEqual(len(pins), 1)
        composition = json.loads((ROOT / 'skills/productivity/mithril-terms-review/integration.json').read_text())
        self.assertEqual(composition['runtimeArtifact']['commit'], next(iter(pins)))
        self.assertFalse(composition['readiness']['liveModelConversation'])
        self.assertFalse(composition['readiness']['automaticKnowledgePublication'])
        for folder, mode, limit in [('agents','--stdin',1),('workflows','--workflow',3)]:
            d = json.loads((ROOT / folder / 'mithril-terms-review/manifest.json').read_text())
            self.assertEqual(d['args'][-1], mode)
            self.assertEqual(d['execution']['maxTasks'], limit)
            self.assertFalse(d['execution']['retryUnknown'])
            self.assertEqual(d['env'], {})
