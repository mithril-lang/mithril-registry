import json
from pathlib import Path
import unittest
import build_index
ROOT=Path(__file__).resolve().parents[1]
class MessageReportRegistryTest(unittest.TestCase):
    def test_executable_workflow_has_immutable_client_and_no_automatic_reward_authority(self):
        index,_=build_index.build()
        entries=[e for e in index['entries'] if e['id']=='mithril-message-report']
        self.assertEqual(len(entries),1)
        d=json.loads((ROOT/'workflows/mithril-message-report/manifest.json').read_text())
        self.assertEqual(d['artifact']['entry'],'bin/mithril-message-report.mjs')
        self.assertEqual(d['execution']['maxTasks'],1)
        self.assertFalse(d['execution']['retryUnknown'])
        self.assertEqual(d['permissions'],['network:api.mithril.fund','knowledge:read','knowledge:write'])
        self.assertFalse(d['readiness']['rewardBudgetActivated'])
        self.assertFalse(d['readiness']['installedNativeQualified'])
        self.assertNotIn('knowledge:review',d['permissions'])
