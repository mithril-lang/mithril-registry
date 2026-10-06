"""Offline trust and composition contracts, including the real packaged CLI."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import build_index
import integration_catalog

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / integration_catalog.PACKAGE_PATH
planner = integration_catalog.load_planner(ROOT)


class EnterpriseIntegrationsTest(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((PACKAGE / "integration.json").read_text())

    def node(self, name):
        return next(node for node in self.data['components'] if node['id'] == name)

    def test_provider_plugins_cover_all_kinds_without_claiming_execution(self):
        for provider in self.data['providers']:
            result = planner.plan(self.data, provider + '-plugin')
            self.assertEqual({node['kind'] for node in result['components']}, planner.KINDS)
            self.assertFalse(result['executable'])
            self.assertIn('execution-adapter-not-shipped', result['blockedBy'])
            self.assertEqual({node['provider'] for node in result['components']}, {provider})
            positions = {node['id']: i for i, node in enumerate(result['components'])}
            for node in result['components']:
                for dependency in node['requires']:
                    self.assertLess(positions[dependency], positions[node['id']])

    def test_binding_targets_does_not_grant_execution(self):
        result = planner.plan(self.data, 'copilot-studio-plugin', {
            'principal': 'profile:test',
            'target': {'tenant': 'test-tenant', 'environment': 'test-env', 'agent': 'test-agent'},
        })
        self.assertEqual(result['blockedBy'], ['execution-adapter-not-shipped', 'live-qualification-not-verified'])
        self.assertFalse(result['executable'])

    def test_target_and_principal_are_part_of_plan_digest(self):
        original = {'principal': 'profile:a', 'target': {'workspace': 'org', 'account': 'a'}}
        changed = {'principal': 'profile:b', 'target': {'workspace': 'org', 'account': 'b'}}
        a = planner.plan(self.data, 'google-workspace-workflow', original)
        self.assertEqual(a, planner.plan(self.data, 'google-workspace-workflow', original))
        self.assertNotEqual(a['planDigest'], planner.plan(self.data, 'google-workspace-workflow', changed)['planDigest'])

    def test_credentials_and_unknown_target_fields_are_rejected(self):
        for context in [{'token': 'not-a-token'}, {'target': {'accessToken': 'not-a-token'}}]:
            with self.assertRaises(ValueError):
                planner.plan(self.data, 'google-workspace-plugin', context)

    def test_missing_dependency_and_cycles_are_rejected(self):
        self.node('google-workspace-agent')['requires'].append('missing')
        with self.assertRaisesRegex(ValueError, 'missing dependency'):
            planner.validate(self.data)
        self.node('google-workspace-agent')['requires'].remove('missing')
        self.node('google-workspace-skill')['requires'].append('google-workspace-plugin')
        with self.assertRaisesRegex(ValueError, 'cycle'):
            planner.validate(self.data)

    def test_cross_provider_authority_is_not_inherited(self):
        self.node('google-workspace-agent')['requires'].append('copilot-studio-skill')
        with self.assertRaisesRegex(ValueError, 'cross-provider'):
            planner.validate(self.data)

    def test_undeclared_permissions_and_approval_removal_are_rejected(self):
        workflow = self.node('google-workspace-workflow')
        workflow['steps'][-1]['permissions'].append('google:admin.write')
        with self.assertRaisesRegex(ValueError, 'exceed component permissions'):
            planner.validate(self.data)
        workflow['steps'][-1]['permissions'].remove('google:admin.write')
        workflow['steps'][-1]['approval'] = 'none'
        with self.assertRaisesRegex(ValueError, 'explicit approval'):
            planner.validate(self.data)

    def test_workflow_cycles_and_missing_steps_are_rejected(self):
        workflow = self.node('copilot-studio-workflow')
        workflow['steps'][0]['after'] = ['publish']
        with self.assertRaisesRegex(ValueError, 'cycle'):
            planner.validate(self.data)
        workflow['steps'][0]['after'] = ['absent']
        with self.assertRaisesRegex(ValueError, 'unknown component'):
            planner.validate(self.data)

    def test_mcp_binding_cannot_advertise_a_fabricated_endpoint(self):
        self.node('copilot-studio-mcp')['binding']['url'] = 'https://example.invalid/mcp'
        with self.assertRaisesRegex(ValueError, 'unverified MCP endpoint'):
            planner.validate(self.data)

    def test_unknown_component_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'unknown component'):
            planner.plan(self.data, 'not-registered')

    def test_unverified_provider_cannot_be_promoted_by_metadata(self):
        self.data['providers']['google-workspace']['qualification'] = 'verified'
        with self.assertRaisesRegex(ValueError, 'separate live evidence'):
            planner.validate(self.data)

    def test_index_keeps_blueprints_out_of_installable_runtime_types(self):
        index, _ = build_index.build()
        entry = next(row for row in index['entries'] if row['id'] == 'mithril-enterprise-integrations')
        self.assertEqual(entry['type'], 'skill')
        self.assertFalse(entry['integration']['runtimeReady'])
        self.assertEqual(set(entry['integration']['kinds']), planner.KINDS)
        self.assertFalse(any(row['id'] in {n['id'] for n in self.data['components']} for row in index['entries']))

    def test_real_cli_plans_and_rejects_invalid_context_without_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            context = Path(directory) / 'context.json'
            context.write_text(json.dumps({'principal': 'profile:a', 'target': {'account': 'a', 'workspace': 'org'}}))
            command = [sys.executable, str(PACKAGE / 'scripts/planner.py'), '--component', 'google-workspace-plugin', '--context', str(context)]
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            self.assertFalse(json.loads(result.stdout)['executable'])
            context.write_text(json.dumps({'credential': 'not-a-real-credential'}))
            rejected = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(rejected.returncode, 2)
            self.assertNotIn('not-a-real-credential', rejected.stderr)


if __name__ == '__main__':
    unittest.main()
