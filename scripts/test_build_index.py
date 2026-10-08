"""Registry trust-boundary checks for executable and non-executable entries."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import build_index


class RegistryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for dirname in ("skills", "mcp", "tools", "plugins", "agents", "workflows", "scripts"):
            shutil.copytree(build_index.ROOT / dirname, self.root / dirname)
        self.root_patch = patch.object(build_index, "ROOT", self.root)
        self.skills_patch = patch.object(build_index, "SKILLS", self.root / "skills")
        self.root_patch.start()
        self.skills_patch.start()

    def tearDown(self):
        self.skills_patch.stop()
        self.root_patch.stop()
        self.temp.cleanup()

    def write_manifest(self, relative, change):
        path = self.root / relative
        data = json.loads(path.read_text())
        change(data)
        path.write_text(json.dumps(data))

    def test_public_tools_are_not_standalone_installs(self):
        index, categories = build_index.build()
        expected = len(list((self.root / "skills").glob("*/*/SKILL.md"))) + sum(
            len(list((self.root / directory).glob("*/manifest.json")))
            for directory in build_index.MANIFEST_DIRS.values()
        )
        self.assertEqual(index["count"], expected)
        self.assertEqual({entry["type"] for entry in index["entries"]}, {"skill", "mcp", "tool", "plugin", "agent", "workflow"})
        self.assertEqual(sum(entry["type"] == "skill" for entry in index["entries"]),
                         len(list((self.root / "skills").glob("*/*/SKILL.md"))))
        self.assertTrue(all(entry["installable"] for entry in index["entries"] if entry["type"] in {"mcp", "plugin"}))
        self.assertTrue(all(not entry["installable"] for entry in index["entries"] if entry["type"] == "tool"))
        self.assertEqual(sum(kind["count"] for kind in categories["types"]), expected)

    def test_system_one_has_all_five_surfaces_with_one_runtime_commit(self):
        index, _ = build_index.build()
        rows = [r for r in index['entries'] if r['id'] in ('mithril-system-one', 'mithril-tasks')]
        self.assertEqual({r['type'] for r in rows}, {'skill','mcp','agent','workflow','plugin'})
        self.assertEqual(len({r['artifact']['commit'] for r in rows if 'artifact' in r}), 1)
        mcp = next(r for r in rows if r['type'] == 'mcp')
        self.assertEqual(mcp['connection']['transport'], 'stdio')
        self.assertNotIn('url', mcp['connection'])

    def test_public_review_composes_five_surfaces_and_independent_profile(self):
        index, _ = build_index.build()
        rows = [r for r in index['entries'] if r['id'] == 'mithril-public-review']
        self.assertEqual({r['type'] for r in rows}, {'skill', 'mcp', 'agent', 'workflow', 'plugin'})
        pins = {r['artifact']['commit'] for r in rows if 'artifact' in r}
        self.assertEqual(len(pins), 1)
        agent = next(r for r in rows if r['type'] == 'agent')
        self.assertEqual(agent['botProfile']['id'], 'mithril-public-code-review')
        composition = json.loads((self.root / 'skills/security/mithril-public-review/integration.json').read_text())
        self.assertEqual(composition['runtimeArtifact']['commit'], next(iter(pins)))
        self.assertTrue(composition['readiness']['liveModelConversation'])
        self.assertFalse(composition['qualification']['credentialDistributed'])
        self.assertFalse(composition['readiness']['githubWrites'])
        mcp = json.loads((self.root / 'mcp/mithril-public-review/manifest.json').read_text())
        self.assertEqual(mcp['env'], {})
        self.assertEqual(mcp['tools'][0]['authentication'], 'none')
        business = next(t for t in mcp['tools'] if t['name'] == 'mithril_business_process_review')
        self.assertEqual((business['authentication'], business['effect']), ('none', 'read'))
        self.assertTrue(composition['readiness']['bpmnBusinessProcessOntology'])
        self.assertFalse(composition['readiness']['operationalBusinessControlsAttested'])
        self.assertIn('mithril_business_process_review', agent['tools'])
        workflow = json.loads((self.root / 'workflows/mithril-public-review/manifest.json').read_text())
        self.assertEqual(workflow['entry'], 'bin/mithril-public-review.mjs')

    def test_public_review_refuses_credentials_and_escaping_profile_files(self):
        self.write_manifest('agents/mithril-public-review/manifest.json', lambda d: d.update(env={'GITHUB_TOKEN': 'value'}))
        with self.assertRaisesRegex(ValueError, 'credential reference'):
            build_index.build()
        self.write_manifest('agents/mithril-public-review/manifest.json', lambda d: d.update(env={}))
        self.write_manifest('agents/mithril-public-review/manifest.json', lambda d: d['botProfile'].update(config='../config.yaml'))
        with self.assertRaisesRegex(ValueError, 'must be packaged'):
            build_index.build()

    def test_executable_entries_refuse_mutable_refs_and_unbounded_workflows(self):
        self.write_manifest('agents/mithril-system-one/manifest.json', lambda d: d['artifact'].update(commit='main'))
        with self.assertRaisesRegex(ValueError, 'full lowercase Git commit'):
            build_index.build()

    def test_workflow_rejects_retrying_unknown_outcomes(self):
        self.write_manifest('workflows/mithril-system-one/manifest.json', lambda d: d['execution'].update(retryUnknown=True))
        with self.assertRaisesRegex(ValueError, 'bounded stop-on-failure'):
            build_index.build()

    def test_stdio_cannot_choose_an_arbitrary_command_or_claim_a_hosted_endpoint(self):
        self.write_manifest('mcp/mithril-system-one/manifest.json', lambda d: d.update(command='sh'))
        with self.assertRaisesRegex(ValueError, 'Node arguments'):
            build_index.build()

    def test_runtime_dependency_cache_does_not_change_distribution_checksum(self):
        folder = self.root / 'skills/security/mithril-security-suite'
        before = build_index.package_checksum(folder)
        cache = folder / '.nbb/.cache/test-runtime'
        cache.mkdir(parents=True, exist_ok=True)
        (cache / 'dependency.jar').write_bytes(b'local cache')
        self.assertEqual(before, build_index.package_checksum(folder))

    def test_plugin_has_pinned_artifact_and_tested_client(self):
        index, _ = build_index.build()
        plugins = {entry["id"]: entry for entry in index["entries"] if entry["type"] == "plugin"}
        self.assertRegex(plugins["mithril-app"]["artifact"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(plugins["hermes-zap-proxy"]["artifact"]["commit"], r"^[0-9a-f]{40}$")
        self.assertEqual(plugins["hermes-zap-proxy"]["requirements"]["commands"], ["clojure"])
        self.assertEqual(plugins["hermes-zap-proxy"]["compatibility"]["clients"][0]["tested"], "0.21.4")
        self.assertRegex(plugins["mithril-data-catalog"]["artifact"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(plugins["mithril-data-catalog"]["tools"], ["mithril_catalog_publish"])

    def test_data_catalog_skill_mcp_and_plugin_are_kept_together(self):
        index, _ = build_index.build()
        entries = {(entry["type"], entry["id"]): entry for entry in index["entries"]}
        self.assertIn(("skill", "mithril-data-catalog"), entries)
        self.assertIn(("mcp", "mithril-data-catalog"), entries)
        self.assertIn(("plugin", "mithril-data-catalog"), entries)
        mcp = entries[("mcp", "mithril-data-catalog")]
        self.assertEqual(mcp["connection"], {
            "transport": "streamable-http",
            "url": "https://mithril-api.cloud-kotoba.workers.dev/v1/internal/data-catalog/mcp",
            "authentication": "per-tool",
        })
        self.assertEqual(set(mcp["permissions"]), {"network:mithril-api.cloud-kotoba.workers.dev", "catalog:ingest"})

    def test_git_plugin_requires_full_commit(self):
        self.write_manifest(
            "plugins/hermes-zap-proxy/manifest.json",
            lambda data: data["artifact"].update(commit="main"),
        )
        with self.assertRaisesRegex(ValueError, "full lowercase Git commit"):
            build_index.build()

    def test_integration_definition_and_skill_versions_must_agree(self):
        path = self.root / 'skills/productivity/mithril-enterprise-integrations/integration.json'
        data = json.loads(path.read_text())
        data['version'] = '0.2.0'
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'integration skill and definition versions differ'):
            build_index.build()

    def test_tool_catalog_binding_must_be_https(self):
        self.write_manifest("tools/knowledge-search/manifest.json", lambda data: data["catalog"].update(url="http://mithril.fund/.well-known/mcp.json"))
        with self.assertRaisesRegex(ValueError, "expected an HTTPS URL"):
            build_index.build()

    def test_no_entry_advertises_the_nonexistent_apex_mcp_endpoint(self):
        index, _ = build_index.build()
        self.assertNotIn("https://mithril.fund/mcp", json.dumps(index))
        self.assertFalse(any(entry["id"] == "mithril-cloud" for entry in index["entries"]))

    def test_tool_names_are_mithril_native(self):
        index, _ = build_index.build()
        text = json.dumps(
            [entry for entry in index["entries"] if entry["type"] == "tool"]
        ).lower()
        self.assertNotIn("kotoba", text)

    def test_contributions_mcp_keeps_private_and_review_authority_separate(self):
        index, _ = build_index.build()
        entry = next(e for e in index["entries"] if e["id"] == "mithril-knowledge-contributions")
        self.assertEqual(entry["connection"]["url"], "https://api.mithril.fund/v1/knowledge/mcp")
        self.assertEqual(set(entry["permissions"]), {"network:api.mithril.fund", "knowledge:read", "knowledge:write"})
        manifest = json.loads((self.root / "mcp/mithril-knowledge-contributions/manifest.json").read_text())
        tools = {tool["name"]: tool for tool in manifest["tools"]}
        self.assertEqual(set(tools), {"mithril_knowledge_" + name for name in (
            "history", "contributor_summary", "submission_status", "submit", "withdraw", "appeal", "profile"
        )})
        self.assertTrue(all(t["authentication"] == "personal-api-token" for t in tools.values()))
        self.assertEqual(tools["mithril_knowledge_submit"]["effect"], "write")
        self.assertEqual(tools["mithril_knowledge_submission_status"]["effect"], "read")

    def test_mcp_endpoint_must_be_https(self):
        self.write_manifest("mcp/mithril-graph/manifest.json", lambda data: data.update(url="http://graph.mithril.fund/mcp"))
        with self.assertRaisesRegex(ValueError, "expected an HTTPS URL"):
            build_index.build()


if __name__ == "__main__":
    unittest.main()
