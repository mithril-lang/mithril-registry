// Run with an installed SDK directory: node scripts/verify_context_mcp.mjs /path/to/node_modules/@modelcontextprotocol/sdk
// No vendor connection or credential is used. SDK dependencies are validation-only.
import assert from 'node:assert/strict';
import {mkdtemp, writeFile, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {resolve, join} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
const sdk = resolve(process.argv[2]);
const {Client} = await import(pathToFileURL(join(sdk, 'dist/esm/client/index.js')).href);
const {StdioClientTransport} = await import(pathToFileURL(join(sdk, 'dist/esm/client/stdio.js')).href);
const script = fileURLToPath(new URL('../skills/security/mithril-cybersecurity-products/scripts/products.py', import.meta.url));
const root = await mkdtemp(join(tmpdir(), 'mithril-context-sdk-'));
const fixtures = {
  runzero: [{id: 'sdk-asset', addresses: ['8.8.8.8'], last_seen: 1791244800}],
  'okta-system-log': [{uuid: 'sdk-event', published: '2026-10-06T00:00:00Z', client: {ipAddress: '8.8.8.8'}}],
  'censys-platform': {result: {resource: {ip: '8.8.8.8'}}},
};
const client = new Client({name: 'mithril-context-validation', version: '1.0.0'});
try {
  await client.connect(new StdioClientTransport({command: 'python3', args: [script, '--mcp']}));
  const tools = await client.listTools();
  assert.equal(tools.tools.length, 7);
  assert.equal(tools.tools.some(t => t.name === 'cybersecurity_collect'), false);
  const resources = await client.listResources();
  assert.equal(resources.resources.length, 2);
  const contract = await client.readResource({uri: 'cybersecurity://contracts'});
  assert.equal(Object.keys(JSON.parse(contract.contents[0].text).products).length, 10);
  const coverage = await client.readResource({uri: 'cybersecurity://coverage'});
  assert.equal(JSON.parse(coverage.contents[0].text).status, 'incomplete-or-unknown');
  const runs = [];
  for (const [product, data] of Object.entries(fixtures)) {
    const input = join(root, product + '.json');
    const output = join(root, product);
    await writeFile(input, JSON.stringify(data));
    const imported = await client.callTool({name: 'cybersecurity_import', arguments: {product, input, output}});
    assert.equal(imported.isError, false);
    assert.equal(imported.structuredContent.coverage.retainedRecords, 1);
    const receipt = JSON.parse(await readFile(join(output, 'receipt.json'), 'utf8'));
    assert.equal(receipt.schemaVersion, 2);
    runs.push(output);
  }
  const result = await client.callTool({name: 'cybersecurity_correlate', arguments: {runs, address: '8.8.8.8'}});
  assert.equal(result.isError, false);
  assert.equal(result.structuredContent.total, 3);
  assert.equal(result.structuredContent.identityConclusion, 'not-established');
  const timeline = await client.callTool({name: 'cybersecurity_timeline', arguments: {runs}});
  assert.equal(timeline.structuredContent.unknownTimeCount, 1);
  const refused = await client.callTool({name: 'cybersecurity_collect', arguments: {policy: join(root, 'missing'), output: join(root, 'forbidden')}});
  assert.equal(refused.isError, true);
  await client.close();
  const enabled = new Client({name: 'mithril-opt-in-validation', version: '1.0.0'});
  try {
    await enabled.connect(new StdioClientTransport({command: 'python3', args: [script, '--mcp', '--allow-network']}));
    assert.equal((await enabled.listTools()).tools.length, 8);
  } finally {await enabled.close();}
  console.log(JSON.stringify({status: 'passed',transport: 'stdio',products: 10,localTools: 7,optInTools: 8,resources: 2,correlatedObservations: 3,vendorConnections: 0}));
} finally {
  await client.close();
  await rm(root, {recursive: true, force: true});
}
