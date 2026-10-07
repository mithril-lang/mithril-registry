// Validation-only SDK dependency. Temporary synthetic keys/sources are removed.
import assert from 'node:assert/strict';
import {mkdtemp, rm} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
const sdk = resolve(process.argv[2]);
const python = process.env.MITHRIL_EVIDENCE_PYTHON || 'python3';
const {Client} = await import(pathToFileURL(join(sdk,'dist/esm/client/index.js')).href);
const {StdioClientTransport} = await import(pathToFileURL(join(sdk,'dist/esm/client/stdio.js')).href);
const scripts = fileURLToPath(new URL('../skills/security/mithril-forensic-evidence/scripts/',import.meta.url));
const root = await mkdtemp(join(tmpdir(),'mithril-forensic-sdk-'));
const clients = [];
try {
  const config = JSON.parse(execFileSync(python,[join(scripts,'acceptance.py'),'--prepare',root],{encoding:'utf8'}));
  async function connect(principal) {
    const client = new Client({name:'mithril-agency-evaluation',version:'1.0.0'});
    clients.push(client);
    await client.connect(new StdioClientTransport({command:python,args:[join(scripts,'evidence.py'),'--policy',config.policy,'--principal',principal,'--mcp']}));
    return client;
  }
  const examiner = await connect('examiner'); const reviewer = await connect('reviewer');
  assert.equal((await examiner.listTools()).tools.length,10);
  assert.equal((await reviewer.listTools()).tools.length,5);
  assert.equal((await reviewer.listResources()).resources.length,1);
  const capability = JSON.parse((await reviewer.readResource({uri:'evidence://capabilities'})).contents[0].text);
  assert.equal(capability.network,false);
  const call = async(client,name,args) => {
    const result = await client.callTool({name,arguments:args});
    assert.equal(result.isError,false); return result.structuredContent;
  };
  const caseId = 'training-case';
  await call(examiner,'evidence_case_create',{caseId,purpose:'Synthetic SDK acceptance'});
  const packageResult = await call(examiner,'evidence_pack',{caseId,evidenceId:'evidence-1',runs:config.runs,authorityRef:'synthetic-evaluation'});
  assert.equal(packageResult.files,9);
  await call(reviewer,'evidence_verify',{caseId,evidenceId:'evidence-1'});
  await call(examiner,'evidence_report',{caseId,reportId:'report-1',evidenceIds:['evidence-1'],question:'What was retained?'});
  await call(reviewer,'evidence_report_approve',{caseId,reportId:'report-1',notes:'Fixture sources and limitations checked'});
  const checkpoint = await call(examiner,'evidence_checkpoint',{caseId});
  const custody = await call(reviewer,'evidence_custody',{caseId,checkpoint});
  assert.equal(custody.unanchoredEvents,0);
  const forbidden = await reviewer.callTool({name:'evidence_pack',arguments:{caseId,evidenceId:'forbidden',runs:config.runs,authorityRef:'fixture'}});
  assert.equal(forbidden.isError,true);
  const crossCase = await reviewer.callTool({name:'evidence_inventory',arguments:{caseId:'other-case'}});
  assert.equal(crossCase.isError,true);
  console.log(JSON.stringify({status:'passed',transport:'stdio',examinerTools:10,reviewerTools:5,resources:1,verifiedFiles:9,reportReviewed:true,caseBoundary:'refused',vendorConnections:0}));
} finally {
  for (const client of clients) await client.close();
  await rm(root,{recursive:true,force:true});
}
