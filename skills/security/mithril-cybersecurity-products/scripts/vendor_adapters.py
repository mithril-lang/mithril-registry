"""Explicit vendor contracts; no arbitrary query or remediation endpoints."""
import base64
import json
import re
import urllib.request
from urllib.parse import urlsplit

EXTRA = {
 'microsoft-defender': {'name':'Microsoft Defender (Graph alerts v2)','collection':'read-alerts-v2','qualification':'fixture-tested'},
 'crowdstrike-falcon': {'name':'CrowdStrike Falcon','collection':'read-selected-alert-details','qualification':'fixture-tested'},
 'tenable-vm': {'name':'Tenable Vulnerability Management','collection':'read-existing-export-chunk','qualification':'fixture-tested'},
 'wazuh': {'name':'Wazuh indexer','collection':'read-alert-search','qualification':'fixture-tested'},
}

def at(row, path):
 for key in path.split('.'):
  if not isinstance(row,dict): return None
  row=row.get(key)
 return row

def normalize_extra(product,data,refusal):
 try:
  if product=='microsoft-defender':
   rows=data['value']; fields=('id','title','severity','createdDateTime'); more=bool(data.get('@odata.nextLink'))
  elif product=='crowdstrike-falcon':
   rows=data['resources'];fields=('composite_id','name','severity','timestamp');more='selected-ids-only'
  elif product=='wazuh':
   if data.get('timed_out') or data.get('_shards',{}).get('failed',0): raise refusal('incomplete_vendor_search')
   hits=data['hits']['hits'];rows=[dict(hit['_source'],_vendor_hit_id=hit['_id']) for hit in hits]
   fields=('_vendor_hit_id','rule.description','rule.level','timestamp');more=data['hits'].get('total','unknown')
  else:
   rows=data;fields=('plugin.id','plugin.name','severity','last_found');more='single-existing-chunk'
  if not isinstance(rows,list) or len(rows)>1000:raise refusal('report_rows_limit')
  findings=[]
  for i,row in enumerate(rows):
   if not isinstance(row,dict):raise refusal('invalid_vendor_row')
   values=[at(row,k) for k in fields]
   if any(v is not None and (type(v) not in (str,int,float)) for v in values):raise refusal('unsupported_vendor_fields')
   asset = at(row,'asset.uuid') if product=='tenable-vm' else at(row,'machineId') if product=='microsoft-defender' else at(row,'device.device_id') if product=='crowdstrike-falcon' else at(row,'agent.id')
   cves=at(row,'plugin.cve') if product=='tenable-vm' else []
   if cves is None:cves=[]
   if not isinstance(cves,list) or len(cves)>100 or any(not isinstance(c,str) or not re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,}',c) for c in cves):raise refusal('invalid_cve_claim')
   if asset is not None and not isinstance(asset,str):raise refusal('invalid_asset_claim')
   findings.append(dict(index=i,vendorId=values[0],title=values[1],severity=values[2],reportedTime=values[3],sourceRow=i,assetId=asset,cves=cves,timeEncoding='unix-seconds' if product=='tenable-vm' else 'zoned-iso'))
 except (KeyError,TypeError,AttributeError,ValueError):raise refusal('unsupported_export_shape') from None
 return dict(schemaVersion=1,product=product,qualification='fixture-tested',provenance='vendor-reported-unverified',findings=findings,pagination=dict(coverage='single-supplied-page',vendorContinuation=more),gaps=['vendor-authenticity-not-attested','coverage-not-complete','reported-time-not-normalized']+([] if findings else ['empty-is-not-clearance']))

def request_extra(policy,secret,refusal):
 product=policy['product'];origin=policy['origin'];url=urlsplit(origin);host=url.hostname or ''
 if url.scheme!='https' or url.username or url.password or url.path or url.query or url.fragment or not host or url.port not in (None,443,9200):raise refusal('invalid_origin')
 headers={'Accept':'application/json','User-Agent':'Mithril-Cybersecurity-Products/0.2.0'}
 if product=='wazuh':
  # Self-hosted destinations are explicitly pinned by an operator-maintained policy.
  if policy.get('approvedOrigin')!=origin:raise refusal('unapproved_wazuh_origin')
  if not re.fullmatch(r'[a-z0-9.-]+',host):raise refusal('invalid_origin')
  if not re.fullmatch(r'https://'+re.escape(host)+r'(?::(?:443|9200))?',origin):raise refusal('invalid_origin')
  credentials=secret(policy['usernameEnv'])+':'+secret(policy['passwordEnv'])
  if ':' in secret(policy['usernameEnv']):raise refusal('invalid_username')
  headers.update(Authorization='Basic '+base64.b64encode(credentials.encode()).decode(),**{'Content-Type':'application/json'})
  body=json.dumps({'size':100,'sort':[{'timestamp':{'order':'desc'}}],'query':{'match_all':{}}}).encode()
  return urllib.request.Request(origin+'/wazuh-alerts*/_search',body,headers,method='POST')
 if url.port not in (None,443) or origin!='https://'+host:raise refusal('invalid_origin')
 if product=='microsoft-defender':
  if host!='graph.microsoft.com':raise refusal('vendor_origin_not_allowed')
  headers['Authorization']='Bearer '+secret(policy['tokenEnv'])
  return urllib.request.Request(origin+'/v1.0/security/alerts_v2?$top=100',headers=headers,method='GET')
 if product=='crowdstrike-falcon':
  if host not in ('api.crowdstrike.com','api.us-2.crowdstrike.com','api.eu-1.crowdstrike.com','api.laggar.gcw.crowdstrike.com'):raise refusal('vendor_origin_not_allowed')
  ids=policy.get('compositeIds')
  if not isinstance(ids,list) or not 1<=len(ids)<=100 or any(not isinstance(i,str) or not re.fullmatch(r'[A-Za-z0-9:_-]{1,200}',i) for i in ids) or len(set(ids))!=len(ids):raise refusal('invalid_alert_ids')
  headers.update(Authorization='Bearer '+secret(policy['tokenEnv']),**{'Content-Type':'application/json'})
  return urllib.request.Request(origin+'/alerts/entities/alerts/v2',json.dumps({'composite_ids':ids}).encode(),headers,method='POST')
 if host!='cloud.tenable.com':raise refusal('vendor_origin_not_allowed')
 uid=policy.get('exportUuid','');chunk=policy.get('chunkId')
 if not isinstance(uid,str) or not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',uid) or type(chunk) is not int or not 0<=chunk<=100000:raise refusal('invalid_export_reference')
 access=secret(policy['accessKeyEnv']);key=secret(policy['secretKeyEnv'])
 if any(c in access+key for c in ';='):raise refusal('invalid_api_key')
 headers['X-ApiKeys']='accessKey='+access+'; secretKey='+key
 return urllib.request.Request(origin+f'/vulns/export/{uid}/chunks/{chunk}',headers=headers,method='GET')
