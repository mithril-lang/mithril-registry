"""Queries over byte-verified local runs; never infer complete coverage."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path


def investigate(name,args,decode,normalize,refusal):
 def text(value):
  if not isinstance(value,str) or not value or len(value)>4096:raise refusal('invalid_arguments')
  return value
 def load(path):
  root=Path(text(path))
  with (root/'receipt.json').open('rb') as stream: receipt=decode(stream.read(16385))
  with (root/'source.json').open('rb') as stream: raw=stream.read(2*1024*1024+1)
  if hashlib.sha256(raw).hexdigest()!=receipt.get('sourceSha256'):raise refusal('source_integrity_failed')
  data=normalize(receipt['product'],raw)
  from coverage import coverage
  data['coverage']=coverage(receipt['product'],data,'retained-bytes')
  # A source digest does not attest mutable receipt metadata. Do not promote it to facts.
  data['coverageClaims']=receipt.get('coverage',dict(status='incomplete-or-unknown',gaps=['legacy-receipt-no-coverage']))
  return data,receipt['sourceSha256']
 def runs(paths):
  if not isinstance(paths,list) or not 1<=len(paths)<=16 or len(set(map(text,paths)))!=len(paths):raise refusal('invalid_runs')
  out=[];sources=[]
  for path in paths:
   data,digest=load(path);sources.append(dict(product=data['product'],sourceSha256=digest,pagination=data['pagination'],gaps=data['gaps'],coverage=data['coverage'],coverageClaims=data['coverageClaims'],coverageAttestation='unsigned-local-receipt'))
   out.extend(dict(f,product=data['product'],sourceSha256=digest) for f in data['findings'])
  return out,sources
 def paging(values):
  limit=args.get('limit',100);offset=args.get('offset',0)
  if type(limit) is not int or not 1<=limit<=200 or type(offset) is not int or not 0<=offset<=16000:raise refusal('invalid_page')
  page=dict(data=values[offset:offset+limit],total=len(values),limit=limit,offset=offset)
  if len(json.dumps(page).encode())>2*1024*1024:raise refusal('result_page_limit')
  return page
 required={'cybersecurity_search':{'runs','query'},'cybersecurity_timeline':{'runs'},'cybersecurity_compare':{'before','after'},'cybersecurity_export':{'runs','output'},'cybersecurity_correlate':{'runs','address'}}[name]
 optional={'limit','offset'} if name in ('cybersecurity_search','cybersecurity_timeline','cybersecurity_correlate') else set()
 if not isinstance(args,dict) or not required<=set(args) or set(args)-required-optional:raise refusal('invalid_arguments')
 if name=='cybersecurity_compare':
  before,bhash=load(args['before']);after,ahash=load(args['after'])
  if before['product']!=after['product']:raise refusal('different_product_samples')
  def keyed(data):
   rows={}
   for row in data['findings']:
    if row['vendorId'] is None:raise refusal('missing_comparison_id')
    key=json.dumps([row['vendorId'],row.get('assetId')],sort_keys=True)
    if key in rows:raise refusal('ambiguous_comparison_id')
    rows[key]=row
   return rows
  left=keyed(before);right=keyed(after)
  fields=lambda row:{k:v for k,v in row.items() if k not in ('index','sourceRow')}
  result=dict(product=before['product'],beforeSourceSha256=bhash,afterSourceSha256=ahash,
              sampleNew=[right[k] for k in sorted(right.keys()-left.keys())],
              sampleAbsent=[left[k] for k in sorted(left.keys()-right.keys())],
              sampleChanged=[dict(before=left[k],after=right[k]) for k in sorted(left.keys()&right.keys()) if fields(left[k])!=fields(right[k])],
              gaps=['samples-not-complete','same-tenant-scope-operator-confirmed','sample-absence-not-resolution'])
  # Comparisons can be large; return bounded output and refuse rather than truncate.
  if len(json.dumps(result).encode())>2*1024*1024:raise refusal('comparison_limit')
  return result
 rows,sources=runs(args['runs'])
 base=dict(sources=sources,gaps=['samples-not-complete','vendor-claims-not-verdicts'])
 if name=='cybersecurity_correlate':
  from context_adapters import address
  ip=address(args['address'],refusal)
  matches=[row for row in rows if ip in row.get('observedIPs',[])]
  return dict(**base,**paging(matches),address=ip,matchBasis='exact-IP-observation-only',identityConclusion='not-established',correlationGaps=['NAT-proxy-and-IP-reuse','tenant-scope-not-verified','observation-times-may-differ'])
 if name=='cybersecurity_search':
  query=text(args['query'])
  if len(query)>200:raise refusal('query_limit')
  # Literal search over normalized claims. No regex or executable vendor query.
  matches=[row for row in rows if query.casefold() in json.dumps({k:v for k,v in row.items() if k not in ('sourceSha256','sourceRow','index')},ensure_ascii=False).casefold()]
  return dict(**base,**paging(matches))
 if name=='cybersecurity_timeline':
  events=[];unknown=0
  for row in rows:
   value=row.get('reportedTime');encoding=row.get('timeEncoding');instant=None
   try:
    if encoding=='unix-seconds' and type(value) in (int,float):
     instant=datetime.fromtimestamp(value,timezone.utc)
    elif isinstance(value,str):
     # Require explicit zone and strict ISO shape; preserve raw vendor time.
     import re
     if re.fullmatch(r'\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)',value):
      instant=datetime.fromisoformat(value.replace('Z','+00:00')).astimezone(timezone.utc)
    if instant is None:unknown+=1;continue
    events.append(dict(row,utcTime=instant.isoformat(),precision='microseconds-for-ordering'))
   except (ValueError,OverflowError,OSError):unknown+=1
  events.sort(key=lambda row:(row['utcTime'],row['product'],row['sourceSha256'],row['sourceRow']))
  return dict(**base,**paging(events),unknownTimeCount=unknown,gapsWithTime=['unknown-times-excluded','submicrosecond-order-not-distinguished','clock-skew-not-corrected'])
 # Export is explicit, private, additive, and contains claims plus source hashes.
 root=Path(text(args['output']));root.mkdir(mode=0o700,parents=True,exist_ok=False)
 data=dict(schemaVersion=1,kind='mithril-cybersecurity-claim-export',**base,findings=rows)
 raw=json.dumps(data,allow_nan=False).encode()
 if len(raw)>32*1024*1024:raise refusal('export_limit')
 fd=os.open(root/'investigation.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb') as stream:stream.write(raw)
 return dict(output=str(root/'investigation.json'),sha256=hashlib.sha256(raw).hexdigest(),count=len(rows),gaps=base['gaps'])
