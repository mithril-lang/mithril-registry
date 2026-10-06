# Asset, identity and Internet context

Use only operator-authorized local runs or separately authorized vendor reads. Read `receipt.json.coverage` and each source's pagination/gaps before drawing conclusions.

1. Import runZero asset JSON, Okta System Log JSON and a selected Censys Platform host response into distinct private output directories. Preserve raw bytes; assets and host observations are not security alerts.
2. Query `cybersecurity_correlate` with an exact IP and a bounded set of verified runs:

```json
{"runs":["/private/runzero-run","/private/okta-run","/private/censys-run"],"address":"8.8.8.8","limit":100,"offset":0}
```

3. Review each returned product, vendorId, sourceSha256 and sourceRow. runZero IDs, Okta actor/event IDs and an Internet IP belong to different namespaces. IP overlap is an observation match, not an identity link or a compromise verdict. NAT, proxy egress, dynamic reuse, differing tenants and observation times can explain the overlap.
4. Use timeline to compare known observation times. runZero last_seen is Unix seconds; Okta published is zoned ISO. Censys has no assumed universal host timestamp and is excluded from time ordering unless a separately reviewed time contract is added; inspect its raw record and receipt collection time.
5. Verify any identity link using independent operator evidence, record its time/scope and cite the source rows. Export with the existing evidence workflow. The tool does not automatically merge assets, assign cases or upload evidence.

Correlate searches normalized IP observations in these three context adapters only. It does not search arbitrary text for IPs or infer missing IP fields in the earlier alert adapters. Original unnormalized fields remain available in the retained source JSON.
