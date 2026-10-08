# Kill-chain workflow

Deterministic, defensive workflow for moving a case through the seven phases. Each step is either (a) a tool call in this skill or (b) an evidence-collection handoff to a human operator. The skill never decides "the attack did X"; it decides "the evidence we have supports phase N, and here is what is missing".

## Loop

For a case under review:

1. **Orient** — `killchain_phases` to confirm the phase model and the evidence types each phase accepts. Note the `registryEntries` per phase: those are the registry entries that historically produce the matching evidence type.
2. **Collect** — ask the operator which evidence types are already retained for the case (domain/brand assets, email artifacts, DAST findings, host baselines, captures, exfiltration records). Do not go collect new evidence here; this skill is read-only over what is supplied.
3. **Evaluate** — build the `killchain_evaluate` payload from the retained evidence types. Map each retained artifact to the phase whose `evidenceTypes` it matches. Keep the `source` field to the system that retained it so a reviewer can trace every matched row back to a source.
4. **Read the verdict** — `first-covered-phase-N` is the earliest phase with a `covered` status. Phases before it that are `absent` or `partial` are the first collection gaps. Do not jump to a later covered phase.
5. **Probe captures** — for any retained `.pcap`, run `killchain_pcap_probe`. Treat `beaconCandidates` as phase-6 (C2) candidates. Confirm each candidate against the full capture and a supervised review before it becomes a finding.
6. **Close the gap** — for each `absent` or `partial` phase, record the specific evidence type that would move it to `covered`. Hand that list to the operator. Re-run `killchain_evaluate` after new evidence is retained.
7. **Stop when** — all seven phases are `covered` or `partial` with a named owner for each gap, or the operator closes the case. Record the final evaluation as the case's kill-chain state.

## Pcap beacon triage

`killchain_pcap_probe` returns `beaconCandidates` when a TCP stream shows a periodic interval (median within 1–3600 s, low coefficient of variation, ≥3 samples). Triage order:

1. **Direction** — `srcPort`/`dstPort`: an outbound periodic stream to a non-well-known port is a stronger C2 candidate than an inbound one.
2. **Endpoint** — is the `dst` in a known-good service range for the case's tenant? A periodic stream to a well-known CDN may be telemetry, not C2.
3. **Name correlation** — cross-reference `dnsQueries` and `tlsSni` for names that match the beacon's `dst` or appear in the same phase-1/3 evidence (domain/URL observations).
4. **Confirm** — a candidate becomes a finding only after the operator reviews the full capture. The skill's output is a bounded, deterministic candidate list, not a packet analysis.

## Output discipline

- Every evaluation is reproducible from the same `killchain_evaluate` payload and pcap bytes.
- Record the exact payload and pcap path in the case so the next operator can re-run and compare.
- Do not merge two cases' evaluations into one verdict; evaluate per case.
