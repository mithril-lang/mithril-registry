# Coscientist Bug-Bounty Round (design contract)

Non-executable design contract for running bug-bounty challenges as a
bounded planner loop, modeled on Coscientist (Boiko, MacKnight, Kline &
Gomes, Nature 624, 2023). The Planner LLM is the user's owning profile;
this contract fixes the deterministic core and its guarantees.

## What it provides

A deterministic, offline-verifiable planner-round ledger
(`mithril-coscientist-bb`) that:

- validates and normalizes a four-command plan
  (`GOOGLE`, `PYTHON`, `DOCUMENTATION`, `EXPERIMENT`);
- digests the round, observations, hypothesis ledger and decision as
  `sha256:` canonical JSON, so identical input yields an identical digest;
- advances the hypothesis ledger (a `confirmed` experiment confirms the
  hypothesis; a `refuted` one refutes it; `unknown` keeps it open);
- synthesizes the decision: `submit_to_human` on a confirmed hypothesis,
  `continue` otherwise, `observe_more` when observations are not recorded.

Execution status: `deterministic-offline`.

## What it does not provide

- Planner-LLM inference (external to the core).
- Live network retrieval, target-code execution or deployment probing.
- Bug-bounty submission or vulnerability confirmation.
- Automatic retry of an unknown outcome.

## Boundaries

- A confirmed hypothesis is a candidate for human review, not a confirmed
  vulnerability; zero confirmed hypotheses does not mean safe.
- A `submit_to_human` decision is a hand-off, not a submission.
- Limits: 12 commands per round, 32 hypotheses, 256 KiB observation bytes.
- The deterministic core makes no credential, network or filesystem writes
  outside its receipt; all live actions belong to the owning profile and
  the human gate.

## Related contracts

- `mithril-exchange-asset-recovery-design` — same
  deterministic-offline guarantee pattern (canonical digest receipt,
  live action external, owning-profile acknowledgement).
