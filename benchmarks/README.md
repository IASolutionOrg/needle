# Benchmark evidence

This directory contains frozen inputs and published evidence reports for Needle.
Reports are organized by current-path and historical calibration boundaries.

Needle is a pre-alpha project. Every retained live result is a bounded
calibration for one recorded setup, not a general or statistically supported
savings claim.

## Layout

```text
benchmarks/
  corpus/derived-actions/ protocol-only Gate A3 manifest and synthetic paired observations
  corpus/router-cache/   answer-free manifest, schedule, synthetic plan, campaign, and cost model
    oracles/             legacy synthetic evaluator fixtures only (not public handles)
  fixtures/              structured protocol and worker fixtures
  results/historical/    accepted observations from an earlier product boundary
  results/live/          accepted provider-backed current-path calibration
  results/offline/       deterministic replay and local performance evidence
```

The experimental method, cost formulas, quality boundary, and paid-run policy
are documented in [Benchmarking](../docs/BENCHMARKING.md).

## Current live calibration

| Report | What it establishes | What it does not establish |
|---|---|---|
| [Routing and cache](results/live/routing-and-cache-calibration.md) | One routed miss plus authoritative zero-worker location hit with complete cost accounting | General savings or route coverage |
| [Structured MCP cache hit](results/live/structured-mcp-cache-hit.md) | One typed MCP call, authoritative composite hit, final response, zero worker, zero main discovery | MCP superiority or paired economics |
| [Partial and cross-route reuse](results/live/partial-and-cross-route-reuse.md) | Only the missing focused-test capability ran; the next route reused it with zero worker | Powered savings or other subjects |

## Offline current-path evidence

| Report | Scope |
|---|---|
| [Claim reuse performance](results/offline/claim-reuse-performance.md) | Claim authority, freshness isolation, mixed planning, and host-specific warm timings |
| [Multi-task quality replay](results/offline/multi-task-quality-replay.md) | Bounded semantic oracle and canonical scenario behavior |
| [End-to-end proof replay](results/offline/end-to-end-proof-replay.md) | Exact, coverage, composite, partial, mutation, and application-simulator closure |

The [derived-action Gate A3 preflight corpus](corpus/derived-actions/README.md)
exercises the bounded Exact, Project, and Assemble evaluation protocol for
`ArchitectureBrief` and `ChangeImpact`. It is synthetic and therefore cannot
close Gate A3 or support a provider-economics claim.

The Phase 6B `test-target-inventory-refresh-microbench` is likewise an offline
Shadow preflight. It includes targeted current-manifest acquisition, verifies
exact agreement with deterministic fresh enumeration, and selects full compute
when refresh has no positive net value. A positive result applies only to that
bounded synthetic case; it does not close Gate A4 by itself.

The [frozen Gate A4 multi-mutation corpus](corpus/test-target-refresh/README.md)
extends that preflight across manifest, explicit-target, metadata, conventional
discovery, workspace, unmapped-path, and incomplete-delta changes. It checks
exact fresh-oracle agreement, zero stale retained partitions, precise fallback
reasons, positive refresh economics, and a bounded p95. It remains synthetic
fixed-Shadow evidence and cannot authorize live refresh by itself.

The `test-target-inventory-refresh-live` runner adds provider-inclusive paired
latency calibration on one exact clean worktree. It applies and restores one
bounded inert Cargo-manifest mutation, alternates Fresh and Refresh samples,
includes Cargo subprocess transport in both arms, and writes a digest-bound
fixed-Shadow report under `target/`. Optional monetary values require explicit
pricing and evidence digests; elapsed time is never converted into money by
Needle. Locally eligible reports are still unaccepted observations and cannot
close Gate A4 or promote capability authority by themselves.

`test-target-inventory-refresh-live-accept` implements the bounded review layer
for those reports. It binds one to eight validated reports to exact clean
source checkouts, reviewer label, timestamp, latency-primary decision, and
explicit limitations, then creates a new immutable acceptance JSON. The
protocol is implemented, but no acceptance should be inferred merely from its
availability; the resulting artifact remains Shadow-only and cannot approve
capability promotion or close Gate A4.

The current worktree additionally records a separate action-native capability decision for
`TestTargetInventory + Refresh`. It closes Gate A4 only in operator-invoked `Shadow`: authoritative
promotion and automatic resolver/lifecycle consumption remain explicitly unapproved. Phase 7 must
earn and record those stronger authorities separately.

## Historical calibration

These reports predate the current proof kernel. They remain valid records of
the observed routing/cache path at the time, but cannot validate current proof
authority.

- [Trace routing](results/historical/routing-trace-calibration.md)
- [Full cache hit](results/historical/cache-hit-calibration.md)
- [Mutation and partial cache](results/historical/cache-mutation-calibration.md)
- [Implementation-location routing](results/historical/routing-location-calibration.md)

## Evidence policy

A published report records:

- evidence level and date;
- repository and exact SHA;
- natural task and route;
- models, reasoning, Codex version, service tier, and pricing digest when live;
- provider observation and retry count;
- complete observed result and accounting;
- reported interpretation and limitations.

Infrastructure failures, code defects, aborted runs, and preflight-only reports
are excluded from published benchmark evidence and do not support benchmark
claims.

The evidence index records observations; it does not approve or schedule
provider runs. Public corpus material is answer-free and synthetic. The
evaluator-owned sealed oracle index and its bytes are supplied out of band by
maintainers; no external bundle path is present in public manifests or arm
launch projections. A real sealed bundle and validated production PowerPlan
are absent from this checkout, so offline preflight remains fail-closed. The
synthetic bundle is complete for evaluator tests but cannot enable a provider
run. `router-cache/synthetic-calibration-observations.jsonl` deterministically
reproduces the checked-in synthetic PowerPlan, while
`router-cache/synthetic-final-observations.jsonl` exercises the exact paired
holdout contract and its fail-closed synthetic boundary. None of these
artifacts is economic evidence. A future caller must keep private evaluator
material unmounted and inaccessible to the runner identity; this protocol does
not claim ACL or process-isolation proof.
