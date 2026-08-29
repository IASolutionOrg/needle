# Benchmarking

Needle benchmarks completed tasks and total observed cost. Transport wiring,
prompt length, cache lookup alone, or a worker process alone is not a product
result.

Accepted reports live in the [evidence index](../benchmarks/README.md). Failed
or diagnostic attempts are excluded from that public archive.

## Product comparison

Needle is primarily an economic task router. Proof-gated cache reuse is the
second multiplier.

| Arm | Execution |
|---|---|
| `MainOnly` | Frontier model completes the task and performs discovery |
| `NeedleMiss` | Same frontier model delegates bounded work to lower-cost workers |
| `NeedleHit` | Needle returns validated cached evidence and starts zero workers |

Primary ratios:

```text
routing saving = 1 - NeedleMiss / MainOnly
cache saving   = 1 - NeedleHit / NeedleMiss
total saving   = 1 - NeedleHit / MainOnly
```

Costs follow the path actually executed. `NeedleMiss` includes every main turn,
worker, repair, escalation, and fallback. `NeedleHit` includes every main turn,
continuation, proof overhead, and projection. If an intended hit starts a
worker, it is not a hit observation.

## Paired-task contract

Economic arms must share:

- natural user objective;
- repository and pinned SHA;
- subject, world, obligations, and completeness;
- main model, reasoning, service tier, and pricing snapshot;
- independent hidden quality oracle.

Public corpus manifests use `needle.frozen-corpus/4`: they contain only
answer-free prompts, source identities, policy commitments, and oracle
commitments. Answer bytes and quality/test policy live in an evaluator-owned
sealed bundle indexed outside the public manifest. The checked-in router-cache
tasks, calibration observations, and power plan are synthetic fixtures and are
permanently ineligible for provider evidence. The synthetic calibration JSONL
exists only to reproduce the checked-in plan and exercise the offline protocol.

The app provider path remains fail-closed until an isolated executor/broker
consumes only the bounded ArmLaunch projection. Evaluator callers must keep
private sealed material unmounted and inaccessible to the runner identity; the
offline protocol does not prove filesystem ACLs or process isolation.

Wording may differ only when the compiled semantic need remains equivalent.
Narrower, wider, residual, or mutation requests are separate cache-behavior
experiments.

## Quality boundary

Quality asks whether the final answer satisfies the natural task without
material error or stale evidence. It does not require details the user did not
request.

Files, symbols, flow steps, and tests become mandatory only when the task or
typed contract requires them. Focused-test identification and test execution
are separate. Test execution is not a universal product gate.

Any quality failure blocks promotion for that observation. A corrected oracle
can validate current evaluator behavior offline, but it cannot retroactively
turn an invalid economic pair into accepted savings evidence.

## Cache correctness

Cache behavior is tested independently from production economics:

- equivalent need resolves from eligible evidence;
- full hit starts zero workers;
- irrelevant mutation preserves independent evidence;
- relevant mutation invalidates only dependent evidence;
- partial hit computes only missing obligations;
- stale, contradicted, ambiguous, or unknown evidence is not served;
- main and worker do not repeat certified discovery.

An offline forced-plan replay can validate correctness. It cannot establish
provider economics. Production mode separately requires positive expected net
reuse value.

## Evidence levels

### Offline validated

Deterministic source, simulator, replay, mutation, or performance evidence with
zero provider calls. Synthetic token or cost values validate accounting only.

### Live calibration

One bounded provider-backed observation for a frozen task, model, tool version,
and pricing snapshot. It validates that path only and is not a general claim.

### Statistically validated

A pre-registered multi-task study with frozen calibration/holdout split,
independent oracles, paired execution, justified sample size, and confidence
interval. Needle has no such result yet.

Transport-only evidence is reported as functional transport calibration, not
product savings.

## Derived-action Gate A3 offline preflight

The `derived-action-gate-a3-preflight` binary is a pure importer and evaluator
for the `ArchitectureBrief` and `ChangeImpact` Shadow actions. It pairs Fresh
and Reuse observations for Exact, Project, and Assemble scenarios and reports
protocol validity, structural validation, quality, semantic equivalence, and
positive observed cost delta as separate fields.

The default checked-in corpus is deterministic and synthetic:

```powershell
rtk cargo run -p needle-bench --bin derived-action-gate-a3-preflight
```

It writes `target/derived-action-gate-a3/report.json`. The corpus can validate
the evaluation protocol, but `gate_a3_eligible` and `gate_a3_passed` remain
false by construction. `--require-gate-pass` is therefore expected to fail for
the default corpus.

The harness never launches a worker, provider, resolver, or store operation.
Future observations are imported explicitly. `provider_backed` evidence must
record exactly one provider call for each Fresh arm and zero for each Reuse
arm.

### Phase 6B Cargo refresh preflight

The offline refresh microbenchmark exercises the provider-specific Cargo
reference adapter without adding Cargo semantics to the generic resolver:

```powershell
rtk cargo run --release -p needle-bench --bin test-target-inventory-refresh-microbench
```

It measures fresh enumeration and validation, targeted current-manifest
acquisition, manifest certification, the pure refresh operator, and the
end-to-end refresh candidate. The full current enumeration used as the
correctness oracle is outside refresh timing. The synthetic metadata input is
already available in memory, so Cargo process transport is explicitly
excluded. A run selects `refresh` only when the complete measured path is
strictly cheaper; otherwise it selects `full_compute`, even if reconstruction
agrees exactly with the fresh oracle. `gate_a4_eligible` describes this bounded
preflight case only and does not close Gate A4 or authorize live reuse.
This preflight is Shadow evidence, not authority or a positive savings claim.

The frozen Gate A4 multi-mutation corpus exercises the same path across five
exact refresh cases and three fail-closed fallback cases:

```powershell
rtk cargo run --release -p needle-bench --bin test-target-inventory-refresh-gate-a4 -- --require-corpus-pass
```

Its digest-bound manifest is stored at
`benchmarks/corpus/test-target-refresh/gate-a4-manifest.json`; the generated
report is written under `target/test-target-refresh-gate-a4/`. The runner fails
if a decision differs from the manifest, a refreshed inventory or certificate
differs from fresh full enumeration, a retained partition is stale, any refresh
case is not strictly cheaper, or the configured p95 bound is exceeded. The
corpus uses a synthetic 64-package workspace with in-memory Cargo metadata, and
therefore remains fixed-Shadow evidence. Passing it satisfies the corpus
prerequisite but does not close Gate A4 or authorize live refresh.

The provider-inclusive live calibration runner measures the same Cargo action on one clean source
worktree. It acquires the prior, applies and digest-binds one fixed inert comment to one tracked
`Cargo.toml`, alternates Fresh and Refresh arms, and restores the original bytes before returning:

```powershell
cargo run -p needle-bench --bin test-target-inventory-refresh-live -- `
  --repository <clean-checkout> --source-repository <public-url> `
  --changed-path <package/Cargo.toml> --samples 36 `
  --p95-budget-micros 250000 --output <new-report.json>
```

Both arms include bounded offline `cargo --version` and
`cargo metadata --format-version 1 --no-deps --locked`. The report records every paired latency,
the p95 comparison, exact fresh-oracle agreement, stale/retained/refreshed counts, source SHA,
toolchain, mutation and content digests, and fixed Shadow authority. The full oracle is outside
Refresh timing. Output uses create-new semantics and must be outside the measured repository.

Latency is the primary local Gate A4 signal. Optional monetary observations are accepted only when
Fresh cost, Refresh cost, pricing revision, and cost-evidence digest are supplied together. The
runner never converts elapsed time into microUSD. A locally eligible report still hardcodes
`gate_a4_closed=false`; explicit review and a separate capability decision are required.

Use one worktree, not paired directories. Cargo metadata contains absolute roots, so separate
checkout paths contaminate the prior/current comparison even at the same SHA.

The review step uses a separate immutable acceptance artifact. Reports and clean source checkouts
are paired by their repeated argument order; every checkout must still have the report's exact full
SHA and matching `origin` before and after acceptance:

```powershell
cargo run -p needle-bench --bin test-target-inventory-refresh-live-accept -- `
  --report <thiserror-report.json> --source-checkout <clean-thiserror-checkout> `
  --report <tracing-report.json> --source-checkout <clean-tracing-checkout> `
  --reviewer-id <local-reviewer-label> --reviewed-unix-ms <timestamp> `
  --limitation "local Windows calibration; no statistical claim" `
  --limitation "no monetary provenance was supplied" `
  --confirm-latency-primary-shadow --output <new-acceptance.json>
```

The acceptance binds the canonical report set, public sources and SHAs, explicit criteria,
reviewer label, timestamp, and limitations. The reviewer label is an audit label, not cryptographic
authentication. This step accepts only the bounded local Shadow evidence: it hardcodes
`authority_promotion_approved=false`, `statistical_claim=false`, and `gate_a4_closed=false`.
Capability review remains a separate operation.

For the current local worktree, that separate decision is recorded as an exact action-native
`TestTargetInventory + Refresh` class. It selects `Shadow` and operator-only invocation, explicitly
rejects authoritative promotion and automatic resolver/lifecycle consumption, and closes Gate A4
only for the bound two-report evidence set and current definition digests. It is not a general
savings claim or permission for zero-worker lifecycle transitions.

For derived-action Gate A3, `accepted_shadow` likewise uses a separate acceptance artifact rather
than embedding an
acceptance digest in the study manifest. The artifact binds the immutable
manifest, complete observation set, reviewed material, reviewer, explicit
timestamp, all action/scenario decisions, and limitations. Create it only
after reviewing real Shadow material:

```powershell
rtk cargo run -p needle-bench --bin derived-action-gate-a3-accept -- `
  --manifest <manifest.json> --observations <observations.jsonl> `
  --review-material <reviewed-material> --source-repository <clean-checkout> `
  --reviewer-id <reviewer> --reviewed-unix-ms <timestamp> `
  --limitation "bounded Shadow calibration; no authority or statistical claim" `
  --confirm-bounded-shadow
```

The command requires an exact clean source SHA both before and after
evaluation, rejects Synthetic and ProviderBacked manifests, and writes the
acceptance plus its re-evaluated report without overwriting existing evidence
paths. This is an explicit local human-review
record, not cryptographic reviewer authentication, a statistical claim, or an
authority-promotion approval.

The quality-judgment and oracle digests remain trusted evaluator commitments
supplied with the imported evidence; the harness verifies their bindings, not
the truth of an unavailable private oracle. A passing imported report closes
only this bounded Gate A3 calibration.

## Accounting

Record separately:

- main input, cached input, output, and reasoning usage;
- every worker, repair, steer, escalation, and fallback;
- proof lookup, validation, planning, projection, and continuation overhead;
- wall time and failure stage;
- pricing snapshot digest and calculated cost.

Thread usage events may be cumulative snapshots and must not be summed twice.
Interrupted or failed turns retain observed usage. Calculated credits are based
on the repository pricing snapshot and are not provider invoices.

## Accepted report metadata

Every retained report states:

- evidence level and date;
- purpose and task;
- public repository and exact SHA;
- route and semantic request;
- main/worker models, reasoning, Codex version, and tier;
- pricing digest;
- provider observation and retry count;
- exact observed outcome;
- source-integrity and discovery checks;
- interpretation and explicit non-claims.

Reports describe accepted evidence and explicit boundaries. Implementation
failures are excluded from accepted benchmark results.

## Current accepted observations

- One current routing/cache calibration covers a live miss and authoritative
  zero-worker location hit.
- One structured-MCP live calibration covers a three-artifact composite hit,
  final response, and zero main discovery.
- One partial-reuse live calibration computes only focused tests and then
  reuses them across routes with zero second worker.
- Claim reuse, multi-task proof closure, and performance have deterministic
  offline evidence.
- Earlier routing, cache, and mutation reports remain historical calibration
  and do not validate the current proof kernel.

No powered corpus or publishable general savings interval exists.

## Paid-run discipline

Before any provider run:

1. freeze task, SHA, request, oracle commitment, models, pricing, and retry policy;
2. run deterministic simulator and current native preflight;
3. verify the immutable schedule, validated PowerPlan, production sealed bundle,
   source integrity, and cleanup;
4. produce a complete cost estimate;
5. obtain explicit human approval for that exact stage;
6. execute once unless the approved protocol explicitly permits repetition.

Preflight and an estimate do not authorize execution. Failures do not authorize
automatic retry.

## Final statistical gate

Power planning and final evaluation are separate digest-bound stages:

1. `experiment power-plan` accepts calibration observations only. Every
   economic pair must contain exactly one `FrontierDirect` and one `NeedleMiss`
   record with matching corpus, campaign commitment, task, route, split,
   repetition, and pair seed. Failed, low-quality, missing, duplicate,
   non-positive, mixed-material, non-beneficial, or zero-variance calibration
   fails without emitting a plan.
2. A canonical `needle.power-plan/2` records the calibration-input digest,
   estimator revision, alpha, target power, per-route log-ratio diagnostics,
   required holdout pairs, material classification, and its canonical artifact
   digest. The final gate verifies its campaign commitment against the exact
   campaign bytes frozen by the manifest. The frozen schedule references the
   exact serialized plan and must contain exactly the required holdout count
   for each route.
3. `experiment final-report` accepts holdout observations only. Their identity
   includes corpus, schedule, power plan, task, route, split, repetition, pair
   seed, and arm. Every scheduled identity must appear exactly once. Explicit
   failures remain in the report; the evaluator never drops them to calculate
   a more favorable ratio or interval.

Calibration values cannot contribute to the final ratio, BCa interval, quality
gate, or staleness gate. Holdout values cannot recompute or resize the frozen
plan. Synthetic plans remain structurally testable but always fail the final
economic claim.

A future general claim requires:

- calibration and holdout tasks frozen before final runs;
- at least both built-in discovery routes;
- powered one-sided paired design;
- 95% BCa bootstrap interval for paired cost ratio entirely below `1.0`;
- no quality failure or stale hit;
- complete main and worker accounting;
- claim limited to measured workloads, models, versions, and pricing.

See [Project status](../PROJECT_STATUS.md) for remaining release work.
