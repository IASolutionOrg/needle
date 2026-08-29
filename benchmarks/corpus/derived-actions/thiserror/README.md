# thiserror Gate A3 study

This directory freezes the first real-source `ArchitectureBrief` and
`ChangeImpact` Gate A3 study without vendoring the source repository or any
model output.

Source pins:

- repository: `https://github.com/dtolnay/thiserror.git`;
- clean study base: `485c2b7eed2702c4a109be3cf42bb4be27fe16bd`;
- change target: `2deec96fc0de605d114d3860f29d1d066ad4151e`;
- focused change test: `cargo test --test test_lints`.

The target is a direct child of the study base and changes only
`impl/src/expand.rs` and `tests/test_lints.rs` (+22/-5). The base workspace has
three packages: `thiserror`, `thiserror-impl`, and
`thiserror_no_std_test`.

Files:

- `study.json` contains public source pins, the provider-neutral external
  Shadow execution profile, prompts, package/component universes, requested
  scopes, and reuse source partitions for all six tasks;
- `sealed-oracles.json` contains reviewer-only quality rubrics. It must never
  be exported to a model prompt or worker context;
- `gate-a3-manifest.json` is the generated `AcceptedShadow` manifest. It binds
  each task to its canonical action request, fixture, oracle, execution
  profile, current action definition, validator, and partition policy.

Exact and Assemble deliberately have equal semantic request identities when
their requested result is equal. Their fixture and oracle commitments remain
different because the reuse mechanism and reviewer checks differ. Project has
a narrower semantic scope and therefore a different request identity.

Regenerate the manifest deterministically from the repository root:

```powershell
rtk cargo run -p needle-bench --bin derived-action-gate-a3-preflight -- `
  --emit-study-manifest benchmarks/corpus/derived-actions/thiserror/study.json `
  --study-oracles benchmarks/corpus/derived-actions/thiserror/sealed-oracles.json
```

The checked-in synchronization test fails if any study input, oracle,
definition, or generated commitment drifts:

```powershell
rtk cargo test -p needle-bench derived_action_gate::study::tests
```

Export the six public model inputs from a clean checkout at the pinned base:

```powershell
rtk cargo run -p needle-bench --bin derived-action-gate-a3-runner -- export `
  --study benchmarks/corpus/derived-actions/thiserror/study.json `
  --manifest benchmarks/corpus/derived-actions/thiserror/gate-a3-manifest.json `
  --source-repository <path-to-clean-thiserror-base-checkout> `
  --output target/derived-action-gate-a3/thiserror-public-inputs.json
```

Each task contains a response template. After an external model has produced a sorted
`needle.derived-action-external-results/1` bundle with its truthful model ID, latency, and cost,
import it without making another provider call:

```powershell
rtk cargo run -p needle-bench --bin derived-action-gate-a3-runner -- import `
  --study benchmarks/corpus/derived-actions/thiserror/study.json `
  --manifest benchmarks/corpus/derived-actions/thiserror/gate-a3-manifest.json `
  --public-inputs target/derived-action-gate-a3/thiserror-public-inputs.json `
  --external-results <external-results.json> `
  --source-repository <path-to-clean-thiserror-base-checkout> `
  --output target/derived-action-gate-a3/review-material.json
```

Import constructs actual typed artifacts, validates them against the pinned source, and measures
local Exact, Project, and Assemble execution. It does not call a provider, evaluate sealed quality
rubrics, create Gate observations, or accept the result.

No observations, model outputs, reviewer acceptance, or provider calls are
included yet. This corpus freezes the study design only and does not close
Gate A3.
