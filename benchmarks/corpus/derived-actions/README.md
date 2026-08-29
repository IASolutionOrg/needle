# Derived-action Gate A3 preflight corpus

This directory contains deterministic protocol-only material for the offline
`ArchitectureBrief` and `ChangeImpact` Gate A3 evaluator.

- `gate-a3-manifest.json` freezes one Exact, Project, and Assemble task for
  each action, the current action/validator/partition definition digests, and
  one paired seed per task.
- `synthetic-observations.jsonl` contains the matching Fresh/Reuse observation
  envelopes.

Both files are classified `synthetic`. They exercise binding, structural,
quality, semantic-equivalence, and positive-cost-delta accounting without
starting a worker or calling a provider. Consequently, a successful preflight
must still report `gate_a3_eligible: false` and `gate_a3_passed: false`.

`thiserror/` contains the first real-source study definition. It pins a small
three-package Rust workspace, a bounded two-file upstream patch, all six
Exact/Project/Assemble tasks, and separate sealed reviewer rubrics. It does not
vendor the upstream repository and does not contain observations or accepted
evidence yet; see `thiserror/README.md` for its exact boundary and regeneration
command.

Run the default preflight from the repository root:

```powershell
rtk cargo run -p needle-bench --bin derived-action-gate-a3-preflight
```

The report is written to
`target/derived-action-gate-a3/report.json`. Passing
`--require-gate-pass` intentionally returns a failing exit code for this
synthetic corpus.

Future accepted evidence is imported with explicit `--manifest`,
`--observations`, and `--acceptance` paths. The study manifest is immutable and
does not contain the acceptance digest. A separate `accepted_shadow` artifact
binds the manifest digest, observation-set digest, reviewed-material digest,
reviewer, timestamp, all six action/scenario decisions, and explicit
limitations. This layering avoids a digest cycle between manifest,
observations, and acceptance.

The acceptance artifact is created only from an `accepted_shadow` manifest:

```powershell
rtk cargo run -p needle-bench --bin derived-action-gate-a3-accept -- `
  --manifest <manifest.json> `
  --observations <observations.jsonl> `
  --review-material <reviewed-material> `
  --source-repository <clean-checkout> `
  --reviewer-id <reviewer> `
  --reviewed-unix-ms <timestamp> `
  --limitation "bounded Shadow calibration; no authority or statistical claim" `
  --confirm-bounded-shadow
```

The command verifies the source SHA and clean worktree before and after
evaluation and creates immutable output paths rather than overwriting prior
evidence. It records explicit local human acceptance; it is not a digital
signature or an authority-promotion approval. The checked-in synthetic
manifest is rejected by this workflow.

`provider_backed` requires exactly one recorded provider observation on every
Fresh arm and zero provider calls on every Reuse arm. Both commands only
validate imported envelopes; they never execute providers, workers, or the
Needle resolver.
