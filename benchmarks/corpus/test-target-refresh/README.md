# Test-target refresh Gate A4 corpus

This directory freezes the deterministic multi-mutation corpus used to evaluate
the target-scoped refresh path for `TestPlan` discovery.

`gate-a4-manifest.json` is digest-bound to the current adapter, acquisition,
refresh, validation, partition-policy, fixture, and mutation definitions. A
definition change therefore invalidates the corpus manifest instead of silently
changing the benchmark.

The corpus creates a synthetic 64-package Cargo workspace and evaluates eight
mutations:

- manifest content change;
- explicit target addition;
- explicit target removal;
- target metadata change;
- conventional target addition;
- workspace manifest change;
- an unmapped repository change;
- an incomplete delta.

The first five cases must produce an exact target-scoped refresh. Each refreshed
inventory and certificate is compared with a fresh full-enumeration oracle, and
retained partitions are checked for stale content. The last three cases must
fall back to full computation with the precise expected reason.

Run the corpus from the repository root:

```text
cargo run --release -p needle-bench --bin test-target-inventory-refresh-gate-a4 -- --require-corpus-pass
```

The report is written to
`target/test-target-refresh-gate-a4/report.json`. Full oracle construction is
intentionally outside refresh timing. Timing covers the in-process adapter and
refresh path; it does not claim process-transport, operating-system cache, or
live repository authority.

Passing this corpus makes the refresh operator eligible for the remaining Gate
A4 integration work. It does not close Gate A4 by itself: persisted attempts,
memos, live orchestration, capability promotion, and control-plane policy remain
separate authority gates.
