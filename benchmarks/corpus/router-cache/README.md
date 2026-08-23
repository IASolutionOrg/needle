    # Router-cache benchmark fixtures

    Checked-in corpus used by router-cache benchmarks so CI and local runs share the same
    inputs (manifest, campaign, schedule, synthetic PowerPlan / observation samples).

    ## Layout

    - `campaign.json`
- `cost-model.json`
- `legacy-offline-campaign.json`
- `legacy-offline-manifest.json`
- `manifest.json`
- `minimal-live-pilot.json`
- `oracles/README.md`
- `oracles/ripgrep-crlf-trace.json`
- `oracles/ripgrep-glob-case-insensitive-locate.json`
- `oracles/ripgrep-no-ignore-vcs-locate.json`
- `oracles/ripgrep-null-data-trace.json`
- `power-plan.json`
- `schedule.json`
- `synthetic-calibration-observations.jsonl`
- `synthetic-final-observations.jsonl`
- `synthetic-sealed/docs/ripgrep-crlf-trace-calibration.json`
- `synthetic-sealed/docs/ripgrep-glob-case-insensitive-locate-calibration.json`
- `synthetic-sealed/docs/ripgrep-no-ignore-vcs-locate-holdout.json`
- `synthetic-sealed/docs/ripgrep-null-data-trace-holdout.json`
- `synthetic-sealed/index.json`

    ## How these are used

    - Treat this tree as **read-only fixtures**: do not commit regenerated large artifacts
      or machine-specific paths.
    - Benchmarks should resolve paths relative to the repository root (or the package
      `CARGO_MANIFEST_DIR`) so clones remain portable.
    - When adding a fixture, keep payloads small, deterministic, and document purpose
      plus which bench target consumes them.

    ## Regenerating (if applicable)

    Prefer committed golden files over ad-hoc generation. If a generator exists under
    `benchmarks/`, document the exact command here and keep outputs stable across platforms.
