use needle_bench::{
    MAX_TEST_TARGET_REFRESH_GATE_MANIFEST_BYTES, TestTargetRefreshGateManifest,
    evaluate_test_target_refresh_gate, frozen_test_target_refresh_gate_manifest, read_bounded_file,
};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    if let Err(error) = run() {
        eprintln!("test-target-inventory-refresh-gate-a4: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse(env::args().skip(1))?;
    if arguments.emit_manifest {
        println!("{}", serde_json::to_string_pretty(&frozen_test_target_refresh_gate_manifest())?);
        return Ok(());
    }
    let workspace = arguments.workspace_root.unwrap_or(env::current_dir()?).canonicalize()?;
    let manifest_path = absolute_from(
        &workspace,
        arguments.manifest.unwrap_or_else(|| {
            PathBuf::from("benchmarks/corpus/test-target-refresh/gate-a4-manifest.json")
        }),
    );
    let output = absolute_from(
        &workspace,
        arguments
            .output
            .unwrap_or_else(|| PathBuf::from("target/test-target-refresh-gate-a4/report.json")),
    );
    let manifest = TestTargetRefreshGateManifest::decode_json(&read_bounded_file(
        &manifest_path,
        MAX_TEST_TARGET_REFRESH_GATE_MANIFEST_BYTES,
    )?)?;
    let report = evaluate_test_target_refresh_gate(&manifest)?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", output.display());
    if !report.expectations_matched
        || !report.exact_oracle_agreement
        || !report.zero_stale_retained_partitions
    {
        return Err("Gate A4 frozen corpus correctness failed; see the written report".into());
    }
    if arguments.require_corpus_pass && !report.gate_a4_corpus_eligible {
        return Err("Gate A4 frozen corpus did not pass; see the written report".into());
    }
    Ok(())
}

#[derive(Default)]
struct Arguments {
    workspace_root: Option<PathBuf>,
    manifest: Option<PathBuf>,
    output: Option<PathBuf>,
    require_corpus_pass: bool,
    emit_manifest: bool,
}

impl Arguments {
    fn parse(values: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut values = values.peekable();
        let mut output = Self::default();
        while let Some(argument) = values.next() {
            match argument.as_str() {
                "--workspace-root" => {
                    output.workspace_root = Some(next_path(&mut values, &argument)?)
                }
                "--manifest" => output.manifest = Some(next_path(&mut values, &argument)?),
                "--output" => output.output = Some(next_path(&mut values, &argument)?),
                "--require-corpus-pass" => output.require_corpus_pass = true,
                "--emit-manifest" => output.emit_manifest = true,
                _ => return Err(format!("unknown argument `{argument}`")),
            }
        }
        if output.emit_manifest
            && (output.workspace_root.is_some()
                || output.manifest.is_some()
                || output.output.is_some()
                || output.require_corpus_pass)
        {
            return Err("--emit-manifest cannot be combined with runner arguments".to_owned());
        }
        Ok(output)
    }
}

fn next_path(
    values: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    flag: &str,
) -> Result<PathBuf, String> {
    values.next().map(PathBuf::from).ok_or_else(|| format!("{flag} requires a path"))
}

fn absolute_from(workspace: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() { path } else { workspace.join(path) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_reject_ambiguous_emit_mode() {
        assert!(Arguments::parse(["--emit-manifest".to_owned()].into_iter()).is_ok());
        assert!(
            Arguments::parse(
                ["--emit-manifest".to_owned(), "--require-corpus-pass".to_owned()].into_iter()
            )
            .is_err()
        );
    }
}
