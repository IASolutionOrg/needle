use needle_bench::{
    DerivedActionEvidenceClass, DerivedActionGateAcceptance, DerivedActionGateManifest,
    DerivedActionStudy, DerivedActionStudyOracleBundle, MAX_DERIVED_ACTION_GATE_ACCEPTANCE_BYTES,
    MAX_DERIVED_ACTION_GATE_MANIFEST_BYTES, MAX_DERIVED_ACTION_GATE_OBSERVATIONS_BYTES,
    MAX_DERIVED_ACTION_STUDY_BYTES, evaluate_derived_action_gate,
    parse_derived_action_observations, read_bounded_file, synthetic_derived_action_gate_material,
};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    if let Err(error) = run() {
        eprintln!("derived-action-gate-a3-preflight: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse(env::args().skip(1))?;
    if arguments.emit_synthetic_manifest || arguments.emit_synthetic_observations {
        let (manifest, observations) = synthetic_derived_action_gate_material();
        if arguments.emit_synthetic_manifest {
            println!("{}", serde_json::to_string_pretty(&manifest)?);
        } else {
            for observation in observations {
                println!("{}", serde_json::to_string(&observation)?);
            }
        }
        return Ok(());
    }

    let workspace = arguments.workspace_root.unwrap_or(env::current_dir()?).canonicalize()?;
    if let Some(study_path) = arguments.emit_study_manifest {
        let oracle_path =
            arguments.study_oracles.ok_or("--emit-study-manifest requires --study-oracles")?;
        let study = DerivedActionStudy::decode_json(&read_bounded_file(
            &absolute_from(&workspace, study_path),
            MAX_DERIVED_ACTION_STUDY_BYTES,
        )?)?;
        let oracles = DerivedActionStudyOracleBundle::decode_json(&read_bounded_file(
            &absolute_from(&workspace, oracle_path),
            MAX_DERIVED_ACTION_STUDY_BYTES,
        )?)?;
        let manifest = study.gate_manifest(DerivedActionEvidenceClass::AcceptedShadow, &oracles)?;
        println!("{}", serde_json::to_string_pretty(&manifest)?);
        return Ok(());
    }
    let manifest_path = absolute_from(
        &workspace,
        arguments.manifest.unwrap_or_else(|| {
            PathBuf::from("benchmarks/corpus/derived-actions/gate-a3-manifest.json")
        }),
    );
    let observations_path = absolute_from(
        &workspace,
        arguments.observations.unwrap_or_else(|| {
            PathBuf::from("benchmarks/corpus/derived-actions/synthetic-observations.jsonl")
        }),
    );
    let output = absolute_from(
        &workspace,
        arguments
            .output
            .unwrap_or_else(|| PathBuf::from("target/derived-action-gate-a3/report.json")),
    );
    let manifest = DerivedActionGateManifest::decode_json(&read_bounded_file(
        &manifest_path,
        MAX_DERIVED_ACTION_GATE_MANIFEST_BYTES,
    )?)?;
    let parsed = parse_derived_action_observations(&read_bounded_file(
        &observations_path,
        MAX_DERIVED_ACTION_GATE_OBSERVATIONS_BYTES,
    )?)?;
    let acceptance = if let Some(path) = arguments.acceptance {
        Some(DerivedActionGateAcceptance::decode_json(&read_bounded_file(
            &absolute_from(&workspace, path),
            MAX_DERIVED_ACTION_GATE_ACCEPTANCE_BYTES,
        )?)?)
    } else {
        None
    };
    let report = evaluate_derived_action_gate(&manifest, &parsed, acceptance.as_ref())?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", output.display());
    if !report.protocol_valid {
        return Err("offline protocol validation failed; see the written report".into());
    }
    if arguments.require_gate_pass && !report.gate_a3_passed {
        return Err("Gate A3 did not pass; see the written report".into());
    }
    Ok(())
}

#[derive(Default)]
struct Arguments {
    workspace_root: Option<PathBuf>,
    manifest: Option<PathBuf>,
    observations: Option<PathBuf>,
    acceptance: Option<PathBuf>,
    output: Option<PathBuf>,
    require_gate_pass: bool,
    emit_synthetic_manifest: bool,
    emit_synthetic_observations: bool,
    emit_study_manifest: Option<PathBuf>,
    study_oracles: Option<PathBuf>,
}

impl Arguments {
    fn parse(values: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut values = values.peekable();
        let mut output = Self::default();
        while let Some(argument) = values.next() {
            match argument.as_str() {
                "--workspace-root" => {
                    output.workspace_root = Some(next_path(&mut values, &argument)?);
                }
                "--manifest" => output.manifest = Some(next_path(&mut values, &argument)?),
                "--observations" => {
                    output.observations = Some(next_path(&mut values, &argument)?);
                }
                "--acceptance" => output.acceptance = Some(next_path(&mut values, &argument)?),
                "--output" => output.output = Some(next_path(&mut values, &argument)?),
                "--require-gate-pass" => output.require_gate_pass = true,
                "--emit-synthetic-manifest" => output.emit_synthetic_manifest = true,
                "--emit-synthetic-observations" => output.emit_synthetic_observations = true,
                "--emit-study-manifest" => {
                    output.emit_study_manifest = Some(next_path(&mut values, &argument)?);
                }
                "--study-oracles" => {
                    output.study_oracles = Some(next_path(&mut values, &argument)?);
                }
                _ => return Err(format!("unknown argument: {argument}")),
            }
        }
        let emit_count = usize::from(output.emit_synthetic_manifest)
            + usize::from(output.emit_synthetic_observations);
        if emit_count > 1 {
            return Err("select only one synthetic emission mode".to_owned());
        }
        if emit_count > 0
            && (output.workspace_root.is_some()
                || output.manifest.is_some()
                || output.observations.is_some()
                || output.acceptance.is_some()
                || output.output.is_some()
                || output.emit_study_manifest.is_some()
                || output.study_oracles.is_some()
                || output.require_gate_pass)
        {
            return Err("synthetic emission does not accept evaluation arguments".to_owned());
        }
        if output.emit_study_manifest.is_some() {
            if output.study_oracles.is_none() {
                return Err("--emit-study-manifest requires --study-oracles".to_owned());
            }
            if output.manifest.is_some()
                || output.observations.is_some()
                || output.acceptance.is_some()
                || output.output.is_some()
                || output.require_gate_pass
            {
                return Err("study emission does not accept evaluation arguments".to_owned());
            }
        } else if output.study_oracles.is_some() {
            return Err("--study-oracles requires --emit-study-manifest".to_owned());
        }
        Ok(output)
    }
}

fn next_path(
    values: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    option: &str,
) -> Result<PathBuf, String> {
    values.next().map(PathBuf::from).ok_or_else(|| format!("{option} requires a path"))
}

fn absolute_from(workspace: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() { path } else { workspace.join(path) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argument_parser_rejects_unknown_and_mixed_emission_modes() {
        assert!(Arguments::parse(["--unknown".to_owned()].into_iter()).is_err());
        assert!(
            Arguments::parse(
                [
                    "--emit-synthetic-manifest".to_owned(),
                    "--output".to_owned(),
                    "report.json".to_owned(),
                ]
                .into_iter(),
            )
            .is_err()
        );
        assert!(
            Arguments::parse(
                [
                    "--emit-synthetic-manifest".to_owned(),
                    "--emit-synthetic-observations".to_owned(),
                ]
                .into_iter(),
            )
            .is_err()
        );
        assert!(
            Arguments::parse(
                ["--emit-study-manifest".to_owned(), "study.json".to_owned(),].into_iter(),
            )
            .is_err()
        );
        assert!(
            Arguments::parse(
                [
                    "--emit-study-manifest".to_owned(),
                    "study.json".to_owned(),
                    "--study-oracles".to_owned(),
                    "oracles.json".to_owned(),
                ]
                .into_iter(),
            )
            .is_ok()
        );
    }
}
