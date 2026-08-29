use needle_bench::{
    DerivedActionEvidenceClass, DerivedActionGateAcceptance, DerivedActionGateAcceptanceDecision,
    DerivedActionGateManifest, DerivedActionKind, DerivedActionReuseScenario,
    MAX_DERIVED_ACTION_GATE_MANIFEST_BYTES, MAX_DERIVED_ACTION_GATE_OBSERVATIONS_BYTES,
    MAX_DERIVED_ACTION_GATE_REVIEW_MATERIAL_BYTES, evaluate_derived_action_gate,
    parse_derived_action_observations, read_bounded_file,
};
use needle_core::Digest;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    if let Err(error) = run() {
        eprintln!("derived-action-gate-a3-accept: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse(env::args().skip(1))?;
    let workspace = arguments.workspace_root.unwrap_or(env::current_dir()?).canonicalize()?;
    let manifest_path = absolute_from(&workspace, required(arguments.manifest, "--manifest")?);
    let observations_path =
        absolute_from(&workspace, required(arguments.observations, "--observations")?);
    let review_material_path =
        absolute_from(&workspace, required(arguments.review_material, "--review-material")?);
    let source_repository =
        absolute_from(&workspace, required(arguments.source_repository, "--source-repository")?)
            .canonicalize()?;
    let reviewer_id = required(arguments.reviewer_id, "--reviewer-id")?;
    let reviewed_unix_ms = required(arguments.reviewed_unix_ms, "--reviewed-unix-ms")?;
    if !arguments.confirm_bounded_shadow {
        return Err("--confirm-bounded-shadow is required".into());
    }
    if arguments.limitations.is_empty() {
        return Err("at least one --limitation is required".into());
    }

    let manifest = DerivedActionGateManifest::decode_json(&read_bounded_file(
        &manifest_path,
        MAX_DERIVED_ACTION_GATE_MANIFEST_BYTES,
    )?)?;
    if manifest.evidence_class != DerivedActionEvidenceClass::AcceptedShadow {
        return Err("the manifest evidence_class must be accepted_shadow".into());
    }
    verify_clean_source(&source_repository, &manifest.repository_sha)?;
    let parsed = parse_derived_action_observations(&read_bounded_file(
        &observations_path,
        MAX_DERIVED_ACTION_GATE_OBSERVATIONS_BYTES,
    )?)?;
    let preflight = evaluate_derived_action_gate(&manifest, &parsed, None)?;
    if !preflight.protocol_valid
        || !preflight.structural_validation_passed
        || !preflight.quality_passed
        || !preflight.semantic_equivalence_passed
        || !preflight.positive_net_value
    {
        return Err("the imported observation set does not pass the bounded preflight".into());
    }
    let review_material =
        read_bounded_file(&review_material_path, MAX_DERIVED_ACTION_GATE_REVIEW_MATERIAL_BYTES)?;
    if review_material.is_empty() {
        return Err("--review-material must not be empty".into());
    }
    let review_material_digest = Digest::blake3(review_material);
    let decisions = DerivedActionKind::ALL
        .into_iter()
        .flat_map(|action| {
            DerivedActionReuseScenario::ALL.into_iter().map(move |scenario| {
                DerivedActionGateAcceptanceDecision::accepted(action, scenario)
            })
        })
        .collect();
    let acceptance = DerivedActionGateAcceptance::new(
        manifest.manifest_digest,
        preflight.observation_set_digest,
        review_material_digest,
        reviewer_id,
        reviewed_unix_ms,
        decisions,
        arguments.limitations,
    )?;
    let report = evaluate_derived_action_gate(&manifest, &parsed, Some(&acceptance))?;
    if !report.gate_a3_passed {
        return Err("accepted Shadow report did not pass Gate A3".into());
    }
    verify_clean_source(&source_repository, &manifest.repository_sha)?;

    let acceptance_output = absolute_from(
        &workspace,
        arguments
            .acceptance_output
            .unwrap_or_else(|| PathBuf::from("target/derived-action-gate-a3/acceptance.json")),
    );
    let report_output = absolute_from(
        &workspace,
        arguments
            .report_output
            .unwrap_or_else(|| PathBuf::from("target/derived-action-gate-a3/accepted-report.json")),
    );
    if acceptance_output == report_output {
        return Err("acceptance and report outputs must be different paths".into());
    }
    if acceptance_output.exists() || report_output.exists() {
        return Err("acceptance outputs are immutable and must not already exist".into());
    }
    write_json_create_new(&report_output, &report)?;
    write_json_create_new(&acceptance_output, &acceptance)?;
    println!("{}", acceptance_output.display());
    println!("{}", report_output.display());
    Ok(())
}

fn verify_clean_source(repository: &Path, expected_sha: &str) -> Result<(), String> {
    let head = git_output(repository, &["rev-parse", "HEAD"])?;
    if head.trim() != expected_sha {
        return Err(format!("source HEAD does not match manifest repository_sha {expected_sha}"));
    }
    let status = git_output(repository, &["status", "--short"])?;
    if !status.trim().is_empty() {
        return Err("source repository must be clean before acceptance".to_owned());
    }
    Ok(())
}

fn git_output(repository: &Path, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .output()
        .map_err(|error| format!("git could not be started: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    String::from_utf8(output.stdout).map_err(|error| format!("git output is not UTF-8: {error}"))
}

fn write_json_create_new(
    path: &Path,
    value: &impl serde::Serialize,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn required<T>(value: Option<T>, name: &str) -> Result<T, String> {
    value.ok_or_else(|| format!("{name} is required"))
}

#[derive(Default)]
struct Arguments {
    workspace_root: Option<PathBuf>,
    manifest: Option<PathBuf>,
    observations: Option<PathBuf>,
    review_material: Option<PathBuf>,
    source_repository: Option<PathBuf>,
    reviewer_id: Option<String>,
    reviewed_unix_ms: Option<u64>,
    limitations: Vec<String>,
    acceptance_output: Option<PathBuf>,
    report_output: Option<PathBuf>,
    confirm_bounded_shadow: bool,
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
                "--review-material" => {
                    output.review_material = Some(next_path(&mut values, &argument)?);
                }
                "--source-repository" => {
                    output.source_repository = Some(next_path(&mut values, &argument)?);
                }
                "--reviewer-id" => {
                    output.reviewer_id = Some(next_value(&mut values, &argument)?);
                }
                "--reviewed-unix-ms" => {
                    let value = next_value(&mut values, &argument)?;
                    output.reviewed_unix_ms = Some(
                        value.parse().map_err(|_| "--reviewed-unix-ms must be a u64".to_owned())?,
                    );
                }
                "--limitation" => {
                    output.limitations.push(next_value(&mut values, &argument)?);
                }
                "--acceptance-output" => {
                    output.acceptance_output = Some(next_path(&mut values, &argument)?);
                }
                "--report-output" => {
                    output.report_output = Some(next_path(&mut values, &argument)?);
                }
                "--confirm-bounded-shadow" => output.confirm_bounded_shadow = true,
                _ => return Err(format!("unknown argument: {argument}")),
            }
        }
        Ok(output)
    }
}

fn next_value(
    values: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    option: &str,
) -> Result<String, String> {
    values.next().ok_or_else(|| format!("{option} requires a value"))
}

fn next_path(
    values: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    option: &str,
) -> Result<PathBuf, String> {
    next_value(values, option).map(PathBuf::from)
}

fn absolute_from(workspace: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() { path } else { workspace.join(path) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn argument_parser_is_explicit_and_rejects_bad_timestamp() {
        assert!(Arguments::parse(["--unknown".to_owned()].into_iter()).is_err());
        assert!(
            Arguments::parse(["--reviewed-unix-ms".to_owned(), "tomorrow".to_owned()].into_iter())
                .is_err()
        );
        let parsed = Arguments::parse(
            [
                "--limitation".to_owned(),
                "bounded".to_owned(),
                "--confirm-bounded-shadow".to_owned(),
            ]
            .into_iter(),
        )
        .unwrap();
        assert_eq!(parsed.limitations, vec!["bounded"]);
        assert!(parsed.confirm_bounded_shadow);
    }

    #[test]
    fn source_verification_requires_exact_head_and_clean_worktree() {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let root = env::temp_dir()
            .join(format!("needle-derived-action-accept-{}-{suffix}", std::process::id()));
        fs::create_dir(&root).unwrap();
        git_output(&root, &["init"]).unwrap();
        git_output(&root, &["config", "user.email", "needle@example.invalid"]).unwrap();
        git_output(&root, &["config", "user.name", "Needle Test"]).unwrap();
        fs::write(root.join("source.txt"), b"accepted source\n").unwrap();
        git_output(&root, &["add", "source.txt"]).unwrap();
        git_output(&root, &["commit", "-m", "fixture"]).unwrap();
        let head = git_output(&root, &["rev-parse", "HEAD"]).unwrap();
        assert!(verify_clean_source(&root, head.trim()).is_ok());
        assert!(
            verify_clean_source(&root, "0123456789abcdef0123456789abcdef01234567")
                .unwrap_err()
                .contains("does not match")
        );
        fs::write(root.join("source.txt"), b"changed\n").unwrap();
        assert!(verify_clean_source(&root, head.trim()).unwrap_err().contains("must be clean"));
        fs::remove_dir_all(root).unwrap();
    }
}
