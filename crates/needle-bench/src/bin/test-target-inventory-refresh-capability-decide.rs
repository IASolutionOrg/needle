use needle_bench::{
    LiveTestTargetRefreshCalibrationReport, LiveTestTargetRefreshCapabilityDecision,
    LiveTestTargetRefreshGateAcceptance, MAX_LIVE_TEST_TARGET_REFRESH_ACCEPTANCE_BYTES,
    MAX_LIVE_TEST_TARGET_REFRESH_ACCEPTED_REPORTS,
    MAX_LIVE_TEST_TARGET_REFRESH_CAPABILITY_DECISION_BYTES,
    MAX_LIVE_TEST_TARGET_REFRESH_REPORT_BYTES, read_bounded_file,
};
use needle_runtime::test_target_inventory_refresh_capability;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

fn main() {
    if let Err(error) = run() {
        eprintln!("test-target-inventory-refresh-capability-decide: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse(env::args().skip(1))?;
    arguments.validate()?;
    let workspace = arguments.workspace_root.unwrap_or(env::current_dir()?).canonicalize()?;
    let acceptance_path =
        absolute_from(&workspace, required(arguments.acceptance, "--acceptance")?);
    let acceptance = LiveTestTargetRefreshGateAcceptance::decode_json(&read_bounded_file(
        &acceptance_path,
        MAX_LIVE_TEST_TARGET_REFRESH_ACCEPTANCE_BYTES,
    )?)?;
    let reports = arguments
        .reports
        .into_iter()
        .map(|path| {
            LiveTestTargetRefreshCalibrationReport::decode_json(
                &read_bounded_file(
                    &absolute_from(&workspace, path),
                    MAX_LIVE_TEST_TARGET_REFRESH_REPORT_BYTES,
                )
                .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    acceptance.validate_for_reports(&reports)?;

    let capability = test_target_inventory_refresh_capability().clone();
    let decision = LiveTestTargetRefreshCapabilityDecision::new(
        &acceptance,
        capability.clone(),
        required(arguments.decider_id, "--decider-id")?,
        required(arguments.decided_unix_ms, "--decided-unix-ms")?,
    )?;
    decision.validate_for(&acceptance, &capability)?;
    let output = safe_absolute_from(
        &workspace,
        arguments.output.unwrap_or_else(|| {
            PathBuf::from("target/test-target-refresh-live/gate-a4-shadow-capability-decision.json")
        }),
    )?;
    write_json_create_new(&output, &decision)?;
    println!("{}", output.display());
    println!("decision_digest={}", decision.decision_digest);
    println!("capability_class_id={}", decision.capability_class.id);
    println!("capability_definition_digest={}", decision.capability_class.definition_digest);
    println!(
        "action_validation_definition_digest={}",
        decision.capability_class.action_validation_definition_digest
    );
    println!("definition_set_digest={}", decision.capability_class.definition_set_digest);
    println!("selected_mode=shadow");
    println!("operator_invocation_only=true");
    println!("gate_a4_closed=true");
    Ok(())
}

fn write_json_create_new(
    path: &Path,
    value: &LiveTestTargetRefreshCapabilityDecision,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_LIVE_TEST_TARGET_REFRESH_CAPABILITY_DECISION_BYTES {
        return Err("serialized capability decision exceeds its wire bound".into());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

#[derive(Default)]
struct Arguments {
    workspace_root: Option<PathBuf>,
    acceptance: Option<PathBuf>,
    reports: Vec<PathBuf>,
    decider_id: Option<String>,
    decided_unix_ms: Option<u64>,
    output: Option<PathBuf>,
    confirm_shadow_operator_only: bool,
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
                "--acceptance" => output.acceptance = Some(next_path(&mut values, &argument)?),
                "--report" => output.reports.push(next_path(&mut values, &argument)?),
                "--decider-id" => {
                    output.decider_id = Some(next_value(&mut values, &argument)?);
                }
                "--decided-unix-ms" => {
                    output.decided_unix_ms = Some(
                        next_value(&mut values, &argument)?
                            .parse()
                            .map_err(|_| "--decided-unix-ms must be a u64".to_owned())?,
                    );
                }
                "--output" => output.output = Some(next_path(&mut values, &argument)?),
                "--confirm-shadow-operator-only" => {
                    output.confirm_shadow_operator_only = true;
                }
                _ => return Err(format!("unknown argument: {argument}")),
            }
        }
        Ok(output)
    }

    fn validate(&self) -> Result<(), String> {
        if self.reports.is_empty()
            || self.reports.len() > MAX_LIVE_TEST_TARGET_REFRESH_ACCEPTED_REPORTS
        {
            return Err(format!(
                "between 1 and {MAX_LIVE_TEST_TARGET_REFRESH_ACCEPTED_REPORTS} --report values are required"
            ));
        }
        if !self.confirm_shadow_operator_only {
            return Err("--confirm-shadow-operator-only is required".to_owned());
        }
        Ok(())
    }
}

fn required<T>(value: Option<T>, name: &str) -> Result<T, String> {
    value.ok_or_else(|| format!("{name} is required"))
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

fn safe_absolute_from(workspace: &Path, path: PathBuf) -> Result<PathBuf, String> {
    if path.components().any(|component| matches!(component, std::path::Component::ParentDir)) {
        return Err("the capability output must not contain parent-directory components".to_owned());
    }
    Ok(absolute_from(workspace, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_require_evidence_and_explicit_shadow_confirmation() {
        let parsed = Arguments::parse(
            [
                "--acceptance",
                "acceptance.json",
                "--report",
                "report.json",
                "--decider-id",
                "local-owner",
                "--decided-unix-ms",
                "1754000000000",
                "--confirm-shadow-operator-only",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .unwrap();
        assert!(parsed.validate().is_ok());

        let missing_confirmation =
            Arguments::parse(["--report", "report.json"].into_iter().map(str::to_owned)).unwrap();
        assert!(missing_confirmation.validate().is_err());
        assert!(Arguments::parse(["--unknown".to_owned()].into_iter()).is_err());
    }
}
