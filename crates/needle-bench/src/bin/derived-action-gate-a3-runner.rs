use needle_bench::{
    DerivedActionChangedFile, DerivedActionExternalResults, DerivedActionGateManifest,
    DerivedActionPublicRun, DerivedActionSourceMaterial, DerivedActionStudy,
    MAX_DERIVED_ACTION_EXTERNAL_RESULTS_BYTES, MAX_DERIVED_ACTION_GATE_MANIFEST_BYTES,
    MAX_DERIVED_ACTION_GATE_REVIEW_MATERIAL_BYTES, MAX_DERIVED_ACTION_STUDY_BYTES,
    derived_action_public_run, import_derived_action_results, read_bounded_file,
};
use needle_runtime::MAX_CHANGE_IMPACT_BLOB_FILE_BYTES;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    if let Err(error) = run() {
        eprintln!("derived-action-gate-a3-runner: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse(env::args().skip(1))?;
    let workspace = arguments.workspace_root.unwrap_or(env::current_dir()?).canonicalize()?;
    let study = DerivedActionStudy::decode_json(&read_bounded_file(
        &absolute_from(&workspace, required(arguments.study, "--study")?),
        MAX_DERIVED_ACTION_STUDY_BYTES,
    )?)?;
    let manifest = DerivedActionGateManifest::decode_json(&read_bounded_file(
        &absolute_from(&workspace, required(arguments.manifest, "--manifest")?),
        MAX_DERIVED_ACTION_GATE_MANIFEST_BYTES,
    )?)?;
    let source_repository =
        absolute_from(&workspace, required(arguments.source_repository, "--source-repository")?)
            .canonicalize()?;
    let source = verified_source_material(&study, &source_repository)?;
    let output = absolute_from(&workspace, required(arguments.output, "--output")?);

    match arguments.mode {
        Mode::Export => {
            if arguments.public_inputs.is_some() || arguments.external_results.is_some() {
                return Err("export does not accept --public-inputs or --external-results".into());
            }
            let public = derived_action_public_run(&study, &manifest)?;
            write_json_create_new(&output, &public)?;
        }
        Mode::Import => {
            let public_path =
                absolute_from(&workspace, required(arguments.public_inputs, "--public-inputs")?);
            let external_path = absolute_from(
                &workspace,
                required(arguments.external_results, "--external-results")?,
            );
            let public = DerivedActionPublicRun::decode_json(&read_bounded_file(
                &public_path,
                MAX_DERIVED_ACTION_GATE_REVIEW_MATERIAL_BYTES,
            )?)?;
            let external = DerivedActionExternalResults::decode_json(&read_bounded_file(
                &external_path,
                MAX_DERIVED_ACTION_EXTERNAL_RESULTS_BYTES,
            )?)?;
            let review =
                import_derived_action_results(&study, &manifest, &public, &external, &source)?;
            write_json_create_new(&output, &review)?;
        }
    }
    println!("{}", output.display());
    Ok(())
}

fn verified_source_material(
    study: &DerivedActionStudy,
    repository: &Path,
) -> Result<DerivedActionSourceMaterial, String> {
    let head = git_text(repository, &["rev-parse", "HEAD"])?;
    if head.trim() != study.source.base_sha {
        return Err(format!("source HEAD must be the pinned base {}", study.source.base_sha));
    }
    if !git_text(repository, &["status", "--short"])?.trim().is_empty() {
        return Err("source repository must be clean".to_owned());
    }
    let parent =
        git_text(repository, &["rev-parse", &format!("{}^", study.source.change_target_sha)])?;
    if parent.trim() != study.source.base_sha {
        return Err("change target must have the pinned base as its first parent".to_owned());
    }
    let expected = expected_changed_paths(study)?;
    let mut actual = git_text(
        repository,
        &["diff", "--name-only", &study.source.base_sha, &study.source.change_target_sha],
    )?
    .lines()
    .filter(|line| !line.is_empty())
    .map(str::to_owned)
    .collect::<Vec<_>>();
    actual.sort();
    if actual != expected {
        return Err(format!("pinned diff paths do not match study: {actual:?}"));
    }
    let changes = expected
        .into_iter()
        .map(|path| {
            let before = bounded_file(&repository.join(&path))?;
            let after = git_blob(
                repository,
                &study.source.change_target_sha,
                &path,
                MAX_CHANGE_IMPACT_BLOB_FILE_BYTES,
            )?;
            Ok(DerivedActionChangedFile { path, before: Some(before), after: Some(after) })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(DerivedActionSourceMaterial { repository_root: repository.to_path_buf(), changes })
}

fn expected_changed_paths(study: &DerivedActionStudy) -> Result<Vec<String>, String> {
    let mut values = study
        .tasks
        .iter()
        .filter_map(|task| match &task.fixture {
            needle_bench::DerivedActionStudyFixture::ChangeImpact(fixture) => {
                Some(fixture.changed_paths.clone())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let first = values.pop().ok_or_else(|| "study contains no change fixture".to_owned())?;
    if values.iter().any(|value| value != &first) {
        return Err("change tasks do not share one changed-path set".to_owned());
    }
    Ok(first)
}

fn bounded_file(path: &Path) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?
        .take((MAX_CHANGE_IMPACT_BLOB_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if bytes.len() > MAX_CHANGE_IMPACT_BLOB_FILE_BYTES {
        return Err(format!("{} exceeds the change blob bound", path.display()));
    }
    Ok(bytes)
}

fn git_blob(
    repository: &Path,
    revision: &str,
    path: &str,
    maximum: usize,
) -> Result<Vec<u8>, String> {
    let object = format!("{revision}:{path}");
    let size = git_text(repository, &["cat-file", "-s", &object])?
        .trim()
        .parse::<usize>()
        .map_err(|error| format!("invalid git blob size for {path}: {error}"))?;
    if size > maximum {
        return Err(format!("git blob {path} contains {size} bytes; maximum is {maximum}"));
    }
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["show", &object])
        .output()
        .map_err(|error| format!("git could not be started: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    if output.stdout.len() != size {
        return Err(format!("git blob {path} size changed while reading"));
    }
    Ok(output.stdout)
}

fn git_text(repository: &Path, arguments: &[&str]) -> Result<String, String> {
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

fn absolute_from(workspace: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() { path } else { workspace.join(path) }
}

fn required<T>(value: Option<T>, name: &str) -> Result<T, String> {
    value.ok_or_else(|| format!("{name} is required"))
}

#[derive(Clone, Copy)]
enum Mode {
    Export,
    Import,
}

#[derive(Default)]
struct Arguments {
    mode: Option<Mode>,
    workspace_root: Option<PathBuf>,
    study: Option<PathBuf>,
    manifest: Option<PathBuf>,
    public_inputs: Option<PathBuf>,
    external_results: Option<PathBuf>,
    source_repository: Option<PathBuf>,
    output: Option<PathBuf>,
}

impl Arguments {
    fn parse(values: impl Iterator<Item = String>) -> Result<ParsedArguments, String> {
        let mut values = values.peekable();
        let mut output = Self::default();
        let mode = values.next().ok_or_else(|| "expected export or import".to_owned())?;
        output.mode = Some(match mode.as_str() {
            "export" => Mode::Export,
            "import" => Mode::Import,
            _ => return Err("first argument must be export or import".to_owned()),
        });
        while let Some(argument) = values.next() {
            match argument.as_str() {
                "--workspace-root" => {
                    output.workspace_root = Some(next_path(&mut values, &argument)?);
                }
                "--study" => output.study = Some(next_path(&mut values, &argument)?),
                "--manifest" => output.manifest = Some(next_path(&mut values, &argument)?),
                "--public-inputs" => {
                    output.public_inputs = Some(next_path(&mut values, &argument)?);
                }
                "--external-results" => {
                    output.external_results = Some(next_path(&mut values, &argument)?);
                }
                "--source-repository" => {
                    output.source_repository = Some(next_path(&mut values, &argument)?);
                }
                "--output" => output.output = Some(next_path(&mut values, &argument)?),
                _ => return Err(format!("unknown argument: {argument}")),
            }
        }
        Ok(ParsedArguments {
            mode: output.mode.expect("mode was assigned"),
            workspace_root: output.workspace_root,
            study: output.study,
            manifest: output.manifest,
            public_inputs: output.public_inputs,
            external_results: output.external_results,
            source_repository: output.source_repository,
            output: output.output,
        })
    }
}

struct ParsedArguments {
    mode: Mode,
    workspace_root: Option<PathBuf>,
    study: Option<PathBuf>,
    manifest: Option<PathBuf>,
    public_inputs: Option<PathBuf>,
    external_results: Option<PathBuf>,
    source_repository: Option<PathBuf>,
    output: Option<PathBuf>,
}

fn next_path(
    values: &mut std::iter::Peekable<impl Iterator<Item = String>>,
    option: &str,
) -> Result<PathBuf, String> {
    values.next().map(PathBuf::from).ok_or_else(|| format!("{option} requires a path"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_requires_mode_and_rejects_unknown_arguments() {
        assert!(Arguments::parse(std::iter::empty()).is_err());
        assert!(Arguments::parse(["run".to_owned()].into_iter()).is_err());
        assert!(
            Arguments::parse(["export".to_owned(), "--unknown".to_owned()].into_iter()).is_err()
        );
        assert!(
            Arguments::parse(
                ["import".to_owned(), "--public-inputs".to_owned(), "public.json".to_owned(),]
                    .into_iter(),
            )
            .is_ok()
        );
    }
}
