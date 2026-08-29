use needle_core::{
    ArchitectureAssertion, ArchitectureAssertionKind, ArchitectureBrief, ArchitectureBriefScope,
    ArchitectureEvidence, ArchitectureEvidenceRole, ArchitecturePackageBrief, Digest,
    TestTargetInventoryScope, TestTargetPackageKey,
};
use needle_runtime::{
    ArchitectureBriefValidationInput, CargoTestTargetInventoryInput,
    MAX_ARCHITECTURE_EVIDENCE_FILE_BYTES, MAX_CARGO_METADATA_INPUT_BYTES,
    architecture_brief_analysis_definition, assemble_architecture_briefs,
    enumerate_cargo_test_targets, project_architecture_brief, validate_architecture_brief,
};
use serde_json::json;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

const VALIDATION_SAMPLES: usize = 25;
const PROJECTION_SAMPLES: usize = 2_000;
const ASSEMBLY_SAMPLES: usize = 500;

fn main() -> Result<(), String> {
    let root = repository_argument()?;
    let metadata = bounded_cargo_stdout(
        &root,
        &["metadata", "--no-deps", "--format-version", "1"],
        MAX_CARGO_METADATA_INPUT_BYTES,
    )?;
    let cargo_version = String::from_utf8(bounded_cargo_stdout(&root, &["--version"], 256)?)
        .map_err(|error| error.to_string())?;
    let repository_lineage = Digest::blake3(root.to_string_lossy().as_bytes());
    let inventory = enumerate_cargo_test_targets(CargoTestTargetInventoryInput {
        repository_root: &root,
        repository_lineage,
        source_selector: "benchmark-worktree",
        scope: TestTargetInventoryScope::all(),
        metadata_json: &metadata,
        cargo_version: cargo_version.trim(),
    })
    .map_err(|error| error.to_string())?;
    let brief = structural_fixture(&root, &inventory)?;
    let full_scope = ArchitectureBriefScope::all();
    let input = ArchitectureBriefValidationInput {
        repository_root: &root,
        repository_lineage,
        source_selector: "benchmark-worktree",
        workspace_manifest: &brief.workspace_manifest,
        scope: &full_scope,
        package_universe: &brief.package_universe,
    };

    let mut validation_nanos = Vec::with_capacity(VALIDATION_SAMPLES);
    for _ in 0..VALIDATION_SAMPLES {
        let started = Instant::now();
        let certificate =
            validate_architecture_brief(input, &brief).map_err(|error| error.to_string())?;
        std::hint::black_box(certificate);
        validation_nanos.push(elapsed_nanos(started));
    }

    let package = brief
        .package_universe
        .first()
        .cloned()
        .ok_or_else(|| "workspace contains no Cargo packages".to_owned())?;
    let package_scope =
        ArchitectureBriefScope::new(vec![package]).map_err(|error| error.to_string())?;
    let mut projection_nanos = Vec::with_capacity(PROJECTION_SAMPLES);
    for _ in 0..PROJECTION_SAMPLES {
        let started = Instant::now();
        let projected = project_architecture_brief(&brief, package_scope.clone())
            .map_err(|error| error.to_string())?;
        std::hint::black_box(projected);
        projection_nanos.push(elapsed_nanos(started));
    }

    let slices = brief
        .package_universe
        .iter()
        .cloned()
        .map(|package| {
            let scope =
                ArchitectureBriefScope::new(vec![package]).map_err(|error| error.to_string())?;
            project_architecture_brief(&brief, scope).map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut assembly_nanos = Vec::new();
    if slices.len() >= 2 {
        assembly_nanos.reserve(ASSEMBLY_SAMPLES);
        for _ in 0..ASSEMBLY_SAMPLES {
            let started = Instant::now();
            let assembled = assemble_architecture_briefs(&slices, ArchitectureBriefScope::all())
                .map_err(|error| error.to_string())?;
            std::hint::black_box(assembled);
            assembly_nanos.push(elapsed_nanos(started));
        }
    }

    let validation_p50 = median(&mut validation_nanos);
    let projection_p50 = median(&mut projection_nanos);
    let assembly_p50 = (!assembly_nanos.is_empty()).then(|| median(&mut assembly_nanos));
    let positive_structural_value = projection_p50 < validation_p50
        && assembly_p50.is_none_or(|assembly| assembly < validation_p50);
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "needle.architecture-brief-microbench/1",
            "classification": "offline-structural-shadow-fixture",
            "repository": root,
            "packages": brief.package_universe.len(),
            "evidence": brief.evidence.len(),
            "assertions": brief.packages.iter().map(|package| package.assertions.len()).sum::<usize>(),
            "samples": {
                "validation": VALIDATION_SAMPLES,
                "projection": PROJECTION_SAMPLES,
                "assembly": assembly_nanos.len(),
            },
            "p50_nanos": {
                "validation": validation_p50,
                "projection": projection_p50,
                "assembly": assembly_p50,
            },
            "positive_structural_value": positive_structural_value,
            "semantic_generation_economics": "unmeasured",
            "gate_a3": "pending-provider-or-accepted-shadow-evidence",
            "authority": "shadow",
        }))
        .map_err(|error| error.to_string())?
    );
    Ok(())
}

fn structural_fixture(
    root: &Path,
    inventory: &needle_core::TestTargetInventory,
) -> Result<ArchitectureBrief, String> {
    let workspace_manifest = inventory
        .partitions
        .first()
        .map(|partition| partition.key.workspace.clone())
        .ok_or_else(|| "inventory contains no test targets".to_owned())?;
    let workspace =
        evidence(root, &workspace_manifest, vec![ArchitectureEvidenceRole::Manifest], Vec::new())?;
    let mut evidence_items = vec![workspace.clone()];
    let mut package_briefs = Vec::with_capacity(inventory.package_universe.len());
    for package in &inventory.package_universe {
        let source_path = inventory
            .partitions
            .iter()
            .find(|partition| &partition.key.package == package)
            .map(|partition| partition.source_path.clone())
            .ok_or_else(|| {
                format!("package {} contains no test-enabled Cargo target", package.name)
            })?;
        let manifest = evidence(
            root,
            &package.manifest_path,
            vec![
                ArchitectureEvidenceRole::Manifest,
                ArchitectureEvidenceRole::DependencyDeclaration,
                ArchitectureEvidenceRole::Supporting,
            ],
            vec![package.clone()],
        )?;
        let source = evidence(
            root,
            &source_path,
            vec![
                ArchitectureEvidenceRole::EntryPoint,
                ArchitectureEvidenceRole::PublicBoundary,
                ArchitectureEvidenceRole::Supporting,
            ],
            vec![package.clone()],
        )?;
        let assertions = vec![
            ArchitectureAssertion::new(
                ArchitectureAssertionKind::Responsibility,
                format!("Offline fixture for Cargo package {}.", package.name),
                vec![source.id],
                Vec::new(),
            )
            .map_err(|error| error.to_string())?,
            ArchitectureAssertion::new(
                ArchitectureAssertionKind::EntryPoint,
                format!("{} is a Cargo target entry point.", source_path),
                vec![source.id],
                Vec::new(),
            )
            .map_err(|error| error.to_string())?,
        ];
        package_briefs.push(
            ArchitecturePackageBrief::new(
                package.clone(),
                format!(
                    "Package {} is represented by its manifest and one Cargo target.",
                    package.name
                ),
                vec![workspace.id, manifest.id, source.id],
                assertions,
                vec![
                    "Fixture does not establish complete responsibilities, dependencies, or public boundaries."
                        .to_owned(),
                ],
            )
            .map_err(|error| error.to_string())?,
        );
        evidence_items.push(manifest);
        evidence_items.push(source);
    }
    ArchitectureBrief::new(
        inventory.repository_lineage,
        inventory.source_selector.clone(),
        workspace_manifest,
        ArchitectureBriefScope::all(),
        architecture_brief_analysis_definition(),
        inventory.package_universe.clone(),
        evidence_items,
        package_briefs,
    )
    .map_err(|error| error.to_string())
}

fn evidence(
    root: &Path,
    relative: &str,
    roles: Vec<ArchitectureEvidenceRole>,
    packages: Vec<TestTargetPackageKey>,
) -> Result<ArchitectureEvidence, String> {
    let digest = bounded_file_digest(&root.join(relative))?;
    ArchitectureEvidence::new(relative, digest, None, None, roles, packages)
        .map_err(|error| error.to_string())
}

fn bounded_file_digest(path: &Path) -> Result<Digest, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| error.to_string())?
        .take((MAX_ARCHITECTURE_EVIDENCE_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > MAX_ARCHITECTURE_EVIDENCE_FILE_BYTES {
        return Err(format!("{} exceeds evidence bound", path.display()));
    }
    Ok(Digest::blake3(bytes))
}

fn repository_argument() -> Result<PathBuf, String> {
    let mut arguments = env::args_os().skip(1);
    let mut root = env::current_dir().map_err(|error| error.to_string())?;
    while let Some(argument) = arguments.next() {
        if argument == "--repository" {
            root = arguments
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "--repository requires a path".to_owned())?;
        } else {
            return Err(format!("unknown argument `{}`", argument.to_string_lossy()));
        }
    }
    root.canonicalize().map_err(|error| error.to_string())
}

fn bounded_cargo_stdout(
    root: &Path,
    arguments: &[&str],
    maximum: usize,
) -> Result<Vec<u8>, String> {
    let mut child = Command::new("cargo")
        .args(arguments)
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| error.to_string())?;
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .ok_or_else(|| "cargo stdout was not captured".to_owned())?
        .take((maximum + 1) as u64)
        .read_to_end(&mut output)
        .map_err(|error| error.to_string())?;
    let status = child.wait().map_err(|error| error.to_string())?;
    if !status.success() {
        return Err(format!("cargo exited with {status}"));
    }
    if output.len() > maximum {
        return Err(format!("cargo output exceeds {maximum} bytes"));
    }
    Ok(output)
}

fn elapsed_nanos(started: Instant) -> u64 {
    started.elapsed().as_nanos().try_into().unwrap_or(u64::MAX)
}

fn median(values: &mut [u64]) -> u64 {
    values.sort_unstable();
    values[values.len() / 2]
}
