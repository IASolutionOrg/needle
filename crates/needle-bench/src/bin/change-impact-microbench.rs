use needle_core::{
    ChangeId, ChangeImpact, ChangeImpactAssessment, ChangeImpactComponentKey,
    ChangeImpactConstraint, ChangeImpactDisposition, ChangeImpactEvidence,
    ChangeImpactEvidenceRole, ChangeImpactEvidenceState, ChangeImpactKind, ChangeImpactRequirement,
    ChangeImpactScope, Digest, PatchArtifact, PatchFile, PatchOperation, Subject, SubjectKind,
};
use needle_runtime::{
    ChangeImpactValidationInput, MAX_CHANGE_IMPACT_BLOB_FILE_BYTES, PatchFileBlob,
    assemble_change_impacts, change_impact_analysis_definition, derive_change_impact_change_set,
    project_change_impact, validate_change_impact,
};
use serde_json::json;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

const VALIDATION_SAMPLES: usize = 100;
const PROJECTION_SAMPLES: usize = 2_000;
const ASSEMBLY_SAMPLES: usize = 1_000;
const FIXTURE_PATH: &str = "Cargo.toml";

fn main() -> Result<(), String> {
    let root = repository_argument()?;
    let fixture = structural_fixture(&root)?;
    let full_scope = ChangeImpactScope::all();
    let input = validation_input(&root, &fixture, &full_scope);

    let mut validation_nanos = Vec::with_capacity(VALIDATION_SAMPLES);
    for _ in 0..VALIDATION_SAMPLES {
        let started = Instant::now();
        let certificate =
            validate_change_impact(input, &fixture.impact).map_err(|error| error.to_string())?;
        std::hint::black_box(certificate);
        validation_nanos.push(elapsed_nanos(started));
    }

    let components = fixture.impact.component_universe();
    let first_scope =
        ChangeImpactScope::new(vec![components[0]]).map_err(|error| error.to_string())?;
    let second_scope =
        ChangeImpactScope::new(vec![components[1]]).map_err(|error| error.to_string())?;
    let mut projection_nanos = Vec::with_capacity(PROJECTION_SAMPLES);
    for _ in 0..PROJECTION_SAMPLES {
        let started = Instant::now();
        let projected = project_change_impact(&fixture.impact, first_scope.clone())
            .map_err(|error| error.to_string())?;
        std::hint::black_box(projected);
        projection_nanos.push(elapsed_nanos(started));
    }

    let slices = vec![
        project_change_impact(&fixture.impact, first_scope).map_err(|error| error.to_string())?,
        project_change_impact(&fixture.impact, second_scope).map_err(|error| error.to_string())?,
    ];
    let mut assembly_nanos = Vec::with_capacity(ASSEMBLY_SAMPLES);
    for _ in 0..ASSEMBLY_SAMPLES {
        let started = Instant::now();
        let assembled = assemble_change_impacts(&slices, ChangeImpactScope::all())
            .map_err(|error| error.to_string())?;
        std::hint::black_box(assembled);
        assembly_nanos.push(elapsed_nanos(started));
    }

    let validation_p50 = median(&mut validation_nanos);
    let projection_p50 = median(&mut projection_nanos);
    let assembly_p50 = median(&mut assembly_nanos);
    let positive_structural_value =
        projection_p50 < validation_p50 && assembly_p50 < validation_p50;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "needle.change-impact-microbench/1",
            "classification": "offline-structural-shadow-fixture",
            "repository": root,
            "files": fixture.impact.change_set.files.len(),
            "requirements": fixture.impact.requirement_universe.len(),
            "subjects": fixture.impact.subject_universe.len(),
            "components": components.len(),
            "evidence": fixture.impact.evidence.len(),
            "samples": {
                "validation": VALIDATION_SAMPLES,
                "projection": PROJECTION_SAMPLES,
                "assembly": ASSEMBLY_SAMPLES,
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

struct Fixture {
    repository_lineage: Digest,
    patch: PatchArtifact,
    blobs: Vec<PatchFileBlob>,
    requirements: Vec<ChangeImpactRequirement>,
    constraints: Vec<ChangeImpactConstraint>,
    subjects: Vec<Subject>,
    impact: ChangeImpact,
}

fn structural_fixture(root: &Path) -> Result<Fixture, String> {
    let before = bounded_file_bytes(&root.join(FIXTURE_PATH))?;
    let mut after = before.clone();
    after.extend_from_slice(b"\n# needle change-impact offline benchmark fixture\n");
    if after.len() > MAX_CHANGE_IMPACT_BLOB_FILE_BYTES {
        return Err("synthetic after state exceeds the change-impact file bound".to_owned());
    }

    let source_snapshot = Digest::blake3(root.to_string_lossy().as_bytes());
    let file = PatchFile {
        path: FIXTURE_PATH.to_owned(),
        operation: PatchOperation::Update,
        before_digest: Some(Digest::blake3(&before)),
        after_digest: Some(Digest::blake3(&after)),
        before_bytes: before.len().try_into().map_err(|_| "before size exceeds u64")?,
        after_bytes: after.len().try_into().map_err(|_| "after size exceeds u64")?,
    };
    let patch = PatchArtifact {
        id: PatchArtifact::compute_id(source_snapshot, std::slice::from_ref(&file)),
        change_id: ChangeId::from_digest(Digest::blake3(b"change-impact-offline-benchmark")),
        revision: 1,
        source_snapshot,
        files: vec![file],
        summary: "Synthetic in-memory Cargo manifest change.".to_owned(),
        acceptance_coverage: Vec::new(),
        residual_risks: Vec::new(),
        declared_output_digest: Digest::blake3(&after),
        discrepancies: Vec::new(),
    };
    let blobs = vec![PatchFileBlob {
        path: FIXTURE_PATH.to_owned(),
        before: Some(before.clone()),
        after: Some(after.clone()),
    }];
    let change_set =
        derive_change_impact_change_set(&patch, &blobs).map_err(|error| error.to_string())?;
    let repository_lineage = Digest::blake3(root.to_string_lossy().as_bytes());
    let requirements = vec![
        ChangeImpactRequirement::new("Preserve workspace build behavior.")
            .map_err(|error| error.to_string())?,
    ];
    let constraints = vec![
        ChangeImpactConstraint::new("Do not change runtime source files.")
            .map_err(|error| error.to_string())?,
    ];
    let mut subjects = vec![
        Subject::exact(repository_lineage, SubjectKind::File, FIXTURE_PATH),
        Subject::exact(repository_lineage, SubjectKind::Module, "workspace"),
    ];
    subjects.sort_by_key(|subject| subject.id);
    let before_evidence = ChangeImpactEvidence::new(
        FIXTURE_PATH,
        ChangeImpactEvidenceState::Before,
        Digest::blake3(&before),
        None,
        None,
        vec![ChangeImpactEvidenceRole::ChangedSurface],
        subjects.iter().map(|subject| subject.id).collect(),
    )
    .map_err(|error| error.to_string())?;
    let after_evidence = ChangeImpactEvidence::new(
        FIXTURE_PATH,
        ChangeImpactEvidenceState::After,
        Digest::blake3(&after),
        None,
        None,
        vec![
            ChangeImpactEvidenceRole::ChangedSurface,
            ChangeImpactEvidenceRole::DependencyDeclaration,
        ],
        subjects.iter().map(|subject| subject.id).collect(),
    )
    .map_err(|error| error.to_string())?;
    let assessments = subjects
        .iter()
        .enumerate()
        .map(|(index, subject)| {
            let key =
                ChangeImpactComponentKey { requirement: requirements[0].id, subject: subject.id };
            if index == 0 {
                ChangeImpactAssessment::new(
                    key,
                    ChangeImpactDisposition::Affected,
                    vec![ChangeImpactKind::Build],
                    "The synthetic manifest change can affect workspace build configuration.",
                    vec![after_evidence.id],
                    Vec::new(),
                    vec![FIXTURE_PATH.to_owned()],
                    Vec::new(),
                )
            } else {
                ChangeImpactAssessment::new(
                    key,
                    ChangeImpactDisposition::Unknown,
                    Vec::new(),
                    "The offline fixture does not establish transitive workspace impact.",
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                )
            }
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    let impact = ChangeImpact::new(
        repository_lineage,
        "benchmark-worktree",
        change_set,
        ChangeImpactScope::all(),
        change_impact_analysis_definition(),
        requirements.clone(),
        constraints.clone(),
        subjects.clone(),
        Vec::new(),
        None,
        None,
        vec![before_evidence, after_evidence],
        assessments,
        vec!["Semantic generation economics are not measured by this fixture.".to_owned()],
    )
    .map_err(|error| error.to_string())?;
    Ok(Fixture { repository_lineage, patch, blobs, requirements, constraints, subjects, impact })
}

fn validation_input<'a>(
    root: &'a Path,
    fixture: &'a Fixture,
    scope: &'a ChangeImpactScope,
) -> ChangeImpactValidationInput<'a> {
    ChangeImpactValidationInput {
        repository_root: root,
        repository_lineage: fixture.repository_lineage,
        source_selector: "benchmark-worktree",
        patch: &fixture.patch,
        patch_blobs: &fixture.blobs,
        scope,
        requirements: &fixture.requirements,
        constraints: &fixture.constraints,
        subjects: &fixture.subjects,
        accepted_inputs: &[],
        test_inventory: None,
        test_inventory_certificate: None,
    }
}

fn bounded_file_bytes(path: &Path) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| error.to_string())?
        .take((MAX_CHANGE_IMPACT_BLOB_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > MAX_CHANGE_IMPACT_BLOB_FILE_BYTES {
        return Err(format!("{} exceeds change-impact file bound", path.display()));
    }
    Ok(bytes)
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

fn elapsed_nanos(started: Instant) -> u64 {
    started.elapsed().as_nanos().try_into().unwrap_or(u64::MAX)
}

fn median(values: &mut [u64]) -> u64 {
    values.sort_unstable();
    values[values.len() / 2]
}
