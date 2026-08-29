use super::*;
use needle_core::{
    ChangeId, ChangeImpactAssessment, ChangeImpactComponentKey, ChangeImpactDisposition,
    ChangeImpactEvidence, ChangeImpactEvidenceRole, ChangeImpactEvidenceState, ChangeImpactKind,
    ChangeImpactRequirement, PatchFile, PatchOperation, SubjectKind, TestTargetInventory,
};
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

struct Fixture {
    root: PathBuf,
    patch: PatchArtifact,
    blobs: Vec<PatchFileBlob>,
    requirements: Vec<ChangeImpactRequirement>,
    constraints: Vec<ChangeImpactConstraint>,
    subjects: Vec<Subject>,
    impact: ChangeImpact,
    test_inventory: TestTargetInventory,
    test_inventory_certificate: crate::TestTargetInventoryValidationCertificate,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let root = std::env::temp_dir().join(format!("needle-change-impact-{nonce}"));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("crates/fixture/src")).unwrap();
        fs::create_dir_all(root.join("crates/fixture/tests")).unwrap();
        fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = [\"crates/*\"]\n").unwrap();
        fs::write(
            root.join("crates/fixture/Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), b"before").unwrap();
        fs::write(root.join("crates/fixture/src/lib.rs"), "pub fn fixture() {}\n").unwrap();
        fs::write(root.join("crates/fixture/tests/impact.rs"), "#[test] fn impact() {}\n").unwrap();

        let source_snapshot = Digest::blake3(b"source");
        let file = PatchFile {
            path: "src/lib.rs".to_owned(),
            operation: PatchOperation::Update,
            before_digest: Some(Digest::blake3(b"before")),
            after_digest: Some(Digest::blake3(b"after")),
            before_bytes: 6,
            after_bytes: 5,
        };
        let patch_id = PatchArtifact::compute_id(source_snapshot, std::slice::from_ref(&file));
        let patch = PatchArtifact {
            id: patch_id,
            change_id: ChangeId::from_digest(Digest::blake3(b"change")),
            revision: 1,
            source_snapshot,
            files: vec![file],
            summary: "Update dispatch behavior.".to_owned(),
            acceptance_coverage: Vec::new(),
            residual_risks: Vec::new(),
            declared_output_digest: Digest::blake3(b"declared"),
            discrepancies: Vec::new(),
        };
        let blobs = vec![PatchFileBlob {
            path: "src/lib.rs".to_owned(),
            before: Some(b"before".to_vec()),
            after: Some(b"after".to_vec()),
        }];
        let change_set = derive_change_impact_change_set(&patch, &blobs).unwrap();
        let repository = Digest::blake3(b"repository");
        let requirements = vec![ChangeImpactRequirement::new("Preserve public behavior.").unwrap()];
        let constraints =
            vec![ChangeImpactConstraint::new("Maintain backward compatibility.").unwrap()];
        let mut subjects = vec![
            Subject::exact(repository, SubjectKind::Symbol, "alpha::dispatch"),
            Subject::exact(repository, SubjectKind::Module, "beta"),
        ];
        subjects.sort_by_key(|subject| subject.id);
        let before = ChangeImpactEvidence::new(
            "src/lib.rs",
            ChangeImpactEvidenceState::Before,
            Digest::blake3(b"before"),
            None,
            None,
            vec![ChangeImpactEvidenceRole::ChangedSurface],
            vec![subjects[0].id],
        )
        .unwrap();
        let after = ChangeImpactEvidence::new(
            "src/lib.rs",
            ChangeImpactEvidenceState::After,
            Digest::blake3(b"after"),
            None,
            None,
            vec![
                ChangeImpactEvidenceRole::ChangedSurface,
                ChangeImpactEvidenceRole::Implementation,
            ],
            vec![subjects[0].id],
        )
        .unwrap();
        let assessments = subjects
            .iter()
            .enumerate()
            .map(|(index, subject)| {
                let key = ChangeImpactComponentKey {
                    requirement: requirements[0].id,
                    subject: subject.id,
                };
                if index == 0 {
                    ChangeImpactAssessment::new(
                        key,
                        ChangeImpactDisposition::Affected,
                        vec![ChangeImpactKind::RuntimeBehavior],
                        "The changed implementation can alter dispatch behavior.",
                        vec![after.id],
                        Vec::new(),
                        vec!["src/lib.rs".to_owned()],
                        Vec::new(),
                    )
                } else {
                    ChangeImpactAssessment::new(
                        key,
                        ChangeImpactDisposition::Unknown,
                        Vec::new(),
                        "No complete dependency evidence was supplied for this module.",
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                    )
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let impact = ChangeImpact::new(
            repository,
            "worktree",
            change_set,
            ChangeImpactScope::all(),
            change_impact_analysis_definition(),
            requirements.clone(),
            constraints.clone(),
            subjects.clone(),
            Vec::new(),
            None,
            None,
            vec![before, after],
            assessments,
            vec!["Transitive callers are not fully enumerated.".to_owned()],
        )
        .unwrap();
        let package_id = "path+file:///fixture#0.1.0";
        let metadata = serde_json::to_vec(&json!({
            "packages": [{
                "id": package_id,
                "name": "fixture",
                "manifest_path": root.join("crates/fixture/Cargo.toml"),
                "targets": [
                    {
                        "name": "fixture",
                        "kind": ["lib"],
                        "crate_types": ["lib"],
                        "required_features": [],
                        "src_path": root.join("crates/fixture/src/lib.rs"),
                        "edition": "2024",
                        "test": true,
                        "doctest": true
                    },
                    {
                        "name": "impact",
                        "kind": ["test"],
                        "crate_types": ["bin"],
                        "required_features": [],
                        "src_path": root.join("crates/fixture/tests/impact.rs"),
                        "edition": "2024",
                        "test": true,
                        "doctest": false
                    }
                ]
            }],
            "workspace_members": [package_id],
            "workspace_root": root,
        }))
        .unwrap();
        let inventory_input = || crate::CargoTestTargetInventoryInput {
            repository_root: &root,
            repository_lineage: repository,
            source_selector: "worktree",
            scope: needle_core::TestTargetInventoryScope::all(),
            metadata_json: &metadata,
            cargo_version: "cargo 1.90.0",
        };
        let test_inventory = crate::enumerate_cargo_test_targets(inventory_input()).unwrap();
        let test_inventory_certificate =
            crate::validate_cargo_test_target_inventory(inventory_input(), &test_inventory)
                .unwrap();
        Self {
            root,
            patch,
            blobs,
            requirements,
            constraints,
            subjects,
            impact,
            test_inventory,
            test_inventory_certificate,
        }
    }

    fn input<'a>(&'a self, scope: &'a ChangeImpactScope) -> ChangeImpactValidationInput<'a> {
        ChangeImpactValidationInput {
            repository_root: &self.root,
            repository_lineage: Digest::blake3(b"repository"),
            source_selector: "worktree",
            patch: &self.patch,
            patch_blobs: &self.blobs,
            scope,
            requirements: &self.requirements,
            constraints: &self.constraints,
            subjects: &self.subjects,
            accepted_inputs: &[],
            test_inventory: None,
            test_inventory_certificate: None,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn patch_adapter_and_validator_are_deterministic_and_detect_blob_drift() {
    let fixture = Fixture::new();
    let scope = ChangeImpactScope::all();
    let left = validate_change_impact(fixture.input(&scope), &fixture.impact).unwrap();
    let right = validate_change_impact(fixture.input(&scope), &fixture.impact).unwrap();
    assert_eq!(left, right);
    assert_eq!(left.change_set_digest, fixture.impact.change_set.digest);

    let mut drifted = fixture.blobs.clone();
    drifted[0].after = Some(b"drift".to_vec());
    let input = ChangeImpactValidationInput { patch_blobs: &drifted, ..fixture.input(&scope) };
    assert!(matches!(
        validate_change_impact(input, &fixture.impact),
        Err(ChangeImpactRuntimeError::Patch(_))
    ));
}

#[test]
fn requirement_subject_projection_and_disjoint_assembly_roundtrip() {
    let fixture = Fixture::new();
    let keys = fixture.impact.component_universe();
    let first_scope = ChangeImpactScope::new(vec![keys[0]]).unwrap();
    let second_scope = ChangeImpactScope::new(vec![keys[1]]).unwrap();
    let first = project_change_impact(&fixture.impact, first_scope.clone()).unwrap();
    let second = project_change_impact(&fixture.impact, second_scope.clone()).unwrap();
    validate_change_impact(fixture.input(&first_scope), &first).unwrap();
    validate_change_impact(fixture.input(&second_scope), &second).unwrap();
    let assembled =
        assemble_change_impacts(&[second.clone(), first.clone()], ChangeImpactScope::all())
            .unwrap();
    assert_eq!(assembled, fixture.impact);
    assert!(matches!(
        assemble_change_impacts(&[first.clone(), first], ChangeImpactScope::all()),
        Err(ChangeImpactRuntimeError::Assembly)
    ));
}

#[test]
fn validator_rejects_missing_changed_surface_and_binding_drift() {
    let fixture = Fixture::new();
    let scope = ChangeImpactScope::all();
    let after_only = fixture
        .impact
        .evidence
        .iter()
        .filter(|evidence| evidence.state == ChangeImpactEvidenceState::After)
        .cloned()
        .collect::<Vec<_>>();
    let missing = ChangeImpact::new(
        fixture.impact.repository_lineage,
        fixture.impact.source_selector.clone(),
        fixture.impact.change_set.clone(),
        fixture.impact.scope.clone(),
        fixture.impact.analysis_definition_digest,
        fixture.impact.requirement_universe.clone(),
        fixture.impact.constraints.clone(),
        fixture.impact.subject_universe.clone(),
        fixture.impact.accepted_inputs.clone(),
        None,
        None,
        after_only,
        fixture.impact.assessments.clone(),
        fixture.impact.gaps.clone(),
    )
    .unwrap();
    assert!(matches!(
        validate_change_impact(fixture.input(&scope), &missing),
        Err(ChangeImpactRuntimeError::ChangedSurfaceCoverage(path)) if path == "src/lib.rs"
    ));

    let wrong_requirements = vec![ChangeImpactRequirement::new("Different requirement.").unwrap()];
    let input =
        ChangeImpactValidationInput { requirements: &wrong_requirements, ..fixture.input(&scope) };
    assert_eq!(
        validate_change_impact(input, &fixture.impact),
        Err(ChangeImpactRuntimeError::Binding)
    );
}

fn impact_with_test_target(fixture: &Fixture, target: Digest) -> ChangeImpact {
    let mut assessments = fixture.impact.assessments.clone();
    let supported = &assessments[0];
    assessments[0] = ChangeImpactAssessment::new(
        supported.key,
        supported.disposition,
        supported.impact_kinds.clone(),
        supported.rationale.clone(),
        supported.evidence_ids.clone(),
        supported.input_artifact_ids.clone(),
        supported.affected_paths.clone(),
        vec![target],
    )
    .unwrap();
    ChangeImpact::new(
        fixture.impact.repository_lineage,
        fixture.impact.source_selector.clone(),
        fixture.impact.change_set.clone(),
        fixture.impact.scope.clone(),
        fixture.impact.analysis_definition_digest,
        fixture.impact.requirement_universe.clone(),
        fixture.impact.constraints.clone(),
        fixture.impact.subject_universe.clone(),
        fixture.impact.accepted_inputs.clone(),
        Some(fixture.test_inventory.content_digest),
        Some(fixture.test_inventory_certificate.certificate_digest),
        fixture.impact.evidence.clone(),
        assessments,
        fixture.impact.gaps.clone(),
    )
    .unwrap()
}

#[test]
fn test_target_references_require_the_matching_validated_inventory() {
    let fixture = Fixture::new();
    let scope = ChangeImpactScope::all();
    let target = fixture
        .test_inventory
        .partitions
        .iter()
        .find(|partition| partition.key.target_name == "impact")
        .unwrap()
        .content_digest;
    let impact = impact_with_test_target(&fixture, target);
    let input = ChangeImpactValidationInput {
        test_inventory: Some(&fixture.test_inventory),
        test_inventory_certificate: Some(&fixture.test_inventory_certificate),
        ..fixture.input(&scope)
    };
    validate_change_impact(input, &impact).unwrap();
    assert_eq!(
        validate_change_impact(fixture.input(&scope), &impact),
        Err(ChangeImpactRuntimeError::TestInventoryBinding)
    );

    let unknown = impact_with_test_target(&fixture, Digest::blake3(b"unknown-target"));
    let input = ChangeImpactValidationInput {
        test_inventory: Some(&fixture.test_inventory),
        test_inventory_certificate: Some(&fixture.test_inventory_certificate),
        ..fixture.input(&scope)
    };
    assert_eq!(
        validate_change_impact(input, &unknown),
        Err(ChangeImpactRuntimeError::TestTargetReference)
    );
}

#[test]
fn patch_adapter_rejects_oversized_duplicate_and_unsafe_material() {
    let fixture = Fixture::new();
    let oversized = vec![PatchFileBlob {
        path: "src/lib.rs".to_owned(),
        before: Some(b"before".to_vec()),
        after: Some(vec![b'x'; MAX_CHANGE_IMPACT_BLOB_FILE_BYTES + 1]),
    }];
    assert!(matches!(
        derive_change_impact_change_set(&fixture.patch, &oversized),
        Err(ChangeImpactRuntimeError::BlobFileBound { .. })
    ));

    let mut duplicate_patch = fixture.patch.clone();
    duplicate_patch.files.push(duplicate_patch.files[0].clone());
    duplicate_patch.id =
        PatchArtifact::compute_id(duplicate_patch.source_snapshot, &duplicate_patch.files);
    let duplicate_blobs = vec![fixture.blobs[0].clone(), fixture.blobs[0].clone()];
    assert!(matches!(
        derive_change_impact_change_set(&duplicate_patch, &duplicate_blobs),
        Err(ChangeImpactRuntimeError::Patch(_))
    ));

    let mut unsafe_patch = fixture.patch.clone();
    unsafe_patch.files[0].path = "../escape.rs".to_owned();
    unsafe_patch.id = PatchArtifact::compute_id(unsafe_patch.source_snapshot, &unsafe_patch.files);
    let unsafe_blobs =
        vec![PatchFileBlob { path: "../escape.rs".to_owned(), ..fixture.blobs[0].clone() }];
    assert!(derive_change_impact_change_set(&unsafe_patch, &unsafe_blobs).is_err());
}
