use super::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const STUDY: &[u8] =
    include_bytes!("../../../../../benchmarks/corpus/derived-actions/thiserror/study.json");
const MANIFEST: &[u8] = include_bytes!(
    "../../../../../benchmarks/corpus/derived-actions/thiserror/gate-a3-manifest.json"
);

#[test]
fn public_run_exports_six_model_inputs_without_sealed_oracles() {
    let study = DerivedActionStudy::decode_json(STUDY).unwrap();
    let manifest = DerivedActionGateManifest::decode_json(MANIFEST).unwrap();
    let public = derived_action_public_run(&study, &manifest).unwrap();
    assert_eq!(public.tasks.len(), 6);
    let json = serde_json::to_string_pretty(&public).unwrap();
    assert!(!json.contains("oracle"));
    assert!(!json.contains("expected_facts"));
    assert!(json.contains("response_template"));

    let decoded = DerivedActionPublicRun::decode_json(json.as_bytes()).unwrap();
    assert_eq!(decoded, public);
}

#[test]
fn external_drafts_become_validated_fresh_and_local_reuse_artifacts() {
    let study = DerivedActionStudy::decode_json(STUDY).unwrap();
    let manifest = DerivedActionGateManifest::decode_json(MANIFEST).unwrap();
    let public = derived_action_public_run(&study, &manifest).unwrap();
    let root = fixture_root();
    write_fixture_source(&root);
    let source = DerivedActionSourceMaterial {
        repository_root: root.clone(),
        changes: vec![
            DerivedActionChangedFile {
                path: "impl/src/expand.rs".to_owned(),
                before: Some(b"pub fn expand() { old(); }\n".to_vec()),
                after: Some(b"pub fn expand() { allow_attributes(); }\n".to_vec()),
            },
            DerivedActionChangedFile {
                path: "tests/test_lints.rs".to_owned(),
                before: Some(b"fn old_lint_test() {}\n".to_vec()),
                after: Some(b"fn test_allow_attributes() {}\n".to_vec()),
            },
        ],
    };
    let external = external_results(&study, manifest.manifest_digest);
    let review =
        import_derived_action_results(&study, &manifest, &public, &external, &source).unwrap();
    assert_eq!(review.tasks.len(), 6);
    assert!(
        review.tasks.iter().all(|task| task.canonical_output_equal),
        "mismatches: {:?}",
        review
            .tasks
            .iter()
            .filter(|task| !task.canonical_output_equal)
            .map(|task| (
                task.task_id.as_str(),
                task.fresh.output_digest(),
                task.reuse.output_digest()
            ))
            .collect::<Vec<_>>()
    );
    assert!(review.tasks.iter().all(|task| task.reuse_latency_micros > 0));
    assert!(review.tasks.iter().all(|task| task.fresh.certificate_digest() != Digest([0; 32])));
    let encoded = serde_json::to_vec_pretty(&review).unwrap();
    let decoded = DerivedActionReviewMaterial::decode_json(&encoded).unwrap();
    assert_eq!(decoded, review);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn import_rejects_tampered_public_inputs_and_unbounded_external_wire() {
    let study = DerivedActionStudy::decode_json(STUDY).unwrap();
    let manifest = DerivedActionGateManifest::decode_json(MANIFEST).unwrap();
    let mut public = derived_action_public_run(&study, &manifest).unwrap();
    public.tasks[0].prompt.push_str(" tampered");
    let external = external_results(&study, manifest.manifest_digest);
    let source = DerivedActionSourceMaterial {
        repository_root: std::env::current_dir().unwrap(),
        changes: vec![
            DerivedActionChangedFile {
                path: "impl/src/expand.rs".to_owned(),
                before: Some(vec![1]),
                after: Some(vec![2]),
            },
            DerivedActionChangedFile {
                path: "tests/test_lints.rs".to_owned(),
                before: Some(vec![1]),
                after: Some(vec![2]),
            },
        ],
    };
    assert!(import_derived_action_results(&study, &manifest, &public, &external, &source).is_err());
    let oversized = vec![b' '; MAX_DERIVED_ACTION_EXTERNAL_RESULTS_BYTES + 1];
    assert!(DerivedActionExternalResults::decode_json(&oversized).is_err());
}

fn external_results(
    study: &DerivedActionStudy,
    manifest_digest: Digest,
) -> DerivedActionExternalResults {
    let tasks = study
        .tasks
        .iter()
        .map(|task| DerivedActionExternalTaskResult {
            task_id: task.id.clone(),
            model_id: "external-test-model".to_owned(),
            latency_micros: 100,
            total_cost_microcredits: 25,
            output: match &task.fixture {
                DerivedActionStudyFixture::ArchitectureBrief(fixture) => {
                    let names = if fixture.requested_packages.is_empty() {
                        fixture
                            .package_universe
                            .iter()
                            .map(|package| package.name.clone())
                            .collect()
                    } else {
                        fixture.requested_packages.clone()
                    };
                    DerivedActionExternalDraft::ArchitectureBrief(ArchitectureBriefDraft {
                        packages: names
                            .into_iter()
                            .map(|name| {
                                let package = fixture
                                    .package_universe
                                    .iter()
                                    .find(|package| package.name == name)
                                    .unwrap();
                                ArchitecturePackageDraft {
                                    package: name.clone(),
                                    summary: format!("{name} is a package in the pinned workspace."),
                                    summary_evidence_paths: vec![package.manifest_path.clone()],
                                    assertions: Vec::new(),
                                    gaps: vec!["Runtime behavior is not established by manifests alone."
                                        .to_owned()],
                                }
                            })
                            .collect(),
                    })
                }
                DerivedActionStudyFixture::ChangeImpact(fixture) => {
                    let components = if fixture.requested_components.is_empty() {
                        fixture.components.iter().map(|value| value.id.clone()).collect()
                    } else {
                        fixture.requested_components.clone()
                    };
                    DerivedActionExternalDraft::ChangeImpact(ChangeImpactDraft {
                        assessments: components
                            .into_iter()
                            .map(|component| {
                                let (path, kind, role, rationale) =
                                    if component == "from-impl-expansion" {
                                        (
                                            "impl/src/expand.rs",
                                            ChangeImpactKind::RuntimeBehavior,
                                            ChangeImpactEvidenceRole::Implementation,
                                            "The generated implementation changes its emitted attributes.",
                                        )
                                    } else {
                                        (
                                            "tests/test_lints.rs",
                                            ChangeImpactKind::Test,
                                            ChangeImpactEvidenceRole::Test,
                                            "The regression test changes to cover allow attributes.",
                                        )
                                    };
                                ChangeImpactAssessmentDraft {
                                    component,
                                    disposition: ChangeImpactDisposition::Affected,
                                    impact_kinds: vec![kind],
                                    rationale: rationale.to_owned(),
                                    evidence: vec![ChangeImpactEvidenceDraft {
                                        path: path.to_owned(),
                                        state: ChangeImpactEvidenceState::After,
                                        roles: vec![role],
                                    }],
                                    affected_paths: vec![path.to_owned()],
                                }
                            })
                            .collect(),
                        gaps: vec![
                            "The focused test command is review context, not a certified target."
                                .to_owned(),
                        ],
                    })
                }
            },
        })
        .collect();
    DerivedActionExternalResults {
        format_revision: DERIVED_ACTION_RUNNER_FORMAT_REVISION,
        schema: DERIVED_ACTION_EXTERNAL_RESULTS_SCHEMA.to_owned(),
        manifest_digest,
        tasks,
    }
}

fn fixture_root() -> PathBuf {
    let suffix = format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    );
    let root = std::env::temp_dir().join(format!("needle-derived-action-runner-{suffix}"));
    fs::create_dir_all(root.join("impl/src")).unwrap();
    fs::create_dir_all(root.join("tests/no-std")).unwrap();
    root
}

fn write_fixture_source(root: &Path) {
    fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = [\"impl\"]\n").unwrap();
    fs::write(root.join("impl/Cargo.toml"), "[package]\nname = \"thiserror-impl\"\n").unwrap();
    fs::write(
        root.join("tests/no-std/Cargo.toml"),
        "[package]\nname = \"thiserror_no_std_test\"\n",
    )
    .unwrap();
    fs::write(root.join("impl/src/expand.rs"), "pub fn expand() { old(); }\n").unwrap();
    fs::write(root.join("tests/test_lints.rs"), "fn old_lint_test() {}\n").unwrap();
}
