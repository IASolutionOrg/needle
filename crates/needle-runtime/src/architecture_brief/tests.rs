use super::*;
use needle_core::{
    ArchitectureAssertion, ArchitectureAssertionKind, ArchitectureEvidence,
    ArchitecturePackageBrief,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

struct Fixture {
    root: PathBuf,
    alpha: TestTargetPackageKey,
    beta: TestTargetPackageKey,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let root = std::env::temp_dir().join(format!("needle-architecture-brief-{nonce}"));
        fs::create_dir_all(root.join("crates/alpha/src")).unwrap();
        fs::create_dir_all(root.join("crates/beta/src")).unwrap();
        fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = [\"crates/*\"]\n").unwrap();
        fs::write(
            root.join("crates/alpha/Cargo.toml"),
            "[package]\nname = \"alpha\"\nversion = \"0.1.0\"\n[dependencies]\nbeta = { path = \"../beta\" }\n",
        )
        .unwrap();
        fs::write(
            root.join("crates/beta/Cargo.toml"),
            "[package]\nname = \"beta\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(root.join("crates/alpha/src/lib.rs"), "pub fn dispatch() { beta::store(); }\n")
            .unwrap();
        fs::write(root.join("crates/beta/src/lib.rs"), "pub fn store() {}\n").unwrap();
        Self {
            root,
            alpha: TestTargetPackageKey::new("alpha", "crates/alpha/Cargo.toml").unwrap(),
            beta: TestTargetPackageKey::new("beta", "crates/beta/Cargo.toml").unwrap(),
        }
    }

    fn packages(&self) -> Vec<TestTargetPackageKey> {
        vec![self.alpha.clone(), self.beta.clone()]
    }

    fn input<'a>(
        &'a self,
        scope: &'a ArchitectureBriefScope,
        packages: &'a [TestTargetPackageKey],
    ) -> ArchitectureBriefValidationInput<'a> {
        ArchitectureBriefValidationInput {
            repository_root: &self.root,
            repository_lineage: Digest::blake3(b"repository"),
            source_selector: "worktree",
            workspace_manifest: "Cargo.toml",
            scope,
            package_universe: packages,
        }
    }

    fn evidence(
        &self,
    ) -> (
        ArchitectureEvidence,
        ArchitectureEvidence,
        ArchitectureEvidence,
        ArchitectureEvidence,
        ArchitectureEvidence,
    ) {
        let workspace = evidence(
            &self.root,
            "Cargo.toml",
            vec![ArchitectureEvidenceRole::Manifest],
            Vec::new(),
        );
        let alpha_manifest = evidence(
            &self.root,
            "crates/alpha/Cargo.toml",
            vec![
                ArchitectureEvidenceRole::Manifest,
                ArchitectureEvidenceRole::DependencyDeclaration,
                ArchitectureEvidenceRole::Supporting,
            ],
            vec![self.alpha.clone()],
        );
        let alpha_source = evidence(
            &self.root,
            "crates/alpha/src/lib.rs",
            vec![
                ArchitectureEvidenceRole::EntryPoint,
                ArchitectureEvidenceRole::PublicBoundary,
                ArchitectureEvidenceRole::Supporting,
            ],
            vec![self.alpha.clone()],
        );
        let beta_manifest = evidence(
            &self.root,
            "crates/beta/Cargo.toml",
            vec![ArchitectureEvidenceRole::Manifest, ArchitectureEvidenceRole::Supporting],
            vec![self.beta.clone()],
        );
        let beta_source = evidence(
            &self.root,
            "crates/beta/src/lib.rs",
            vec![ArchitectureEvidenceRole::EntryPoint, ArchitectureEvidenceRole::Supporting],
            vec![self.beta.clone()],
        );
        (workspace, alpha_manifest, alpha_source, beta_manifest, beta_source)
    }

    fn brief(&self) -> ArchitectureBrief {
        let (workspace, alpha_manifest, alpha_source, beta_manifest, beta_source) = self.evidence();
        let alpha = ArchitecturePackageBrief::new(
            self.alpha.clone(),
            "Alpha routes requests to storage.",
            vec![workspace.id, alpha_manifest.id, alpha_source.id],
            vec![
                ArchitectureAssertion::new(
                    ArchitectureAssertionKind::Responsibility,
                    "Alpha coordinates request routing.",
                    vec![alpha_source.id],
                    Vec::new(),
                )
                .unwrap(),
                ArchitectureAssertion::new(
                    ArchitectureAssertionKind::EntryPoint,
                    "dispatch is the package entry point.",
                    vec![alpha_source.id],
                    Vec::new(),
                )
                .unwrap(),
                ArchitectureAssertion::new(
                    ArchitectureAssertionKind::PublicBoundary,
                    "dispatch is public.",
                    vec![alpha_source.id],
                    Vec::new(),
                )
                .unwrap(),
                ArchitectureAssertion::new(
                    ArchitectureAssertionKind::Dependency,
                    "Alpha depends on Beta for storage.",
                    vec![alpha_manifest.id],
                    vec![self.beta.clone()],
                )
                .unwrap(),
            ],
            Vec::new(),
        )
        .unwrap();
        let beta = ArchitecturePackageBrief::new(
            self.beta.clone(),
            "Beta owns storage primitives.",
            vec![workspace.id, beta_manifest.id, beta_source.id],
            vec![
                ArchitectureAssertion::new(
                    ArchitectureAssertionKind::Responsibility,
                    "Beta persists values.",
                    vec![beta_source.id],
                    Vec::new(),
                )
                .unwrap(),
                ArchitectureAssertion::new(
                    ArchitectureAssertionKind::EntryPoint,
                    "store is the package entry point.",
                    vec![beta_source.id],
                    Vec::new(),
                )
                .unwrap(),
            ],
            vec!["Public API completeness is not established.".to_owned()],
        )
        .unwrap();
        ArchitectureBrief::new(
            Digest::blake3(b"repository"),
            "worktree",
            "Cargo.toml",
            ArchitectureBriefScope::all(),
            architecture_brief_analysis_definition(),
            self.packages(),
            vec![workspace, alpha_manifest, alpha_source, beta_manifest, beta_source],
            vec![alpha, beta],
        )
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn evidence(
    root: &Path,
    relative: &str,
    roles: Vec<ArchitectureEvidenceRole>,
    packages: Vec<TestTargetPackageKey>,
) -> ArchitectureEvidence {
    let bytes = fs::read(root.join(relative)).unwrap();
    ArchitectureEvidence::new(relative, Digest::blake3(bytes), None, None, roles, packages).unwrap()
}

#[test]
fn validator_binds_current_files_definitions_and_manifest_coverage() {
    let fixture = Fixture::new();
    let packages = fixture.packages();
    let scope = ArchitectureBriefScope::all();
    let brief = fixture.brief();
    let left = validate_architecture_brief(fixture.input(&scope, &packages), &brief).unwrap();
    let right = validate_architecture_brief(fixture.input(&scope, &packages), &brief).unwrap();
    assert_eq!(left, right);
    assert_eq!(left.brief, brief.content_digest);
    assert!(left.validate().is_ok());

    fs::write(fixture.root.join("crates/alpha/src/lib.rs"), "pub fn changed() {}\n").unwrap();
    assert!(matches!(
        validate_architecture_brief(fixture.input(&scope, &packages), &brief),
        Err(ArchitectureBriefRuntimeError::EvidenceDrift(path))
            if path == "crates/alpha/src/lib.rs"
    ));
}

#[test]
fn package_projection_and_disjoint_assembly_preserve_only_supported_claims() {
    let fixture = Fixture::new();
    let full = fixture.brief();
    let alpha_scope = ArchitectureBriefScope::new(vec![fixture.alpha.clone()]).unwrap();
    let beta_scope = ArchitectureBriefScope::new(vec![fixture.beta.clone()]).unwrap();
    let alpha = project_architecture_brief(&full, alpha_scope.clone()).unwrap();
    let beta = project_architecture_brief(&full, beta_scope.clone()).unwrap();
    assert_eq!(alpha.packages.len(), 1);
    assert!(alpha.evidence.iter().all(|item| {
        item.packages.is_empty() || item.packages.binary_search(&fixture.alpha).is_ok()
    }));

    let packages = fixture.packages();
    validate_architecture_brief(fixture.input(&alpha_scope, &packages), &alpha).unwrap();
    validate_architecture_brief(fixture.input(&beta_scope, &packages), &beta).unwrap();
    let assembled =
        assemble_architecture_briefs(&[beta.clone(), alpha.clone()], ArchitectureBriefScope::all())
            .unwrap();
    assert_eq!(assembled, full);
    assert!(matches!(
        assemble_architecture_briefs(&[alpha.clone(), alpha], ArchitectureBriefScope::all()),
        Err(ArchitectureBriefRuntimeError::Assembly)
    ));
}

#[test]
fn validator_rejects_missing_manifest_and_definition_or_universe_drift() {
    let fixture = Fixture::new();
    let full = fixture.brief();
    let packages = fixture.packages();
    let scope = ArchitectureBriefScope::all();
    let package_briefs = full
        .packages
        .iter()
        .map(|package| {
            let summary_ids = package
                .summary_evidence_ids
                .iter()
                .copied()
                .filter(|id| {
                    full.evidence
                        .iter()
                        .find(|item| item.id == *id)
                        .is_some_and(|item| item.path != "Cargo.toml")
                })
                .collect();
            ArchitecturePackageBrief::new(
                package.package.clone(),
                package.summary.clone(),
                summary_ids,
                package.assertions.clone(),
                package.gaps.clone(),
            )
            .unwrap()
        })
        .collect();
    let without_workspace = ArchitectureBrief::new(
        full.repository_lineage,
        full.source_selector.clone(),
        full.workspace_manifest.clone(),
        full.scope.clone(),
        full.analysis_definition_digest,
        full.package_universe.clone(),
        full.evidence.iter().filter(|item| item.path != "Cargo.toml").cloned().collect(),
        package_briefs,
    )
    .unwrap();
    assert_eq!(
        validate_architecture_brief(fixture.input(&scope, &packages), &without_workspace),
        Err(ArchitectureBriefRuntimeError::ManifestCoverage("Cargo.toml".to_owned()))
    );

    let drifted_definition = ArchitectureBrief::new(
        full.repository_lineage,
        full.source_selector.clone(),
        full.workspace_manifest.clone(),
        full.scope.clone(),
        Digest::blake3(b"drifted-definition"),
        full.package_universe.clone(),
        full.evidence.clone(),
        full.packages.clone(),
    )
    .unwrap();
    assert_eq!(
        validate_architecture_brief(fixture.input(&scope, &packages), &drifted_definition),
        Err(ArchitectureBriefRuntimeError::Binding)
    );

    let alpha_only = vec![fixture.alpha.clone()];
    assert_eq!(
        validate_architecture_brief(fixture.input(&scope, &alpha_only), &full),
        Err(ArchitectureBriefRuntimeError::Binding)
    );
}

#[test]
fn validator_fails_closed_on_missing_and_oversized_evidence() {
    let fixture = Fixture::new();
    let full = fixture.brief();
    let packages = fixture.packages();
    let scope = ArchitectureBriefScope::all();

    let missing = ArchitectureEvidence::new(
        "crates/alpha/src/missing.rs",
        Digest::blake3(b"missing"),
        None,
        None,
        vec![ArchitectureEvidenceRole::Supporting],
        vec![fixture.alpha.clone()],
    )
    .unwrap();
    let mut alpha = full.packages[0].clone();
    alpha.assertions.push(
        ArchitectureAssertion::new(
            ArchitectureAssertionKind::DesignConstraint,
            "A missing file is claimed as support.",
            vec![missing.id],
            Vec::new(),
        )
        .unwrap(),
    );
    alpha.assertions.sort_by_key(|assertion| assertion.id);
    alpha = ArchitecturePackageBrief::new(
        alpha.package,
        alpha.summary,
        alpha.summary_evidence_ids,
        alpha.assertions,
        alpha.gaps,
    )
    .unwrap();
    let missing_brief = ArchitectureBrief::new(
        full.repository_lineage,
        full.source_selector.clone(),
        full.workspace_manifest.clone(),
        full.scope.clone(),
        full.analysis_definition_digest,
        full.package_universe.clone(),
        full.evidence.iter().cloned().chain([missing]).collect(),
        vec![alpha, full.packages[1].clone()],
    )
    .unwrap();
    assert!(matches!(
        validate_architecture_brief(fixture.input(&scope, &packages), &missing_brief),
        Err(ArchitectureBriefRuntimeError::MissingEvidence(path))
            if path == "crates/alpha/src/missing.rs"
    ));

    let oversized_path = fixture.root.join("crates/alpha/src/oversized.rs");
    fs::write(&oversized_path, vec![b'x'; MAX_ARCHITECTURE_EVIDENCE_FILE_BYTES + 1]).unwrap();
    let oversized = ArchitectureEvidence::new(
        "crates/alpha/src/oversized.rs",
        Digest::blake3(b"not-read-past-bound"),
        None,
        None,
        vec![ArchitectureEvidenceRole::Supporting],
        vec![fixture.alpha.clone()],
    )
    .unwrap();
    let assertion = ArchitectureAssertion::new(
        ArchitectureAssertionKind::DesignConstraint,
        "The oversized file is claimed as support.",
        vec![oversized.id],
        Vec::new(),
    )
    .unwrap();
    let workspace = full.evidence.iter().find(|item| item.path == "Cargo.toml").unwrap().clone();
    let alpha_manifest =
        full.evidence.iter().find(|item| item.path == fixture.alpha.manifest_path).unwrap().clone();
    let alpha = ArchitecturePackageBrief::new(
        fixture.alpha.clone(),
        "Alpha evidence is bounded.",
        vec![workspace.id, alpha_manifest.id],
        vec![assertion],
        Vec::new(),
    )
    .unwrap();
    let oversized_scope = ArchitectureBriefScope::new(vec![fixture.alpha.clone()]).unwrap();
    let oversized_brief = ArchitectureBrief::new(
        full.repository_lineage,
        full.source_selector.clone(),
        full.workspace_manifest.clone(),
        oversized_scope.clone(),
        full.analysis_definition_digest,
        full.package_universe.clone(),
        vec![oversized, workspace, alpha_manifest],
        vec![alpha],
    )
    .unwrap();
    assert!(matches!(
        validate_architecture_brief(
            fixture.input(&oversized_scope, &packages),
            &oversized_brief
        ),
        Err(ArchitectureBriefRuntimeError::EvidenceFileBound { path, .. })
            if path == "crates/alpha/src/oversized.rs"
    ));
}
