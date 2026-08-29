use super::*;
use crate::TestTargetInventoryError;
use serde_json::json;

fn packages() -> (TestTargetPackageKey, TestTargetPackageKey) {
    (
        TestTargetPackageKey::new("alpha", "crates/alpha/Cargo.toml").unwrap(),
        TestTargetPackageKey::new("beta", "crates/beta/Cargo.toml").unwrap(),
    )
}

fn brief() -> ArchitectureBrief {
    let (alpha, beta) = packages();
    let alpha_manifest = ArchitectureEvidence::new(
        "crates/alpha/Cargo.toml",
        Digest::blake3(b"alpha-manifest"),
        None,
        None,
        vec![ArchitectureEvidenceRole::Manifest, ArchitectureEvidenceRole::Supporting],
        vec![alpha.clone()],
    )
    .unwrap();
    let alpha_source = ArchitectureEvidence::new(
        "crates/alpha/src/lib.rs",
        Digest::blake3(b"alpha-source"),
        Some(0),
        Some(32),
        vec![
            ArchitectureEvidenceRole::EntryPoint,
            ArchitectureEvidenceRole::PublicBoundary,
            ArchitectureEvidenceRole::Supporting,
        ],
        vec![alpha.clone()],
    )
    .unwrap();
    let alpha_dependency = ArchitectureEvidence::new(
        "crates/alpha/Cargo.toml",
        Digest::blake3(b"alpha-manifest"),
        Some(0),
        Some(24),
        vec![ArchitectureEvidenceRole::DependencyDeclaration],
        vec![alpha.clone()],
    )
    .unwrap();
    let beta_source = ArchitectureEvidence::new(
        "crates/beta/src/lib.rs",
        Digest::blake3(b"beta-source"),
        None,
        None,
        vec![ArchitectureEvidenceRole::EntryPoint, ArchitectureEvidenceRole::Supporting],
        vec![beta.clone()],
    )
    .unwrap();

    let alpha_brief = ArchitecturePackageBrief::new(
        alpha.clone(),
        "Alpha owns request routing.\r\nIt exposes the public dispatcher.",
        vec![alpha_source.id, alpha_manifest.id],
        vec![
            ArchitectureAssertion::new(
                ArchitectureAssertionKind::Responsibility,
                "Alpha coordinates requests.",
                vec![alpha_source.id],
                Vec::new(),
            )
            .unwrap(),
            ArchitectureAssertion::new(
                ArchitectureAssertionKind::EntryPoint,
                "The library root is an entry point.",
                vec![alpha_source.id],
                Vec::new(),
            )
            .unwrap(),
            ArchitectureAssertion::new(
                ArchitectureAssertionKind::PublicBoundary,
                "The dispatcher is a public boundary.",
                vec![alpha_source.id],
                Vec::new(),
            )
            .unwrap(),
            ArchitectureAssertion::new(
                ArchitectureAssertionKind::Dependency,
                "Alpha depends on Beta.",
                vec![alpha_dependency.id],
                vec![beta.clone()],
            )
            .unwrap(),
        ],
        Vec::new(),
    )
    .unwrap();
    let beta_brief = ArchitecturePackageBrief::new(
        beta.clone(),
        "Beta provides storage.",
        vec![beta_source.id],
        vec![
            ArchitectureAssertion::new(
                ArchitectureAssertionKind::Responsibility,
                "Beta owns storage primitives.",
                vec![beta_source.id],
                Vec::new(),
            )
            .unwrap(),
        ],
        vec!["Public-boundary classification is incomplete.".to_owned()],
    )
    .unwrap();

    ArchitectureBrief::new(
        Digest::blake3(b"repository"),
        "worktree",
        "Cargo.toml",
        ArchitectureBriefScope::all(),
        Digest::blake3(b"analysis-definition"),
        vec![beta, alpha],
        vec![beta_source, alpha_dependency, alpha_source, alpha_manifest],
        vec![beta_brief, alpha_brief],
    )
    .unwrap()
}

#[test]
fn architecture_brief_is_canonical_bounded_and_explicitly_model_authored() {
    let value = brief();
    assert!(value.is_canonical());
    assert_eq!(value.analysis_authority, ArchitectureAnalysisAuthority::ModelAuthored);
    assert_eq!(value.packages[0].package.name, "alpha");
    assert!(!value.packages[0].summary.contains('\r'));
    assert!(value.evidence.windows(2).all(|pair| pair[0].id < pair[1].id));

    let encoded = serde_json::to_vec(&value).unwrap();
    assert!(encoded.len() < MAX_ARCHITECTURE_BRIEF_WIRE_BYTES);
    assert_eq!(ArchitectureBrief::decode_json(&encoded).unwrap(), value);
}

#[test]
fn architecture_brief_wire_rejects_unknown_fields_and_oversized_values() {
    let value = brief();
    let mut json = serde_json::to_value(&value).unwrap();
    json.as_object_mut().unwrap().insert("authority".to_owned(), json!("authoritative"));
    assert!(serde_json::from_value::<ArchitectureBrief>(json).is_err());

    let mut json = serde_json::to_value(&value).unwrap();
    json["packages"][0]["summary"] = json!("x".repeat(MAX_ARCHITECTURE_SUMMARY_BYTES + 1));
    assert!(serde_json::from_value::<ArchitectureBrief>(json).is_err());

    let oversized = vec![b' '; MAX_ARCHITECTURE_BRIEF_WIRE_BYTES + 1];
    assert!(matches!(
        ArchitectureBrief::decode_json(&oversized),
        Err(ArchitectureBriefError::Bound { field: "brief.wire_bytes", .. })
    ));
}

#[test]
fn architecture_brief_rejects_tamper_scope_and_incompatible_evidence_roles() {
    let mut tampered = brief();
    tampered.packages[0].content_digest = Digest::blake3(b"tampered");
    assert_eq!(tampered.validate(), Err(ArchitectureBriefError::Digest("package.content_digest")));

    let (alpha, beta) = packages();
    let manifest = ArchitectureEvidence::new(
        "crates/alpha/Cargo.toml",
        Digest::blake3(b"manifest"),
        None,
        None,
        vec![ArchitectureEvidenceRole::Manifest],
        vec![alpha.clone()],
    )
    .unwrap();
    let assertion = ArchitectureAssertion::new(
        ArchitectureAssertionKind::EntryPoint,
        "The manifest is an entry point.",
        vec![manifest.id],
        Vec::new(),
    )
    .unwrap();
    let package =
        ArchitecturePackageBrief::new(alpha.clone(), "", Vec::new(), vec![assertion], Vec::new())
            .unwrap();
    assert_eq!(
        ArchitectureBrief::new(
            Digest::blake3(b"repository"),
            "worktree",
            "Cargo.toml",
            ArchitectureBriefScope::new(vec![alpha.clone()]).unwrap(),
            Digest::blake3(b"analysis"),
            vec![alpha.clone(), beta],
            vec![manifest],
            vec![package],
        ),
        Err(ArchitectureBriefError::Reference("assertion.evidence_role"))
    );

    let mut wrong_scope = brief();
    wrong_scope.scope = ArchitectureBriefScope::new(vec![alpha]).unwrap();
    assert_eq!(wrong_scope.validate(), Err(ArchitectureBriefError::Reference("brief.packages")));
}

#[test]
fn architecture_brief_rejects_collection_and_range_bounds_before_digest_trust() {
    let mut too_many = brief();
    too_many.evidence = vec![too_many.evidence[0].clone(); MAX_ARCHITECTURE_EVIDENCE + 1];
    assert!(matches!(
        too_many.validate(),
        Err(ArchitectureBriefError::Bound { field: "brief.evidence", .. })
    ));

    let mut invalid_range = serde_json::to_value(brief()).unwrap();
    invalid_range["evidence"][0]["byte_start"] = json!(12);
    invalid_range["evidence"][0]["byte_end"] = json!(4);
    let invalid_range: ArchitectureBrief = serde_json::from_value(invalid_range).unwrap();
    assert_eq!(invalid_range.validate(), Err(ArchitectureBriefError::Range));

    let mut unsafe_package = serde_json::to_value(brief()).unwrap();
    unsafe_package["package_universe"][0]["manifest_path"] = json!("../outside/Cargo.toml");
    let unsafe_package: ArchitectureBrief = serde_json::from_value(unsafe_package).unwrap();
    assert!(matches!(
        unsafe_package.validate(),
        Err(ArchitectureBriefError::Package(TestTargetInventoryError::Path(_)))
    ));

    assert!(
        ArchitectureEvidence::new(
            "../outside.rs",
            Digest::blake3(b"outside"),
            None,
            None,
            vec![ArchitectureEvidenceRole::Supporting],
            Vec::new(),
        )
        .is_err()
    );
}
