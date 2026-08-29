use super::*;
use crate::SubjectKind;
use serde_json::json;

fn fixture() -> ChangeImpact {
    let repository = Digest::blake3(b"repository");
    let requirement =
        ChangeImpactRequirement::new("Preserve the public command behavior.").unwrap();
    let subject = Subject::exact(repository, SubjectKind::Symbol, "alpha::dispatch");
    let key = ChangeImpactComponentKey { requirement: requirement.id, subject: subject.id };
    let file = ChangeImpactFile::new(
        "crates/alpha/src/lib.rs",
        PatchOperation::Update,
        Some(Digest::blake3(b"before")),
        Some(Digest::blake3(b"after")),
        6,
        5,
    )
    .unwrap();
    let source_snapshot = Digest::blake3(b"source");
    let patch_file = PatchFile {
        path: file.path.clone(),
        operation: file.operation,
        before_digest: file.before_digest,
        after_digest: file.after_digest,
        before_bytes: file.before_bytes,
        after_bytes: file.after_bytes,
    };
    let patch_id = PatchArtifact::compute_id(source_snapshot, &[patch_file]);
    let change_set = ChangeImpactChangeSet::new(patch_id, source_snapshot, vec![file]).unwrap();
    let evidence = ChangeImpactEvidence::new(
        "crates/alpha/src/lib.rs",
        ChangeImpactEvidenceState::After,
        Digest::blake3(b"after"),
        None,
        None,
        vec![ChangeImpactEvidenceRole::ChangedSurface],
        vec![subject.id],
    )
    .unwrap();
    let assessment = ChangeImpactAssessment::new(
        key,
        ChangeImpactDisposition::Affected,
        vec![ChangeImpactKind::PublicApi],
        "The changed public dispatch surface may alter command behavior.",
        vec![evidence.id],
        Vec::new(),
        vec!["crates/alpha/src/lib.rs".to_owned()],
        Vec::new(),
    )
    .unwrap();
    ChangeImpact::new(
        repository,
        "worktree",
        change_set,
        ChangeImpactScope::all(),
        Digest::blake3(b"analysis-definition"),
        vec![requirement],
        vec![ChangeImpactConstraint::new("Maintain backward compatibility.").unwrap()],
        vec![subject],
        Vec::new(),
        None,
        None,
        vec![evidence],
        vec![assessment],
        vec!["Dynamic callers are not enumerated.".to_owned()],
    )
    .unwrap()
}

#[test]
fn change_impact_is_canonical_explicitly_model_authored_and_roundtrips() {
    let value = fixture();
    assert!(value.validate().is_ok());
    assert_eq!(value.assessments[0].authority, ChangeImpactAnalysisAuthority::ModelAuthored);
    let encoded = serde_json::to_vec(&value).unwrap();
    assert_eq!(ChangeImpact::decode_json(&encoded).unwrap(), value);

    let mut reordered = value.clone();
    reordered.evidence.push(reordered.evidence[0].clone());
    assert!(matches!(
        reordered.validate(),
        Err(ChangeImpactError::Canonical("change_impact.evidence"))
    ));
}

#[test]
fn wire_rejects_unknown_fields_and_oversized_collections() {
    let value = fixture();
    let mut encoded = serde_json::to_value(&value).unwrap();
    encoded.as_object_mut().unwrap().insert("unknown".to_owned(), json!(true));
    assert!(ChangeImpact::decode_json(&serde_json::to_vec(&encoded).unwrap()).is_err());

    let mut oversized = serde_json::to_value(&value).unwrap();
    oversized["gaps"] = json!(vec!["gap"; MAX_CHANGE_IMPACT_REFERENCES + 1]);
    assert!(ChangeImpact::decode_json(&serde_json::to_vec(&oversized).unwrap()).is_err());

    let mut oversized_text = serde_json::to_value(&value).unwrap();
    oversized_text["gaps"] = json!(["x".repeat(MAX_CHANGE_IMPACT_TEXT_BYTES + 1)]);
    assert!(ChangeImpact::decode_json(&serde_json::to_vec(&oversized_text).unwrap()).is_err());
    assert!(matches!(
        ChangeImpact::decode_json(&vec![b'x'; MAX_CHANGE_IMPACT_WIRE_BYTES + 1]),
        Err(ChangeImpactError::Bound { field: "change_impact.wire_bytes", .. })
    ));
}

#[test]
fn tamper_scope_and_reference_mismatches_fail_closed() {
    let value = fixture();
    let mut tampered = value.clone();
    tampered.assessments[0].content_digest = Digest::blake3(b"tampered");
    assert!(matches!(tampered.validate(), Err(ChangeImpactError::Digest(_))));

    let mut missing = value.clone();
    missing.evidence.clear();
    assert!(matches!(missing.validate(), Err(ChangeImpactError::Reference("assessment"))));

    let mut wrong_scope = value.clone();
    wrong_scope.scope = ChangeImpactScope::new(vec![ChangeImpactComponentKey {
        requirement: ChangeImpactRequirementId(Digest::blake3(b"unknown")),
        subject: wrong_scope.subject_universe[0].id,
    }])
    .unwrap();
    assert!(matches!(
        wrong_scope.validate(),
        Err(ChangeImpactError::Reference("scope.components"))
    ));
}

#[test]
fn change_file_subject_text_and_component_bounds_are_enforced() {
    assert!(
        ChangeImpactFile::new(
            "../escape.rs",
            PatchOperation::Create,
            None,
            Some(Digest::blake3(b"after")),
            0,
            5,
        )
        .is_err()
    );
    assert!(
        ChangeImpactFile::new("src/lib.rs", PatchOperation::Delete, None, None, 0, 0,).is_err()
    );
    assert!(ChangeImpactRequirement::new("x".repeat(MAX_CHANGE_IMPACT_TEXT_BYTES + 1)).is_err());

    let repository = Digest::blake3(b"repository");
    let requirements = (0..=MAX_CHANGE_IMPACT_REQUIREMENTS)
        .map(|index| ChangeImpactRequirement::new(format!("requirement {index}")).unwrap())
        .collect::<Vec<_>>();
    let subject = Subject::exact(repository, SubjectKind::File, "src/lib.rs");
    assert!(subject.is_canonical());
    let base = fixture();
    assert!(matches!(
        ChangeImpact::new(
            base.repository_lineage,
            base.source_selector,
            base.change_set,
            base.scope,
            base.analysis_definition_digest,
            requirements,
            base.constraints,
            vec![subject],
            base.accepted_inputs,
            None,
            None,
            base.evidence,
            base.assessments,
            base.gaps,
        ),
        Err(ChangeImpactError::Bound { field: "change_impact.requirement_universe", .. })
    ));
}

#[test]
fn accepted_input_artifact_ids_are_unique_across_contract_references() {
    let base = fixture();
    let artifact = ArtifactId(Digest::blake3(b"accepted-artifact"));
    let first = ChangeImpactInputReference::new(
        "needle.analysis.first",
        1,
        artifact,
        Digest::blake3(b"first-certificate"),
        Digest::blake3(b"first-definition"),
    )
    .unwrap();
    let second = ChangeImpactInputReference::new(
        "needle.analysis.second",
        1,
        artifact,
        Digest::blake3(b"second-certificate"),
        Digest::blake3(b"second-definition"),
    )
    .unwrap();
    assert!(matches!(
        ChangeImpact::new(
            base.repository_lineage,
            base.source_selector,
            base.change_set,
            base.scope,
            base.analysis_definition_digest,
            base.requirement_universe,
            base.constraints,
            base.subject_universe,
            vec![first, second],
            None,
            None,
            base.evidence,
            base.assessments,
            base.gaps,
        ),
        Err(ChangeImpactError::Canonical("change_impact.accepted_inputs.artifact"))
    ));
}
