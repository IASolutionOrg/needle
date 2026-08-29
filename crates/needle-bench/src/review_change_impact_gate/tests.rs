use super::*;
use needle_core::{
    AcceptanceStatus, ActionRequest, ArtifactRequest, ChangeId, ManifestProvenance, NeedFragmentId,
    NeedId, NeedKey, PartitionKeyMapping, PartitionRef, PatchId, RepositoryContextId,
    ReviewCoverage, ReviewFinding, ReviewReportVerdict, ReviewSeverity, SemanticWorld,
};
use needle_runtime::{
    ShadowManifestContext, built_in_action_contracts, derive_review_shadow_manifest,
};

fn digest(label: &str) -> Digest {
    Digest::blake3(label.as_bytes())
}

fn review_request(label: &str, repository: Digest) -> ActionRequest {
    let action = built_in_action_contracts()
        .iter()
        .find(|candidate| {
            candidate.contract.id.as_str() == needle_core::REVIEW_DIFF_ACTION_CONTRACT
        })
        .unwrap();
    ActionRequest::new_with_semantic_parameters(
        &action.contract,
        ArtifactRequest {
            contract_id: action.output_contract_id.to_owned(),
            contract_revision: action.output_contract_revision,
            repository_id: repository,
            source_snapshot_digest: digest("source"),
            route_key: NeedKey::new("locate.implementation").unwrap(),
            normalized_request: "Review the bounded patch.".to_owned(),
            semantic_fragment_id: Some(NeedFragmentId::new(digest(label))),
            input_artifact_ids: Vec::new(),
        },
        digest(&format!("semantic-parameters-{label}")),
        action.contract.default_dispatch_policy,
        NeedKey::new("locate.implementation").unwrap(),
        NeedId::new(digest("need")),
    )
    .unwrap()
}

fn finding(path: &str, rule: &str) -> ReviewFinding {
    ReviewFinding::new(
        rule,
        ReviewSeverity::Warning,
        path,
        Some(1),
        format!("{rule} remains actionable"),
        digest(&format!("{path}:{rule}:evidence")),
    )
    .unwrap()
}

fn report(
    request: &ActionRequest,
    patch: PatchId,
    findings: Vec<ReviewFinding>,
    manifest: needle_core::PartitionManifestId,
    created_unix_ms: u64,
) -> ReviewReport {
    ReviewReport::new(
        request.semantic_id(),
        ChangeId::from_digest(digest("change")),
        patch,
        digest("requirements"),
        digest("reviewer-definition"),
        ReviewReportVerdict::Rejected,
        vec![ReviewCoverage {
            criterion_digest: digest("criterion"),
            status: AcceptanceStatus::Addressed,
            evidence_digest: digest("coverage-evidence"),
        }],
        findings,
        Some(manifest),
        created_unix_ms,
    )
    .unwrap()
}

fn case(id: &str, ecosystem: &str) -> ReviewChangeImpactGateCase {
    let repository = digest("repository");
    let world = SemanticWorld {
        repository_lineage: repository,
        source_selector: "fixture".to_owned(),
        platform: "any".to_owned(),
        features: "default".to_owned(),
        configuration: None,
        toolchain: None,
    };
    let prior_request = review_request("prior", repository);
    let refresh_request = review_request("refresh", repository);
    let full_request = review_request("full", repository);
    let stale = finding("src/changed.ext", "stale.rule");
    let retained = finding("src/stable.ext", "stable.rule");
    let added = finding("src/new.ext", "new.rule");
    let prior_findings = vec![stale.clone(), retained.clone()];
    let current_findings = vec![retained.clone(), added];
    let full_findings = vec![
        finding("src/stable.ext", "oracle.stable.rule"),
        finding("src/new.ext", "oracle.new.rule"),
    ];
    let prior_manifest = derive_review_shadow_manifest(
        ShadowManifestContext {
            request: &prior_request,
            world: &world,
            definition_set_digest: digest("definitions"),
        },
        &prior_findings,
        digest("prior-dependencies"),
    )
    .unwrap();
    let refresh_manifest = derive_review_shadow_manifest(
        ShadowManifestContext {
            request: &refresh_request,
            world: &world,
            definition_set_digest: digest("definitions"),
        },
        &current_findings,
        digest("current-dependencies"),
    )
    .unwrap();
    let full_manifest = derive_review_shadow_manifest(
        ShadowManifestContext {
            request: &full_request,
            world: &world,
            definition_set_digest: digest("definitions"),
        },
        &full_findings,
        digest("full-dependencies"),
    )
    .unwrap();
    let prior_report = report(
        &prior_request,
        PatchId(digest("prior-patch")),
        prior_findings,
        prior_manifest.id,
        10,
    );
    let refresh_report = report(
        &refresh_request,
        PatchId(digest("current-patch")),
        current_findings.clone(),
        refresh_manifest.id,
        20,
    );
    let full_report = report(
        &full_request,
        PatchId(digest("current-patch")),
        full_findings,
        full_manifest.id,
        21,
    );
    let stale_raw = review_finding_partition_key(&stale).bytes();
    let retained_raw = review_finding_partition_key(&retained).bytes();
    let stale_key = prior_manifest
        .entries
        .iter()
        .find(|entry| entry.key.value.as_slice() == stale_raw)
        .unwrap()
        .key
        .digest;
    let prior_retained_key = prior_manifest
        .entries
        .iter()
        .find(|entry| entry.key.value.as_slice() == retained_raw)
        .unwrap()
        .key
        .digest;
    let current_retained_key = refresh_manifest
        .entries
        .iter()
        .find(|entry| entry.key.value.as_slice() == retained_raw)
        .unwrap()
        .key
        .digest;
    let delta = StateDelta::new(
        repository,
        RepositoryContextId::new(digest("context")),
        1,
        2,
        vec![needle_core::DependencyLocator::repository_path("src/changed.ext").unwrap()],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        true,
    )
    .unwrap();
    let definition = built_in_partition_for_action(&refresh_request.contract).unwrap();
    let transition = ManifestTransition::new(
        prior_manifest.id,
        refresh_manifest.id,
        delta.digest,
        vec![PartitionKeyMapping {
            prior: PartitionRef::new(prior_manifest.id, prior_retained_key),
            current: PartitionRef::new(refresh_manifest.id, current_retained_key),
        }],
        ManifestProvenance::ProducerAuthored { attempt: digest(&format!("attempt-{id}")) },
        definition.policy.manifest_validator.clone(),
    )
    .unwrap();
    ReviewChangeImpactGateCase {
        id: id.to_owned(),
        ecosystem: ecosystem.to_owned(),
        state_delta: delta,
        prior_report,
        refresh_report,
        full_report,
        prior_manifest,
        refresh_manifest,
        full_manifest,
        transition,
        invalidated_prior_partition_keys: vec![stale_key],
        prior_execution_digest: digest(&format!("prior-execution-{id}")),
        refresh_execution_digest: digest(&format!("refresh-execution-{id}")),
        full_execution_digest: digest(&format!("full-execution-{id}")),
    }
}

#[test]
fn provider_backed_gate_requires_two_opaque_ecosystem_fixtures_and_exact_oracle_parity() {
    let campaign = ReviewChangeImpactGateCampaign::new(
        ReviewChangeImpactEvidenceClass::ProviderBacked,
        vec![case("javascript-fixture", "javascript"), case("rust-fixture", "rust")],
    )
    .unwrap();
    let report = evaluate_review_change_impact_gate(&campaign).unwrap();
    assert!(report.language_agnostic_fixture_coverage);
    assert!(report.gate_eligible);
    assert!(report.passed);
    assert!(report.cases.iter().all(|case| case.passed));
}

#[test]
fn synthetic_evidence_can_validate_the_protocol_but_cannot_pass_gate_a6() {
    let campaign = ReviewChangeImpactGateCampaign::new(
        ReviewChangeImpactEvidenceClass::Synthetic,
        vec![case("javascript-fixture", "javascript"), case("rust-fixture", "rust")],
    )
    .unwrap();
    let report = evaluate_review_change_impact_gate(&campaign).unwrap();
    assert!(report.cases.iter().all(|case| case.passed));
    assert!(!report.gate_eligible);
    assert!(!report.passed);
}

#[test]
fn missing_independent_full_execution_fails_noninferiority_gate() {
    let mut rust = case("rust-fixture", "rust");
    rust.full_execution_digest = rust.refresh_execution_digest;
    let campaign = ReviewChangeImpactGateCampaign::new(
        ReviewChangeImpactEvidenceClass::ProviderBacked,
        vec![case("javascript-fixture", "javascript"), rust],
    )
    .unwrap();
    let report = evaluate_review_change_impact_gate(&campaign).unwrap();
    assert!(!report.passed);
    assert!(!report.cases.iter().find(|case| case.id == "rust-fixture").unwrap().passed);
}

#[test]
fn defect_locus_projection_rejects_ambiguous_same_line_findings() {
    let request = review_request("ambiguous", digest("repository"));
    let report = report(
        &request,
        PatchId(digest("patch")),
        vec![finding("src/lib.ext", "rule.one"), finding("src/lib.ext", "rule.two")],
        needle_core::PartitionManifestId::new(digest("manifest")),
        10,
    );

    assert!(defect_locus_projection(&report).is_none());
}

#[test]
fn campaign_wire_is_closed_bounded_and_digest_checked() {
    let campaign = ReviewChangeImpactGateCampaign::new(
        ReviewChangeImpactEvidenceClass::Synthetic,
        vec![case("javascript-fixture", "javascript"), case("rust-fixture", "rust")],
    )
    .unwrap();
    let bytes = serde_json::to_vec(&campaign).unwrap();
    assert_eq!(ReviewChangeImpactGateCampaign::decode_json(&bytes).unwrap(), campaign);
    let mut value = serde_json::to_value(&campaign).unwrap();
    value["unknown"] = serde_json::json!(true);
    assert!(
        ReviewChangeImpactGateCampaign::decode_json(&serde_json::to_vec(&value).unwrap()).is_err()
    );
    let mut tampered = campaign;
    tampered.campaign_digest = digest("tampered");
    assert!(
        ReviewChangeImpactGateCampaign::decode_json(&serde_json::to_vec(&tampered).unwrap())
            .is_err()
    );
    assert!(
        ReviewChangeImpactGateCampaign::decode_json(&vec![
            b' ';
            MAX_REVIEW_CHANGE_IMPACT_GATE_BYTES + 1
        ])
        .is_err()
    );
}
