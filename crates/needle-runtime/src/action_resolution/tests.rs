use super::*;
use crate::{built_in_action_for_artifact_kind, validator_definition};
use needle_core::{
    ActionRequest, ArtifactKind, ArtifactRequest, CoverageEntry, CoverageManifest, Facet, Need,
    NeedFragmentId, NeedId, NeedKey, Obligation, PlanEconomics, PredicateKind, ProofBudget,
    ReuseDescriptorInput, SelectedPlan, SemanticWorld, Subject, SubjectId, SubjectKind,
    need_fragment,
};
use serde_json::json;

struct Fixture {
    request: ActionRequest,
    action: &'static BuiltInActionDefinition,
}

fn fixture() -> Fixture {
    fixture_for(ArtifactKind::code_location(), "locate.implementation")
}

fn fixture_for(kind: ArtifactKind, route: &str) -> Fixture {
    let action = built_in_action_for_artifact_kind(&kind).unwrap();
    let request = ActionRequest::new(
        &action.contract,
        ArtifactRequest {
            contract_id: action.output_contract_id.to_owned(),
            contract_revision: action.output_contract_revision,
            repository_id: Digest::blake3(b"repository"),
            source_snapshot_digest: Digest::blake3(b"source"),
            route_key: NeedKey::new(route).unwrap(),
            normalized_request: "find implementation".to_owned(),
            semantic_fragment_id: Some(NeedFragmentId::new(Digest::blake3(b"fragment"))),
            input_artifact_ids: Vec::new(),
        },
        action.contract.default_dispatch_policy,
        NeedKey::new(route).unwrap(),
        NeedId::new(Digest::blake3(b"need")),
    )
    .unwrap();
    Fixture { request, action }
}

fn descriptor(fixture: &Fixture, index: usize, origin: ArtifactRequestId) -> ReuseDescriptor {
    let obligation = Obligation::new(
        PredicateKind::ImplementationLocation,
        SubjectId::new(Digest::blake3(index.to_le_bytes())),
        vec![Facet { key: "selection".to_owned(), value: "primary".to_owned() }],
    );
    descriptor_with_obligation(fixture, index, origin, obligation)
}

fn descriptor_with_obligation(
    fixture: &Fixture,
    index: usize,
    origin: ArtifactRequestId,
    obligation: Obligation,
) -> ReuseDescriptor {
    ReuseDescriptor::new(ReuseDescriptorInput {
        artifact: ArtifactId::new(Digest::blake3(format!("artifact-{index}"))),
        exact_request: origin,
        action_contract: fixture.action.contract.id.clone(),
        action_semantic_definition_digest: fixture.action.contract.semantic_definition_digest,
        action_validation_definition_digest: fixture.action.contract.validation_definition_digest,
        output_contract_definition_digest: fixture.action.output_contract_definition_digest,
        validator_definition_digest: validator_definition(fixture.action.artifact_kind()),
        validation_certificate: ArtifactValidationCertificateId::new(Digest::blake3(format!(
            "certificate-{index}"
        ))),
        coverage: CoverageManifest {
            entries: vec![CoverageEntry {
                obligation,
                evidence: vec![format!("src/{index}.rs:item")],
            }],
            world: test_world(),
            dependency_manifest_digest: Digest::blake3(format!("manifest-{index}")),
        },
    })
    .unwrap()
}

fn test_world() -> SemanticWorld {
    SemanticWorld {
        repository_lineage: Digest::blake3(b"repository"),
        source_selector: "worktree".to_owned(),
        platform: "windows".to_owned(),
        features: "default".to_owned(),
        configuration: None,
        toolchain: None,
    }
}

fn summary(
    fixture: &Fixture,
    resolution: ShadowActionResolutionKind,
    descriptors: &[ReuseDescriptor],
    covered_mask: u16,
    missing_mask: u16,
) -> Result<ShadowActionResolutionSummary, ShadowActionResolutionError> {
    ShadowActionResolutionSummary::new(ShadowActionResolutionInput {
        request: &fixture.request,
        action: fixture.action,
        resolution,
        descriptors,
        selected_plan: SelectedPlanId::new(Digest::blake3(b"plan")),
        sufficiency_certificate: (resolution != ShadowActionResolutionKind::Partial)
            .then(|| ReuseSufficiencyCertificateId::new(Digest::blake3(b"sufficiency"))),
        covered_mask,
        missing_mask,
    })
}

fn projection_need(
    subject: Subject,
    mut obligations: Vec<Obligation>,
) -> (NeedRequest, Need, NeedFragment) {
    obligations.sort();
    let request = NeedRequest {
        key: NeedKey::new("trace.state-flow").unwrap(),
        body: "find implementation".to_owned(),
    };
    let need = Need {
        id: NeedId::new(Digest::blake3(b"projection-need")),
        subjects: vec![subject],
        required: obligations,
        preferred: Vec::new(),
        semantic_constraints: Vec::new(),
        world: test_world(),
        input_artifacts: Vec::new(),
        residual: None,
        body_digest: Digest::blake3(request.body.as_bytes()),
        format_revision: 1,
    };
    let fragment = need_fragment(&need, need.required.clone(), Vec::new());
    (request, need, fragment)
}

fn projected_request_id(
    request: &NeedRequest,
    need: &Need,
    fragment: &NeedFragment,
    action: &BuiltInActionDefinition,
) -> ArtifactRequestId {
    ActionRequest::new(
        &action.contract,
        ArtifactRequest {
            contract_id: action.output_contract_id.to_owned(),
            contract_revision: action.output_contract_revision,
            repository_id: test_world().repository_lineage,
            source_snapshot_digest: Digest::blake3(b"source"),
            route_key: request.key.clone(),
            normalized_request: request.body.clone(),
            semantic_fragment_id: Some(fragment.id),
            input_artifact_ids: Vec::new(),
        },
        action.contract.default_dispatch_policy,
        request.key.clone(),
        need.id,
    )
    .unwrap()
    .semantic_id()
}

fn selected_plan(
    need: &Need,
    descriptors: &[ReuseDescriptor],
    covered_mask: u16,
    missing_mask: u16,
) -> SelectedPlan {
    SelectedPlan {
        id: SelectedPlanId::new(Digest::blake3(b"projection-plan")),
        need: need.id,
        artifact_ids: descriptors.iter().map(|descriptor| descriptor.artifact).collect(),
        claim_ids: Vec::new(),
        claim_validation_certificate_ids: Vec::new(),
        claim_set_certificate_ids: Vec::new(),
        covered_mask,
        missing_mask,
        economics: PlanEconomics {
            expected_fresh_microusd: None,
            expected_selected_microusd: None,
            proof_overhead_micros: 0,
            expected_net_microusd: None,
        },
        proof_budget: ProofBudget::default(),
        decision_reason: "shadow projection fixture".to_owned(),
    }
}

#[test]
fn four_shadow_shapes_are_canonical_and_semantically_distinct() {
    let fixture = fixture();
    let exact = descriptor(&fixture, 0, fixture.request.semantic_id());
    let projected =
        descriptor(&fixture, 1, ArtifactRequestId::new(Digest::blake3(b"different-request")));
    let composite = [
        descriptor(&fixture, 2, ArtifactRequestId::new(Digest::blake3(b"origin-2"))),
        descriptor(&fixture, 3, ArtifactRequestId::new(Digest::blake3(b"origin-3"))),
    ];

    let exact_summary =
        summary(&fixture, ShadowActionResolutionKind::Exact, &[exact], 0b1, 0).unwrap();
    let coverage_summary =
        summary(&fixture, ShadowActionResolutionKind::Coverage, &[projected], 0b1, 0).unwrap();
    let composite_summary =
        summary(&fixture, ShadowActionResolutionKind::Composite, &composite, 0b11, 0).unwrap();
    let partial_summary =
        summary(&fixture, ShadowActionResolutionKind::Partial, &composite, 0b1, 0b10).unwrap();

    for value in [&exact_summary, &coverage_summary, &composite_summary, &partial_summary] {
        assert!(value.is_canonical());
        assert!(value.validate_for_action(fixture.action).is_ok());
        assert!(value.validate_for_request_and_action(&fixture.request, fixture.action).is_ok());
        assert_eq!(value.authority, ShadowActionResolutionAuthority::Shadow);
    }
    assert_eq!(exact_summary.request, fixture.request.semantic_id());
    assert_ne!(exact_summary.request.digest(), fixture.request.artifact_request.id());
    assert_eq!(exact_summary.artifact_matched_requests[0], exact_summary.request);
    assert_ne!(coverage_summary.artifact_matched_requests[0], coverage_summary.request);
    assert_eq!(composite_summary.artifacts.len(), 2);
    assert_eq!(partial_summary.missing_mask, 0b10);
    assert!(partial_summary.sufficiency_certificate.is_none());
}

#[test]
fn projector_groups_selected_descriptors_into_exact_and_coverage_actions() {
    let subject = Subject::exact(test_world().repository_lineage, SubjectKind::CliOption, "--flag");
    let location_obligation = Obligation::new(
        PredicateKind::ImplementationLocation,
        subject.id,
        vec![Facet { key: "selection".to_owned(), value: "primary".to_owned() }],
    );
    let trace_obligation = Obligation::new(
        PredicateKind::RuntimeFlow,
        subject.id,
        vec![Facet { key: "scenario".to_owned(), value: "default".to_owned() }],
    );
    let (request, need, fragment) =
        projection_need(subject, vec![location_obligation.clone(), trace_obligation.clone()]);
    let location_fixture = fixture_for(ArtifactKind::code_location(), request.key.as_str());
    let trace_fixture = fixture_for(ArtifactKind::behavior_trace(), request.key.as_str());
    let location_origin = projected_request_id(&request, &need, &fragment, location_fixture.action);
    let descriptors = vec![
        descriptor_with_obligation(&location_fixture, 10, location_origin, location_obligation),
        descriptor_with_obligation(
            &trace_fixture,
            11,
            ArtifactRequestId::new(Digest::blake3(b"prior-trace-request")),
            trace_obligation,
        ),
    ];
    let full_mask = (1_u16 << need.required.len()) - 1;
    let plan = selected_plan(&need, &descriptors, full_mask, 0);

    let summaries = project_shadow_action_resolutions(ShadowActionResolutionProjectionInput {
        request: &request,
        need: &need,
        fragment: &fragment,
        repository_id: test_world().repository_lineage,
        source_snapshot_digest: Digest::blake3(b"source"),
        descriptors,
        plan: &plan,
        sufficiency_certificate: Some(ReuseSufficiencyCertificateId::new(Digest::blake3(
            b"root-proof",
        ))),
    })
    .unwrap();

    assert_eq!(summaries.len(), 2);
    assert_eq!(summaries[0].predicate, PredicateKind::ImplementationLocation);
    assert_eq!(summaries[0].resolution, ShadowActionResolutionKind::Exact);
    assert_eq!(summaries[1].predicate, PredicateKind::RuntimeFlow);
    assert_eq!(summaries[1].resolution, ShadowActionResolutionKind::Coverage);
    assert!(summaries.iter().all(ShadowActionResolutionSummary::is_canonical));
}

#[test]
fn projector_preserves_composite_and_root_partial_shapes_without_synthesizing_proof() {
    let subject = Subject::exact(test_world().repository_lineage, SubjectKind::CliOption, "--flag");
    let primary = Obligation::new(
        PredicateKind::ImplementationLocation,
        subject.id,
        vec![Facet { key: "selection".to_owned(), value: "primary".to_owned() }],
    );
    let supporting = Obligation::new(
        PredicateKind::ImplementationLocation,
        subject.id,
        vec![Facet { key: "selection".to_owned(), value: "supporting".to_owned() }],
    );
    let location_fixture = fixture_for(ArtifactKind::code_location(), "trace.state-flow");

    let (request, need, fragment) = projection_need(subject.clone(), vec![primary.clone()]);
    let composite_descriptors = vec![
        descriptor_with_obligation(
            &location_fixture,
            20,
            ArtifactRequestId::new(Digest::blake3(b"origin-20")),
            primary.clone(),
        ),
        descriptor_with_obligation(
            &location_fixture,
            21,
            ArtifactRequestId::new(Digest::blake3(b"origin-21")),
            primary.clone(),
        ),
    ];
    let composite_plan = selected_plan(&need, &composite_descriptors, 1, 0);
    let composite = project_shadow_action_resolutions(ShadowActionResolutionProjectionInput {
        request: &request,
        need: &need,
        fragment: &fragment,
        repository_id: test_world().repository_lineage,
        source_snapshot_digest: Digest::blake3(b"source"),
        descriptors: composite_descriptors,
        plan: &composite_plan,
        sufficiency_certificate: Some(ReuseSufficiencyCertificateId::new(Digest::blake3(
            b"composite-proof",
        ))),
    })
    .unwrap();
    assert_eq!(composite[0].resolution, ShadowActionResolutionKind::Composite);

    let (request, need, fragment) = projection_need(subject, vec![primary.clone(), supporting]);
    let partial_descriptors = vec![descriptor_with_obligation(
        &location_fixture,
        22,
        ArtifactRequestId::new(Digest::blake3(b"origin-22")),
        primary.clone(),
    )];
    let covered_index =
        need.required.iter().position(|obligation| obligation.id == primary.id).unwrap();
    let covered_mask = 1_u16 << covered_index;
    let missing_mask = ((1_u16 << need.required.len()) - 1) ^ covered_mask;
    let partial_plan = selected_plan(&need, &partial_descriptors, covered_mask, missing_mask);
    let partial = project_shadow_action_resolutions(ShadowActionResolutionProjectionInput {
        request: &request,
        need: &need,
        fragment: &fragment,
        repository_id: test_world().repository_lineage,
        source_snapshot_digest: Digest::blake3(b"source"),
        descriptors: partial_descriptors,
        plan: &partial_plan,
        sufficiency_certificate: None,
    })
    .unwrap();
    assert_eq!(partial[0].resolution, ShadowActionResolutionKind::Partial);
    assert!(partial[0].sufficiency_certificate.is_none());
}

#[test]
fn summary_roundtrips_rejects_unknown_fields_and_has_stable_digest() {
    let fixture = fixture();
    let descriptors = [descriptor(&fixture, 0, fixture.request.semantic_id())];
    let summary = summary(&fixture, ShadowActionResolutionKind::Exact, &descriptors, 1, 0).unwrap();
    assert_eq!(
        summary.definition_digest,
        Digest::parse("b3:2da6c57aa6abd8f498355a6c8516bd0b2254fa8f5bb60a21738b8fbeff8e4ada")
            .unwrap()
    );
    let encoded = serde_json::to_value(&summary).unwrap();
    let decoded: ShadowActionResolutionSummary = serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(decoded, summary);
    assert!(decoded.is_canonical());
    assert_eq!(encoded["authority"], "shadow");
    assert_eq!(encoded["resolution"], "exact");
    for prohibited in ["fresh", "capability", "operational_policy", "cache_resolution"] {
        assert_eq!(encoded.get(prohibited), None);
    }
    let mut unknown = encoded;
    unknown.as_object_mut().unwrap().insert("unknown".to_owned(), json!(true));
    assert!(serde_json::from_value::<ShadowActionResolutionSummary>(unknown).is_err());

    let mut legacy = summary;
    legacy.format_revision = LEGACY_SHADOW_ACTION_RESOLUTION_FORMAT_REVISION;
    legacy.artifact_matched_requests.clear();
    legacy.definition_digest = legacy.compute_definition_digest();
    let mut legacy_wire = serde_json::to_value(&legacy).unwrap();
    legacy_wire.as_object_mut().unwrap().remove("artifact_matched_requests");
    let decoded: ShadowActionResolutionSummary = serde_json::from_value(legacy_wire).unwrap();
    assert!(decoded.is_canonical());
    assert!(decoded.artifact_matched_requests.is_empty());
}

#[test]
fn summary_rejects_legacy_requests_shape_mismatches_duplicates_and_tampering() {
    let mut legacy_fixture = fixture();
    legacy_fixture.request.artifact_request.semantic_fragment_id = None;
    let legacy_descriptor =
        descriptor(&legacy_fixture, 0, ArtifactRequestId::new(Digest::blake3(b"legacy-origin")));
    assert!(matches!(
        summary(&legacy_fixture, ShadowActionResolutionKind::Coverage, &[legacy_descriptor], 1, 0,),
        Err(ShadowActionResolutionError::Request)
    ));

    let fixture = fixture();
    let exact = descriptor(&fixture, 0, fixture.request.semantic_id());

    let mut oversized_request = fixture.request.clone();
    oversized_request.artifact_request.normalized_request = "x".repeat(MAX_NEED_IR_BYTES + 1);
    assert!(matches!(
        ShadowActionResolutionSummary::new(ShadowActionResolutionInput {
            request: &oversized_request,
            action: fixture.action,
            resolution: ShadowActionResolutionKind::Exact,
            descriptors: std::slice::from_ref(&exact),
            selected_plan: SelectedPlanId::new(Digest::blake3(b"plan")),
            sufficiency_certificate: Some(ReuseSufficiencyCertificateId::new(Digest::blake3(
                b"sufficiency"
            ))),
            covered_mask: 1,
            missing_mask: 0,
        }),
        Err(ShadowActionResolutionError::RequestTextBound {
            actual,
            maximum: MAX_NEED_IR_BYTES,
        }) if actual == MAX_NEED_IR_BYTES + 1
    ));

    let mut duplicate_input_request = fixture.request.clone();
    let duplicate = Digest::blake3(b"duplicate-input");
    duplicate_input_request.artifact_request.input_artifact_ids = vec![duplicate, duplicate];
    assert!(matches!(
        ShadowActionResolutionSummary::new(ShadowActionResolutionInput {
            request: &duplicate_input_request,
            action: fixture.action,
            resolution: ShadowActionResolutionKind::Exact,
            descriptors: std::slice::from_ref(&exact),
            selected_plan: SelectedPlanId::new(Digest::blake3(b"plan")),
            sufficiency_certificate: Some(ReuseSufficiencyCertificateId::new(Digest::blake3(
                b"sufficiency"
            ))),
            covered_mask: 1,
            missing_mask: 0,
        }),
        Err(ShadowActionResolutionError::Request)
    ));

    let mut wrong_request = fixture.request.clone();
    wrong_request.artifact_request.contract_id = "needle.semantic.other".to_owned();
    assert!(matches!(
        ShadowActionResolutionSummary::new(ShadowActionResolutionInput {
            request: &wrong_request,
            action: fixture.action,
            resolution: ShadowActionResolutionKind::Exact,
            descriptors: std::slice::from_ref(&exact),
            selected_plan: SelectedPlanId::new(Digest::blake3(b"plan")),
            sufficiency_certificate: Some(ReuseSufficiencyCertificateId::new(Digest::blake3(
                b"sufficiency"
            ))),
            covered_mask: 1,
            missing_mask: 0,
        }),
        Err(ShadowActionResolutionError::Request)
    ));

    let mismatched_validator = ReuseDescriptor::new(ReuseDescriptorInput {
        artifact: exact.artifact,
        exact_request: exact.exact_request,
        action_contract: exact.action_contract.clone(),
        action_semantic_definition_digest: exact.action_semantic_definition_digest,
        action_validation_definition_digest: exact.action_validation_definition_digest,
        output_contract_definition_digest: exact.output_contract_definition_digest,
        validator_definition_digest: Digest::blake3(b"other-validator"),
        validation_certificate: exact.validation_certificate,
        coverage: exact.coverage.clone(),
    })
    .unwrap();
    assert!(matches!(
        summary(&fixture, ShadowActionResolutionKind::Exact, &[mismatched_validator], 1, 0,),
        Err(ShadowActionResolutionError::DescriptorBinding)
    ));

    let mut predicate_coverage = exact.coverage.clone();
    predicate_coverage.entries[0].obligation = Obligation::new(
        PredicateKind::RuntimeFlow,
        SubjectId::new(Digest::blake3(b"other-subject")),
        vec![Facet { key: "selection".to_owned(), value: "primary".to_owned() }],
    );
    let mismatched_predicate = ReuseDescriptor::new(ReuseDescriptorInput {
        artifact: exact.artifact,
        exact_request: exact.exact_request,
        action_contract: exact.action_contract.clone(),
        action_semantic_definition_digest: exact.action_semantic_definition_digest,
        action_validation_definition_digest: exact.action_validation_definition_digest,
        output_contract_definition_digest: exact.output_contract_definition_digest,
        validator_definition_digest: exact.validator_definition_digest,
        validation_certificate: exact.validation_certificate,
        coverage: predicate_coverage,
    })
    .unwrap();
    assert!(matches!(
        summary(&fixture, ShadowActionResolutionKind::Exact, &[mismatched_predicate], 1, 0,),
        Err(ShadowActionResolutionError::DescriptorBinding)
    ));

    assert!(matches!(
        summary(&fixture, ShadowActionResolutionKind::Coverage, std::slice::from_ref(&exact), 1, 0,),
        Err(ShadowActionResolutionError::ResolutionShape)
    ));
    assert!(matches!(
        summary(
            &fixture,
            ShadowActionResolutionKind::Composite,
            std::slice::from_ref(&exact),
            1,
            0,
        ),
        Err(ShadowActionResolutionError::ResolutionShape)
    ));
    assert!(matches!(
        summary(
            &fixture,
            ShadowActionResolutionKind::Partial,
            std::slice::from_ref(&exact),
            0b1,
            0b1,
        ),
        Err(ShadowActionResolutionError::Masks)
    ));
    assert!(matches!(
        summary(&fixture, ShadowActionResolutionKind::Composite, &[exact.clone(), exact], 1, 0),
        Err(ShadowActionResolutionError::Ordering)
    ));

    let descriptors = [descriptor(&fixture, 1, fixture.request.semantic_id())];
    let mut valid =
        summary(&fixture, ShadowActionResolutionKind::Exact, &descriptors, 1, 0).unwrap();
    valid.semantic_world_digest = Digest::blake3(b"other-world");
    assert!(matches!(valid.validate(), Err(ShadowActionResolutionError::DefinitionDigest { .. })));

    let canonical =
        summary(&fixture, ShadowActionResolutionKind::Exact, &descriptors, 1, 0).unwrap();
    let mut altered_action = fixture.action.clone();
    altered_action.output_contract_definition_digest = Digest::blake3(b"other-output-contract");
    assert!(matches!(
        canonical.validate_for_action(&altered_action),
        Err(ShadowActionResolutionError::ActionDefinition)
    ));
}

#[test]
fn summary_enforces_constructor_and_wire_binding_bounds() {
    let fixture = fixture();
    let descriptors = (0..MAX_PROOF_ARTIFACTS)
        .map(|index| {
            descriptor(
                &fixture,
                index,
                ArtifactRequestId::new(Digest::blake3(format!("origin-{index}"))),
            )
        })
        .collect::<Vec<_>>();
    assert!(summary(&fixture, ShadowActionResolutionKind::Composite, &descriptors, 1, 0,).is_ok());

    let mut oversized = descriptors;
    oversized.push(descriptor(
        &fixture,
        MAX_PROOF_ARTIFACTS,
        ArtifactRequestId::new(Digest::blake3(b"overflow-origin")),
    ));
    assert!(matches!(
        summary(&fixture, ShadowActionResolutionKind::Composite, &oversized, 1, 0,),
        Err(ShadowActionResolutionError::DescriptorBound { .. })
    ));

    let one = [descriptor(&fixture, 100, ArtifactRequestId::new(Digest::blake3(b"different")))];
    let summary = summary(&fixture, ShadowActionResolutionKind::Coverage, &one, 1, 0).unwrap();
    let wire = serde_json::to_value(summary).unwrap();
    for field in [
        "artifacts",
        "artifact_matched_requests",
        "artifact_origin_requests",
        "validation_certificates",
    ] {
        let mut oversized_wire = wire.clone();
        let binding = oversized_wire[field][0].clone();
        oversized_wire[field] =
            serde_json::Value::Array((0..=MAX_PROOF_ARTIFACTS).map(|_| binding.clone()).collect());
        assert!(serde_json::from_value::<ShadowActionResolutionSummary>(oversized_wire).is_err());
    }
}
