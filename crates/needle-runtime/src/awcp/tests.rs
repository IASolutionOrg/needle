use super::*;
use crate::built_in_action_contracts;
use needle_core::*;
use serde_json::{Value, json};

const NOW: u64 = 1_800_000_000_000;

struct Fixture {
    action: ActionRequestProjection,
    context: AuthenticatedAwcpContext,
}

fn fixture() -> Fixture {
    fixture_for(0, "locate.implementation")
}

fn fixture_for(index: usize, route: &str) -> Fixture {
    let built_in = &built_in_action_contracts()[index];
    let request = ActionRequest::new(
        &built_in.contract,
        ArtifactRequest {
            contract_id: built_in.output_contract_id.to_owned(),
            contract_revision: built_in.output_contract_revision,
            repository_id: Digest::blake3(b"repository"),
            source_snapshot_digest: Digest::blake3(b"source-snapshot"),
            route_key: NeedKey::new(route).unwrap(),
            normalized_request: route.to_owned(),
            semantic_fragment_id: Some(NeedFragmentId::new(Digest::blake3(b"fragment"))),
            input_artifact_ids: Vec::new(),
        },
        built_in.contract.default_dispatch_policy,
        NeedKey::new(route).unwrap(),
        NeedId::new(Digest::blake3(b"need")),
    )
    .unwrap();
    let source_binding = ResolutionSourceBinding {
        semantic_source_context_digest: Digest::blake3(b"world"),
        repository_generation: None,
        state_delta_digest: None,
        definition_set_digest: Digest::blake3(b"definition-set"),
    };
    let action =
        ActionRequestProjection::new(request, definition_handle(built_in), source_binding).unwrap();
    let context = AuthenticatedAwcpContext {
        caller_identity_digest: Digest::blake3(b"authenticated-caller"),
        source_binding,
        effective_dispatch_policy_digest: action.request.effective_dispatch_policy_digest,
        allowed_effect: action.definition.effect_class,
    };
    Fixture { action, context }
}

#[test]
fn partitioned_inventory_action_uses_generic_shadow_awcp_resolution() {
    let fixture = fixture_for(3, "tests.inventory");
    assert_eq!(fixture.action.definition.id.as_str(), "needle.tests.inventory");
    let artifact = OfflineArtifactProjection::new(
        ArtifactId::new(Digest::blake3(b"inventory-projection")),
        fixture.action.definition.id.clone(),
        json!({"schema": TEST_TARGET_INVENTORY_SCHEMA_ID, "targets": 2}),
    )
    .unwrap();
    let mut simulator = OfflineAwcpSimulator::with_secret([16; 32]);
    simulator
        .register_resolution(OfflineActionResolution {
            action_request: fixture.action.request.semantic_id(),
            definition: fixture.action.definition.clone(),
            source_binding: fixture.action.source_binding,
            resolution: ActionResolutionProjection::Project,
            artifacts: vec![artifact],
            missing: Vec::new(),
            proof: Some(ProofHandle { id: Digest::blake3(b"inventory-proof") }),
            effective_mode: CapabilityMode::Shadow,
            limits: AppliedLimits::offline_default(),
            prior_artifact: None,
            refresh_plan_digest: None,
        })
        .unwrap();

    let response = resolve(&mut simulator, &fixture);
    assert_eq!(response.resolution, ActionResolutionProjection::Project);
    assert_eq!(response.negotiated_capabilities.effective_mode, CapabilityMode::Shadow);
    assert!(matches!(response.execution_hint, ExecutionHint::StartFreshWorker { .. }));
    assert_eq!(response.ticket.publish_authority, PublishAuthority::FreshResult);
}

#[test]
fn derived_architecture_action_uses_generic_shadow_awcp_resolution() {
    let fixture = fixture_for(4, "architecture.describe");
    assert_eq!(fixture.action.definition.id.as_str(), "needle.architecture.describe");
    assert_eq!(fixture.action.definition.effect_class, EffectClass::DerivedAnalysis);
    let artifact = OfflineArtifactProjection::new(
        ArtifactId::new(Digest::blake3(b"architecture-projection")),
        fixture.action.definition.id.clone(),
        json!({"schema": ARCHITECTURE_BRIEF_SCHEMA_ID, "packages": 2}),
    )
    .unwrap();
    let mut simulator = OfflineAwcpSimulator::with_secret([17; 32]);
    simulator
        .register_resolution(OfflineActionResolution {
            action_request: fixture.action.request.semantic_id(),
            definition: fixture.action.definition.clone(),
            source_binding: fixture.action.source_binding,
            resolution: ActionResolutionProjection::Project,
            artifacts: vec![artifact],
            missing: Vec::new(),
            proof: Some(ProofHandle { id: Digest::blake3(b"architecture-proof") }),
            effective_mode: CapabilityMode::Shadow,
            limits: AppliedLimits::offline_default(),
            prior_artifact: None,
            refresh_plan_digest: None,
        })
        .unwrap();

    let response = resolve(&mut simulator, &fixture);
    assert_eq!(response.resolution, ActionResolutionProjection::Project);
    assert_eq!(response.negotiated_capabilities.effective_mode, CapabilityMode::Shadow);
    assert!(matches!(response.execution_hint, ExecutionHint::StartFreshWorker { .. }));
    assert_eq!(response.ticket.publish_authority, PublishAuthority::FreshResult);
}

#[test]
fn derived_change_impact_action_uses_generic_shadow_awcp_resolution() {
    let fixture = fixture_for(5, "change.impact");
    assert_eq!(fixture.action.definition.id.as_str(), "needle.change.impact");
    assert_eq!(fixture.action.definition.effect_class, EffectClass::DerivedAnalysis);
    let artifact = OfflineArtifactProjection::new(
        ArtifactId::new(Digest::blake3(b"change-impact-projection")),
        fixture.action.definition.id.clone(),
        json!({"schema": CHANGE_IMPACT_SCHEMA_ID, "components": 2}),
    )
    .unwrap();
    let mut simulator = OfflineAwcpSimulator::with_secret([18; 32]);
    simulator
        .register_resolution(OfflineActionResolution {
            action_request: fixture.action.request.semantic_id(),
            definition: fixture.action.definition.clone(),
            source_binding: fixture.action.source_binding,
            resolution: ActionResolutionProjection::Project,
            artifacts: vec![artifact],
            missing: Vec::new(),
            proof: Some(ProofHandle { id: Digest::blake3(b"change-impact-proof") }),
            effective_mode: CapabilityMode::Shadow,
            limits: AppliedLimits::offline_default(),
            prior_artifact: None,
            refresh_plan_digest: None,
        })
        .unwrap();

    let response = resolve(&mut simulator, &fixture);
    assert_eq!(response.resolution, ActionResolutionProjection::Project);
    assert_eq!(response.negotiated_capabilities.effective_mode, CapabilityMode::Shadow);
    assert!(matches!(response.execution_hint, ExecutionHint::StartFreshWorker { .. }));
    assert_eq!(response.ticket.publish_authority, PublishAuthority::FreshResult);
}

fn resolve_request(fixture: &Fixture) -> ResolveActionRequest {
    ResolveActionRequest {
        protocol_revision: AWCP_PROTOCOL_REVISION,
        action: fixture.action.clone(),
        known_definitions: Vec::new(),
        caller_capabilities: CallerCapabilities::offline_complete(),
        requested_limits: AppliedLimits::offline_default(),
    }
}

fn resolve(simulator: &mut OfflineAwcpSimulator, fixture: &Fixture) -> ResolveActionResponse {
    let encoded =
        serde_json::to_vec(&AwcpRequest::ResolveAction(Box::new(resolve_request(fixture))))
            .unwrap();
    let response = simulator.handle_bytes(fixture.context, NOW, &encoded);
    assert!(response.len() <= MAX_AWCP_MESSAGE_BYTES);
    match serde_json::from_slice::<AwcpResponse>(&response).unwrap() {
        AwcpResponse::ResolveAction(response) => *response,
        other => panic!("unexpected resolve response: {other:?}"),
    }
}

fn observation(effect: EffectClass) -> WorkerObservationProjection {
    WorkerObservationProjection {
        started_at_unix_ms: NOW + 1,
        completed_at_unix_ms: NOW + 2,
        usage: UsageProjection {
            input_tokens: Some(10),
            cached_input_tokens: Some(0),
            output_tokens: Some(5),
        },
        cancelled: false,
        cleanup_succeeded: true,
        observed_effect: effect,
        effect_receipt_digest: None,
    }
}

fn provenance(seed: &'static [u8]) -> ExecutionProvenanceProjection {
    ExecutionProvenanceProjection {
        worker_definition_digest: Digest::blake3(seed),
        adapter_definition_digest: Digest::blake3(b"adapter"),
        sandbox_identity_digest: Digest::blake3(b"sandbox"),
    }
}

fn publish_request(
    fixture: &Fixture,
    ticket: ResolutionTicket,
    result: Value,
) -> PublishActionRequest {
    PublishActionRequest {
        protocol_revision: AWCP_PROTOCOL_REVISION,
        resolution_ticket: ticket,
        action_request: fixture.action.request.semantic_id(),
        action_contract: fixture.action.definition.clone(),
        worker_result: BoundedWorkerResult::from_value("needle.awcp.fixture/1", &result).unwrap(),
        observation: observation(fixture.action.definition.effect_class),
        execution_provenance: provenance(b"worker"),
    }
}

fn error_code(response: AwcpResponse) -> AwcpErrorCode {
    match response {
        AwcpResponse::Error(AwcpErrorResponse { code, .. }) => code,
        other => panic!("expected AWCP error, got {other:?}"),
    }
}

#[test]
fn exact_protocol_fixture_avoids_worker_and_grants_only_the_authenticated_caller() {
    let fixture = fixture();
    let artifact = OfflineArtifactProjection::new(
        ArtifactId::new(Digest::blake3(b"artifact")),
        fixture.action.definition.id.clone(),
        json!({"kind": "code-location", "path": "src/lib.rs", "symbol": "answer"}),
    )
    .unwrap();
    let artifact_id = artifact.handle.id;
    let mut simulator = OfflineAwcpSimulator::with_secret([7; 32]);
    simulator
        .register_resolution(OfflineActionResolution::exact(
            &fixture.action,
            artifact,
            ProofHandle { id: Digest::blake3(b"proof") },
            CapabilityMode::Authoritative,
        ))
        .unwrap();

    let response = resolve(&mut simulator, &fixture);
    assert_eq!(response.resolution, ActionResolutionProjection::Exact);
    assert_eq!(response.execution_hint, ExecutionHint::DoNotStartWorker);
    assert_eq!(response.ticket.publish_authority, PublishAuthority::Forbidden);
    assert_eq!(response.negotiated_capabilities.effective_mode, CapabilityMode::Authoritative);
    assert_eq!(simulator.ticket_count(), 1);

    let forbidden_publish =
        publish_request(&fixture, response.ticket.clone(), json!({"must_not_be_accepted": true}));
    assert_eq!(
        error_code(simulator.handle(
            fixture.context,
            NOW + 1,
            AwcpRequest::PublishAction(Box::new(forbidden_publish)),
        )),
        AwcpErrorCode::PublishForbidden
    );

    // This is the host decision point. The exact protocol response does not
    // invoke the fallback worker branch.
    let mut worker_spawns = 0_u32;
    if response.execution_hint != ExecutionHint::DoNotStartWorker {
        worker_spawns += 1;
    }
    assert_eq!(worker_spawns, 0);

    let artifact_response = simulator.handle(
        fixture.context,
        NOW + 1,
        AwcpRequest::GetArtifact(GetArtifactRequest {
            protocol_revision: AWCP_PROTOCOL_REVISION,
            artifact: artifact_id,
        }),
    );
    assert!(matches!(artifact_response, AwcpResponse::GetArtifact(_)));

    let mut other_caller = fixture.context;
    other_caller.caller_identity_digest = Digest::blake3(b"other-caller");
    assert_eq!(
        error_code(simulator.handle(
            other_caller,
            NOW + 1,
            AwcpRequest::GetArtifact(GetArtifactRequest {
                protocol_revision: AWCP_PROTOCOL_REVISION,
                artifact: artifact_id,
            }),
        )),
        AwcpErrorCode::ArtifactForbidden
    );

    let report = ReportExecutionRequest {
        protocol_revision: AWCP_PROTOCOL_REVISION,
        resolution_ticket: response.ticket,
        action_request: fixture.action.request.semantic_id(),
        status: ExecutionStatus::Skipped,
        observation: observation(fixture.action.definition.effect_class),
        execution_provenance: provenance(b"host"),
    };
    let first = simulator.handle(
        fixture.context,
        NOW + 2,
        AwcpRequest::ReportExecution(Box::new(report.clone())),
    );
    let replay =
        simulator.handle(fixture.context, NOW + 2, AwcpRequest::ReportExecution(Box::new(report)));
    assert_eq!(first, replay);
    assert_eq!(simulator.report_count(), 1);
}

#[test]
fn caller_cannot_self_promote_shadow_resolution() {
    let fixture = fixture();
    let artifact = OfflineArtifactProjection::new(
        ArtifactId::new(Digest::blake3(b"shadow-artifact")),
        fixture.action.definition.id.clone(),
        json!({"kind": "code-location"}),
    )
    .unwrap();
    let mut simulator = OfflineAwcpSimulator::with_secret([8; 32]);
    simulator
        .register_resolution(OfflineActionResolution::exact(
            &fixture.action,
            artifact,
            ProofHandle { id: Digest::blake3(b"proof") },
            CapabilityMode::Shadow,
        ))
        .unwrap();
    let response = resolve(&mut simulator, &fixture);
    assert_eq!(response.negotiated_capabilities.effective_mode, CapabilityMode::Shadow);
    assert_eq!(
        response.execution_hint,
        ExecutionHint::StartFreshWorker { action_request: fixture.action.request.semantic_id() }
    );
    assert_eq!(response.ticket.publish_authority, PublishAuthority::FreshResult);

    let mut value =
        serde_json::to_value(AwcpRequest::ResolveAction(Box::new(resolve_request(&fixture))))
            .unwrap();
    value["body"]["caller_capabilities"]["effective_mode"] = json!("authoritative");
    let response =
        simulator.handle_bytes(fixture.context, NOW, &serde_json::to_vec(&value).unwrap());
    assert_eq!(
        error_code(serde_json::from_slice(&response).unwrap()),
        AwcpErrorCode::MalformedMessage
    );
}

#[test]
fn disabled_mode_and_narrow_caller_limits_fail_without_issuing_authority() {
    let fixture = fixture();
    let disabled_artifact = OfflineArtifactProjection::new(
        ArtifactId::new(Digest::blake3(b"disabled-artifact")),
        fixture.action.definition.id.clone(),
        json!({"kind": "code-location"}),
    )
    .unwrap();
    let mut disabled = OfflineAwcpSimulator::with_secret([12; 32]);
    disabled
        .register_resolution(OfflineActionResolution::exact(
            &fixture.action,
            disabled_artifact,
            ProofHandle { id: Digest::blake3(b"proof") },
            CapabilityMode::Disabled,
        ))
        .unwrap();
    let response = resolve(&mut disabled, &fixture);
    assert_eq!(
        response.execution_hint,
        ExecutionHint::ContinueNative { reason: AwcpReasonCode::AuthorityInsufficient }
    );
    assert_eq!(response.ticket.publish_authority, PublishAuthority::Forbidden);

    let mut artifacts = [b"assemble-a".as_slice(), b"assemble-b".as_slice()]
        .into_iter()
        .map(|seed| {
            OfflineArtifactProjection::new(
                ArtifactId::new(Digest::blake3(seed)),
                fixture.action.definition.id.clone(),
                json!({"part": String::from_utf8_lossy(seed)}),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    artifacts.sort_by_key(|artifact| artifact.handle.id);
    let mut bounded = OfflineAwcpSimulator::with_secret([13; 32]);
    bounded
        .register_resolution(OfflineActionResolution {
            action_request: fixture.action.request.semantic_id(),
            definition: fixture.action.definition.clone(),
            source_binding: fixture.action.source_binding,
            resolution: ActionResolutionProjection::Assemble,
            artifacts,
            missing: Vec::new(),
            proof: Some(ProofHandle { id: Digest::blake3(b"assemble-proof") }),
            effective_mode: CapabilityMode::Authoritative,
            limits: AppliedLimits::offline_default(),
            prior_artifact: None,
            refresh_plan_digest: None,
        })
        .unwrap();
    let mut narrow = resolve_request(&fixture);
    narrow.requested_limits.max_artifacts = 1;
    assert_eq!(
        error_code(bounded.handle(
            fixture.context,
            NOW,
            AwcpRequest::ResolveAction(Box::new(narrow)),
        )),
        AwcpErrorCode::BoundExceeded
    );
    assert_eq!(bounded.ticket_count(), 0);
}

#[test]
fn publish_is_ticket_bound_and_identical_replay_is_idempotent() {
    let fixture = fixture();
    let mut simulator = OfflineAwcpSimulator::with_secret([9; 32]);
    simulator
        .register_resolution(OfflineActionResolution::compute_required(
            &fixture.action,
            CapabilityMode::Shadow,
        ))
        .unwrap();
    let resolved = resolve(&mut simulator, &fixture);
    assert!(matches!(resolved.execution_hint, ExecutionHint::StartFreshWorker { .. }));
    let publish = publish_request(&fixture, resolved.ticket.clone(), json!({"answer": 42}));

    let first = simulator.handle(
        fixture.context,
        NOW + 3,
        AwcpRequest::PublishAction(Box::new(publish.clone())),
    );
    let replay = simulator.handle(
        fixture.context,
        NOW + 3,
        AwcpRequest::PublishAction(Box::new(publish.clone())),
    );
    assert_eq!(first, replay);
    let accepted = match first {
        AwcpResponse::PublishAction(response) => response,
        other => panic!("unexpected publish response: {other:?}"),
    };
    assert_eq!(accepted.disposition, PublishDisposition::AcceptedForValidation);
    assert!(!accepted.reusable);
    assert!(accepted.artifact.is_none());
    assert!(accepted.validation.is_none());

    let divergent = publish_request(&fixture, resolved.ticket, json!({"answer": 43}));
    assert_eq!(
        error_code(simulator.handle(
            fixture.context,
            NOW + 3,
            AwcpRequest::PublishAction(Box::new(divergent)),
        )),
        AwcpErrorCode::ConsumedTicket
    );
}

#[test]
fn forged_ticket_wins_before_invalid_worker_json_and_live_bindings_fail_closed() {
    let fixture = fixture();
    let mut simulator = OfflineAwcpSimulator::with_secret([10; 32]);
    simulator
        .register_resolution(OfflineActionResolution::compute_required(
            &fixture.action,
            CapabilityMode::Authoritative,
        ))
        .unwrap();
    let resolved = resolve(&mut simulator, &fixture);
    let mut forged = publish_request(&fixture, resolved.ticket.clone(), json!({"answer": 42}));
    forged.resolution_ticket.authenticator = Digest::blake3(b"forged");
    forged.worker_result.canonical_json = "not-json".to_owned();
    assert_eq!(
        error_code(simulator.handle(
            fixture.context,
            NOW + 1,
            AwcpRequest::PublishAction(Box::new(forged)),
        )),
        AwcpErrorCode::ForgedTicket
    );

    let publish = publish_request(&fixture, resolved.ticket.clone(), json!({"answer": 42}));
    let mut caller_drift = fixture.context;
    caller_drift.caller_identity_digest = Digest::blake3(b"different-caller");
    assert_eq!(
        error_code(simulator.handle(
            caller_drift,
            NOW + 1,
            AwcpRequest::PublishAction(Box::new(publish.clone())),
        )),
        AwcpErrorCode::CallerDrift
    );

    let mut source_drift = fixture.context;
    source_drift.source_binding.semantic_source_context_digest = Digest::blake3(b"changed-world");
    assert_eq!(
        error_code(simulator.handle(
            source_drift,
            NOW + 1,
            AwcpRequest::PublishAction(Box::new(publish.clone())),
        )),
        AwcpErrorCode::SourceDrift
    );

    let mut dispatch_drift = fixture.context;
    dispatch_drift.effective_dispatch_policy_digest = Digest::blake3(b"changed-dispatch");
    assert_eq!(
        error_code(simulator.handle(
            dispatch_drift,
            NOW + 1,
            AwcpRequest::PublishAction(Box::new(publish.clone())),
        )),
        AwcpErrorCode::DispatchDrift
    );

    let mut effect_drift = fixture.context;
    effect_drift.allowed_effect = EffectClass::ExternalRead;
    assert_eq!(
        error_code(simulator.handle(
            effect_drift,
            NOW + 1,
            AwcpRequest::PublishAction(Box::new(publish.clone())),
        )),
        AwcpErrorCode::EffectDrift
    );

    assert_eq!(
        error_code(simulator.handle(
            fixture.context,
            NOW + MAX_AWCP_TICKET_TTL_MS,
            AwcpRequest::PublishAction(Box::new(publish)),
        )),
        AwcpErrorCode::ExpiredTicket
    );
}

#[test]
fn definition_effect_credentials_bounds_and_report_conflicts_are_rejected() {
    let fixture = fixture();
    let mut simulator = OfflineAwcpSimulator::with_secret([11; 32]);
    simulator
        .register_resolution(OfflineActionResolution::compute_required(
            &fixture.action,
            CapabilityMode::Shadow,
        ))
        .unwrap();
    let resolved = resolve(&mut simulator, &fixture);

    let mut definition_drift =
        publish_request(&fixture, resolved.ticket.clone(), json!({"answer": 42}));
    definition_drift.action_contract.validation_definition_digest = Digest::blake3(b"changed");
    assert_eq!(
        error_code(simulator.handle(
            fixture.context,
            NOW + 1,
            AwcpRequest::PublishAction(Box::new(definition_drift)),
        )),
        AwcpErrorCode::DefinitionDrift
    );

    let mut effect_drift =
        publish_request(&fixture, resolved.ticket.clone(), json!({"answer": 42}));
    effect_drift.observation.observed_effect = EffectClass::ExternalRead;
    assert_eq!(
        error_code(simulator.handle(
            fixture.context,
            NOW + 1,
            AwcpRequest::PublishAction(Box::new(effect_drift)),
        )),
        AwcpErrorCode::EffectDrift
    );

    let mut credential = publish_request(&fixture, resolved.ticket.clone(), json!({"answer": 42}));
    credential.worker_result = BoundedWorkerResult {
        schema_id: "needle.awcp.fixture/1".to_owned(),
        canonical_json: serde_json::to_string(&json!({"api_key": "forbidden"})).unwrap(),
    };
    assert_eq!(
        error_code(simulator.handle(
            fixture.context,
            NOW + 1,
            AwcpRequest::PublishAction(Box::new(credential)),
        )),
        AwcpErrorCode::InvalidWorkerResult
    );

    let oversized = vec![b' '; MAX_AWCP_MESSAGE_BYTES + 1];
    let response = simulator.handle_bytes(fixture.context, NOW, &oversized);
    assert_eq!(
        error_code(serde_json::from_slice(&response).unwrap()),
        AwcpErrorCode::BoundExceeded
    );

    let report = ReportExecutionRequest {
        protocol_revision: AWCP_PROTOCOL_REVISION,
        resolution_ticket: resolved.ticket,
        action_request: fixture.action.request.semantic_id(),
        status: ExecutionStatus::Completed,
        observation: observation(fixture.action.definition.effect_class),
        execution_provenance: provenance(b"first"),
    };
    assert!(matches!(
        simulator.handle(
            fixture.context,
            NOW + 2,
            AwcpRequest::ReportExecution(Box::new(report.clone())),
        ),
        AwcpResponse::ReportExecution(_)
    ));
    let mut conflicting = report;
    conflicting.execution_provenance = provenance(b"second");
    assert_eq!(
        error_code(simulator.handle(
            fixture.context,
            NOW + 2,
            AwcpRequest::ReportExecution(Box::new(conflicting)),
        )),
        AwcpErrorCode::ExecutionReportConflict
    );
}
