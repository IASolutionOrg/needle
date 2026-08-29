use super::*;
use crate::{
    ActionContract, ActionContractId, ActionContractInput, ActionRequest, ArtifactRequest,
    CompletionPolicy, DispatchPolicy, EffectClass, EvidencePolicy, MAX_REQUEST_BYTES,
    NeedFragmentId, NeedId, NeedKey, PersistencePolicy, PriorArtifactPolicy, ReuseMode,
};
use serde_json::json;

fn dispatch() -> DispatchPolicy {
    DispatchPolicy {
        completion: CompletionPolicy::ReuseAllowed,
        evidence: EvidencePolicy::Standard,
        prior_artifacts: PriorArtifactPolicy::ContractDefined,
        persistence: PersistencePolicy::Ephemeral,
    }
}

fn contract() -> ActionContract {
    ActionContract::new(ActionContractInput {
        id: ActionContractId::new("needle.test.awcp").unwrap(),
        semantic_authority_source_digest: Digest::blake3(b"semantic"),
        validation_authority_source_digest: Digest::blake3(b"validation"),
        operational_authority_source_digest: Digest::blake3(b"operational"),
        effect_class: EffectClass::PureEvidence,
        reuse_modes: vec![ReuseMode::Exact],
        default_dispatch_policy: dispatch(),
    })
    .unwrap()
}

fn action() -> (ActionRequestProjection, ActionContract) {
    let contract = contract();
    let mut input_artifact_ids = vec![Digest::blake3(b"input-a"), Digest::blake3(b"input-b")];
    input_artifact_ids.sort();
    let request = ActionRequest::new(
        &contract,
        ArtifactRequest {
            contract_id: "needle.semantic.code-location".to_owned(),
            contract_revision: 2,
            repository_id: Digest::blake3(b"repository"),
            source_snapshot_digest: Digest::blake3(b"source"),
            route_key: NeedKey::new("locate.implementation").unwrap(),
            normalized_request: "locate the implementation".to_owned(),
            semantic_fragment_id: Some(NeedFragmentId::new(Digest::blake3(b"fragment"))),
            input_artifact_ids,
        },
        dispatch(),
        NeedKey::new("locate.implementation").unwrap(),
        NeedId::new(Digest::blake3(b"need")),
    )
    .unwrap();
    let definition = ActionDefinitionHandle {
        id: contract.id.clone(),
        semantic_definition_digest: contract.semantic_definition_digest,
        validation_definition_digest: contract.validation_definition_digest,
        operational_policy_digest: contract.operational_policy_digest,
        definition_digest: contract.definition_digest,
        effect_class: contract.effect_class,
    };
    let projection = ActionRequestProjection::new(
        request,
        definition,
        ResolutionSourceBinding {
            semantic_source_context_digest: Digest::blake3(b"world"),
            repository_generation: None,
            state_delta_digest: None,
            definition_set_digest: Digest::blake3(b"definitions"),
        },
    )
    .unwrap();
    (projection, contract)
}

#[test]
fn resolve_request_is_versioned_bounded_and_definition_bound() {
    let (action_projection, _) = action();
    let mut known_definitions = vec![Digest::blake3(b"a"), Digest::blake3(b"b")];
    known_definitions.sort();
    let request = ResolveActionRequest {
        protocol_revision: AWCP_PROTOCOL_REVISION,
        action: action_projection,
        known_definitions,
        caller_capabilities: CallerCapabilities::offline_complete(),
        requested_limits: AppliedLimits::offline_default(),
    };
    request.validate_shape().unwrap();
    let encoded =
        serde_json::to_vec(&AwcpRequest::ResolveAction(Box::new(request.clone()))).unwrap();
    assert!(encoded.len() <= MAX_AWCP_MESSAGE_BYTES);
    assert_eq!(
        serde_json::from_slice::<AwcpRequest>(&encoded).unwrap(),
        AwcpRequest::ResolveAction(Box::new(request))
    );

    let mut drifted = match serde_json::from_slice::<AwcpRequest>(&encoded).unwrap() {
        AwcpRequest::ResolveAction(request) => *request,
        _ => unreachable!(),
    };
    drifted.action.definition.semantic_definition_digest = Digest::blake3(b"drift");
    assert_eq!(drifted.validate_shape(), Err(AwcpValidationError::ActionDefinitionBinding));

    drifted = ResolveActionRequest {
        protocol_revision: AWCP_PROTOCOL_REVISION,
        action: action().0,
        known_definitions: vec![Digest::blake3(b"same"), Digest::blake3(b"same")],
        caller_capabilities: CallerCapabilities::offline_complete(),
        requested_limits: AppliedLimits::offline_default(),
    };
    assert_eq!(
        drifted.validate_shape(),
        Err(AwcpValidationError::CanonicalSet("known_definitions"))
    );

    let mut over_bound = (0..=MAX_AWCP_KNOWN_DEFINITIONS)
        .map(|index| Digest::blake3(index.to_le_bytes()))
        .collect::<Vec<_>>();
    over_bound.sort();
    let too_many = ResolveActionRequest {
        protocol_revision: AWCP_PROTOCOL_REVISION,
        action: action().0,
        known_definitions: over_bound,
        caller_capabilities: CallerCapabilities::offline_complete(),
        requested_limits: AppliedLimits::offline_default(),
    };
    assert!(matches!(
        too_many.validate_shape(),
        Err(AwcpValidationError::Bound {
            field: "known_definitions",
            actual,
            maximum: MAX_AWCP_KNOWN_DEFINITIONS,
        }) if actual == MAX_AWCP_KNOWN_DEFINITIONS + 1
    ));

    let mut oversized_action = action().0;
    oversized_action.request.artifact_request.normalized_request =
        "x".repeat(MAX_REQUEST_BYTES + 1);
    assert!(matches!(
        oversized_action.validate_shape(),
        Err(AwcpValidationError::Bound {
            field: "action.request.normalized_request",
            actual,
            maximum: MAX_REQUEST_BYTES,
        }) if actual == MAX_REQUEST_BYTES + 1
    ));
}

#[test]
fn worker_result_is_canonical_bounded_and_credential_free() {
    let result = BoundedWorkerResult::from_value(
        "needle.awcp.test/1",
        &json!({"artifact": {"kind": "code-location"}}),
    )
    .unwrap();
    assert_eq!(
        result.validate_after_authentication(MAX_AWCP_WORKER_RESULT_BYTES).unwrap(),
        json!({"artifact": {"kind": "code-location"}})
    );

    let noncanonical = BoundedWorkerResult {
        schema_id: "needle.awcp.test/1".to_owned(),
        canonical_json: "{ \"ok\": true }".to_owned(),
    };
    assert_eq!(
        noncanonical.validate_after_authentication(MAX_AWCP_WORKER_RESULT_BYTES),
        Err(AwcpValidationError::WorkerResultCanonical)
    );

    let credential = BoundedWorkerResult::from_value(
        "needle.awcp.test/1",
        &json!({"nested": {"access_token": "must-not-cross-awcp"}}),
    );
    assert_eq!(credential, Err(AwcpValidationError::CredentialMaterial));
}

#[test]
fn ticket_shape_binds_expiry_and_refresh_authority() {
    let (action, _) = action();
    let ticket = ResolutionTicket {
        id: ResolutionTicketId::new(Digest::blake3(b"ticket")),
        protocol_revision: AWCP_PROTOCOL_REVISION,
        action_request: action.request.semantic_id(),
        action_contract: action.definition.id,
        semantic_definition_digest: action.definition.semantic_definition_digest,
        validation_definition_digest: action.definition.validation_definition_digest,
        contract_operational_policy_digest: action.definition.operational_policy_digest,
        effective_dispatch_policy_digest: action.request.effective_dispatch_policy_digest,
        semantic_inputs_digest: action.semantic_inputs_digest,
        source_binding: action.source_binding,
        resolution_digest: Digest::blake3(b"resolution"),
        allowed_effect: EffectClass::PureEvidence,
        publish_authority: PublishAuthority::Forbidden,
        prior_artifact: None,
        refresh_plan_digest: None,
        applied_limits: AppliedLimits::offline_default(),
        caller_identity_digest: Digest::blake3(b"caller"),
        nonce: Digest::blake3(b"nonce"),
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
        authenticator: Digest::blake3(b"authenticator"),
    };
    ticket.validate_shape().unwrap();

    let mut invalid = ticket.clone();
    invalid.expires_at_unix_ms = invalid.issued_at_unix_ms + MAX_AWCP_TICKET_TTL_MS + 1;
    assert_eq!(invalid.validate_shape(), Err(AwcpValidationError::TicketExpiry));

    invalid = ticket;
    invalid.publish_authority = PublishAuthority::RefreshResult;
    assert_eq!(invalid.validate_shape(), Err(AwcpValidationError::PublishAuthorityBinding));
}

#[test]
fn envelope_rejects_unknown_fields_and_unsupported_revision() {
    let (action_projection, _) = action();
    let request = AwcpRequest::ResolveAction(Box::new(ResolveActionRequest {
        protocol_revision: AWCP_PROTOCOL_REVISION,
        action: action_projection,
        known_definitions: Vec::new(),
        caller_capabilities: CallerCapabilities::offline_complete(),
        requested_limits: AppliedLimits::offline_default(),
    }));
    let mut value = serde_json::to_value(request).unwrap();
    value.as_object_mut().unwrap().insert("credential".to_owned(), json!("forbidden"));
    assert!(serde_json::from_value::<AwcpRequest>(value).is_err());

    let mut unsupported = ResolveActionRequest {
        protocol_revision: AWCP_PROTOCOL_REVISION + 1,
        action: action().0,
        known_definitions: Vec::new(),
        caller_capabilities: CallerCapabilities::offline_complete(),
        requested_limits: AppliedLimits::offline_default(),
    };
    assert_eq!(
        unsupported.validate_shape(),
        Err(AwcpValidationError::Revision(AWCP_PROTOCOL_REVISION + 1))
    );
    unsupported.protocol_revision = AWCP_PROTOCOL_REVISION;
    unsupported.validate_shape().unwrap();
}
