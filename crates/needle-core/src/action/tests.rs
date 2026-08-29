use super::*;
use crate::{
    ArtifactRequest, CanonicalHasher, Digest, MAX_NEED_INPUTS, NeedFragmentId, NeedId, NeedKey,
};

fn reuse_allowed() -> DispatchPolicy {
    DispatchPolicy {
        completion: CompletionPolicy::ReuseAllowed,
        evidence: EvidencePolicy::Standard,
        prior_artifacts: PriorArtifactPolicy::ContractDefined,
        persistence: PersistencePolicy::Persistent,
    }
}

fn fresh_no_store() -> DispatchPolicy {
    DispatchPolicy {
        completion: CompletionPolicy::FreshRequired,
        evidence: EvidencePolicy::IndependentEvidenceRequired,
        prior_artifacts: PriorArtifactPolicy::ContractDefined,
        persistence: PersistencePolicy::NoStore,
    }
}

fn input(
    effect_class: EffectClass,
    reuse_modes: Vec<ReuseMode>,
    dispatch: DispatchPolicy,
) -> ActionContractInput {
    ActionContractInput {
        id: ActionContractId::new("needle.location.resolve").unwrap(),
        semantic_authority_source_digest: Digest::blake3(b"semantic-source"),
        validation_authority_source_digest: Digest::blake3(b"validation-source"),
        operational_authority_source_digest: Digest::blake3(b"operational-source"),
        effect_class,
        reuse_modes,
        default_dispatch_policy: dispatch,
    }
}

fn contract() -> ActionContract {
    ActionContract::new(input(
        EffectClass::PureEvidence,
        vec![ReuseMode::Assemble, ReuseMode::Exact, ReuseMode::Project],
        reuse_allowed(),
    ))
    .unwrap()
}

fn artifact_request() -> ArtifactRequest {
    ArtifactRequest {
        contract_id: "needle.semantic.code-location".to_owned(),
        contract_revision: 2,
        repository_id: Digest::blake3(b"repo"),
        source_snapshot_digest: Digest::blake3(b"source"),
        route_key: NeedKey::new("locate.implementation").unwrap(),
        normalized_request: "find implementation".to_owned(),
        semantic_fragment_id: Some(NeedFragmentId::new(Digest::blake3(b"fragment"))),
        input_artifact_ids: vec![Digest::blake3(b"input")],
    }
}

#[test]
fn dispatch_policy_digest_is_stable_and_axis_sensitive() {
    let base = reuse_allowed();
    assert_eq!(
        base.digest(),
        Digest::parse("b3:47afcad92d05234bb3eec53db31474b24d5cde9f8a86f73d9722e1c5c18ffbfb")
            .unwrap()
    );
    for changed in [
        DispatchPolicy { completion: CompletionPolicy::ExactReuseOnly, ..base },
        DispatchPolicy { evidence: EvidencePolicy::IndependentEvidenceRequired, ..base },
        DispatchPolicy { prior_artifacts: PriorArtifactPolicy::AdvisoryOnly, ..base },
        DispatchPolicy { persistence: PersistencePolicy::Ephemeral, ..base },
    ] {
        assert_ne!(base.digest(), changed.digest());
    }
}

#[test]
fn dispatch_axes_remain_independent_and_use_kebab_case() {
    let fresh = fresh_no_store();
    let exact = DispatchPolicy {
        completion: CompletionPolicy::ExactReuseOnly,
        evidence: EvidencePolicy::Standard,
        prior_artifacts: PriorArtifactPolicy::Forbidden,
        persistence: PersistencePolicy::Ephemeral,
    };
    assert_ne!(fresh.digest(), exact.digest());

    let json = serde_json::to_string(&fresh).unwrap();
    assert!(json.contains("\"completion\":\"fresh-required\""));
    assert!(json.contains("\"evidence\":\"independent-evidence-required\""));
    assert!(json.contains("\"persistence\":\"no-store\""));
    assert!(serde_json::from_str::<DispatchPolicy>(
        r#"{"completion":"fresh-required","evidence":"standard","prior_artifacts":"forbidden","persistence":"no-store","unknown":true}"#
    )
    .is_err());
    assert!(serde_json::from_str::<ActionContractId>(r#""Needle.Bad""#).is_err());
}

#[test]
fn reuse_mode_set_is_canonical_bounded_and_never_is_exclusive() {
    let left = ReuseModeSet::new([
        ReuseMode::Refresh,
        ReuseMode::Exact,
        ReuseMode::Exact,
        ReuseMode::Project,
    ])
    .unwrap();
    let right =
        ReuseModeSet::new([ReuseMode::Project, ReuseMode::Refresh, ReuseMode::Exact]).unwrap();
    assert_eq!(left, right);
    assert_eq!(serde_json::to_string(&left).unwrap(), r#"["exact","project","refresh"]"#);
    assert_eq!(serde_json::from_str::<ReuseModeSet>(r#"["refresh","exact"]"#).unwrap().len(), 2);
    assert_eq!(ReuseModeSet::new([]), Err(ReuseModeSetError::Empty));
    assert_eq!(
        ReuseModeSet::new([ReuseMode::Never, ReuseMode::Exact]),
        Err(ReuseModeSetError::NeverExclusive)
    );

    let maximum = [ReuseMode::Exact; MAX_REUSE_MODE_ENTRIES];
    assert!(ReuseModeSet::new(maximum).is_ok());
    assert_eq!(
        ReuseModeSet::new([ReuseMode::Exact; MAX_REUSE_MODE_ENTRIES + 1]),
        Err(ReuseModeSetError::TooManyEntries { maximum: MAX_REUSE_MODE_ENTRIES })
    );
    assert!(
        serde_json::from_str::<ReuseModeSet>(
            r#"["exact","exact","exact","exact","exact","exact"]"#
        )
        .is_err()
    );
}

#[test]
fn contract_digests_have_separate_authority() {
    let base = contract();

    let effect = ActionContract::new(input(
        EffectClass::DerivedAnalysis,
        vec![ReuseMode::Exact, ReuseMode::Project, ReuseMode::Assemble],
        reuse_allowed(),
    ))
    .unwrap();
    assert_ne!(base.semantic_definition_digest, effect.semantic_definition_digest);
    assert_eq!(base.validation_definition_digest, effect.validation_definition_digest);
    assert_eq!(base.operational_policy_digest, effect.operational_policy_digest);
    assert_ne!(base.definition_digest, effect.definition_digest);

    let validation = ActionContract::new(input(
        EffectClass::PureEvidence,
        vec![ReuseMode::Exact],
        reuse_allowed(),
    ))
    .unwrap();
    assert_eq!(base.semantic_definition_digest, validation.semantic_definition_digest);
    assert_ne!(base.validation_definition_digest, validation.validation_definition_digest);
    assert_eq!(base.operational_policy_digest, validation.operational_policy_digest);
    assert_ne!(base.definition_digest, validation.definition_digest);

    let operational = ActionContract::new(input(
        EffectClass::PureEvidence,
        vec![ReuseMode::Exact, ReuseMode::Project, ReuseMode::Assemble],
        DispatchPolicy { persistence: PersistencePolicy::Ephemeral, ..reuse_allowed() },
    ))
    .unwrap();
    assert_eq!(base.semantic_definition_digest, operational.semantic_definition_digest);
    assert_eq!(base.validation_definition_digest, operational.validation_definition_digest);
    assert_ne!(base.operational_policy_digest, operational.operational_policy_digest);
    assert_ne!(base.definition_digest, operational.definition_digest);

    let mut tampered = base;
    tampered.definition_digest = Digest::blake3(b"tampered");
    assert!(!tampered.is_canonical());
}

#[test]
fn external_effect_and_never_require_fresh_completion() {
    assert!(
        ActionContract::new(input(
            EffectClass::ExternalEffect,
            vec![ReuseMode::Never],
            fresh_no_store(),
        ))
        .is_ok()
    );
    assert_eq!(
        ActionContract::new(input(
            EffectClass::ExternalEffect,
            vec![ReuseMode::Exact],
            reuse_allowed(),
        )),
        Err(ActionValidationError::ExternalEffectRequiresNever)
    );
    assert_eq!(
        ActionContract::new(input(
            EffectClass::PureEvidence,
            vec![ReuseMode::Never],
            reuse_allowed(),
        )),
        Err(ActionValidationError::NeverRequiresFresh)
    );
}

#[test]
fn action_request_v2_identity_excludes_operational_and_legacy_request_state() {
    let contract = contract();
    let artifact_request = artifact_request();
    let base = ActionRequest::new(
        &contract,
        artifact_request.clone(),
        reuse_allowed(),
        NeedKey::new("locate.implementation").unwrap(),
        NeedId::new(Digest::blake3(b"root-a")),
    )
    .unwrap();
    let mut changed_artifact_request = artifact_request.clone();
    changed_artifact_request.contract_id = "legacy.other-contract".to_owned();
    changed_artifact_request.contract_revision += 1;
    changed_artifact_request.repository_id = Digest::blake3(b"legacy-repository-field");
    changed_artifact_request.source_snapshot_digest = Digest::blake3(b"other-snapshot");
    changed_artifact_request.route_key = NeedKey::new("trace.state-flow").unwrap();
    changed_artifact_request.normalized_request = "different wording".to_owned();
    let changed = ActionRequest::new(
        &contract,
        changed_artifact_request,
        fresh_no_store(),
        NeedKey::new("trace.state-flow").unwrap(),
        NeedId::new(Digest::blake3(b"root-b")),
    )
    .unwrap();

    assert_eq!(
        base.semantic_id().to_string(),
        "b3:6b50bfd8442cff2d86a57f6e6e5105f9aed8f6a6248513708753da47d7fa8a33"
    );
    assert_ne!(base.semantic_id(), artifact_request.semantic_id());
    assert_eq!(base.legacy_semantic_id(), artifact_request.semantic_id());
    assert_eq!(base.semantic_id(), changed.semantic_id());
    assert_ne!(base.effective_dispatch_policy_digest, changed.effective_dispatch_policy_digest);
    assert!(base.is_canonical(&contract));

    let mut tampered = base.clone();
    tampered.effective_dispatch_policy_digest = Digest::blake3(b"tampered");
    assert_eq!(
        tampered.validate(&contract),
        Err(ActionValidationError::EffectiveDispatchPolicyMismatch)
    );
    let mut tampered = base;
    tampered.contract_operational_policy_digest = Digest::blake3(b"other-policy");
    assert_eq!(
        tampered.validate(&contract),
        Err(ActionValidationError::RequestOperationalPolicyMismatch)
    );
}

#[test]
fn action_request_v2_identity_binds_fragment_inputs_and_action_definition() {
    let base_contract = contract();
    let base = ActionRequest::new(
        &base_contract,
        artifact_request(),
        reuse_allowed(),
        NeedKey::new("locate.implementation").unwrap(),
        NeedId::new(Digest::blake3(b"root")),
    )
    .unwrap();

    let mut different_fragment_request = artifact_request();
    different_fragment_request.semantic_fragment_id =
        Some(NeedFragmentId::new(Digest::blake3(b"different-fragment")));
    let different_fragment = ActionRequest::new(
        &base_contract,
        different_fragment_request,
        reuse_allowed(),
        NeedKey::new("locate.implementation").unwrap(),
        NeedId::new(Digest::blake3(b"root")),
    )
    .unwrap();
    assert_ne!(base.semantic_id(), different_fragment.semantic_id());

    let mut different_input_request = artifact_request();
    different_input_request.input_artifact_ids = vec![Digest::blake3(b"different-input")];
    let different_input = ActionRequest::new(
        &base_contract,
        different_input_request,
        reuse_allowed(),
        NeedKey::new("locate.implementation").unwrap(),
        NeedId::new(Digest::blake3(b"root")),
    )
    .unwrap();
    assert_ne!(base.semantic_id(), different_input.semantic_id());

    let mut changed_input = input(
        EffectClass::PureEvidence,
        vec![ReuseMode::Assemble, ReuseMode::Exact, ReuseMode::Project],
        reuse_allowed(),
    );
    changed_input.semantic_authority_source_digest = Digest::blake3(b"changed-semantic-source");
    let different_contract = ActionContract::new(changed_input).unwrap();
    let different_definition = ActionRequest::new(
        &different_contract,
        artifact_request(),
        reuse_allowed(),
        NeedKey::new("locate.implementation").unwrap(),
        NeedId::new(Digest::blake3(b"root")),
    )
    .unwrap();
    assert_ne!(base.semantic_id(), different_definition.semantic_id());

    for nonsemantic_contract in [
        ActionContract::new(input(
            EffectClass::PureEvidence,
            vec![ReuseMode::Exact],
            reuse_allowed(),
        ))
        .unwrap(),
        ActionContract::new(input(
            EffectClass::PureEvidence,
            vec![ReuseMode::Assemble, ReuseMode::Exact, ReuseMode::Project],
            DispatchPolicy { persistence: PersistencePolicy::Ephemeral, ..reuse_allowed() },
        ))
        .unwrap(),
    ] {
        let request = ActionRequest::new(
            &nonsemantic_contract,
            artifact_request(),
            reuse_allowed(),
            NeedKey::new("locate.implementation").unwrap(),
            NeedId::new(Digest::blake3(b"root")),
        )
        .unwrap();
        assert_eq!(base.semantic_id(), request.semantic_id());
    }

    let mut tampered = base;
    tampered.contract_semantic_definition_digest = Some(Digest::blake3(b"tampered"));
    assert_eq!(
        tampered.validate(&base_contract),
        Err(ActionValidationError::RequestSemanticPolicyMismatch)
    );
}

#[test]
fn action_request_v3_binds_typed_parameters_without_binding_operational_state() {
    let contract = contract();
    let parameters = Digest::blake3(b"typed-action-parameters");
    let base = ActionRequest::new_with_semantic_parameters(
        &contract,
        artifact_request(),
        parameters,
        reuse_allowed(),
        NeedKey::new("locate.implementation").unwrap(),
        NeedId::new(Digest::blake3(b"root-a")),
    )
    .unwrap();
    let operationally_different = ActionRequest::new_with_semantic_parameters(
        &contract,
        artifact_request(),
        parameters,
        fresh_no_store(),
        NeedKey::new("trace.state-flow").unwrap(),
        NeedId::new(Digest::blake3(b"root-b")),
    )
    .unwrap();
    let semantically_different = ActionRequest::new_with_semantic_parameters(
        &contract,
        artifact_request(),
        Digest::blake3(b"different-typed-action-parameters"),
        reuse_allowed(),
        NeedKey::new("locate.implementation").unwrap(),
        NeedId::new(Digest::blake3(b"root-a")),
    )
    .unwrap();

    assert_eq!(base.format_revision, ACTION_REQUEST_PARAMETERIZED_FORMAT_REVISION);
    assert_eq!(base.semantic_id(), operationally_different.semantic_id());
    assert_ne!(base.semantic_id(), semantically_different.semantic_id());
    assert!(base.is_canonical(&contract));

    let mut v2_with_parameters = ActionRequest::new(
        &contract,
        artifact_request(),
        reuse_allowed(),
        NeedKey::new("locate.implementation").unwrap(),
        NeedId::new(Digest::blake3(b"root")),
    )
    .unwrap();
    v2_with_parameters.semantic_parameter_digest = Some(parameters);
    assert_eq!(
        v2_with_parameters.validate(&contract),
        Err(ActionValidationError::RequestSemanticParameterMismatch)
    );
    assert_eq!(
        ActionRequest::new_with_semantic_parameters(
            &contract,
            artifact_request(),
            Digest([0; 32]),
            reuse_allowed(),
            NeedKey::new("locate.implementation").unwrap(),
            NeedId::new(Digest::blake3(b"root")),
        ),
        Err(ActionValidationError::RequestSemanticParameterRequired)
    );
}

#[test]
fn action_request_enforces_never_and_validates_deserialized_routes() {
    let contract = ActionContract::new(input(
        EffectClass::ExternalEffect,
        vec![ReuseMode::Never],
        fresh_no_store(),
    ))
    .unwrap();
    assert_eq!(
        ActionRequest::new(
            &contract,
            artifact_request(),
            reuse_allowed(),
            NeedKey::new("locate.implementation").unwrap(),
            NeedId::new(Digest::blake3(b"root")),
        ),
        Err(ActionValidationError::NeverRequiresFresh)
    );

    let request = ActionRequest::new(
        &contract,
        artifact_request(),
        fresh_no_store(),
        NeedKey::new("locate.implementation").unwrap(),
        NeedId::new(Digest::blake3(b"root")),
    )
    .unwrap();
    let mut value = serde_json::to_value(request).unwrap();
    value.as_object_mut().unwrap().insert("route".to_owned(), "Invalid Route".into());
    let decoded: ActionRequest = serde_json::from_value(value).unwrap();
    assert_eq!(
        decoded.validate(&contract),
        Err(ActionValidationError::RequestRoute { field: "route" })
    );

    let mut unchecked_artifact_request = artifact_request();
    unchecked_artifact_request.route_key = serde_json::from_str(r#""Invalid Route""#).unwrap();
    assert_eq!(
        ActionRequest::new(
            &contract,
            unchecked_artifact_request,
            fresh_no_store(),
            NeedKey::new("locate.implementation").unwrap(),
            NeedId::new(Digest::blake3(b"root")),
        ),
        Err(ActionValidationError::RequestRoute { field: "artifact_request.route_key" })
    );
}

#[test]
fn action_request_rejects_input_overflow_and_legacy_json_still_decodes() {
    let contract = contract();
    let mut request = artifact_request();
    request.input_artifact_ids =
        (0..=MAX_NEED_INPUTS).map(|index| Digest::blake3(index.to_le_bytes())).collect();
    assert_eq!(
        ActionRequest::new(
            &contract,
            request,
            reuse_allowed(),
            NeedKey::new("locate.implementation").unwrap(),
            NeedId::new(Digest::blake3(b"root")),
        ),
        Err(ActionValidationError::RequestInputBound {
            actual: MAX_NEED_INPUTS + 1,
            maximum: MAX_NEED_INPUTS,
        })
    );

    let legacy = artifact_request();
    let mut value = serde_json::to_value(&legacy).unwrap();
    value.as_object_mut().unwrap().remove("semantic_fragment_id");
    let decoded: ArtifactRequest = serde_json::from_value(value).unwrap();
    assert_eq!(decoded.semantic_fragment_id, None);

    let action = ActionRequest::new(
        &contract,
        artifact_request(),
        reuse_allowed(),
        NeedKey::new("locate.implementation").unwrap(),
        NeedId::new(Digest::blake3(b"root")),
    )
    .unwrap();
    let mut legacy_action = serde_json::to_value(&action).unwrap();
    legacy_action["format_revision"] = ACTION_FORMAT_REVISION.into();
    legacy_action.as_object_mut().unwrap().remove("contract_semantic_definition_digest");
    let mut legacy_effective = CanonicalHasher::new(b"action-request-effective-dispatch-v1");
    legacy_effective.field_u16(ACTION_FORMAT_REVISION);
    legacy_effective.field_digest(contract.operational_policy_digest);
    legacy_effective.field_digest(action.dispatch_policy.digest());
    legacy_action["effective_dispatch_policy_digest"] =
        serde_json::to_value(legacy_effective.finish()).unwrap();
    let decoded: ActionRequest = serde_json::from_value(legacy_action).unwrap();
    assert_eq!(decoded.format_revision, ACTION_FORMAT_REVISION);
    assert_eq!(decoded.contract_semantic_definition_digest, None);
    assert_eq!(decoded.semantic_id(), decoded.artifact_request.semantic_id());
    assert!(decoded.is_canonical(&contract));

    let mut value = serde_json::to_value(action).unwrap();
    value["artifact_request"]["input_artifact_ids"] = serde_json::Value::Array(
        (0..=MAX_NEED_INPUTS)
            .map(|index| serde_json::to_value(Digest::blake3(index.to_le_bytes())).unwrap())
            .collect(),
    );
    assert!(serde_json::from_value::<ActionRequest>(value).is_err());
}

#[test]
fn action_request_v2_requires_fragment_and_canonical_inputs() {
    let contract = contract();
    let mut missing_fragment = artifact_request();
    missing_fragment.semantic_fragment_id = None;
    assert_eq!(
        ActionRequest::new(
            &contract,
            missing_fragment,
            reuse_allowed(),
            NeedKey::new("locate.implementation").unwrap(),
            NeedId::new(Digest::blake3(b"root")),
        ),
        Err(ActionValidationError::RequestSemanticFragmentRequired)
    );

    let first = Digest::blake3(b"first");
    let second = Digest::blake3(b"second");
    let mut noncanonical = artifact_request();
    noncanonical.input_artifact_ids =
        if first < second { vec![second, first] } else { vec![first, second] };
    assert_eq!(
        ActionRequest::new(
            &contract,
            noncanonical,
            reuse_allowed(),
            NeedKey::new("locate.implementation").unwrap(),
            NeedId::new(Digest::blake3(b"root")),
        ),
        Err(ActionValidationError::RequestInputsNotCanonical)
    );

    let mut duplicate = artifact_request();
    duplicate.input_artifact_ids = vec![first, first];
    assert_eq!(
        ActionRequest::new(
            &contract,
            duplicate,
            reuse_allowed(),
            NeedKey::new("locate.implementation").unwrap(),
            NeedId::new(Digest::blake3(b"root")),
        ),
        Err(ActionValidationError::RequestInputsNotCanonical)
    );
}
