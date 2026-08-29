use super::*;
use crate::{
    ActionCapabilityClassInput, ActionContractId, ActionManifestProvenancePolicy,
    ActionSubjectAuthorityClass, ActionWorldPolicyClass, CompletionPolicy, DispatchPolicy,
    EffectClass, EvidencePolicy, PersistencePolicy, PriorArtifactPolicy, ReuseMode,
};

fn digest(label: &str) -> Digest {
    Digest::blake3(label.as_bytes())
}

fn capability() -> ActionCapabilityClass {
    ActionCapabilityClass::new(ActionCapabilityClassInput {
        action_contract: ActionContractId::new("needle.location.resolve").unwrap(),
        action_semantic_definition_digest: digest("semantic"),
        action_validation_definition_digest: digest("validation"),
        action_operational_policy_digest: digest("operational"),
        effect_class: EffectClass::PureEvidence,
        reuse_mode: ReuseMode::Exact,
        subject_authority: ActionSubjectAuthorityClass::Exact,
        world_policy: ActionWorldPolicyClass::Exact,
        partition_policy: None,
        partition_policy_definition_digest: None,
        partition_scheme: None,
        partition_scheme_definition_digest: None,
        partition_registry_definition_digest: None,
        manifest_provenance: ActionManifestProvenancePolicy {
            request_bound: false,
            producer_authored: false,
            provider_attested: false,
            derived: false,
        },
        manifest_closure: None,
        dispatch_policy: DispatchPolicy {
            completion: CompletionPolicy::ReuseAllowed,
            evidence: EvidencePolicy::Standard,
            prior_artifacts: PriorArtifactPolicy::ContractDefined,
            persistence: PersistencePolicy::Persistent,
        },
        definition_set_digest: digest("definition-set"),
        mode: CapabilityMode::Shadow,
    })
    .unwrap()
}

fn evidence(capability: &ActionCapabilityClass) -> ActionAssuranceEvidence {
    ActionAssuranceEvidence::new(ActionAssuranceEvidenceInput {
        capability_class: capability.id,
        capability_definition_digest: capability.definition_digest,
        action_request: ArtifactRequestId::new(digest("request")),
        artifact: ArtifactId::new(digest("artifact")),
        validation_certificate: ArtifactValidationCertificateId::new(digest("certificate")),
        repository: digest("repository"),
        source_snapshot: digest("source"),
        lifecycle: LifecycleId(digest("lifecycle")),
        adapter_invocation: digest("adapter-invocation"),
        evidence_kind: ActionAssuranceEvidenceKind::ProviderBackedFresh,
        execution_evidence_digest: digest("live-report"),
        observed_unix_ms: 10,
    })
    .unwrap()
}

#[test]
fn evidence_is_canonical_bounded_and_capability_bound() {
    let capability = capability();
    let evidence = evidence(&capability);
    evidence.validate_for(&capability).unwrap();
    let bytes = serde_json::to_vec(&evidence).unwrap();
    assert_eq!(ActionAssuranceEvidence::decode_json(&bytes).unwrap(), evidence);

    let mut tampered = evidence.clone();
    tampered.source_snapshot = digest("other-source");
    assert_eq!(tampered.validate(), Err(ActionAssuranceError::DefinitionDigest));

    let mut other = capability.clone();
    other.definition_digest = digest("other-capability");
    assert!(matches!(evidence.validate_for(&other), Err(ActionAssuranceError::Capability(_))));

    let oversized = vec![b' '; MAX_ACTION_ASSURANCE_WIRE_BYTES + 1];
    assert!(matches!(
        ActionAssuranceEvidence::decode_json(&oversized),
        Err(ActionAssuranceError::WireBound { .. })
    ));
}

#[test]
fn authoritative_decision_is_explicit_staged_and_reversible() {
    let capability = capability();
    let evidence = evidence(&capability);
    let authoritative = ActionCapabilityDecision::new(ActionCapabilityDecisionInput {
        capability_class: capability.id,
        capability_definition_digest: capability.definition_digest,
        evidence: evidence.id,
        evidence_definition_digest: evidence.definition_digest,
        previous_decision: None,
        selected_mode: CapabilityMode::Authoritative,
        automatic_resolver_consumption_approved: true,
        automatic_lifecycle_consumption_approved: false,
        decider_id: "local-operator".to_owned(),
        decided_unix_ms: 20,
    })
    .unwrap();
    authoritative.validate_for(&capability, &evidence).unwrap();

    let demotion = ActionCapabilityDecision::new(ActionCapabilityDecisionInput {
        capability_class: capability.id,
        capability_definition_digest: capability.definition_digest,
        evidence: evidence.id,
        evidence_definition_digest: evidence.definition_digest,
        previous_decision: Some(authoritative.id),
        selected_mode: CapabilityMode::Shadow,
        automatic_resolver_consumption_approved: false,
        automatic_lifecycle_consumption_approved: false,
        decider_id: "local-operator".to_owned(),
        decided_unix_ms: 21,
    })
    .unwrap();
    demotion.validate_for(&capability, &evidence).unwrap();
    assert_ne!(authoritative.id, demotion.id);
}

#[test]
fn decision_rejects_implicit_or_unbound_authority() {
    let capability = capability();
    let evidence = evidence(&capability);
    let lifecycle_without_resolver = ActionCapabilityDecision::new(ActionCapabilityDecisionInput {
        capability_class: capability.id,
        capability_definition_digest: capability.definition_digest,
        evidence: evidence.id,
        evidence_definition_digest: evidence.definition_digest,
        previous_decision: None,
        selected_mode: CapabilityMode::Authoritative,
        automatic_resolver_consumption_approved: false,
        automatic_lifecycle_consumption_approved: true,
        decider_id: "local-operator".to_owned(),
        decided_unix_ms: 20,
    });
    assert_eq!(lifecycle_without_resolver, Err(ActionAssuranceError::DecisionShape));

    let shadow_with_consumption = ActionCapabilityDecision::new(ActionCapabilityDecisionInput {
        capability_class: capability.id,
        capability_definition_digest: capability.definition_digest,
        evidence: evidence.id,
        evidence_definition_digest: evidence.definition_digest,
        previous_decision: None,
        selected_mode: CapabilityMode::Shadow,
        automatic_resolver_consumption_approved: true,
        automatic_lifecycle_consumption_approved: false,
        decider_id: "local-operator".to_owned(),
        decided_unix_ms: 20,
    });
    assert_eq!(shadow_with_consumption, Err(ActionAssuranceError::DecisionShape));

    let mut late_evidence = evidence.clone();
    late_evidence.observed_unix_ms = 30;
    late_evidence.definition_digest = late_evidence.compute_definition_digest();
    late_evidence.id = evidence_id(late_evidence.definition_digest);
    let decision = ActionCapabilityDecision::new(ActionCapabilityDecisionInput {
        capability_class: capability.id,
        capability_definition_digest: capability.definition_digest,
        evidence: late_evidence.id,
        evidence_definition_digest: late_evidence.definition_digest,
        previous_decision: None,
        selected_mode: CapabilityMode::Authoritative,
        automatic_resolver_consumption_approved: true,
        automatic_lifecycle_consumption_approved: false,
        decider_id: "local-operator".to_owned(),
        decided_unix_ms: 20,
    })
    .unwrap();
    assert_eq!(
        decision.validate_for(&capability, &late_evidence),
        Err(ActionAssuranceError::DecisionBinding)
    );
}

#[test]
fn decision_round_trip_rejects_tamper_and_oversized_wire() {
    let capability = capability();
    let evidence = evidence(&capability);
    let decision = ActionCapabilityDecision::new(ActionCapabilityDecisionInput {
        capability_class: capability.id,
        capability_definition_digest: capability.definition_digest,
        evidence: evidence.id,
        evidence_definition_digest: evidence.definition_digest,
        previous_decision: None,
        selected_mode: CapabilityMode::Authoritative,
        automatic_resolver_consumption_approved: true,
        automatic_lifecycle_consumption_approved: true,
        decider_id: "local-operator".to_owned(),
        decided_unix_ms: 20,
    })
    .unwrap();
    let bytes = serde_json::to_vec(&decision).unwrap();
    assert_eq!(ActionCapabilityDecision::decode_json(&bytes).unwrap(), decision);

    let mut tampered = decision;
    tampered.automatic_lifecycle_consumption_approved = false;
    assert_eq!(tampered.validate(), Err(ActionAssuranceError::DefinitionDigest));

    let oversized = vec![b' '; MAX_ACTION_CAPABILITY_DECISION_WIRE_BYTES + 1];
    assert!(matches!(
        ActionCapabilityDecision::decode_json(&oversized),
        Err(ActionAssuranceError::WireBound { .. })
    ));
}
