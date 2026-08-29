use crate::{active_definition_set, built_in_action_contracts, built_in_partition_for_action};
use needle_core::{
    ActionCapabilityClass, ActionCapabilityClassId, ActionCapabilityClassInput,
    ActionManifestProvenancePolicy, ActionSubjectAuthorityClass, ActionWorldPolicyClass,
    CapabilityMode, ManifestClosure, ReuseMode,
};
use std::sync::OnceLock;

pub fn implementation_location_exact_capability() -> &'static ActionCapabilityClass {
    static CAPABILITY: OnceLock<ActionCapabilityClass> = OnceLock::new();
    CAPABILITY.get_or_init(|| {
        let action = built_in_action_contracts()
            .iter()
            .find(|definition| definition.contract.id.as_str() == "needle.location.resolve")
            .expect("implementation-location action is registered");
        assert!(action.contract.reuse_modes.contains(ReuseMode::Exact));
        assert_eq!(action.initial_mode, CapabilityMode::Shadow);
        ActionCapabilityClass::new(ActionCapabilityClassInput {
            action_contract: action.contract.id.clone(),
            action_semantic_definition_digest: action.contract.semantic_definition_digest,
            action_validation_definition_digest: action.contract.validation_definition_digest,
            action_operational_policy_digest: action.contract.operational_policy_digest,
            effect_class: action.contract.effect_class,
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
            dispatch_policy: action.contract.default_dispatch_policy,
            definition_set_digest: active_definition_set().audit_digest,
            mode: CapabilityMode::Shadow,
        })
        .expect("implementation-location exact capability is canonical")
    })
}

pub(crate) fn authority_capability_for_id(
    id: ActionCapabilityClassId,
) -> Option<&'static ActionCapabilityClass> {
    let capability = implementation_location_exact_capability();
    (capability.id == id).then_some(capability)
}

pub fn test_target_inventory_refresh_capability() -> &'static ActionCapabilityClass {
    static CAPABILITY: OnceLock<ActionCapabilityClass> = OnceLock::new();
    CAPABILITY.get_or_init(|| {
        let action = built_in_action_contracts()
            .iter()
            .find(|definition| definition.contract.id.as_str() == "needle.tests.inventory")
            .expect("test-target inventory action is registered");
        assert!(action.contract.reuse_modes.contains(ReuseMode::Refresh));
        assert_eq!(action.initial_mode, CapabilityMode::Shadow);
        let partition = built_in_partition_for_action(&action.contract.id)
            .expect("test-target inventory partition definition is registered");
        partition.validate().expect("test-target partition definition is canonical");
        ActionCapabilityClass::new(ActionCapabilityClassInput {
            action_contract: action.contract.id.clone(),
            action_semantic_definition_digest: action.contract.semantic_definition_digest,
            action_validation_definition_digest: action.contract.validation_definition_digest,
            action_operational_policy_digest: action.contract.operational_policy_digest,
            effect_class: action.contract.effect_class,
            reuse_mode: ReuseMode::Refresh,
            subject_authority: ActionSubjectAuthorityClass::NotApplicable,
            world_policy: ActionWorldPolicyClass::Exact,
            partition_policy: Some(partition.policy.id.clone()),
            partition_policy_definition_digest: Some(partition.policy.definition_digest),
            partition_scheme: Some(partition.scheme.id.clone()),
            partition_scheme_definition_digest: Some(partition.scheme.definition_digest),
            partition_registry_definition_digest: Some(partition.definition_digest),
            manifest_provenance: ActionManifestProvenancePolicy::request_bound_and_derived(),
            manifest_closure: Some(ManifestClosure::Closed),
            dispatch_policy: action.contract.default_dispatch_policy,
            definition_set_digest: active_definition_set().audit_digest,
            mode: CapabilityMode::Shadow,
        })
        .expect("test-target refresh capability is canonical")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use needle_core::{ActionSubjectAuthorityClass, ActionWorldPolicyClass, Digest};

    #[test]
    fn implementation_location_exact_capability_is_narrow_and_shadow_only() {
        let capability = implementation_location_exact_capability();
        capability.validate().unwrap();
        assert_eq!(capability.action_contract.as_str(), "needle.location.resolve");
        assert_eq!(capability.reuse_mode, ReuseMode::Exact);
        assert_eq!(capability.mode, CapabilityMode::Shadow);
        assert_eq!(capability.subject_authority, ActionSubjectAuthorityClass::Exact);
        assert_eq!(capability.world_policy, ActionWorldPolicyClass::Exact);
        assert_eq!(capability.effect_class, needle_core::EffectClass::PureEvidence);
        assert!(capability.partition_policy.is_none());
        assert!(capability.partition_scheme.is_none());
        assert!(capability.manifest_closure.is_none());
        assert!(!capability.manifest_provenance.request_bound);
        assert!(!capability.manifest_provenance.producer_authored);
        assert!(!capability.manifest_provenance.provider_attested);
        assert!(!capability.manifest_provenance.derived);
        assert_eq!(capability.definition_set_digest, active_definition_set().audit_digest);
        assert_eq!(
            capability.definition_digest,
            Digest::parse("b3:225d6abd01fb5c532aa7bb7ae653e6ddb465d3a1ff65f302a705febf2c702f3d")
                .unwrap()
        );
    }

    #[test]
    fn test_target_refresh_capability_is_exact_action_native_and_shadow_only() {
        let capability = test_target_inventory_refresh_capability();
        capability.validate().unwrap();
        assert_eq!(capability.action_contract.as_str(), "needle.tests.inventory");
        assert_eq!(capability.reuse_mode, ReuseMode::Refresh);
        assert_eq!(capability.mode, CapabilityMode::Shadow);
        assert_eq!(capability.subject_authority, ActionSubjectAuthorityClass::NotApplicable);
        assert_eq!(capability.world_policy, ActionWorldPolicyClass::Exact);
        assert_eq!(
            capability.partition_policy.as_ref().unwrap().as_str(),
            "needle.tests.inventory.partition-policy"
        );
        assert_eq!(
            capability.partition_scheme.as_ref().unwrap().as_str(),
            "needle.tests.inventory.target"
        );
        assert_eq!(capability.manifest_closure, Some(ManifestClosure::Closed));
        assert!(capability.manifest_provenance.request_bound);
        assert!(capability.manifest_provenance.derived);
        assert!(!capability.manifest_provenance.provider_attested);
        assert_eq!(capability.definition_set_digest, active_definition_set().audit_digest);
    }

    #[test]
    fn test_target_refresh_capability_digest_is_stable() {
        assert_eq!(
            test_target_inventory_refresh_capability().definition_digest,
            Digest::parse("b3:e71fd0a40569d5adf4bf5f44a4b6b8e06bdba023328f61880ca07d6e34cbf90b")
                .unwrap()
        );
    }
}
