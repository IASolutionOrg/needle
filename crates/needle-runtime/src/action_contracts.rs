use crate::semantic_validation::validator_definition;
use needle_core::{
    ActionContract, ActionContractId, ActionContractInput, ArtifactContract, ArtifactKind,
    CacheScope, CanonicalHasher, CapabilityClass, CapabilityMode, CompletionPolicy, DispatchPolicy,
    EffectClass, EvidencePolicy, PersistencePolicy, PredicateContract, PredicateKind,
    PriorArtifactPolicy, ReuseMode, built_in_capability_classes, built_in_claim_capability_classes,
    built_in_predicate_contracts,
};
use std::sync::OnceLock;

pub const BUILT_IN_ACTION_COUNT: usize = 11;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuiltInActionCoverage {
    SemanticPredicate(PredicateContract),
    Partitioned { policy_definition_digest: needle_core::Digest },
    Opaque { semantic_definition_digest: needle_core::Digest },
}

impl BuiltInActionCoverage {
    pub fn predicate(&self) -> Option<PredicateKind> {
        match self {
            Self::SemanticPredicate(contract) => Some(contract.predicate),
            Self::Partitioned { .. } | Self::Opaque { .. } => None,
        }
    }

    pub fn definition_digest(&self) -> needle_core::Digest {
        match self {
            Self::SemanticPredicate(contract) => contract.definition_digest,
            Self::Partitioned { policy_definition_digest } => *policy_definition_digest,
            Self::Opaque { semantic_definition_digest } => *semantic_definition_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltInActionDefinition {
    pub contract: ActionContract,
    pub output_contract_id: &'static str,
    pub output_contract_revision: u32,
    pub output_schema_id: &'static str,
    pub artifact_kind: ArtifactKind,
    pub output_contract_definition_digest: needle_core::Digest,
    pub validator_definition_digest: needle_core::Digest,
    pub coverage: BuiltInActionCoverage,
    pub initial_mode: CapabilityMode,
}

impl BuiltInActionDefinition {
    pub fn artifact_kind(&self) -> &ArtifactKind {
        &self.artifact_kind
    }

    pub fn predicate(&self) -> Option<PredicateKind> {
        self.coverage.predicate()
    }
}

#[derive(Clone, Copy)]
struct BuiltInActionSeed {
    action_contract_id: &'static str,
    output_contract_id: &'static str,
    output_contract_revision: u32,
    output_schema_id: &'static str,
    artifact_kind: fn() -> ArtifactKind,
    predicate: Option<PredicateKind>,
    partition_policy_definition: Option<fn() -> needle_core::Digest>,
    opaque_semantic_definition: Option<fn() -> needle_core::Digest>,
    validator_definition: Option<fn() -> needle_core::Digest>,
    effect_class: EffectClass,
    reuse_modes: &'static [ReuseMode],
    default_dispatch_policy: DispatchPolicy,
}

const STANDARD_REUSE_MODES: &[ReuseMode] =
    &[ReuseMode::Exact, ReuseMode::Project, ReuseMode::Assemble];
const PARTITION_REFRESH_REUSE_MODES: &[ReuseMode] =
    &[ReuseMode::Exact, ReuseMode::Project, ReuseMode::Assemble, ReuseMode::Refresh];
const EXACT_PROJECT_REUSE_MODES: &[ReuseMode] = &[ReuseMode::Exact, ReuseMode::Project];
const EXECUTION_REUSE_MODES: &[ReuseMode] = &[ReuseMode::Exact, ReuseMode::Assemble];
const EXACT_REUSE_MODE: &[ReuseMode] = &[ReuseMode::Exact];
const NEVER_REUSE_MODE: &[ReuseMode] = &[ReuseMode::Never];

const STANDARD_DISPATCH: DispatchPolicy = DispatchPolicy {
    completion: CompletionPolicy::ReuseAllowed,
    evidence: EvidencePolicy::Standard,
    prior_artifacts: PriorArtifactPolicy::ContractDefined,
    persistence: PersistencePolicy::Persistent,
};
const FRESH_ADVISORY_DISPATCH: DispatchPolicy = DispatchPolicy {
    completion: CompletionPolicy::FreshRequired,
    evidence: EvidencePolicy::Standard,
    prior_artifacts: PriorArtifactPolicy::AdvisoryOnly,
    persistence: PersistencePolicy::Persistent,
};
const FRESH_INDEPENDENT_DISPATCH: DispatchPolicy = DispatchPolicy {
    completion: CompletionPolicy::FreshRequired,
    evidence: EvidencePolicy::IndependentEvidenceRequired,
    prior_artifacts: PriorArtifactPolicy::ContractDefined,
    persistence: PersistencePolicy::Persistent,
};
const FRESH_EFFECT_DISPATCH: DispatchPolicy = DispatchPolicy {
    completion: CompletionPolicy::FreshRequired,
    evidence: EvidencePolicy::Standard,
    prior_artifacts: PriorArtifactPolicy::Forbidden,
    persistence: PersistencePolicy::Persistent,
};

const BUILT_IN_ACTION_SEEDS: [BuiltInActionSeed; BUILT_IN_ACTION_COUNT] = [
    BuiltInActionSeed {
        action_contract_id: "needle.location.resolve",
        output_contract_id: "needle.semantic.code-location",
        output_contract_revision: 2,
        output_schema_id: needle_core::SEMANTIC_ARTIFACT_RESULT_SCHEMA_ID,
        artifact_kind: ArtifactKind::code_location,
        predicate: Some(PredicateKind::ImplementationLocation),
        partition_policy_definition: None,
        opaque_semantic_definition: None,
        validator_definition: None,
        effect_class: EffectClass::PureEvidence,
        reuse_modes: STANDARD_REUSE_MODES,
        default_dispatch_policy: STANDARD_DISPATCH,
    },
    BuiltInActionSeed {
        action_contract_id: "needle.flow.trace",
        output_contract_id: "needle.semantic.behavior-trace",
        output_contract_revision: 2,
        output_schema_id: needle_core::SEMANTIC_ARTIFACT_RESULT_SCHEMA_ID,
        artifact_kind: ArtifactKind::behavior_trace,
        predicate: Some(PredicateKind::RuntimeFlow),
        partition_policy_definition: None,
        opaque_semantic_definition: None,
        validator_definition: None,
        effect_class: EffectClass::PureEvidence,
        reuse_modes: STANDARD_REUSE_MODES,
        default_dispatch_policy: STANDARD_DISPATCH,
    },
    BuiltInActionSeed {
        action_contract_id: "needle.tests.plan",
        output_contract_id: "needle.semantic.test-plan",
        output_contract_revision: 2,
        output_schema_id: needle_core::SEMANTIC_ARTIFACT_RESULT_SCHEMA_ID,
        artifact_kind: ArtifactKind::test_plan,
        predicate: Some(PredicateKind::FocusedTests),
        partition_policy_definition: None,
        opaque_semantic_definition: None,
        validator_definition: None,
        effect_class: EffectClass::PureEvidence,
        reuse_modes: STANDARD_REUSE_MODES,
        default_dispatch_policy: STANDARD_DISPATCH,
    },
    BuiltInActionSeed {
        action_contract_id: "needle.tests.inventory",
        output_contract_id: needle_core::TEST_TARGET_INVENTORY_OUTPUT_CONTRACT_ID,
        output_contract_revision: needle_core::TEST_TARGET_INVENTORY_OUTPUT_CONTRACT_REVISION,
        output_schema_id: needle_core::TEST_TARGET_INVENTORY_SCHEMA_ID,
        artifact_kind: ArtifactKind::test_target_inventory,
        predicate: None,
        partition_policy_definition: Some(crate::test_target_inventory_partition_policy_definition),
        opaque_semantic_definition: None,
        validator_definition: Some(crate::test_target_inventory_validator_definition),
        effect_class: EffectClass::PureEvidence,
        reuse_modes: PARTITION_REFRESH_REUSE_MODES,
        default_dispatch_policy: STANDARD_DISPATCH,
    },
    BuiltInActionSeed {
        action_contract_id: "needle.architecture.describe",
        output_contract_id: needle_core::ARCHITECTURE_BRIEF_OUTPUT_CONTRACT_ID,
        output_contract_revision: needle_core::ARCHITECTURE_BRIEF_OUTPUT_CONTRACT_REVISION,
        output_schema_id: needle_core::ARCHITECTURE_BRIEF_SCHEMA_ID,
        artifact_kind: ArtifactKind::architecture_brief,
        predicate: None,
        partition_policy_definition: Some(crate::architecture_brief_partition_policy_definition),
        opaque_semantic_definition: None,
        validator_definition: Some(crate::architecture_brief_validator_definition),
        effect_class: EffectClass::DerivedAnalysis,
        reuse_modes: STANDARD_REUSE_MODES,
        default_dispatch_policy: STANDARD_DISPATCH,
    },
    BuiltInActionSeed {
        action_contract_id: "needle.change.impact",
        output_contract_id: needle_core::CHANGE_IMPACT_OUTPUT_CONTRACT_ID,
        output_contract_revision: needle_core::CHANGE_IMPACT_OUTPUT_CONTRACT_REVISION,
        output_schema_id: needle_core::CHANGE_IMPACT_SCHEMA_ID,
        artifact_kind: ArtifactKind::change_impact,
        predicate: None,
        partition_policy_definition: Some(crate::change_impact_partition_policy_definition),
        opaque_semantic_definition: None,
        validator_definition: Some(crate::change_impact_validator_definition),
        effect_class: EffectClass::DerivedAnalysis,
        reuse_modes: STANDARD_REUSE_MODES,
        default_dispatch_policy: STANDARD_DISPATCH,
    },
    BuiltInActionSeed {
        action_contract_id: needle_core::PATCH_PROPOSE_ACTION_CONTRACT,
        output_contract_id: needle_core::PATCH_PROPOSAL_OUTPUT_CONTRACT_ID,
        output_contract_revision: needle_core::PATCH_PROPOSAL_OUTPUT_CONTRACT_REVISION,
        output_schema_id: needle_core::PATCH_PROPOSAL_SCHEMA_ID,
        artifact_kind: ArtifactKind::patch_proposal,
        predicate: None,
        partition_policy_definition: None,
        opaque_semantic_definition: Some(needle_core::patch_proposal_semantic_definition),
        validator_definition: Some(needle_core::patch_proposal_validator_definition),
        effect_class: EffectClass::TransformProposal,
        reuse_modes: EXACT_PROJECT_REUSE_MODES,
        default_dispatch_policy: STANDARD_DISPATCH,
    },
    BuiltInActionSeed {
        action_contract_id: needle_core::TESTS_EXECUTE_ACTION_CONTRACT,
        output_contract_id: needle_core::TEST_EXECUTION_OUTPUT_CONTRACT_ID,
        output_contract_revision: needle_core::TEST_EXECUTION_OUTPUT_CONTRACT_REVISION,
        output_schema_id: needle_core::TEST_EXECUTION_EVIDENCE_SCHEMA_ID,
        artifact_kind: ArtifactKind::test_execution,
        predicate: None,
        partition_policy_definition: None,
        opaque_semantic_definition: Some(needle_core::test_execution_semantic_definition),
        validator_definition: Some(needle_core::test_execution_validator_definition),
        effect_class: EffectClass::ExecutionEvidence,
        reuse_modes: EXECUTION_REUSE_MODES,
        default_dispatch_policy: FRESH_ADVISORY_DISPATCH,
    },
    BuiltInActionSeed {
        action_contract_id: needle_core::REVIEW_DIFF_ACTION_CONTRACT,
        output_contract_id: needle_core::REVIEW_REPORT_OUTPUT_CONTRACT_ID,
        output_contract_revision: needle_core::REVIEW_REPORT_OUTPUT_CONTRACT_REVISION,
        output_schema_id: needle_core::REVIEW_REPORT_SCHEMA_ID,
        artifact_kind: ArtifactKind::review_report,
        predicate: None,
        partition_policy_definition: Some(needle_core::review_partition_policy_definition),
        opaque_semantic_definition: None,
        validator_definition: Some(needle_core::review_report_validator_definition),
        effect_class: EffectClass::DerivedAnalysis,
        reuse_modes: PARTITION_REFRESH_REUSE_MODES,
        default_dispatch_policy: FRESH_ADVISORY_DISPATCH,
    },
    BuiltInActionSeed {
        action_contract_id: needle_core::PATCH_VERIFY_ACTION_CONTRACT,
        output_contract_id: needle_core::PATCH_VERIFICATION_OUTPUT_CONTRACT_ID,
        output_contract_revision: needle_core::PATCH_VERIFICATION_OUTPUT_CONTRACT_REVISION,
        output_schema_id: needle_core::PATCH_VERIFICATION_SCHEMA_ID,
        artifact_kind: ArtifactKind::patch_verification,
        predicate: None,
        partition_policy_definition: None,
        opaque_semantic_definition: Some(needle_core::patch_verification_semantic_definition),
        validator_definition: Some(needle_core::patch_verification_validator_definition),
        effect_class: EffectClass::DerivedAnalysis,
        reuse_modes: EXACT_REUSE_MODE,
        default_dispatch_policy: FRESH_INDEPENDENT_DISPATCH,
    },
    BuiltInActionSeed {
        action_contract_id: needle_core::PATCH_APPLY_ACTION_CONTRACT,
        output_contract_id: needle_core::APPLY_RECEIPT_OUTPUT_CONTRACT_ID,
        output_contract_revision: needle_core::APPLY_RECEIPT_OUTPUT_CONTRACT_REVISION,
        output_schema_id: needle_core::APPLY_RECEIPT_SCHEMA_ID,
        artifact_kind: ArtifactKind::apply_receipt,
        predicate: None,
        partition_policy_definition: None,
        opaque_semantic_definition: Some(needle_core::apply_receipt_semantic_definition),
        validator_definition: Some(needle_core::apply_receipt_validator_definition),
        effect_class: EffectClass::ExternalEffect,
        reuse_modes: NEVER_REUSE_MODE,
        default_dispatch_policy: FRESH_EFFECT_DISPATCH,
    },
];

pub fn built_in_action_contracts() -> &'static [BuiltInActionDefinition; BUILT_IN_ACTION_COUNT] {
    static DEFINITIONS: OnceLock<[BuiltInActionDefinition; BUILT_IN_ACTION_COUNT]> =
        OnceLock::new();
    DEFINITIONS.get_or_init(|| {
        let predicates = built_in_predicate_contracts();
        let artifact_capabilities = built_in_capability_classes();
        let claim_capabilities = built_in_claim_capability_classes();
        BUILT_IN_ACTION_SEEDS.map(|seed| {
            build_definition(seed, &predicates, &artifact_capabilities, &claim_capabilities)
        })
    })
}

pub fn built_in_action_for_predicate(predicate: PredicateKind) -> &'static BuiltInActionDefinition {
    &built_in_action_contracts()[match predicate {
        PredicateKind::ImplementationLocation => 0,
        PredicateKind::RuntimeFlow => 1,
        PredicateKind::FocusedTests => 2,
    }]
}

pub fn built_in_action_for_artifact_kind(
    kind: &ArtifactKind,
) -> Option<&'static BuiltInActionDefinition> {
    let index = match kind.0.as_str() {
        "code-location" => 0,
        "behavior-trace" => 1,
        "test-plan" => 2,
        "test-target-inventory" => 3,
        "architecture-brief" => 4,
        "change-impact" => 5,
        "patch-proposal" => 6,
        "test-execution" => 7,
        "review-report" => 8,
        "patch-verification" => 9,
        "apply-receipt" => 10,
        _ => return None,
    };
    Some(&built_in_action_contracts()[index])
}

fn build_definition(
    seed: BuiltInActionSeed,
    predicates: &[PredicateContract],
    artifact_capabilities: &[CapabilityClass],
    claim_capabilities: &[CapabilityClass],
) -> BuiltInActionDefinition {
    let artifact_kind = (seed.artifact_kind)();
    let output_contract_definition_digest = ArtifactContract::semantic_with_schema(
        seed.output_contract_id,
        seed.output_contract_revision,
        artifact_kind.clone(),
        seed.output_schema_id,
        CacheScope::SnapshotExact,
    )
    .definition_digest;
    let coverage =
        match (seed.predicate, seed.partition_policy_definition, seed.opaque_semantic_definition) {
            (Some(predicate), None, None) => BuiltInActionCoverage::SemanticPredicate(
                predicates
                    .iter()
                    .find(|contract| contract.predicate == predicate)
                    .expect("every built-in action predicate has a predicate contract")
                    .clone(),
            ),
            (None, Some(definition), None) => {
                BuiltInActionCoverage::Partitioned { policy_definition_digest: definition() }
            }
            (None, None, Some(definition)) => {
                BuiltInActionCoverage::Opaque { semantic_definition_digest: definition() }
            }
            _ => panic!("built-in action coverage seed is invalid"),
        };
    let validator_definition_digest = seed
        .validator_definition
        .map_or_else(|| validator_definition(&artifact_kind), |definition| definition());
    let initial_mode = CapabilityMode::Shadow;

    let mut semantic_source = CanonicalHasher::new(b"built-in-action-semantic-authority-v1");
    semantic_source.field_digest(output_contract_definition_digest);
    semantic_source.field_digest(coverage.definition_digest());

    let mut validation_source = CanonicalHasher::new(b"built-in-action-validation-authority-v1");
    validation_source.field_digest(validator_definition_digest);
    if let Some(predicate) = seed.predicate {
        let artifact_capability = capability_for(predicate, artifact_capabilities, "artifact");
        let claim_capability = capability_for(predicate, claim_capabilities, "claim");
        assert_eq!(artifact_capability.mode, CapabilityMode::Shadow);
        assert_eq!(claim_capability.mode, CapabilityMode::Shadow);
        validation_source.field_digest(artifact_capability.definition_digest);
        validation_source.field_digest(claim_capability.definition_digest);
    } else {
        validation_source.field_digest(coverage.definition_digest());
    }

    let mut operational_source = CanonicalHasher::new(b"built-in-action-operational-authority-v1");
    operational_source.field_u8(capability_mode_tag(initial_mode));

    let contract = ActionContract::new(ActionContractInput {
        id: ActionContractId::new(seed.action_contract_id)
            .expect("built-in action contract ids are valid"),
        semantic_authority_source_digest: semantic_source.finish(),
        validation_authority_source_digest: validation_source.finish(),
        operational_authority_source_digest: operational_source.finish(),
        effect_class: seed.effect_class,
        reuse_modes: seed.reuse_modes.to_vec(),
        default_dispatch_policy: seed.default_dispatch_policy,
    })
    .expect("built-in action contracts are valid");

    BuiltInActionDefinition {
        contract,
        output_contract_id: seed.output_contract_id,
        output_contract_revision: seed.output_contract_revision,
        output_schema_id: seed.output_schema_id,
        artifact_kind,
        output_contract_definition_digest,
        validator_definition_digest,
        coverage,
        initial_mode,
    }
}

fn capability_for<'a>(
    predicate: PredicateKind,
    capabilities: &'a [CapabilityClass],
    reuse_unit: &str,
) -> &'a CapabilityClass {
    capabilities
        .iter()
        .find(|capability| capability.predicate == predicate)
        .unwrap_or_else(|| panic!("built-in {reuse_unit} capability is missing for {predicate:?}"))
}

const fn capability_mode_tag(mode: CapabilityMode) -> u8 {
    match mode {
        CapabilityMode::Disabled => 0,
        CapabilityMode::Shadow => 1,
        CapabilityMode::Advisory => 2,
        CapabilityMode::Authoritative => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use needle_core::{Digest, SubjectKind};
    use std::collections::BTreeSet;

    #[test]
    fn catalog_is_complete_bijective_and_shadow_only() {
        let definitions = built_in_action_contracts();
        assert_eq!(definitions.len(), BUILT_IN_ACTION_COUNT);
        assert_eq!(
            definitions
                .iter()
                .map(|definition| definition.contract.id.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            BUILT_IN_ACTION_COUNT
        );

        for (definition, seed) in definitions.iter().zip(BUILT_IN_ACTION_SEEDS) {
            assert_eq!(definition.contract.id.as_str(), seed.action_contract_id);
            assert_eq!(definition.output_contract_id, seed.output_contract_id);
            assert_eq!(definition.output_contract_revision, seed.output_contract_revision);
            assert_eq!(definition.artifact_kind(), &(seed.artifact_kind)());
            for scope in [CacheScope::SnapshotExact, CacheScope::WorktreeSemantic] {
                assert_eq!(
                    definition.output_contract_definition_digest,
                    ArtifactContract::semantic_with_schema(
                        seed.output_contract_id,
                        seed.output_contract_revision,
                        (seed.artifact_kind)(),
                        seed.output_schema_id,
                        scope,
                    )
                    .definition_digest
                );
            }
            assert_eq!(definition.predicate(), seed.predicate);
            assert_eq!(definition.initial_mode, CapabilityMode::Shadow);
            assert_eq!(definition.contract.effect_class, seed.effect_class);
            for mode in [
                ReuseMode::Exact,
                ReuseMode::Project,
                ReuseMode::Assemble,
                ReuseMode::Refresh,
                ReuseMode::Never,
            ] {
                assert_eq!(
                    definition.contract.reuse_modes.contains(mode),
                    seed.reuse_modes.contains(&mode),
                    "{} has unexpected {mode:?} policy",
                    seed.action_contract_id
                );
            }
            assert_eq!(definition.contract.default_dispatch_policy, seed.default_dispatch_policy);
            assert!(definition.contract.is_canonical());
            if let Some(predicate) = seed.predicate {
                let BuiltInActionCoverage::SemanticPredicate(predicate_contract) =
                    &definition.coverage
                else {
                    panic!("semantic action must retain predicate coverage");
                };
                assert_eq!(
                    predicate_contract.allowed_subject_kinds,
                    vec![
                        SubjectKind::Symbol,
                        SubjectKind::CliOption,
                        SubjectKind::ConfigurationKey,
                        SubjectKind::Test,
                        SubjectKind::File,
                        SubjectKind::Module,
                        SubjectKind::Behavior,
                    ]
                );
                assert!(std::ptr::eq(definition, built_in_action_for_predicate(predicate)));
            } else if seed.partition_policy_definition.is_some() {
                assert!(matches!(definition.coverage, BuiltInActionCoverage::Partitioned { .. }));
            } else {
                assert!(matches!(definition.coverage, BuiltInActionCoverage::Opaque { .. }));
            }
            assert!(std::ptr::eq(
                definition,
                built_in_action_for_artifact_kind(&(seed.artifact_kind)()).unwrap()
            ));
        }
        assert!(built_in_action_for_artifact_kind(&ArtifactKind::evidence_brief()).is_none());
        assert_eq!(
            built_in_action_for_artifact_kind(&ArtifactKind::architecture_brief())
                .unwrap()
                .contract
                .effect_class,
            EffectClass::DerivedAnalysis
        );
        assert_eq!(
            built_in_action_for_artifact_kind(&ArtifactKind::change_impact())
                .unwrap()
                .contract
                .effect_class,
            EffectClass::DerivedAnalysis
        );
    }

    #[test]
    fn definition_digests_are_stable() {
        assert_eq!(
            built_in_action_contracts()
                .iter()
                .map(|definition| definition.contract.definition_digest)
                .collect::<Vec<_>>(),
            vec![
                Digest::parse(
                    "b3:f696ca681e358296d189b1aa7818a305a114a06380e4e1c465c8ce6bc8ef3d74",
                )
                .unwrap(),
                Digest::parse(
                    "b3:acb59f060e0f34453a1c78f5ba05ceac601db2d87717094d1580c16ed34c3762",
                )
                .unwrap(),
                Digest::parse(
                    "b3:d6cefdc6740b0b02d96324c5fc514fa2f3fe9cc1001446c2e4cbfa23a527c16f",
                )
                .unwrap(),
                Digest::parse(
                    "b3:6e67036e6b2a5a78bae67fa0bce34488f2c00058ee0c8745689a68e06362b380",
                )
                .unwrap(),
                Digest::parse(
                    "b3:e24e23a6c38abc215426e2c43f4700ac2266525d124de3f6e09005ae9685e1b7",
                )
                .unwrap(),
                Digest::parse(
                    "b3:43b6b15b4ccaaaaa7c9930c35f76e89607802a6dcb2ae27e4f9cb448e89693a3",
                )
                .unwrap(),
                Digest::parse(
                    "b3:810d64634e510b8de30bd4958fd4ceb2694719afd3522f77d449cd6f2d92d500",
                )
                .unwrap(),
                Digest::parse(
                    "b3:d8d751aad63c51b488792e6dd4452bbb5b5ad6e65c459814c8b7bf51708c82d0",
                )
                .unwrap(),
                Digest::parse(
                    "b3:2e42f7682f09dbaf75f24b93866ea589e136ef3ab459994e3a19457305eafc95",
                )
                .unwrap(),
                Digest::parse(
                    "b3:57f63d1aee2315f8e8dbb0d0ccb596929ff5885871e25f01adcef5718cd7e0c0",
                )
                .unwrap(),
                Digest::parse(
                    "b3:7cddb5a0b9e47a9d3fc1cde757ebfed5403eed009fb1325604fe93ce9d69e2ae",
                )
                .unwrap(),
            ]
        );
    }
}
