use super::LifecycleError;
use crate::{
    ACTION_REQUEST_FORMAT_REVISION, ActionRequest, CanonicalHasher, Digest, MAX_NEED_IR_BYTES,
    NeedFragment,
};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

pub const LIFECYCLE_EXPLORE_ACTION_PLAN_FORMAT_REVISION: u16 = 1;
pub const MAX_LIFECYCLE_EXPLORE_ACTIONS: usize = 8;
pub const MAX_LIFECYCLE_EXPLORE_ACTION_PLAN_BYTES: usize = 48 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleExploreActionPlan {
    pub format_revision: u16,
    pub need_definition_digest: Digest,
    pub fragment: NeedFragment,
    #[serde(deserialize_with = "deserialize_bounded_actions")]
    pub actions: Vec<ActionRequest>,
    pub definition_digest: Digest,
}

fn deserialize_bounded_actions<'de, D>(deserializer: D) -> Result<Vec<ActionRequest>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedActionsVisitor;

    impl<'de> Visitor<'de> for BoundedActionsVisitor {
        type Value = Vec<ActionRequest>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_LIFECYCLE_EXPLORE_ACTIONS} lifecycle Explore actions")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let capacity = sequence.size_hint().unwrap_or(0).min(MAX_LIFECYCLE_EXPLORE_ACTIONS);
            let mut values = Vec::with_capacity(capacity);
            while let Some(value) = sequence.next_element()? {
                if values.len() == MAX_LIFECYCLE_EXPLORE_ACTIONS {
                    return Err(serde::de::Error::custom("too many lifecycle Explore actions"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(BoundedActionsVisitor)
}

impl LifecycleExploreActionPlan {
    pub fn new(
        fragment: NeedFragment,
        mut actions: Vec<ActionRequest>,
        need_definition_digest: Digest,
    ) -> Result<Self, LifecycleError> {
        actions.sort_by(|left, right| left.contract.cmp(&right.contract));
        let mut value = Self {
            format_revision: LIFECYCLE_EXPLORE_ACTION_PLAN_FORMAT_REVISION,
            need_definition_digest,
            fragment,
            actions,
            definition_digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.definition_digest = value.compute_definition_digest();
        value.validate_wire_bound()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), LifecycleError> {
        self.validate_shape()?;
        if self.definition_digest != self.compute_definition_digest() {
            return Err(LifecycleError::InvalidExploreActionPlan);
        }
        self.validate_wire_bound()
    }

    pub fn repository_id(&self) -> Digest {
        self.fragment.world.repository_lineage
    }

    pub fn source_snapshot(&self) -> Option<Digest> {
        self.actions.first().map(|action| action.artifact_request.source_snapshot_digest)
    }

    fn validate_shape(&self) -> Result<(), LifecycleError> {
        if self.format_revision != LIFECYCLE_EXPLORE_ACTION_PLAN_FORMAT_REVISION
            || self.need_definition_digest == Digest([0; 32])
            || !self.fragment.is_consistent()
            || self.fragment.obligations.is_empty()
            || self.actions.is_empty()
            || self.actions.len() > MAX_LIFECYCLE_EXPLORE_ACTIONS
            || !self.actions.windows(2).all(|pair| pair[0].contract < pair[1].contract)
        {
            return Err(LifecycleError::InvalidExploreActionPlan);
        }

        let repository = self.fragment.world.repository_lineage;
        let source = self.actions[0].artifact_request.source_snapshot_digest;
        let route = &self.actions[0].route;
        let normalized_request = &self.actions[0].artifact_request.normalized_request;
        let semantic_inputs = self
            .fragment
            .semantic_inputs
            .iter()
            .map(|artifact| artifact.digest())
            .collect::<Vec<_>>();
        if source == Digest([0; 32])
            || self.actions.iter().any(|action| {
                action.format_revision != ACTION_REQUEST_FORMAT_REVISION
                    || action.contract_semantic_definition_digest.is_none()
                    || action.contract_operational_policy_digest == Digest([0; 32])
                    || action.effective_dispatch_policy_digest == Digest([0; 32])
                    || action.root_need != self.fragment.root_need
                    || action.route != *route
                    || action.artifact_request.route_key != *route
                    || action.artifact_request.repository_id != repository
                    || action.artifact_request.source_snapshot_digest != source
                    || action.artifact_request.normalized_request != *normalized_request
                    || action.artifact_request.semantic_fragment_id != Some(self.fragment.id)
                    || action.artifact_request.input_artifact_ids != semantic_inputs
                    || action.artifact_request.normalized_request.is_empty()
                    || action.artifact_request.normalized_request.len() > MAX_NEED_IR_BYTES
            })
        {
            return Err(LifecycleError::InvalidExploreActionPlan);
        }
        Ok(())
    }

    fn validate_wire_bound(&self) -> Result<(), LifecycleError> {
        let bytes =
            serde_json::to_vec(self).map_err(|_| LifecycleError::InvalidExploreActionPlan)?;
        if bytes.len() > MAX_LIFECYCLE_EXPLORE_ACTION_PLAN_BYTES {
            return Err(LifecycleError::InvalidExploreActionPlan);
        }
        Ok(())
    }

    fn compute_definition_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"lifecycle-explore-action-plan-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.need_definition_digest);
        hasher.field_digest(self.fragment.id.digest());
        hasher.field_digest(self.fragment.root_need.digest());
        hasher.field_u16(self.actions.len() as u16);
        for action in &self.actions {
            hasher.field_str(action.contract.as_str());
            hasher.field_digest(action.semantic_id().digest());
            hasher.field_str(&action.artifact_request.contract_id);
            hasher.field_u32(action.artifact_request.contract_revision);
            hasher.field_digest(action.artifact_request.repository_id);
            hasher.field_digest(action.artifact_request.source_snapshot_digest);
            hasher.field_str(action.artifact_request.route_key.as_str());
            hasher.field_normalized_lines(&action.artifact_request.normalized_request);
            hasher.field_digest(
                action
                    .contract_semantic_definition_digest
                    .expect("validated lifecycle actions bind their semantic definition"),
            );
            hasher.field_digest(action.contract_operational_policy_digest);
            hasher.field_digest(action.dispatch_policy.digest());
            hasher.field_digest(action.effective_dispatch_policy_digest);
            hasher.field_str(action.route.as_str());
            hasher.field_digest(action.root_need.digest());
        }
        hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ActionContract, ActionContractId, ActionContractInput, ArtifactRequest, CompletionPolicy,
        DispatchPolicy, EffectClass, EvidencePolicy, Facet, Need, NeedId, NeedKey, Obligation,
        PersistencePolicy, PredicateKind, PriorArtifactPolicy, ReuseMode, SemanticWorld, Subject,
        SubjectKind, need_fragment,
    };

    fn fixture() -> LifecycleExploreActionPlan {
        let repository = Digest::blake3(b"core-lifecycle-plan-repository");
        let source = Digest::blake3(b"core-lifecycle-plan-source");
        let subject = Subject::exact(repository, SubjectKind::CliOption, "--plan");
        let required = vec![Obligation::new(
            PredicateKind::ImplementationLocation,
            subject.id,
            vec![Facet { key: "selection".to_owned(), value: "primary".to_owned() }],
        )];
        let body = "Locate the plan implementation.";
        let need = Need {
            id: NeedId::new(Digest::blake3(b"core-lifecycle-plan-need")),
            subjects: vec![subject],
            required,
            preferred: Vec::new(),
            semantic_constraints: Vec::new(),
            world: SemanticWorld {
                repository_lineage: repository,
                source_selector: "worktree".to_owned(),
                platform: "windows".to_owned(),
                features: "default".to_owned(),
                configuration: None,
                toolchain: None,
            },
            input_artifacts: Vec::new(),
            residual: None,
            body_digest: Digest::blake3(body.as_bytes()),
            format_revision: crate::NEED_IR_FORMAT_REVISION,
        };
        let fragment = need_fragment(&need, need.required.clone(), Vec::new());
        let policy = DispatchPolicy {
            completion: CompletionPolicy::ReuseAllowed,
            evidence: EvidencePolicy::Standard,
            prior_artifacts: PriorArtifactPolicy::ContractDefined,
            persistence: PersistencePolicy::Persistent,
        };
        let contract = ActionContract::new(ActionContractInput {
            id: ActionContractId::new("needle.test.lifecycle-plan").unwrap(),
            semantic_authority_source_digest: Digest::blake3(b"semantic"),
            validation_authority_source_digest: Digest::blake3(b"validation"),
            operational_authority_source_digest: Digest::blake3(b"operational"),
            effect_class: EffectClass::PureEvidence,
            reuse_modes: vec![ReuseMode::Exact],
            default_dispatch_policy: policy,
        })
        .unwrap();
        let route = NeedKey::new("locate.implementation").unwrap();
        let action = ActionRequest::new(
            &contract,
            ArtifactRequest {
                contract_id: "needle.semantic.code-location".to_owned(),
                contract_revision: 2,
                repository_id: repository,
                source_snapshot_digest: source,
                route_key: route.clone(),
                normalized_request: body.to_owned(),
                semantic_fragment_id: Some(fragment.id),
                input_artifact_ids: Vec::new(),
            },
            policy,
            route,
            fragment.root_need,
        )
        .unwrap();
        LifecycleExploreActionPlan::new(fragment, vec![action], need.definition_digest()).unwrap()
    }

    #[test]
    fn plan_is_canonical_and_digest_tamper_is_rejected() {
        let plan = fixture();
        plan.validate().unwrap();
        assert_eq!(
            serde_json::from_str::<LifecycleExploreActionPlan>(
                &serde_json::to_string(&plan).unwrap()
            )
            .unwrap(),
            plan
        );

        let mut tampered = plan;
        tampered.definition_digest = Digest::blake3(b"tampered");
        assert_eq!(tampered.validate(), Err(LifecycleError::InvalidExploreActionPlan));
    }

    #[test]
    fn deserialization_rejects_the_ninth_action_before_retaining_it() {
        let plan = fixture();
        let mut value = serde_json::to_value(&plan).unwrap();
        value["actions"] = serde_json::Value::Array(
            std::iter::repeat_n(serde_json::to_value(&plan.actions[0]).unwrap(), 9).collect(),
        );
        assert!(serde_json::from_value::<LifecycleExploreActionPlan>(value).is_err());
    }
}
