use crate::{
    LifecycleChangeContext, ShadowActionResolutionAuthority, ShadowActionResolutionKind,
    ShadowActionResolutionSummary, built_in_action_contracts,
    validate_lifecycle_explore_action_plan,
};
use needle_core::{
    CanonicalHasher, Digest, LifecycleExploreActionPlan, LifecycleId, MAX_LIFECYCLE_EXPLORE_ACTIONS,
};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use thiserror::Error;

pub const LIFECYCLE_EXPLORE_SHADOW_OBSERVATION_FORMAT_REVISION: u16 = 1;
pub const MAX_LIFECYCLE_EXPLORE_SHADOW_OBSERVATION_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleExploreShadowResolutionKind {
    Unavailable,
    Miss,
    Partial,
    Resolved,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleExploreShadowObservationPersistence {
    Stored,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleExploreActionResolverOutcome {
    Unavailable,
    Miss,
    Resolved(Vec<ShadowActionResolutionSummary>),
    Invalid,
}

/// Supplies non-authoritative action-resolution evidence for Explore.
///
/// Implementations cannot mutate lifecycle state through this interface. The
/// kernel records the projection as Shadow and still invokes the phase adapter.
pub trait LifecycleExploreActionResolver {
    fn resolve(
        &self,
        plan: &LifecycleExploreActionPlan,
        change: &LifecycleChangeContext,
    ) -> LifecycleExploreActionResolverOutcome;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopLifecycleExploreActionResolver;

impl LifecycleExploreActionResolver for NoopLifecycleExploreActionResolver {
    fn resolve(
        &self,
        _plan: &LifecycleExploreActionPlan,
        _change: &LifecycleChangeContext,
    ) -> LifecycleExploreActionResolverOutcome {
        LifecycleExploreActionResolverOutcome::Unavailable
    }
}

pub(crate) static NOOP_LIFECYCLE_EXPLORE_ACTION_RESOLVER: NoopLifecycleExploreActionResolver =
    NoopLifecycleExploreActionResolver;

/// Immutable observation emitted by the Explore preflight.
///
/// `authority` is permanently Shadow and `adapter_invocation_required` is
/// permanently true in this format revision. It is diagnostic output, not a
/// lifecycle transition or a cache decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleExploreShadowObservation {
    pub format_revision: u16,
    pub lifecycle: LifecycleId,
    pub expected_state_digest: Digest,
    pub plan_definition_digest: Digest,
    pub planned_action_count: u16,
    pub resolution: LifecycleExploreShadowResolutionKind,
    #[serde(deserialize_with = "deserialize_bounded_summaries")]
    pub actions: Vec<ShadowActionResolutionSummary>,
    pub authority: ShadowActionResolutionAuthority,
    pub adapter_invocation_required: bool,
    pub definition_digest: Digest,
}

impl LifecycleExploreShadowObservation {
    pub fn from_resolver_outcome(
        lifecycle: LifecycleId,
        expected_state_digest: Digest,
        plan: &LifecycleExploreActionPlan,
        outcome: LifecycleExploreActionResolverOutcome,
    ) -> Self {
        let planned_action_count = plan.actions.len() as u16;
        let (resolution, actions) = match outcome {
            LifecycleExploreActionResolverOutcome::Unavailable => {
                (LifecycleExploreShadowResolutionKind::Unavailable, Vec::new())
            }
            LifecycleExploreActionResolverOutcome::Miss => {
                (LifecycleExploreShadowResolutionKind::Miss, Vec::new())
            }
            LifecycleExploreActionResolverOutcome::Invalid => {
                (LifecycleExploreShadowResolutionKind::Invalid, Vec::new())
            }
            LifecycleExploreActionResolverOutcome::Resolved(mut actions) => {
                if actions.len() > plan.actions.len()
                    || actions.len() > MAX_LIFECYCLE_EXPLORE_ACTIONS
                {
                    return Self::invalid(
                        lifecycle,
                        expected_state_digest,
                        plan.definition_digest,
                        planned_action_count,
                    );
                }
                actions.sort_by(|left, right| left.action_contract.cmp(&right.action_contract));
                let valid = validate_resolved_actions(plan, &actions).is_ok();
                if !valid || actions.is_empty() {
                    (LifecycleExploreShadowResolutionKind::Invalid, Vec::new())
                } else if actions.len() < plan.actions.len()
                    || actions
                        .iter()
                        .any(|action| action.resolution == ShadowActionResolutionKind::Partial)
                {
                    (LifecycleExploreShadowResolutionKind::Partial, actions)
                } else {
                    (LifecycleExploreShadowResolutionKind::Resolved, actions)
                }
            }
        };
        let mut observation = Self {
            format_revision: LIFECYCLE_EXPLORE_SHADOW_OBSERVATION_FORMAT_REVISION,
            lifecycle,
            expected_state_digest,
            plan_definition_digest: plan.definition_digest,
            planned_action_count,
            resolution,
            actions,
            authority: ShadowActionResolutionAuthority::Shadow,
            adapter_invocation_required: true,
            definition_digest: Digest([0; 32]),
        };
        observation.definition_digest = observation.compute_definition_digest();
        observation
    }

    fn invalid(
        lifecycle: LifecycleId,
        expected_state_digest: Digest,
        plan_definition_digest: Digest,
        planned_action_count: u16,
    ) -> Self {
        let mut observation = Self {
            format_revision: LIFECYCLE_EXPLORE_SHADOW_OBSERVATION_FORMAT_REVISION,
            lifecycle,
            expected_state_digest,
            plan_definition_digest,
            planned_action_count,
            resolution: LifecycleExploreShadowResolutionKind::Invalid,
            actions: Vec::new(),
            authority: ShadowActionResolutionAuthority::Shadow,
            adapter_invocation_required: true,
            definition_digest: Digest([0; 32]),
        };
        observation.definition_digest = observation.compute_definition_digest();
        observation
    }

    pub fn validate(&self) -> Result<(), LifecycleExploreShadowObservationError> {
        self.validate_shape()?;
        let expected = self.compute_definition_digest();
        if self.definition_digest != expected {
            return Err(LifecycleExploreShadowObservationError::DefinitionDigest {
                expected,
                actual: self.definition_digest,
            });
        }
        let bytes = serde_json::to_vec(self)
            .map_err(|_| LifecycleExploreShadowObservationError::WireBound)?;
        if bytes.len() > MAX_LIFECYCLE_EXPLORE_SHADOW_OBSERVATION_BYTES {
            return Err(LifecycleExploreShadowObservationError::WireBound);
        }
        Ok(())
    }

    pub fn validate_for_execution(
        &self,
        lifecycle: LifecycleId,
        expected_state_digest: Digest,
        plan: &LifecycleExploreActionPlan,
    ) -> Result<(), LifecycleExploreShadowObservationError> {
        self.validate()?;
        validate_lifecycle_explore_action_plan(plan)
            .map_err(|_| LifecycleExploreShadowObservationError::PlanBinding)?;
        if self.lifecycle != lifecycle || self.expected_state_digest != expected_state_digest {
            return Err(LifecycleExploreShadowObservationError::ExecutionBinding);
        }
        if self.plan_definition_digest != plan.definition_digest
            || self.planned_action_count != plan.actions.len() as u16
        {
            return Err(LifecycleExploreShadowObservationError::PlanBinding);
        }
        if matches!(
            self.resolution,
            LifecycleExploreShadowResolutionKind::Partial
                | LifecycleExploreShadowResolutionKind::Resolved
        ) {
            validate_resolved_actions(plan, &self.actions)?;
        }
        Ok(())
    }

    pub fn is_canonical(&self) -> bool {
        self.validate().is_ok()
    }

    fn validate_shape(&self) -> Result<(), LifecycleExploreShadowObservationError> {
        if self.format_revision != LIFECYCLE_EXPLORE_SHADOW_OBSERVATION_FORMAT_REVISION {
            return Err(LifecycleExploreShadowObservationError::FormatRevision(
                self.format_revision,
            ));
        }
        if self.authority != ShadowActionResolutionAuthority::Shadow
            || !self.adapter_invocation_required
        {
            return Err(LifecycleExploreShadowObservationError::Authority);
        }
        let planned = usize::from(self.planned_action_count);
        if planned == 0
            || planned > MAX_LIFECYCLE_EXPLORE_ACTIONS
            || self.actions.len() > planned
            || !self
                .actions
                .windows(2)
                .all(|pair| pair[0].action_contract < pair[1].action_contract)
        {
            return Err(LifecycleExploreShadowObservationError::ActionShape);
        }
        let shape_matches = match self.resolution {
            LifecycleExploreShadowResolutionKind::Unavailable
            | LifecycleExploreShadowResolutionKind::Miss
            | LifecycleExploreShadowResolutionKind::Invalid => self.actions.is_empty(),
            LifecycleExploreShadowResolutionKind::Partial => {
                !self.actions.is_empty()
                    && (self.actions.len() < planned
                        || self
                            .actions
                            .iter()
                            .any(|action| action.resolution == ShadowActionResolutionKind::Partial))
            }
            LifecycleExploreShadowResolutionKind::Resolved => {
                self.actions.len() == planned
                    && self
                        .actions
                        .iter()
                        .all(|action| action.resolution != ShadowActionResolutionKind::Partial)
            }
        };
        if !shape_matches || self.actions.iter().any(|action| !action.is_canonical()) {
            return Err(LifecycleExploreShadowObservationError::ActionShape);
        }
        Ok(())
    }

    fn compute_definition_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"lifecycle-explore-shadow-observation-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.lifecycle.0);
        hasher.field_digest(self.expected_state_digest);
        hasher.field_digest(self.plan_definition_digest);
        hasher.field_u16(self.planned_action_count);
        hasher.field_u8(resolution_tag(self.resolution));
        hasher.field_u16(self.actions.len() as u16);
        for action in &self.actions {
            hasher.field_str(action.action_contract.as_str());
            hasher.field_digest(action.definition_digest);
        }
        hasher.field_u8(0);
        hasher.field_u8(u8::from(self.adapter_invocation_required));
        hasher.finish()
    }
}

fn validate_resolved_actions(
    plan: &LifecycleExploreActionPlan,
    actions: &[ShadowActionResolutionSummary],
) -> Result<(), LifecycleExploreShadowObservationError> {
    if actions.len() > plan.actions.len()
        || !actions.windows(2).all(|pair| pair[0].action_contract < pair[1].action_contract)
    {
        return Err(LifecycleExploreShadowObservationError::ActionShape);
    }
    for summary in actions {
        let request = plan
            .actions
            .iter()
            .find(|request| request.contract == summary.action_contract)
            .ok_or(LifecycleExploreShadowObservationError::ActionBinding)?;
        let definition = built_in_action_contracts()
            .iter()
            .find(|definition| definition.contract.id == summary.action_contract)
            .ok_or(LifecycleExploreShadowObservationError::ActionBinding)?;
        summary
            .validate_for_request_and_action(request, definition)
            .map_err(|_| LifecycleExploreShadowObservationError::ActionBinding)?;
    }
    Ok(())
}

fn resolution_tag(resolution: LifecycleExploreShadowResolutionKind) -> u8 {
    match resolution {
        LifecycleExploreShadowResolutionKind::Unavailable => 0,
        LifecycleExploreShadowResolutionKind::Miss => 1,
        LifecycleExploreShadowResolutionKind::Partial => 2,
        LifecycleExploreShadowResolutionKind::Resolved => 3,
        LifecycleExploreShadowResolutionKind::Invalid => 4,
    }
}

fn deserialize_bounded_summaries<'de, D>(
    deserializer: D,
) -> Result<Vec<ShadowActionResolutionSummary>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedSummariesVisitor;

    impl<'de> Visitor<'de> for BoundedSummariesVisitor {
        type Value = Vec<ShadowActionResolutionSummary>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_LIFECYCLE_EXPLORE_ACTIONS} action summaries")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let capacity = sequence.size_hint().unwrap_or(0).min(MAX_LIFECYCLE_EXPLORE_ACTIONS);
            let mut values = Vec::with_capacity(capacity);
            while let Some(value) = sequence.next_element()? {
                if values.len() == MAX_LIFECYCLE_EXPLORE_ACTIONS {
                    return Err(serde::de::Error::custom(
                        "too many lifecycle Explore action summaries",
                    ));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(BoundedSummariesVisitor)
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LifecycleExploreShadowObservationError {
    #[error("unsupported lifecycle Explore Shadow observation revision {0}")]
    FormatRevision(u16),
    #[error("lifecycle Explore observation authority is invalid")]
    Authority,
    #[error("lifecycle Explore observation action shape is invalid")]
    ActionShape,
    #[error("lifecycle Explore observation action binding is invalid")]
    ActionBinding,
    #[error("lifecycle Explore observation plan binding is invalid")]
    PlanBinding,
    #[error("lifecycle Explore observation execution binding is invalid")]
    ExecutionBinding,
    #[error("lifecycle Explore observation exceeds its wire bound")]
    WireBound,
    #[error("lifecycle Explore observation digest mismatch: expected {expected}, got {actual}")]
    DefinitionDigest { expected: Digest, actual: Digest },
}
