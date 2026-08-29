use super::{LifecycleError, LifecyclePhase};
use crate::{ActionContractId, CanonicalHasher, Digest};
use serde::{Deserialize, Serialize};

pub const LIFECYCLE_ACTION_PHASE_PLAN_FORMAT_REVISION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleActionPhasePlan {
    pub format_revision: u16,
    pub phase: LifecyclePhase,
    pub action_contract: ActionContractId,
    pub action_definition_digest: Digest,
    pub adapter_definition_digest: Digest,
    pub definition_digest: Digest,
}

impl LifecycleActionPhasePlan {
    pub fn new(
        phase: LifecyclePhase,
        action_contract: ActionContractId,
        action_definition_digest: Digest,
        adapter_definition_digest: Digest,
    ) -> Result<Self, LifecycleError> {
        let mut value = Self {
            format_revision: LIFECYCLE_ACTION_PHASE_PLAN_FORMAT_REVISION,
            phase,
            action_contract,
            action_definition_digest,
            adapter_definition_digest,
            definition_digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.definition_digest = value.compute_definition_digest();
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), LifecycleError> {
        self.validate_shape()?;
        if self.definition_digest != self.compute_definition_digest() {
            return Err(LifecycleError::InvalidActionPhasePlan);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), LifecycleError> {
        if self.format_revision != LIFECYCLE_ACTION_PHASE_PLAN_FORMAT_REVISION
            || !matches!(
                self.phase,
                LifecyclePhase::Implement
                    | LifecyclePhase::Test
                    | LifecyclePhase::Review
                    | LifecyclePhase::Verify
            )
            || self.action_definition_digest == Digest([0; 32])
            || self.adapter_definition_digest == Digest([0; 32])
        {
            return Err(LifecycleError::InvalidActionPhasePlan);
        }
        Ok(())
    }

    fn compute_definition_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"needle-lifecycle-action-phase-plan-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_str(self.phase.as_str());
        hasher.field_str(self.action_contract.as_str());
        hasher.field_digest(self.action_definition_digest);
        hasher.field_digest(self.adapter_definition_digest);
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleActionPhasePlans {
    pub implement: LifecycleActionPhasePlan,
    pub test: LifecycleActionPhasePlan,
    pub review: LifecycleActionPhasePlan,
    pub verify: LifecycleActionPhasePlan,
    pub definition_digest: Digest,
}

impl LifecycleActionPhasePlans {
    pub fn new(
        implement: LifecycleActionPhasePlan,
        test: LifecycleActionPhasePlan,
        review: LifecycleActionPhasePlan,
        verify: LifecycleActionPhasePlan,
    ) -> Result<Self, LifecycleError> {
        let mut value =
            Self { implement, test, review, verify, definition_digest: Digest([0; 32]) };
        value.validate_shape()?;
        value.definition_digest = value.compute_definition_digest();
        Ok(value)
    }

    pub fn for_phase(&self, phase: LifecyclePhase) -> Option<&LifecycleActionPhasePlan> {
        match phase {
            LifecyclePhase::Implement => Some(&self.implement),
            LifecyclePhase::Test => Some(&self.test),
            LifecyclePhase::Review => Some(&self.review),
            LifecyclePhase::Verify => Some(&self.verify),
            LifecyclePhase::Explore | LifecyclePhase::Apply => None,
        }
    }

    pub fn validate(&self) -> Result<(), LifecycleError> {
        self.validate_shape()?;
        if self.definition_digest != self.compute_definition_digest() {
            return Err(LifecycleError::InvalidActionPhasePlan);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), LifecycleError> {
        for (expected, plan) in [
            (LifecyclePhase::Implement, &self.implement),
            (LifecyclePhase::Test, &self.test),
            (LifecyclePhase::Review, &self.review),
            (LifecyclePhase::Verify, &self.verify),
        ] {
            plan.validate()?;
            if plan.phase != expected {
                return Err(LifecycleError::InvalidActionPhasePlan);
            }
        }
        Ok(())
    }

    fn compute_definition_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"needle-lifecycle-action-phase-plans-v1");
        for plan in [&self.implement, &self.test, &self.review, &self.verify] {
            hasher.field_digest(plan.definition_digest);
        }
        hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(phase: LifecyclePhase, contract: &str) -> LifecycleActionPhasePlan {
        LifecycleActionPhasePlan::new(
            phase,
            ActionContractId::new(contract).unwrap(),
            Digest::blake3(format!("{contract}:action")),
            Digest::blake3(format!("{contract}:adapter")),
        )
        .unwrap()
    }

    #[test]
    fn phase_plans_are_closed_and_digest_addressed() {
        let plans = LifecycleActionPhasePlans::new(
            plan(LifecyclePhase::Implement, "needle.patch.propose"),
            plan(LifecyclePhase::Test, "needle.tests.execute"),
            plan(LifecyclePhase::Review, "needle.review.diff"),
            plan(LifecyclePhase::Verify, "needle.patch.verify"),
        )
        .unwrap();
        plans.validate().unwrap();
        let mut tampered = plans.clone();
        tampered.review.adapter_definition_digest = Digest::blake3(b"tampered");
        assert_eq!(tampered.validate(), Err(LifecycleError::InvalidActionPhasePlan));
    }
}
