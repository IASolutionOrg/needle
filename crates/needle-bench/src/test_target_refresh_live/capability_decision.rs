use super::{
    LIVE_TEST_TARGET_REFRESH_FORMAT_REVISION, LiveRefreshAcceptanceError,
    LiveTestTargetRefreshGateAcceptance, hash_bool, hash_u64,
};
use needle_core::{
    ActionCapabilityClass, ActionSubjectAuthorityClass, ActionWorldPolicyClass, CanonicalHasher,
    CapabilityMode, Digest, EffectClass, ManifestClosure, ReuseMode,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const LIVE_TEST_TARGET_REFRESH_CAPABILITY_DECISION_SCHEMA: &str =
    "needle.test-target-refresh-capability-decision/1";
pub const MAX_LIVE_TEST_TARGET_REFRESH_CAPABILITY_DECISION_BYTES: usize = 128 * 1024;
pub const MAX_LIVE_TEST_TARGET_REFRESH_DECIDER_BYTES: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveTestTargetRefreshCapabilityDecision {
    pub format_revision: u16,
    pub schema: String,
    pub acceptance_digest: Digest,
    pub report_set_digest: Digest,
    pub capability_class: ActionCapabilityClass,
    pub decider_id: String,
    pub decided_unix_ms: u64,
    pub selected_mode: CapabilityMode,
    pub operator_invocation_only: bool,
    pub automatic_resolver_consumption_approved: bool,
    pub automatic_lifecycle_consumption_approved: bool,
    pub authoritative_promotion_approved: bool,
    pub gate_a4_closed: bool,
    pub decision_digest: Digest,
}

impl LiveTestTargetRefreshCapabilityDecision {
    pub fn new(
        acceptance: &LiveTestTargetRefreshGateAcceptance,
        capability_class: ActionCapabilityClass,
        decider_id: impl Into<String>,
        decided_unix_ms: u64,
    ) -> Result<Self, LiveRefreshCapabilityDecisionError> {
        acceptance.validate()?;
        let mut value = Self {
            format_revision: LIVE_TEST_TARGET_REFRESH_FORMAT_REVISION,
            schema: LIVE_TEST_TARGET_REFRESH_CAPABILITY_DECISION_SCHEMA.to_owned(),
            acceptance_digest: acceptance.acceptance_digest,
            report_set_digest: acceptance.report_set_digest,
            capability_class,
            decider_id: decider_id.into(),
            decided_unix_ms,
            selected_mode: CapabilityMode::Shadow,
            operator_invocation_only: true,
            automatic_resolver_consumption_approved: false,
            automatic_lifecycle_consumption_approved: false,
            authoritative_promotion_approved: false,
            gate_a4_closed: true,
            decision_digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.decision_digest = value.compute_digest();
        Ok(value)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, LiveRefreshCapabilityDecisionError> {
        if bytes.len() > MAX_LIVE_TEST_TARGET_REFRESH_CAPABILITY_DECISION_BYTES {
            return Err(LiveRefreshCapabilityDecisionError::WireBound {
                actual: bytes.len(),
                maximum: MAX_LIVE_TEST_TARGET_REFRESH_CAPABILITY_DECISION_BYTES,
            });
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| LiveRefreshCapabilityDecisionError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), LiveRefreshCapabilityDecisionError> {
        self.validate_shape()?;
        if self.decision_digest != self.compute_digest() {
            return Err(LiveRefreshCapabilityDecisionError::DecisionDigest);
        }
        Ok(())
    }

    pub fn validate_for(
        &self,
        acceptance: &LiveTestTargetRefreshGateAcceptance,
        current_capability: &ActionCapabilityClass,
    ) -> Result<(), LiveRefreshCapabilityDecisionError> {
        self.validate()?;
        acceptance.validate()?;
        current_capability
            .validate()
            .map_err(|error| LiveRefreshCapabilityDecisionError::Capability(error.to_string()))?;
        if self.acceptance_digest != acceptance.acceptance_digest
            || self.report_set_digest != acceptance.report_set_digest
            || &self.capability_class != current_capability
        {
            return Err(LiveRefreshCapabilityDecisionError::Binding);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), LiveRefreshCapabilityDecisionError> {
        if self.format_revision != LIVE_TEST_TARGET_REFRESH_FORMAT_REVISION {
            return Err(LiveRefreshCapabilityDecisionError::FormatRevision(self.format_revision));
        }
        if self.schema != LIVE_TEST_TARGET_REFRESH_CAPABILITY_DECISION_SCHEMA
            || self.acceptance_digest == Digest([0; 32])
            || self.report_set_digest == Digest([0; 32])
        {
            return Err(LiveRefreshCapabilityDecisionError::Shape);
        }
        self.capability_class
            .validate()
            .map_err(|error| LiveRefreshCapabilityDecisionError::Capability(error.to_string()))?;
        let provenance = self.capability_class.manifest_provenance;
        if self.capability_class.action_contract.as_str() != "needle.tests.inventory"
            || self.capability_class.reuse_mode != ReuseMode::Refresh
            || self.capability_class.effect_class != EffectClass::PureEvidence
            || self.capability_class.subject_authority != ActionSubjectAuthorityClass::NotApplicable
            || self.capability_class.world_policy != ActionWorldPolicyClass::Exact
            || self.capability_class.manifest_closure != Some(ManifestClosure::Closed)
            || !provenance.request_bound
            || !provenance.derived
            || provenance.producer_authored
            || provenance.provider_attested
        {
            return Err(LiveRefreshCapabilityDecisionError::CapabilityScope);
        }
        if self.decider_id.is_empty()
            || self.decider_id.trim() != self.decider_id
            || self.decider_id.len() > MAX_LIVE_TEST_TARGET_REFRESH_DECIDER_BYTES
            || self.decider_id.chars().any(char::is_control)
            || self.decided_unix_ms == 0
        {
            return Err(LiveRefreshCapabilityDecisionError::Decider);
        }
        if self.selected_mode != CapabilityMode::Shadow
            || self.capability_class.mode != CapabilityMode::Shadow
            || !self.operator_invocation_only
            || self.automatic_resolver_consumption_approved
            || self.automatic_lifecycle_consumption_approved
            || self.authoritative_promotion_approved
            || !self.gate_a4_closed
        {
            return Err(LiveRefreshCapabilityDecisionError::AuthorityBoundary);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"test-target-refresh-capability-decision-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_str(&self.schema);
        hasher.field_digest(self.acceptance_digest);
        hasher.field_digest(self.report_set_digest);
        hasher.field_digest(self.capability_class.id.digest());
        hasher.field_digest(self.capability_class.definition_digest);
        hasher.field_str(&self.decider_id);
        hash_u64(&mut hasher, self.decided_unix_ms);
        hasher.field_u8(capability_mode_tag(self.selected_mode));
        hash_bool(&mut hasher, self.operator_invocation_only);
        hash_bool(&mut hasher, self.automatic_resolver_consumption_approved);
        hash_bool(&mut hasher, self.automatic_lifecycle_consumption_approved);
        hash_bool(&mut hasher, self.authoritative_promotion_approved);
        hash_bool(&mut hasher, self.gate_a4_closed);
        hasher.finish()
    }
}

const fn capability_mode_tag(value: CapabilityMode) -> u8 {
    match value {
        CapabilityMode::Disabled => 0,
        CapabilityMode::Shadow => 1,
        CapabilityMode::Advisory => 2,
        CapabilityMode::Authoritative => 3,
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum LiveRefreshCapabilityDecisionError {
    #[error(transparent)]
    Acceptance(#[from] LiveRefreshAcceptanceError),
    #[error("live refresh capability decision format revision {0} is unsupported")]
    FormatRevision(u16),
    #[error("live refresh capability decision shape is invalid")]
    Shape,
    #[error("live refresh capability class is invalid: {0}")]
    Capability(String),
    #[error("live refresh capability class is outside the accepted Gate A4 scope")]
    CapabilityScope,
    #[error("live refresh capability decision decider is invalid")]
    Decider,
    #[error("live refresh capability decision broadens authority or automatic consumption")]
    AuthorityBoundary,
    #[error("live refresh capability decision does not bind current evidence and definitions")]
    Binding,
    #[error("live refresh capability decision digest is inconsistent")]
    DecisionDigest,
    #[error("live refresh capability decision JSON is invalid: {0}")]
    Json(String),
    #[error("live refresh capability decision wire has {actual} bytes; maximum is {maximum}")]
    WireBound { actual: usize, maximum: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_target_refresh_live::tests::report;
    use needle_runtime::test_target_inventory_refresh_capability;

    fn acceptance() -> LiveTestTargetRefreshGateAcceptance {
        LiveTestTargetRefreshGateAcceptance::new(
            &[report()],
            "local-owner",
            1_754_000_000_000,
            vec!["bounded local Shadow calibration".to_owned()],
        )
        .unwrap()
    }

    #[test]
    fn decision_round_trip_closes_only_gate_a4_in_shadow() {
        let acceptance = acceptance();
        let capability = test_target_inventory_refresh_capability().clone();
        let decision = LiveTestTargetRefreshCapabilityDecision::new(
            &acceptance,
            capability.clone(),
            "local-owner",
            1_754_000_000_001,
        )
        .unwrap();
        decision.validate_for(&acceptance, &capability).unwrap();
        assert!(decision.gate_a4_closed);
        assert_eq!(decision.selected_mode, CapabilityMode::Shadow);
        assert!(!decision.authoritative_promotion_approved);
        assert!(!decision.automatic_resolver_consumption_approved);
        assert!(!decision.automatic_lifecycle_consumption_approved);
        let bytes = serde_json::to_vec(&decision).unwrap();
        assert_eq!(LiveTestTargetRefreshCapabilityDecision::decode_json(&bytes).unwrap(), decision);
    }

    #[test]
    fn decision_rejects_authority_tamper_and_definition_drift() {
        let acceptance = acceptance();
        let capability = test_target_inventory_refresh_capability().clone();
        let mut decision = LiveTestTargetRefreshCapabilityDecision::new(
            &acceptance,
            capability.clone(),
            "local-owner",
            1_754_000_000_001,
        )
        .unwrap();
        decision.selected_mode = CapabilityMode::Authoritative;
        assert_eq!(decision.validate(), Err(LiveRefreshCapabilityDecisionError::AuthorityBoundary));

        let mut drifted = capability.clone();
        drifted.mode = CapabilityMode::Advisory;
        assert_eq!(
            LiveTestTargetRefreshCapabilityDecision::new(&acceptance, drifted, "local-owner", 1),
            Err(LiveRefreshCapabilityDecisionError::AuthorityBoundary)
        );
    }

    #[test]
    fn decision_decode_is_bounded() {
        let oversized = vec![b' '; MAX_LIVE_TEST_TARGET_REFRESH_CAPABILITY_DECISION_BYTES + 1];
        assert!(matches!(
            LiveTestTargetRefreshCapabilityDecision::decode_json(&oversized),
            Err(LiveRefreshCapabilityDecisionError::WireBound { .. })
        ));
    }
}
