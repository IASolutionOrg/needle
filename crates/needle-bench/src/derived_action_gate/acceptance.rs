use super::{
    DERIVED_ACTION_GATE_ACCEPTANCE_SCHEMA, DERIVED_ACTION_GATE_FORMAT_REVISION,
    DerivedActionGateError, DerivedActionKind, DerivedActionReuseScenario,
    MAX_DERIVED_ACTION_GATE_ACCEPTANCE_BYTES, MAX_DERIVED_ACTION_GATE_FAILURE_BYTES,
    MAX_DERIVED_ACTION_GATE_LIMITATIONS, action_tag, hash_u64, scenario_tag, validate_label,
    validate_nonzero_digest, validate_sorted_unique,
};
use needle_core::{CanonicalHasher, Digest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedActionGateAcceptanceDecision {
    pub action: DerivedActionKind,
    pub scenario: DerivedActionReuseScenario,
    pub fresh_quality_accepted: bool,
    pub reuse_quality_accepted: bool,
    pub semantic_equivalence_accepted: bool,
}

impl DerivedActionGateAcceptanceDecision {
    pub const fn accepted(action: DerivedActionKind, scenario: DerivedActionReuseScenario) -> Self {
        Self {
            action,
            scenario,
            fresh_quality_accepted: true,
            reuse_quality_accepted: true,
            semantic_equivalence_accepted: true,
        }
    }

    const fn is_accepted(&self) -> bool {
        self.fresh_quality_accepted
            && self.reuse_quality_accepted
            && self.semantic_equivalence_accepted
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedActionGateAcceptance {
    pub format_revision: u16,
    pub schema: String,
    pub manifest_digest: Digest,
    pub observation_set_digest: Digest,
    pub review_material_digest: Digest,
    pub reviewer_id: String,
    pub reviewed_unix_ms: u64,
    pub decisions: Vec<DerivedActionGateAcceptanceDecision>,
    pub limitations: Vec<String>,
    pub authority_promotion_approved: bool,
    pub statistical_claim: bool,
    pub acceptance_digest: Digest,
}

impl DerivedActionGateAcceptance {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        manifest_digest: Digest,
        observation_set_digest: Digest,
        review_material_digest: Digest,
        reviewer_id: impl Into<String>,
        reviewed_unix_ms: u64,
        mut decisions: Vec<DerivedActionGateAcceptanceDecision>,
        mut limitations: Vec<String>,
    ) -> Result<Self, DerivedActionGateError> {
        decisions.sort();
        limitations.sort();
        let mut value = Self {
            format_revision: DERIVED_ACTION_GATE_FORMAT_REVISION,
            schema: DERIVED_ACTION_GATE_ACCEPTANCE_SCHEMA.to_owned(),
            manifest_digest,
            observation_set_digest,
            review_material_digest,
            reviewer_id: reviewer_id.into(),
            reviewed_unix_ms,
            decisions,
            limitations,
            authority_promotion_approved: false,
            statistical_claim: false,
            acceptance_digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.acceptance_digest = value.compute_digest();
        Ok(value)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, DerivedActionGateError> {
        if bytes.len() > MAX_DERIVED_ACTION_GATE_ACCEPTANCE_BYTES {
            return Err(DerivedActionGateError::Bound {
                field: "acceptance.bytes",
                actual: bytes.len(),
                maximum: MAX_DERIVED_ACTION_GATE_ACCEPTANCE_BYTES,
            });
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| DerivedActionGateError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), DerivedActionGateError> {
        self.validate_shape()?;
        if self.acceptance_digest != self.compute_digest() {
            return Err(DerivedActionGateError::Digest("acceptance.acceptance_digest"));
        }
        Ok(())
    }

    pub fn validate_for(
        &self,
        manifest_digest: Digest,
        observation_set_digest: Digest,
    ) -> Result<(), DerivedActionGateError> {
        self.validate()?;
        if self.manifest_digest != manifest_digest
            || self.observation_set_digest != observation_set_digest
        {
            return Err(DerivedActionGateError::AcceptanceBinding);
        }
        if !self.decisions.iter().all(|decision| decision.is_accepted()) {
            return Err(DerivedActionGateError::AcceptanceRejected);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), DerivedActionGateError> {
        if self.format_revision != DERIVED_ACTION_GATE_FORMAT_REVISION {
            return Err(DerivedActionGateError::FormatRevision(self.format_revision));
        }
        if self.schema != DERIVED_ACTION_GATE_ACCEPTANCE_SCHEMA {
            return Err(DerivedActionGateError::Schema("acceptance.schema"));
        }
        for (field, digest) in [
            ("acceptance.manifest_digest", self.manifest_digest),
            ("acceptance.observation_set_digest", self.observation_set_digest),
            ("acceptance.review_material_digest", self.review_material_digest),
        ] {
            validate_nonzero_digest(field, digest)?;
        }
        validate_label("acceptance.reviewer_id", &self.reviewer_id)?;
        if self.reviewed_unix_ms == 0 {
            return Err(DerivedActionGateError::Metric("acceptance.reviewed_unix_ms"));
        }
        if self.authority_promotion_approved || self.statistical_claim {
            return Err(DerivedActionGateError::ReportAuthority);
        }
        if self.decisions.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(DerivedActionGateError::Canonical("acceptance.decisions"));
        }
        let coverage = self
            .decisions
            .iter()
            .map(|decision| (decision.action, decision.scenario))
            .collect::<BTreeSet<_>>();
        let expected = DerivedActionKind::ALL
            .into_iter()
            .flat_map(|action| {
                DerivedActionReuseScenario::ALL.into_iter().map(move |scenario| (action, scenario))
            })
            .collect::<BTreeSet<_>>();
        if coverage != expected || self.decisions.len() != expected.len() {
            return Err(DerivedActionGateError::ScenarioCoverage);
        }
        validate_sorted_unique(
            "acceptance.limitations",
            &self.limitations,
            1,
            MAX_DERIVED_ACTION_GATE_LIMITATIONS,
        )?;
        if self.limitations.iter().any(|limitation| {
            limitation.trim().is_empty()
                || limitation.len() > MAX_DERIVED_ACTION_GATE_FAILURE_BYTES
                || limitation.chars().any(char::is_control)
        }) {
            return Err(DerivedActionGateError::Text("acceptance.limitations"));
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"derived-action-gate-a3-acceptance-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_str(&self.schema);
        hasher.field_digest(self.manifest_digest);
        hasher.field_digest(self.observation_set_digest);
        hasher.field_digest(self.review_material_digest);
        hasher.field_str(&self.reviewer_id);
        hash_u64(&mut hasher, self.reviewed_unix_ms);
        hasher.field_u16(self.decisions.len().try_into().unwrap_or(u16::MAX));
        for decision in &self.decisions {
            hasher.field_u8(action_tag(decision.action));
            hasher.field_u8(scenario_tag(decision.scenario));
            hasher.field_u8(u8::from(decision.fresh_quality_accepted));
            hasher.field_u8(u8::from(decision.reuse_quality_accepted));
            hasher.field_u8(u8::from(decision.semantic_equivalence_accepted));
        }
        hasher.field_u16(self.limitations.len().try_into().unwrap_or(u16::MAX));
        for limitation in &self.limitations {
            hasher.field_str(limitation);
        }
        hasher.field_u8(u8::from(self.authority_promotion_approved));
        hasher.field_u8(u8::from(self.statistical_claim));
        hasher.finish()
    }
}
