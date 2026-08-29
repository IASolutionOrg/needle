use crate::{
    BUILT_IN_ACTION_COUNT, BuiltInActionDefinition, built_in_action_contracts,
    semantic_action_request::build_semantic_action_request,
};
use needle_core::{
    ActionContractId, ActionRequest, ArtifactId, ArtifactRequestId,
    ArtifactValidationCertificateId, CanonicalHasher, CapabilityMode, Digest, MAX_NEED_IR_BYTES,
    MAX_PROOF_ARTIFACTS, Need, NeedFragment, NeedRequest, PredicateKind, ReuseDescriptor,
    ReuseDescriptorError, ReuseSufficiencyCertificateId, SelectedPlan, SelectedPlanId,
};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::marker::PhantomData;
use thiserror::Error;

const LEGACY_SHADOW_ACTION_RESOLUTION_FORMAT_REVISION: u16 = 1;
pub const SHADOW_ACTION_RESOLUTION_FORMAT_REVISION: u16 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowActionResolutionAuthority {
    Shadow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowActionResolutionKind {
    Exact,
    Coverage,
    Composite,
    Partial,
}

pub struct ShadowActionResolutionInput<'a> {
    pub request: &'a ActionRequest,
    pub action: &'a BuiltInActionDefinition,
    pub resolution: ShadowActionResolutionKind,
    pub descriptors: &'a [ReuseDescriptor],
    pub selected_plan: SelectedPlanId,
    pub sufficiency_certificate: Option<ReuseSufficiencyCertificateId>,
    pub covered_mask: u16,
    pub missing_mask: u16,
}

pub(crate) struct ShadowActionResolutionProjectionInput<'a> {
    pub request: &'a NeedRequest,
    pub need: &'a Need,
    pub fragment: &'a NeedFragment,
    pub repository_id: Digest,
    pub source_snapshot_digest: Digest,
    pub descriptors: Vec<ReuseDescriptor>,
    pub plan: &'a SelectedPlan,
    pub sufficiency_certificate: Option<ReuseSufficiencyCertificateId>,
}

/// Non-authoritative per-action projection over validated reuse descriptors.
///
/// This record does not establish freshness, effective capability, or a
/// resolver decision. It is deliberately separate from `CacheResolution`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowActionResolutionSummary {
    pub format_revision: u16,
    pub authority: ShadowActionResolutionAuthority,
    pub request: ArtifactRequestId,
    pub action_contract: ActionContractId,
    pub action_semantic_definition_digest: Digest,
    pub action_validation_definition_digest: Digest,
    pub output_contract_definition_digest: Digest,
    pub validator_definition_digest: Digest,
    pub predicate: PredicateKind,
    pub repository_lineage: Digest,
    pub semantic_world_digest: Digest,
    pub resolution: ShadowActionResolutionKind,
    #[serde(deserialize_with = "deserialize_bounded_vec")]
    pub artifacts: Vec<ArtifactId>,
    #[serde(default, deserialize_with = "deserialize_bounded_vec")]
    pub artifact_matched_requests: Vec<ArtifactRequestId>,
    #[serde(deserialize_with = "deserialize_bounded_vec")]
    pub artifact_origin_requests: Vec<ArtifactRequestId>,
    #[serde(deserialize_with = "deserialize_bounded_vec")]
    pub validation_certificates: Vec<ArtifactValidationCertificateId>,
    pub selected_plan: SelectedPlanId,
    pub sufficiency_certificate: Option<ReuseSufficiencyCertificateId>,
    pub covered_mask: u16,
    pub missing_mask: u16,
    pub definition_digest: Digest,
}

impl ShadowActionResolutionSummary {
    pub fn new(
        input: ShadowActionResolutionInput<'_>,
    ) -> Result<Self, ShadowActionResolutionError> {
        validate_action(input.action)?;
        let predicate =
            input.action.predicate().ok_or(ShadowActionResolutionError::ActionDefinition)?;
        let request = validate_request(input.request, input.action)?;
        if input.descriptors.is_empty() || input.descriptors.len() > MAX_PROOF_ARTIFACTS {
            return Err(ShadowActionResolutionError::DescriptorBound {
                actual: input.descriptors.len(),
                maximum: MAX_PROOF_ARTIFACTS,
            });
        }

        let validator_definition_digest = input.action.validator_definition_digest;
        let mut bindings = Vec::with_capacity(input.descriptors.len());
        let mut semantic_world = None;
        for descriptor in input.descriptors {
            descriptor.validate()?;
            if descriptor.action_contract != input.action.contract.id
                || descriptor.action_semantic_definition_digest
                    != input.action.contract.semantic_definition_digest
                || descriptor.action_validation_definition_digest
                    != input.action.contract.validation_definition_digest
                || descriptor.output_contract_definition_digest
                    != input.action.output_contract_definition_digest
                || descriptor.validator_definition_digest != validator_definition_digest
                || descriptor.coverage.world.repository_lineage
                    != input.request.artifact_request.repository_id
                || descriptor
                    .coverage
                    .entries
                    .iter()
                    .any(|entry| entry.obligation.predicate != predicate)
            {
                return Err(ShadowActionResolutionError::DescriptorBinding);
            }
            match semantic_world {
                Some(expected) if expected != descriptor.semantic_world_digest => {
                    return Err(ShadowActionResolutionError::DescriptorBinding);
                }
                None => semantic_world = Some(descriptor.semantic_world_digest),
                Some(_) => {}
            }
            bindings.push((
                descriptor.artifact,
                descriptor.exact_request,
                descriptor.origin_request,
                descriptor.validation_certificate,
            ));
        }
        let semantic_world_digest =
            semantic_world.ok_or(ShadowActionResolutionError::DescriptorBinding)?;
        bindings.sort_unstable_by_key(|binding| binding.0);
        if !bindings.windows(2).all(|pair| pair[0].0 < pair[1].0) {
            return Err(ShadowActionResolutionError::Ordering);
        }
        let mut certificates = bindings.iter().map(|binding| binding.3).collect::<Vec<_>>();
        certificates.sort_unstable();
        if !certificates.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(ShadowActionResolutionError::Ordering);
        }

        let mut summary = Self {
            format_revision: SHADOW_ACTION_RESOLUTION_FORMAT_REVISION,
            authority: ShadowActionResolutionAuthority::Shadow,
            request,
            action_contract: input.action.contract.id.clone(),
            action_semantic_definition_digest: input.action.contract.semantic_definition_digest,
            action_validation_definition_digest: input.action.contract.validation_definition_digest,
            output_contract_definition_digest: input.action.output_contract_definition_digest,
            validator_definition_digest,
            predicate,
            repository_lineage: input.request.artifact_request.repository_id,
            semantic_world_digest,
            resolution: input.resolution,
            artifacts: bindings.iter().map(|binding| binding.0).collect(),
            artifact_matched_requests: bindings.iter().map(|binding| binding.1).collect(),
            artifact_origin_requests: bindings.iter().map(|binding| binding.2).collect(),
            validation_certificates: bindings.iter().map(|binding| binding.3).collect(),
            selected_plan: input.selected_plan,
            sufficiency_certificate: input.sufficiency_certificate,
            covered_mask: input.covered_mask,
            missing_mask: input.missing_mask,
            definition_digest: Digest([0; 32]),
        };
        summary.validate_shape()?;
        summary.definition_digest = summary.compute_definition_digest();
        Ok(summary)
    }

    pub fn validate(&self) -> Result<(), ShadowActionResolutionError> {
        self.validate_shape()?;
        let expected = self.compute_definition_digest();
        if self.definition_digest != expected {
            return Err(ShadowActionResolutionError::DefinitionDigest {
                expected,
                actual: self.definition_digest,
            });
        }
        Ok(())
    }

    pub fn validate_for_action(
        &self,
        action: &BuiltInActionDefinition,
    ) -> Result<(), ShadowActionResolutionError> {
        self.validate()?;
        validate_action(action)?;
        if self.action_contract != action.contract.id
            || self.action_semantic_definition_digest != action.contract.semantic_definition_digest
            || self.action_validation_definition_digest
                != action.contract.validation_definition_digest
            || self.output_contract_definition_digest != action.output_contract_definition_digest
            || self.validator_definition_digest != action.validator_definition_digest
            || Some(self.predicate) != action.predicate()
        {
            return Err(ShadowActionResolutionError::ActionDefinition);
        }
        Ok(())
    }

    pub fn validate_for_request_and_action(
        &self,
        request: &ActionRequest,
        action: &BuiltInActionDefinition,
    ) -> Result<(), ShadowActionResolutionError> {
        self.validate_for_action(action)?;
        if self.request != validate_request(request, action)?
            || self.repository_lineage != request.artifact_request.repository_id
        {
            return Err(ShadowActionResolutionError::Request);
        }
        Ok(())
    }

    pub fn is_canonical(&self) -> bool {
        self.validate().is_ok()
    }

    fn validate_shape(&self) -> Result<(), ShadowActionResolutionError> {
        if !matches!(
            self.format_revision,
            LEGACY_SHADOW_ACTION_RESOLUTION_FORMAT_REVISION
                | SHADOW_ACTION_RESOLUTION_FORMAT_REVISION
        ) {
            return Err(ShadowActionResolutionError::FormatRevision(self.format_revision));
        }
        if self.authority != ShadowActionResolutionAuthority::Shadow {
            return Err(ShadowActionResolutionError::Authority);
        }
        let count = self.artifacts.len();
        if count == 0 || count > MAX_PROOF_ARTIFACTS {
            return Err(ShadowActionResolutionError::DescriptorBound {
                actual: count,
                maximum: MAX_PROOF_ARTIFACTS,
            });
        }
        if self.artifact_origin_requests.len() != count
            || self.validation_certificates.len() != count
            || (self.format_revision == SHADOW_ACTION_RESOLUTION_FORMAT_REVISION
                && self.artifact_matched_requests.len() != count)
            || (self.format_revision == LEGACY_SHADOW_ACTION_RESOLUTION_FORMAT_REVISION
                && !self.artifact_matched_requests.is_empty())
        {
            return Err(ShadowActionResolutionError::BindingCardinality);
        }
        if !self.artifacts.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(ShadowActionResolutionError::Ordering);
        }
        let mut certificates = self.validation_certificates.clone();
        certificates.sort_unstable();
        if !certificates.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(ShadowActionResolutionError::Ordering);
        }
        if self.covered_mask == 0 || self.covered_mask & self.missing_mask != 0 {
            return Err(ShadowActionResolutionError::Masks);
        }
        let matched_requests =
            if self.format_revision == LEGACY_SHADOW_ACTION_RESOLUTION_FORMAT_REVISION {
                &self.artifact_origin_requests
            } else {
                &self.artifact_matched_requests
            };
        match self.resolution {
            ShadowActionResolutionKind::Exact => {
                if count != 1 || matched_requests[0] != self.request {
                    return Err(ShadowActionResolutionError::ResolutionShape);
                }
                self.validate_full_resolution()?;
            }
            ShadowActionResolutionKind::Coverage => {
                if count != 1 || matched_requests[0] == self.request {
                    return Err(ShadowActionResolutionError::ResolutionShape);
                }
                self.validate_full_resolution()?;
            }
            ShadowActionResolutionKind::Composite => {
                if count < 2 {
                    return Err(ShadowActionResolutionError::ResolutionShape);
                }
                self.validate_full_resolution()?;
            }
            ShadowActionResolutionKind::Partial => {
                if self.missing_mask == 0 || self.sufficiency_certificate.is_some() {
                    return Err(ShadowActionResolutionError::ResolutionShape);
                }
            }
        }
        Ok(())
    }

    fn validate_full_resolution(&self) -> Result<(), ShadowActionResolutionError> {
        if self.missing_mask != 0 {
            return Err(ShadowActionResolutionError::ResolutionShape);
        }
        Ok(())
    }

    fn compute_definition_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(
            if self.format_revision == LEGACY_SHADOW_ACTION_RESOLUTION_FORMAT_REVISION {
                b"shadow-action-resolution-summary-v1"
            } else {
                b"shadow-action-resolution-summary-v2"
            },
        );
        hasher.field_u16(self.format_revision);
        hasher.field_u8(0);
        hasher.field_digest(self.request.digest());
        hasher.field_str(self.action_contract.as_str());
        hasher.field_digest(self.action_semantic_definition_digest);
        hasher.field_digest(self.action_validation_definition_digest);
        hasher.field_digest(self.output_contract_definition_digest);
        hasher.field_digest(self.validator_definition_digest);
        hasher.field_str(self.predicate.as_str());
        hasher.field_digest(self.repository_lineage);
        hasher.field_digest(self.semantic_world_digest);
        hasher.field_u8(match self.resolution {
            ShadowActionResolutionKind::Exact => 0,
            ShadowActionResolutionKind::Coverage => 1,
            ShadowActionResolutionKind::Composite => 2,
            ShadowActionResolutionKind::Partial => 3,
        });
        hasher.field_u16(self.artifacts.len() as u16);
        for index in 0..self.artifacts.len() {
            hasher.field_digest(self.artifacts[index].digest());
            if self.format_revision >= SHADOW_ACTION_RESOLUTION_FORMAT_REVISION {
                hasher.field_digest(self.artifact_matched_requests[index].digest());
            }
            hasher.field_digest(self.artifact_origin_requests[index].digest());
            hasher.field_digest(self.validation_certificates[index].digest());
        }
        hasher.field_digest(self.selected_plan.digest());
        match self.sufficiency_certificate {
            Some(certificate) => {
                hasher.field_u8(1);
                hasher.field_digest(certificate.digest());
            }
            None => hasher.field_u8(0),
        }
        hasher.field_u16(self.covered_mask);
        hasher.field_u16(self.missing_mask);
        hasher.finish()
    }
}

pub(crate) fn project_shadow_action_resolutions(
    input: ShadowActionResolutionProjectionInput<'_>,
) -> Result<Vec<ShadowActionResolutionSummary>, ShadowActionResolutionError> {
    if input.request.body.len() > MAX_NEED_IR_BYTES {
        return Err(ShadowActionResolutionError::RequestTextBound {
            actual: input.request.body.len(),
            maximum: MAX_NEED_IR_BYTES,
        });
    }
    if !input.fragment.is_consistent()
        || input.fragment.root_need != input.need.id
        || input.fragment.world != input.need.world
        || input.fragment.obligations != input.need.required
        || input.repository_id != input.need.world.repository_lineage
    {
        return Err(ShadowActionResolutionError::ProjectionNeed);
    }
    if input.plan.need != input.need.id
        || !input.plan.claim_ids.is_empty()
        || !input.plan.claim_validation_certificate_ids.is_empty()
        || !input.plan.claim_set_certificate_ids.is_empty()
        || input.plan.artifact_ids.is_empty()
        || input.plan.artifact_ids.len() > MAX_PROOF_ARTIFACTS
    {
        return Err(ShadowActionResolutionError::ProjectionPlan);
    }
    let required_mask = required_obligation_mask(input.need.required.len())
        .ok_or(ShadowActionResolutionError::ProjectionNeed)?;
    if input.plan.covered_mask & input.plan.missing_mask != 0
        || input.plan.covered_mask | input.plan.missing_mask != required_mask
        || (input.plan.missing_mask == 0) != input.sufficiency_certificate.is_some()
    {
        return Err(ShadowActionResolutionError::ProjectionPlan);
    }
    if input.descriptors.len() != input.plan.artifact_ids.len()
        || input.descriptors.is_empty()
        || input.descriptors.len() > MAX_PROOF_ARTIFACTS
    {
        return Err(ShadowActionResolutionError::ProjectionDescriptors);
    }

    let mut descriptor_artifacts =
        input.descriptors.iter().map(|descriptor| descriptor.artifact).collect::<Vec<_>>();
    descriptor_artifacts.sort_unstable();
    let mut plan_artifacts = input.plan.artifact_ids.clone();
    plan_artifacts.sort_unstable();
    let mut validation_certificates = input
        .descriptors
        .iter()
        .map(|descriptor| descriptor.validation_certificate)
        .collect::<Vec<_>>();
    validation_certificates.sort_unstable();
    if descriptor_artifacts != plan_artifacts
        || !descriptor_artifacts.windows(2).all(|pair| pair[0] < pair[1])
        || !validation_certificates.windows(2).all(|pair| pair[0] < pair[1])
        || input
            .descriptors
            .iter()
            .any(|descriptor| descriptor.semantic_world_digest != input.need.world.id())
    {
        return Err(ShadowActionResolutionError::ProjectionDescriptors);
    }

    let actions = built_in_action_contracts();
    let mut groups = vec![Vec::<ReuseDescriptor>::new(); actions.len()];
    for descriptor in input.descriptors {
        let index = actions
            .iter()
            .position(|action| action.contract.id == descriptor.action_contract)
            .ok_or(ShadowActionResolutionError::ProjectionDescriptors)?;
        groups[index].push(descriptor);
    }

    let mut summaries = Vec::with_capacity(actions.len());
    for (action, descriptors) in actions.iter().zip(groups) {
        if descriptors.is_empty() {
            continue;
        }
        let predicate =
            action.predicate().ok_or(ShadowActionResolutionError::ProjectionDescriptors)?;
        let action_mask = input
            .need
            .required
            .iter()
            .enumerate()
            .filter(|(_, obligation)| obligation.predicate == predicate)
            .fold(0_u16, |mask, (index, _)| mask | (1_u16 << index));
        let covered_mask = input.plan.covered_mask & action_mask;
        let missing_mask = input.plan.missing_mask & action_mask;
        let descriptor_coverage_mask = input
            .need
            .required
            .iter()
            .enumerate()
            .filter(|(_, requested)| requested.predicate == predicate)
            .filter(|(_, requested)| {
                descriptors.iter().any(|descriptor| {
                    descriptor
                        .coverage
                        .entries
                        .iter()
                        .any(|entry| entry.obligation.satisfies(requested))
                })
            })
            .fold(0_u16, |mask, (index, _)| mask | (1_u16 << index));
        if action_mask == 0 || covered_mask == 0 || descriptor_coverage_mask != covered_mask {
            return Err(ShadowActionResolutionError::ProjectionDescriptors);
        }

        let action_request = build_semantic_action_request(
            input.request,
            input.fragment,
            input.repository_id,
            input.source_snapshot_digest,
            action,
        )
        .map_err(|_| ShadowActionResolutionError::Request)?;
        let resolution = if missing_mask != 0 {
            ShadowActionResolutionKind::Partial
        } else if descriptors.len() > 1 {
            ShadowActionResolutionKind::Composite
        } else if descriptors[0].exact_request == action_request.semantic_id() {
            ShadowActionResolutionKind::Exact
        } else {
            ShadowActionResolutionKind::Coverage
        };
        summaries.push(ShadowActionResolutionSummary::new(ShadowActionResolutionInput {
            request: &action_request,
            action,
            resolution,
            descriptors: &descriptors,
            selected_plan: input.plan.id,
            sufficiency_certificate: input.sufficiency_certificate,
            covered_mask,
            missing_mask,
        })?);
    }
    if summaries.is_empty() {
        return Err(ShadowActionResolutionError::ProjectionDescriptors);
    }
    Ok(summaries)
}

fn required_obligation_mask(count: usize) -> Option<u16> {
    match count {
        1..=15 => Some((1_u16 << count) - 1),
        16 => Some(u16::MAX),
        _ => None,
    }
}

fn validate_action(action: &BuiltInActionDefinition) -> Result<(), ShadowActionResolutionError> {
    if action.initial_mode != CapabilityMode::Shadow
        || !action.contract.is_canonical()
        || crate::built_in_action_for_artifact_kind(action.artifact_kind()) != Some(action)
        || action.predicate().is_none()
    {
        return Err(ShadowActionResolutionError::ActionDefinition);
    }
    Ok(())
}

fn validate_request(
    request: &ActionRequest,
    action: &BuiltInActionDefinition,
) -> Result<ArtifactRequestId, ShadowActionResolutionError> {
    request.validate(&action.contract).map_err(|_| ShadowActionResolutionError::Request)?;
    if request.artifact_request.contract_id != action.output_contract_id
        || request.artifact_request.contract_revision != action.output_contract_revision
    {
        return Err(ShadowActionResolutionError::Request);
    }
    if request.artifact_request.semantic_fragment_id.is_none() {
        return Err(ShadowActionResolutionError::TypedRequest);
    }
    let request_bytes = request.artifact_request.normalized_request.len();
    if request_bytes > MAX_NEED_IR_BYTES {
        return Err(ShadowActionResolutionError::RequestTextBound {
            actual: request_bytes,
            maximum: MAX_NEED_IR_BYTES,
        });
    }
    let inputs = &request.artifact_request.input_artifact_ids;
    if inputs.iter().enumerate().any(|(index, input)| inputs[..index].contains(input)) {
        return Err(ShadowActionResolutionError::DuplicateRequestInput);
    }
    Ok(request.semantic_id())
}

#[derive(Debug, Error)]
pub enum ShadowActionResolutionError {
    #[error("built-in action definition is not canonical Shadow material")]
    ActionDefinition,
    #[error("action request does not match the built-in action definition")]
    Request,
    #[error("action resolution requires a typed semantic fragment")]
    TypedRequest,
    #[error("action resolution projection need or fragment is inconsistent")]
    ProjectionNeed,
    #[error("action resolution projection plan is inconsistent")]
    ProjectionPlan,
    #[error("action resolution projection descriptors are inconsistent")]
    ProjectionDescriptors,
    #[error("action request text contains {actual} bytes; the maximum is {maximum}")]
    RequestTextBound { actual: usize, maximum: usize },
    #[error("action request input artifact ids must be unique")]
    DuplicateRequestInput,
    #[error("action resolution contains {actual} descriptors; the maximum is {maximum}")]
    DescriptorBound { actual: usize, maximum: usize },
    #[error(transparent)]
    Descriptor(#[from] ReuseDescriptorError),
    #[error("reuse descriptor does not match the action definition")]
    DescriptorBinding,
    #[error("action resolution binding vectors have different cardinality")]
    BindingCardinality,
    #[error("action resolution artifact or certificate bindings are not ordered and unique")]
    Ordering,
    #[error("action resolution coverage masks are invalid")]
    Masks,
    #[error("action resolution kind, descriptor count, masks, or certificate are inconsistent")]
    ResolutionShape,
    #[error("action resolution format revision {0} is unsupported")]
    FormatRevision(u16),
    #[error("action resolution authority is not Shadow")]
    Authority,
    #[error("action resolution definition digest mismatch: expected {expected}, got {actual}")]
    DefinitionDigest { expected: Digest, actual: Digest },
}

fn deserialize_bounded_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVecVisitor<T>(PhantomData<T>);

    impl<'de, T> Visitor<'de> for BoundedVecVisitor<T>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_PROOF_ARTIFACTS} action resolution bindings")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let capacity = sequence.size_hint().unwrap_or(0).min(MAX_PROOF_ARTIFACTS);
            let mut values = Vec::with_capacity(capacity);
            while let Some(value) = sequence.next_element::<T>()? {
                if values.len() == MAX_PROOF_ARTIFACTS {
                    return Err(serde::de::Error::custom(
                        "action resolution binding bound exceeded",
                    ));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(BoundedVecVisitor(PhantomData))
}

pub(crate) fn deserialize_shadow_action_resolution_summaries<'de, D>(
    deserializer: D,
) -> Result<Vec<ShadowActionResolutionSummary>, D::Error>
where
    D: Deserializer<'de>,
{
    struct SummaryVisitor;

    impl<'de> Visitor<'de> for SummaryVisitor {
        type Value = Vec<ShadowActionResolutionSummary>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {BUILT_IN_ACTION_COUNT} Shadow action summaries")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let capacity = sequence.size_hint().unwrap_or(0).min(BUILT_IN_ACTION_COUNT);
            let mut summaries = Vec::with_capacity(capacity);
            let mut previous_action = None;
            while let Some(summary) = sequence.next_element::<ShadowActionResolutionSummary>()? {
                if summaries.len() == BUILT_IN_ACTION_COUNT {
                    return Err(serde::de::Error::custom("Shadow action summary bound exceeded"));
                }
                summary.validate().map_err(serde::de::Error::custom)?;
                let action_index = built_in_action_contracts()
                    .iter()
                    .position(|action| action.contract.id == summary.action_contract)
                    .ok_or_else(|| {
                        serde::de::Error::custom("unknown Shadow action summary contract")
                    })?;
                if previous_action.is_some_and(|previous| previous >= action_index) {
                    return Err(serde::de::Error::custom(
                        "Shadow action summaries must be ordered and unique",
                    ));
                }
                summaries.push(summary);
                previous_action = Some(action_index);
            }
            Ok(summaries)
        }
    }

    deserializer.deserialize_seq(SummaryVisitor)
}

#[cfg(test)]
mod tests;
