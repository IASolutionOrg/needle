use super::{
    ACTION_FORMAT_REVISION, ACTION_REQUEST_FORMAT_REVISION,
    ACTION_REQUEST_PARAMETERIZED_FORMAT_REVISION, ActionContract, ActionContractId,
    ActionValidationError, DispatchPolicy,
};
use crate::{
    ArtifactRequest, ArtifactRequestId, CanonicalHasher, Digest, MAX_NEED_INPUTS, NeedFragmentId,
    NeedId, NeedKey,
};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

/// Versioned action-native request envelope.
///
/// Revision 1 preserves the v0.4 artifact request identity for wire
/// compatibility. Revision 2 binds semantic demand to the action definition,
/// need fragment, and canonical semantic inputs while keeping execution and
/// freshness state outside that identity. Revision 3 additionally binds a
/// typed action-parameter digest without placing execution intent in Need
/// identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActionRequest {
    pub format_revision: u16,
    pub contract: ActionContractId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_semantic_definition_digest: Option<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_parameter_digest: Option<Digest>,
    pub artifact_request: ArtifactRequest,
    pub contract_operational_policy_digest: Digest,
    pub dispatch_policy: DispatchPolicy,
    pub effective_dispatch_policy_digest: Digest,
    pub route: NeedKey,
    pub root_need: NeedId,
}

impl ActionRequest {
    pub fn new(
        contract: &ActionContract,
        artifact_request: ArtifactRequest,
        dispatch_policy: DispatchPolicy,
        route: NeedKey,
        root_need: NeedId,
    ) -> Result<Self, ActionValidationError> {
        Self::build(
            ACTION_REQUEST_FORMAT_REVISION,
            contract,
            artifact_request,
            None,
            dispatch_policy,
            route,
            root_need,
        )
    }

    pub fn new_with_semantic_parameters(
        contract: &ActionContract,
        artifact_request: ArtifactRequest,
        semantic_parameter_digest: Digest,
        dispatch_policy: DispatchPolicy,
        route: NeedKey,
        root_need: NeedId,
    ) -> Result<Self, ActionValidationError> {
        if semantic_parameter_digest == Digest([0; 32]) {
            return Err(ActionValidationError::RequestSemanticParameterRequired);
        }
        Self::build(
            ACTION_REQUEST_PARAMETERIZED_FORMAT_REVISION,
            contract,
            artifact_request,
            Some(semantic_parameter_digest),
            dispatch_policy,
            route,
            root_need,
        )
    }

    fn build(
        format_revision: u16,
        contract: &ActionContract,
        artifact_request: ArtifactRequest,
        semantic_parameter_digest: Option<Digest>,
        dispatch_policy: DispatchPolicy,
        route: NeedKey,
        root_need: NeedId,
    ) -> Result<Self, ActionValidationError> {
        contract.validate()?;
        validate_request_inputs(&artifact_request, true)?;
        if artifact_request.semantic_fragment_id.is_none() {
            return Err(ActionValidationError::RequestSemanticFragmentRequired);
        }
        validate_route("route", &route)?;
        validate_route("artifact_request.route_key", &artifact_request.route_key)?;
        contract.validate_dispatch_policy(dispatch_policy)?;
        let effective_dispatch_policy_digest = effective_dispatch_digest(
            format_revision,
            contract.operational_policy_digest,
            dispatch_policy,
        );
        Ok(Self {
            format_revision,
            contract: contract.id.clone(),
            contract_semantic_definition_digest: Some(contract.semantic_definition_digest),
            semantic_parameter_digest,
            artifact_request,
            contract_operational_policy_digest: contract.operational_policy_digest,
            dispatch_policy,
            effective_dispatch_policy_digest,
            route,
            root_need,
        })
    }

    pub fn semantic_id(&self) -> ArtifactRequestId {
        if self.format_revision == ACTION_FORMAT_REVISION {
            return self.legacy_semantic_id();
        }

        let mut hasher = if self.format_revision == ACTION_REQUEST_PARAMETERIZED_FORMAT_REVISION {
            CanonicalHasher::new(b"action-request-semantic-v3")
        } else {
            CanonicalHasher::new(b"action-request-semantic-v2")
        };
        hasher.field_u16(self.format_revision);
        match self.contract_semantic_definition_digest {
            Some(digest) => {
                hasher.field_u8(1);
                hasher.field_digest(digest);
            }
            None => hasher.field_u8(0),
        }
        match self.artifact_request.semantic_fragment_id {
            Some(fragment) => {
                hasher.field_u8(1);
                hasher.field_digest(fragment.digest());
            }
            None => hasher.field_u8(0),
        }
        if self.format_revision == ACTION_REQUEST_PARAMETERIZED_FORMAT_REVISION {
            match self.semantic_parameter_digest {
                Some(digest) => {
                    hasher.field_u8(1);
                    hasher.field_digest(digest);
                }
                None => hasher.field_u8(0),
            }
        }
        hasher.field_u16(self.artifact_request.input_artifact_ids.len() as u16);
        for input in &self.artifact_request.input_artifact_ids {
            hasher.field_digest(*input);
        }
        ArtifactRequestId::new(hasher.finish())
    }

    /// Frozen v0.4 request identity used only for compatibility mappings.
    pub fn legacy_semantic_id(&self) -> ArtifactRequestId {
        self.artifact_request.semantic_id()
    }

    pub fn validate(&self, contract: &ActionContract) -> Result<(), ActionValidationError> {
        contract.validate()?;
        if self.contract != contract.id {
            return Err(ActionValidationError::RequestContractMismatch);
        }
        match self.format_revision {
            ACTION_FORMAT_REVISION => {
                if self.contract_semantic_definition_digest.is_some()
                    || self.semantic_parameter_digest.is_some()
                {
                    return Err(ActionValidationError::RequestSemanticPolicyMismatch);
                }
                validate_request_inputs(&self.artifact_request, false)?;
            }
            ACTION_REQUEST_FORMAT_REVISION => {
                if self.contract_semantic_definition_digest
                    != Some(contract.semantic_definition_digest)
                {
                    return Err(ActionValidationError::RequestSemanticPolicyMismatch);
                }
                if self.artifact_request.semantic_fragment_id.is_none() {
                    return Err(ActionValidationError::RequestSemanticFragmentRequired);
                }
                validate_request_inputs(&self.artifact_request, true)?;
                if self.semantic_parameter_digest.is_some() {
                    return Err(ActionValidationError::RequestSemanticParameterMismatch);
                }
            }
            ACTION_REQUEST_PARAMETERIZED_FORMAT_REVISION => {
                if self.contract_semantic_definition_digest
                    != Some(contract.semantic_definition_digest)
                {
                    return Err(ActionValidationError::RequestSemanticPolicyMismatch);
                }
                if self.artifact_request.semantic_fragment_id.is_none() {
                    return Err(ActionValidationError::RequestSemanticFragmentRequired);
                }
                validate_request_inputs(&self.artifact_request, true)?;
                if self.semantic_parameter_digest.is_none()
                    || self.semantic_parameter_digest == Some(Digest([0; 32]))
                {
                    return Err(ActionValidationError::RequestSemanticParameterRequired);
                }
            }
            revision => return Err(ActionValidationError::FormatRevision(revision)),
        }
        if self.contract_operational_policy_digest != contract.operational_policy_digest {
            return Err(ActionValidationError::RequestOperationalPolicyMismatch);
        }
        validate_route("route", &self.route)?;
        validate_route("artifact_request.route_key", &self.artifact_request.route_key)?;
        contract.validate_dispatch_policy(self.dispatch_policy)?;
        let expected = effective_dispatch_digest(
            self.format_revision,
            self.contract_operational_policy_digest,
            self.dispatch_policy,
        );
        if self.effective_dispatch_policy_digest != expected {
            return Err(ActionValidationError::EffectiveDispatchPolicyMismatch);
        }
        Ok(())
    }

    pub fn is_canonical(&self, contract: &ActionContract) -> bool {
        self.validate(contract).is_ok()
    }
}

fn validate_route(field: &'static str, route: &NeedKey) -> Result<(), ActionValidationError> {
    let bytes = route.as_str().as_bytes();
    let canonical = !bytes.is_empty()
        && bytes.len() <= 64
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(*byte, b'.' | b'_' | b'-')
        });
    if canonical { Ok(()) } else { Err(ActionValidationError::RequestRoute { field }) }
}

fn validate_request_inputs(
    request: &ArtifactRequest,
    require_canonical: bool,
) -> Result<(), ActionValidationError> {
    if request.input_artifact_ids.len() > MAX_NEED_INPUTS {
        return Err(ActionValidationError::RequestInputBound {
            actual: request.input_artifact_ids.len(),
            maximum: MAX_NEED_INPUTS,
        });
    }
    if require_canonical && request.input_artifact_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ActionValidationError::RequestInputsNotCanonical);
    }
    Ok(())
}

fn effective_dispatch_digest(
    format_revision: u16,
    contract_operational_policy_digest: Digest,
    dispatch_policy: DispatchPolicy,
) -> Digest {
    let mut hasher = CanonicalHasher::new(b"action-request-effective-dispatch-v1");
    hasher.field_u16(format_revision);
    hasher.field_digest(contract_operational_policy_digest);
    hasher.field_digest(dispatch_policy.digest());
    hasher.finish()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionRequestWire {
    format_revision: u16,
    contract: ActionContractId,
    #[serde(default)]
    contract_semantic_definition_digest: Option<Digest>,
    #[serde(default)]
    semantic_parameter_digest: Option<Digest>,
    #[serde(deserialize_with = "deserialize_artifact_request")]
    artifact_request: ArtifactRequest,
    contract_operational_policy_digest: Digest,
    dispatch_policy: DispatchPolicy,
    effective_dispatch_policy_digest: Digest,
    route: NeedKey,
    root_need: NeedId,
}

impl<'de> Deserialize<'de> for ActionRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ActionRequestWire::deserialize(deserializer)?;
        Ok(Self {
            format_revision: wire.format_revision,
            contract: wire.contract,
            contract_semantic_definition_digest: wire.contract_semantic_definition_digest,
            semantic_parameter_digest: wire.semantic_parameter_digest,
            artifact_request: wire.artifact_request,
            contract_operational_policy_digest: wire.contract_operational_policy_digest,
            dispatch_policy: wire.dispatch_policy,
            effective_dispatch_policy_digest: wire.effective_dispatch_policy_digest,
            route: wire.route,
            root_need: wire.root_need,
        })
    }
}

fn deserialize_artifact_request<'de, D>(deserializer: D) -> Result<ArtifactRequest, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ArtifactRequestWire {
        contract_id: String,
        contract_revision: u32,
        repository_id: Digest,
        source_snapshot_digest: Digest,
        route_key: NeedKey,
        normalized_request: String,
        #[serde(default)]
        semantic_fragment_id: Option<NeedFragmentId>,
        #[serde(deserialize_with = "deserialize_input_artifact_ids")]
        input_artifact_ids: Vec<Digest>,
    }

    let wire = ArtifactRequestWire::deserialize(deserializer)?;
    Ok(ArtifactRequest {
        contract_id: wire.contract_id,
        contract_revision: wire.contract_revision,
        repository_id: wire.repository_id,
        source_snapshot_digest: wire.source_snapshot_digest,
        route_key: wire.route_key,
        normalized_request: wire.normalized_request,
        semantic_fragment_id: wire.semantic_fragment_id,
        input_artifact_ids: wire.input_artifact_ids,
    })
}

fn deserialize_input_artifact_ids<'de, D>(deserializer: D) -> Result<Vec<Digest>, D::Error>
where
    D: Deserializer<'de>,
{
    struct InputArtifactIdsVisitor;

    impl<'de> Visitor<'de> for InputArtifactIdsVisitor {
        type Value = Vec<Digest>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_NEED_INPUTS} input artifact ids")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let capacity = sequence.size_hint().unwrap_or(0).min(MAX_NEED_INPUTS);
            let mut inputs = Vec::with_capacity(capacity);
            while let Some(input) = sequence.next_element::<Digest>()? {
                if inputs.len() == MAX_NEED_INPUTS {
                    return Err(serde::de::Error::custom(
                        ActionValidationError::RequestInputBound {
                            actual: MAX_NEED_INPUTS + 1,
                            maximum: MAX_NEED_INPUTS,
                        },
                    ));
                }
                inputs.push(input);
            }
            Ok(inputs)
        }
    }

    deserializer.deserialize_seq(InputArtifactIdsVisitor)
}
