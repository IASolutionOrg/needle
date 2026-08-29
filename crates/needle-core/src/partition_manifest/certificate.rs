use super::*;
use crate::CapabilityMode;

pub const PARTITION_MANIFEST_CERTIFICATE_FORMAT_REVISION: u16 = 1;
pub const MAX_PARTITION_MANIFEST_CERTIFICATE_WIRE_BYTES: usize = 32 * 1024;

/// Immutable evidence that a server-side validator accepted a manifest while
/// the partition capability was still Shadow-only. This record is audit
/// evidence; it never grants reuse authority by itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionManifestValidationCertificate {
    pub format_revision: u16,
    pub id: PartitionManifestValidationCertificateId,
    pub manifest: PartitionManifestId,
    pub manifest_definition_digest: Digest,
    pub action_request: ArtifactRequestId,
    #[serde(deserialize_with = "wire::deserialize_action_contract")]
    pub action_contract: ActionContractId,
    #[serde(deserialize_with = "wire::deserialize_output_contract")]
    pub output_contract: String,
    pub scheme: PartitionSchemeId,
    pub partition_policy: PartitionPolicyId,
    pub scheme_definition_digest: Digest,
    pub policy_definition_digest: Digest,
    pub declared_policy_authority_digest: Digest,
    pub manifest_validator: ValidatorId,
    pub validator_definition_digest: Digest,
    pub adapter_definition_digest: Digest,
    pub semantic_input_set_digest: Digest,
    pub semantic_world_digest: Digest,
    pub repository: Digest,
    #[serde(deserialize_with = "wire::deserialize_source_selector")]
    pub source_selector: String,
    pub source_payload_digest: Digest,
    pub source_validation_certificate_digest: Digest,
    pub definition_set_digest: Digest,
    pub issued_mode: CapabilityMode,
    pub issued_unix_ms: u64,
    pub definition_digest: Digest,
}

impl PartitionManifestValidationCertificate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        manifest: &PartitionManifest,
        scheme: &PartitionScheme,
        policy: &PartitionPolicy,
        declared_policy_authority_digest: Digest,
        validator_definition_digest: Digest,
        adapter_definition_digest: Digest,
        source_payload_digest: Digest,
        source_validation_certificate_digest: Digest,
        issued_unix_ms: u64,
    ) -> Result<Self, PartitionManifestError> {
        policy.accepts(manifest, scheme)?;
        let mut value = Self {
            format_revision: PARTITION_MANIFEST_CERTIFICATE_FORMAT_REVISION,
            id: PartitionManifestValidationCertificateId::new(zero_digest()),
            manifest: manifest.id,
            manifest_definition_digest: manifest.definition_digest,
            action_request: manifest.binding.action_request,
            action_contract: manifest.binding.action_contract.clone(),
            output_contract: manifest.binding.output_contract.clone(),
            scheme: scheme.id.clone(),
            partition_policy: policy.id.clone(),
            scheme_definition_digest: scheme.definition_digest,
            policy_definition_digest: policy.definition_digest,
            declared_policy_authority_digest,
            manifest_validator: policy.manifest_validator.clone(),
            validator_definition_digest,
            adapter_definition_digest,
            semantic_input_set_digest: manifest.binding.semantic_input_set_digest,
            semantic_world_digest: manifest.binding.semantic_world_digest,
            repository: manifest.binding.repository,
            source_selector: manifest.binding.source_selector.clone(),
            source_payload_digest,
            source_validation_certificate_digest,
            definition_set_digest: manifest.binding.definition_set_digest,
            issued_mode: CapabilityMode::Shadow,
            issued_unix_ms,
            definition_digest: zero_digest(),
        };
        value.validate_shape()?;
        value.definition_digest = value.compute_definition_digest();
        value.id = compute_certificate_id(value.definition_digest);
        Ok(value)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, PartitionManifestError> {
        if bytes.len() > MAX_PARTITION_MANIFEST_CERTIFICATE_WIRE_BYTES {
            return Err(PartitionManifestError::Bound {
                field: "partition_manifest_certificate.wire_bytes",
                actual: bytes.len(),
                maximum: MAX_PARTITION_MANIFEST_CERTIFICATE_WIRE_BYTES,
            });
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| PartitionManifestError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), PartitionManifestError> {
        self.validate_shape()?;
        let definition_digest = self.compute_definition_digest();
        validate_digest(
            "partition_manifest_certificate.definition_digest",
            self.definition_digest,
            definition_digest,
        )?;
        let expected = compute_certificate_id(definition_digest);
        if self.id != expected {
            return Err(PartitionManifestError::IdentifierDigest {
                field: "partition_manifest_certificate.id",
                expected: expected.digest(),
                actual: self.id.digest(),
            });
        }
        Ok(())
    }

    pub fn validate_against_manifest(
        &self,
        manifest: &PartitionManifest,
        scheme: &PartitionScheme,
        policy: &PartitionPolicy,
    ) -> Result<(), PartitionManifestError> {
        self.validate()?;
        policy.accepts(manifest, scheme)?;
        if self.manifest != manifest.id
            || self.manifest_definition_digest != manifest.definition_digest
            || self.action_request != manifest.binding.action_request
            || self.action_contract != manifest.binding.action_contract
            || self.output_contract != manifest.binding.output_contract
            || self.scheme != scheme.id
            || self.partition_policy != policy.id
            || self.scheme_definition_digest != scheme.definition_digest
            || self.policy_definition_digest != policy.definition_digest
            || self.manifest_validator != policy.manifest_validator
            || self.semantic_input_set_digest != manifest.binding.semantic_input_set_digest
            || self.semantic_world_digest != manifest.binding.semantic_world_digest
            || self.repository != manifest.binding.repository
            || self.source_selector != manifest.binding.source_selector
            || self.definition_set_digest != manifest.binding.definition_set_digest
        {
            return Err(PartitionManifestError::CertificateBinding);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), PartitionManifestError> {
        if self.format_revision != PARTITION_MANIFEST_CERTIFICATE_FORMAT_REVISION {
            return Err(PartitionManifestError::FormatRevision {
                record: "partition_manifest_certificate",
                actual: self.format_revision,
            });
        }
        if self.issued_mode != CapabilityMode::Shadow {
            return Err(PartitionManifestError::CertificateAuthority);
        }
        validate_identifier(
            "partition_manifest_certificate.output_contract",
            &self.output_contract,
        )?;
        validate_text(
            "partition_manifest_certificate.source_selector",
            &self.source_selector,
            MAX_PARTITION_SOURCE_SELECTOR_BYTES,
            false,
        )
    }

    fn compute_definition_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"partition-manifest-validation-certificate-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.manifest.digest());
        hasher.field_digest(self.manifest_definition_digest);
        hasher.field_digest(self.action_request.digest());
        hasher.field_str(self.action_contract.as_str());
        hasher.field_str(&self.output_contract);
        hasher.field_str(self.scheme.as_str());
        hasher.field_str(self.partition_policy.as_str());
        hasher.field_digest(self.scheme_definition_digest);
        hasher.field_digest(self.policy_definition_digest);
        hasher.field_digest(self.declared_policy_authority_digest);
        hasher.field_str(self.manifest_validator.as_str());
        hasher.field_digest(self.validator_definition_digest);
        hasher.field_digest(self.adapter_definition_digest);
        hasher.field_digest(self.semantic_input_set_digest);
        hasher.field_digest(self.semantic_world_digest);
        hasher.field_digest(self.repository);
        hasher.field_str(&self.source_selector);
        hasher.field_digest(self.source_payload_digest);
        hasher.field_digest(self.source_validation_certificate_digest);
        hasher.field_digest(self.definition_set_digest);
        hasher.field_u8(1);
        hasher.field_bytes(&self.issued_unix_ms.to_le_bytes());
        hasher.finish()
    }
}

fn compute_certificate_id(definition_digest: Digest) -> PartitionManifestValidationCertificateId {
    let mut hasher = CanonicalHasher::new(b"partition-manifest-validation-certificate-id-v1");
    hasher.field_digest(definition_digest);
    PartitionManifestValidationCertificateId::new(hasher.finish())
}
