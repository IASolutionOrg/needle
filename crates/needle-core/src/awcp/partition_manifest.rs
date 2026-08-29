use super::{
    AWCP_PROTOCOL_REVISION, AwcpValidationError, MAX_AWCP_MESSAGE_BYTES, validate_revision,
};
use crate::{
    CanonicalHasher, CapabilityMode, Digest, MAX_PARTITION_MANIFEST_ENTRIES, ManifestClosure,
    PartitionManifest, PartitionManifestId, PartitionManifestValidationCertificate,
    PartitionPolicy, PartitionScheme,
};
use serde::{Deserialize, Serialize};

/// Provider-neutral bounded AWCP inspection projection for a server-certified
/// manifest. It is not a resolution result and cannot grant reuse authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwcpPartitionManifestProjection {
    pub protocol_revision: u16,
    pub manifest: PartitionManifestId,
    pub certificate: PartitionManifestValidationCertificate,
    pub closure: ManifestClosure,
    pub entry_count: u16,
    pub authority: CapabilityMode,
    pub definition_digest: Digest,
}

impl AwcpPartitionManifestProjection {
    pub fn new(
        manifest: &PartitionManifest,
        certificate: &PartitionManifestValidationCertificate,
        scheme: &PartitionScheme,
        policy: &PartitionPolicy,
    ) -> Result<Self, AwcpValidationError> {
        certificate
            .validate_against_manifest(manifest, scheme, policy)
            .map_err(|_| AwcpValidationError::PartitionManifestProjection)?;
        let entry_count = manifest
            .entries
            .len()
            .try_into()
            .map_err(|_| AwcpValidationError::PartitionManifestProjection)?;
        let mut value = Self {
            protocol_revision: AWCP_PROTOCOL_REVISION,
            manifest: manifest.id,
            certificate: certificate.clone(),
            closure: manifest.closure,
            entry_count,
            authority: CapabilityMode::Shadow,
            definition_digest: Digest([0; 32]),
        };
        value.definition_digest = value.compute_definition_digest();
        value.validate_shape()?;
        Ok(value)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, AwcpValidationError> {
        if bytes.len() > MAX_AWCP_MESSAGE_BYTES {
            return Err(AwcpValidationError::Bound {
                field: "partition_manifest_projection",
                actual: bytes.len(),
                maximum: MAX_AWCP_MESSAGE_BYTES,
            });
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| AwcpValidationError::PartitionManifestProjection)?;
        value.validate_shape()?;
        Ok(value)
    }

    pub fn validate_against_manifest(
        &self,
        manifest: &PartitionManifest,
        scheme: &PartitionScheme,
        policy: &PartitionPolicy,
    ) -> Result<(), AwcpValidationError> {
        self.validate_shape()?;
        self.certificate
            .validate_against_manifest(manifest, scheme, policy)
            .map_err(|_| AwcpValidationError::PartitionManifestProjection)?;
        if self.manifest != manifest.id
            || self.closure != manifest.closure
            || usize::from(self.entry_count) != manifest.entries.len()
        {
            return Err(AwcpValidationError::PartitionManifestProjection);
        }
        Ok(())
    }

    pub fn validate_shape(&self) -> Result<(), AwcpValidationError> {
        validate_revision(self.protocol_revision)?;
        self.certificate
            .validate()
            .map_err(|_| AwcpValidationError::PartitionManifestProjection)?;
        if self.authority != CapabilityMode::Shadow {
            return Err(AwcpValidationError::PartitionManifestAuthority);
        }
        if self.manifest != self.certificate.manifest
            || usize::from(self.entry_count) > MAX_PARTITION_MANIFEST_ENTRIES
        {
            return Err(AwcpValidationError::PartitionManifestProjection);
        }
        if self.definition_digest != self.compute_definition_digest() {
            return Err(AwcpValidationError::PartitionManifestDigest);
        }
        Ok(())
    }

    fn compute_definition_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"awcp-partition-manifest-projection-v1");
        hasher.field_u16(self.protocol_revision);
        hasher.field_digest(self.manifest.digest());
        hasher.field_digest(self.certificate.definition_digest);
        hasher.field_u8(match self.closure {
            ManifestClosure::Open => 0,
            ManifestClosure::Closed => 1,
        });
        hasher.field_u16(self.entry_count);
        hasher.field_u8(1);
        hasher.finish()
    }
}
