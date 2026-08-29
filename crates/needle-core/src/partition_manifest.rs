use crate::{
    ActionContractId, ArtifactId, ArtifactRequestId, CanonicalHasher, CoverageManifest, Digest,
    MAX_NEED_INPUTS, MAX_NEED_IR_BYTES, MAX_OBLIGATION_FACETS, MAX_REQUIRED_OBLIGATIONS,
    MAX_REUSE_DESCRIPTOR_EVIDENCE_PER_ENTRY, Obligation, ReuseMode,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

mod wire;

#[cfg(test)]
mod tests;

pub const PARTITION_MANIFEST_FORMAT_REVISION: u16 = 1;
pub const MANIFEST_TRANSITION_FORMAT_REVISION: u16 = 1;
pub const MAX_PARTITION_MANIFEST_WIRE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PARTITION_MANIFEST_ENTRIES: usize = 4_096;
pub const MAX_PARTITION_TRANSITION_MAPPINGS: usize = 4_096;
pub const MAX_PARTITION_KEY_BYTES: usize = 1_024;
pub const MAX_PARTITION_DISPLAY_BYTES: usize = 256;
pub const MAX_PARTITION_IDENTIFIER_BYTES: usize = 128;
pub const MAX_PARTITION_SOURCE_SELECTOR_BYTES: usize = 2_048;
pub const MAX_PARTITION_PROVENANCE_PARENTS: usize = 16;
pub const MAX_PARTITION_POLICY_SCHEMES: usize = 32;

macro_rules! digest_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Digest);

        impl $name {
            pub const fn new(digest: Digest) -> Self {
                Self(digest)
            }

            pub const fn digest(self) -> Digest {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

macro_rules! string_id {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, PartitionManifestError> {
                let value = value.into();
                validate_identifier($label, &value)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = wire::deserialize_bounded_identifier(deserializer, $label)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

digest_id!(PartitionManifestId);
digest_id!(PartitionManifestValidationCertificateId);
digest_id!(ManifestTransitionId);
digest_id!(DerivationRuleId);
digest_id!(ProjectionId);

mod certificate;

pub use certificate::*;

string_id!(PartitionSchemeId, "partition_scheme.id");
string_id!(PartitionPolicyId, "partition_policy.id");
string_id!(ProviderId, "partition_provider.id");
string_id!(SchemaId, "partition_schema.id");
string_id!(ValidatorId, "partition_validator.id");

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PartitionSchemeKind {
    ContractDefined,
    ProducerAuthored,
    ProviderDefined { provider: ProviderId },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionKeyScope {
    ManifestLocal,
    LineageStable,
    ProviderStable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionScheme {
    pub id: PartitionSchemeId,
    pub kind: PartitionSchemeKind,
    pub key_scope: PartitionKeyScope,
    pub key_schema: SchemaId,
    pub maximum_key_bytes: u16,
    pub definition_digest: Digest,
}

impl PartitionScheme {
    pub fn new(
        id: PartitionSchemeId,
        kind: PartitionSchemeKind,
        key_scope: PartitionKeyScope,
        key_schema: SchemaId,
        maximum_key_bytes: u16,
    ) -> Result<Self, PartitionManifestError> {
        let mut value = Self {
            id,
            kind,
            key_scope,
            key_schema,
            maximum_key_bytes,
            definition_digest: zero_digest(),
        };
        value.validate_shape()?;
        value.definition_digest = value.compute_definition_digest();
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), PartitionManifestError> {
        self.validate_shape()?;
        validate_digest(
            "partition_scheme.definition_digest",
            self.definition_digest,
            self.compute_definition_digest(),
        )
    }

    pub fn is_canonical(&self) -> bool {
        self.validate().is_ok()
    }

    fn validate_shape(&self) -> Result<(), PartitionManifestError> {
        validate_identifier("partition_scheme.id", self.id.as_str())?;
        validate_identifier("partition_scheme.key_schema", self.key_schema.as_str())?;
        if let PartitionSchemeKind::ProviderDefined { provider } = &self.kind {
            validate_identifier("partition_scheme.provider", provider.as_str())?;
        }
        let maximum = usize::from(self.maximum_key_bytes);
        if maximum == 0 || maximum > MAX_PARTITION_KEY_BYTES {
            return Err(PartitionManifestError::Bound {
                field: "partition_scheme.maximum_key_bytes",
                actual: maximum,
                maximum: MAX_PARTITION_KEY_BYTES,
            });
        }
        Ok(())
    }

    fn compute_definition_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"partition-scheme-definition-v1");
        hasher.field_str(self.id.as_str());
        hash_scheme_kind(&mut hasher, &self.kind);
        hasher.field_u8(match self.key_scope {
            PartitionKeyScope::ManifestLocal => 0,
            PartitionKeyScope::LineageStable => 1,
            PartitionKeyScope::ProviderStable => 2,
        });
        hasher.field_str(self.key_schema.as_str());
        hasher.field_u16(self.maximum_key_bytes);
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionDisplay {
    #[serde(deserialize_with = "wire::deserialize_partition_display")]
    pub label: String,
}

impl PartitionDisplay {
    pub fn new(label: impl Into<String>) -> Result<Self, PartitionManifestError> {
        let label = label.into();
        validate_text("partition_key.display", &label, MAX_PARTITION_DISPLAY_BYTES, false)?;
        Ok(Self { label })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpaquePartitionKey {
    pub scheme: PartitionSchemeId,
    #[serde(deserialize_with = "wire::deserialize_partition_key_bytes")]
    pub value: Vec<u8>,
    pub digest: Digest,
    pub display: Option<PartitionDisplay>,
}

impl OpaquePartitionKey {
    pub fn new(
        scheme: &PartitionScheme,
        value: Vec<u8>,
        display: Option<PartitionDisplay>,
    ) -> Result<Self, PartitionManifestError> {
        scheme.validate()?;
        validate_key_bytes(&value, usize::from(scheme.maximum_key_bytes))?;
        let digest = compute_partition_key_digest(&scheme.id, &value);
        Ok(Self { scheme: scheme.id.clone(), value, digest, display })
    }

    pub fn validate_against_scheme(
        &self,
        scheme: &PartitionScheme,
    ) -> Result<(), PartitionManifestError> {
        scheme.validate()?;
        if self.scheme != scheme.id {
            return Err(PartitionManifestError::SchemeMismatch);
        }
        validate_key_bytes(&self.value, usize::from(scheme.maximum_key_bytes))?;
        if let Some(display) = &self.display {
            validate_text(
                "partition_key.display",
                &display.label,
                MAX_PARTITION_DISPLAY_BYTES,
                false,
            )?;
        }
        validate_digest(
            "partition_key.digest",
            self.digest,
            compute_partition_key_digest(&self.scheme, &self.value),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SemanticInputBinding {
    ByRequest { request: ArtifactRequestId },
    ByArtifact { artifact: ArtifactId },
    ByProjection { artifact: ArtifactId, projection: ProjectionId },
}

pub fn semantic_input_set_digest(
    bindings: &[SemanticInputBinding],
) -> Result<Digest, PartitionManifestError> {
    validate_canonical_set("semantic_input_bindings", bindings, MAX_NEED_INPUTS, true)?;
    let mut hasher = CanonicalHasher::new(b"partition-semantic-input-set-v1");
    hasher.field_u16(bindings.len().try_into().unwrap_or(u16::MAX));
    for binding in bindings {
        hash_semantic_input_binding(&mut hasher, binding);
    }
    Ok(hasher.finish())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestBinding {
    pub action_request: ArtifactRequestId,
    #[serde(deserialize_with = "wire::deserialize_action_contract")]
    pub action_contract: ActionContractId,
    #[serde(deserialize_with = "wire::deserialize_output_contract")]
    pub output_contract: String,
    pub semantic_input_set_digest: Digest,
    pub semantic_world_digest: Digest,
    pub repository: Digest,
    #[serde(deserialize_with = "wire::deserialize_source_selector")]
    pub source_selector: String,
    pub definition_set_digest: Digest,
}

impl ManifestBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        action_request: ArtifactRequestId,
        action_contract: ActionContractId,
        output_contract: impl Into<String>,
        semantic_input_set_digest: Digest,
        semantic_world_digest: Digest,
        repository: Digest,
        source_selector: impl Into<String>,
        definition_set_digest: Digest,
    ) -> Result<Self, PartitionManifestError> {
        let value = Self {
            action_request,
            action_contract,
            output_contract: output_contract.into(),
            semantic_input_set_digest,
            semantic_world_digest,
            repository,
            source_selector: source_selector.into(),
            definition_set_digest,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), PartitionManifestError> {
        validate_identifier("manifest_binding.output_contract", &self.output_contract)?;
        validate_text(
            "manifest_binding.source_selector",
            &self.source_selector,
            MAX_PARTITION_SOURCE_SELECTOR_BYTES,
            false,
        )
    }

    pub fn digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"partition-manifest-binding-v1");
        hasher.field_digest(self.action_request.digest());
        hasher.field_str(self.action_contract.as_str());
        hasher.field_str(&self.output_contract);
        hasher.field_digest(self.semantic_input_set_digest);
        hasher.field_digest(self.semantic_world_digest);
        hasher.field_digest(self.repository);
        hasher.field_str(&self.source_selector);
        hasher.field_digest(self.definition_set_digest);
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManifestProvenance {
    RequestBound {
        request: ArtifactRequestId,
    },
    ProducerAuthored {
        attempt: Digest,
    },
    ProviderAttested {
        provider: ProviderId,
        attestation: Digest,
    },
    Derived {
        rule: DerivationRuleId,
        #[serde(deserialize_with = "wire::deserialize_provenance_parents")]
        parents: Vec<PartitionManifestId>,
    },
}

impl ManifestProvenance {
    pub fn derived(
        rule: DerivationRuleId,
        mut parents: Vec<PartitionManifestId>,
    ) -> Result<Self, PartitionManifestError> {
        parents.sort_unstable();
        let value = Self::Derived { rule, parents };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), PartitionManifestError> {
        match self {
            Self::ProviderAttested { provider, .. } => {
                validate_identifier("manifest_provenance.provider", provider.as_str())
            }
            Self::Derived { parents, .. } => validate_canonical_set(
                "manifest_provenance.parents",
                parents,
                MAX_PARTITION_PROVENANCE_PARENTS,
                false,
            ),
            Self::RequestBound { .. } | Self::ProducerAuthored { .. } => Ok(()),
        }
    }

    fn hash_into(&self, hasher: &mut CanonicalHasher) {
        match self {
            Self::RequestBound { request } => {
                hasher.field_u8(0);
                hasher.field_digest(request.digest());
            }
            Self::ProducerAuthored { attempt } => {
                hasher.field_u8(1);
                hasher.field_digest(*attempt);
            }
            Self::ProviderAttested { provider, attestation } => {
                hasher.field_u8(2);
                hasher.field_str(provider.as_str());
                hasher.field_digest(*attestation);
            }
            Self::Derived { rule, parents } => {
                hasher.field_u8(3);
                hasher.field_digest(rule.digest());
                hasher.field_u16(parents.len().try_into().unwrap_or(u16::MAX));
                for parent in parents {
                    hasher.field_digest(parent.digest());
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestClosure {
    Open,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionRole {
    Component,
    Aggregate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionEntry {
    pub key: OpaquePartitionKey,
    pub role: PartitionRole,
    pub payload_digest: Digest,
    #[serde(deserialize_with = "wire::deserialize_coverage")]
    pub coverage: CoverageManifest,
    pub dependencies: Digest,
    #[serde(deserialize_with = "wire::deserialize_semantic_input_bindings")]
    pub semantic_input_bindings: Vec<SemanticInputBinding>,
    #[serde(deserialize_with = "wire::deserialize_validated_input_artifacts")]
    pub validated_input_artifacts: Vec<ArtifactId>,
}

impl PartitionEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: OpaquePartitionKey,
        role: PartitionRole,
        payload_digest: Digest,
        coverage: CoverageManifest,
        dependencies: Digest,
        mut semantic_input_bindings: Vec<SemanticInputBinding>,
        mut validated_input_artifacts: Vec<ArtifactId>,
    ) -> Result<Self, PartitionManifestError> {
        semantic_input_bindings.sort_unstable();
        validated_input_artifacts.sort_unstable();
        let value = Self {
            key,
            role,
            payload_digest,
            coverage,
            dependencies,
            semantic_input_bindings,
            validated_input_artifacts,
        };
        value.validate_shape()?;
        Ok(value)
    }

    fn validate_shape(&self) -> Result<(), PartitionManifestError> {
        validate_canonical_set(
            "partition_entry.semantic_input_bindings",
            &self.semantic_input_bindings,
            MAX_NEED_INPUTS,
            true,
        )?;
        validate_canonical_set(
            "partition_entry.validated_input_artifacts",
            &self.validated_input_artifacts,
            MAX_NEED_INPUTS,
            true,
        )?;
        if self.dependencies != self.coverage.dependency_manifest_digest {
            return Err(PartitionManifestError::Coverage(
                "entry dependency digest differs from coverage dependency digest".to_owned(),
            ));
        }
        validate_partition_coverage(&self.coverage)
    }

    fn hash_into(&self, hasher: &mut CanonicalHasher) {
        hasher.field_str(self.key.scheme.as_str());
        hasher.field_bytes(&self.key.value);
        hasher.field_digest(self.key.digest);
        hasher.field_u8(match self.role {
            PartitionRole::Component => 0,
            PartitionRole::Aggregate => 1,
        });
        hasher.field_digest(self.payload_digest);
        hasher.field_digest(coverage_digest(&self.coverage));
        hasher.field_digest(self.dependencies);
        hasher.field_u16(self.semantic_input_bindings.len().try_into().unwrap_or(u16::MAX));
        for binding in &self.semantic_input_bindings {
            hash_semantic_input_binding(hasher, binding);
        }
        hasher.field_u16(self.validated_input_artifacts.len().try_into().unwrap_or(u16::MAX));
        for artifact in &self.validated_input_artifacts {
            hasher.field_digest(artifact.digest());
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionManifest {
    pub format_revision: u16,
    pub id: PartitionManifestId,
    pub scheme: PartitionSchemeId,
    pub binding: ManifestBinding,
    pub provenance: ManifestProvenance,
    pub closure: ManifestClosure,
    #[serde(deserialize_with = "wire::deserialize_manifest_entries")]
    pub entries: Vec<PartitionEntry>,
    pub aggregate_derivation: Option<DerivationRuleId>,
    pub definition_digest: Digest,
}

impl PartitionManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scheme: &PartitionScheme,
        binding: ManifestBinding,
        provenance: ManifestProvenance,
        closure: ManifestClosure,
        mut entries: Vec<PartitionEntry>,
        aggregate_derivation: Option<DerivationRuleId>,
    ) -> Result<Self, PartitionManifestError> {
        entries.sort_unstable_by_key(|entry| entry.key.digest);
        let mut value = Self {
            format_revision: PARTITION_MANIFEST_FORMAT_REVISION,
            id: PartitionManifestId::new(zero_digest()),
            scheme: scheme.id.clone(),
            binding,
            provenance,
            closure,
            entries,
            aggregate_derivation,
            definition_digest: zero_digest(),
        };
        value.validate_shape(scheme)?;
        value.definition_digest = value.compute_definition_digest();
        value.id = compute_manifest_id(value.definition_digest);
        Ok(value)
    }

    pub fn decode_json(
        bytes: &[u8],
        scheme: &PartitionScheme,
    ) -> Result<Self, PartitionManifestError> {
        if bytes.len() > MAX_PARTITION_MANIFEST_WIRE_BYTES {
            return Err(PartitionManifestError::Bound {
                field: "partition_manifest.wire_bytes",
                actual: bytes.len(),
                maximum: MAX_PARTITION_MANIFEST_WIRE_BYTES,
            });
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| PartitionManifestError::Json(error.to_string()))?;
        value.validate_against_scheme(scheme)?;
        Ok(value)
    }

    pub fn validate_against_scheme(
        &self,
        scheme: &PartitionScheme,
    ) -> Result<(), PartitionManifestError> {
        self.validate_shape(scheme)?;
        let definition_digest = self.compute_definition_digest();
        validate_digest(
            "partition_manifest.definition_digest",
            self.definition_digest,
            definition_digest,
        )?;
        let id = compute_manifest_id(definition_digest);
        if self.id != id {
            return Err(PartitionManifestError::IdentifierDigest {
                field: "partition_manifest.id",
                expected: id.digest(),
                actual: self.id.digest(),
            });
        }
        Ok(())
    }

    pub fn is_canonical(&self, scheme: &PartitionScheme) -> bool {
        self.validate_against_scheme(scheme).is_ok()
    }

    pub fn contains(&self, partition: &PartitionRef) -> bool {
        partition.manifest == self.id
            && self
                .entries
                .binary_search_by_key(&partition.key_digest, |entry| entry.key.digest)
                .is_ok()
    }

    fn validate_shape(&self, scheme: &PartitionScheme) -> Result<(), PartitionManifestError> {
        if self.format_revision != PARTITION_MANIFEST_FORMAT_REVISION {
            return Err(PartitionManifestError::FormatRevision {
                record: "partition_manifest",
                actual: self.format_revision,
            });
        }
        scheme.validate()?;
        if self.scheme != scheme.id {
            return Err(PartitionManifestError::SchemeMismatch);
        }
        self.binding.validate()?;
        self.provenance.validate()?;
        if let ManifestProvenance::RequestBound { request } = &self.provenance
            && *request != self.binding.action_request
        {
            return Err(PartitionManifestError::ProvenanceBinding);
        }
        if self.entries.is_empty() && self.closure != ManifestClosure::Closed {
            return Err(PartitionManifestError::EmptyOpenManifest);
        }
        validate_canonical_entries(&self.entries)?;
        for entry in &self.entries {
            entry.key.validate_against_scheme(scheme)?;
            entry.validate_shape()?;
            if entry.coverage.world.id() != self.binding.semantic_world_digest
                || entry.coverage.world.repository_lineage != self.binding.repository
                || entry.coverage.world.source_selector != self.binding.source_selector
            {
                return Err(PartitionManifestError::BindingMismatch);
            }
        }
        let has_aggregate = self.entries.iter().any(|entry| entry.role == PartitionRole::Aggregate);
        if self.aggregate_derivation.is_some() != has_aggregate {
            return Err(PartitionManifestError::AggregateDerivation);
        }
        Ok(())
    }

    fn compute_definition_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"partition-manifest-definition-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_str(self.scheme.as_str());
        hasher.field_digest(self.binding.digest());
        self.provenance.hash_into(&mut hasher);
        hasher.field_u8(match self.closure {
            ManifestClosure::Open => 0,
            ManifestClosure::Closed => 1,
        });
        hasher.field_u32(self.entries.len().try_into().unwrap_or(u32::MAX));
        for entry in &self.entries {
            entry.hash_into(&mut hasher);
        }
        hash_optional_digest(&mut hasher, self.aggregate_derivation.map(DerivationRuleId::digest));
        hasher.finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionRef {
    pub manifest: PartitionManifestId,
    pub key_digest: Digest,
}

impl PartitionRef {
    pub const fn new(manifest: PartitionManifestId, key_digest: Digest) -> Self {
        Self { manifest, key_digest }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionOverlapPolicy {
    Disjoint,
    ValidatorDefined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestClosurePolicy {
    OpenAllowed,
    ClosedRequired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionPolicy {
    pub id: PartitionPolicyId,
    #[serde(deserialize_with = "wire::deserialize_allowed_schemes")]
    pub allowed_schemes: Vec<PartitionSchemeId>,
    pub manifest_validator: ValidatorId,
    pub maximum_partitions: u16,
    pub maximum_manifest_bytes: u32,
    pub overlap_policy: PartitionOverlapPolicy,
    pub closure_policy: ManifestClosurePolicy,
    pub definition_digest: Digest,
}

impl PartitionPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: PartitionPolicyId,
        mut allowed_schemes: Vec<PartitionSchemeId>,
        manifest_validator: ValidatorId,
        maximum_partitions: u16,
        maximum_manifest_bytes: u32,
        overlap_policy: PartitionOverlapPolicy,
        closure_policy: ManifestClosurePolicy,
    ) -> Result<Self, PartitionManifestError> {
        allowed_schemes.sort_unstable();
        let mut value = Self {
            id,
            allowed_schemes,
            manifest_validator,
            maximum_partitions,
            maximum_manifest_bytes,
            overlap_policy,
            closure_policy,
            definition_digest: zero_digest(),
        };
        value.validate_shape()?;
        value.definition_digest = value.compute_definition_digest();
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), PartitionManifestError> {
        self.validate_shape()?;
        validate_digest(
            "partition_policy.definition_digest",
            self.definition_digest,
            self.compute_definition_digest(),
        )
    }

    pub fn accepts(
        &self,
        manifest: &PartitionManifest,
        scheme: &PartitionScheme,
    ) -> Result<(), PartitionManifestError> {
        self.validate()?;
        manifest.validate_against_scheme(scheme)?;
        if self.allowed_schemes.binary_search(&manifest.scheme).is_err() {
            return Err(PartitionManifestError::SchemeNotAllowed);
        }
        if manifest.entries.len() > usize::from(self.maximum_partitions) {
            return Err(PartitionManifestError::Bound {
                field: "partition_manifest.entries",
                actual: manifest.entries.len(),
                maximum: usize::from(self.maximum_partitions),
            });
        }
        if self.closure_policy == ManifestClosurePolicy::ClosedRequired
            && manifest.closure != ManifestClosure::Closed
        {
            return Err(PartitionManifestError::ClosureRequired);
        }
        Ok(())
    }

    pub fn decode_manifest_json(
        &self,
        bytes: &[u8],
        scheme: &PartitionScheme,
    ) -> Result<PartitionManifest, PartitionManifestError> {
        self.validate()?;
        let maximum = usize::try_from(self.maximum_manifest_bytes).unwrap_or(usize::MAX);
        if bytes.len() > maximum {
            return Err(PartitionManifestError::Bound {
                field: "partition_manifest.wire_bytes",
                actual: bytes.len(),
                maximum,
            });
        }
        let manifest = PartitionManifest::decode_json(bytes, scheme)?;
        self.accepts(&manifest, scheme)?;
        Ok(manifest)
    }

    fn validate_shape(&self) -> Result<(), PartitionManifestError> {
        validate_identifier("partition_policy.id", self.id.as_str())?;
        validate_identifier(
            "partition_policy.manifest_validator",
            self.manifest_validator.as_str(),
        )?;
        validate_canonical_set(
            "partition_policy.allowed_schemes",
            &self.allowed_schemes,
            MAX_PARTITION_POLICY_SCHEMES,
            false,
        )?;
        if self.maximum_partitions == 0
            || usize::from(self.maximum_partitions) > MAX_PARTITION_MANIFEST_ENTRIES
        {
            return Err(PartitionManifestError::Bound {
                field: "partition_policy.maximum_partitions",
                actual: usize::from(self.maximum_partitions),
                maximum: MAX_PARTITION_MANIFEST_ENTRIES,
            });
        }
        let bytes = usize::try_from(self.maximum_manifest_bytes).unwrap_or(usize::MAX);
        if bytes == 0 || bytes > MAX_PARTITION_MANIFEST_WIRE_BYTES {
            return Err(PartitionManifestError::Bound {
                field: "partition_policy.maximum_manifest_bytes",
                actual: bytes,
                maximum: MAX_PARTITION_MANIFEST_WIRE_BYTES,
            });
        }
        Ok(())
    }

    fn compute_definition_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"partition-policy-definition-v1");
        hasher.field_str(self.id.as_str());
        hasher.field_u16(self.allowed_schemes.len().try_into().unwrap_or(u16::MAX));
        for scheme in &self.allowed_schemes {
            hasher.field_str(scheme.as_str());
        }
        hasher.field_str(self.manifest_validator.as_str());
        hasher.field_u16(self.maximum_partitions);
        hasher.field_u32(self.maximum_manifest_bytes);
        hasher.field_u8(match self.overlap_policy {
            PartitionOverlapPolicy::Disjoint => 0,
            PartitionOverlapPolicy::ValidatorDefined => 1,
        });
        hasher.field_u8(match self.closure_policy {
            ManifestClosurePolicy::OpenAllowed => 0,
            ManifestClosurePolicy::ClosedRequired => 1,
        });
        hasher.finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionKeyMapping {
    pub prior: PartitionRef,
    pub current: PartitionRef,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestTransition {
    pub format_revision: u16,
    pub id: ManifestTransitionId,
    pub prior: PartitionManifestId,
    pub current: PartitionManifestId,
    pub state_delta: Digest,
    #[serde(deserialize_with = "wire::deserialize_transition_mappings")]
    pub mappings: Vec<PartitionKeyMapping>,
    pub provenance: ManifestProvenance,
    pub validator: ValidatorId,
    pub definition_digest: Digest,
}

impl ManifestTransition {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        prior: PartitionManifestId,
        current: PartitionManifestId,
        state_delta: Digest,
        mut mappings: Vec<PartitionKeyMapping>,
        provenance: ManifestProvenance,
        validator: ValidatorId,
    ) -> Result<Self, PartitionManifestError> {
        mappings.sort_unstable();
        let mut value = Self {
            format_revision: MANIFEST_TRANSITION_FORMAT_REVISION,
            id: ManifestTransitionId::new(zero_digest()),
            prior,
            current,
            state_delta,
            mappings,
            provenance,
            validator,
            definition_digest: zero_digest(),
        };
        value.validate_shape()?;
        value.definition_digest = value.compute_definition_digest();
        value.id = compute_transition_id(value.definition_digest);
        Ok(value)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, PartitionManifestError> {
        if bytes.len() > MAX_PARTITION_MANIFEST_WIRE_BYTES {
            return Err(PartitionManifestError::Bound {
                field: "manifest_transition.wire_bytes",
                actual: bytes.len(),
                maximum: MAX_PARTITION_MANIFEST_WIRE_BYTES,
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
            "manifest_transition.definition_digest",
            self.definition_digest,
            definition_digest,
        )?;
        let id = compute_transition_id(definition_digest);
        if self.id != id {
            return Err(PartitionManifestError::IdentifierDigest {
                field: "manifest_transition.id",
                expected: id.digest(),
                actual: self.id.digest(),
            });
        }
        Ok(())
    }

    pub fn is_canonical(&self) -> bool {
        self.validate().is_ok()
    }

    fn validate_shape(&self) -> Result<(), PartitionManifestError> {
        if self.format_revision != MANIFEST_TRANSITION_FORMAT_REVISION {
            return Err(PartitionManifestError::FormatRevision {
                record: "manifest_transition",
                actual: self.format_revision,
            });
        }
        if self.prior == self.current {
            return Err(PartitionManifestError::TransitionManifests);
        }
        validate_identifier("manifest_transition.validator", self.validator.as_str())?;
        self.provenance.validate()?;
        validate_canonical_set(
            "manifest_transition.mappings",
            &self.mappings,
            MAX_PARTITION_TRANSITION_MAPPINGS,
            false,
        )?;
        for mapping in &self.mappings {
            if mapping.prior.manifest != self.prior || mapping.current.manifest != self.current {
                return Err(PartitionManifestError::TransitionMappingBinding);
            }
        }
        let mut current = self.mappings.iter().map(|mapping| mapping.current).collect::<Vec<_>>();
        current.sort_unstable();
        if self.mappings.windows(2).any(|pair| pair[0].prior == pair[1].prior)
            || current.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(PartitionManifestError::TransitionMappingAmbiguous);
        }
        Ok(())
    }

    fn compute_definition_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"partition-manifest-transition-definition-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.prior.digest());
        hasher.field_digest(self.current.digest());
        hasher.field_digest(self.state_delta);
        hasher.field_u32(self.mappings.len().try_into().unwrap_or(u32::MAX));
        for mapping in &self.mappings {
            hash_partition_ref(&mut hasher, mapping.prior);
            hash_partition_ref(&mut hasher, mapping.current);
        }
        self.provenance.hash_into(&mut hasher);
        hasher.field_str(self.validator.as_str());
        hasher.finish()
    }
}

/// Exact reuse remains artifact/request identity reuse and requires no
/// partition manifest. Project, Assemble, and Refresh are manifest-relative.
pub const fn partition_manifest_required(mode: ReuseMode) -> bool {
    matches!(mode, ReuseMode::Project | ReuseMode::Assemble | ReuseMode::Refresh)
}

pub fn validate_partition_projection(
    policy: &PartitionPolicy,
    scheme: &PartitionScheme,
    manifest: &PartitionManifest,
    expected_binding: &ManifestBinding,
    partitions: &[PartitionRef],
) -> Result<(), PartitionManifestError> {
    validate_manifest_for_reuse(policy, scheme, manifest, expected_binding)?;
    validate_partition_refs("partition_projection.partitions", partitions, policy)?;
    if partitions.iter().any(|partition| !manifest.contains(partition)) {
        return Err(PartitionManifestError::PartitionReference);
    }
    Ok(())
}

pub fn validate_partition_assembly(
    policy: &PartitionPolicy,
    scheme: &PartitionScheme,
    manifests: &[&PartitionManifest],
    expected_binding: &ManifestBinding,
    partitions: &[PartitionRef],
    transition: Option<&ManifestTransition>,
) -> Result<(), PartitionManifestError> {
    if manifests.is_empty() || manifests.len() > 2 {
        return Err(PartitionManifestError::AssemblyManifestCount(manifests.len()));
    }
    validate_partition_refs("partition_assembly.partitions", partitions, policy)?;
    if partitions
        .iter()
        .any(|partition| !manifests.iter().any(|manifest| manifest.contains(partition)))
    {
        return Err(PartitionManifestError::PartitionReference);
    }

    let first = manifests[0].id;
    if manifests.iter().all(|manifest| manifest.id == first) {
        if manifests.len() != 1 {
            return Err(PartitionManifestError::AssemblyManifestCount(manifests.len()));
        }
        validate_manifest_for_reuse(policy, scheme, manifests[0], expected_binding)?;
        if transition.is_some() {
            return Err(PartitionManifestError::UnexpectedTransition);
        }
        return Ok(());
    }

    let transition = transition.ok_or(PartitionManifestError::MissingTransition)?;
    transition.validate()?;
    if manifests.len() != 2
        || !manifests.iter().any(|manifest| manifest.id == transition.prior)
        || !manifests.iter().any(|manifest| manifest.id == transition.current)
    {
        return Err(PartitionManifestError::TransitionManifests);
    }
    let prior = manifests
        .iter()
        .find(|manifest| manifest.id == transition.prior)
        .copied()
        .ok_or(PartitionManifestError::TransitionManifests)?;
    let current = manifests
        .iter()
        .find(|manifest| manifest.id == transition.current)
        .copied()
        .ok_or(PartitionManifestError::TransitionManifests)?;
    validate_manifest_structural(policy, scheme, prior)?;
    validate_manifest_for_reuse(policy, scheme, current, expected_binding)?;
    if prior.binding.action_contract != current.binding.action_contract
        || prior.binding.output_contract != current.binding.output_contract
        || prior.binding.repository != current.binding.repository
    {
        return Err(PartitionManifestError::BindingMismatch);
    }
    if !transition_maps_all(transition, partitions) {
        return Err(PartitionManifestError::UnmappedCrossManifestPartition);
    }
    Ok(())
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PartitionManifestError {
    #[error("unsupported {record} format revision {actual}")]
    FormatRevision { record: &'static str, actual: u16 },
    #[error("{field} exceeds its bound: {actual} > {maximum}")]
    Bound { field: &'static str, actual: usize, maximum: usize },
    #[error("{field} must be canonical non-empty ASCII identifier text")]
    Identifier { field: &'static str },
    #[error("{field} must be non-empty bounded text without control characters")]
    Text { field: &'static str },
    #[error("{field} must be strictly sorted and unique")]
    NonCanonicalSet { field: &'static str },
    #[error("canonical digest mismatch for {field}: expected {expected}, got {actual}")]
    Digest { field: &'static str, expected: Digest, actual: Digest },
    #[error("canonical identifier mismatch for {field}: expected {expected}, got {actual}")]
    IdentifierDigest { field: &'static str, expected: Digest, actual: Digest },
    #[error("partition key or manifest scheme does not match the registered scheme")]
    SchemeMismatch,
    #[error("partition scheme is not allowed by the policy")]
    SchemeNotAllowed,
    #[error("partition key value must be non-empty and within the registered scheme bound")]
    PartitionKey,
    #[error("partition entry coverage is invalid: {0}")]
    Coverage(String),
    #[error("an aggregate entry requires exactly one aggregate derivation declaration")]
    AggregateDerivation,
    #[error("the partition policy requires a structurally closed manifest")]
    ClosureRequired,
    #[error("manifest binding differs from the exact action context")]
    BindingMismatch,
    #[error("request-bound provenance differs from the manifest action request")]
    ProvenanceBinding,
    #[error("an empty partition manifest must be structurally closed")]
    EmptyOpenManifest,
    #[error("partition manifest validation certificate is not shadow-only")]
    CertificateAuthority,
    #[error("partition manifest validation certificate differs from its manifest or definitions")]
    CertificateBinding,
    #[error("partition references must be explicit, canonical, and non-empty")]
    PartitionReference,
    #[error("assembly requires one or two manifest records, got {0}")]
    AssemblyManifestCount(usize),
    #[error("same-manifest assembly must not carry a transition")]
    UnexpectedTransition,
    #[error("cross-manifest assembly requires an accepted transition")]
    MissingTransition,
    #[error("transition must connect two distinct selected manifests")]
    TransitionManifests,
    #[error("transition mapping is not bound to its prior and current manifests")]
    TransitionMappingBinding,
    #[error("transition mappings must be one-to-one")]
    TransitionMappingAmbiguous,
    #[error("cross-manifest partition has no explicit accepted mapping")]
    UnmappedCrossManifestPartition,
    #[error("partition manifest JSON is invalid: {0}")]
    Json(String),
}

fn validate_manifest_for_reuse(
    policy: &PartitionPolicy,
    scheme: &PartitionScheme,
    manifest: &PartitionManifest,
    expected_binding: &ManifestBinding,
) -> Result<(), PartitionManifestError> {
    expected_binding.validate()?;
    validate_manifest_structural(policy, scheme, manifest)?;
    if &manifest.binding != expected_binding {
        return Err(PartitionManifestError::BindingMismatch);
    }
    Ok(())
}

fn validate_manifest_structural(
    policy: &PartitionPolicy,
    scheme: &PartitionScheme,
    manifest: &PartitionManifest,
) -> Result<(), PartitionManifestError> {
    policy.accepts(manifest, scheme)
}

fn validate_partition_refs(
    field: &'static str,
    partitions: &[PartitionRef],
    policy: &PartitionPolicy,
) -> Result<(), PartitionManifestError> {
    if partitions.is_empty() {
        return Err(PartitionManifestError::PartitionReference);
    }
    validate_canonical_set(field, partitions, usize::from(policy.maximum_partitions), false)
}

fn transition_maps_all(transition: &ManifestTransition, partitions: &[PartitionRef]) -> bool {
    let mut current = transition.mappings.iter().map(|mapping| mapping.current).collect::<Vec<_>>();
    current.sort_unstable();
    partitions.iter().all(|partition| {
        if partition.manifest == transition.prior {
            transition.mappings.binary_search_by_key(partition, |mapping| mapping.prior).is_ok()
        } else if partition.manifest == transition.current {
            current.binary_search(partition).is_ok()
        } else {
            false
        }
    })
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), PartitionManifestError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_PARTITION_IDENTIFIER_BYTES
        || !(bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        || bytes.iter().any(|byte| {
            !(byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(*byte, b'.' | b'_' | b'-' | b'/' | b':'))
        })
    {
        return Err(PartitionManifestError::Identifier { field });
    }
    Ok(())
}

fn validate_text(
    field: &'static str,
    value: &str,
    maximum: usize,
    allow_empty: bool,
) -> Result<(), PartitionManifestError> {
    if (!allow_empty && value.is_empty())
        || value.len() > maximum
        || value.chars().any(char::is_control)
    {
        return Err(PartitionManifestError::Text { field });
    }
    Ok(())
}

fn validate_key_bytes(value: &[u8], scheme_maximum: usize) -> Result<(), PartitionManifestError> {
    if value.is_empty() || value.len() > scheme_maximum || value.len() > MAX_PARTITION_KEY_BYTES {
        return Err(PartitionManifestError::PartitionKey);
    }
    Ok(())
}

fn validate_canonical_entries(entries: &[PartitionEntry]) -> Result<(), PartitionManifestError> {
    if entries.len() > MAX_PARTITION_MANIFEST_ENTRIES {
        return Err(PartitionManifestError::Bound {
            field: "partition_manifest.entries",
            actual: entries.len(),
            maximum: MAX_PARTITION_MANIFEST_ENTRIES,
        });
    }
    if entries.windows(2).any(|pair| pair[0].key.digest >= pair[1].key.digest) {
        return Err(PartitionManifestError::NonCanonicalSet {
            field: "partition_manifest.entries",
        });
    }
    Ok(())
}

fn validate_partition_coverage(coverage: &CoverageManifest) -> Result<(), PartitionManifestError> {
    if coverage.entries.len() > MAX_REQUIRED_OBLIGATIONS {
        return Err(PartitionManifestError::Bound {
            field: "partition_entry.coverage.entries",
            actual: coverage.entries.len(),
            maximum: MAX_REQUIRED_OBLIGATIONS,
        });
    }
    if !coverage.entries.windows(2).all(|pair| pair[0].obligation.id < pair[1].obligation.id) {
        return Err(PartitionManifestError::NonCanonicalSet {
            field: "partition_entry.coverage.entries",
        });
    }
    for value in
        [&coverage.world.source_selector, &coverage.world.platform, &coverage.world.features]
    {
        validate_text("partition_entry.coverage.world", value, MAX_NEED_IR_BYTES, true)?;
    }
    for entry in &coverage.entries {
        if entry.obligation.facets.len() > MAX_OBLIGATION_FACETS {
            return Err(PartitionManifestError::Bound {
                field: "partition_entry.coverage.facets",
                actual: entry.obligation.facets.len(),
                maximum: MAX_OBLIGATION_FACETS,
            });
        }
        for facet in &entry.obligation.facets {
            validate_text(
                "partition_entry.coverage.facet_key",
                &facet.key,
                MAX_NEED_IR_BYTES,
                true,
            )?;
            validate_text(
                "partition_entry.coverage.facet_value",
                &facet.value,
                MAX_NEED_IR_BYTES,
                true,
            )?;
        }
        if Obligation::new(
            entry.obligation.predicate,
            entry.obligation.subject,
            entry.obligation.facets.clone(),
        ) != entry.obligation
        {
            return Err(PartitionManifestError::Coverage("obligation is not canonical".to_owned()));
        }
        validate_canonical_set(
            "partition_entry.coverage.evidence",
            &entry.evidence,
            MAX_REUSE_DESCRIPTOR_EVIDENCE_PER_ENTRY,
            false,
        )?;
        for evidence in &entry.evidence {
            validate_text("partition_entry.coverage.evidence", evidence, MAX_NEED_IR_BYTES, false)?;
        }
    }
    Ok(())
}

fn validate_canonical_set<T: Ord>(
    field: &'static str,
    values: &[T],
    maximum: usize,
    empty_allowed: bool,
) -> Result<(), PartitionManifestError> {
    if values.len() > maximum {
        return Err(PartitionManifestError::Bound { field, actual: values.len(), maximum });
    }
    if (!empty_allowed && values.is_empty()) || values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(PartitionManifestError::NonCanonicalSet { field });
    }
    Ok(())
}

fn validate_digest(
    field: &'static str,
    actual: Digest,
    expected: Digest,
) -> Result<(), PartitionManifestError> {
    if actual != expected {
        return Err(PartitionManifestError::Digest { field, expected, actual });
    }
    Ok(())
}

fn zero_digest() -> Digest {
    Digest([0; 32])
}

fn compute_partition_key_digest(scheme: &PartitionSchemeId, value: &[u8]) -> Digest {
    let mut hasher = CanonicalHasher::new(b"opaque-partition-key-v1");
    hasher.field_str(scheme.as_str());
    hasher.field_bytes(value);
    hasher.finish()
}

fn compute_manifest_id(definition_digest: Digest) -> PartitionManifestId {
    let mut hasher = CanonicalHasher::new(b"partition-manifest-id-v1");
    hasher.field_digest(definition_digest);
    PartitionManifestId::new(hasher.finish())
}

fn compute_transition_id(definition_digest: Digest) -> ManifestTransitionId {
    let mut hasher = CanonicalHasher::new(b"partition-manifest-transition-id-v1");
    hasher.field_digest(definition_digest);
    ManifestTransitionId::new(hasher.finish())
}

fn hash_scheme_kind(hasher: &mut CanonicalHasher, kind: &PartitionSchemeKind) {
    match kind {
        PartitionSchemeKind::ContractDefined => hasher.field_u8(0),
        PartitionSchemeKind::ProducerAuthored => hasher.field_u8(1),
        PartitionSchemeKind::ProviderDefined { provider } => {
            hasher.field_u8(2);
            hasher.field_str(provider.as_str());
        }
    }
}

fn hash_optional_digest(hasher: &mut CanonicalHasher, value: Option<Digest>) {
    match value {
        Some(value) => {
            hasher.field_u8(1);
            hasher.field_digest(value);
        }
        None => hasher.field_u8(0),
    }
}

fn hash_partition_ref(hasher: &mut CanonicalHasher, partition: PartitionRef) {
    hasher.field_digest(partition.manifest.digest());
    hasher.field_digest(partition.key_digest);
}

fn hash_semantic_input_binding(hasher: &mut CanonicalHasher, binding: &SemanticInputBinding) {
    match binding {
        SemanticInputBinding::ByRequest { request } => {
            hasher.field_u8(0);
            hasher.field_digest(request.digest());
        }
        SemanticInputBinding::ByArtifact { artifact } => {
            hasher.field_u8(1);
            hasher.field_digest(artifact.digest());
        }
        SemanticInputBinding::ByProjection { artifact, projection } => {
            hasher.field_u8(2);
            hasher.field_digest(artifact.digest());
            hasher.field_digest(projection.digest());
        }
    }
}

fn coverage_digest(coverage: &CoverageManifest) -> Digest {
    let mut hasher = CanonicalHasher::new(b"partition-entry-coverage-v1");
    hasher.field_digest(coverage.world.id());
    hasher.field_digest(coverage.dependency_manifest_digest);
    hasher.field_u16(coverage.entries.len().try_into().unwrap_or(u16::MAX));
    for entry in &coverage.entries {
        hasher.field_digest(entry.obligation.id.digest());
        hasher.field_digest(entry.obligation.subject.digest());
        hasher.field_u16(entry.obligation.facets.len().try_into().unwrap_or(u16::MAX));
        for facet in &entry.obligation.facets {
            hasher.field_str(&facet.key);
            hasher.field_str(&facet.value);
        }
        hasher.field_u16(entry.evidence.len().try_into().unwrap_or(u16::MAX));
        for evidence in &entry.evidence {
            hasher.field_str(evidence);
        }
    }
    hasher.finish()
}
