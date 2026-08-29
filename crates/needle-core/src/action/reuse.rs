use super::ActionContractId;
use crate::{
    ArtifactId, ArtifactRequestId, ArtifactValidationCertificateId, CanonicalHasher, CoverageEntry,
    CoverageManifest, Digest, Facet, MAX_NEED_IR_BYTES, MAX_OBLIGATION_FACETS,
    MAX_REQUIRED_OBLIGATIONS, Obligation, PartitionManifestId, SemanticWorld,
};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use thiserror::Error;

const LEGACY_REUSE_DESCRIPTOR_FORMAT_REVISION: u16 = 1;
pub const REUSE_DESCRIPTOR_FORMAT_REVISION: u16 = 2;
pub const PARTITIONED_REUSE_DESCRIPTOR_FORMAT_REVISION: u16 = 3;
pub const MAX_REUSE_DESCRIPTOR_EVIDENCE_PER_ENTRY: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReuseDescriptorInput {
    pub artifact: ArtifactId,
    pub exact_request: ArtifactRequestId,
    pub action_contract: ActionContractId,
    pub action_semantic_definition_digest: Digest,
    pub action_validation_definition_digest: Digest,
    pub output_contract_definition_digest: Digest,
    pub validator_definition_digest: Digest,
    pub validation_certificate: ArtifactValidationCertificateId,
    pub coverage: CoverageManifest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartitionedReuseDescriptorInput {
    pub artifact: ArtifactId,
    pub exact_request: ArtifactRequestId,
    pub action_contract: ActionContractId,
    pub action_semantic_definition_digest: Digest,
    pub action_validation_definition_digest: Digest,
    pub output_contract_definition_digest: Digest,
    pub validator_definition_digest: Digest,
    pub validation_certificate: ArtifactValidationCertificateId,
    pub coverage: CoverageManifest,
    pub partition_manifest: PartitionManifestId,
}

/// Shadow-only index projection over an existing validation certificate.
///
/// This record proves structural integrity and definition binding. It does not
/// establish freshness, effective capability mode, or reuse authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReuseDescriptor {
    pub format_revision: u16,
    pub artifact: ArtifactId,
    pub exact_request: ArtifactRequestId,
    /// Immutable request row that originally produced or observed the artifact.
    pub origin_request: ArtifactRequestId,
    pub action_contract: ActionContractId,
    pub action_semantic_definition_digest: Digest,
    pub action_validation_definition_digest: Digest,
    pub output_contract_definition_digest: Digest,
    pub validator_definition_digest: Digest,
    pub validation_certificate: ArtifactValidationCertificateId,
    pub coverage: CoverageManifest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partition_manifest: Option<PartitionManifestId>,
    pub dependency_manifest_digest: Digest,
    pub semantic_world_digest: Digest,
    pub definition_digest: Digest,
}

impl ReuseDescriptor {
    pub fn new(input: ReuseDescriptorInput) -> Result<Self, ReuseDescriptorError> {
        validate_reuse_descriptor_coverage(&input.coverage)?;
        let dependency_manifest_digest = input.coverage.dependency_manifest_digest;
        let semantic_world_digest = input.coverage.world.id();
        let mut descriptor = Self {
            format_revision: REUSE_DESCRIPTOR_FORMAT_REVISION,
            artifact: input.artifact,
            exact_request: input.exact_request,
            origin_request: input.exact_request,
            action_contract: input.action_contract,
            action_semantic_definition_digest: input.action_semantic_definition_digest,
            action_validation_definition_digest: input.action_validation_definition_digest,
            output_contract_definition_digest: input.output_contract_definition_digest,
            validator_definition_digest: input.validator_definition_digest,
            validation_certificate: input.validation_certificate,
            coverage: input.coverage,
            partition_manifest: None,
            dependency_manifest_digest,
            semantic_world_digest,
            definition_digest: Digest([0; 32]),
        };
        descriptor.definition_digest = descriptor.compute_definition_digest();
        Ok(descriptor)
    }

    pub fn new_partitioned(
        input: PartitionedReuseDescriptorInput,
    ) -> Result<Self, ReuseDescriptorError> {
        validate_partitioned_reuse_descriptor_coverage(&input.coverage)?;
        let dependency_manifest_digest = input.coverage.dependency_manifest_digest;
        let semantic_world_digest = input.coverage.world.id();
        let mut descriptor = Self {
            format_revision: PARTITIONED_REUSE_DESCRIPTOR_FORMAT_REVISION,
            artifact: input.artifact,
            exact_request: input.exact_request,
            origin_request: input.exact_request,
            action_contract: input.action_contract,
            action_semantic_definition_digest: input.action_semantic_definition_digest,
            action_validation_definition_digest: input.action_validation_definition_digest,
            output_contract_definition_digest: input.output_contract_definition_digest,
            validator_definition_digest: input.validator_definition_digest,
            validation_certificate: input.validation_certificate,
            coverage: input.coverage,
            partition_manifest: Some(input.partition_manifest),
            dependency_manifest_digest,
            semantic_world_digest,
            definition_digest: Digest([0; 32]),
        };
        descriptor.definition_digest = descriptor.compute_definition_digest();
        Ok(descriptor)
    }

    pub fn validate(&self) -> Result<(), ReuseDescriptorError> {
        if !matches!(self.format_revision, 1..=PARTITIONED_REUSE_DESCRIPTOR_FORMAT_REVISION) {
            return Err(ReuseDescriptorError::FormatRevision(self.format_revision));
        }
        if self.format_revision == LEGACY_REUSE_DESCRIPTOR_FORMAT_REVISION
            && self.origin_request != self.exact_request
        {
            return Err(ReuseDescriptorError::LegacyRequestBinding);
        }
        if self.format_revision < PARTITIONED_REUSE_DESCRIPTOR_FORMAT_REVISION {
            if self.partition_manifest.is_some() {
                return Err(ReuseDescriptorError::PartitionManifestBinding);
            }
            validate_reuse_descriptor_coverage(&self.coverage)?;
        } else {
            if self.partition_manifest.is_none() {
                return Err(ReuseDescriptorError::PartitionManifestBinding);
            }
            validate_partitioned_reuse_descriptor_coverage(&self.coverage)?;
        }
        if self.dependency_manifest_digest != self.coverage.dependency_manifest_digest {
            return Err(ReuseDescriptorError::DependencyManifestDigest);
        }
        if self.semantic_world_digest != self.coverage.world.id() {
            return Err(ReuseDescriptorError::SemanticWorldDigest);
        }
        let expected = self.compute_definition_digest();
        if self.definition_digest != expected {
            return Err(ReuseDescriptorError::DefinitionDigest {
                expected,
                actual: self.definition_digest,
            });
        }
        Ok(())
    }

    pub fn is_canonical(&self) -> bool {
        self.validate().is_ok()
    }

    /// Rebinds a validated descriptor to a canonical action request while
    /// retaining the verified historical origin for audit.
    pub fn bind_request(
        mut self,
        exact_request: ArtifactRequestId,
        origin_request: ArtifactRequestId,
    ) -> Result<Self, ReuseDescriptorError> {
        self.validate()?;
        if self.format_revision == LEGACY_REUSE_DESCRIPTOR_FORMAT_REVISION {
            self.format_revision = REUSE_DESCRIPTOR_FORMAT_REVISION;
        }
        self.exact_request = exact_request;
        self.origin_request = origin_request;
        self.definition_digest = self.compute_definition_digest();
        Ok(self)
    }

    fn compute_definition_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(match self.format_revision {
            LEGACY_REUSE_DESCRIPTOR_FORMAT_REVISION => b"reuse-descriptor-shadow-v1",
            REUSE_DESCRIPTOR_FORMAT_REVISION => b"reuse-descriptor-shadow-v2",
            _ => b"reuse-descriptor-shadow-v3",
        });
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.artifact.digest());
        hasher.field_digest(self.exact_request.digest());
        if self.format_revision >= REUSE_DESCRIPTOR_FORMAT_REVISION {
            hasher.field_digest(self.origin_request.digest());
        }
        hasher.field_str(self.action_contract.as_str());
        hasher.field_digest(self.action_semantic_definition_digest);
        hasher.field_digest(self.action_validation_definition_digest);
        hasher.field_digest(self.output_contract_definition_digest);
        hasher.field_digest(self.validator_definition_digest);
        hasher.field_digest(self.validation_certificate.digest());
        hasher.field_digest(coverage_digest(&self.coverage));
        if self.format_revision >= PARTITIONED_REUSE_DESCRIPTOR_FORMAT_REVISION {
            hasher.field_digest(
                self.partition_manifest.map(PartitionManifestId::digest).unwrap_or(Digest([0; 32])),
            );
        }
        hasher.field_digest(self.dependency_manifest_digest);
        hasher.field_digest(self.semantic_world_digest);
        hasher.finish()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ReuseDescriptorError {
    #[error("reuse descriptor format revision {0} is unsupported")]
    FormatRevision(u16),
    #[error("legacy reuse descriptors cannot separate matched and origin requests")]
    LegacyRequestBinding,
    #[error("reuse descriptor coverage must not be empty")]
    EmptyCoverage,
    #[error("reuse descriptor coverage contains {actual} entries; the maximum is {maximum}")]
    CoverageBound { actual: usize, maximum: usize },
    #[error("reuse descriptor coverage entries must be ordered, unique, and canonical")]
    CoverageNotCanonical,
    #[error("reuse descriptor facet text exceeds the canonical byte bound")]
    FacetTextBound,
    #[error("reuse descriptor evidence contains {actual} entries; the maximum is {maximum}")]
    EvidenceBound { actual: usize, maximum: usize },
    #[error("reuse descriptor evidence labels must be non-empty, bounded, ordered, and unique")]
    EvidenceNotCanonical,
    #[error("reuse descriptor semantic-world text exceeds the canonical byte bound")]
    SemanticWorldTextBound,
    #[error("reuse descriptor dependency manifest digest is inconsistent")]
    DependencyManifestDigest,
    #[error("reuse descriptor semantic world digest is inconsistent")]
    SemanticWorldDigest,
    #[error("reuse descriptor partition manifest does not match its format revision")]
    PartitionManifestBinding,
    #[error("reuse descriptor definition digest mismatch: expected {expected}, got {actual}")]
    DefinitionDigest { expected: Digest, actual: Digest },
}

pub fn validate_reuse_descriptor_coverage(
    coverage: &CoverageManifest,
) -> Result<(), ReuseDescriptorError> {
    if coverage.entries.is_empty() {
        return Err(ReuseDescriptorError::EmptyCoverage);
    }
    if coverage.entries.len() > MAX_REQUIRED_OBLIGATIONS {
        return Err(ReuseDescriptorError::CoverageBound {
            actual: coverage.entries.len(),
            maximum: MAX_REQUIRED_OBLIGATIONS,
        });
    }
    if !coverage.entries.windows(2).all(|pair| pair[0].obligation.id < pair[1].obligation.id) {
        return Err(ReuseDescriptorError::CoverageNotCanonical);
    }
    if [&coverage.world.source_selector, &coverage.world.platform, &coverage.world.features]
        .into_iter()
        .any(|value| value.len() > MAX_NEED_IR_BYTES)
    {
        return Err(ReuseDescriptorError::SemanticWorldTextBound);
    }
    for entry in &coverage.entries {
        if entry.obligation.facets.len() > MAX_OBLIGATION_FACETS {
            return Err(ReuseDescriptorError::CoverageNotCanonical);
        }
        if entry.obligation.facets.iter().any(|facet| {
            facet.key.len() > MAX_NEED_IR_BYTES || facet.value.len() > MAX_NEED_IR_BYTES
        }) {
            return Err(ReuseDescriptorError::FacetTextBound);
        }
        if Obligation::new(
            entry.obligation.predicate,
            entry.obligation.subject,
            entry.obligation.facets.clone(),
        ) != entry.obligation
        {
            return Err(ReuseDescriptorError::CoverageNotCanonical);
        }
        if entry.evidence.len() > MAX_REUSE_DESCRIPTOR_EVIDENCE_PER_ENTRY {
            return Err(ReuseDescriptorError::EvidenceBound {
                actual: entry.evidence.len(),
                maximum: MAX_REUSE_DESCRIPTOR_EVIDENCE_PER_ENTRY,
            });
        }
        if entry.evidence.is_empty()
            || !entry.evidence.windows(2).all(|pair| pair[0] < pair[1])
            || entry
                .evidence
                .iter()
                .any(|label| label.is_empty() || label.len() > MAX_NEED_IR_BYTES)
        {
            return Err(ReuseDescriptorError::EvidenceNotCanonical);
        }
    }
    Ok(())
}

fn validate_partitioned_reuse_descriptor_coverage(
    coverage: &CoverageManifest,
) -> Result<(), ReuseDescriptorError> {
    if !coverage.entries.is_empty() {
        return Err(ReuseDescriptorError::CoverageNotCanonical);
    }
    validate_reuse_descriptor_world(coverage)
}

fn validate_reuse_descriptor_world(
    coverage: &CoverageManifest,
) -> Result<(), ReuseDescriptorError> {
    if [&coverage.world.source_selector, &coverage.world.platform, &coverage.world.features]
        .into_iter()
        .any(|value| value.len() > MAX_NEED_IR_BYTES)
    {
        return Err(ReuseDescriptorError::SemanticWorldTextBound);
    }
    Ok(())
}

fn coverage_digest(coverage: &CoverageManifest) -> Digest {
    let mut hasher = CanonicalHasher::new(b"reuse-descriptor-coverage-v1");
    hasher.field_digest(coverage.world.id());
    hasher.field_digest(coverage.dependency_manifest_digest);
    hasher.field_u16(coverage.entries.len() as u16);
    for entry in &coverage.entries {
        hasher.field_digest(entry.obligation.id.digest());
        hasher.field_digest(entry.obligation.subject.digest());
        hasher.field_u16(entry.obligation.facets.len() as u16);
        for facet in &entry.obligation.facets {
            hasher.field_str(&facet.key);
            hasher.field_str(&facet.value);
        }
        hasher.field_u16(entry.evidence.len() as u16);
        for evidence in &entry.evidence {
            hasher.field_str(evidence);
        }
    }
    hasher.finish()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReuseDescriptorWire {
    format_revision: u16,
    artifact: ArtifactId,
    exact_request: ArtifactRequestId,
    #[serde(default)]
    origin_request: Option<ArtifactRequestId>,
    action_contract: ActionContractId,
    action_semantic_definition_digest: Digest,
    action_validation_definition_digest: Digest,
    output_contract_definition_digest: Digest,
    validator_definition_digest: Digest,
    validation_certificate: ArtifactValidationCertificateId,
    #[serde(deserialize_with = "deserialize_coverage")]
    coverage: CoverageManifest,
    #[serde(default)]
    partition_manifest: Option<PartitionManifestId>,
    dependency_manifest_digest: Digest,
    semantic_world_digest: Digest,
    definition_digest: Digest,
}

impl<'de> Deserialize<'de> for ReuseDescriptor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ReuseDescriptorWire::deserialize(deserializer)?;
        let origin_request = wire.origin_request.unwrap_or(wire.exact_request);
        Ok(Self {
            format_revision: wire.format_revision,
            artifact: wire.artifact,
            exact_request: wire.exact_request,
            origin_request,
            action_contract: wire.action_contract,
            action_semantic_definition_digest: wire.action_semantic_definition_digest,
            action_validation_definition_digest: wire.action_validation_definition_digest,
            output_contract_definition_digest: wire.output_contract_definition_digest,
            validator_definition_digest: wire.validator_definition_digest,
            validation_certificate: wire.validation_certificate,
            coverage: wire.coverage,
            partition_manifest: wire.partition_manifest,
            dependency_manifest_digest: wire.dependency_manifest_digest,
            semantic_world_digest: wire.semantic_world_digest,
            definition_digest: wire.definition_digest,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoverageEntryWire {
    #[serde(deserialize_with = "deserialize_obligation")]
    obligation: Obligation,
    #[serde(deserialize_with = "deserialize_evidence")]
    evidence: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObligationWire {
    id: crate::ObligationId,
    predicate: crate::PredicateKind,
    subject: crate::SubjectId,
    #[serde(deserialize_with = "deserialize_facets")]
    facets: Vec<Facet>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FacetWire {
    #[serde(deserialize_with = "deserialize_bounded_text")]
    key: String,
    #[serde(deserialize_with = "deserialize_bounded_text")]
    value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticWorldWire {
    repository_lineage: Digest,
    #[serde(deserialize_with = "deserialize_bounded_text")]
    source_selector: String,
    #[serde(deserialize_with = "deserialize_bounded_text")]
    platform: String,
    #[serde(deserialize_with = "deserialize_bounded_text")]
    features: String,
    configuration: Option<Digest>,
    toolchain: Option<Digest>,
}

fn deserialize_coverage<'de, D>(deserializer: D) -> Result<CoverageManifest, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CoverageWire {
        #[serde(deserialize_with = "deserialize_coverage_entries")]
        entries: Vec<CoverageEntry>,
        #[serde(deserialize_with = "deserialize_semantic_world")]
        world: SemanticWorld,
        dependency_manifest_digest: Digest,
    }

    let wire = CoverageWire::deserialize(deserializer)?;
    Ok(CoverageManifest {
        entries: wire.entries,
        world: wire.world,
        dependency_manifest_digest: wire.dependency_manifest_digest,
    })
}

fn deserialize_semantic_world<'de, D>(deserializer: D) -> Result<SemanticWorld, D::Error>
where
    D: Deserializer<'de>,
{
    let wire = SemanticWorldWire::deserialize(deserializer)?;
    Ok(SemanticWorld {
        repository_lineage: wire.repository_lineage,
        source_selector: wire.source_selector,
        platform: wire.platform,
        features: wire.features,
        configuration: wire.configuration,
        toolchain: wire.toolchain,
    })
}

fn deserialize_coverage_entries<'de, D>(deserializer: D) -> Result<Vec<CoverageEntry>, D::Error>
where
    D: Deserializer<'de>,
{
    struct CoverageEntriesVisitor;
    impl<'de> Visitor<'de> for CoverageEntriesVisitor {
        type Value = Vec<CoverageEntry>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_REQUIRED_OBLIGATIONS} coverage entries")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let capacity = sequence.size_hint().unwrap_or(0).min(MAX_REQUIRED_OBLIGATIONS);
            let mut entries = Vec::with_capacity(capacity);
            while let Some(entry) = sequence.next_element::<CoverageEntryWire>()? {
                if entries.len() == MAX_REQUIRED_OBLIGATIONS {
                    return Err(serde::de::Error::custom(ReuseDescriptorError::CoverageBound {
                        actual: MAX_REQUIRED_OBLIGATIONS + 1,
                        maximum: MAX_REQUIRED_OBLIGATIONS,
                    }));
                }
                entries
                    .push(CoverageEntry { obligation: entry.obligation, evidence: entry.evidence });
            }
            Ok(entries)
        }
    }
    deserializer.deserialize_seq(CoverageEntriesVisitor)
}

fn deserialize_obligation<'de, D>(deserializer: D) -> Result<Obligation, D::Error>
where
    D: Deserializer<'de>,
{
    let wire = ObligationWire::deserialize(deserializer)?;
    Ok(Obligation {
        id: wire.id,
        predicate: wire.predicate,
        subject: wire.subject,
        facets: wire.facets,
    })
}

fn deserialize_facets<'de, D>(deserializer: D) -> Result<Vec<Facet>, D::Error>
where
    D: Deserializer<'de>,
{
    struct FacetsVisitor;
    impl<'de> Visitor<'de> for FacetsVisitor {
        type Value = Vec<Facet>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_OBLIGATION_FACETS} obligation facets")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let capacity = sequence.size_hint().unwrap_or(0).min(MAX_OBLIGATION_FACETS);
            let mut facets = Vec::with_capacity(capacity);
            while let Some(facet) = sequence.next_element::<FacetWire>()? {
                if facets.len() == MAX_OBLIGATION_FACETS {
                    return Err(serde::de::Error::custom("obligation facet bound exceeded"));
                }
                facets.push(Facet { key: facet.key, value: facet.value });
            }
            Ok(facets)
        }
    }
    deserializer.deserialize_seq(FacetsVisitor)
}

fn deserialize_evidence<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct EvidenceVisitor;
    impl<'de> Visitor<'de> for EvidenceVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_REUSE_DESCRIPTOR_EVIDENCE_PER_ENTRY} evidence labels")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let capacity =
                sequence.size_hint().unwrap_or(0).min(MAX_REUSE_DESCRIPTOR_EVIDENCE_PER_ENTRY);
            let mut evidence = Vec::with_capacity(capacity);
            while let Some(label) = sequence.next_element::<BoundedText>()? {
                if evidence.len() == MAX_REUSE_DESCRIPTOR_EVIDENCE_PER_ENTRY {
                    return Err(serde::de::Error::custom(ReuseDescriptorError::EvidenceBound {
                        actual: MAX_REUSE_DESCRIPTOR_EVIDENCE_PER_ENTRY + 1,
                        maximum: MAX_REUSE_DESCRIPTOR_EVIDENCE_PER_ENTRY,
                    }));
                }
                evidence.push(label.0);
            }
            Ok(evidence)
        }
    }
    deserializer.deserialize_seq(EvidenceVisitor)
}

struct BoundedText(String);

impl<'de> Deserialize<'de> for BoundedText {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_bounded_text(deserializer).map(Self)
    }
}

fn deserialize_bounded_text<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedTextVisitor;

    impl<'de> Visitor<'de> for BoundedTextVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a string of at most {MAX_NEED_IR_BYTES} bytes")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value.len() > MAX_NEED_IR_BYTES {
                return Err(E::custom("reuse descriptor text bound exceeded"));
            }
            Ok(value.to_owned())
        }

        fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            self.visit_str(value)
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value.len() > MAX_NEED_IR_BYTES {
                return Err(E::custom("reuse descriptor text bound exceeded"));
            }
            Ok(value)
        }
    }

    deserializer.deserialize_string(BoundedTextVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PredicateKind, SemanticWorld, SubjectId};

    fn coverage(entry_count: usize) -> CoverageManifest {
        let mut entries = (0..entry_count)
            .map(|index| CoverageEntry {
                obligation: Obligation::new(
                    PredicateKind::ImplementationLocation,
                    SubjectId::new(Digest::blake3(index.to_le_bytes())),
                    vec![Facet {
                        key: "granularity".to_owned(),
                        value: "exact-location".to_owned(),
                    }],
                ),
                evidence: vec![format!("src/{index}.rs:item")],
            })
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.obligation.id);
        CoverageManifest {
            entries,
            world: SemanticWorld {
                repository_lineage: Digest::blake3(b"repository"),
                source_selector: "worktree".to_owned(),
                platform: "windows".to_owned(),
                features: "default".to_owned(),
                configuration: None,
                toolchain: None,
            },
            dependency_manifest_digest: Digest::blake3(b"manifest"),
        }
    }

    fn descriptor(entry_count: usize) -> Result<ReuseDescriptor, ReuseDescriptorError> {
        ReuseDescriptor::new(ReuseDescriptorInput {
            artifact: ArtifactId::new(Digest::blake3(b"artifact")),
            exact_request: ArtifactRequestId::new(Digest::blake3(b"request")),
            action_contract: ActionContractId::new("needle.location.resolve").unwrap(),
            action_semantic_definition_digest: Digest::blake3(b"action-semantic"),
            action_validation_definition_digest: Digest::blake3(b"action-validation"),
            output_contract_definition_digest: Digest::blake3(b"output-contract"),
            validator_definition_digest: Digest::blake3(b"validator"),
            validation_certificate: ArtifactValidationCertificateId::new(Digest::blake3(
                b"certificate",
            )),
            coverage: coverage(entry_count),
        })
    }

    fn partitioned_descriptor() -> ReuseDescriptor {
        ReuseDescriptor::new_partitioned(PartitionedReuseDescriptorInput {
            artifact: ArtifactId::new(Digest::blake3(b"partitioned-artifact")),
            exact_request: ArtifactRequestId::new(Digest::blake3(b"partitioned-request")),
            action_contract: ActionContractId::new("needle.tests.inventory").unwrap(),
            action_semantic_definition_digest: Digest::blake3(b"action-semantic"),
            action_validation_definition_digest: Digest::blake3(b"action-validation"),
            output_contract_definition_digest: Digest::blake3(b"output-contract"),
            validator_definition_digest: Digest::blake3(b"validator"),
            validation_certificate: ArtifactValidationCertificateId::new(Digest::blake3(
                b"partitioned-certificate",
            )),
            coverage: CoverageManifest {
                entries: Vec::new(),
                world: coverage(1).world,
                dependency_manifest_digest: Digest::blake3(b"partitioned-dependencies"),
            },
            partition_manifest: PartitionManifestId::new(Digest::blake3(b"manifest")),
        })
        .unwrap()
    }

    #[test]
    fn descriptor_is_canonical_roundtrips_and_has_stable_digest() {
        let descriptor = descriptor(1).unwrap();
        assert!(descriptor.is_canonical());
        assert_eq!(
            descriptor.definition_digest,
            Digest::parse("b3:3fae7baaa12c232a787c9f2fde2ed68fdbf6d4a859032f8091bb903a17303c28")
                .unwrap()
        );
        let json = serde_json::to_string(&descriptor).unwrap();
        let decoded: ReuseDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, descriptor);
        assert!(decoded.is_canonical());
        let mut value = serde_json::to_value(&descriptor).unwrap();
        value.as_object_mut().unwrap().insert("unknown".to_owned(), true.into());
        assert!(serde_json::from_value::<ReuseDescriptor>(value).is_err());
    }

    #[test]
    fn descriptor_separates_canonical_match_from_legacy_origin() {
        let descriptor = descriptor(1).unwrap();
        let origin = descriptor.origin_request;
        let matched = ArtifactRequestId::new(Digest::blake3(b"canonical-action-request"));
        let rebound = descriptor.clone().bind_request(matched, origin).unwrap();
        assert_eq!(rebound.exact_request, matched);
        assert_eq!(rebound.origin_request, origin);
        assert_ne!(rebound.definition_digest, descriptor.definition_digest);
        assert!(rebound.is_canonical());

        let mut legacy = descriptor;
        legacy.format_revision = LEGACY_REUSE_DESCRIPTOR_FORMAT_REVISION;
        legacy.origin_request = legacy.exact_request;
        legacy.definition_digest = legacy.compute_definition_digest();
        let mut wire = serde_json::to_value(&legacy).unwrap();
        wire.as_object_mut().unwrap().remove("origin_request");
        let decoded: ReuseDescriptor = serde_json::from_value(wire).unwrap();
        assert_eq!(decoded.origin_request, decoded.exact_request);
        assert!(decoded.is_canonical());
    }

    #[test]
    fn partitioned_descriptor_requires_manifest_and_empty_predicate_coverage() {
        let descriptor = partitioned_descriptor();
        assert_eq!(descriptor.format_revision, PARTITIONED_REUSE_DESCRIPTOR_FORMAT_REVISION);
        assert!(descriptor.partition_manifest.is_some());
        assert!(descriptor.coverage.entries.is_empty());
        let json = serde_json::to_vec(&descriptor).unwrap();
        let decoded: ReuseDescriptor = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded, descriptor);
        assert!(decoded.is_canonical());

        let mut missing_manifest = descriptor.clone();
        missing_manifest.partition_manifest = None;
        assert_eq!(
            missing_manifest.validate(),
            Err(ReuseDescriptorError::PartitionManifestBinding)
        );
        let mut predicate_coverage = descriptor;
        predicate_coverage.coverage = coverage(1);
        assert_eq!(predicate_coverage.validate(), Err(ReuseDescriptorError::CoverageNotCanonical));
    }

    #[test]
    fn descriptor_rejects_tampering_and_noncanonical_coverage() {
        let base = descriptor(2).unwrap();
        let mut tampered = base.clone();
        tampered.action_validation_definition_digest = Digest::blake3(b"tampered");
        assert!(matches!(tampered.validate(), Err(ReuseDescriptorError::DefinitionDigest { .. })));
        let mut tampered = base.clone();
        tampered.coverage.entries[0].evidence.push("duplicate".to_owned());
        tampered.coverage.entries[0].evidence.push("duplicate".to_owned());
        assert_eq!(tampered.validate(), Err(ReuseDescriptorError::EvidenceNotCanonical));
        let mut tampered = base;
        tampered.coverage.entries.swap(0, 1);
        assert_eq!(tampered.validate(), Err(ReuseDescriptorError::CoverageNotCanonical));
    }

    #[test]
    fn descriptor_enforces_constructor_and_wire_bounds() {
        assert!(descriptor(MAX_REQUIRED_OBLIGATIONS).is_ok());
        assert_eq!(
            descriptor(MAX_REQUIRED_OBLIGATIONS + 1),
            Err(ReuseDescriptorError::CoverageBound {
                actual: MAX_REQUIRED_OBLIGATIONS + 1,
                maximum: MAX_REQUIRED_OBLIGATIONS,
            })
        );

        let descriptor = descriptor(1).unwrap();
        let mut value = serde_json::to_value(descriptor).unwrap();
        let entry = value["coverage"]["entries"][0].clone();
        value["coverage"]["entries"] = serde_json::Value::Array(
            (0..=MAX_REQUIRED_OBLIGATIONS).map(|_| entry.clone()).collect(),
        );
        assert!(serde_json::from_value::<ReuseDescriptor>(value).is_err());
    }

    #[test]
    fn descriptor_rejects_oversized_wire_and_owned_text() {
        let oversized = "x".repeat(MAX_NEED_IR_BYTES + 1);

        let mut owned = coverage(1);
        owned.entries[0].obligation.facets[0].value = oversized.clone();
        assert_eq!(
            ReuseDescriptor::new(ReuseDescriptorInput {
                artifact: ArtifactId::new(Digest::blake3(b"artifact")),
                exact_request: ArtifactRequestId::new(Digest::blake3(b"request")),
                action_contract: ActionContractId::new("needle.location.resolve").unwrap(),
                action_semantic_definition_digest: Digest::blake3(b"action-semantic"),
                action_validation_definition_digest: Digest::blake3(b"action-validation"),
                output_contract_definition_digest: Digest::blake3(b"output-contract"),
                validator_definition_digest: Digest::blake3(b"validator"),
                validation_certificate: ArtifactValidationCertificateId::new(Digest::blake3(
                    b"certificate",
                )),
                coverage: owned,
            }),
            Err(ReuseDescriptorError::FacetTextBound)
        );

        for pointer in [
            "/coverage/entries/0/obligation/facets/0/key",
            "/coverage/entries/0/evidence/0",
            "/coverage/world/source_selector",
        ] {
            let mut value = serde_json::to_value(descriptor(1).unwrap()).unwrap();
            *value.pointer_mut(pointer).unwrap() = oversized.clone().into();
            assert!(
                serde_json::from_value::<ReuseDescriptor>(value).is_err(),
                "oversized text at {pointer} was accepted"
            );
        }
    }
}
