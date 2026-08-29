use super::*;
use crate::{CoverageEntry, Facet, MAX_NEED_IR_BYTES, Obligation, SemanticWorld};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::marker::PhantomData;

pub(super) fn deserialize_bounded_identifier<'de, D>(
    deserializer: D,
    field: &'static str,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_text(deserializer, field, MAX_PARTITION_IDENTIFIER_BYTES, false)
}

pub(super) fn deserialize_partition_display<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_text(
        deserializer,
        "partition_key.display",
        MAX_PARTITION_DISPLAY_BYTES,
        false,
    )
}

pub(super) fn deserialize_output_contract<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_identifier(deserializer, "manifest_binding.output_contract")
}

pub(super) fn deserialize_action_contract<'de, D>(
    deserializer: D,
) -> Result<ActionContractId, D::Error>
where
    D: Deserializer<'de>,
{
    let value = deserialize_bounded_text(
        deserializer,
        "manifest_binding.action_contract",
        crate::MAX_ACTION_CONTRACT_ID_BYTES,
        false,
    )?;
    ActionContractId::new(value).map_err(serde::de::Error::custom)
}

pub(super) fn deserialize_source_selector<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_text(
        deserializer,
        "manifest_binding.source_selector",
        MAX_PARTITION_SOURCE_SELECTOR_BYTES,
        false,
    )
}

pub(super) fn deserialize_partition_key_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, u8, MAX_PARTITION_KEY_BYTES>(deserializer, "partition_key.value")
}

pub(super) fn deserialize_provenance_parents<'de, D>(
    deserializer: D,
) -> Result<Vec<PartitionManifestId>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, PartitionManifestId, MAX_PARTITION_PROVENANCE_PARENTS>(
        deserializer,
        "manifest_provenance.parents",
    )
}

pub(super) fn deserialize_semantic_input_bindings<'de, D>(
    deserializer: D,
) -> Result<Vec<SemanticInputBinding>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, SemanticInputBinding, MAX_NEED_INPUTS>(
        deserializer,
        "partition_entry.semantic_input_bindings",
    )
}

pub(super) fn deserialize_validated_input_artifacts<'de, D>(
    deserializer: D,
) -> Result<Vec<ArtifactId>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, ArtifactId, MAX_NEED_INPUTS>(
        deserializer,
        "partition_entry.validated_input_artifacts",
    )
}

pub(super) fn deserialize_manifest_entries<'de, D>(
    deserializer: D,
) -> Result<Vec<PartitionEntry>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, PartitionEntry, MAX_PARTITION_MANIFEST_ENTRIES>(
        deserializer,
        "partition_manifest.entries",
    )
}

pub(super) fn deserialize_allowed_schemes<'de, D>(
    deserializer: D,
) -> Result<Vec<PartitionSchemeId>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, PartitionSchemeId, MAX_PARTITION_POLICY_SCHEMES>(
        deserializer,
        "partition_policy.allowed_schemes",
    )
}

pub(super) fn deserialize_transition_mappings<'de, D>(
    deserializer: D,
) -> Result<Vec<PartitionKeyMapping>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, PartitionKeyMapping, MAX_PARTITION_TRANSITION_MAPPINGS>(
        deserializer,
        "manifest_transition.mappings",
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoverageWire {
    #[serde(deserialize_with = "deserialize_coverage_entries")]
    entries: Vec<CoverageEntry>,
    #[serde(deserialize_with = "deserialize_semantic_world")]
    world: SemanticWorld,
    dependency_manifest_digest: Digest,
}

pub(super) fn deserialize_coverage<'de, D>(deserializer: D) -> Result<CoverageManifest, D::Error>
where
    D: Deserializer<'de>,
{
    let wire = CoverageWire::deserialize(deserializer)?;
    Ok(CoverageManifest {
        entries: wire.entries,
        world: wire.world,
        dependency_manifest_digest: wire.dependency_manifest_digest,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticWorldWire {
    repository_lineage: Digest,
    #[serde(deserialize_with = "deserialize_need_text")]
    source_selector: String,
    #[serde(deserialize_with = "deserialize_need_text")]
    platform: String,
    #[serde(deserialize_with = "deserialize_need_text")]
    features: String,
    configuration: Option<Digest>,
    toolchain: Option<Digest>,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoverageEntryWire {
    #[serde(deserialize_with = "deserialize_obligation")]
    obligation: Obligation,
    #[serde(deserialize_with = "deserialize_evidence")]
    evidence: Vec<String>,
}

fn deserialize_coverage_entries<'de, D>(deserializer: D) -> Result<Vec<CoverageEntry>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec_map::<
        D,
        CoverageEntryWire,
        CoverageEntry,
        { crate::MAX_REQUIRED_OBLIGATIONS },
    >(deserializer, "partition_entry.coverage.entries", |entry| CoverageEntry {
        obligation: entry.obligation,
        evidence: entry.evidence,
    })
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FacetWire {
    #[serde(deserialize_with = "deserialize_need_text")]
    key: String,
    #[serde(deserialize_with = "deserialize_need_text")]
    value: String,
}

fn deserialize_facets<'de, D>(deserializer: D) -> Result<Vec<Facet>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec_map::<D, FacetWire, Facet, { crate::MAX_OBLIGATION_FACETS }>(
        deserializer,
        "partition_entry.coverage.facets",
        |facet| Facet { key: facet.key, value: facet.value },
    )
}

fn deserialize_evidence<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    const MAXIMUM: usize = crate::MAX_REUSE_DESCRIPTOR_EVIDENCE_PER_ENTRY;
    struct EvidenceVisitor;

    impl<'de> Visitor<'de> for EvidenceVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAXIMUM} bounded evidence labels")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence.size_hint().is_some_and(|size| size > MAXIMUM) {
                return Err(serde::de::Error::custom("partition evidence bound exceeded"));
            }
            let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAXIMUM));
            while let Some(value) = sequence.next_element::<NeedText>()? {
                if values.len() == MAXIMUM {
                    return Err(serde::de::Error::custom("partition evidence bound exceeded"));
                }
                values.push(value.0);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(EvidenceVisitor)
}

struct NeedText(String);

impl<'de> Deserialize<'de> for NeedText {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_need_text(deserializer).map(Self)
    }
}

fn deserialize_need_text<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_text(deserializer, "partition_entry.coverage.text", MAX_NEED_IR_BYTES, true)
}

fn deserialize_bounded_text<'de, D>(
    deserializer: D,
    field: &'static str,
    maximum: usize,
    allow_empty: bool,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedTextVisitor {
        field: &'static str,
        maximum: usize,
        allow_empty: bool,
    }

    impl<'de> Visitor<'de> for BoundedTextVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "{} with at most {} bytes", self.field, self.maximum)
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if (!self.allow_empty && value.is_empty())
                || value.len() > self.maximum
                || value.chars().any(char::is_control)
            {
                return Err(E::custom(format_args!(
                    "{} is invalid or exceeds its bound",
                    self.field
                )));
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
            if (!self.allow_empty && value.is_empty())
                || value.len() > self.maximum
                || value.chars().any(char::is_control)
            {
                return Err(E::custom(format_args!(
                    "{} is invalid or exceeds its bound",
                    self.field
                )));
            }
            Ok(value)
        }
    }

    deserializer.deserialize_string(BoundedTextVisitor { field, maximum, allow_empty })
}

fn deserialize_bounded_vec<'de, D, T, const MAXIMUM: usize>(
    deserializer: D,
    field: &'static str,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserialize_bounded_vec_map::<D, T, T, MAXIMUM>(deserializer, field, |value| value)
}

fn deserialize_bounded_vec_map<'de, D, T, U, const MAXIMUM: usize>(
    deserializer: D,
    field: &'static str,
    map: fn(T) -> U,
) -> Result<Vec<U>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVecVisitor<T, U, const MAXIMUM: usize> {
        field: &'static str,
        map: fn(T) -> U,
        marker: PhantomData<(T, U)>,
    }

    impl<'de, T, U, const MAXIMUM: usize> Visitor<'de> for BoundedVecVisitor<T, U, MAXIMUM>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<U>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "{} with at most {MAXIMUM} entries", self.field)
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence.size_hint().is_some_and(|size| size > MAXIMUM) {
                return Err(serde::de::Error::custom(format_args!(
                    "{} exceeds its bound of {MAXIMUM}",
                    self.field
                )));
            }
            let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAXIMUM));
            while let Some(value) = sequence.next_element::<T>()? {
                if values.len() == MAXIMUM {
                    return Err(serde::de::Error::custom(format_args!(
                        "{} exceeds its bound of {MAXIMUM}",
                        self.field
                    )));
                }
                values.push((self.map)(value));
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(BoundedVecVisitor::<T, U, MAXIMUM> {
        field,
        map,
        marker: PhantomData,
    })
}
