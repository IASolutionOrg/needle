use crate::{CanonicalHasher, Digest};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

pub const DEFINITION_SET_FORMAT_REVISION: u16 = 1;
pub const DEFINITION_SET_GENERATION_FORMAT_REVISION: u16 = 1;
pub const MAX_DEFINITION_HANDLE_BYTES: usize = 128;
pub const MAX_DEFINITION_SET_ENTRIES: usize = 256;
pub const MAX_DEFINITION_SET_WIRE_BYTES: usize = 128 * 1024;
pub const MAX_DEFINITION_SET_GENERATION_WIRE_BYTES: usize = 160 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefinitionKind {
    NeedGrammar,
    PredicateContract,
    ActionContract,
    ArtifactContract,
    ValidatorDefinition,
    PartitionPolicy,
    PartitionScheme,
    ManifestTransition,
    MergePolicy,
    RefreshPolicy,
    WorldCompatibilityRule,
    DerivationRule,
    CompletenessOracle,
}

impl DefinitionKind {
    const fn tag(self) -> u8 {
        match self {
            Self::NeedGrammar => 0,
            Self::PredicateContract => 1,
            Self::ActionContract => 2,
            Self::ArtifactContract => 3,
            Self::ValidatorDefinition => 4,
            Self::PartitionPolicy => 5,
            Self::PartitionScheme => 6,
            Self::ManifestTransition => 7,
            Self::MergePolicy => 8,
            Self::RefreshPolicy => 9,
            Self::WorldCompatibilityRule => 10,
            Self::DerivationRule => 11,
            Self::CompletenessOracle => 12,
        }
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DefinitionHandle(String);

impl DefinitionHandle {
    pub fn new(value: impl Into<String>) -> Result<Self, DefinitionGenerationError> {
        let value = value.into();
        let bytes = value.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_DEFINITION_HANDLE_BYTES {
            return Err(DefinitionGenerationError::HandleLength);
        }
        if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
            return Err(DefinitionGenerationError::HandleCharacter(0));
        }
        if let Some((index, _)) = bytes.iter().enumerate().find(|(_, byte)| {
            !(byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(**byte, b'.' | b'_' | b'-' | b':' | b'@'))
        }) {
            return Err(DefinitionGenerationError::HandleCharacter(index));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for DefinitionHandle {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for DefinitionHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("DefinitionHandle").field(&self.0).finish()
    }
}

impl fmt::Display for DefinitionHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for DefinitionHandle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DefinitionHandle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// One immutable definition and the authority domains that depend on it.
///
/// `definition_digest` identifies the complete source definition. The three
/// optional authority digests are intentionally separate so callers never
/// need to treat the aggregate definition set as a cache identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefinitionSetEntry {
    pub kind: DefinitionKind,
    pub handle: DefinitionHandle,
    pub semantic_definition_digest: Option<Digest>,
    pub validation_definition_digest: Option<Digest>,
    pub operational_definition_digest: Option<Digest>,
    pub definition_digest: Digest,
    pub binding_digest: Digest,
}

impl DefinitionSetEntry {
    pub fn new(
        kind: DefinitionKind,
        handle: DefinitionHandle,
        semantic_definition_digest: Option<Digest>,
        validation_definition_digest: Option<Digest>,
        operational_definition_digest: Option<Digest>,
        definition_digest: Digest,
    ) -> Result<Self, DefinitionGenerationError> {
        let mut value = Self {
            kind,
            handle,
            semantic_definition_digest,
            validation_definition_digest,
            operational_definition_digest,
            definition_digest,
            binding_digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.binding_digest = value.compute_binding_digest();
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), DefinitionGenerationError> {
        self.validate_shape()?;
        if self.binding_digest != self.compute_binding_digest() {
            return Err(DefinitionGenerationError::Digest("definition_set.entry.binding_digest"));
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), DefinitionGenerationError> {
        if self.semantic_definition_digest.is_none()
            && self.validation_definition_digest.is_none()
            && self.operational_definition_digest.is_none()
        {
            return Err(DefinitionGenerationError::AuthorityMissing);
        }
        Ok(())
    }

    fn compute_binding_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"definition-set-entry-v1");
        hasher.field_u8(self.kind.tag());
        hasher.field_str(self.handle.as_str());
        hash_optional_digest(&mut hasher, self.semantic_definition_digest);
        hash_optional_digest(&mut hasher, self.validation_definition_digest);
        hash_optional_digest(&mut hasher, self.operational_definition_digest);
        hasher.field_digest(self.definition_digest);
        hasher.finish()
    }
}

/// Canonical content snapshot of every active immutable runtime definition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefinitionSet {
    pub format_revision: u16,
    #[serde(deserialize_with = "deserialize_entries")]
    pub entries: Vec<DefinitionSetEntry>,
    pub semantic_set_digest: Digest,
    pub validation_set_digest: Digest,
    pub operational_set_digest: Digest,
    pub audit_digest: Digest,
}

impl DefinitionSet {
    pub fn new(mut entries: Vec<DefinitionSetEntry>) -> Result<Self, DefinitionGenerationError> {
        entries.sort_unstable_by(|left, right| {
            (left.kind, &left.handle).cmp(&(right.kind, &right.handle))
        });
        let mut value = Self {
            format_revision: DEFINITION_SET_FORMAT_REVISION,
            entries,
            semantic_set_digest: Digest([0; 32]),
            validation_set_digest: Digest([0; 32]),
            operational_set_digest: Digest([0; 32]),
            audit_digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.semantic_set_digest = value.compute_authority_digest(DefinitionAuthority::Semantic);
        value.validation_set_digest =
            value.compute_authority_digest(DefinitionAuthority::Validation);
        value.operational_set_digest =
            value.compute_authority_digest(DefinitionAuthority::Operational);
        value.audit_digest = value.compute_audit_digest();
        Ok(value)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, DefinitionGenerationError> {
        if bytes.len() > MAX_DEFINITION_SET_WIRE_BYTES {
            return Err(DefinitionGenerationError::Bound {
                field: "definition_set.wire_bytes",
                actual: bytes.len(),
                maximum: MAX_DEFINITION_SET_WIRE_BYTES,
            });
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| DefinitionGenerationError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), DefinitionGenerationError> {
        self.validate_shape()?;
        if self.semantic_set_digest != self.compute_authority_digest(DefinitionAuthority::Semantic)
        {
            return Err(DefinitionGenerationError::Digest("definition_set.semantic_set_digest"));
        }
        if self.validation_set_digest
            != self.compute_authority_digest(DefinitionAuthority::Validation)
        {
            return Err(DefinitionGenerationError::Digest("definition_set.validation_set_digest"));
        }
        if self.operational_set_digest
            != self.compute_authority_digest(DefinitionAuthority::Operational)
        {
            return Err(DefinitionGenerationError::Digest("definition_set.operational_set_digest"));
        }
        if self.audit_digest != self.compute_audit_digest() {
            return Err(DefinitionGenerationError::Digest("definition_set.audit_digest"));
        }
        Ok(())
    }

    pub fn is_canonical(&self) -> bool {
        self.validate().is_ok()
    }

    fn validate_shape(&self) -> Result<(), DefinitionGenerationError> {
        if self.format_revision != DEFINITION_SET_FORMAT_REVISION {
            return Err(DefinitionGenerationError::FormatRevision {
                record: "definition_set",
                actual: self.format_revision,
            });
        }
        if self.entries.is_empty() || self.entries.len() > MAX_DEFINITION_SET_ENTRIES {
            return Err(DefinitionGenerationError::Bound {
                field: "definition_set.entries",
                actual: self.entries.len(),
                maximum: MAX_DEFINITION_SET_ENTRIES,
            });
        }
        for entry in &self.entries {
            entry.validate()?;
        }
        if self
            .entries
            .windows(2)
            .any(|pair| (pair[0].kind, &pair[0].handle) >= (pair[1].kind, &pair[1].handle))
        {
            return Err(DefinitionGenerationError::NonCanonicalEntries);
        }
        Ok(())
    }

    fn compute_authority_digest(&self, authority: DefinitionAuthority) -> Digest {
        let mut hasher = CanonicalHasher::new(authority.domain());
        hasher.field_u16(self.format_revision);
        let count = self.entries.iter().filter(|entry| authority.digest(entry).is_some()).count();
        hasher.field_u32(count.try_into().unwrap_or(u32::MAX));
        for entry in &self.entries {
            let Some(digest) = authority.digest(entry) else {
                continue;
            };
            hasher.field_u8(entry.kind.tag());
            hasher.field_str(entry.handle.as_str());
            hasher.field_digest(digest);
        }
        hasher.finish()
    }

    fn compute_audit_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"definition-set-audit-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.semantic_set_digest);
        hasher.field_digest(self.validation_set_digest);
        hasher.field_digest(self.operational_set_digest);
        hasher.field_u32(self.entries.len().try_into().unwrap_or(u32::MAX));
        for entry in &self.entries {
            hasher.field_digest(entry.binding_digest);
        }
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefinitionSetGeneration {
    pub format_revision: u16,
    pub generation: u64,
    pub definition_set: DefinitionSet,
    pub digest: Digest,
}

impl DefinitionSetGeneration {
    pub fn new(
        generation: u64,
        definition_set: DefinitionSet,
    ) -> Result<Self, DefinitionGenerationError> {
        definition_set.validate()?;
        let mut value = Self {
            format_revision: DEFINITION_SET_GENERATION_FORMAT_REVISION,
            generation,
            definition_set,
            digest: Digest([0; 32]),
        };
        value.digest = value.compute_digest();
        Ok(value)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, DefinitionGenerationError> {
        if bytes.len() > MAX_DEFINITION_SET_GENERATION_WIRE_BYTES {
            return Err(DefinitionGenerationError::Bound {
                field: "definition_set_generation.wire_bytes",
                actual: bytes.len(),
                maximum: MAX_DEFINITION_SET_GENERATION_WIRE_BYTES,
            });
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| DefinitionGenerationError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), DefinitionGenerationError> {
        if self.format_revision != DEFINITION_SET_GENERATION_FORMAT_REVISION {
            return Err(DefinitionGenerationError::FormatRevision {
                record: "definition_set_generation",
                actual: self.format_revision,
            });
        }
        self.definition_set.validate()?;
        if self.digest != self.compute_digest() {
            return Err(DefinitionGenerationError::Digest("definition_set_generation.digest"));
        }
        Ok(())
    }

    pub fn is_canonical(&self) -> bool {
        self.validate().is_ok()
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"definition-set-generation-v1");
        hasher.field_u16(self.format_revision);
        hash_u64(&mut hasher, self.generation);
        hasher.field_digest(self.definition_set.semantic_set_digest);
        hasher.field_digest(self.definition_set.validation_set_digest);
        hasher.field_digest(self.definition_set.operational_set_digest);
        hasher.field_digest(self.definition_set.audit_digest);
        hasher.finish()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DefinitionGenerationError {
    #[error("unsupported {record} format revision {actual}")]
    FormatRevision { record: &'static str, actual: u16 },
    #[error("{field} exceeds its bound: {actual} > {maximum}")]
    Bound { field: &'static str, actual: usize, maximum: usize },
    #[error("definition handle must contain between 1 and 128 ASCII bytes")]
    HandleLength,
    #[error("definition handle contains an invalid character at byte {0}")]
    HandleCharacter(usize),
    #[error("a definition-set entry must belong to at least one authority domain")]
    AuthorityMissing,
    #[error("definition-set entries must be strictly sorted and unique")]
    NonCanonicalEntries,
    #[error("canonical digest mismatch for {0}")]
    Digest(&'static str),
    #[error("definition generation JSON is invalid: {0}")]
    Json(String),
}

#[derive(Clone, Copy)]
enum DefinitionAuthority {
    Semantic,
    Validation,
    Operational,
}

impl DefinitionAuthority {
    const fn domain(self) -> &'static [u8] {
        match self {
            Self::Semantic => b"definition-set-semantic-v1",
            Self::Validation => b"definition-set-validation-v1",
            Self::Operational => b"definition-set-operational-v1",
        }
    }

    const fn digest(self, entry: &DefinitionSetEntry) -> Option<Digest> {
        match self {
            Self::Semantic => entry.semantic_definition_digest,
            Self::Validation => entry.validation_definition_digest,
            Self::Operational => entry.operational_definition_digest,
        }
    }
}

fn hash_optional_digest(hasher: &mut CanonicalHasher, digest: Option<Digest>) {
    match digest {
        Some(digest) => {
            hasher.field_u8(1);
            hasher.field_digest(digest);
        }
        None => hasher.field_u8(0),
    }
}

fn hash_u64(hasher: &mut CanonicalHasher, value: u64) {
    hasher.field_u32((value >> 32) as u32);
    hasher.field_u32(value as u32);
}

fn deserialize_entries<'de, D>(deserializer: D) -> Result<Vec<DefinitionSetEntry>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct EntriesVisitor;

    impl<'de> serde::de::Visitor<'de> for EntriesVisitor {
        type Value = Vec<DefinitionSetEntry>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_DEFINITION_SET_ENTRIES} definition-set entries")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut entries = Vec::with_capacity(
                sequence.size_hint().unwrap_or(0).min(MAX_DEFINITION_SET_ENTRIES),
            );
            while let Some(entry) = sequence.next_element()? {
                if entries.len() == MAX_DEFINITION_SET_ENTRIES {
                    return Err(serde::de::Error::custom(format_args!(
                        "definition_set.entries exceeds {MAX_DEFINITION_SET_ENTRIES} entries"
                    )));
                }
                entries.push(entry);
            }
            Ok(entries)
        }
    }

    deserializer.deserialize_seq(EntriesVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(
        label: &str,
        semantic: Option<&str>,
        validation: Option<&str>,
        operational: Option<&str>,
    ) -> DefinitionSetEntry {
        DefinitionSetEntry::new(
            DefinitionKind::ActionContract,
            DefinitionHandle::new(label).unwrap(),
            semantic.map(|value| Digest::blake3(value.as_bytes())),
            validation.map(|value| Digest::blake3(value.as_bytes())),
            operational.map(|value| Digest::blake3(value.as_bytes())),
            Digest::blake3(format!("record:{label}")),
        )
        .unwrap()
    }

    #[test]
    fn authority_digests_are_isolated_and_order_is_canonical() {
        let base = DefinitionSet::new(vec![
            entry("needle.second", Some("semantic-b"), Some("validation-b"), Some("op-b")),
            entry("needle.first", Some("semantic-a"), Some("validation-a"), Some("op-a")),
        ])
        .unwrap();
        assert_eq!(base.entries[0].handle.as_str(), "needle.first");

        let operational = DefinitionSet::new(vec![
            entry("needle.first", Some("semantic-a"), Some("validation-a"), Some("op-new")),
            entry("needle.second", Some("semantic-b"), Some("validation-b"), Some("op-b")),
        ])
        .unwrap();
        assert_eq!(base.semantic_set_digest, operational.semantic_set_digest);
        assert_eq!(base.validation_set_digest, operational.validation_set_digest);
        assert_ne!(base.operational_set_digest, operational.operational_set_digest);
        assert_ne!(base.audit_digest, operational.audit_digest);

        let validation = DefinitionSet::new(vec![
            entry("needle.first", Some("semantic-a"), Some("validation-new"), Some("op-a")),
            entry("needle.second", Some("semantic-b"), Some("validation-b"), Some("op-b")),
        ])
        .unwrap();
        assert_eq!(base.semantic_set_digest, validation.semantic_set_digest);
        assert_ne!(base.validation_set_digest, validation.validation_set_digest);
        assert_eq!(base.operational_set_digest, validation.operational_set_digest);
    }

    #[test]
    fn duplicate_missing_authority_and_bounds_are_rejected() {
        let duplicate = entry("needle.same", Some("semantic"), None, None);
        assert_eq!(
            DefinitionSet::new(vec![duplicate.clone(), duplicate]).unwrap_err(),
            DefinitionGenerationError::NonCanonicalEntries
        );
        assert_eq!(
            DefinitionSetEntry::new(
                DefinitionKind::ValidatorDefinition,
                DefinitionHandle::new("needle.validator").unwrap(),
                None,
                None,
                None,
                Digest::blake3(b"validator"),
            )
            .unwrap_err(),
            DefinitionGenerationError::AuthorityMissing
        );
        assert!(DefinitionHandle::new("x".repeat(MAX_DEFINITION_HANDLE_BYTES)).is_ok());
        assert_eq!(
            DefinitionHandle::new("x".repeat(MAX_DEFINITION_HANDLE_BYTES + 1)).unwrap_err(),
            DefinitionGenerationError::HandleLength
        );
    }

    #[test]
    fn generation_round_trip_rejects_tamper_unknown_fields_and_oversized_entries() {
        let set = DefinitionSet::new(vec![entry(
            "needle.action",
            Some("semantic"),
            Some("validation"),
            Some("operational"),
        )])
        .unwrap();
        let generation = DefinitionSetGeneration::new(7, set).unwrap();
        let encoded = serde_json::to_vec(&generation).unwrap();
        assert_eq!(DefinitionSetGeneration::decode_json(&encoded).unwrap(), generation);

        let mut tampered = serde_json::to_value(&generation).unwrap();
        tampered["digest"] = serde_json::to_value(Digest::blake3(b"tampered")).unwrap();
        assert!(
            DefinitionSetGeneration::decode_json(&serde_json::to_vec(&tampered).unwrap()).is_err()
        );

        let mut unknown = serde_json::to_value(&generation).unwrap();
        unknown.as_object_mut().unwrap().insert("unknown".to_owned(), serde_json::json!(true));
        assert!(
            DefinitionSetGeneration::decode_json(&serde_json::to_vec(&unknown).unwrap()).is_err()
        );

        let mut oversized = serde_json::to_value(&generation.definition_set).unwrap();
        oversized["entries"] = serde_json::Value::Array(
            (0..=MAX_DEFINITION_SET_ENTRIES)
                .map(|index| {
                    serde_json::to_value(entry(
                        &format!("needle.action-{index:03}"),
                        Some("semantic"),
                        None,
                        None,
                    ))
                    .unwrap()
                })
                .collect(),
        );
        assert!(DefinitionSet::decode_json(&serde_json::to_vec(&oversized).unwrap()).is_err());
    }
}
