use crate::{ArtifactId, CanonicalHasher, Digest};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::marker::PhantomData;
use thiserror::Error;

pub const REPOSITORY_GENERATION_FORMAT_REVISION: u16 = 1;
pub const STATE_DELTA_FORMAT_REVISION: u16 = 1;
pub const MAX_REPOSITORY_GENERATION_WIRE_BYTES: usize = 16 * 1024;
pub const MAX_STATE_DELTA_WIRE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_STATE_DELTA_LOCATORS: usize = 4_096;
pub const MAX_STATE_DELTA_INPUT_ARTIFACTS: usize = 256;
pub const MAX_STATE_DELTA_DEFINITIONS: usize = 256;
pub const MAX_STATE_DELTA_WORLD_DIMENSIONS: usize = 64;
pub const MAX_REPOSITORY_PATH_BYTES: usize = 512;

/// Local operational identity for one tracked repository context, normally a
/// specific worktree. It deliberately does not participate in semantic action
/// or artifact identity.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RepositoryContextId(Digest);

impl RepositoryContextId {
    pub const fn new(digest: Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(self) -> Digest {
        self.0
    }
}

impl fmt::Debug for RepositoryContextId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("RepositoryContextId").field(&self.0).finish()
    }
}

impl fmt::Display for RepositoryContextId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A language-agnostic dependency locator. Repository paths are reduced to a
/// canonical digest. Domain-specific locators remain opaque and are namespaced
/// by the definition digest of their registered provider scheme.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DependencyLocator {
    RepositoryPath { path_digest: Digest },
    ProviderOpaque { scheme_definition_digest: Digest, locator_digest: Digest },
}

impl DependencyLocator {
    pub fn repository_path(path: &str) -> Result<Self, RepositoryGenerationError> {
        let canonical = canonical_repository_path(path)?;
        let mut hasher = CanonicalHasher::new(b"repository-path-locator-v1");
        hasher.field_str(&canonical);
        Ok(Self::RepositoryPath { path_digest: hasher.finish() })
    }

    pub const fn from_repository_path_digest(path_digest: Digest) -> Self {
        Self::RepositoryPath { path_digest }
    }

    pub const fn provider_opaque(scheme_definition_digest: Digest, locator_digest: Digest) -> Self {
        Self::ProviderOpaque { scheme_definition_digest, locator_digest }
    }

    fn hash_into(self, hasher: &mut CanonicalHasher) {
        match self {
            Self::RepositoryPath { path_digest } => {
                hasher.field_u8(0);
                hasher.field_digest(path_digest);
            }
            Self::ProviderOpaque { scheme_definition_digest, locator_digest } => {
                hasher.field_u8(1);
                hasher.field_digest(scheme_definition_digest);
                hasher.field_digest(locator_digest);
            }
        }
    }
}

/// Immutable local observation of one repository/worktree generation.
/// `source_context_digest` binds the complete source state observed by the
/// caller. `source_version_digest` is an optional VCS/provider version handle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryGeneration {
    pub format_revision: u16,
    pub repository_lineage: Digest,
    pub repository_context: RepositoryContextId,
    pub generation: u64,
    pub source_context_digest: Digest,
    pub source_version_digest: Option<Digest>,
    pub reconciled: bool,
    pub digest: Digest,
}

impl RepositoryGeneration {
    pub fn new(
        repository_lineage: Digest,
        repository_context: RepositoryContextId,
        generation: u64,
        source_context_digest: Digest,
        source_version_digest: Option<Digest>,
        reconciled: bool,
    ) -> Self {
        let mut value = Self {
            format_revision: REPOSITORY_GENERATION_FORMAT_REVISION,
            repository_lineage,
            repository_context,
            generation,
            source_context_digest,
            source_version_digest,
            reconciled,
            digest: Digest([0; 32]),
        };
        value.digest = value.compute_digest();
        value
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, RepositoryGenerationError> {
        if bytes.len() > MAX_REPOSITORY_GENERATION_WIRE_BYTES {
            return Err(RepositoryGenerationError::Bound {
                field: "repository_generation.wire_bytes",
                actual: bytes.len(),
                maximum: MAX_REPOSITORY_GENERATION_WIRE_BYTES,
            });
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| RepositoryGenerationError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), RepositoryGenerationError> {
        if self.format_revision != REPOSITORY_GENERATION_FORMAT_REVISION {
            return Err(RepositoryGenerationError::FormatRevision {
                record: "repository_generation",
                actual: self.format_revision,
            });
        }
        if self.digest != self.compute_digest() {
            return Err(RepositoryGenerationError::Digest("repository_generation.digest"));
        }
        Ok(())
    }

    pub fn is_canonical(&self) -> bool {
        self.validate().is_ok()
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"repository-generation-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.repository_lineage);
        hasher.field_digest(self.repository_context.digest());
        hash_u64(&mut hasher, self.generation);
        hasher.field_digest(self.source_context_digest);
        hash_optional_digest(&mut hasher, self.source_version_digest);
        hasher.field_u8(u8::from(self.reconciled));
        hasher.finish()
    }
}

/// Complete or explicitly incomplete set of changes between two adjacent
/// repository generations. No locator is interpreted by the generic kernel.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateDelta {
    pub format_revision: u16,
    pub repository_lineage: Digest,
    pub repository_context: RepositoryContextId,
    pub from_generation: u64,
    pub to_generation: u64,
    #[serde(deserialize_with = "deserialize_changed_locators")]
    pub changed_locators: Vec<DependencyLocator>,
    #[serde(deserialize_with = "deserialize_changed_input_artifacts")]
    pub changed_input_artifacts: Vec<ArtifactId>,
    #[serde(deserialize_with = "deserialize_changed_definitions")]
    pub changed_definitions: Vec<Digest>,
    #[serde(deserialize_with = "deserialize_semantic_world_changes")]
    pub semantic_world_changes: Vec<Digest>,
    pub complete: bool,
    pub digest: Digest,
}

impl StateDelta {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository_lineage: Digest,
        repository_context: RepositoryContextId,
        from_generation: u64,
        to_generation: u64,
        mut changed_locators: Vec<DependencyLocator>,
        mut changed_input_artifacts: Vec<ArtifactId>,
        mut changed_definitions: Vec<Digest>,
        mut semantic_world_changes: Vec<Digest>,
        complete: bool,
    ) -> Result<Self, RepositoryGenerationError> {
        changed_locators.sort_unstable();
        changed_input_artifacts.sort_unstable();
        changed_definitions.sort_unstable();
        semantic_world_changes.sort_unstable();
        let mut value = Self {
            format_revision: STATE_DELTA_FORMAT_REVISION,
            repository_lineage,
            repository_context,
            from_generation,
            to_generation,
            changed_locators,
            changed_input_artifacts,
            changed_definitions,
            semantic_world_changes,
            complete,
            digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.digest = value.compute_digest();
        Ok(value)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, RepositoryGenerationError> {
        if bytes.len() > MAX_STATE_DELTA_WIRE_BYTES {
            return Err(RepositoryGenerationError::Bound {
                field: "state_delta.wire_bytes",
                actual: bytes.len(),
                maximum: MAX_STATE_DELTA_WIRE_BYTES,
            });
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| RepositoryGenerationError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), RepositoryGenerationError> {
        self.validate_shape()?;
        if self.digest != self.compute_digest() {
            return Err(RepositoryGenerationError::Digest("state_delta.digest"));
        }
        Ok(())
    }

    pub fn is_canonical(&self) -> bool {
        self.validate().is_ok()
    }

    fn validate_shape(&self) -> Result<(), RepositoryGenerationError> {
        if self.format_revision != STATE_DELTA_FORMAT_REVISION {
            return Err(RepositoryGenerationError::FormatRevision {
                record: "state_delta",
                actual: self.format_revision,
            });
        }
        if self.from_generation.checked_add(1) != Some(self.to_generation) {
            return Err(RepositoryGenerationError::NonAdjacentTransition {
                from: self.from_generation,
                to: self.to_generation,
            });
        }
        validate_canonical_set(
            "state_delta.changed_locators",
            &self.changed_locators,
            MAX_STATE_DELTA_LOCATORS,
        )?;
        validate_canonical_set(
            "state_delta.changed_input_artifacts",
            &self.changed_input_artifacts,
            MAX_STATE_DELTA_INPUT_ARTIFACTS,
        )?;
        validate_canonical_set(
            "state_delta.changed_definitions",
            &self.changed_definitions,
            MAX_STATE_DELTA_DEFINITIONS,
        )?;
        validate_canonical_set(
            "state_delta.semantic_world_changes",
            &self.semantic_world_changes,
            MAX_STATE_DELTA_WORLD_DIMENSIONS,
        )?;
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"repository-state-delta-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.repository_lineage);
        hasher.field_digest(self.repository_context.digest());
        hash_u64(&mut hasher, self.from_generation);
        hash_u64(&mut hasher, self.to_generation);
        hasher.field_u32(self.changed_locators.len().try_into().unwrap_or(u32::MAX));
        for locator in &self.changed_locators {
            locator.hash_into(&mut hasher);
        }
        hasher.field_u32(self.changed_input_artifacts.len().try_into().unwrap_or(u32::MAX));
        for artifact in &self.changed_input_artifacts {
            hasher.field_digest(artifact.digest());
        }
        hasher.field_u32(self.changed_definitions.len().try_into().unwrap_or(u32::MAX));
        for definition in &self.changed_definitions {
            hasher.field_digest(*definition);
        }
        hasher.field_u32(self.semantic_world_changes.len().try_into().unwrap_or(u32::MAX));
        for dimension in &self.semantic_world_changes {
            hasher.field_digest(*dimension);
        }
        hasher.field_u8(u8::from(self.complete));
        hasher.finish()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RepositoryGenerationError {
    #[error("unsupported {record} format revision {actual}")]
    FormatRevision { record: &'static str, actual: u16 },
    #[error("{field} exceeds its bound: {actual} > {maximum}")]
    Bound { field: &'static str, actual: usize, maximum: usize },
    #[error("{field} must be strictly sorted and unique")]
    NonCanonicalSet { field: &'static str },
    #[error("repository generation transition must be adjacent: {from} -> {to}")]
    NonAdjacentTransition { from: u64, to: u64 },
    #[error("repository path is not a canonical safe relative path")]
    RepositoryPath,
    #[error("canonical digest mismatch for {0}")]
    Digest(&'static str),
    #[error("repository generation JSON is invalid: {0}")]
    Json(String),
}

fn canonical_repository_path(value: &str) -> Result<String, RepositoryGenerationError> {
    if value.is_empty()
        || value.len() > MAX_REPOSITORY_PATH_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(RepositoryGenerationError::RepositoryPath);
    }
    let normalized = value.replace('\\', "/");
    if normalized.starts_with('/')
        || normalized.ends_with('/')
        || normalized
            .as_bytes()
            .get(1)
            .is_some_and(|value| *value == b':' && normalized.as_bytes()[0].is_ascii_alphabetic())
        || normalized.split('/').any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(RepositoryGenerationError::RepositoryPath);
    }
    Ok(normalized)
}

fn validate_canonical_set<T: Ord>(
    field: &'static str,
    values: &[T],
    maximum: usize,
) -> Result<(), RepositoryGenerationError> {
    if values.len() > maximum {
        return Err(RepositoryGenerationError::Bound { field, actual: values.len(), maximum });
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(RepositoryGenerationError::NonCanonicalSet { field });
    }
    Ok(())
}

fn hash_u64(hasher: &mut CanonicalHasher, value: u64) {
    hasher.field_bytes(&value.to_le_bytes());
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

fn deserialize_changed_locators<'de, D>(deserializer: D) -> Result<Vec<DependencyLocator>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, DependencyLocator, MAX_STATE_DELTA_LOCATORS>(
        deserializer,
        "state_delta.changed_locators",
    )
}

fn deserialize_changed_input_artifacts<'de, D>(deserializer: D) -> Result<Vec<ArtifactId>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, ArtifactId, MAX_STATE_DELTA_INPUT_ARTIFACTS>(
        deserializer,
        "state_delta.changed_input_artifacts",
    )
}

fn deserialize_changed_definitions<'de, D>(deserializer: D) -> Result<Vec<Digest>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, Digest, MAX_STATE_DELTA_DEFINITIONS>(
        deserializer,
        "state_delta.changed_definitions",
    )
}

fn deserialize_semantic_world_changes<'de, D>(deserializer: D) -> Result<Vec<Digest>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, Digest, MAX_STATE_DELTA_WORLD_DIMENSIONS>(
        deserializer,
        "state_delta.semantic_world_changes",
    )
}

fn deserialize_bounded_vec<'de, D, T, const MAXIMUM: usize>(
    deserializer: D,
    field: &'static str,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVecVisitor<T, const MAXIMUM: usize> {
        field: &'static str,
        marker: PhantomData<T>,
    }

    impl<'de, T, const MAXIMUM: usize> Visitor<'de> for BoundedVecVisitor<T, MAXIMUM>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

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
            while let Some(value) = sequence.next_element()? {
                if values.len() == MAXIMUM {
                    return Err(serde::de::Error::custom(format_args!(
                        "{} exceeds its bound of {MAXIMUM}",
                        self.field
                    )));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(BoundedVecVisitor::<T, MAXIMUM> { field, marker: PhantomData })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn digest(label: impl AsRef<[u8]>) -> Digest {
        Digest::blake3(label)
    }

    fn context() -> RepositoryContextId {
        RepositoryContextId::new(digest("worktree"))
    }

    fn delta() -> StateDelta {
        StateDelta::new(
            digest("repository"),
            context(),
            7,
            8,
            vec![
                DependencyLocator::provider_opaque(digest("scheme"), digest("provider-value")),
                DependencyLocator::repository_path("src/lib.rs").unwrap(),
            ],
            vec![ArtifactId::new(digest("input"))],
            vec![digest("definition")],
            vec![digest("world")],
            true,
        )
        .unwrap()
    }

    #[test]
    fn repository_paths_are_platform_neutral_and_opaque() {
        assert_eq!(
            DependencyLocator::repository_path("src\\lib.rs").unwrap(),
            DependencyLocator::repository_path("src/lib.rs").unwrap()
        );
        for invalid in ["", "/src/lib.rs", "C:\\src\\lib.rs", "src/../lib.rs", "src//lib.rs"] {
            assert_eq!(
                DependencyLocator::repository_path(invalid),
                Err(RepositoryGenerationError::RepositoryPath)
            );
        }
    }

    #[test]
    fn repository_generation_rejects_tamper_and_unknown_fields() {
        let generation = RepositoryGeneration::new(
            digest("repository"),
            context(),
            3,
            digest("source"),
            Some(digest("version")),
            true,
        );
        assert!(generation.is_canonical());
        let mut tampered = generation.clone();
        tampered.reconciled = false;
        assert_eq!(
            tampered.validate(),
            Err(RepositoryGenerationError::Digest("repository_generation.digest"))
        );

        let mut wire = serde_json::to_value(&generation).unwrap();
        wire.as_object_mut().unwrap().insert("unknown".to_owned(), json!(true));
        assert!(RepositoryGeneration::decode_json(&serde_json::to_vec(&wire).unwrap()).is_err());
    }

    #[test]
    fn state_delta_is_canonical_and_order_independent_at_construction() {
        let expected = delta();
        let reordered = StateDelta::new(
            expected.repository_lineage,
            expected.repository_context,
            expected.from_generation,
            expected.to_generation,
            expected.changed_locators.iter().copied().rev().collect(),
            expected.changed_input_artifacts.iter().copied().rev().collect(),
            expected.changed_definitions.iter().copied().rev().collect(),
            expected.semantic_world_changes.iter().copied().rev().collect(),
            expected.complete,
        )
        .unwrap();
        assert_eq!(expected, reordered);
        assert_eq!(
            expected.digest.to_string(),
            "b3:16c66457160638d5ef5f8587e09748d9120eece65e5dc6756011e5a746b7f196"
        );
    }

    #[test]
    fn state_delta_rejects_noncanonical_tamper_and_non_adjacent_transition() {
        let mut tampered = delta();
        tampered.changed_definitions.push(tampered.changed_definitions[0]);
        assert_eq!(
            tampered.validate(),
            Err(RepositoryGenerationError::NonCanonicalSet {
                field: "state_delta.changed_definitions"
            })
        );
        assert!(matches!(
            StateDelta::new(
                digest("repository"),
                context(),
                7,
                9,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                false,
            ),
            Err(RepositoryGenerationError::NonAdjacentTransition { from: 7, to: 9 })
        ));
    }

    #[test]
    fn state_delta_bounds_are_enforced_before_retention() {
        let locator =
            serde_json::to_value(DependencyLocator::from_repository_path_digest(digest("path")))
                .unwrap();
        let mut wire = serde_json::to_value(delta()).unwrap();
        wire["changed_locators"] = serde_json::Value::Array(
            (0..=MAX_STATE_DELTA_LOCATORS).map(|_| locator.clone()).collect(),
        );
        let bytes = serde_json::to_vec(&wire).unwrap();
        assert!(serde_json::from_slice::<StateDelta>(&bytes).is_err());

        assert!(matches!(
            StateDelta::new(
                digest("repository"),
                context(),
                0,
                1,
                (0..=MAX_STATE_DELTA_LOCATORS)
                    .map(|index| {
                        DependencyLocator::from_repository_path_digest(digest(index.to_le_bytes()))
                    })
                    .collect(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                false,
            ),
            Err(RepositoryGenerationError::Bound {
                field: "state_delta.changed_locators",
                actual,
                maximum: MAX_STATE_DELTA_LOCATORS,
            }) if actual == MAX_STATE_DELTA_LOCATORS + 1
        ));
    }
}
