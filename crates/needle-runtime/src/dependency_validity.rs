use crate::semantic_validation::manifest_digest;
use needle_core::{
    CanonicalHasher, DependencyLocator, DependencyManifest, Digest, MAX_NEED_IR_BYTES,
    MAX_REPOSITORY_PATH_BYTES, MAX_REQUIRED_OBLIGATIONS, RepositoryGenerationError, StateDelta,
};
use std::cmp::Ordering;
use std::sync::OnceLock;
use thiserror::Error;

pub const DEPENDENCY_INTERSECTION_FORMAT_REVISION: u16 = 1;
pub const FAST_VALIDITY_FORMAT_REVISION: u16 = 1;
pub const MAX_DEPENDENCY_MANIFEST_ENTRIES: usize = 256;
pub const MAX_DEPENDENCY_MANIFEST_TEXT_BYTES: usize = 64 * 1024;
pub const MAX_FAST_VALIDITY_DELTAS: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DependencyRevalidationReason {
    IncompleteDelta,
    ProviderOpaqueChange,
    InputArtifactChange,
    DefinitionChange,
    SemanticWorldChange,
}

/// Conservative relationship between an exact dependency-locator set and one
/// validated, adjacent state delta.
///
/// `Disjoint` is not a freshness or reuse decision. It only states that this
/// complete delta contains no changed repository-path locator in the set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DependencyDeltaIntersection {
    Disjoint,
    Intersects { locators: Vec<DependencyLocator> },
    RequiresRevalidation { reason: DependencyRevalidationReason },
}

/// Canonical, language-agnostic projection of a worktree-semantic dependency
/// manifest into exact repository-path locators.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyLocatorSet {
    pub format_revision: u16,
    pub dependency_manifest_digest: Digest,
    pub projection_definition_digest: Digest,
    pub locators: Vec<DependencyLocator>,
    pub digest: Digest,
}

impl DependencyLocatorSet {
    pub fn from_manifest(
        manifest: &DependencyManifest,
    ) -> Result<Self, DependencyIntersectionError> {
        validate_dependency_manifest_bounds(manifest)?;
        if !manifest.supports_worktree_semantic() {
            return Err(DependencyIntersectionError::ManifestIneligible);
        }

        let mut locators = Vec::with_capacity(manifest.dependencies.len());
        for dependency in &manifest.dependencies {
            let locator = DependencyLocator::repository_path(&dependency.path)
                .map_err(|_| DependencyIntersectionError::ManifestPath)?;
            locators.push(locator);
        }
        locators.sort_unstable();
        if locators.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(DependencyIntersectionError::DuplicateManifestDependency);
        }

        let mut value = Self {
            format_revision: DEPENDENCY_INTERSECTION_FORMAT_REVISION,
            dependency_manifest_digest: manifest_digest(manifest),
            projection_definition_digest: dependency_intersection_definition_digest(),
            locators,
            digest: Digest([0; 32]),
        };
        value.digest = value.compute_digest();
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), DependencyIntersectionError> {
        if self.format_revision != DEPENDENCY_INTERSECTION_FORMAT_REVISION {
            return Err(DependencyIntersectionError::FormatRevision(self.format_revision));
        }
        if self.projection_definition_digest != dependency_intersection_definition_digest() {
            return Err(DependencyIntersectionError::DefinitionDigest);
        }
        if self.locators.is_empty()
            || self.locators.len() > MAX_DEPENDENCY_MANIFEST_ENTRIES
            || self.locators.windows(2).any(|pair| pair[0] >= pair[1])
            || self
                .locators
                .iter()
                .any(|locator| !matches!(locator, DependencyLocator::RepositoryPath { .. }))
        {
            return Err(DependencyIntersectionError::NonCanonicalLocatorSet);
        }
        if self.digest != self.compute_digest() {
            return Err(DependencyIntersectionError::SetDigest);
        }
        Ok(())
    }

    pub fn is_canonical(&self) -> bool {
        self.validate().is_ok()
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"dependency-locator-set-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.dependency_manifest_digest);
        hasher.field_digest(self.projection_definition_digest);
        hasher.field_u32(self.locators.len().try_into().unwrap_or(u32::MAX));
        for locator in &self.locators {
            hash_locator(&mut hasher, *locator);
        }
        hasher.finish()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DependencyIntersectionError {
    #[error("dependency manifest is not eligible for exact worktree-semantic projection")]
    ManifestIneligible,
    #[error("dependency manifest exceeds the bounded projection limits")]
    ManifestBound,
    #[error("dependency manifest contains a non-canonical repository path")]
    ManifestPath,
    #[error("dependency manifest contains duplicate canonical repository paths")]
    DuplicateManifestDependency,
    #[error("unsupported dependency locator set format revision {0}")]
    FormatRevision(u16),
    #[error("dependency locator projection definition digest is stale or invalid")]
    DefinitionDigest,
    #[error("dependency locator set is not canonical")]
    NonCanonicalLocatorSet,
    #[error("dependency locator set digest is not canonical")]
    SetDigest,
    #[error("state delta is not canonical: {0}")]
    StateDelta(RepositoryGenerationError),
}

/// Classifies a single validated state delta without consulting the store,
/// filesystem, resolver, or any language-specific implementation.
pub fn classify_dependency_delta(
    dependencies: &DependencyLocatorSet,
    delta: &StateDelta,
) -> Result<DependencyDeltaIntersection, DependencyIntersectionError> {
    dependencies.validate()?;
    delta.validate().map_err(DependencyIntersectionError::StateDelta)?;

    if !delta.complete {
        return Ok(DependencyDeltaIntersection::RequiresRevalidation {
            reason: DependencyRevalidationReason::IncompleteDelta,
        });
    }
    if !delta.changed_input_artifacts.is_empty() {
        return Ok(DependencyDeltaIntersection::RequiresRevalidation {
            reason: DependencyRevalidationReason::InputArtifactChange,
        });
    }
    if !delta.changed_definitions.is_empty() {
        return Ok(DependencyDeltaIntersection::RequiresRevalidation {
            reason: DependencyRevalidationReason::DefinitionChange,
        });
    }
    if !delta.semantic_world_changes.is_empty() {
        return Ok(DependencyDeltaIntersection::RequiresRevalidation {
            reason: DependencyRevalidationReason::SemanticWorldChange,
        });
    }
    if delta
        .changed_locators
        .iter()
        .any(|locator| matches!(locator, DependencyLocator::ProviderOpaque { .. }))
    {
        return Ok(DependencyDeltaIntersection::RequiresRevalidation {
            reason: DependencyRevalidationReason::ProviderOpaqueChange,
        });
    }

    let mut dependency_index = 0;
    let mut changed_index = 0;
    let mut intersections = Vec::new();
    while dependency_index < dependencies.locators.len()
        && changed_index < delta.changed_locators.len()
    {
        match dependencies.locators[dependency_index].cmp(&delta.changed_locators[changed_index]) {
            Ordering::Less => dependency_index += 1,
            Ordering::Greater => changed_index += 1,
            Ordering::Equal => {
                intersections.push(dependencies.locators[dependency_index]);
                dependency_index += 1;
                changed_index += 1;
            }
        }
    }

    if intersections.is_empty() {
        Ok(DependencyDeltaIntersection::Disjoint)
    } else {
        Ok(DependencyDeltaIntersection::Intersects { locators: intersections })
    }
}

pub fn dependency_intersection_definition_digest() -> Digest {
    static DIGEST: OnceLock<Digest> = OnceLock::new();
    *DIGEST.get_or_init(|| {
        let mut hasher = CanonicalHasher::new(b"dependency-intersection-definition-v1");
        hasher.field_u16(DEPENDENCY_INTERSECTION_FORMAT_REVISION);
        hasher.field_u32(MAX_DEPENDENCY_MANIFEST_ENTRIES.try_into().unwrap_or(u32::MAX));
        hasher.field_u32(MAX_DEPENDENCY_MANIFEST_TEXT_BYTES.try_into().unwrap_or(u32::MAX));
        hasher.field_u32(MAX_REPOSITORY_PATH_BYTES.try_into().unwrap_or(u32::MAX));
        hasher.field_u32(MAX_REQUIRED_OBLIGATIONS.try_into().unwrap_or(u32::MAX));
        hasher.field_u32(MAX_NEED_IR_BYTES.try_into().unwrap_or(u32::MAX));
        hasher.field_str("exact-repository-path-locators");
        hasher.field_str("incomplete-delta-requires-revalidation");
        hasher.field_str("provider-opaque-change-requires-revalidation");
        hasher.field_str("input-artifact-change-requires-revalidation");
        hasher.field_str("definition-change-requires-revalidation");
        hasher.field_str("semantic-world-change-requires-revalidation");
        hasher.finish()
    })
}

pub fn fast_validity_definition_digest() -> Digest {
    static DIGEST: OnceLock<Digest> = OnceLock::new();
    *DIGEST.get_or_init(|| {
        let mut hasher = CanonicalHasher::new(b"fast-validity-definition-v1");
        hasher.field_u16(FAST_VALIDITY_FORMAT_REVISION);
        hasher.field_u32(MAX_FAST_VALIDITY_DELTAS.try_into().unwrap_or(u32::MAX));
        hasher.field_digest(dependency_intersection_definition_digest());
        hasher.field_digest(crate::input_artifact_state_definition_digest());
        hasher.field_str("adjacent-complete-delta-chain");
        hasher.field_str("reconciled-generations-only");
        hasher.field_str("exact-definition-generation-match");
        hasher.field_str("bounded-recursive-input-artifact-validation");
        hasher.field_str("non-external-built-in-effects-only");
        hasher.field_str("positive-current-or-unaffected-memos-only");
        hasher.finish()
    })
}

pub(crate) fn dependency_manifest_is_bounded(manifest: &DependencyManifest) -> bool {
    validate_dependency_manifest_bounds(manifest).is_ok()
}

fn validate_dependency_manifest_bounds(
    manifest: &DependencyManifest,
) -> Result<(), DependencyIntersectionError> {
    if manifest.dependencies.len() > MAX_DEPENDENCY_MANIFEST_ENTRIES
        || manifest.gaps.len() > MAX_REQUIRED_OBLIGATIONS
    {
        return Err(DependencyIntersectionError::ManifestBound);
    }

    let mut text_bytes = 0_usize;
    let mut add_text = |value: &str| {
        if value.len() > MAX_NEED_IR_BYTES {
            return false;
        }
        text_bytes = text_bytes.saturating_add(value.len());
        text_bytes <= MAX_DEPENDENCY_MANIFEST_TEXT_BYTES
    };
    for dependency in &manifest.dependencies {
        if dependency.claims.len() > MAX_REQUIRED_OBLIGATIONS || !add_text(&dependency.path) {
            return Err(DependencyIntersectionError::ManifestBound);
        }
        if !dependency.claims.iter().all(|claim| add_text(claim)) {
            return Err(DependencyIntersectionError::ManifestBound);
        }
    }
    if !manifest.gaps.iter().all(|gap| add_text(gap)) {
        return Err(DependencyIntersectionError::ManifestBound);
    }
    Ok(())
}

fn hash_locator(hasher: &mut CanonicalHasher, locator: DependencyLocator) {
    match locator {
        DependencyLocator::RepositoryPath { path_digest } => {
            hasher.field_u8(0);
            hasher.field_digest(path_digest);
        }
        DependencyLocator::ProviderOpaque { scheme_definition_digest, locator_digest } => {
            hasher.field_u8(1);
            hasher.field_digest(scheme_definition_digest);
            hasher.field_digest(locator_digest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use needle_core::{ArtifactId, CacheScope, Dependency, RepositoryContextId};

    fn digest(label: &str) -> Digest {
        Digest::blake3(label)
    }

    fn dependency(path: &str) -> Dependency {
        Dependency {
            path: path.to_owned(),
            content_digest: digest(path),
            byte_start: None,
            byte_end: None,
            claims: vec![format!("claim:{path}")],
        }
    }

    fn manifest(paths: &[&str]) -> DependencyManifest {
        DependencyManifest {
            scope: CacheScope::WorktreeSemantic,
            observed_files_complete: true,
            dependencies: paths.iter().map(|path| dependency(path)).collect(),
            gaps: Vec::new(),
        }
    }

    fn delta(
        changed_locators: Vec<DependencyLocator>,
        changed_input_artifacts: Vec<ArtifactId>,
        changed_definitions: Vec<Digest>,
        semantic_world_changes: Vec<Digest>,
        complete: bool,
    ) -> StateDelta {
        StateDelta::new(
            digest("repository"),
            RepositoryContextId::new(digest("context")),
            10,
            11,
            changed_locators,
            changed_input_artifacts,
            changed_definitions,
            semantic_world_changes,
            complete,
        )
        .unwrap()
    }

    #[test]
    fn manifest_projection_is_order_independent_and_normalizes_path_separators() {
        let left =
            DependencyLocatorSet::from_manifest(&manifest(&["src/lib.rs", "src/main.rs"])).unwrap();
        let right =
            DependencyLocatorSet::from_manifest(&manifest(&["src/main.rs", "src/lib.rs"])).unwrap();

        assert_eq!(left, right);
        assert!(left.is_canonical());

        let backslash = DependencyLocatorSet::from_manifest(&manifest(&["src\\lib.rs"])).unwrap();
        let slash = DependencyLocatorSet::from_manifest(&manifest(&["src/lib.rs"])).unwrap();
        assert_eq!(backslash.locators, slash.locators);
        assert_ne!(backslash.dependency_manifest_digest, slash.dependency_manifest_digest);
    }

    #[test]
    fn exact_path_intersection_and_disjoint_delta_are_distinguished() {
        let dependencies =
            DependencyLocatorSet::from_manifest(&manifest(&["src/lib.rs", "src/main.rs"])).unwrap();
        let changed = DependencyLocator::repository_path("src/lib.rs").unwrap();
        let unrelated = DependencyLocator::repository_path("README.md").unwrap();

        assert_eq!(
            classify_dependency_delta(
                &dependencies,
                &delta(vec![changed], vec![], vec![], vec![], true)
            )
            .unwrap(),
            DependencyDeltaIntersection::Intersects { locators: vec![changed] }
        );
        assert_eq!(
            classify_dependency_delta(
                &dependencies,
                &delta(vec![unrelated], vec![], vec![], vec![], true),
            )
            .unwrap(),
            DependencyDeltaIntersection::Disjoint
        );
    }

    #[test]
    fn rename_delta_intersects_the_old_dependency_path() {
        let dependencies = DependencyLocatorSet::from_manifest(&manifest(&["src/old.rs"])).unwrap();
        let old = DependencyLocator::repository_path("src/old.rs").unwrap();
        let new = DependencyLocator::repository_path("src/new.rs").unwrap();

        assert_eq!(
            classify_dependency_delta(
                &dependencies,
                &delta(vec![old, new], vec![], vec![], vec![], true),
            )
            .unwrap(),
            DependencyDeltaIntersection::Intersects { locators: vec![old] }
        );
    }

    #[test]
    fn uncertain_delta_dimensions_fail_closed() {
        let dependencies = DependencyLocatorSet::from_manifest(&manifest(&["src/lib.rs"])).unwrap();
        let cases = [
            (
                delta(vec![], vec![], vec![], vec![], false),
                DependencyRevalidationReason::IncompleteDelta,
            ),
            (
                delta(
                    vec![DependencyLocator::provider_opaque(digest("scheme"), digest("locator"))],
                    vec![],
                    vec![],
                    vec![],
                    true,
                ),
                DependencyRevalidationReason::ProviderOpaqueChange,
            ),
            (
                delta(vec![], vec![ArtifactId::new(digest("input"))], vec![], vec![], true),
                DependencyRevalidationReason::InputArtifactChange,
            ),
            (
                delta(vec![], vec![], vec![digest("definition")], vec![], true),
                DependencyRevalidationReason::DefinitionChange,
            ),
            (
                delta(vec![], vec![], vec![], vec![digest("semantic-world-dimension")], true),
                DependencyRevalidationReason::SemanticWorldChange,
            ),
        ];

        for (delta, reason) in cases {
            assert_eq!(
                classify_dependency_delta(&dependencies, &delta).unwrap(),
                DependencyDeltaIntersection::RequiresRevalidation { reason }
            );
        }
    }

    #[test]
    fn malformed_delta_is_rejected_before_classification() {
        let dependencies = DependencyLocatorSet::from_manifest(&manifest(&["src/lib.rs"])).unwrap();
        let mut changed = delta(vec![], vec![], vec![], vec![], true);
        changed.digest = digest("tampered");

        assert!(matches!(
            classify_dependency_delta(&dependencies, &changed),
            Err(DependencyIntersectionError::StateDelta(RepositoryGenerationError::Digest(_)))
        ));
    }

    #[test]
    fn ineligible_duplicate_and_unsafe_manifests_are_rejected() {
        let mut incomplete = manifest(&["src/lib.rs"]);
        incomplete.observed_files_complete = false;
        assert_eq!(
            DependencyLocatorSet::from_manifest(&incomplete),
            Err(DependencyIntersectionError::ManifestIneligible)
        );

        let mut gap = manifest(&["src/lib.rs"]);
        gap.gaps.push("unknown dependency".to_owned());
        assert_eq!(
            DependencyLocatorSet::from_manifest(&gap),
            Err(DependencyIntersectionError::ManifestIneligible)
        );

        let mut no_claims = manifest(&["src/lib.rs"]);
        no_claims.dependencies[0].claims.clear();
        assert_eq!(
            DependencyLocatorSet::from_manifest(&no_claims),
            Err(DependencyIntersectionError::ManifestIneligible)
        );

        assert_eq!(
            DependencyLocatorSet::from_manifest(&manifest(&["src/lib.rs", "src\\lib.rs"])),
            Err(DependencyIntersectionError::DuplicateManifestDependency)
        );
        assert_eq!(
            DependencyLocatorSet::from_manifest(&manifest(&["../outside.rs"])),
            Err(DependencyIntersectionError::ManifestPath)
        );
    }

    #[test]
    fn manifest_bounds_are_enforced_before_projection() {
        let at_limit = (0..MAX_DEPENDENCY_MANIFEST_ENTRIES)
            .map(|index| format!("src/{index}.rs"))
            .collect::<Vec<_>>();
        let at_limit_refs = at_limit.iter().map(String::as_str).collect::<Vec<_>>();
        assert!(DependencyLocatorSet::from_manifest(&manifest(&at_limit_refs)).is_ok());

        let over_limit = (0..=MAX_DEPENDENCY_MANIFEST_ENTRIES)
            .map(|index| format!("src/{index}.rs"))
            .collect::<Vec<_>>();
        let over_limit_refs = over_limit.iter().map(String::as_str).collect::<Vec<_>>();
        assert_eq!(
            DependencyLocatorSet::from_manifest(&manifest(&over_limit_refs)),
            Err(DependencyIntersectionError::ManifestBound)
        );

        let oversized = "x".repeat(MAX_NEED_IR_BYTES + 1);
        assert_eq!(
            DependencyLocatorSet::from_manifest(&manifest(&[&oversized])),
            Err(DependencyIntersectionError::ManifestBound)
        );

        let mut total_text_overflow = manifest(&["src/lib.rs"]);
        total_text_overflow.dependencies[0].claims = vec!["x".repeat(MAX_NEED_IR_BYTES); 5];
        assert_eq!(
            DependencyLocatorSet::from_manifest(&total_text_overflow),
            Err(DependencyIntersectionError::ManifestBound)
        );

        let long_but_individually_bounded_path = "x".repeat(MAX_REPOSITORY_PATH_BYTES + 1);
        assert_eq!(
            DependencyLocatorSet::from_manifest(&manifest(&[&long_but_individually_bounded_path])),
            Err(DependencyIntersectionError::ManifestPath)
        );
    }

    #[test]
    fn locator_set_detects_definition_shape_and_digest_tampering() {
        let canonical =
            DependencyLocatorSet::from_manifest(&manifest(&["src/lib.rs", "src/main.rs"])).unwrap();

        let mut changed = canonical.clone();
        changed.projection_definition_digest = digest("changed-definition");
        assert_eq!(changed.validate(), Err(DependencyIntersectionError::DefinitionDigest));

        let mut changed = canonical.clone();
        changed.locators.reverse();
        assert_eq!(changed.validate(), Err(DependencyIntersectionError::NonCanonicalLocatorSet));

        let mut changed = canonical;
        changed.digest = digest("changed-set");
        assert_eq!(changed.validate(), Err(DependencyIntersectionError::SetDigest));
    }

    #[test]
    fn dependency_intersection_definition_digest_is_stable() {
        assert_eq!(
            dependency_intersection_definition_digest(),
            Digest::parse("b3:9b6864cac84ab8ebdead4a8c55605b33ad8b23c73b6c79c7386a78493ae327ef")
                .unwrap()
        );
    }

    #[test]
    fn fast_validity_definition_digest_is_stable() {
        assert_eq!(
            fast_validity_definition_digest(),
            Digest::parse("b3:5f40a5252f1e494ad4052247c586c4c343e005fd396d789c06940cc41222ccf6")
                .unwrap()
        );
    }
}
