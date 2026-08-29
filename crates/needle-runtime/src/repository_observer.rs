use crate::snapshot::{GitSnapshotObservation, capture_git_observation, git_changed_locators};
use crate::{RuntimeStore, StoreError};
use needle_core::{
    CanonicalHasher, DependencyLocator, Digest, MAX_STATE_DELTA_LOCATORS, RepositoryContextId,
    RepositoryGeneration, StateDelta,
};
use std::collections::BTreeSet;
use std::path::Path;
use thiserror::Error;

pub const GIT_REPOSITORY_OBSERVER_REVISION: u16 = 1;
pub const MAX_REPOSITORY_SOURCE_VERSION_BYTES: usize = 256;
const MAX_STABILITY_CAPTURES: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryReconciliationStatus {
    Initialized,
    Unchanged,
    Advanced,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryReconciliation {
    pub status: RepositoryReconciliationStatus,
    pub generation: RepositoryGeneration,
    pub delta: Option<StateDelta>,
}

#[derive(Debug, Error)]
pub enum RepositoryReconciliationError {
    #[error("repository snapshot failed: {0}")]
    Snapshot(#[from] crate::SnapshotError),
    #[error("repository generation store failed: {0}")]
    Store(#[from] StoreError),
    #[error("repository changed during synchronous observation")]
    Unstable,
    #[error("repository generation counter is exhausted")]
    GenerationOverflow,
    #[error("repository state delta is invalid: {0}")]
    Generation(#[from] needle_core::RepositoryGenerationError),
    #[error("repository observation is invalid: {0}")]
    Observation(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RepositoryObservation {
    pub format_revision: u16,
    pub repository_lineage: Digest,
    pub repository_context: RepositoryContextId,
    pub generation: u64,
    pub source_context_digest: Digest,
    pub observer_definition_digest: Digest,
    pub source_version: String,
    pub locators: Vec<DependencyLocator>,
    pub locators_complete: bool,
    pub digest: Digest,
}

impl RepositoryObservation {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        repository_lineage: Digest,
        repository_context: RepositoryContextId,
        generation: u64,
        source_context_digest: Digest,
        observer_definition_digest: Digest,
        source_version: String,
        mut locators: Vec<DependencyLocator>,
        locators_complete: bool,
    ) -> Result<Self, RepositoryReconciliationError> {
        locators.sort_unstable();
        locators.dedup();
        let mut value = Self {
            format_revision: GIT_REPOSITORY_OBSERVER_REVISION,
            repository_lineage,
            repository_context,
            generation,
            source_context_digest,
            observer_definition_digest,
            source_version,
            locators,
            locators_complete,
            digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.digest = value.compute_digest();
        Ok(value)
    }

    pub(crate) fn validate(&self) -> Result<(), RepositoryReconciliationError> {
        self.validate_shape()?;
        if self.digest != self.compute_digest() {
            return Err(RepositoryReconciliationError::Observation("digest"));
        }
        Ok(())
    }

    pub(crate) fn source_version_digest(&self) -> Digest {
        source_version_digest(self.observer_definition_digest, &self.source_version)
    }

    fn validate_shape(&self) -> Result<(), RepositoryReconciliationError> {
        if self.format_revision != GIT_REPOSITORY_OBSERVER_REVISION {
            return Err(RepositoryReconciliationError::Observation("unsupported revision"));
        }
        if self.source_version.is_empty()
            || self.source_version.len() > MAX_REPOSITORY_SOURCE_VERSION_BYTES
            || self.source_version.chars().any(char::is_control)
        {
            return Err(RepositoryReconciliationError::Observation("source version"));
        }
        if self.locators.len() > MAX_STATE_DELTA_LOCATORS
            || self.locators.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(RepositoryReconciliationError::Observation("locator set"));
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"repository-observation-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_digest(self.repository_lineage);
        hasher.field_digest(self.repository_context.digest());
        hasher.field_bytes(&self.generation.to_le_bytes());
        hasher.field_digest(self.source_context_digest);
        hasher.field_digest(self.observer_definition_digest);
        hasher.field_str(&self.source_version);
        hasher.field_u32(self.locators.len().try_into().unwrap_or(u32::MAX));
        for locator in &self.locators {
            hash_locator(&mut hasher, *locator);
        }
        hasher.field_u8(u8::from(self.locators_complete));
        hasher.finish()
    }
}

pub fn git_repository_observer_definition_digest() -> Digest {
    let mut hasher = CanonicalHasher::new(b"git-repository-observer-definition-v1");
    hasher.field_u16(GIT_REPOSITORY_OBSERVER_REVISION);
    hasher.field_u32(MAX_STATE_DELTA_LOCATORS.try_into().unwrap_or(u32::MAX));
    hasher.field_u16(MAX_REPOSITORY_SOURCE_VERSION_BYTES.try_into().unwrap_or(u16::MAX));
    hasher.field_u8(MAX_STABILITY_CAPTURES.try_into().unwrap_or(u8::MAX));
    hasher.field_str("git-status-porcelain-v1-z-untracked-all");
    hasher.field_str("git-diff-name-only-z-no-renames");
    hasher.finish()
}

pub fn reconcile_git_repository(
    store: &RuntimeStore,
    root: &Path,
) -> Result<RepositoryReconciliation, RepositoryReconciliationError> {
    let captured = stable_git_observation(root)?;
    let observer_definition_digest = git_repository_observer_definition_digest();
    let repository_lineage = captured.snapshot.repository_id;
    let repository_context = repository_context_id(repository_lineage, &captured.top);
    let source_version_digest =
        source_version_digest(observer_definition_digest, captured.snapshot.head_sha.as_str());
    let current = store.current_repository_generation(repository_lineage, repository_context)?;

    let Some(current) = current else {
        let generation = RepositoryGeneration::new(
            repository_lineage,
            repository_context,
            0,
            captured.snapshot.source_digest,
            Some(source_version_digest),
            captured.locators_complete,
        );
        let observation = observation_for_capture(
            &captured,
            repository_context,
            generation.generation,
            observer_definition_digest,
        )?;
        store.initialize_observed_repository_generation(&generation, &observation)?;
        return Ok(RepositoryReconciliation {
            status: RepositoryReconciliationStatus::Initialized,
            generation,
            delta: None,
        });
    };

    let baseline =
        store.repository_observation(repository_lineage, repository_context, current.generation)?;
    if current.source_context_digest == captured.snapshot.source_digest {
        let observation = observation_for_capture(
            &captured,
            repository_context,
            current.generation,
            observer_definition_digest,
        )?;
        match baseline {
            Some(stored) if stored != observation => {
                return Err(StoreError::RepositoryGenerationConflict(
                    "an unchanged source has divergent observation material".to_owned(),
                )
                .into());
            }
            None => store.attach_repository_observation(&current, &observation)?,
            Some(_) => {}
        }
        return Ok(RepositoryReconciliation {
            status: RepositoryReconciliationStatus::Unchanged,
            generation: current,
            delta: None,
        });
    }

    let next_generation = current
        .generation
        .checked_add(1)
        .ok_or(RepositoryReconciliationError::GenerationOverflow)?;
    let mut changed_locators = BTreeSet::new();
    let mut complete = captured.locators_complete;
    extend_bounded(&mut changed_locators, captured.dirty_locators.iter().copied(), &mut complete);
    if let Some(baseline) = baseline {
        if baseline.source_context_digest != current.source_context_digest
            || baseline.observer_definition_digest != observer_definition_digest
        {
            complete = false;
        } else {
            complete &= baseline.locators_complete;
            extend_bounded(&mut changed_locators, baseline.locators.iter().copied(), &mut complete);
            match git_changed_locators(
                &captured.top,
                &baseline.source_version,
                &captured.snapshot.head_sha,
            ) {
                Ok(changed) => {
                    complete &= changed.complete;
                    extend_bounded(&mut changed_locators, changed.locators, &mut complete);
                }
                Err(_) => complete = false,
            }
        }
    } else {
        complete = false;
    }

    let delta = StateDelta::new(
        repository_lineage,
        repository_context,
        current.generation,
        next_generation,
        changed_locators.into_iter().collect(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        complete,
    )?;
    let generation = RepositoryGeneration::new(
        repository_lineage,
        repository_context,
        next_generation,
        captured.snapshot.source_digest,
        Some(source_version_digest),
        complete,
    );
    let observation = observation_for_capture(
        &captured,
        repository_context,
        next_generation,
        observer_definition_digest,
    )?;
    store.advance_observed_repository_generation(&generation, &delta, &observation)?;
    Ok(RepositoryReconciliation {
        status: RepositoryReconciliationStatus::Advanced,
        generation,
        delta: Some(delta),
    })
}

fn stable_git_observation(
    root: &Path,
) -> Result<GitSnapshotObservation, RepositoryReconciliationError> {
    let mut previous = capture_git_observation(root)?;
    for _ in 1..MAX_STABILITY_CAPTURES {
        let current = capture_git_observation(root)?;
        if current == previous {
            return Ok(current);
        }
        previous = current;
    }
    Err(RepositoryReconciliationError::Unstable)
}

fn observation_for_capture(
    captured: &GitSnapshotObservation,
    repository_context: RepositoryContextId,
    generation: u64,
    observer_definition_digest: Digest,
) -> Result<RepositoryObservation, RepositoryReconciliationError> {
    RepositoryObservation::new(
        captured.snapshot.repository_id,
        repository_context,
        generation,
        captured.snapshot.source_digest,
        observer_definition_digest,
        captured.snapshot.head_sha.clone(),
        captured.dirty_locators.clone(),
        captured.locators_complete,
    )
}

fn extend_bounded(
    target: &mut BTreeSet<DependencyLocator>,
    values: impl IntoIterator<Item = DependencyLocator>,
    complete: &mut bool,
) {
    for value in values {
        if target.contains(&value) {
            continue;
        }
        if target.len() == MAX_STATE_DELTA_LOCATORS {
            *complete = false;
            continue;
        }
        target.insert(value);
    }
}

pub(crate) fn repository_context_id(
    repository_lineage: Digest,
    canonical_repository_root: &Path,
) -> RepositoryContextId {
    let mut hasher = CanonicalHasher::new(b"repository-context-v1");
    hasher.field_digest(repository_lineage);
    hash_os_path(&mut hasher, canonical_repository_root);
    RepositoryContextId::new(hasher.finish())
}

#[cfg(unix)]
fn hash_os_path(hasher: &mut CanonicalHasher, path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    hasher.field_bytes(path.as_os_str().as_bytes());
}

#[cfg(windows)]
fn hash_os_path(hasher: &mut CanonicalHasher, path: &Path) {
    use std::os::windows::ffi::OsStrExt;
    let wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    hasher.field_u32(wide.len().try_into().unwrap_or(u32::MAX));
    for value in wide {
        hasher.field_u16(value);
    }
}

#[cfg(not(any(unix, windows)))]
fn hash_os_path(hasher: &mut CanonicalHasher, path: &Path) {
    hasher.field_str(&path.to_string_lossy());
}

fn source_version_digest(observer_definition_digest: Digest, source_version: &str) -> Digest {
    let mut hasher = CanonicalHasher::new(b"repository-source-version-v1");
    hasher.field_digest(observer_definition_digest);
    hasher.field_str(source_version);
    hasher.finish()
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
    use rusqlite::Connection;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture() -> (PathBuf, PathBuf, RuntimeStore) {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let root = std::env::temp_dir()
            .join(format!("needle-repository-observer-{}-{suffix}", std::process::id()));
        let repository = root.join("repository");
        fs::create_dir_all(repository.join("src")).unwrap();
        fs::write(repository.join("src/lib.rs"), b"pub fn answer() -> u32 { 42 }\n").unwrap();
        for arguments in [
            &["init", "--quiet"][..],
            &["config", "user.email", "needle@example.invalid"],
            &["config", "user.name", "Needle Test"],
            &["add", "src/lib.rs"],
            &["commit", "--quiet", "-m", "fixture"],
        ] {
            git(&repository, arguments);
        }
        let store = RuntimeStore::new(root.join("data/needle.sqlite3"));
        store.initialize().unwrap();
        (root, repository, store)
    }

    fn git(repository: &Path, arguments: &[&str]) {
        let output =
            Command::new("git").arg("-C").arg(repository).args(arguments).output().unwrap();
        assert!(output.status.success(), "git failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    #[test]
    fn first_observation_initializes_and_identical_source_does_not_advance() {
        let (root, repository, store) = fixture();
        let first = reconcile_git_repository(&store, &repository).unwrap();
        assert_eq!(first.status, RepositoryReconciliationStatus::Initialized);
        assert_eq!(first.generation.generation, 0);
        assert!(first.generation.reconciled);
        assert!(first.delta.is_none());

        let store_path = store.path().to_path_buf();
        drop(store);
        let store = RuntimeStore::new(store_path);
        store.initialize().unwrap();
        let second = reconcile_git_repository(&store, &repository).unwrap();
        assert_eq!(second.status, RepositoryReconciliationStatus::Unchanged);
        assert_eq!(second.generation, first.generation);
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dirty_overlay_produces_complete_file_locators() {
        let (root, repository, store) = fixture();
        reconcile_git_repository(&store, &repository).unwrap();
        fs::write(repository.join("src/lib.rs"), b"pub fn answer() -> u32 { 43 }\n").unwrap();
        fs::write(repository.join("notes.txt"), b"local\n").unwrap();

        let reconciled = reconcile_git_repository(&store, &repository).unwrap();
        assert_eq!(reconciled.status, RepositoryReconciliationStatus::Advanced);
        let delta = reconciled.delta.unwrap();
        assert!(delta.complete);
        assert_eq!(
            delta.changed_locators,
            vec![
                DependencyLocator::repository_path("notes.txt").unwrap(),
                DependencyLocator::repository_path("src/lib.rs").unwrap(),
            ]
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
        );
        let store_path = store.path().to_path_buf();
        drop(store);
        let connection = Connection::open(store_path).unwrap();
        assert!(
            connection
                .execute("UPDATE repository_observations SET locators_complete=0", [])
                .is_err()
        );
        assert!(connection.execute("DELETE FROM repository_observation_locators", []).is_err());
        drop(connection);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn clean_commit_and_rename_are_reconciled_from_git_history() {
        let (root, repository, store) = fixture();
        reconcile_git_repository(&store, &repository).unwrap();
        git(&repository, &["mv", "src/lib.rs", "src/main.rs"]);
        git(&repository, &["commit", "--quiet", "-m", "rename"]);

        let reconciled = reconcile_git_repository(&store, &repository).unwrap();
        let delta = reconciled.delta.unwrap();
        assert!(delta.complete);
        assert!(
            delta
                .changed_locators
                .contains(&DependencyLocator::repository_path("src/lib.rs").unwrap())
        );
        assert!(
            delta
                .changed_locators
                .contains(&DependencyLocator::repository_path("src/main.rs").unwrap())
        );
        assert!(capture_git_observation(&repository).unwrap().dirty_locators.is_empty());
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bounded_union_fails_closed_without_growing_past_the_limit() {
        let mut target = (0..MAX_STATE_DELTA_LOCATORS)
            .map(|index| {
                DependencyLocator::from_repository_path_digest(Digest::blake3(index.to_le_bytes()))
            })
            .collect::<BTreeSet<_>>();
        let mut complete = true;
        extend_bounded(
            &mut target,
            [DependencyLocator::from_repository_path_digest(Digest::blake3(b"overflow"))],
            &mut complete,
        );
        assert!(!complete);
        assert_eq!(target.len(), MAX_STATE_DELTA_LOCATORS);
    }
}
