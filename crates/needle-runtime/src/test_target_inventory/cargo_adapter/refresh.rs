use super::*;
use crate::test_target_inventory::{
    CargoTestTargetInventoryInput, TestTargetInventoryValidationCertificate, dependency_set_digest,
};
use needle_core::{DependencyLocator, StateDelta, TestTargetInventoryScope};
use serde::Serialize;

#[derive(Clone)]
pub struct CargoTestTargetRefreshInput<'a> {
    pub current: CargoTestTargetInventoryInput<'a>,
    pub prior_inventory: &'a TestTargetInventory,
    pub prior_validation: &'a TestTargetInventoryValidationCertificate,
    pub state_delta: &'a StateDelta,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CargoTestTargetRefreshFallback {
    IncompleteDelta,
    ChangedInputArtifacts,
    ChangedDefinitions,
    ChangedSemanticWorld,
    ProviderOpaqueDelta,
    ContextMismatch,
    UnsupportedScope,
    WorkspaceChange,
    UnmappedRepositoryChange,
    MetadataWithoutDelta,
    NoInventoryChange,
    NoRetainedPartitions,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CargoTestTargetRefreshCandidate {
    pub inventory: TestTargetInventory,
    pub validation_certificate: TestTargetInventoryValidationCertificate,
    pub retained_partitions: usize,
    pub recomputed_partitions: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum CargoTestTargetRefreshAcquisition {
    Candidate { result: Box<CargoTestTargetRefreshCandidate> },
    FullCompute { reason: CargoTestTargetRefreshFallback },
}

pub fn cargo_test_target_refresh_acquisition_definition() -> Digest {
    let mut hasher = CanonicalHasher::new(b"cargo-test-target-refresh-acquisition-v1");
    hasher.field_digest(super::super::cargo_test_target_adapter_definition());
    hasher.field_str("complete-adjacent-delta");
    hasher.field_str("all-scope-only");
    hasher.field_str("exact-path-digest-to-package-mapping");
    hasher.field_str("unmapped-and-workspace-change-full-compute");
    hasher.field_str("target-scoped-metadata-binding");
    hasher.field_str("affected-package-materialization");
    hasher.field_str("retained-package-locator-closure");
    hasher.field_str("canonical-whole-inventory-validation");
    hasher.finish()
}

/// Acquire a current Cargo inventory by materializing only packages whose
/// exact repository locators occur in one complete adjacent delta. The
/// generic repository kernel remains path-digest-only; locator interpretation
/// is confined to this optional provider adapter. Anything that cannot be
/// mapped exactly falls back before reuse.
pub fn acquire_cargo_test_target_refresh_candidate(
    input: CargoTestTargetRefreshInput<'_>,
) -> Result<CargoTestTargetRefreshAcquisition, TestTargetInventoryRuntimeError> {
    input.prior_inventory.validate()?;
    input.prior_validation.validate()?;
    input
        .state_delta
        .validate()
        .map_err(|error| TestTargetInventoryRuntimeError::Metadata(error.to_string()))?;
    if input.prior_validation.inventory != input.prior_inventory.content_digest
        || input.prior_validation.adapter_definition_digest
            != input.prior_inventory.adapter_definition_digest
        || input.prior_validation.metadata_digest != input.prior_inventory.metadata_digest
        || input.prior_validation.dependency_set_digest
            != dependency_set_digest(input.prior_inventory)
    {
        return Err(TestTargetInventoryRuntimeError::Certificate);
    }
    if !input.state_delta.complete {
        return Ok(full_compute(CargoTestTargetRefreshFallback::IncompleteDelta));
    }
    if !input.state_delta.changed_input_artifacts.is_empty() {
        return Ok(full_compute(CargoTestTargetRefreshFallback::ChangedInputArtifacts));
    }
    if !input.state_delta.changed_definitions.is_empty() {
        return Ok(full_compute(CargoTestTargetRefreshFallback::ChangedDefinitions));
    }
    if !input.state_delta.semantic_world_changes.is_empty() {
        return Ok(full_compute(CargoTestTargetRefreshFallback::ChangedSemanticWorld));
    }
    if input
        .state_delta
        .changed_locators
        .iter()
        .any(|locator| matches!(locator, DependencyLocator::ProviderOpaque { .. }))
    {
        return Ok(full_compute(CargoTestTargetRefreshFallback::ProviderOpaqueDelta));
    }
    if input.prior_inventory.repository_lineage != input.current.repository_lineage
        || input.prior_inventory.source_selector != input.current.source_selector
        || input.prior_inventory.scope != input.current.scope
        || input.prior_inventory.adapter_definition_digest
            != super::super::cargo_test_target_adapter_definition()
        || input.state_delta.repository_lineage != input.current.repository_lineage
    {
        return Ok(full_compute(CargoTestTargetRefreshFallback::ContextMismatch));
    }
    if input.current.scope != TestTargetInventoryScope::all() {
        return Ok(full_compute(CargoTestTargetRefreshFallback::UnsupportedScope));
    }

    let prepared = PreparedWorkspace::new(&input.current)?;
    let prior_packages = input
        .prior_inventory
        .package_universe
        .iter()
        .map(|package| (package.manifest_path.as_str(), package))
        .collect::<BTreeMap<_, _>>();
    let package_manifests = prior_packages
        .keys()
        .map(|manifest| (*manifest).to_owned())
        .chain(prepared.packages.keys().cloned())
        .collect::<BTreeSet<_>>();
    let mut owners = BTreeMap::new();
    register_path_owner(&mut owners, &prepared.workspace_manifest_relative, PathOwner::Workspace)?;
    for package in prior_packages.values() {
        register_path_owner(
            &mut owners,
            &package.manifest_path,
            PathOwner::Package(package.manifest_path.clone()),
        )?;
    }
    for package in prepared.packages.values() {
        register_path_owner(
            &mut owners,
            &package.key.manifest_path,
            PathOwner::Package(package.key.manifest_path.clone()),
        )?;
        for target in &package.targets {
            register_path_owner(
                &mut owners,
                &target.source_path,
                PathOwner::Package(package.key.manifest_path.clone()),
            )?;
        }
    }
    for partition in &input.prior_inventory.partitions {
        register_path_owner(
            &mut owners,
            &partition.source_path,
            PathOwner::Package(partition.key.package.manifest_path.clone()),
        )?;
    }
    for locator in input
        .prior_inventory
        .collection_dependencies
        .iter()
        .chain(prepared.locators.values.values())
    {
        if locator.kind != TestTargetLocatorKind::AdapterInput {
            register_path_owner(
                &mut owners,
                &locator.path,
                owner_for_path(&locator.path, &package_manifests),
            )?;
        }
    }

    let mut affected = BTreeSet::new();
    for changed in &input.state_delta.changed_locators {
        let Some(owner) = owners.get(changed) else {
            return Ok(full_compute(CargoTestTargetRefreshFallback::UnmappedRepositoryChange));
        };
        match owner {
            PathOwner::Workspace => {
                return Ok(full_compute(CargoTestTargetRefreshFallback::WorkspaceChange));
            }
            PathOwner::Package(manifest) => {
                affected.insert(manifest.clone());
            }
        }
    }

    for manifest in &package_manifests {
        let prior = prior_packages.get(manifest.as_str()).copied();
        let current = prepared.packages.get(manifest);
        if prior.map(|package| package.name.as_str())
            != current.map(|package| package.key.name.as_str())
            && !affected.contains(manifest)
        {
            return Ok(full_compute(CargoTestTargetRefreshFallback::MetadataWithoutDelta));
        }
    }

    let prior_partitions = input
        .prior_inventory
        .partitions
        .iter()
        .map(|partition| (&partition.key, partition))
        .collect::<BTreeMap<_, _>>();
    let prior_locator_ids = input
        .prior_inventory
        .collection_dependencies
        .iter()
        .map(|locator| (locator.id, locator))
        .collect::<BTreeMap<_, _>>();
    let mut locators = prepared.locators;
    let mut partitions = Vec::with_capacity(input.prior_inventory.partitions.len());
    let mut retained_partitions = 0;
    for (manifest, package) in prepared.packages {
        if affected.contains(&manifest) || !prior_packages.contains_key(manifest.as_str()) {
            materialize_package(
                &prepared.repository_root,
                &prepared.workspace_manifest_relative,
                prepared.workspace_manifest_locator,
                prepared.cargo_version_locator,
                package.package,
                &mut locators,
                &mut partitions,
            )?;
            continue;
        }

        let prior = input
            .prior_inventory
            .partitions
            .iter()
            .filter(|partition| partition.key.package.manifest_path == manifest)
            .collect::<Vec<_>>();
        if package.targets.len() != prior.len()
            || package.targets.iter().any(|target| {
                prior_partitions.get(&target.key).is_none_or(|partition| {
                    !target.matches_partition(
                        partition,
                        prepared.workspace_manifest_locator,
                        prepared.cargo_version_locator,
                        &prior_locator_ids,
                    )
                })
            })
        {
            return Ok(full_compute(CargoTestTargetRefreshFallback::MetadataWithoutDelta));
        }

        let referenced = prior
            .iter()
            .flat_map(|partition| partition.locator_ids.iter().copied())
            .collect::<BTreeSet<_>>();
        for locator_id in &referenced {
            if !prior_locator_ids.contains_key(locator_id) {
                return Err(TestTargetInventoryRuntimeError::Metadata(
                    "retained partition references a missing prior locator".to_owned(),
                ));
            }
        }
        for locator in &input.prior_inventory.collection_dependencies {
            let package_owned = locator.kind != TestTargetLocatorKind::AdapterInput
                && owner_for_path(&locator.path, &package_manifests)
                    == PathOwner::Package(manifest.clone());
            let referenced_adapter = locator.kind == TestTargetLocatorKind::AdapterInput
                && locator.path.starts_with("@adapter/cargo-target/")
                && referenced.contains(&locator.id);
            if package_owned || referenced_adapter {
                locators.insert(locator.clone())?;
            }
        }
        retained_partitions += prior.len();
        partitions.extend(prior.into_iter().cloned());
    }

    if retained_partitions == 0 {
        return Ok(full_compute(CargoTestTargetRefreshFallback::NoRetainedPartitions));
    }
    let inventory = TestTargetInventory::new(
        input.current.repository_lineage,
        input.current.source_selector,
        input.current.scope,
        super::super::cargo_test_target_adapter_definition(),
        prepared.metadata_digest,
        prepared.package_universe,
        locators.into_values(),
        partitions,
    )?;
    if inventory == *input.prior_inventory {
        return Ok(full_compute(CargoTestTargetRefreshFallback::NoInventoryChange));
    }
    let validation_certificate = TestTargetInventoryValidationCertificate::new(&inventory);
    validation_certificate.validate()?;
    let recomputed_partitions = inventory.partitions.len().saturating_sub(retained_partitions);
    Ok(CargoTestTargetRefreshAcquisition::Candidate {
        result: Box::new(CargoTestTargetRefreshCandidate {
            inventory,
            validation_certificate,
            retained_partitions,
            recomputed_partitions,
        }),
    })
}

struct PreparedWorkspace {
    repository_root: PathBuf,
    workspace_manifest_relative: String,
    workspace_manifest_locator: Digest,
    cargo_version_locator: Digest,
    metadata_digest: Digest,
    package_universe: Vec<TestTargetPackageKey>,
    packages: BTreeMap<String, PreparedPackage>,
    locators: LocatorSet,
}

impl PreparedWorkspace {
    fn new(
        input: &CargoTestTargetInventoryInput<'_>,
    ) -> Result<Self, TestTargetInventoryRuntimeError> {
        validate_input(input)?;
        let repository_root = fs::canonicalize(input.repository_root).map_err(|error| {
            TestTargetInventoryRuntimeError::Io {
                path: input.repository_root.display().to_string(),
                message: error.to_string(),
            }
        })?;
        let metadata: CargoMetadata = serde_json::from_slice(input.metadata_json)
            .map_err(|error| TestTargetInventoryRuntimeError::Metadata(error.to_string()))?;
        validate_metadata_bounds(&metadata)?;
        let metadata_root = fs::canonicalize(&metadata.workspace_root)
            .map_err(|_| TestTargetInventoryRuntimeError::WorkspaceRoot)?;
        if metadata_root != repository_root {
            return Err(TestTargetInventoryRuntimeError::WorkspaceRoot);
        }

        let metadata_digest = Digest::blake3(input.metadata_json);
        let mut locators = LocatorSet::default();
        locators.insert(TestTargetLocator::new(
            TestTargetLocatorKind::AdapterInput,
            "@adapter/cargo-metadata.json",
            metadata_digest,
        )?)?;
        let cargo_version_locator = locators.insert(TestTargetLocator::new(
            TestTargetLocatorKind::AdapterInput,
            "@adapter/cargo-version.txt",
            Digest::blake3(input.cargo_version.as_bytes()),
        )?)?;
        let workspace_manifest = repository_root.join("Cargo.toml");
        let workspace_manifest_relative =
            relative_existing_path(&repository_root, &workspace_manifest)?;
        let workspace_manifest_bytes = read_bounded_file(&workspace_manifest)?;
        let workspace_manifest_locator = locators.insert(TestTargetLocator::new(
            TestTargetLocatorKind::ManifestContent,
            workspace_manifest_relative.clone(),
            Digest::blake3(&workspace_manifest_bytes),
        )?)?;
        let workspace_document =
            parse_manifest(&workspace_manifest_relative, &workspace_manifest_bytes)?;
        add_workspace_membership_locators(&repository_root, &workspace_document, &mut locators)?;

        let member_ids = metadata.workspace_members.into_iter().collect::<BTreeSet<_>>();
        let mut packages_by_id = BTreeMap::new();
        for package in metadata.packages {
            if packages_by_id.insert(package.id.clone(), package).is_some() {
                return Err(TestTargetInventoryRuntimeError::Metadata(
                    "duplicate package id".to_owned(),
                ));
            }
        }
        if member_ids.iter().any(|id| !packages_by_id.contains_key(id)) {
            return Err(TestTargetInventoryRuntimeError::Metadata(
                "workspace member is absent from packages".to_owned(),
            ));
        }

        let mut packages = BTreeMap::new();
        let mut package_universe = Vec::with_capacity(member_ids.len());
        for member_id in member_ids {
            let package =
                packages_by_id.remove(&member_id).expect("workspace membership checked above");
            let prepared = PreparedPackage::new(
                &repository_root,
                input.repository_root,
                &workspace_manifest_relative,
                package,
            )?;
            package_universe.push(prepared.key.clone());
            if packages.insert(prepared.key.manifest_path.clone(), prepared).is_some() {
                return Err(TestTargetInventoryRuntimeError::Metadata(
                    "duplicate workspace manifest path".to_owned(),
                ));
            }
        }
        package_universe.sort();
        if !package_universe.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(TestTargetInventoryRuntimeError::Metadata(
                "duplicate workspace package key".to_owned(),
            ));
        }
        Ok(Self {
            repository_root,
            workspace_manifest_relative,
            workspace_manifest_locator,
            cargo_version_locator,
            metadata_digest,
            package_universe,
            packages,
            locators,
        })
    }
}

struct PreparedPackage {
    key: TestTargetPackageKey,
    package: CargoPackage,
    targets: Vec<PreparedTarget>,
}

impl PreparedPackage {
    fn new(
        repository_root: &Path,
        declared_root: &Path,
        workspace_manifest_relative: &str,
        package: CargoPackage,
    ) -> Result<Self, TestTargetInventoryRuntimeError> {
        let manifest_path = PathBuf::from(&package.manifest_path);
        let manifest_relative =
            relative_metadata_path(repository_root, declared_root, &manifest_path)?;
        let key = TestTargetPackageKey::new(&package.name, &manifest_relative)?;
        let mut targets = package
            .targets
            .iter()
            .filter(|target| target.test)
            .map(|target| {
                PreparedTarget::new(
                    repository_root,
                    declared_root,
                    workspace_manifest_relative,
                    &key,
                    target,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        targets.sort_by(|left, right| left.key.cmp(&right.key));
        if !targets.windows(2).all(|pair| pair[0].key < pair[1].key) {
            return Err(TestTargetInventoryRuntimeError::Metadata(
                "duplicate test target key".to_owned(),
            ));
        }
        Ok(Self { key, package, targets })
    }
}

struct PreparedTarget {
    key: TestTargetPartitionKey,
    source_path: String,
    crate_types: Vec<String>,
    required_features: Vec<String>,
    edition: String,
    doctest: bool,
    input_locator: TestTargetLocator,
}

impl PreparedTarget {
    fn new(
        repository_root: &Path,
        declared_root: &Path,
        workspace_manifest_relative: &str,
        package: &TestTargetPackageKey,
        target: &CargoTarget,
    ) -> Result<Self, TestTargetInventoryRuntimeError> {
        let target_kind = parse_target_kind(target)?;
        validate_short_text("target name", &target.name)?;
        validate_short_text("edition", &target.edition)?;
        validate_text_set("crate type", &target.crate_types)?;
        validate_text_set("required feature", &target.required_features)?;
        let source_path =
            relative_metadata_path(repository_root, declared_root, Path::new(&target.src_path))?;
        let key = TestTargetPartitionKey {
            ecosystem: TestTargetEcosystem::Cargo,
            workspace: workspace_manifest_relative.to_owned(),
            package: package.clone(),
            target_kind,
            target_name: target.name.clone(),
        };
        key.validate()?;
        let input_locator = TestTargetLocator::new(
            TestTargetLocatorKind::AdapterInput,
            format!(
                "@adapter/cargo-target/{}.json",
                super::super::cargo_test_target_partition_opaque_key(&key).to_hex()
            ),
            cargo_target_input_digest(target, target_kind, &source_path),
        )?;
        let mut crate_types = target.crate_types.clone();
        let mut required_features = target.required_features.clone();
        crate_types.sort();
        required_features.sort();
        if !crate_types.windows(2).all(|pair| pair[0] < pair[1])
            || !required_features.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(TestTargetInventoryRuntimeError::Metadata(
                "target metadata sets contain duplicates".to_owned(),
            ));
        }
        Ok(Self {
            key,
            source_path,
            crate_types,
            required_features,
            edition: target.edition.clone(),
            doctest: target.doctest,
            input_locator,
        })
    }

    fn matches_partition(
        &self,
        partition: &TestTargetPartition,
        workspace_manifest_locator: Digest,
        cargo_version_locator: Digest,
        locators: &BTreeMap<Digest, &TestTargetLocator>,
    ) -> bool {
        partition.key == self.key
            && partition.source_path == self.source_path
            && partition.crate_types == self.crate_types
            && partition.required_features == self.required_features
            && partition.edition == self.edition
            && partition.doctest == self.doctest
            && partition.locator_ids.binary_search(&self.input_locator.id).is_ok()
            && partition.locator_ids.binary_search(&workspace_manifest_locator).is_ok()
            && partition.locator_ids.binary_search(&cargo_version_locator).is_ok()
            && locators.get(&self.input_locator.id).copied() == Some(&self.input_locator)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PathOwner {
    Workspace,
    Package(String),
}

fn register_path_owner(
    owners: &mut BTreeMap<DependencyLocator, PathOwner>,
    path: &str,
    owner: PathOwner,
) -> Result<(), TestTargetInventoryRuntimeError> {
    let locator = DependencyLocator::repository_path(path)
        .map_err(|error| TestTargetInventoryRuntimeError::Metadata(error.to_string()))?;
    if let Some(existing) = owners.get(&locator)
        && existing != &owner
    {
        owners.insert(locator, PathOwner::Workspace);
    } else {
        owners.insert(locator, owner);
    }
    Ok(())
}

fn owner_for_path(path: &str, package_manifests: &BTreeSet<String>) -> PathOwner {
    package_manifests
        .iter()
        .filter(|manifest| path_is_within_package(path, manifest))
        .max_by_key(|manifest| manifest.len())
        .map(|manifest| PathOwner::Package((*manifest).clone()))
        .unwrap_or(PathOwner::Workspace)
}

fn path_is_within_package(path: &str, manifest: &str) -> bool {
    let Some((root, _)) = manifest.rsplit_once('/') else {
        return true;
    };
    path == manifest
        || path == root
        || path.strip_prefix(root).is_some_and(|rest| rest.starts_with('/'))
}

fn relative_metadata_path(
    repository_root: &Path,
    declared_root: &Path,
    path: &Path,
) -> Result<String, TestTargetInventoryRuntimeError> {
    for root in [declared_root, repository_root] {
        if let Ok(relative) = path.strip_prefix(root)
            && let Some(normalized) = normalize_relative(relative)
        {
            return Ok(normalized);
        }
    }
    relative_existing_path(repository_root, path)
}

fn full_compute(reason: CargoTestTargetRefreshFallback) -> CargoTestTargetRefreshAcquisition {
    CargoTestTargetRefreshAcquisition::FullCompute { reason }
}
