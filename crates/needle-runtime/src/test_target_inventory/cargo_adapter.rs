use super::{
    CargoTestTargetInventoryInput, MAX_CARGO_METADATA_INPUT_BYTES, MAX_CARGO_VERSION_BYTES,
    MAX_TEST_TARGET_DIRECTORY_ENTRIES, MAX_TEST_TARGET_MANIFEST_BYTES,
    TestTargetInventoryRuntimeError, cargo_test_target_adapter_definition,
};
use needle_core::{
    CanonicalHasher, Digest, MAX_TEST_TARGET_NAME_BYTES, MAX_TEST_TARGET_PACKAGES,
    MAX_TEST_TARGET_PATH_BYTES, MAX_TEST_TARGETS, TestTargetDeclaration, TestTargetEcosystem,
    TestTargetInventory, TestTargetKind, TestTargetLocator, TestTargetLocatorKind,
    TestTargetPackageKey, TestTargetPartition, TestTargetPartitionKey,
};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

mod refresh;

pub use refresh::{
    CargoTestTargetRefreshAcquisition, CargoTestTargetRefreshCandidate,
    CargoTestTargetRefreshFallback, CargoTestTargetRefreshInput,
    acquire_cargo_test_target_refresh_candidate, cargo_test_target_refresh_acquisition_definition,
};

#[derive(Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
    workspace_members: Vec<String>,
    workspace_root: String,
}

#[derive(Deserialize)]
struct CargoPackage {
    id: String,
    name: String,
    manifest_path: String,
    targets: Vec<CargoTarget>,
}

#[derive(Deserialize)]
struct CargoTarget {
    name: String,
    kind: Vec<String>,
    crate_types: Vec<String>,
    #[serde(rename = "required-features", default)]
    required_features: Vec<String>,
    src_path: String,
    edition: String,
    test: bool,
    doctest: bool,
}

pub fn enumerate_cargo_test_targets(
    input: CargoTestTargetInventoryInput<'_>,
) -> Result<TestTargetInventory, TestTargetInventoryRuntimeError> {
    validate_input(&input)?;
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
    if member_ids.len() > MAX_TEST_TARGET_PACKAGES {
        return Err(TestTargetInventoryRuntimeError::Metadata(
            "workspace member bound exceeded".to_owned(),
        ));
    }
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

    let mut package_universe = Vec::with_capacity(member_ids.len());
    let mut partitions = Vec::new();
    for member_id in member_ids {
        let package =
            packages_by_id.remove(&member_id).expect("workspace membership checked above");
        package_universe.push(materialize_package(
            &repository_root,
            &workspace_manifest_relative,
            workspace_manifest_locator,
            cargo_version_locator,
            package,
            &mut locators,
            &mut partitions,
        )?);
    }

    let partitions =
        partitions.into_iter().filter(|partition| input.scope.matches(&partition.key)).collect();
    TestTargetInventory::new(
        input.repository_lineage,
        input.source_selector,
        input.scope,
        cargo_test_target_adapter_definition(),
        metadata_digest,
        package_universe,
        locators.into_values(),
        partitions,
    )
    .map_err(Into::into)
}

#[allow(clippy::too_many_arguments)]
fn materialize_package(
    repository_root: &Path,
    workspace_manifest_relative: &str,
    workspace_manifest_locator: Digest,
    cargo_version_locator: Digest,
    package: CargoPackage,
    locators: &mut LocatorSet,
    partitions: &mut Vec<TestTargetPartition>,
) -> Result<TestTargetPackageKey, TestTargetInventoryRuntimeError> {
    let manifest_path = PathBuf::from(&package.manifest_path);
    let manifest_relative = relative_existing_path(repository_root, &manifest_path)?;
    let manifest_bytes = read_bounded_file(&manifest_path)?;
    let manifest_locator = locators.insert(TestTargetLocator::new(
        TestTargetLocatorKind::ManifestContent,
        manifest_relative.clone(),
        Digest::blake3(&manifest_bytes),
    )?)?;
    let manifest_document = parse_manifest(&manifest_relative, &manifest_bytes)?;
    let package_key = TestTargetPackageKey::new(&package.name, &manifest_relative)?;
    let package_root = manifest_path
        .parent()
        .ok_or_else(|| TestTargetInventoryRuntimeError::UnsafeLocator(manifest_relative.clone()))?;
    let discovery_locators =
        add_package_discovery_locators(repository_root, package_root, locators)?;

    for target in package.targets.into_iter().filter(|target| target.test) {
        if partitions.len() == MAX_TEST_TARGETS {
            return Err(TestTargetInventoryRuntimeError::Metadata(
                "test target bound exceeded".to_owned(),
            ));
        }
        let target_kind = parse_target_kind(&target)?;
        validate_short_text("target name", &target.name)?;
        validate_short_text("edition", &target.edition)?;
        validate_text_set("crate type", &target.crate_types)?;
        validate_text_set("required feature", &target.required_features)?;
        let source_path = PathBuf::from(&target.src_path);
        if !source_path.is_file() {
            return Err(TestTargetInventoryRuntimeError::MissingLocator(
                source_path.display().to_string(),
            ));
        }
        let source_relative = relative_existing_path(repository_root, &source_path)?;
        let source_locator = locators.insert(TestTargetLocator::new(
            TestTargetLocatorKind::FilePresence,
            source_relative.clone(),
            presence_digest(&source_relative, true),
        )?)?;
        let declaration =
            target_declaration(&manifest_document, package_root, &target, target_kind);
        let key = TestTargetPartitionKey {
            ecosystem: TestTargetEcosystem::Cargo,
            workspace: workspace_manifest_relative.to_owned(),
            package: package_key.clone(),
            target_kind,
            target_name: target.name.clone(),
        };
        let target_input_locator = locators.insert(TestTargetLocator::new(
            TestTargetLocatorKind::AdapterInput,
            format!(
                "@adapter/cargo-target/{}.json",
                super::cargo_test_target_partition_opaque_key(&key).to_hex()
            ),
            cargo_target_input_digest(&target, target_kind, &source_relative),
        )?)?;
        let mut locator_ids = vec![
            cargo_version_locator,
            workspace_manifest_locator,
            manifest_locator,
            source_locator,
            target_input_locator,
        ];
        if declaration == TestTargetDeclaration::Conventional {
            locator_ids.extend(discovery_locators_for_source(
                package_root,
                &source_path,
                &discovery_locators,
            ));
        }
        locator_ids.sort_unstable();
        locator_ids.dedup();
        partitions.push(TestTargetPartition::new(
            key,
            source_relative,
            declaration,
            target.crate_types,
            target.required_features,
            target.edition,
            target.doctest,
            locator_ids,
        )?);
    }
    Ok(package_key)
}

fn validate_input(
    input: &CargoTestTargetInventoryInput<'_>,
) -> Result<(), TestTargetInventoryRuntimeError> {
    if input.metadata_json.len() > MAX_CARGO_METADATA_INPUT_BYTES {
        return Err(TestTargetInventoryRuntimeError::MetadataBound {
            actual: input.metadata_json.len(),
            maximum: MAX_CARGO_METADATA_INPUT_BYTES,
        });
    }
    if input.cargo_version.is_empty()
        || input.cargo_version.len() > MAX_CARGO_VERSION_BYTES
        || input.cargo_version.chars().any(char::is_control)
    {
        return Err(TestTargetInventoryRuntimeError::CargoVersionBound);
    }
    input.scope.validate()?;
    Ok(())
}

fn validate_metadata_bounds(
    metadata: &CargoMetadata,
) -> Result<(), TestTargetInventoryRuntimeError> {
    if metadata.packages.len() > MAX_TEST_TARGET_PACKAGES
        || metadata.workspace_members.len() > MAX_TEST_TARGET_PACKAGES
        || metadata.packages.iter().map(|package| package.targets.len()).sum::<usize>()
            > MAX_TEST_TARGETS
    {
        return Err(TestTargetInventoryRuntimeError::Metadata(
            "metadata cardinality bound exceeded".to_owned(),
        ));
    }
    Ok(())
}

fn parse_target_kind(
    target: &CargoTarget,
) -> Result<TestTargetKind, TestTargetInventoryRuntimeError> {
    if target.kind.len() != 1 {
        return Err(TestTargetInventoryRuntimeError::UnsupportedTarget(target.name.clone()));
    }
    match target.kind[0].as_str() {
        "lib" => Ok(TestTargetKind::Lib),
        "proc-macro" => Ok(TestTargetKind::ProcMacro),
        "bin" => Ok(TestTargetKind::Bin),
        "test" => Ok(TestTargetKind::Test),
        "example" => Ok(TestTargetKind::Example),
        "bench" => Ok(TestTargetKind::Bench),
        _ => Err(TestTargetInventoryRuntimeError::UnsupportedTarget(target.name.clone())),
    }
}

fn target_declaration(
    manifest: &toml::Value,
    package_root: &Path,
    target: &CargoTarget,
    kind: TestTargetKind,
) -> TestTargetDeclaration {
    if kind == TestTargetKind::ProcMacro {
        return TestTargetDeclaration::Manifest;
    }
    let explicit = match kind {
        TestTargetKind::Lib => manifest.get("lib").is_some(),
        TestTargetKind::Bin => explicit_array_target(manifest, "bin", target),
        TestTargetKind::Test => explicit_array_target(manifest, "test", target),
        TestTargetKind::Example => explicit_array_target(manifest, "example", target),
        TestTargetKind::Bench => explicit_array_target(manifest, "bench", target),
        TestTargetKind::ProcMacro => true,
    };
    if explicit
        || !is_conventional_source(package_root, Path::new(&target.src_path), kind, &target.name)
    {
        TestTargetDeclaration::Manifest
    } else {
        TestTargetDeclaration::Conventional
    }
}

fn cargo_target_input_digest(
    target: &CargoTarget,
    kind: TestTargetKind,
    source_relative: &str,
) -> Digest {
    let mut crate_types = target.crate_types.iter().map(String::as_str).collect::<Vec<_>>();
    let mut required_features =
        target.required_features.iter().map(String::as_str).collect::<Vec<_>>();
    crate_types.sort_unstable();
    required_features.sort_unstable();
    let mut hasher = CanonicalHasher::new(b"cargo-test-target-adapter-input-v1");
    hasher.field_str(&target.name);
    hasher.field_str(kind.as_str());
    hasher.field_str(source_relative);
    hasher.field_u32(crate_types.len().try_into().unwrap_or(u32::MAX));
    for crate_type in crate_types {
        hasher.field_str(crate_type);
    }
    hasher.field_u32(required_features.len().try_into().unwrap_or(u32::MAX));
    for feature in required_features {
        hasher.field_str(feature);
    }
    hasher.field_str(&target.edition);
    hasher.field_u8(u8::from(target.doctest));
    hasher.finish()
}

fn explicit_array_target(manifest: &toml::Value, table: &str, target: &CargoTarget) -> bool {
    manifest.get(table).and_then(toml::Value::as_array).is_some_and(|entries| {
        entries.iter().any(|entry| {
            entry.get("name").and_then(toml::Value::as_str) == Some(target.name.as_str())
        })
    })
}

fn is_conventional_source(
    package_root: &Path,
    source: &Path,
    kind: TestTargetKind,
    name: &str,
) -> bool {
    let Ok(relative) = source.strip_prefix(package_root) else {
        return false;
    };
    let normalized = normalize_relative(relative).unwrap_or_default();
    match kind {
        TestTargetKind::Lib => normalized == "src/lib.rs",
        TestTargetKind::Bin => {
            normalized == "src/main.rs"
                || normalized == format!("src/bin/{name}.rs")
                || normalized == format!("src/bin/{name}/main.rs")
        }
        TestTargetKind::Test => {
            normalized == format!("tests/{name}.rs")
                || normalized == format!("tests/{name}/main.rs")
        }
        TestTargetKind::Example => {
            normalized == format!("examples/{name}.rs")
                || normalized == format!("examples/{name}/main.rs")
        }
        TestTargetKind::Bench => {
            normalized == format!("benches/{name}.rs")
                || normalized == format!("benches/{name}/main.rs")
        }
        TestTargetKind::ProcMacro => false,
    }
}

#[derive(Default)]
struct LocatorSet {
    values: BTreeMap<(String, TestTargetLocatorKind), TestTargetLocator>,
}

impl LocatorSet {
    fn insert(
        &mut self,
        locator: TestTargetLocator,
    ) -> Result<Digest, TestTargetInventoryRuntimeError> {
        let key = (locator.path.clone(), locator.kind);
        if let Some(existing) = self.values.get(&key) {
            if existing != &locator {
                return Err(TestTargetInventoryRuntimeError::Metadata(format!(
                    "locator changed during enumeration: {}",
                    locator.path
                )));
            }
            return Ok(existing.id);
        }
        let id = locator.id;
        self.values.insert(key, locator);
        Ok(id)
    }

    fn into_values(self) -> Vec<TestTargetLocator> {
        self.values.into_values().collect()
    }
}

fn add_workspace_membership_locators(
    root: &Path,
    document: &toml::Value,
    locators: &mut LocatorSet,
) -> Result<(), TestTargetInventoryRuntimeError> {
    let Some(workspace) = document.get("workspace") else {
        return Ok(());
    };
    for field in ["members", "exclude"] {
        let Some(patterns) = workspace.get(field).and_then(toml::Value::as_array) else {
            continue;
        };
        for pattern in patterns {
            let Some(pattern) = pattern.as_str() else {
                return Err(TestTargetInventoryRuntimeError::UnsupportedWorkspacePattern(
                    field.to_owned(),
                ));
            };
            validate_workspace_pattern(pattern)?;
            let segments = pattern.split('/').collect::<Vec<_>>();
            if let Some(index) = segments.iter().position(|segment| *segment == "*") {
                let parent = segments[..index].join("/");
                let relative = if parent.is_empty() { "." } else { &parent };
                let parent = root.join(relative);
                add_workspace_directory_locator(root, &parent, locators)?;
                let suffix = &segments[index + 1..];
                for entry in bounded_directory_entries(root, &parent)? {
                    if entry.is_directory {
                        add_workspace_candidate_locator(
                            root,
                            &parent.join(&entry.name),
                            suffix,
                            locators,
                        )?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_workspace_pattern(pattern: &str) -> Result<(), TestTargetInventoryRuntimeError> {
    let wildcard_segments = pattern.split('/').filter(|segment| *segment == "*").count();
    let has_unsupported = pattern.contains("**")
        || pattern.contains('?')
        || pattern.contains('[')
        || pattern.contains(']')
        || pattern.split('/').any(|segment| segment.contains('*') && segment != "*");
    if wildcard_segments > 1 || has_unsupported || normalize_relative(Path::new(pattern)).is_none()
    {
        return Err(TestTargetInventoryRuntimeError::UnsupportedWorkspacePattern(
            pattern.to_owned(),
        ));
    }
    Ok(())
}

fn add_package_discovery_locators(
    root: &Path,
    package_root: &Path,
    locators: &mut LocatorSet,
) -> Result<BTreeMap<String, Digest>, TestTargetInventoryRuntimeError> {
    let mut values = BTreeMap::new();
    for relative in ["src", "src/bin", "tests", "examples", "benches"] {
        let directory = package_root.join(relative);
        if !directory.is_dir() {
            continue;
        }
        let id = add_target_directory_locator(root, &directory, relative == "src", locators)?;
        values.insert(relative.to_owned(), id);
        if relative != "src" {
            for entry in bounded_directory_entries(root, &directory)? {
                if entry.is_directory {
                    let child = directory.join(&entry.name);
                    let child_id = add_target_directory_locator(root, &child, false, locators)?;
                    values.insert(format!("{relative}/{}", entry.name), child_id);
                }
            }
        }
    }
    Ok(values)
}

fn discovery_locators_for_source(
    package_root: &Path,
    source: &Path,
    discovery: &BTreeMap<String, Digest>,
) -> Vec<Digest> {
    let Ok(relative) = source.strip_prefix(package_root) else {
        return Vec::new();
    };
    let Some(normalized) = normalize_relative(relative) else {
        return Vec::new();
    };
    let components = normalized.split('/').collect::<Vec<_>>();
    let mut ids = Vec::new();
    for depth in 1..components.len() {
        let prefix = components[..depth].join("/");
        if let Some(value) = discovery.get(&prefix) {
            ids.push(*value);
        }
    }
    ids
}

fn add_workspace_candidate_locator(
    root: &Path,
    wildcard_child: &Path,
    suffix: &[&str],
    locators: &mut LocatorSet,
) -> Result<(), TestTargetInventoryRuntimeError> {
    let mut candidate = wildcard_child.to_path_buf();
    for segment in suffix {
        if !candidate.is_dir() {
            return Ok(());
        }
        add_workspace_directory_locator(root, &candidate, locators)?;
        candidate.push(segment);
    }
    if candidate.is_dir() {
        add_file_presence_locator(root, &candidate.join("Cargo.toml"), locators)?;
    }
    Ok(())
}

fn add_file_presence_locator(
    root: &Path,
    path: &Path,
    locators: &mut LocatorSet,
) -> Result<Digest, TestTargetInventoryRuntimeError> {
    let present = path.is_file();
    let relative = if path.exists() {
        relative_existing_path(root, path)?
    } else {
        relative_lexical_path(root, path)?
    };
    locators.insert(TestTargetLocator::new(
        TestTargetLocatorKind::FilePresence,
        relative.clone(),
        presence_digest(&relative, present),
    )?)
}

fn add_workspace_directory_locator(
    root: &Path,
    directory: &Path,
    locators: &mut LocatorSet,
) -> Result<Digest, TestTargetInventoryRuntimeError> {
    let relative = relative_existing_path(root, directory)?;
    let entries = bounded_directory_entries(root, directory)?;
    let mut hasher = CanonicalHasher::new(b"test-target-workspace-directories-v1");
    for entry in entries.into_iter().filter(|entry| entry.is_directory) {
        hasher.field_str(&entry.name);
    }
    locators.insert(TestTargetLocator::new(
        TestTargetLocatorKind::DirectoryEntries,
        relative,
        hasher.finish(),
    )?)
}

fn add_target_directory_locator(
    root: &Path,
    directory: &Path,
    src_root: bool,
    locators: &mut LocatorSet,
) -> Result<Digest, TestTargetInventoryRuntimeError> {
    let relative = relative_existing_path(root, directory)?;
    let entries = bounded_directory_entries(root, directory)?;
    let mut hasher = CanonicalHasher::new(b"test-target-discovery-entries-v1");
    hasher.field_u8(u8::from(src_root));
    for entry in entries.into_iter().filter(|entry| {
        if src_root {
            (!entry.is_directory && matches!(entry.name.as_str(), "lib.rs" | "main.rs"))
                || (entry.is_directory && entry.name == "bin")
        } else if directory.ends_with("src/bin")
            || directory.ends_with("tests")
            || directory.ends_with("examples")
            || directory.ends_with("benches")
        {
            entry.is_directory || entry.name.ends_with(".rs")
        } else {
            !entry.is_directory && entry.name == "main.rs"
        }
    }) {
        hasher.field_str(&entry.name);
        hasher.field_u8(if entry.is_directory { 1 } else { 0 });
    }
    locators.insert(TestTargetLocator::new(
        TestTargetLocatorKind::TargetDirectoryEntries,
        relative,
        hasher.finish(),
    )?)
}

struct DirectoryEntry {
    name: String,
    is_directory: bool,
}

fn bounded_directory_entries(
    root: &Path,
    directory: &Path,
) -> Result<Vec<DirectoryEntry>, TestTargetInventoryRuntimeError> {
    let relative = relative_existing_path(root, directory)?;
    let read = fs::read_dir(directory).map_err(|error| TestTargetInventoryRuntimeError::Io {
        path: relative.clone(),
        message: error.to_string(),
    })?;
    let mut values = Vec::new();
    for entry in read {
        if values.len() == MAX_TEST_TARGET_DIRECTORY_ENTRIES {
            return Err(TestTargetInventoryRuntimeError::DirectoryBound {
                path: relative,
                maximum: MAX_TEST_TARGET_DIRECTORY_ENTRIES,
            });
        }
        let entry = entry.map_err(|error| TestTargetInventoryRuntimeError::Io {
            path: relative.clone(),
            message: error.to_string(),
        })?;
        let name = entry.file_name().into_string().map_err(|_| {
            TestTargetInventoryRuntimeError::UnsafeLocator(entry.path().display().to_string())
        })?;
        validate_short_text("directory entry", &name)?;
        let file_type = entry.file_type().map_err(|error| TestTargetInventoryRuntimeError::Io {
            path: entry.path().display().to_string(),
            message: error.to_string(),
        })?;
        values.push(DirectoryEntry { name, is_directory: file_type.is_dir() });
    }
    values.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(values)
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>, TestTargetInventoryRuntimeError> {
    let display = path.display().to_string();
    let file = File::open(path).map_err(|error| TestTargetInventoryRuntimeError::Io {
        path: display.clone(),
        message: error.to_string(),
    })?;
    let mut bytes = Vec::new();
    file.take((MAX_TEST_TARGET_MANIFEST_BYTES + 1) as u64).read_to_end(&mut bytes).map_err(
        |error| TestTargetInventoryRuntimeError::Io {
            path: display.clone(),
            message: error.to_string(),
        },
    )?;
    if bytes.len() > MAX_TEST_TARGET_MANIFEST_BYTES {
        return Err(TestTargetInventoryRuntimeError::LocatorBound {
            path: display,
            maximum: MAX_TEST_TARGET_MANIFEST_BYTES,
        });
    }
    Ok(bytes)
}

fn parse_manifest(
    path: &str,
    bytes: &[u8],
) -> Result<toml::Value, TestTargetInventoryRuntimeError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| TestTargetInventoryRuntimeError::Metadata(error.to_string()))?;
    toml::from_str(text)
        .map_err(|error| TestTargetInventoryRuntimeError::Metadata(format!("{path}: {error}")))
}

fn relative_existing_path(
    root: &Path,
    path: &Path,
) -> Result<String, TestTargetInventoryRuntimeError> {
    let canonical = fs::canonicalize(path)
        .map_err(|_| TestTargetInventoryRuntimeError::MissingLocator(path.display().to_string()))?;
    let relative = canonical
        .strip_prefix(root)
        .map_err(|_| TestTargetInventoryRuntimeError::UnsafeLocator(path.display().to_string()))?;
    normalize_relative(relative)
        .ok_or_else(|| TestTargetInventoryRuntimeError::UnsafeLocator(path.display().to_string()))
}

fn relative_lexical_path(
    root: &Path,
    path: &Path,
) -> Result<String, TestTargetInventoryRuntimeError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| TestTargetInventoryRuntimeError::UnsafeLocator(path.display().to_string()))?;
    normalize_relative(relative)
        .ok_or_else(|| TestTargetInventoryRuntimeError::UnsafeLocator(path.display().to_string()))
}

fn normalize_relative(path: &Path) -> Option<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => parts.push(value.to_str()?.to_owned()),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    let value = if parts.is_empty() { ".".to_owned() } else { parts.join("/") };
    (value.len() <= MAX_TEST_TARGET_PATH_BYTES).then_some(value)
}

fn validate_short_text(field: &str, value: &str) -> Result<(), TestTargetInventoryRuntimeError> {
    if value.is_empty()
        || value.len() > MAX_TEST_TARGET_NAME_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(TestTargetInventoryRuntimeError::Metadata(format!(
            "{field} exceeds its bound"
        )));
    }
    Ok(())
}

fn validate_text_set(
    field: &str,
    values: &[String],
) -> Result<(), TestTargetInventoryRuntimeError> {
    for value in values {
        validate_short_text(field, value)?;
    }
    Ok(())
}

fn presence_digest(path: &str, present: bool) -> Digest {
    let mut hasher = CanonicalHasher::new(b"test-target-file-presence-v1");
    hasher.field_str(path);
    hasher.field_u8(u8::from(present));
    hasher.finish()
}
