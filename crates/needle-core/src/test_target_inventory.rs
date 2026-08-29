use crate::{CanonicalHasher, Digest};
use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::path::{Component, Path};
use thiserror::Error;

pub const TEST_TARGET_INVENTORY_FORMAT_REVISION: u16 = 1;
pub const TEST_TARGET_INVENTORY_SCHEMA_ID: &str = "needle.test-target-inventory/1";
pub const TEST_TARGET_INVENTORY_OUTPUT_CONTRACT_ID: &str =
    "needle.repository.test-target-inventory";
pub const TEST_TARGET_INVENTORY_OUTPUT_CONTRACT_REVISION: u32 = 1;
pub const MAX_TEST_TARGET_INVENTORY_WIRE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_TEST_TARGET_PACKAGES: usize = 256;
pub const MAX_TEST_TARGETS: usize = 2_048;
pub const MAX_TEST_TARGET_LOCATORS: usize = 4_096;
pub const MAX_TEST_TARGET_LOCATORS_PER_TARGET: usize = 32;
pub const MAX_TEST_TARGET_FILTER_VALUES: usize = 256;
pub const MAX_TEST_TARGET_FEATURES: usize = 64;
pub const MAX_TEST_TARGET_CRATE_TYPES: usize = 16;
pub const MAX_TEST_TARGET_NAME_BYTES: usize = 128;
pub const MAX_TEST_TARGET_PATH_BYTES: usize = 512;
pub const MAX_TEST_TARGET_SOURCE_SELECTOR_BYTES: usize = 2_048;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TestTargetEcosystem {
    Cargo,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TestTargetKind {
    Lib,
    ProcMacro,
    Bin,
    Test,
    Example,
    Bench,
}

impl TestTargetKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lib => "lib",
            Self::ProcMacro => "proc-macro",
            Self::Bin => "bin",
            Self::Test => "test",
            Self::Example => "example",
            Self::Bench => "bench",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestTargetDeclaration {
    Manifest,
    Conventional,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestTargetLocatorKind {
    AdapterInput,
    ManifestContent,
    FilePresence,
    DirectoryEntries,
    TargetDirectoryEntries,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestTargetPackageKey {
    #[serde(deserialize_with = "deserialize_name")]
    pub name: String,
    #[serde(deserialize_with = "deserialize_path")]
    pub manifest_path: String,
}

impl TestTargetPackageKey {
    pub fn new(
        name: impl Into<String>,
        manifest_path: impl Into<String>,
    ) -> Result<Self, TestTargetInventoryError> {
        let value = Self { name: name.into(), manifest_path: manifest_path.into() };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), TestTargetInventoryError> {
        validate_name("package.name", &self.name)?;
        validate_relative_path("package.manifest_path", &self.manifest_path)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestTargetInventoryScope {
    #[serde(deserialize_with = "deserialize_packages")]
    pub packages: Vec<TestTargetPackageKey>,
    #[serde(deserialize_with = "deserialize_kinds")]
    pub target_kinds: Vec<TestTargetKind>,
    #[serde(deserialize_with = "deserialize_names")]
    pub target_names: Vec<String>,
}

impl TestTargetInventoryScope {
    pub fn all() -> Self {
        Self { packages: Vec::new(), target_kinds: Vec::new(), target_names: Vec::new() }
    }

    pub fn new(
        mut packages: Vec<TestTargetPackageKey>,
        mut target_kinds: Vec<TestTargetKind>,
        mut target_names: Vec<String>,
    ) -> Result<Self, TestTargetInventoryError> {
        packages.sort();
        target_kinds.sort();
        target_names.sort();
        let value = Self { packages, target_kinds, target_names };
        value.validate()?;
        Ok(value)
    }

    pub fn matches(&self, key: &TestTargetPartitionKey) -> bool {
        (self.packages.is_empty() || self.packages.binary_search(&key.package).is_ok())
            && (self.target_kinds.is_empty()
                || self.target_kinds.binary_search(&key.target_kind).is_ok())
            && (self.target_names.is_empty()
                || self.target_names.binary_search(&key.target_name).is_ok())
    }

    pub fn is_projection_of(&self, broader: &Self) -> bool {
        dimension_is_subset(&self.packages, &broader.packages)
            && dimension_is_subset(&self.target_kinds, &broader.target_kinds)
            && dimension_is_subset(&self.target_names, &broader.target_names)
    }

    pub fn digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"test-target-inventory-scope-v1");
        hasher.field_u16(self.packages.len().try_into().unwrap_or(u16::MAX));
        for package in &self.packages {
            hasher.field_str(&package.name);
            hasher.field_str(&package.manifest_path);
        }
        hasher.field_u16(self.target_kinds.len().try_into().unwrap_or(u16::MAX));
        for kind in &self.target_kinds {
            hasher.field_str(kind.as_str());
        }
        hasher.field_u16(self.target_names.len().try_into().unwrap_or(u16::MAX));
        for name in &self.target_names {
            hasher.field_str(name);
        }
        hasher.finish()
    }

    pub fn validate(&self) -> Result<(), TestTargetInventoryError> {
        validate_canonical_set("scope.packages", &self.packages, MAX_TEST_TARGET_PACKAGES)?;
        validate_canonical_set(
            "scope.target_kinds",
            &self.target_kinds,
            MAX_TEST_TARGET_FILTER_VALUES,
        )?;
        validate_canonical_set(
            "scope.target_names",
            &self.target_names,
            MAX_TEST_TARGET_FILTER_VALUES,
        )?;
        for package in &self.packages {
            package.validate()?;
        }
        for name in &self.target_names {
            validate_name("scope.target_names", name)?;
        }
        Ok(())
    }
}

impl Default for TestTargetInventoryScope {
    fn default() -> Self {
        Self::all()
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestTargetPartitionKey {
    pub ecosystem: TestTargetEcosystem,
    #[serde(deserialize_with = "deserialize_path")]
    pub workspace: String,
    pub package: TestTargetPackageKey,
    pub target_kind: TestTargetKind,
    #[serde(deserialize_with = "deserialize_name")]
    pub target_name: String,
}

impl TestTargetPartitionKey {
    pub fn validate(&self) -> Result<(), TestTargetInventoryError> {
        validate_relative_path("partition.key.workspace", &self.workspace)?;
        self.package.validate()?;
        validate_name("partition.key.target_name", &self.target_name)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestTargetLocator {
    pub id: Digest,
    pub kind: TestTargetLocatorKind,
    #[serde(deserialize_with = "deserialize_path")]
    pub path: String,
    pub value_digest: Digest,
}

impl TestTargetLocator {
    pub fn new(
        kind: TestTargetLocatorKind,
        path: impl Into<String>,
        value_digest: Digest,
    ) -> Result<Self, TestTargetInventoryError> {
        let path = path.into();
        validate_relative_path("locator.path", &path)?;
        let id = locator_id(kind, &path, value_digest);
        Ok(Self { id, kind, path, value_digest })
    }

    pub fn validate(&self) -> Result<(), TestTargetInventoryError> {
        validate_relative_path("locator.path", &self.path)?;
        if self.id != locator_id(self.kind, &self.path, self.value_digest) {
            return Err(TestTargetInventoryError::Digest("locator.id"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestTargetPartition {
    pub key: TestTargetPartitionKey,
    #[serde(deserialize_with = "deserialize_path")]
    pub source_path: String,
    pub declaration: TestTargetDeclaration,
    #[serde(deserialize_with = "deserialize_names")]
    pub crate_types: Vec<String>,
    #[serde(deserialize_with = "deserialize_names")]
    pub required_features: Vec<String>,
    #[serde(deserialize_with = "deserialize_name")]
    pub edition: String,
    pub doctest: bool,
    #[serde(deserialize_with = "deserialize_locator_ids")]
    pub locator_ids: Vec<Digest>,
    pub content_digest: Digest,
}

impl TestTargetPartition {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: TestTargetPartitionKey,
        source_path: impl Into<String>,
        declaration: TestTargetDeclaration,
        mut crate_types: Vec<String>,
        mut required_features: Vec<String>,
        edition: impl Into<String>,
        doctest: bool,
        mut locator_ids: Vec<Digest>,
    ) -> Result<Self, TestTargetInventoryError> {
        crate_types.sort();
        required_features.sort();
        locator_ids.sort();
        let mut value = Self {
            key,
            source_path: source_path.into(),
            declaration,
            crate_types,
            required_features,
            edition: edition.into(),
            doctest,
            locator_ids,
            content_digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.content_digest = value.compute_digest();
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), TestTargetInventoryError> {
        self.validate_shape()?;
        if self.content_digest != self.compute_digest() {
            return Err(TestTargetInventoryError::Digest("partition.content_digest"));
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), TestTargetInventoryError> {
        self.key.validate()?;
        validate_relative_path("partition.source_path", &self.source_path)?;
        validate_name("partition.edition", &self.edition)?;
        validate_canonical_text_set(
            "partition.crate_types",
            &self.crate_types,
            MAX_TEST_TARGET_CRATE_TYPES,
        )?;
        validate_canonical_text_set(
            "partition.required_features",
            &self.required_features,
            MAX_TEST_TARGET_FEATURES,
        )?;
        if self.locator_ids.is_empty() {
            return Err(TestTargetInventoryError::Empty("partition.locator_ids"));
        }
        validate_canonical_set(
            "partition.locator_ids",
            &self.locator_ids,
            MAX_TEST_TARGET_LOCATORS_PER_TARGET,
        )
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"test-target-partition-v1");
        hash_partition_key(&mut hasher, &self.key);
        hasher.field_str(&self.source_path);
        hasher.field_u8(match self.declaration {
            TestTargetDeclaration::Manifest => 0,
            TestTargetDeclaration::Conventional => 1,
        });
        for crate_type in &self.crate_types {
            hasher.field_str(crate_type);
        }
        for feature in &self.required_features {
            hasher.field_str(feature);
        }
        hasher.field_str(&self.edition);
        hasher.field_u8(u8::from(self.doctest));
        for locator in &self.locator_ids {
            hasher.field_digest(*locator);
        }
        hasher.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestTargetInventory {
    pub format_revision: u16,
    #[serde(deserialize_with = "deserialize_schema")]
    pub schema: String,
    pub repository_lineage: Digest,
    #[serde(deserialize_with = "deserialize_source_selector")]
    pub source_selector: String,
    pub scope: TestTargetInventoryScope,
    pub adapter_definition_digest: Digest,
    pub metadata_digest: Digest,
    #[serde(deserialize_with = "deserialize_packages")]
    pub package_universe: Vec<TestTargetPackageKey>,
    #[serde(deserialize_with = "deserialize_locators")]
    pub collection_dependencies: Vec<TestTargetLocator>,
    #[serde(deserialize_with = "deserialize_partitions")]
    pub partitions: Vec<TestTargetPartition>,
    pub content_digest: Digest,
}

impl TestTargetInventory {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository_lineage: Digest,
        source_selector: impl Into<String>,
        scope: TestTargetInventoryScope,
        adapter_definition_digest: Digest,
        metadata_digest: Digest,
        mut package_universe: Vec<TestTargetPackageKey>,
        mut collection_dependencies: Vec<TestTargetLocator>,
        mut partitions: Vec<TestTargetPartition>,
    ) -> Result<Self, TestTargetInventoryError> {
        package_universe.sort();
        collection_dependencies.sort_by(|left, right| {
            (left.path.as_str(), left.kind).cmp(&(right.path.as_str(), right.kind))
        });
        partitions.sort_by(|left, right| left.key.cmp(&right.key));
        let mut value = Self {
            format_revision: TEST_TARGET_INVENTORY_FORMAT_REVISION,
            schema: TEST_TARGET_INVENTORY_SCHEMA_ID.to_owned(),
            repository_lineage,
            source_selector: source_selector.into(),
            scope,
            adapter_definition_digest,
            metadata_digest,
            package_universe,
            collection_dependencies,
            partitions,
            content_digest: Digest([0; 32]),
        };
        value.validate_shape()?;
        value.content_digest = value.compute_digest();
        Ok(value)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, TestTargetInventoryError> {
        if bytes.len() > MAX_TEST_TARGET_INVENTORY_WIRE_BYTES {
            return Err(TestTargetInventoryError::Bound {
                field: "inventory.wire_bytes",
                actual: bytes.len(),
                maximum: MAX_TEST_TARGET_INVENTORY_WIRE_BYTES,
            });
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| TestTargetInventoryError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), TestTargetInventoryError> {
        self.validate_shape()?;
        if self.content_digest != self.compute_digest() {
            return Err(TestTargetInventoryError::Digest("inventory.content_digest"));
        }
        Ok(())
    }

    pub fn is_canonical(&self) -> bool {
        self.validate().is_ok()
    }

    fn validate_shape(&self) -> Result<(), TestTargetInventoryError> {
        if self.format_revision != TEST_TARGET_INVENTORY_FORMAT_REVISION {
            return Err(TestTargetInventoryError::FormatRevision(self.format_revision));
        }
        if self.schema != TEST_TARGET_INVENTORY_SCHEMA_ID {
            return Err(TestTargetInventoryError::Schema);
        }
        validate_text(
            "inventory.source_selector",
            &self.source_selector,
            MAX_TEST_TARGET_SOURCE_SELECTOR_BYTES,
        )?;
        self.scope.validate()?;
        validate_canonical_set(
            "inventory.package_universe",
            &self.package_universe,
            MAX_TEST_TARGET_PACKAGES,
        )?;
        for package in &self.package_universe {
            package.validate()?;
        }
        if self
            .scope
            .packages
            .iter()
            .any(|package| self.package_universe.binary_search(package).is_err())
        {
            return Err(TestTargetInventoryError::Reference("scope.packages"));
        }
        if self.collection_dependencies.len() > MAX_TEST_TARGET_LOCATORS {
            return Err(TestTargetInventoryError::Bound {
                field: "inventory.collection_dependencies",
                actual: self.collection_dependencies.len(),
                maximum: MAX_TEST_TARGET_LOCATORS,
            });
        }
        if !self.collection_dependencies.windows(2).all(|pair| {
            (pair[0].path.as_str(), pair[0].kind) < (pair[1].path.as_str(), pair[1].kind)
        }) {
            return Err(TestTargetInventoryError::Canonical("inventory.collection_dependencies"));
        }
        let mut locator_ids = BTreeSet::new();
        for locator in &self.collection_dependencies {
            locator.validate()?;
            if !locator_ids.insert(locator.id) {
                return Err(TestTargetInventoryError::Canonical(
                    "inventory.collection_dependencies",
                ));
            }
        }
        if self.partitions.len() > MAX_TEST_TARGETS {
            return Err(TestTargetInventoryError::Bound {
                field: "inventory.partitions",
                actual: self.partitions.len(),
                maximum: MAX_TEST_TARGETS,
            });
        }
        if !self.partitions.windows(2).all(|pair| pair[0].key < pair[1].key) {
            return Err(TestTargetInventoryError::Canonical("inventory.partitions"));
        }
        for partition in &self.partitions {
            partition.validate()?;
            if self.package_universe.binary_search(&partition.key.package).is_err()
                || !self.scope.matches(&partition.key)
            {
                return Err(TestTargetInventoryError::Reference("partition.key"));
            }
            if partition.locator_ids.iter().any(|locator| !locator_ids.contains(locator)) {
                return Err(TestTargetInventoryError::Reference("partition.locator_ids"));
            }
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut hasher = CanonicalHasher::new(b"test-target-inventory-v1");
        hasher.field_u16(self.format_revision);
        hasher.field_str(&self.schema);
        hasher.field_digest(self.repository_lineage);
        hasher.field_str(&self.source_selector);
        hasher.field_digest(self.scope.digest());
        hasher.field_digest(self.adapter_definition_digest);
        hasher.field_digest(self.metadata_digest);
        for package in &self.package_universe {
            hasher.field_str(&package.name);
            hasher.field_str(&package.manifest_path);
        }
        for locator in &self.collection_dependencies {
            hasher.field_digest(locator.id);
        }
        for partition in &self.partitions {
            hasher.field_digest(partition.content_digest);
        }
        hasher.finish()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TestTargetInventoryError {
    #[error("test-target inventory format revision {0} is unsupported")]
    FormatRevision(u16),
    #[error("test-target inventory schema is unsupported")]
    Schema,
    #[error("{field} contains {actual} entries or bytes; the maximum is {maximum}")]
    Bound { field: &'static str, actual: usize, maximum: usize },
    #[error("{0} must be non-empty and bounded")]
    Text(&'static str),
    #[error("{0} must be a safe repository-relative path")]
    Path(&'static str),
    #[error("{0} must be ordered and unique")]
    Canonical(&'static str),
    #[error("{0} must not be empty")]
    Empty(&'static str),
    #[error("{0} contains an unknown reference")]
    Reference(&'static str),
    #[error("{0} digest is inconsistent")]
    Digest(&'static str),
    #[error("test-target inventory JSON is invalid: {0}")]
    Json(String),
}

fn locator_id(kind: TestTargetLocatorKind, path: &str, value_digest: Digest) -> Digest {
    let mut hasher = CanonicalHasher::new(b"test-target-locator-v1");
    hasher.field_u8(match kind {
        TestTargetLocatorKind::AdapterInput => 0,
        TestTargetLocatorKind::ManifestContent => 1,
        TestTargetLocatorKind::FilePresence => 2,
        TestTargetLocatorKind::DirectoryEntries => 3,
        TestTargetLocatorKind::TargetDirectoryEntries => 4,
    });
    hasher.field_str(path);
    hasher.field_digest(value_digest);
    hasher.finish()
}

fn hash_partition_key(hasher: &mut CanonicalHasher, key: &TestTargetPartitionKey) {
    hasher.field_u8(match key.ecosystem {
        TestTargetEcosystem::Cargo => 0,
    });
    hasher.field_str(&key.workspace);
    hasher.field_str(&key.package.name);
    hasher.field_str(&key.package.manifest_path);
    hasher.field_str(key.target_kind.as_str());
    hasher.field_str(&key.target_name);
}

fn dimension_is_subset<T: Ord>(narrower: &[T], broader: &[T]) -> bool {
    broader.is_empty()
        || (!narrower.is_empty() && narrower.iter().all(|item| broader.binary_search(item).is_ok()))
}

fn validate_canonical_text_set(
    field: &'static str,
    values: &[String],
    maximum: usize,
) -> Result<(), TestTargetInventoryError> {
    validate_canonical_set(field, values, maximum)?;
    for value in values {
        validate_name(field, value)?;
    }
    Ok(())
}

fn validate_canonical_set<T: Ord>(
    field: &'static str,
    values: &[T],
    maximum: usize,
) -> Result<(), TestTargetInventoryError> {
    if values.len() > maximum {
        return Err(TestTargetInventoryError::Bound { field, actual: values.len(), maximum });
    }
    if !values.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(TestTargetInventoryError::Canonical(field));
    }
    Ok(())
}

fn validate_name(field: &'static str, value: &str) -> Result<(), TestTargetInventoryError> {
    validate_text(field, value, MAX_TEST_TARGET_NAME_BYTES)
}

fn validate_text(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), TestTargetInventoryError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(TestTargetInventoryError::Text(field));
    }
    Ok(())
}

fn validate_relative_path(
    field: &'static str,
    value: &str,
) -> Result<(), TestTargetInventoryError> {
    if value.is_empty() || value.len() > MAX_TEST_TARGET_PATH_BYTES || value.contains('\\') {
        return Err(TestTargetInventoryError::Path(field));
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        return Err(TestTargetInventoryError::Path(field));
    }
    Ok(())
}

struct BoundedTextVisitor {
    field: &'static str,
    maximum: usize,
}

impl Visitor<'_> for BoundedTextVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a non-empty string no longer than {} bytes", self.maximum)
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        self.check(value)?;
        Ok(value.to_owned())
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
        self.check(&value)?;
        Ok(value)
    }
}

impl BoundedTextVisitor {
    fn check<E: serde::de::Error>(&self, value: &str) -> Result<(), E> {
        if value.is_empty() || value.len() > self.maximum || value.chars().any(char::is_control) {
            return Err(E::custom(format!("{} exceeds its text bound", self.field)));
        }
        Ok(())
    }
}

fn deserialize_bounded_text<'de, D>(
    deserializer: D,
    field: &'static str,
    maximum: usize,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_string(BoundedTextVisitor { field, maximum })
}

fn deserialize_name<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_text(deserializer, "name", MAX_TEST_TARGET_NAME_BYTES)
}

fn deserialize_path<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_text(deserializer, "path", MAX_TEST_TARGET_PATH_BYTES)
}

fn deserialize_source_selector<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_text(deserializer, "source_selector", MAX_TEST_TARGET_SOURCE_SELECTOR_BYTES)
}

fn deserialize_schema<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_text(deserializer, "schema", 128)
}

struct BoundedVecVisitor<T> {
    field: &'static str,
    maximum: usize,
    marker: std::marker::PhantomData<T>,
}

impl<'de, T> Visitor<'de> for BoundedVecVisitor<T>
where
    T: Deserialize<'de>,
{
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "at most {} {} entries", self.maximum, self.field)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.maximum));
        while let Some(value) = sequence.next_element()? {
            if values.len() == self.maximum {
                return Err(A::Error::custom(format!("{} exceeds its bound", self.field)));
            }
            values.push(value);
        }
        Ok(values)
    }
}

fn deserialize_bounded_vec<'de, D, T>(
    deserializer: D,
    field: &'static str,
    maximum: usize,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserializer.deserialize_seq(BoundedVecVisitor {
        field,
        maximum,
        marker: std::marker::PhantomData,
    })
}

macro_rules! bounded_vec_deserializer {
    ($name:ident, $type:ty, $field:literal, $maximum:expr) => {
        fn $name<'de, D>(deserializer: D) -> Result<Vec<$type>, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserialize_bounded_vec(deserializer, $field, $maximum)
        }
    };
}

bounded_vec_deserializer!(
    deserialize_packages,
    TestTargetPackageKey,
    "packages",
    MAX_TEST_TARGET_PACKAGES
);
bounded_vec_deserializer!(
    deserialize_kinds,
    TestTargetKind,
    "target_kinds",
    MAX_TEST_TARGET_FILTER_VALUES
);
bounded_vec_deserializer!(deserialize_names, String, "names", MAX_TEST_TARGET_FILTER_VALUES);
bounded_vec_deserializer!(
    deserialize_locator_ids,
    Digest,
    "locator_ids",
    MAX_TEST_TARGET_LOCATORS_PER_TARGET
);
bounded_vec_deserializer!(
    deserialize_locators,
    TestTargetLocator,
    "collection_dependencies",
    MAX_TEST_TARGET_LOCATORS
);
bounded_vec_deserializer!(
    deserialize_partitions,
    TestTargetPartition,
    "partitions",
    MAX_TEST_TARGETS
);

#[cfg(test)]
mod tests;
