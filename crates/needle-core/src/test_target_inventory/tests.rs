use super::*;

fn locator(path: &str) -> TestTargetLocator {
    TestTargetLocator::new(
        TestTargetLocatorKind::ManifestContent,
        path,
        Digest::blake3(path.as_bytes()),
    )
    .unwrap()
}

fn package(name: &str, path: &str) -> TestTargetPackageKey {
    TestTargetPackageKey::new(name, path).unwrap()
}

fn partition(package: TestTargetPackageKey, name: &str, locator: Digest) -> TestTargetPartition {
    TestTargetPartition::new(
        TestTargetPartitionKey {
            ecosystem: TestTargetEcosystem::Cargo,
            workspace: "Cargo.toml".to_owned(),
            package,
            target_kind: TestTargetKind::Test,
            target_name: name.to_owned(),
        },
        format!("tests/{name}.rs"),
        TestTargetDeclaration::Conventional,
        vec!["bin".to_owned()],
        Vec::new(),
        "2024",
        false,
        vec![locator],
    )
    .unwrap()
}

fn inventory_fixture() -> TestTargetInventory {
    let first_package = package("alpha", "crates/alpha/Cargo.toml");
    let second_package = package("beta", "crates/beta/Cargo.toml");
    let first_locator = locator("crates/alpha/Cargo.toml");
    let second_locator = locator("crates/beta/Cargo.toml");
    TestTargetInventory::new(
        Digest::blake3(b"repository"),
        "worktree",
        TestTargetInventoryScope::all(),
        Digest::blake3(b"adapter"),
        Digest::blake3(b"metadata"),
        vec![second_package.clone(), first_package.clone()],
        vec![second_locator.clone(), first_locator.clone()],
        vec![
            partition(second_package, "beta", second_locator.id),
            partition(first_package, "alpha", first_locator.id),
        ],
    )
    .unwrap()
}

#[test]
fn inventory_is_canonical_bounded_and_roundtrips() {
    let inventory = inventory_fixture();
    assert!(inventory.is_canonical());
    assert_eq!(inventory.package_universe[0].name, "alpha");
    assert_eq!(inventory.partitions[0].key.target_name, "alpha");
    let encoded = serde_json::to_vec(&inventory).unwrap();
    assert_eq!(TestTargetInventory::decode_json(&encoded).unwrap(), inventory);

    let mut unknown = serde_json::to_value(&inventory).unwrap();
    unknown.as_object_mut().unwrap().insert("authority".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<TestTargetInventory>(unknown).is_err());

    let oversized = vec![b' '; MAX_TEST_TARGET_INVENTORY_WIRE_BYTES + 1];
    assert!(matches!(
        TestTargetInventory::decode_json(&oversized),
        Err(TestTargetInventoryError::Bound { field: "inventory.wire_bytes", .. })
    ));
}

#[test]
fn tampering_and_noncanonical_sets_are_rejected() {
    let mut inventory = inventory_fixture();
    inventory.partitions.reverse();
    assert_eq!(
        inventory.validate(),
        Err(TestTargetInventoryError::Canonical("inventory.partitions"))
    );

    let mut inventory = inventory_fixture();
    inventory.partitions[0].source_path = "../escape.rs".to_owned();
    assert_eq!(inventory.validate(), Err(TestTargetInventoryError::Path("partition.source_path")));

    let mut inventory = inventory_fixture();
    inventory.content_digest = Digest::blake3(b"tampered");
    assert_eq!(
        inventory.validate(),
        Err(TestTargetInventoryError::Digest("inventory.content_digest"))
    );
}

#[test]
fn scopes_have_explicit_projection_semantics() {
    let alpha = package("alpha", "crates/alpha/Cargo.toml");
    let all = TestTargetInventoryScope::all();
    let package = TestTargetInventoryScope::new(vec![alpha], Vec::new(), Vec::new()).unwrap();
    let named = TestTargetInventoryScope::new(
        Vec::new(),
        vec![TestTargetKind::Test],
        vec!["alpha".to_owned()],
    )
    .unwrap();
    assert!(package.is_projection_of(&all));
    assert!(named.is_projection_of(&all));
    assert!(!all.is_projection_of(&package));
}

#[test]
fn collection_and_partition_bounds_reject_before_retention() {
    let mut value = serde_json::to_value(inventory_fixture()).unwrap();
    value["partitions"] =
        serde_json::Value::Array((0..=MAX_TEST_TARGETS).map(|_| serde_json::json!(null)).collect());
    assert!(serde_json::from_value::<TestTargetInventory>(value).is_err());

    let oversized_name = "x".repeat(MAX_TEST_TARGET_NAME_BYTES + 1);
    assert!(TestTargetPackageKey::new(oversized_name, "Cargo.toml").is_err());
}
