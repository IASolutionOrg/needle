use super::*;
use crate::{
    PartitionedActionHeadKey, RuntimeStore, ShadowManifestContext,
    ShadowPartitionManifestPublication, ShadowPartitionedActionHeadAdvance,
    built_in_action_contracts, certify_test_target_inventory_action_artifact,
    certify_test_target_inventory_shadow_manifest,
};
use needle_core::{
    ActionRequest, ArtifactId, ArtifactRequest, CapabilityMode, DependencyLocator, NeedFragmentId,
    NeedId, NeedKey, RefreshCostEvidence, RefreshCostEvidenceBasis, RefreshCostEvidenceInput,
    RefreshEconomicPolicy, RefreshEconomicPolicyInput, RepositoryContextId, RepositoryGeneration,
    SemanticWorld, StateDelta, TestTargetInventoryScope, TestTargetKind, TestTargetPackageKey,
};
use serde_json::json;
use std::cell::Cell;
use std::convert::Infallible;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

struct Fixture {
    root: PathBuf,
    metadata: Vec<u8>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let root = std::env::temp_dir().join(format!("needle-test-target-inventory-{nonce}"));
        fs::create_dir_all(root.join("crates/alpha/src")).unwrap();
        fs::create_dir_all(root.join("crates/alpha/tests")).unwrap();
        fs::create_dir_all(root.join("crates/beta/src")).unwrap();
        fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = [\"crates/*\"]\n").unwrap();
        fs::write(
            root.join("crates/alpha/Cargo.toml"),
            "[package]\nname = \"alpha\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[[test]]\nname = \"explicit\"\npath = \"tests/special.rs\"\n",
        )
        .unwrap();
        fs::write(root.join("crates/alpha/src/lib.rs"), "pub fn alpha() {}\n").unwrap();
        fs::write(root.join("crates/alpha/tests/special.rs"), "#[test] fn explicit() {}\n")
            .unwrap();
        fs::write(root.join("crates/alpha/tests/implicit.rs"), "#[test] fn implicit() {}\n")
            .unwrap();
        fs::write(
            root.join("crates/beta/Cargo.toml"),
            "[package]\nname = \"beta\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lib]\npath = \"src/lib.rs\"\n",
        )
        .unwrap();
        fs::write(root.join("crates/beta/src/lib.rs"), "pub fn beta() {}\n").unwrap();
        let alpha_id = "path+file:///fixture/alpha#0.1.0";
        let beta_id = "path+file:///fixture/beta#0.1.0";
        let metadata = json!({
            "packages": [
                package_json(&root, "alpha", alpha_id, &[
                    ("alpha", "lib", "src/lib.rs", true),
                    ("explicit", "test", "tests/special.rs", false),
                    ("implicit", "test", "tests/implicit.rs", false),
                ]),
                package_json(&root, "beta", beta_id, &[
                    ("beta", "lib", "src/lib.rs", true),
                ]),
            ],
            "workspace_members": [alpha_id, beta_id],
            "workspace_root": root,
        });
        Self { root, metadata: serde_json::to_vec(&metadata).unwrap() }
    }

    fn input(&self, scope: TestTargetInventoryScope) -> CargoTestTargetInventoryInput<'_> {
        CargoTestTargetInventoryInput {
            repository_root: &self.root,
            repository_lineage: Digest::blake3(b"repository"),
            source_selector: "worktree",
            scope,
            metadata_json: &self.metadata,
            cargo_version: "cargo 1.90.0",
        }
    }

    fn root_package() -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let root = std::env::temp_dir().join(format!("needle-test-target-root-package-{nonce}"));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"root-package\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn root_package() {}\n").unwrap();
        let package_id = "path+file:///fixture/root-package#0.1.0";
        let metadata = json!({
            "packages": [{
                "id": package_id,
                "name": "root-package",
                "manifest_path": root.join("Cargo.toml"),
                "targets": [{
                    "name": "root_package",
                    "kind": ["lib"],
                    "crate_types": ["lib"],
                    "required_features": [],
                    "src_path": root.join("src/lib.rs"),
                    "edition": "2024",
                    "test": true,
                    "doctest": true,
                }],
            }],
            "workspace_members": [package_id],
            "workspace_root": root,
        });
        Self { root, metadata: serde_json::to_vec(&metadata).unwrap() }
    }

    fn root_and_member_packages() -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let root = std::env::temp_dir().join(format!("needle-test-target-root-member-{nonce}"));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("member/src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"member\"]\n\n[package]\nname = \"root-package\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn root_package() {}\n").unwrap();
        fs::write(
            root.join("member/Cargo.toml"),
            "[package]\nname = \"member\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(root.join("member/src/lib.rs"), "pub fn member() {}\n").unwrap();
        let root_id = "path+file:///fixture/root-package#0.1.0";
        let member_id = "path+file:///fixture/member#0.1.0";
        let metadata = json!({
            "packages": [
                {
                    "id": root_id,
                    "name": "root-package",
                    "manifest_path": root.join("Cargo.toml"),
                    "targets": [{
                        "name": "root_package",
                        "kind": ["lib"],
                        "crate_types": ["lib"],
                        "required_features": [],
                        "src_path": root.join("src/lib.rs"),
                        "edition": "2024",
                        "test": true,
                        "doctest": true,
                    }],
                },
                {
                    "id": member_id,
                    "name": "member",
                    "manifest_path": root.join("member/Cargo.toml"),
                    "targets": [{
                        "name": "member",
                        "kind": ["lib"],
                        "crate_types": ["lib"],
                        "required_features": [],
                        "src_path": root.join("member/src/lib.rs"),
                        "edition": "2024",
                        "test": true,
                        "doctest": true,
                    }],
                },
            ],
            "workspace_members": [root_id, member_id],
            "workspace_root": root,
        });
        Self { root, metadata: serde_json::to_vec(&metadata).unwrap() }
    }
}

fn package_json(
    root: &Path,
    name: &str,
    id: &str,
    targets: &[(&str, &str, &str, bool)],
) -> serde_json::Value {
    let package_root = root.join("crates").join(name);
    json!({
        "id": id,
        "name": name,
        "manifest_path": package_root.join("Cargo.toml"),
        "targets": targets.iter().map(|(target, kind, path, doctest)| json!({
            "name": target,
            "kind": [kind],
            "crate_types": [if *kind == "lib" { "lib" } else { "bin" }],
            "required_features": [],
            "src_path": package_root.join(path),
            "edition": "2024",
            "test": true,
            "doctest": doctest,
        })).collect::<Vec<_>>()
    })
}

#[test]
fn cargo_adapter_enumerates_explicit_and_implicit_targets_canonically() {
    let fixture = Fixture::new();
    let inventory =
        enumerate_cargo_test_targets(fixture.input(TestTargetInventoryScope::all())).unwrap();
    assert_eq!(inventory.package_universe.len(), 2);
    assert_eq!(inventory.partitions.len(), 4);
    assert!(inventory.is_canonical());
    assert_eq!(inventory.partitions[0].key.package.name, "alpha");
    assert_eq!(
        inventory
            .partitions
            .iter()
            .find(|partition| partition.key.target_name == "explicit")
            .unwrap()
            .declaration,
        needle_core::TestTargetDeclaration::Manifest
    );
    assert!(inventory.collection_dependencies.iter().any(|locator| {
        locator.kind == needle_core::TestTargetLocatorKind::TargetDirectoryEntries
            && locator.path == "crates/alpha/tests"
    }));
    let certificate = validate_cargo_test_target_inventory(
        fixture.input(TestTargetInventoryScope::all()),
        &inventory,
    )
    .unwrap();
    assert_eq!(certificate.inventory, inventory.content_digest);
    assert!(certificate.validate().is_ok());
}

#[test]
fn cargo_adapter_deduplicates_the_root_package_workspace_manifest_locator() {
    let fixture = Fixture::root_package();
    let inventory =
        enumerate_cargo_test_targets(fixture.input(TestTargetInventoryScope::all())).unwrap();
    assert_eq!(inventory.partitions.len(), 1);
    assert!(inventory.partitions[0].locator_ids.windows(2).all(|pair| pair[0] < pair[1]));
}

#[test]
fn targeted_refresh_retains_every_locator_referenced_by_a_root_package_partition() {
    let fixture = Fixture::root_and_member_packages();
    let input = fixture.input(TestTargetInventoryScope::all());
    let prior = enumerate_cargo_test_targets(input.clone()).unwrap();
    let prior_validation = validate_cargo_test_target_inventory(input.clone(), &prior).unwrap();
    let member_manifest = fixture.root.join("member/Cargo.toml");
    let previous = fs::read_to_string(&member_manifest).unwrap();
    fs::write(&member_manifest, format!("{previous}\n# changed member\n")).unwrap();
    let delta = repository_delta(&prior, &["member/Cargo.toml"], true);
    let acquisition = acquire_cargo_test_target_refresh_candidate(CargoTestTargetRefreshInput {
        current: input.clone(),
        prior_inventory: &prior,
        prior_validation: &prior_validation,
        state_delta: &delta,
    })
    .unwrap();
    let CargoTestTargetRefreshAcquisition::Candidate { result } = acquisition else {
        panic!("a member-only change must retain the root package partition");
    };
    let fresh = enumerate_cargo_test_targets(input).unwrap();
    assert_eq!(result.inventory, fresh);
    assert_eq!(result.retained_partitions, 1);
}

#[test]
fn validator_rejects_omission_and_locator_drift() {
    let fixture = Fixture::new();
    let inventory =
        enumerate_cargo_test_targets(fixture.input(TestTargetInventoryScope::all())).unwrap();
    let omitted = TestTargetInventory::new(
        inventory.repository_lineage,
        inventory.source_selector.clone(),
        inventory.scope.clone(),
        inventory.adapter_definition_digest,
        inventory.metadata_digest,
        inventory.package_universe.clone(),
        inventory.collection_dependencies.clone(),
        inventory.partitions[1..].to_vec(),
    )
    .unwrap();
    assert!(matches!(
        validate_cargo_test_target_inventory(
            fixture.input(TestTargetInventoryScope::all()),
            &omitted
        ),
        Err(TestTargetInventoryRuntimeError::Mismatch)
    ));

    fs::write(fixture.root.join("crates/alpha/tests/new_target.rs"), "#[test] fn new() {}\n")
        .unwrap();
    assert!(matches!(
        validate_cargo_test_target_inventory(
            fixture.input(TestTargetInventoryScope::all()),
            &inventory
        ),
        Err(TestTargetInventoryRuntimeError::Mismatch)
    ));
}

#[test]
fn validator_ignores_source_files_that_cannot_change_target_membership() {
    let fixture = Fixture::new();
    let inventory =
        enumerate_cargo_test_targets(fixture.input(TestTargetInventoryScope::all())).unwrap();
    fs::write(fixture.root.join("crates/alpha/src/module.rs"), "pub fn module() {}\n").unwrap();
    assert!(
        validate_cargo_test_target_inventory(
            fixture.input(TestTargetInventoryScope::all()),
            &inventory
        )
        .is_ok()
    );
}

#[test]
fn validator_tracks_wildcard_members_and_nested_conventional_targets() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.root.join("crates/pending")).unwrap();
    let before_member =
        enumerate_cargo_test_targets(fixture.input(TestTargetInventoryScope::all())).unwrap();
    fs::write(
        fixture.root.join("crates/pending/Cargo.toml"),
        "[package]\nname = \"pending\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    assert!(matches!(
        validate_cargo_test_target_inventory(
            fixture.input(TestTargetInventoryScope::all()),
            &before_member
        ),
        Err(TestTargetInventoryRuntimeError::Mismatch)
    ));

    fs::create_dir_all(fixture.root.join("crates/alpha/tests/nested")).unwrap();
    fs::write(fixture.root.join("crates/alpha/tests/nested/main.rs"), "#[test] fn nested() {}\n")
        .unwrap();
    let nested_id = "path+file:///fixture/alpha#0.1.0";
    let mut metadata: serde_json::Value = serde_json::from_slice(&fixture.metadata).unwrap();
    metadata["packages"][0]["targets"].as_array_mut().unwrap().push(json!({
        "name": "nested",
        "kind": ["test"],
        "crate_types": ["bin"],
        "required-features": [],
        "src_path": fixture.root.join("crates/alpha/tests/nested/main.rs"),
        "edition": "2024",
        "test": true,
        "doctest": false,
    }));
    assert_eq!(metadata["packages"][0]["id"], json!(nested_id));
    let bytes = serde_json::to_vec(&metadata).unwrap();
    let mut input = fixture.input(TestTargetInventoryScope::all());
    input.metadata_json = &bytes;
    let inventory = enumerate_cargo_test_targets(input).unwrap();
    let nested = inventory
        .partitions
        .iter()
        .find(|partition| partition.key.target_name == "nested")
        .unwrap();
    assert!(nested.locator_ids.iter().any(|id| {
        inventory.collection_dependencies.iter().any(|locator| {
            locator.id == *id
                && locator.kind == needle_core::TestTargetLocatorKind::TargetDirectoryEntries
                && locator.path == "crates/alpha/tests/nested"
        })
    }));
}

#[test]
fn package_projection_and_disjoint_assembly_are_exact() {
    let fixture = Fixture::new();
    let full =
        enumerate_cargo_test_targets(fixture.input(TestTargetInventoryScope::all())).unwrap();
    let alpha = TestTargetPackageKey::new("alpha", "crates/alpha/Cargo.toml").unwrap();
    let beta = TestTargetPackageKey::new("beta", "crates/beta/Cargo.toml").unwrap();
    let alpha_scope = TestTargetInventoryScope::new(vec![alpha], Vec::new(), Vec::new()).unwrap();
    let beta_scope = TestTargetInventoryScope::new(vec![beta], Vec::new(), Vec::new()).unwrap();
    let alpha = project_test_target_inventory(&full, alpha_scope).unwrap();
    let beta = project_test_target_inventory(&full, beta_scope).unwrap();
    let assembled = assemble_test_target_inventories(
        &[beta.clone(), alpha.clone()],
        TestTargetInventoryScope::all(),
    )
    .unwrap();
    assert_eq!(assembled, full);
    assert!(matches!(
        assemble_test_target_inventories(&[alpha.clone(), alpha], TestTargetInventoryScope::all()),
        Err(TestTargetInventoryRuntimeError::Assembly)
    ));

    let tests_only =
        TestTargetInventoryScope::new(Vec::new(), vec![TestTargetKind::Test], Vec::new()).unwrap();
    assert_eq!(project_test_target_inventory(&full, tests_only).unwrap().partitions.len(), 2);
}

#[test]
fn adapter_fails_closed_on_bounds_unsafe_paths_and_unsupported_kinds() {
    let fixture = Fixture::new();
    let oversized = vec![b' '; MAX_CARGO_METADATA_INPUT_BYTES + 1];
    let mut input = fixture.input(TestTargetInventoryScope::all());
    input.metadata_json = &oversized;
    assert!(matches!(
        enumerate_cargo_test_targets(input),
        Err(TestTargetInventoryRuntimeError::MetadataBound { .. })
    ));

    let mut metadata: serde_json::Value = serde_json::from_slice(&fixture.metadata).unwrap();
    metadata["packages"][0]["targets"][0]["kind"] = json!(["custom-build"]);
    let bytes = serde_json::to_vec(&metadata).unwrap();
    let mut input = fixture.input(TestTargetInventoryScope::all());
    input.metadata_json = &bytes;
    assert!(matches!(
        enumerate_cargo_test_targets(input),
        Err(TestTargetInventoryRuntimeError::UnsupportedTarget(_))
    ));

    metadata = serde_json::from_slice(&fixture.metadata).unwrap();
    metadata["packages"][0]["targets"][0]["src_path"] =
        json!(fixture.root.parent().unwrap().join("outside.rs"));
    fs::write(fixture.root.parent().unwrap().join("outside.rs"), "outside").unwrap();
    let bytes = serde_json::to_vec(&metadata).unwrap();
    let mut input = fixture.input(TestTargetInventoryScope::all());
    input.metadata_json = &bytes;
    assert!(matches!(
        enumerate_cargo_test_targets(input),
        Err(TestTargetInventoryRuntimeError::UnsafeLocator(_))
    ));
    let _ = fs::remove_file(fixture.root.parent().unwrap().join("outside.rs"));
}

#[test]
fn shadow_refresh_retains_only_delta_disjoint_partitions_and_matches_fresh_oracle() {
    let fixture = Fixture::new();
    let request = inventory_action_request();
    let world = inventory_world();
    let prior =
        enumerate_cargo_test_targets(fixture.input(TestTargetInventoryScope::all())).unwrap();
    let prior_validation = validate_cargo_test_target_inventory(
        fixture.input(TestTargetInventoryScope::all()),
        &prior,
    )
    .unwrap();
    let prior_publication = certify_test_target_inventory_shadow_manifest(
        ShadowManifestContext {
            request: &request,
            world: &world,
            definition_set_digest: Digest::blake3(b"definition-set"),
        },
        &prior,
        &prior_validation,
        1,
    )
    .unwrap();

    let alpha_manifest = fixture.root.join("crates/alpha/Cargo.toml");
    let previous = fs::read_to_string(&alpha_manifest).unwrap();
    fs::write(&alpha_manifest, format!("{previous}\n# adjacent generation\n")).unwrap();
    let current =
        enumerate_cargo_test_targets(fixture.input(TestTargetInventoryScope::all())).unwrap();
    let current_validation = validate_cargo_test_target_inventory(
        fixture.input(TestTargetInventoryScope::all()),
        &current,
    )
    .unwrap();
    let current_publication = certify_test_target_inventory_shadow_manifest(
        ShadowManifestContext {
            request: &request,
            world: &world,
            definition_set_digest: Digest::blake3(b"definition-set"),
        },
        &current,
        &current_validation,
        2,
    )
    .unwrap();
    let delta = StateDelta::new(
        prior.repository_lineage,
        RepositoryContextId::new(Digest::blake3(b"worktree")),
        1,
        2,
        vec![DependencyLocator::repository_path("crates/alpha/Cargo.toml").unwrap()],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        true,
    )
    .unwrap();

    let decision = evaluate_test_target_inventory_refresh(TestTargetInventoryRefreshInput {
        prior_inventory: &prior,
        prior_validation: &prior_validation,
        prior_publication: &prior_publication,
        current_inventory: &current,
        current_validation: &current_validation,
        current_publication: &current_publication,
        state_delta: &delta,
    })
    .unwrap();
    let admitted_decision = decision.clone();
    let TestTargetInventoryRefreshDecision::Refresh { result } = decision else {
        panic!("one unchanged explicit package must remain refresh-eligible");
    };
    assert_eq!(result.authority, needle_core::CapabilityMode::Shadow);
    assert_eq!(result.reconstructed, current);
    assert_eq!(result.fresh_oracle_digest, current.content_digest);
    assert_eq!(result.plan.transition.mappings.len(), 4);
    assert_eq!(result.plan.retained.len(), 1);
    assert_eq!(result.plan.refreshed.len(), 3);
    assert!(result.plan.added.is_empty());
    assert!(result.plan.removed.is_empty());
    assert!(result.plan.validate().is_ok());
    let mut tampered = result.plan.clone();
    tampered.retained.clear();
    assert!(tampered.validate().is_err());

    let definition = built_in_action_contracts()
        .iter()
        .find(|definition| definition.contract.id.as_str() == "needle.tests.inventory")
        .unwrap();
    let policy = RefreshEconomicPolicy::new(RefreshEconomicPolicyInput {
        action_operational_policy_digest: definition.contract.operational_policy_digest,
        refresh_policy_definition_digest: test_target_inventory_refresh_definition(),
        minimum_expected_net_microusd: 100,
        maximum_refresh_latency_micros: Some(50_000),
    })
    .unwrap();
    let evidence = RefreshCostEvidence::new(RefreshCostEvidenceInput {
        request: request.semantic_id(),
        action_contract: definition.contract.id.clone(),
        candidate_definition_digest: result.plan.definition_digest,
        operator_definition_digest: test_target_inventory_refresh_definition(),
        execution_scope_digest: Digest::blake3(b"inventory-refresh-scope"),
        basis: RefreshCostEvidenceBasis::BenchmarkDerived,
        evidence_digest: Digest::blake3(b"frozen-refresh-corpus"),
        pricing_revision: Some(Digest::blake3(b"fixture-pricing")),
        estimated_fresh_total_microusd: 1_000,
        estimated_refresh_total_microusd: 200,
        estimated_refresh_latency_micros: Some(15_000),
    })
    .unwrap();
    let fallback_calls = Cell::new(0);
    let resolved = resolve_test_target_inventory_refresh_or_full_compute(
        &request,
        &definition.contract,
        admitted_decision,
        &policy,
        Some(&evidence),
        Digest::blake3(b"inventory-refresh-scope"),
        || {
            fallback_calls.set(fallback_calls.get() + 1);
            Ok::<_, Infallible>(())
        },
    )
    .unwrap();
    assert_eq!(fallback_calls.get(), 0);
    assert!(matches!(resolved, crate::ShadowRefreshResolution::Refresh { .. }));
}

struct PersistedShadowInventory {
    store: RuntimeStore,
    request: ActionRequest,
    world: SemanticWorld,
    prior: TestTargetInventory,
    prior_validation: TestTargetInventoryValidationCertificate,
    prior_manifest: ShadowPartitionManifestPublication,
    prior_artifact: ArtifactId,
    head_key: PartitionedActionHeadKey,
}

fn persisted_shadow_inventory(fixture: &Fixture) -> PersistedShadowInventory {
    let request = inventory_action_request();
    let world = inventory_world();
    let prior =
        enumerate_cargo_test_targets(fixture.input(TestTargetInventoryScope::all())).unwrap();
    let prior_validation = validate_cargo_test_target_inventory(
        fixture.input(TestTargetInventoryScope::all()),
        &prior,
    )
    .unwrap();
    let prior_manifest = certify_test_target_inventory_shadow_manifest(
        ShadowManifestContext {
            request: &request,
            world: &world,
            definition_set_digest: Digest::blake3(b"shadow-execution-definitions"),
        },
        &prior,
        &prior_validation,
        1,
    )
    .unwrap();
    let prior_publication = certify_test_target_inventory_action_artifact(
        &request,
        &prior,
        &prior_validation,
        &world,
        &prior_manifest,
        1,
    )
    .unwrap();
    let prior_artifact = ArtifactId::new(prior_publication.artifact().id);
    let head_key = PartitionedActionHeadKey::new(
        request.contract.clone(),
        prior.repository_lineage,
        RepositoryContextId::new(Digest::blake3(b"shadow-execution-repository-context")),
        &prior.source_selector,
        Digest::blake3(b"shadow-execution-provider-context"),
        prior.scope.digest(),
    )
    .unwrap();
    let prior_validation_json = serde_json::to_vec(&prior_validation).unwrap();
    let store = RuntimeStore::new(fixture.root.join("shadow-execution.sqlite3"));
    store.initialize().unwrap();
    store.publish_shadow_partition_manifest(&prior_manifest).unwrap();
    store
        .publish_shadow_partitioned_action_artifact_and_advance_head(
            &request,
            &prior_manifest,
            &prior_publication,
            ShadowPartitionedActionHeadAdvance {
                key: head_key.clone(),
                expected_prior_artifact: None,
                repository_generation: 0,
                source_validation_certificate_digest: prior_validation.certificate_digest,
                source_validation_validator_definition_digest: prior_validation
                    .validator_definition_digest,
                source_validation_json: &prior_validation_json,
                content_digest: prior.content_digest,
            },
        )
        .unwrap();
    PersistedShadowInventory {
        store,
        request,
        world,
        prior,
        prior_validation,
        prior_manifest,
        prior_artifact,
        head_key,
    }
}

fn shadow_refresh_policy() -> RefreshEconomicPolicy {
    let definition = built_in_action_contracts()
        .iter()
        .find(|definition| definition.contract.id.as_str() == "needle.tests.inventory")
        .unwrap();
    RefreshEconomicPolicy::new(RefreshEconomicPolicyInput {
        action_operational_policy_digest: definition.contract.operational_policy_digest,
        refresh_policy_definition_digest: test_target_inventory_refresh_definition(),
        minimum_expected_net_microusd: 100,
        maximum_refresh_latency_micros: Some(50_000),
    })
    .unwrap()
}

fn mutate_alpha_manifest(fixture: &Fixture) {
    let manifest = fixture.root.join("crates/alpha/Cargo.toml");
    let previous = fs::read_to_string(&manifest).unwrap();
    fs::write(&manifest, format!("{previous}\n# shadow executor refresh\n")).unwrap();
}

#[test]
fn shadow_executor_atomically_publishes_economically_selected_refresh() {
    let fixture = Fixture::new();
    let persisted = persisted_shadow_inventory(&fixture);
    mutate_alpha_manifest(&fixture);
    let delta = repository_delta(&persisted.prior, &["crates/alpha/Cargo.toml"], true);
    let policy = shadow_refresh_policy();
    let attempts = [Digest::blake3(b"provider-snapshot-attempt")];

    let execution = execute_shadow_cargo_test_target_refresh(
        &persisted.store,
        ShadowCargoTestTargetRefreshExecutionInput {
            request: &persisted.request,
            world: &persisted.world,
            definition_set_digest: Digest::blake3(b"shadow-execution-definitions"),
            prior_inventory: &persisted.prior,
            prior_validation: &persisted.prior_validation,
            prior_manifest: &persisted.prior_manifest,
            prior_artifact: persisted.prior_artifact,
            current: fixture.input(TestTargetInventoryScope::all()),
            state_delta: &delta,
            economic_policy: &policy,
            cost_estimate: Some(ShadowRefreshCostEstimate {
                basis: RefreshCostEvidenceBasis::BenchmarkDerived,
                evidence_digest: Digest::blake3(b"shadow-refresh-benchmark"),
                pricing_revision: Some(Digest::blake3(b"shadow-pricing")),
                estimated_fresh_total_microusd: 1_000,
                estimated_refresh_total_microusd: 200,
                estimated_refresh_latency_micros: Some(15_000),
            }),
            execution_scope_digest: Digest::blake3(b"shadow-execution-scope"),
            execution_attempts: &attempts,
            started_unix_ms: 1,
            observed_refresh_cost_microusd: Some(190),
            head: None,
        },
    )
    .unwrap();

    let ShadowTestTargetRefreshExecution::RefreshPublished { publication, attempt, assessment } =
        execution
    else {
        panic!("economically admitted candidate must publish a refresh");
    };
    assert_eq!(publication.authority, CapabilityMode::Shadow);
    assert!(
        persisted.store.semantic_artifact(&publication.artifact.to_string()).unwrap().is_some()
    );
    assert_eq!(persisted.store.refresh_attempt(attempt).unwrap().unwrap().id, attempt);
    let stored = persisted.store.refresh_economic_assessment(assessment).unwrap().unwrap();
    assert_eq!(stored.selected_refresh_attempt, Some(attempt));
    assert_eq!(stored.assessment.authority, CapabilityMode::Shadow);
}

#[test]
fn shadow_executor_atomically_advances_the_partitioned_head() {
    let fixture = Fixture::new();
    let persisted = persisted_shadow_inventory(&fixture);
    mutate_alpha_manifest(&fixture);
    let delta = repository_delta(&persisted.prior, &["crates/alpha/Cargo.toml"], true);
    let policy = shadow_refresh_policy();

    let execution = execute_shadow_cargo_test_target_refresh(
        &persisted.store,
        ShadowCargoTestTargetRefreshExecutionInput {
            request: &persisted.request,
            world: &persisted.world,
            definition_set_digest: Digest::blake3(b"shadow-execution-definitions"),
            prior_inventory: &persisted.prior,
            prior_validation: &persisted.prior_validation,
            prior_manifest: &persisted.prior_manifest,
            prior_artifact: persisted.prior_artifact,
            current: fixture.input(TestTargetInventoryScope::all()),
            state_delta: &delta,
            economic_policy: &policy,
            cost_estimate: Some(ShadowRefreshCostEstimate {
                basis: RefreshCostEvidenceBasis::BenchmarkDerived,
                evidence_digest: Digest::blake3(b"headed-shadow-refresh-benchmark"),
                pricing_revision: None,
                estimated_fresh_total_microusd: 1_000,
                estimated_refresh_total_microusd: 200,
                estimated_refresh_latency_micros: Some(15_000),
            }),
            execution_scope_digest: Digest::blake3(b"shadow-execution-scope"),
            execution_attempts: &[],
            started_unix_ms: 1,
            observed_refresh_cost_microusd: Some(190),
            head: Some(ShadowTestTargetHeadExecutionContext {
                key: &persisted.head_key,
                expected_prior_artifact: persisted.prior_artifact,
                repository_generation: 1,
            }),
        },
    )
    .unwrap();

    let ShadowTestTargetRefreshExecution::RefreshPublished { publication, .. } = execution else {
        panic!("economically admitted candidate must publish a refresh");
    };
    let head = persisted.store.partitioned_action_head(&persisted.head_key).unwrap().unwrap();
    assert_eq!(head.repository_generation, 1);
    assert_eq!(head.artifact, publication.artifact);
    assert_ne!(head.artifact, persisted.prior_artifact);
}

#[test]
fn shadow_host_bootstraps_and_reuses_the_same_repository_generation() {
    let fixture = Fixture::new();
    let store = RuntimeStore::new(fixture.root.join("shadow-host-current.sqlite3"));
    store.initialize().unwrap();
    let context = RepositoryContextId::new(Digest::blake3(b"shadow-host-context"));
    let generation = RepositoryGeneration::new(
        Digest::blake3(b"repository"),
        context,
        0,
        Digest::blake3(b"shadow-host-source-0"),
        None,
        true,
    );
    let policy = shadow_refresh_policy();

    let first = execute_shadow_cargo_test_target_host(
        &store,
        ShadowCargoTestTargetHostInput {
            repository_root: &fixture.root,
            generation: &generation,
            delta: None,
            source_selector: "worktree",
            scope: TestTargetInventoryScope::all(),
            metadata_json: &fixture.metadata,
            cargo_version: "cargo 1.90.0",
            platform: "test-platform",
            economic_policy: &policy,
            cost_estimate: None,
            execution_scope_digest: Digest::blake3(b"shadow-host-execution"),
            execution_attempts: &[],
            started_unix_ms: 1,
            observed_refresh_cost_microusd: None,
        },
    )
    .unwrap();
    let ShadowCargoTestTargetHostExecution::BootstrapPublished {
        publication: first_publication,
        repository_generation: 0,
    } = first
    else {
        panic!("the first host invocation must bootstrap the Shadow head");
    };

    let second = execute_shadow_cargo_test_target_host(
        &store,
        ShadowCargoTestTargetHostInput {
            repository_root: &fixture.root,
            generation: &generation,
            delta: None,
            source_selector: "worktree",
            scope: TestTargetInventoryScope::all(),
            metadata_json: &fixture.metadata,
            cargo_version: "cargo 1.90.0",
            platform: "test-platform",
            economic_policy: &policy,
            cost_estimate: None,
            execution_scope_digest: Digest::blake3(b"shadow-host-execution"),
            execution_attempts: &[],
            started_unix_ms: 1,
            observed_refresh_cost_microusd: None,
        },
    )
    .unwrap();
    let ShadowCargoTestTargetHostExecution::PriorRemainsCurrent {
        publication: second_publication,
        repository_generation: 0,
    } = second
    else {
        panic!("an identical repository generation must keep the prior publication");
    };
    assert_eq!(second_publication, first_publication);
}

#[test]
fn shadow_host_refreshes_an_adjacent_generation_and_rebaselines_a_gap() {
    let fixture = Fixture::new();
    let store = RuntimeStore::new(fixture.root.join("shadow-host-advance.sqlite3"));
    store.initialize().unwrap();
    let context = RepositoryContextId::new(Digest::blake3(b"shadow-host-advance-context"));
    let generation_0 = RepositoryGeneration::new(
        Digest::blake3(b"repository"),
        context,
        0,
        Digest::blake3(b"shadow-host-advance-source-0"),
        None,
        true,
    );
    let policy = shadow_refresh_policy();
    execute_shadow_cargo_test_target_host(
        &store,
        economically_evidenced_shadow_host_input(&fixture, &generation_0, None, &policy),
    )
    .unwrap();

    mutate_alpha_manifest(&fixture);
    let generation_1 = RepositoryGeneration::new(
        generation_0.repository_lineage,
        context,
        1,
        Digest::blake3(b"shadow-host-advance-source-1"),
        None,
        true,
    );
    let delta_1 = StateDelta::new(
        generation_0.repository_lineage,
        context,
        0,
        1,
        vec![DependencyLocator::repository_path("crates/alpha/Cargo.toml").unwrap()],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        true,
    )
    .unwrap();
    let refreshed = execute_shadow_cargo_test_target_host(
        &store,
        economically_evidenced_shadow_host_input(&fixture, &generation_1, Some(&delta_1), &policy),
    )
    .unwrap();
    assert!(matches!(
        refreshed,
        ShadowCargoTestTargetHostExecution::RefreshExecuted {
            execution: ShadowTestTargetRefreshExecution::RefreshPublished { .. },
            from_repository_generation: 0,
            to_repository_generation: 1,
        }
    ));

    mutate_alpha_manifest(&fixture);
    let generation_3 = RepositoryGeneration::new(
        generation_0.repository_lineage,
        context,
        3,
        Digest::blake3(b"shadow-host-advance-source-3"),
        None,
        true,
    );
    let rebaseline = execute_shadow_cargo_test_target_host(
        &store,
        economically_evidenced_shadow_host_input(&fixture, &generation_3, None, &policy),
    )
    .unwrap();
    assert!(matches!(
        rebaseline,
        ShadowCargoTestTargetHostExecution::RebaselinePublished {
            repository_generation: 3,
            trigger: ShadowCargoTestTargetHostRebaseline::GenerationGap,
            ..
        }
    ));
}

fn economically_evidenced_shadow_host_input<'a>(
    fixture: &'a Fixture,
    generation: &'a RepositoryGeneration,
    delta: Option<&'a StateDelta>,
    policy: &'a RefreshEconomicPolicy,
) -> ShadowCargoTestTargetHostInput<'a> {
    ShadowCargoTestTargetHostInput {
        repository_root: &fixture.root,
        generation,
        delta,
        source_selector: "worktree",
        scope: TestTargetInventoryScope::all(),
        metadata_json: &fixture.metadata,
        cargo_version: "cargo 1.90.0",
        platform: "test-platform",
        economic_policy: policy,
        cost_estimate: Some(ShadowRefreshCostEstimate {
            basis: RefreshCostEvidenceBasis::BenchmarkDerived,
            evidence_digest: Digest::blake3(b"shadow-host-cost-evidence"),
            pricing_revision: None,
            estimated_fresh_total_microusd: 1_000,
            estimated_refresh_total_microusd: 200,
            estimated_refresh_latency_micros: Some(15_000),
        }),
        execution_scope_digest: Digest::blake3(b"shadow-host-execution"),
        execution_attempts: &[],
        started_unix_ms: 1,
        observed_refresh_cost_microusd: Some(190),
    }
}

#[test]
fn shadow_executor_publishes_assessed_full_compute_without_refresh_selection() {
    let fixture = Fixture::new();
    let persisted = persisted_shadow_inventory(&fixture);
    mutate_alpha_manifest(&fixture);
    let delta = repository_delta(&persisted.prior, &["crates/alpha/Cargo.toml"], true);
    let policy = shadow_refresh_policy();

    let execution = execute_shadow_cargo_test_target_refresh(
        &persisted.store,
        ShadowCargoTestTargetRefreshExecutionInput {
            request: &persisted.request,
            world: &persisted.world,
            definition_set_digest: Digest::blake3(b"shadow-execution-definitions"),
            prior_inventory: &persisted.prior,
            prior_validation: &persisted.prior_validation,
            prior_manifest: &persisted.prior_manifest,
            prior_artifact: persisted.prior_artifact,
            current: fixture.input(TestTargetInventoryScope::all()),
            state_delta: &delta,
            economic_policy: &policy,
            cost_estimate: Some(ShadowRefreshCostEstimate {
                basis: RefreshCostEvidenceBasis::BenchmarkDerived,
                evidence_digest: Digest::blake3(b"shadow-refresh-too-expensive"),
                pricing_revision: None,
                estimated_fresh_total_microusd: 1_000,
                estimated_refresh_total_microusd: 950,
                estimated_refresh_latency_micros: Some(15_000),
            }),
            execution_scope_digest: Digest::blake3(b"shadow-execution-scope"),
            execution_attempts: &[],
            started_unix_ms: 1,
            observed_refresh_cost_microusd: None,
            head: None,
        },
    )
    .unwrap();

    let ShadowTestTargetRefreshExecution::FullComputePublished {
        publication,
        assessment: Some(assessment),
        ..
    } = execution
    else {
        panic!("an uneconomic refresh must publish the fresh oracle and its assessment");
    };
    assert_eq!(publication.authority, CapabilityMode::Shadow);
    assert!(
        persisted.store.semantic_artifact(&publication.artifact.to_string()).unwrap().is_some()
    );
    let stored = persisted.store.refresh_economic_assessment(assessment).unwrap().unwrap();
    assert_eq!(stored.selected_refresh_attempt, None);
    assert_eq!(stored.assessment.authority, CapabilityMode::Shadow);
}

#[test]
fn shadow_executor_acquisition_fallback_does_not_fabricate_economic_selection() {
    let fixture = Fixture::new();
    let persisted = persisted_shadow_inventory(&fixture);
    let delta = repository_delta(&persisted.prior, &["README.md"], true);
    let policy = shadow_refresh_policy();

    let execution = execute_shadow_cargo_test_target_refresh(
        &persisted.store,
        ShadowCargoTestTargetRefreshExecutionInput {
            request: &persisted.request,
            world: &persisted.world,
            definition_set_digest: Digest::blake3(b"shadow-execution-definitions"),
            prior_inventory: &persisted.prior,
            prior_validation: &persisted.prior_validation,
            prior_manifest: &persisted.prior_manifest,
            prior_artifact: persisted.prior_artifact,
            current: fixture.input(TestTargetInventoryScope::all()),
            state_delta: &delta,
            economic_policy: &policy,
            cost_estimate: Some(ShadowRefreshCostEstimate {
                basis: RefreshCostEvidenceBasis::BenchmarkDerived,
                evidence_digest: Digest::blake3(b"unused-shadow-estimate"),
                pricing_revision: None,
                estimated_fresh_total_microusd: 1_000,
                estimated_refresh_total_microusd: 100,
                estimated_refresh_latency_micros: Some(10_000),
            }),
            execution_scope_digest: Digest::blake3(b"shadow-execution-scope"),
            execution_attempts: &[],
            started_unix_ms: 1,
            observed_refresh_cost_microusd: None,
            head: None,
        },
    )
    .unwrap();

    let ShadowTestTargetRefreshExecution::PriorRemainsCurrent {
        publication,
        trigger: CargoTestTargetRefreshFallback::UnmappedRepositoryChange,
    } = execution
    else {
        panic!("an unmapped no-op must keep the exact prior publication without fake economics");
    };
    assert_eq!(publication.artifact, persisted.prior_artifact);
    assert!(
        persisted.store.semantic_artifact(&publication.artifact.to_string()).unwrap().is_some()
    );
    assert!(persisted.store.refresh_economic_assessments(10).unwrap().is_empty());
}

#[test]
fn typed_refresh_validity_rejection_runs_full_compute_once() {
    let request = inventory_action_request();
    let definition = built_in_action_contracts()
        .iter()
        .find(|definition| definition.contract.id.as_str() == "needle.tests.inventory")
        .unwrap();
    let policy = RefreshEconomicPolicy::new(RefreshEconomicPolicyInput {
        action_operational_policy_digest: definition.contract.operational_policy_digest,
        refresh_policy_definition_digest: test_target_inventory_refresh_definition(),
        minimum_expected_net_microusd: 100,
        maximum_refresh_latency_micros: None,
    })
    .unwrap();
    let fallback_calls = Cell::new(0);
    let resolved = resolve_test_target_inventory_refresh_or_full_compute(
        &request,
        &definition.contract,
        TestTargetInventoryRefreshDecision::FullCompute {
            reason: TestTargetInventoryRefreshFallback::IncompleteDelta,
        },
        &policy,
        None,
        Digest::blake3(b"inventory-refresh-scope"),
        || {
            fallback_calls.set(fallback_calls.get() + 1);
            Ok::<_, Infallible>("fresh")
        },
    )
    .unwrap();
    assert_eq!(fallback_calls.get(), 1);
    assert!(matches!(
        resolved,
        crate::ShadowRefreshResolution::FullCompute {
            result: "fresh",
            trigger: crate::ShadowRefreshFallbackTrigger::CandidateRejected { .. },
            assessment: None,
        }
    ));
}

#[test]
fn shadow_refresh_falls_back_on_incomplete_or_definition_delta() {
    let fixture = Fixture::new();
    let request = inventory_action_request();
    let world = inventory_world();
    let inventory =
        enumerate_cargo_test_targets(fixture.input(TestTargetInventoryScope::all())).unwrap();
    let validation = validate_cargo_test_target_inventory(
        fixture.input(TestTargetInventoryScope::all()),
        &inventory,
    )
    .unwrap();
    let publication = certify_test_target_inventory_shadow_manifest(
        ShadowManifestContext {
            request: &request,
            world: &world,
            definition_set_digest: Digest::blake3(b"definition-set"),
        },
        &inventory,
        &validation,
        1,
    )
    .unwrap();
    let changed_manifest = fixture.root.join("crates/alpha/Cargo.toml");
    let previous = fs::read_to_string(&changed_manifest).unwrap();
    fs::write(&changed_manifest, format!("{previous}\n# changed\n")).unwrap();
    let current =
        enumerate_cargo_test_targets(fixture.input(TestTargetInventoryScope::all())).unwrap();
    let current_validation = validate_cargo_test_target_inventory(
        fixture.input(TestTargetInventoryScope::all()),
        &current,
    )
    .unwrap();
    let current_publication = certify_test_target_inventory_shadow_manifest(
        ShadowManifestContext {
            request: &request,
            world: &world,
            definition_set_digest: Digest::blake3(b"definition-set"),
        },
        &current,
        &current_validation,
        2,
    )
    .unwrap();

    for (complete, definitions, expected) in [
        (false, Vec::new(), TestTargetInventoryRefreshFallback::IncompleteDelta),
        (
            true,
            vec![Digest::blake3(b"changed-definition")],
            TestTargetInventoryRefreshFallback::ChangedDefinitions,
        ),
    ] {
        let delta = StateDelta::new(
            inventory.repository_lineage,
            RepositoryContextId::new(Digest::blake3(b"worktree")),
            1,
            2,
            vec![DependencyLocator::repository_path("crates/alpha/Cargo.toml").unwrap()],
            Vec::new(),
            definitions,
            Vec::new(),
            complete,
        )
        .unwrap();
        let decision = evaluate_test_target_inventory_refresh(TestTargetInventoryRefreshInput {
            prior_inventory: &inventory,
            prior_validation: &validation,
            prior_publication: &publication,
            current_inventory: &current,
            current_validation: &current_validation,
            current_publication: &current_publication,
            state_delta: &delta,
        })
        .unwrap();
        assert_eq!(decision, TestTargetInventoryRefreshDecision::FullCompute { reason: expected });
    }
}

#[test]
fn targeted_cargo_refresh_acquisition_matches_fresh_oracle() {
    let fixture = Fixture::new();
    let prior =
        enumerate_cargo_test_targets(fixture.input(TestTargetInventoryScope::all())).unwrap();
    let prior_validation = validate_cargo_test_target_inventory(
        fixture.input(TestTargetInventoryScope::all()),
        &prior,
    )
    .unwrap();
    let manifest = fixture.root.join("crates/alpha/Cargo.toml");
    let previous = fs::read_to_string(&manifest).unwrap();
    fs::write(&manifest, format!("{previous}\n# targeted refresh\n")).unwrap();
    let delta = repository_delta(&prior, &["crates/alpha/Cargo.toml"], true);

    let oracle =
        enumerate_cargo_test_targets(fixture.input(TestTargetInventoryScope::all())).unwrap();
    let oracle_validation = validate_cargo_test_target_inventory(
        fixture.input(TestTargetInventoryScope::all()),
        &oracle,
    )
    .unwrap();
    let acquisition = acquire_cargo_test_target_refresh_candidate(CargoTestTargetRefreshInput {
        current: fixture.input(TestTargetInventoryScope::all()),
        prior_inventory: &prior,
        prior_validation: &prior_validation,
        state_delta: &delta,
    })
    .unwrap();
    let CargoTestTargetRefreshAcquisition::Candidate { result } = acquisition else {
        panic!("one changed package and one retained package must be refreshable");
    };
    assert_eq!(result.inventory, oracle);
    assert_eq!(result.validation_certificate, oracle_validation);
    assert_eq!(result.retained_partitions, 1);
    assert_eq!(result.recomputed_partitions, 3);
}

#[test]
fn targeted_cargo_refresh_handles_an_added_explicit_target() {
    let fixture = Fixture::new();
    let prior =
        enumerate_cargo_test_targets(fixture.input(TestTargetInventoryScope::all())).unwrap();
    let prior_validation = validate_cargo_test_target_inventory(
        fixture.input(TestTargetInventoryScope::all()),
        &prior,
    )
    .unwrap();
    let request = inventory_action_request();
    let world = inventory_world();
    let prior_publication = certify_test_target_inventory_shadow_manifest(
        ShadowManifestContext {
            request: &request,
            world: &world,
            definition_set_digest: Digest::blake3(b"targeted-definition-set"),
        },
        &prior,
        &prior_validation,
        1,
    )
    .unwrap();
    let manifest = fixture.root.join("crates/alpha/Cargo.toml");
    let previous = fs::read_to_string(&manifest).unwrap();
    fs::write(
        &manifest,
        format!("{previous}\n[[test]]\nname = \"added\"\npath = \"tests/added.rs\"\n"),
    )
    .unwrap();
    fs::write(fixture.root.join("crates/alpha/tests/added.rs"), "#[test] fn added() {}\n").unwrap();
    let mut metadata: serde_json::Value = serde_json::from_slice(&fixture.metadata).unwrap();
    metadata["packages"][0]["targets"].as_array_mut().unwrap().push(json!({
        "name": "added",
        "kind": ["test"],
        "crate_types": ["bin"],
        "required-features": [],
        "src_path": fixture.root.join("crates/alpha/tests/added.rs"),
        "edition": "2024",
        "test": true,
        "doctest": false,
    }));
    let metadata = serde_json::to_vec(&metadata).unwrap();
    let mut current_input = fixture.input(TestTargetInventoryScope::all());
    current_input.metadata_json = &metadata;
    let delta =
        repository_delta(&prior, &["crates/alpha/Cargo.toml", "crates/alpha/tests/added.rs"], true);
    let oracle = enumerate_cargo_test_targets(CargoTestTargetInventoryInput {
        metadata_json: &metadata,
        ..fixture.input(TestTargetInventoryScope::all())
    })
    .unwrap();
    let acquisition = acquire_cargo_test_target_refresh_candidate(CargoTestTargetRefreshInput {
        current: current_input,
        prior_inventory: &prior,
        prior_validation: &prior_validation,
        state_delta: &delta,
    })
    .unwrap();
    let CargoTestTargetRefreshAcquisition::Candidate { result } = acquisition else {
        panic!("an explicit target addition must refresh only its package");
    };
    assert_eq!(result.inventory, oracle);
    assert_eq!(result.retained_partitions, 1);
    assert_eq!(result.recomputed_partitions, 4);
    let current_publication = certify_test_target_inventory_shadow_manifest(
        ShadowManifestContext {
            request: &request,
            world: &world,
            definition_set_digest: Digest::blake3(b"targeted-definition-set"),
        },
        &result.inventory,
        &result.validation_certificate,
        2,
    )
    .unwrap();
    let decision = evaluate_test_target_inventory_refresh(TestTargetInventoryRefreshInput {
        prior_inventory: &prior,
        prior_validation: &prior_validation,
        prior_publication: &prior_publication,
        current_inventory: &result.inventory,
        current_validation: &result.validation_certificate,
        current_publication: &current_publication,
        state_delta: &delta,
    })
    .unwrap();
    let TestTargetInventoryRefreshDecision::Refresh { result } = decision else {
        panic!("target-scoped metadata must keep the unchanged package retainable");
    };
    assert_eq!(result.plan.retained.len(), 1);
    assert_eq!(result.plan.refreshed.len(), 3);
    assert_eq!(result.plan.added.len(), 1);
}

#[test]
fn targeted_cargo_refresh_falls_back_for_unmapped_or_unexplained_changes() {
    let fixture = Fixture::new();
    let prior =
        enumerate_cargo_test_targets(fixture.input(TestTargetInventoryScope::all())).unwrap();
    let prior_validation = validate_cargo_test_target_inventory(
        fixture.input(TestTargetInventoryScope::all()),
        &prior,
    )
    .unwrap();
    let unknown_delta = repository_delta(&prior, &["README.md"], true);
    assert_eq!(
        acquire_cargo_test_target_refresh_candidate(CargoTestTargetRefreshInput {
            current: fixture.input(TestTargetInventoryScope::all()),
            prior_inventory: &prior,
            prior_validation: &prior_validation,
            state_delta: &unknown_delta,
        })
        .unwrap(),
        CargoTestTargetRefreshAcquisition::FullCompute {
            reason: CargoTestTargetRefreshFallback::UnmappedRepositoryChange,
        }
    );

    let mut metadata: serde_json::Value = serde_json::from_slice(&fixture.metadata).unwrap();
    metadata["packages"][0]["targets"][0]["edition"] = json!("2021");
    let metadata = serde_json::to_vec(&metadata).unwrap();
    let empty_delta = repository_delta(&prior, &[], true);
    assert_eq!(
        acquire_cargo_test_target_refresh_candidate(CargoTestTargetRefreshInput {
            current: CargoTestTargetInventoryInput {
                metadata_json: &metadata,
                ..fixture.input(TestTargetInventoryScope::all())
            },
            prior_inventory: &prior,
            prior_validation: &prior_validation,
            state_delta: &empty_delta,
        })
        .unwrap(),
        CargoTestTargetRefreshAcquisition::FullCompute {
            reason: CargoTestTargetRefreshFallback::MetadataWithoutDelta,
        }
    );
}

fn repository_delta(
    inventory: &needle_core::TestTargetInventory,
    paths: &[&str],
    complete: bool,
) -> StateDelta {
    StateDelta::new(
        inventory.repository_lineage,
        RepositoryContextId::new(Digest::blake3(b"targeted-refresh-worktree")),
        1,
        2,
        paths.iter().map(|path| DependencyLocator::repository_path(path).unwrap()).collect(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        complete,
    )
    .unwrap()
}

fn inventory_action_request() -> ActionRequest {
    let definition = built_in_action_contracts()
        .iter()
        .find(|definition| definition.contract.id.as_str() == "needle.tests.inventory")
        .unwrap();
    let fragment = NeedFragmentId::new(Digest::blake3(b"inventory-refresh-fragment"));
    let route = NeedKey::new("needle.tests.inventory").unwrap();
    ActionRequest::new(
        &definition.contract,
        ArtifactRequest {
            contract_id: definition.output_contract_id.to_owned(),
            contract_revision: definition.output_contract_revision,
            repository_id: Digest::blake3(b"repository"),
            source_snapshot_digest: Digest::blake3(b"worktree"),
            route_key: route.clone(),
            normalized_request: "enumerate test targets".to_owned(),
            semantic_fragment_id: Some(fragment),
            input_artifact_ids: Vec::new(),
        },
        definition.contract.default_dispatch_policy,
        route,
        NeedId::new(fragment.digest()),
    )
    .unwrap()
}

fn inventory_world() -> SemanticWorld {
    SemanticWorld {
        repository_lineage: Digest::blake3(b"repository"),
        source_selector: "worktree".to_owned(),
        platform: "any".to_owned(),
        features: "default".to_owned(),
        configuration: None,
        toolchain: None,
    }
}
