use needle_core::{
    ActionRequest, ArtifactRequest, DependencyLocator, Digest, NeedFragmentId, NeedId, NeedKey,
    RepositoryContextId, SemanticWorld, StateDelta, TestTargetInventoryScope,
};
use needle_runtime::{
    CargoTestTargetInventoryInput, CargoTestTargetRefreshAcquisition, CargoTestTargetRefreshInput,
    ShadowManifestContext, TestTargetInventoryRefreshDecision, TestTargetInventoryRefreshInput,
    acquire_cargo_test_target_refresh_candidate, built_in_action_contracts,
    certify_test_target_inventory_shadow_manifest, enumerate_cargo_test_targets,
    evaluate_test_target_inventory_refresh, validate_cargo_test_target_inventory,
};
use serde_json::json;
use std::env;
use std::fs;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const PACKAGE_COUNT: usize = 64;
const SAMPLES: usize = 40;
const DEFAULT_P95_BUDGET_MS: f64 = 250.0;

fn main() -> Result<(), String> {
    let fixture = Fixture::new(PACKAGE_COUNT)?;
    let repository = Digest::blake3(b"phase6b-refresh-benchmark-repository");
    let source = "benchmark-worktree";
    let request = action_request(repository, source)?;
    let world = semantic_world(repository, source);
    let definition_set = Digest::blake3(b"phase6b-refresh-definition-set");

    let prior = enumerate(&fixture, repository, source)?;
    let prior_validation = validate(&fixture, repository, source, &prior)?;
    let prior_publication = certify_test_target_inventory_shadow_manifest(
        ShadowManifestContext {
            request: &request,
            world: &world,
            definition_set_digest: definition_set,
        },
        &prior,
        &prior_validation,
        1,
    )
    .map_err(|error| error.to_string())?;

    fixture.mutate_first_package()?;
    let delta = StateDelta::new(
        repository,
        RepositoryContextId::new(Digest::blake3(b"phase6b-refresh-worktree")),
        1,
        2,
        vec![
            DependencyLocator::repository_path("crates/pkg000/Cargo.toml")
                .map_err(|error| error.to_string())?,
        ],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        true,
    )
    .map_err(|error| error.to_string())?;

    let current = enumerate(&fixture, repository, source)?;
    let current_validation = validate(&fixture, repository, source, &current)?;
    let current_publication = certify_test_target_inventory_shadow_manifest(
        ShadowManifestContext {
            request: &request,
            world: &world,
            definition_set_digest: definition_set,
        },
        &current,
        &current_validation,
        2,
    )
    .map_err(|error| error.to_string())?;
    let acquired = acquire(&fixture, repository, source, &prior, &prior_validation, &delta)?;
    if acquired.inventory != current || acquired.validation_certificate != current_validation {
        return Err("targeted acquisition differs from the fresh deterministic oracle".to_owned());
    }

    let mut enumeration_samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        black_box(enumerate(&fixture, repository, source)?);
        enumeration_samples.push(elapsed_nanos(started));
    }
    let mut validation_samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        black_box(validate(&fixture, repository, source, &current)?);
        validation_samples.push(elapsed_nanos(started));
    }
    let mut acquisition_samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        black_box(acquire(&fixture, repository, source, &prior, &prior_validation, &delta)?);
        acquisition_samples.push(elapsed_nanos(started));
    }
    let mut certification_samples = Vec::with_capacity(SAMPLES * 10);
    for _ in 0..(SAMPLES * 10) {
        let started = Instant::now();
        black_box(
            certify_test_target_inventory_shadow_manifest(
                ShadowManifestContext {
                    request: &request,
                    world: &world,
                    definition_set_digest: definition_set,
                },
                &current,
                &current_validation,
                2,
            )
            .map_err(|error| error.to_string())?,
        );
        certification_samples.push(elapsed_nanos(started));
    }

    let mut operator_samples = Vec::with_capacity(SAMPLES * 10);
    let mut retained = 0;
    let mut refreshed = 0;
    for _ in 0..(SAMPLES * 10) {
        let started = Instant::now();
        let decision = evaluate_test_target_inventory_refresh(TestTargetInventoryRefreshInput {
            prior_inventory: &prior,
            prior_validation: &prior_validation,
            prior_publication: &prior_publication,
            current_inventory: &current,
            current_validation: &current_validation,
            current_publication: &current_publication,
            state_delta: &delta,
        })
        .map_err(|error| error.to_string())?;
        operator_samples.push(elapsed_nanos(started));
        let TestTargetInventoryRefreshDecision::Refresh { result } = decision else {
            return Err("synthetic mutation unexpectedly fell back to full compute".to_owned());
        };
        retained = result.plan.retained.len();
        refreshed = result.plan.refreshed.len() + result.plan.added.len();
        if result.reconstructed != current || result.fresh_oracle_digest != current.content_digest {
            return Err("refresh result differs from the fresh oracle".to_owned());
        }
        black_box(result);
    }

    let measure_fresh = || -> Result<u64, String> {
        let started = Instant::now();
        let inventory = enumerate(&fixture, repository, source)?;
        let certificate = validate(&fixture, repository, source, &inventory)?;
        black_box((inventory, certificate));
        Ok(elapsed_nanos(started))
    };
    let measure_refresh = || -> Result<u64, String> {
        let started = Instant::now();
        let candidate = acquire(&fixture, repository, source, &prior, &prior_validation, &delta)?;
        let candidate_publication = certify_test_target_inventory_shadow_manifest(
            ShadowManifestContext {
                request: &request,
                world: &world,
                definition_set_digest: definition_set,
            },
            &candidate.inventory,
            &candidate.validation_certificate,
            2,
        )
        .map_err(|error| error.to_string())?;
        let decision = evaluate_test_target_inventory_refresh(TestTargetInventoryRefreshInput {
            prior_inventory: &prior,
            prior_validation: &prior_validation,
            prior_publication: &prior_publication,
            current_inventory: &candidate.inventory,
            current_validation: &candidate.validation_certificate,
            current_publication: &candidate_publication,
            state_delta: &delta,
        })
        .map_err(|error| error.to_string())?;
        black_box(decision);
        Ok(elapsed_nanos(started))
    };
    let mut fresh_samples = Vec::with_capacity(SAMPLES);
    let mut end_to_end_samples = Vec::with_capacity(SAMPLES);
    for sample in 0..SAMPLES {
        if sample % 2 == 0 {
            fresh_samples.push(measure_fresh()?);
            end_to_end_samples.push(measure_refresh()?);
        } else {
            end_to_end_samples.push(measure_refresh()?);
            fresh_samples.push(measure_fresh()?);
        }
    }

    let fresh_p50 = percentile(&mut fresh_samples, 50);
    let fresh_p95 = percentile(&mut fresh_samples, 95);
    let enumeration_p50 = percentile(&mut enumeration_samples, 50);
    let enumeration_p95 = percentile(&mut enumeration_samples, 95);
    let validation_p50 = percentile(&mut validation_samples, 50);
    let validation_p95 = percentile(&mut validation_samples, 95);
    let acquisition_p50 = percentile(&mut acquisition_samples, 50);
    let acquisition_p95 = percentile(&mut acquisition_samples, 95);
    let certification_p50 = percentile(&mut certification_samples, 50);
    let certification_p95 = percentile(&mut certification_samples, 95);
    let operator_p50 = percentile(&mut operator_samples, 50);
    let operator_p95 = percentile(&mut operator_samples, 95);
    let end_to_end_p50 = percentile(&mut end_to_end_samples, 50);
    let end_to_end_p95 = percentile(&mut end_to_end_samples, 95);
    let positive_net_value = end_to_end_p95 < fresh_p95;
    let selected_plan = if positive_net_value { "refresh" } else { "full_compute" };
    let budget_ms = env::var("NEEDLE_PHASE6B_REFRESH_P95_BUDGET_MS")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(DEFAULT_P95_BUDGET_MS);
    let bounded_p95 = nanos_to_ms(end_to_end_p95) <= budget_ms;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "needle.test-target-inventory-refresh-microbench/2",
            "classification": "offline-synthetic-provider-input",
            "authority": "shadow",
            "packages": PACKAGE_COUNT,
            "targets": current.partitions.len(),
            "retained_partitions": retained,
            "recomputed_partitions": refreshed,
            "retained_ratio": retained as f64 / current.partitions.len() as f64,
            "samples": {
                "fresh_compute": SAMPLES,
                "enumeration": SAMPLES,
                "validation": SAMPLES,
                "targeted_current_acquisition": SAMPLES,
                "manifest_certification": SAMPLES * 10,
                "refresh_operator": SAMPLES * 10,
                "refresh_end_to_end": SAMPLES,
            },
            "p50_nanos": {
                "fresh_compute": fresh_p50,
                "enumeration": enumeration_p50,
                "validation": validation_p50,
                "targeted_current_acquisition": acquisition_p50,
                "manifest_certification": certification_p50,
                "refresh_operator": operator_p50,
                "refresh_end_to_end": end_to_end_p50,
            },
            "p95_nanos": {
                "fresh_compute": fresh_p95,
                "enumeration": enumeration_p95,
                "validation": validation_p95,
                "targeted_current_acquisition": acquisition_p95,
                "manifest_certification": certification_p95,
                "refresh_operator": operator_p95,
                "refresh_end_to_end": end_to_end_p95,
            },
            "fresh_oracle_agreement": true,
            "targeted_acquisition_oracle_agreement": true,
            "stale_retained_partitions": 0,
            "current_manifest_acquisition_included": true,
            "full_current_oracle_outside_refresh_timing": true,
            "provider_process_transport_included": false,
            "positive_net_refresh_value": positive_net_value,
            "selected_plan": selected_plan,
            "p95_budget_ms": budget_ms,
            "bounded_p95": bounded_p95,
            "gate_a4_eligible": positive_net_value && bounded_p95,
        }))
        .map_err(|error| error.to_string())?
    );
    if !bounded_p95 {
        return Err(format!(
            "refresh end-to-end p95 {:.3} ms exceeds the {:.3} ms budget",
            nanos_to_ms(end_to_end_p95),
            budget_ms
        ));
    }
    Ok(())
}

fn enumerate(
    fixture: &Fixture,
    repository: Digest,
    source: &str,
) -> Result<needle_core::TestTargetInventory, String> {
    enumerate_cargo_test_targets(fixture.input(repository, source))
        .map_err(|error| error.to_string())
}

fn validate(
    fixture: &Fixture,
    repository: Digest,
    source: &str,
    inventory: &needle_core::TestTargetInventory,
) -> Result<needle_runtime::TestTargetInventoryValidationCertificate, String> {
    validate_cargo_test_target_inventory(fixture.input(repository, source), inventory)
        .map_err(|error| error.to_string())
}

fn acquire(
    fixture: &Fixture,
    repository: Digest,
    source: &str,
    prior: &needle_core::TestTargetInventory,
    prior_validation: &needle_runtime::TestTargetInventoryValidationCertificate,
    delta: &StateDelta,
) -> Result<needle_runtime::CargoTestTargetRefreshCandidate, String> {
    let acquisition = acquire_cargo_test_target_refresh_candidate(CargoTestTargetRefreshInput {
        current: fixture.input(repository, source),
        prior_inventory: prior,
        prior_validation,
        state_delta: delta,
    })
    .map_err(|error| error.to_string())?;
    let CargoTestTargetRefreshAcquisition::Candidate { result } = acquisition else {
        return Err("targeted acquisition unexpectedly selected full compute".to_owned());
    };
    Ok(*result)
}

fn action_request(repository: Digest, source: &str) -> Result<ActionRequest, String> {
    let definition = built_in_action_contracts()
        .iter()
        .find(|definition| definition.contract.id.as_str() == "needle.tests.inventory")
        .ok_or_else(|| "test-target inventory action is missing".to_owned())?;
    let fragment = NeedFragmentId::new(Digest::blake3(b"phase6b-refresh-fragment"));
    let route = NeedKey::new("needle.tests.inventory").map_err(|error| error.to_string())?;
    ActionRequest::new(
        &definition.contract,
        ArtifactRequest {
            contract_id: definition.output_contract_id.to_owned(),
            contract_revision: definition.output_contract_revision,
            repository_id: repository,
            source_snapshot_digest: Digest::blake3(source.as_bytes()),
            route_key: route.clone(),
            normalized_request: "enumerate Cargo test targets".to_owned(),
            semantic_fragment_id: Some(fragment),
            input_artifact_ids: Vec::new(),
        },
        definition.contract.default_dispatch_policy,
        route,
        NeedId::new(fragment.digest()),
    )
    .map_err(|error| error.to_string())
}

fn semantic_world(repository: Digest, source: &str) -> SemanticWorld {
    SemanticWorld {
        repository_lineage: repository,
        source_selector: source.to_owned(),
        platform: "any".to_owned(),
        features: "default".to_owned(),
        configuration: None,
        toolchain: None,
    }
}

struct Fixture {
    root: PathBuf,
    metadata: Vec<u8>,
}

impl Fixture {
    fn new(packages: usize) -> Result<Self, String> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos();
        let root =
            env::temp_dir().join(format!("needle-phase6b-refresh-{}-{nonce}", std::process::id()));
        fs::create_dir_all(root.join("crates")).map_err(|error| error.to_string())?;
        fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = [\"crates/*\"]\n")
            .map_err(|error| error.to_string())?;
        let mut package_values = Vec::with_capacity(packages);
        let mut member_ids = Vec::with_capacity(packages);
        for index in 0..packages {
            let name = format!("pkg{index:03}");
            let package_root = root.join("crates").join(&name);
            fs::create_dir_all(package_root.join("src")).map_err(|error| error.to_string())?;
            fs::write(
                package_root.join("Cargo.toml"),
                format!(
                    "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lib]\npath = \"src/lib.rs\"\n"
                ),
            )
            .map_err(|error| error.to_string())?;
            fs::write(package_root.join("src/lib.rs"), "pub fn target() {}\n")
                .map_err(|error| error.to_string())?;
            let id = format!("path+file:///phase6b/{name}#0.1.0");
            member_ids.push(id.clone());
            package_values.push(json!({
                "id": id,
                "name": name,
                "manifest_path": package_root.join("Cargo.toml"),
                "targets": [{
                    "name": format!("pkg{index:03}"),
                    "kind": ["lib"],
                    "crate_types": ["lib"],
                    "required_features": [],
                    "src_path": package_root.join("src/lib.rs"),
                    "edition": "2024",
                    "test": true,
                    "doctest": true,
                }]
            }));
        }
        let metadata = serde_json::to_vec(&json!({
            "packages": package_values,
            "workspace_members": member_ids,
            "workspace_root": root,
        }))
        .map_err(|error| error.to_string())?;
        Ok(Self { root, metadata })
    }

    fn input<'a>(
        &'a self,
        repository: Digest,
        source: &'a str,
    ) -> CargoTestTargetInventoryInput<'a> {
        CargoTestTargetInventoryInput {
            repository_root: &self.root,
            repository_lineage: repository,
            source_selector: source,
            scope: TestTargetInventoryScope::all(),
            metadata_json: &self.metadata,
            cargo_version: "cargo 1.90.0",
        }
    }

    fn mutate_first_package(&self) -> Result<(), String> {
        let path = self.root.join("crates/pkg000/Cargo.toml");
        let current = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        fs::write(path, format!("{current}\n# adjacent generation\n"))
            .map_err(|error| error.to_string())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn elapsed_nanos(started: Instant) -> u64 {
    started.elapsed().as_nanos().try_into().unwrap_or(u64::MAX)
}

fn percentile(values: &mut [u64], percentile: usize) -> u64 {
    values.sort_unstable();
    let index = (values.len() - 1) * percentile / 100;
    values[index]
}

fn nanos_to_ms(value: u64) -> f64 {
    value as f64 / 1_000_000.0
}
