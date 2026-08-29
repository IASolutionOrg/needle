use needle_core::{
    ActionContractId, ArtifactRequestId, CapabilityMode, CoverageManifest, Digest, ManifestBinding,
    ManifestClosure, ManifestClosurePolicy, ManifestProvenance, OpaquePartitionKey, PartitionEntry,
    PartitionKeyScope, PartitionManifest, PartitionManifestValidationCertificate,
    PartitionOverlapPolicy, PartitionPolicy, PartitionPolicyId, PartitionRef, PartitionRole,
    PartitionScheme, PartitionSchemeId, PartitionSchemeKind, ProviderId, SchemaId, SemanticWorld,
    ValidatorId, semantic_input_set_digest, validate_partition_assembly,
    validate_partition_projection,
};
use serde::Serialize;
use std::alloc::{GlobalAlloc, Layout, System};
use std::env;
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const ENTRY_COUNT: usize = 128;
const SELECTED_COUNT: usize = 32;
const ITERATIONS: usize = 1_000;
const DECODE_ITERATIONS: usize = 250;
const DEFAULT_P95_BUDGET_MS: u64 = 10;

struct CountingAllocator;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);

// SAFETY: every allocation operation delegates to System with the exact
// pointer/Layout contract it received. Atomics only observe aggregate counts.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        ALLOCATED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        // SAFETY: delegated with the caller-provided valid Layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        ALLOCATED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        // SAFETY: delegated with the caller-provided valid Layout.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: delegated with the original pointer and Layout.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, old: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        ALLOCATED_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        // SAFETY: delegated with the caller-provided pointer, Layout and size.
        unsafe { System.realloc(pointer, old, new_size) }
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

#[derive(Serialize)]
struct Observation {
    name: &'static str,
    iterations: usize,
    median_ns: u128,
    p95_ns: u128,
    allocations: u64,
    allocated_bytes: u64,
}

fn main() -> Result<(), String> {
    let fixture = fixture()?;
    let manifest_json = serde_json::to_vec(&fixture.manifest).map_err(|error| error.to_string())?;
    let certificate_json =
        serde_json::to_vec(&fixture.certificate).map_err(|error| error.to_string())?;

    for _ in 0..50 {
        fixture
            .certificate
            .validate_against_manifest(&fixture.manifest, &fixture.scheme, &fixture.policy)
            .map_err(|error| error.to_string())?;
        validate_partition_projection(
            &fixture.policy,
            &fixture.scheme,
            &fixture.manifest,
            &fixture.binding,
            &fixture.selected,
        )
        .map_err(|error| error.to_string())?;
    }

    let observations = vec![
        measure("certificate_validation", ITERATIONS, || {
            fixture.certificate.validate_against_manifest(
                &fixture.manifest,
                &fixture.scheme,
                &fixture.policy,
            )
        })?,
        measure("partition_projection", ITERATIONS, || {
            validate_partition_projection(
                &fixture.policy,
                &fixture.scheme,
                &fixture.manifest,
                &fixture.binding,
                &fixture.selected,
            )
        })?,
        measure("same_manifest_assembly", ITERATIONS, || {
            validate_partition_assembly(
                &fixture.policy,
                &fixture.scheme,
                &[&fixture.manifest],
                &fixture.binding,
                &fixture.selected,
                None,
            )
        })?,
        measure("manifest_decode", DECODE_ITERATIONS, || {
            PartitionManifest::decode_json(&manifest_json, &fixture.scheme).map(|_| ())
        })?,
        measure("certificate_decode", DECODE_ITERATIONS, || {
            PartitionManifestValidationCertificate::decode_json(&certificate_json).map(|_| ())
        })?,
    ];
    let budget_ms = env::var("NEEDLE_PHASE6A_MANIFEST_P95_BUDGET_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_P95_BUDGET_MS);
    let budget_ns = u128::from(budget_ms) * 1_000_000;
    let passed = observations.iter().all(|observation| observation.p95_ns <= budget_ns);
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "needle.partition-manifest-microbench/1",
            "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
            "classification": "offline-language-agnostic-shadow",
            "manifest_entries": ENTRY_COUNT,
            "selected_partitions": SELECTED_COUNT,
            "manifest_bytes": manifest_json.len(),
            "certificate_bytes": certificate_json.len(),
            "p95_budget_ms": budget_ms,
            "observations": observations,
            "authority": CapabilityMode::Shadow,
            "passed": passed,
        }))
        .map_err(|error| error.to_string())?
    );
    if !passed {
        return Err(format!(
            "one or more manifest operations exceeded the {budget_ms} ms p95 budget"
        ));
    }
    Ok(())
}

struct Fixture {
    scheme: PartitionScheme,
    policy: PartitionPolicy,
    binding: ManifestBinding,
    manifest: PartitionManifest,
    certificate: PartitionManifestValidationCertificate,
    selected: Vec<PartitionRef>,
}

fn fixture() -> Result<Fixture, String> {
    let scheme = PartitionScheme::new(
        PartitionSchemeId::new("benchmark.opaque.partition").map_err(string_error)?,
        PartitionSchemeKind::ProviderDefined {
            provider: ProviderId::new("benchmark.external-provider").map_err(string_error)?,
        },
        PartitionKeyScope::ProviderStable,
        SchemaId::new("benchmark.opaque-key.v1").map_err(string_error)?,
        32,
    )
    .map_err(string_error)?;
    let policy = PartitionPolicy::new(
        PartitionPolicyId::new("benchmark.partition-policy").map_err(string_error)?,
        vec![scheme.id.clone()],
        ValidatorId::new("benchmark.partition-validator.v1").map_err(string_error)?,
        ENTRY_COUNT.try_into().map_err(|_| "entry count exceeds u16".to_owned())?,
        needle_core::MAX_PARTITION_MANIFEST_WIRE_BYTES as u32,
        PartitionOverlapPolicy::ValidatorDefined,
        ManifestClosurePolicy::ClosedRequired,
    )
    .map_err(string_error)?;
    let repository = digest("repository");
    let world = SemanticWorld {
        repository_lineage: repository,
        source_selector: "benchmark-snapshot".to_owned(),
        platform: "any".to_owned(),
        features: "default".to_owned(),
        configuration: None,
        toolchain: None,
    };
    let request = ArtifactRequestId::new(digest("action-request"));
    let binding = ManifestBinding::new(
        request,
        ActionContractId::new("benchmark.partition-action").map_err(string_error)?,
        "benchmark.partition-output",
        semantic_input_set_digest(&[]).map_err(string_error)?,
        world.id(),
        repository,
        &world.source_selector,
        digest("definition-set"),
    )
    .map_err(string_error)?;
    let entries = (0..ENTRY_COUNT)
        .map(|index| {
            let dependency = digest(format!("dependency-{index}"));
            PartitionEntry::new(
                OpaquePartitionKey::new(
                    &scheme,
                    digest(format!("opaque-key-{index}")).bytes().to_vec(),
                    None,
                )?,
                PartitionRole::Component,
                digest(format!("payload-{index}")),
                CoverageManifest {
                    entries: Vec::new(),
                    world: world.clone(),
                    dependency_manifest_digest: dependency,
                },
                dependency,
                Vec::new(),
                Vec::new(),
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(string_error)?;
    let manifest = PartitionManifest::new(
        &scheme,
        binding.clone(),
        ManifestProvenance::RequestBound { request },
        ManifestClosure::Closed,
        entries,
        None,
    )
    .map_err(string_error)?;
    let certificate = PartitionManifestValidationCertificate::new(
        &manifest,
        &scheme,
        &policy,
        digest("declared-policy-authority"),
        digest("validator-definition"),
        digest("adapter-definition"),
        digest("source-payload"),
        digest("source-validation-certificate"),
        42,
    )
    .map_err(string_error)?;
    let selected = manifest
        .entries
        .iter()
        .take(SELECTED_COUNT)
        .map(|entry| PartitionRef::new(manifest.id, entry.key.digest))
        .collect();
    Ok(Fixture { scheme, policy, binding, manifest, certificate, selected })
}

fn measure<E>(
    name: &'static str,
    iterations: usize,
    mut operation: impl FnMut() -> Result<(), E>,
) -> Result<Observation, String>
where
    E: ToString,
{
    let mut durations = Vec::with_capacity(iterations);
    ALLOCATIONS.store(0, Ordering::Relaxed);
    ALLOCATED_BYTES.store(0, Ordering::Relaxed);
    for _ in 0..iterations {
        let started = Instant::now();
        black_box(operation().map_err(|error| error.to_string())?);
        durations.push(started.elapsed().as_nanos());
    }
    let allocations = ALLOCATIONS.load(Ordering::Relaxed);
    let allocated_bytes = ALLOCATED_BYTES.load(Ordering::Relaxed);
    durations.sort_unstable();
    let p95_index = (iterations * 95).div_ceil(100).saturating_sub(1).min(iterations - 1);
    Ok(Observation {
        name,
        iterations,
        median_ns: durations[iterations / 2],
        p95_ns: durations[p95_index],
        allocations,
        allocated_bytes,
    })
}

fn digest(value: impl AsRef<[u8]>) -> Digest {
    Digest::blake3(value)
}

fn string_error(error: impl ToString) -> String {
    error.to_string()
}
