use needle_core::{Digest, TestTargetInventoryScope};
use needle_runtime::{
    CargoTestTargetInventoryInput, MAX_CARGO_METADATA_INPUT_BYTES,
    assemble_test_target_inventories, enumerate_cargo_test_targets, project_test_target_inventory,
};
use serde_json::json;
use std::env;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

const FRESH_SAMPLES: usize = 25;
const PROJECTION_SAMPLES: usize = 2_000;
const ASSEMBLY_SAMPLES: usize = 500;

fn main() -> Result<(), String> {
    let root = repository_argument()?;
    let metadata = bounded_cargo_stdout(
        &root,
        &["metadata", "--no-deps", "--format-version", "1"],
        MAX_CARGO_METADATA_INPUT_BYTES,
    )?;
    let cargo_version = String::from_utf8(bounded_cargo_stdout(&root, &["--version"], 256)?)
        .map_err(|error| error.to_string())?;
    let cargo_version = cargo_version.trim();
    let repository_lineage = Digest::blake3(root.to_string_lossy().as_bytes());
    let enumerate = || {
        enumerate_cargo_test_targets(CargoTestTargetInventoryInput {
            repository_root: &root,
            repository_lineage,
            source_selector: "benchmark-worktree",
            scope: TestTargetInventoryScope::all(),
            metadata_json: &metadata,
            cargo_version,
        })
        .map_err(|error| error.to_string())
    };

    let mut fresh_nanos = Vec::with_capacity(FRESH_SAMPLES);
    let mut full = None;
    for _ in 0..FRESH_SAMPLES {
        let started = Instant::now();
        let inventory = enumerate()?;
        fresh_nanos.push(elapsed_nanos(started));
        full = Some(inventory);
    }
    let full = full.expect("fresh sample count is non-zero");
    let package = full
        .package_universe
        .first()
        .cloned()
        .ok_or_else(|| "workspace contains no Cargo packages".to_owned())?;
    let package_scope = TestTargetInventoryScope::new(vec![package], Vec::new(), Vec::new())
        .map_err(|error| error.to_string())?;
    let mut projection_nanos = Vec::with_capacity(PROJECTION_SAMPLES);
    for _ in 0..PROJECTION_SAMPLES {
        let started = Instant::now();
        let projection = project_test_target_inventory(&full, package_scope.clone())
            .map_err(|error| error.to_string())?;
        std::hint::black_box(projection);
        projection_nanos.push(elapsed_nanos(started));
    }

    let package_slices = full
        .package_universe
        .iter()
        .cloned()
        .map(|package| {
            let scope = TestTargetInventoryScope::new(vec![package], Vec::new(), Vec::new())
                .map_err(|error| error.to_string())?;
            project_test_target_inventory(&full, scope).map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut assembly_nanos = Vec::new();
    if package_slices.len() >= 2 {
        assembly_nanos.reserve(ASSEMBLY_SAMPLES);
        for _ in 0..ASSEMBLY_SAMPLES {
            let started = Instant::now();
            let assembled =
                assemble_test_target_inventories(&package_slices, TestTargetInventoryScope::all())
                    .map_err(|error| error.to_string())?;
            std::hint::black_box(assembled);
            assembly_nanos.push(elapsed_nanos(started));
        }
    }

    let fresh_p50 = median(&mut fresh_nanos);
    let projection_p50 = median(&mut projection_nanos);
    let assembly_p50 = (!assembly_nanos.is_empty()).then(|| median(&mut assembly_nanos));
    let positive_net_value =
        projection_p50 < fresh_p50 && assembly_p50.is_none_or(|assembly| assembly < fresh_p50);
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "needle.test-target-inventory-microbench/1",
            "classification": "offline-local-mechanical",
            "repository": root,
            "packages": full.package_universe.len(),
            "test_targets": full.partitions.len(),
            "metadata_bytes": metadata.len(),
            "samples": {
                "fresh": FRESH_SAMPLES,
                "projection": PROJECTION_SAMPLES,
                "assembly": assembly_nanos.len(),
            },
            "p50_nanos": {
                "fresh": fresh_p50,
                "projection": projection_p50,
                "assembly": assembly_p50,
            },
            "positive_net_value": positive_net_value,
            "authority": "shadow",
        }))
        .map_err(|error| error.to_string())?
    );
    Ok(())
}

fn repository_argument() -> Result<PathBuf, String> {
    let mut arguments = env::args_os().skip(1);
    let mut root = env::current_dir().map_err(|error| error.to_string())?;
    while let Some(argument) = arguments.next() {
        if argument == "--repository" {
            root = arguments
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "--repository requires a path".to_owned())?;
        } else {
            return Err(format!("unknown argument `{}`", argument.to_string_lossy()));
        }
    }
    root.canonicalize().map_err(|error| error.to_string())
}

fn bounded_cargo_stdout(
    root: &Path,
    arguments: &[&str],
    maximum: usize,
) -> Result<Vec<u8>, String> {
    let mut child = Command::new("cargo")
        .args(arguments)
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| error.to_string())?;
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .ok_or_else(|| "cargo stdout was not captured".to_owned())?
        .take((maximum + 1) as u64)
        .read_to_end(&mut output)
        .map_err(|error| error.to_string())?;
    let status = child.wait().map_err(|error| error.to_string())?;
    if !status.success() {
        return Err(format!("cargo exited with {status}"));
    }
    if output.len() > maximum {
        return Err(format!("cargo output exceeds {maximum} bytes"));
    }
    Ok(output)
}

fn elapsed_nanos(started: Instant) -> u64 {
    started.elapsed().as_nanos().try_into().unwrap_or(u64::MAX)
}

fn median(values: &mut [u64]) -> u64 {
    values.sort_unstable();
    values[values.len() / 2]
}
