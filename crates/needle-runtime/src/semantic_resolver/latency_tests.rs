use super::{SemanticResolver, SemanticReuseDecision};
use crate::{
    NeedShadowWrite, RuntimeSettings, RuntimeStore, SemanticCostEstimates,
    validate_semantic_artifact,
};
use needle_core::{
    ActionRequest, ArtifactId, ArtifactKind, ArtifactRequest, CacheResolution, CapabilityMode,
    Digest, EvidenceFailurePolicy, LocationRole, MultiNeedPolicy, Need, NeedIr, NeedKey,
    PredicateKind, RepositoryGeneration, ReuseUnit, SemanticLocation, SemanticWorkerArtifact,
    built_in_route_contracts, need_fragment,
};
use rusqlite::Connection;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Clone, Copy)]
enum ExpectedActionResolution {
    Exact,
    Coverage,
}

struct ActionValidityLatencyFixture {
    root: PathBuf,
    database: PathBuf,
    resolver: SemanticResolver,
    need: Need,
    route_key: NeedKey,
    request: ActionRequest,
}

impl ActionValidityLatencyFixture {
    fn create(label: &str, expected: ExpectedActionResolution, record_stamp: bool) -> Self {
        let root = std::env::temp_dir().join(format!(
            "needle-phase5-latency-{label}-{}-{}",
            std::process::id(),
            Digest::blake3(format!("{:?}", Instant::now())).to_hex()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn answer() -> u32 { 42 }\n").unwrap();
        let database = root.join("needle.sqlite3");
        let store = RuntimeStore::new(&database);
        store.initialize().unwrap();
        store
            .initialize_defaults(&RuntimeSettings {
                codex_executable: "codex".to_owned(),
                worker_model: "test".to_owned(),
                worker_reasoning: "low".to_owned(),
                worker_timeout_seconds: 1,
                evidence_failure_policy: EvidenceFailurePolicy::DiscardInvalidFact,
                trusted_test_execution: false,
                multi_need_policy: MultiNeedPolicy::default(),
            })
            .unwrap();

        let repository_lineage = Digest::blake3(format!("phase5-repository-{label}"));
        let source_snapshot_digest = Digest::blake3(format!("phase5-source-{label}"));
        let locate_ir = NeedIr::parse(
            "@@need\n\
             @route locate.implementation\n\
             @subject symbol:\"answer\"\n\
             @require implementation-location selection=primary granularity=exact-location polarity=positive\n\
             @world source=current features=default\n\
             \n\
             Locate the implementation.\n\
             @@end",
        )
        .unwrap()
        .unwrap();
        let locate_route = built_in_route_contracts()
            .into_iter()
            .find(|route| route.route.as_str() == "locate.implementation")
            .unwrap();
        let locate_need =
            needle_core::compile_need(&locate_ir, repository_lineage, &locate_route).unwrap();
        let locate_fragment = need_fragment(&locate_need, locate_need.required.clone(), Vec::new());
        store
            .record_need_shadow(NeedShadowWrite {
                session_id: "phase5-latency-session",
                turn_id: "phase5-latency-locate-turn",
                transport_digest: locate_ir.transport_digest(),
                parser_definition_digest: Digest::blake3(b"phase5-parser"),
                prompt_profile_digest: Digest::blake3(b"phase5-profile"),
                need_ir: &locate_ir,
                need: &locate_need,
                fragments: std::slice::from_ref(&locate_fragment),
            })
            .unwrap();

        let trace_ir = NeedIr::parse(
            "@@need\n\
             @route trace.state-flow\n\
             @subject symbol:\"answer\"\n\
             @require implementation-location selection=primary granularity=exact-location polarity=positive\n\
             @require runtime-flow scenario=default completeness=contract-complete granularity=stepwise\n\
             @world source=current features=default\n\
             \n\
             Trace the implementation and runtime flow.\n\
             @@end",
        )
        .unwrap()
        .unwrap();
        let trace_route = built_in_route_contracts()
            .into_iter()
            .find(|route| route.route.as_str() == "trace.state-flow")
            .unwrap();
        let trace_need =
            needle_core::compile_need(&trace_ir, repository_lineage, &trace_route).unwrap();
        let trace_fragment = need_fragment(&trace_need, trace_need.required.clone(), Vec::new());
        store
            .record_need_shadow(NeedShadowWrite {
                session_id: "phase5-latency-session",
                turn_id: "phase5-latency-trace-turn",
                transport_digest: trace_ir.transport_digest(),
                parser_definition_digest: Digest::blake3(b"phase5-parser"),
                prompt_profile_digest: Digest::blake3(b"phase5-profile"),
                need_ir: &trace_ir,
                need: &trace_need,
                fragments: std::slice::from_ref(&trace_fragment),
            })
            .unwrap();

        let action = crate::built_in_action_for_artifact_kind(&ArtifactKind::code_location())
            .expect("built-in code-location action");
        let (origin_need, origin_fragment, origin_route, origin_request_text) = match expected {
            ExpectedActionResolution::Exact => {
                (&locate_need, &locate_fragment, &locate_route.route, "locate answer")
            }
            ExpectedActionResolution::Coverage => {
                (&trace_need, &trace_fragment, &trace_route.route, "trace answer")
            }
        };
        let origin_request = ActionRequest::new(
            &action.contract,
            ArtifactRequest {
                contract_id: action.output_contract_id.to_owned(),
                contract_revision: action.output_contract_revision,
                repository_id: repository_lineage,
                source_snapshot_digest,
                route_key: origin_route.clone(),
                normalized_request: origin_request_text.to_owned(),
                semantic_fragment_id: Some(origin_fragment.id),
                input_artifact_ids: Vec::new(),
            },
            action.contract.default_dispatch_policy,
            origin_route.clone(),
            origin_need.id,
        )
        .unwrap();
        let request = ActionRequest::new(
            &action.contract,
            ArtifactRequest {
                contract_id: action.output_contract_id.to_owned(),
                contract_revision: action.output_contract_revision,
                repository_id: repository_lineage,
                source_snapshot_digest,
                route_key: locate_route.route.clone(),
                normalized_request: "locate answer".to_owned(),
                semantic_fragment_id: Some(locate_fragment.id),
                input_artifact_ids: Vec::new(),
            },
            action.contract.default_dispatch_policy,
            locate_route.route.clone(),
            locate_need.id,
        )
        .unwrap();
        match expected {
            ExpectedActionResolution::Exact => {
                assert_eq!(request.semantic_id(), origin_request.semantic_id());
            }
            ExpectedActionResolution::Coverage => {
                assert_ne!(request.semantic_id(), origin_request.semantic_id());
            }
        }

        let validated = validate_semantic_artifact(
            origin_fragment,
            &SemanticWorkerArtifact::CodeLocation {
                locations: vec![SemanticLocation {
                    role: LocationRole::Primary,
                    path: "src/lib.rs".to_owned(),
                    symbol: Some("answer".to_owned()),
                    byte_start: None,
                    byte_end: None,
                }],
                gaps: Vec::new(),
            },
            &root,
            origin_request.semantic_id().digest(),
        )
        .unwrap();
        store
            .publish_action_artifact(&origin_request, &validated.artifact, &validated.certificate)
            .unwrap();

        let canonical_root = fs::canonicalize(&root).unwrap();
        let repository_context =
            crate::repository_observer::repository_context_id(repository_lineage, &canonical_root);
        store
            .initialize_repository_generation(&RepositoryGeneration::new(
                repository_lineage,
                repository_context,
                0,
                source_snapshot_digest,
                None,
                true,
            ))
            .unwrap();
        if record_stamp {
            store
                .record_dependency_stamp(
                    ArtifactId::new(validated.artifact.id),
                    validated.certificate.id,
                    repository_context,
                )
                .unwrap();
        }

        let capability = store
            .capability_classes()
            .unwrap()
            .into_iter()
            .find(|class| {
                class.reuse_unit == ReuseUnit::Artifact
                    && class.predicate == PredicateKind::ImplementationLocation
            })
            .expect("implementation-location artifact capability");
        store
            .set_capability_mode(
                &capability.id,
                capability.definition_digest,
                CapabilityMode::Authoritative,
                Some(Digest::blake3(b"phase5-latency-capability-evidence")),
            )
            .unwrap();

        let resolver = SemanticResolver::new(store.clone());
        Self { root, database, resolver, need: locate_need, route_key: locate_route.route, request }
    }

    fn resolve(&self) -> SemanticReuseDecision {
        self.resolver
            .resolve_for_route_actions(
                &self.need,
                &self.route_key,
                &self.root,
                self.request.artifact_request.source_snapshot_digest,
                SemanticCostEstimates {
                    fresh_microusd: Some(100),
                    artifact_reuse_microusd: Some(1),
                    claim_reuse_microusd: None,
                    claim_partial_reuse_microusd: None,
                },
                std::slice::from_ref(&self.request),
            )
            .unwrap()
    }

    fn operational_memo_count(&self) -> u64 {
        Connection::open(&self.database)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM operational_validity_memos", [], |row| row.get(0))
            .unwrap()
    }
}

impl Drop for ActionValidityLatencyFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct LatencyObservation {
    name: &'static str,
    median_ns: u128,
    p95_ns: u128,
}

fn assert_resolution(decision: &SemanticReuseDecision, expected: ExpectedActionResolution) {
    match expected {
        ExpectedActionResolution::Exact => {
            assert!(matches!(decision.resolution, CacheResolution::ExactHit { .. }));
        }
        ExpectedActionResolution::Coverage => {
            assert!(matches!(decision.resolution, CacheResolution::CoverageHit { .. }));
        }
    }
    assert!(decision.authoritative);
}

fn measure_action_resolution(
    name: &'static str,
    fixture: &ActionValidityLatencyFixture,
    expected: ExpectedActionResolution,
    iterations: usize,
) -> LatencyObservation {
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        let decision = fixture.resolve();
        let elapsed_ns = started.elapsed().as_nanos();
        assert_resolution(&decision, expected);
        samples.push(elapsed_ns);
    }
    samples.sort_unstable();
    let p95_index = (samples.len() * 95).div_ceil(100).saturating_sub(1);
    LatencyObservation { name, median_ns: samples[samples.len() / 2], p95_ns: samples[p95_index] }
}

#[test]
#[ignore = "manual release-mode Phase 5 latency gate"]
fn phase5_action_validity_exact_and_coverage_p95_stay_within_budget() {
    const WARMUP_ITERATIONS: usize = 10;
    const MEASURED_ITERATIONS: usize = 100;
    const DEFAULT_P95_BUDGET_MS: u128 = 10;

    assert!(!cfg!(debug_assertions), "the Phase 5 latency gate must run with --release");
    let exact_memo =
        ActionValidityLatencyFixture::create("exact-memo", ExpectedActionResolution::Exact, true);
    let coverage_memo = ActionValidityLatencyFixture::create(
        "coverage-memo",
        ExpectedActionResolution::Coverage,
        true,
    );
    let exact_filesystem = ActionValidityLatencyFixture::create(
        "exact-filesystem",
        ExpectedActionResolution::Exact,
        false,
    );
    let coverage_filesystem = ActionValidityLatencyFixture::create(
        "coverage-filesystem",
        ExpectedActionResolution::Coverage,
        false,
    );
    for _ in 0..WARMUP_ITERATIONS {
        assert_resolution(&exact_memo.resolve(), ExpectedActionResolution::Exact);
        assert_resolution(&coverage_memo.resolve(), ExpectedActionResolution::Coverage);
        assert_resolution(&exact_filesystem.resolve(), ExpectedActionResolution::Exact);
        assert_resolution(&coverage_filesystem.resolve(), ExpectedActionResolution::Coverage);
    }
    assert_eq!(exact_memo.operational_memo_count(), 1);
    assert_eq!(coverage_memo.operational_memo_count(), 1);
    assert_eq!(exact_filesystem.operational_memo_count(), 0);
    assert_eq!(coverage_filesystem.operational_memo_count(), 0);

    let observations = [
        measure_action_resolution(
            "exact_generation_memo",
            &exact_memo,
            ExpectedActionResolution::Exact,
            MEASURED_ITERATIONS,
        ),
        measure_action_resolution(
            "coverage_generation_memo",
            &coverage_memo,
            ExpectedActionResolution::Coverage,
            MEASURED_ITERATIONS,
        ),
        measure_action_resolution(
            "exact_filesystem_fallback",
            &exact_filesystem,
            ExpectedActionResolution::Exact,
            MEASURED_ITERATIONS,
        ),
        measure_action_resolution(
            "coverage_filesystem_fallback",
            &coverage_filesystem,
            ExpectedActionResolution::Coverage,
            MEASURED_ITERATIONS,
        ),
    ];
    let budget_ms = std::env::var("NEEDLE_PHASE5_RESOLVER_P95_BUDGET_MS")
        .ok()
        .and_then(|value| value.parse::<u128>().ok())
        .unwrap_or(DEFAULT_P95_BUDGET_MS);
    let budget_ns = budget_ms.saturating_mul(1_000_000);
    println!(
        "phase5 action validity latency: iterations={MEASURED_ITERATIONS}, p95_budget_ms={budget_ms}"
    );
    for observation in &observations {
        println!(
            "{}: median_ms={:.3}, p95_ms={:.3}",
            observation.name,
            observation.median_ns as f64 / 1_000_000.0,
            observation.p95_ns as f64 / 1_000_000.0
        );
    }
    for observation in &observations[..2] {
        assert!(
            observation.p95_ns <= budget_ns,
            "{} p95 {:.3} ms exceeded the configured {} ms budget",
            observation.name,
            observation.p95_ns as f64 / 1_000_000.0,
            budget_ms
        );
    }
    assert_eq!(exact_memo.operational_memo_count(), 1);
    assert_eq!(coverage_memo.operational_memo_count(), 1);
    assert_eq!(exact_filesystem.operational_memo_count(), 0);
    assert_eq!(coverage_filesystem.operational_memo_count(), 0);
}
