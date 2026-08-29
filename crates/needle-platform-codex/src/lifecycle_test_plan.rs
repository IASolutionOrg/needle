use crate::{CodexWorker, HookConfig};
use needle_core::{
    Digest, Facet, LifecycleResolvedTestPlan, LifecycleUsage, MAX_REQUEST_BYTES, NeedIr, NeedKey,
    NeedRequest, ObligationExpression, PredicateKind,
};
use needle_runtime::{LifecyclePhaseAdapterRequest, ResolveRequest, RuntimeEngine, RuntimeStore};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const TEST_PLAN_DISCOVERY_TRANSPORT: &[u8] = b"needle.lifecycle-test-plan-discovery/1";
pub(crate) const TEST_PLAN_DISCOVERY_DEFINITION: &[u8] =
    b"needle-codex-lifecycle-test-plan-discovery-v3";

pub(crate) struct LifecycleTestPlanDiscovery {
    pub plans: Vec<LifecycleResolvedTestPlan>,
    pub usage: LifecycleUsage,
}

pub(crate) fn discover(
    store: &RuntimeStore,
    data_directory: &Path,
    repository_root: &Path,
    codex_home: Option<&Path>,
    request: &LifecyclePhaseAdapterRequest,
) -> Result<LifecycleTestPlanDiscovery, String> {
    let action_plan = request
        .lifecycle
        .spec
        .explore_action_plan
        .as_ref()
        .ok_or_else(|| "lifecycle TestPlan discovery has no frozen Need plan".to_owned())?;
    let shadow = store
        .need_shadow(&action_plan.fragment.root_need)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "lifecycle TestPlan discovery Need is unavailable".to_owned())?;
    if shadow.need.id != action_plan.fragment.root_need
        || shadow.need.world.repository_lineage != request.change.repository_id
        || request.lifecycle.phase != needle_core::LifecyclePhase::Test
        || !request.lifecycle.spec.test_plans.is_empty()
        || !request.lifecycle.resolved_test_plans.is_empty()
    {
        return Err("lifecycle TestPlan discovery binding changed".to_owned());
    }

    let need_ir = test_plan_need(&shadow.need_ir, request)?;
    let session_id = format!("needle-lifecycle-test-plan-{}", request.invocation_id.to_hex());
    let turn_id = "test-plan";
    let cwd = repository_root.to_string_lossy();
    let prompt_profile = HookConfig::default().profile().map_err(|error| error.to_string())?;
    store
        .record_session_start_for_transport_profiled(
            &session_id,
            prompt_profile.definition_digest,
            Some("codex"),
            Some(&cwd),
            "lifecycle-test-plan",
            Digest::blake3(TEST_PLAN_DISCOVERY_TRANSPORT),
            Some(needle_core::need_grammar_definition_digest()),
            &request.profile.profile_id,
        )
        .map_err(|error| error.to_string())?;
    store
        .record_user_prompt(&session_id, Some(turn_id), &need_ir.body, Some(&cwd))
        .map_err(|error| error.to_string())?;

    let cursor = store.worker_run_cursor().map_err(|error| error.to_string())?;
    let worker = codex_home.map_or_else(
        || CodexWorker::new(data_directory),
        |home| CodexWorker::with_codex_home(data_directory, home),
    );
    let engine = RuntimeEngine::new(store.clone(), worker);
    let resolve_request = ResolveRequest {
        session_id: session_id.clone(),
        turn_id: turn_id.to_owned(),
        platform: "codex".to_owned(),
        main_model: "codex".to_owned(),
        cwd: PathBuf::from(repository_root),
        need: NeedRequest {
            key: NeedKey::new("tests.relevant").map_err(|error| error.to_string())?,
            body: need_ir.body.clone(),
        },
        need_ir: Some(need_ir),
        declared_test_plan: None,
    };
    let resolved =
        engine.resolve_direct_explore(&resolve_request).map_err(|error| error.to_string());
    let cleanup = store.end_session(&session_id).map_err(|error| error.to_string());
    let resolved = resolved?;
    cleanup?;

    let run = store
        .worker_run_for_profile_after(cursor, &request.profile)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| {
            "lifecycle TestPlan discovery produced no uniquely attributable worker run".to_owned()
        })?;
    if !resolved.worker_spawned
        || resolved.cache_hit
        || run.failure_code.is_some()
        || run.result_digest.is_none()
        || run.logical_worker_spawns != 1
        || run.worker_turns != 1
        || run.repair_performed
        || run.session_cleanup_success != Some(true)
        || run.role_profile_provenance.as_ref() != Some(&request.profile)
    {
        return Err("lifecycle TestPlan discovery worker provenance is invalid".to_owned());
    }

    let artifact_ids = resolved.semantic_artifact_ids.into_iter().collect::<BTreeSet<_>>();
    let mut plans = store
        .lifecycle_start_test_plan_candidates(request.change.source_snapshot)
        .map_err(|error| error.to_string())?
        .into_iter()
        .filter(|candidate| artifact_ids.contains(&candidate.artifact_id))
        .map(|candidate| LifecycleResolvedTestPlan {
            artifact: candidate.artifact_id,
            binding: candidate.binding,
        })
        .collect::<Vec<_>>();
    plans.sort_by_key(|plan| (plan.binding.plan_digest(), plan.artifact));
    if plans.is_empty()
        || plans.len() > needle_core::MAX_LIFECYCLE_TEST_PLANS
        || plans.windows(2).any(|pair| {
            (pair[0].binding.plan_digest(), pair[0].artifact)
                >= (pair[1].binding.plan_digest(), pair[1].artifact)
        })
    {
        return Err("lifecycle TestPlan discovery returned no canonical certified plan".to_owned());
    }

    let revision = store
        .read_role_profile_revision(&request.profile.profile_id, request.profile.revision)
        .map_err(|error| error.to_string())?;
    if revision.definition.definition_digest != request.profile.definition_digest {
        return Err("lifecycle TestPlan discovery profile revision changed".to_owned());
    }
    Ok(LifecycleTestPlanDiscovery {
        plans,
        usage: LifecycleUsage {
            worker_turns: run.worker_turns,
            output_tokens: run
                .output_tokens
                .unwrap_or(u64::from(revision.definition.budget.max_output_tokens)),
            cost_microusd: revision.definition.budget.max_cost_microusd,
        },
    })
}

fn test_plan_need(
    source: &NeedIr,
    request: &LifecyclePhaseAdapterRequest,
) -> Result<NeedIr, String> {
    let mut value = source.clone();
    value.route_hint = Some(NeedKey::new("tests.relevant").map_err(|error| error.to_string())?);
    value.required = vec![ObligationExpression {
        predicate: PredicateKind::FocusedTests,
        facets: vec![
            Facet { key: "completeness".to_owned(), value: "open-world".to_owned() },
            Facet { key: "polarity".to_owned(), value: "positive".to_owned() },
            Facet { key: "selection".to_owned(), value: "representative".to_owned() },
        ],
    }];
    value.preferred.clear();
    value.projection.clear();
    value.body = bounded_discovery_body(request);
    serde_json::to_vec(&value).map_err(|error| error.to_string()).and_then(|encoded| {
        if encoded.len() > needle_core::MAX_NEED_IR_BYTES {
            Err("derived lifecycle TestPlan NeedIR exceeds its byte bound".to_owned())
        } else {
            Ok(value)
        }
    })
}

fn bounded_discovery_body(request: &LifecyclePhaseAdapterRequest) -> String {
    let mut body = String::from("Find the focused tests for this exact lifecycle change.\nTask: ");
    body.push_str(&request.change.request.task);
    body.push_str("\nAcceptance criteria:");
    for criterion in &request.change.request.acceptance_criteria {
        body.push('\n');
        body.push_str(criterion);
    }
    body.push_str("\nAllowed write paths (these do not restrict read-only test discovery):");
    for allowed in &request.change.request.allowed_paths {
        body.push('\n');
        body.push_str(&allowed.path);
    }
    body.push_str("\nChange digest: ");
    body.push_str(&request.change.request_digest.to_string());
    if body.len() <= MAX_REQUEST_BYTES {
        return body;
    }

    let suffix = format!("\nChange digest: {}", request.change.request_digest);
    let maximum_prefix = MAX_REQUEST_BYTES.saturating_sub(suffix.len());
    let mut boundary = maximum_prefix.min(body.len());
    while boundary > 0 && !body.is_char_boundary(boundary) {
        boundary -= 1;
    }
    body.truncate(boundary);
    body.push_str(&suffix);
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_body_keeps_the_full_change_identity() {
        let suffix = format!("\nChange digest: {}", Digest::blake3(b"change"));
        let mut body = "é".repeat(MAX_REQUEST_BYTES);
        let maximum_prefix = MAX_REQUEST_BYTES - suffix.len();
        let mut boundary = maximum_prefix.min(body.len());
        while boundary > 0 && !body.is_char_boundary(boundary) {
            boundary -= 1;
        }
        body.truncate(boundary);
        body.push_str(&suffix);
        assert!(body.len() <= MAX_REQUEST_BYTES);
        assert!(body.ends_with(&suffix));
    }
}
