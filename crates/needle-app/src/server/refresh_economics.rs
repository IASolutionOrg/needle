use super::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use needle_core::Digest;
use needle_runtime::{
    MAX_REFRESH_ECONOMIC_ASSESSMENT_LIST_LIMIT, RefreshEconomicAssessmentRecord, RuntimeStore,
};
use serde::Deserialize;
use serde_json::{Value, json};

const SCHEMA: &str = "needle.refresh-economic-inspection/1";
const DEFAULT_LIMIT: usize = 20;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitQuery {
    limit: Option<usize>,
}

pub(super) fn routes(router: Router<AppState>) -> Router<AppState> {
    router
        .route("/api/v1/refresh-economics", get(list_assessments))
        .route("/api/v1/refresh-economics/{id}", get(get_assessment))
}

pub(super) fn control_plane_envelope(store: &RuntimeStore) -> Result<Value, String> {
    list_envelope(store, DEFAULT_LIMIT)
}

async fn list_assessments(State(state): State<AppState>, query: Query<LimitQuery>) -> Response {
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    match list_envelope(&state.store, limit) {
        Ok(value) => Json(value).into_response(),
        Err(error) if limit == 0 || limit > MAX_REFRESH_ECONOMIC_ASSESSMENT_LIST_LIMIT => {
            (StatusCode::BAD_REQUEST, Json(json!({"error": error}))).into_response()
        }
        Err(error) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": error}))).into_response()
        }
    }
}

async fn get_assessment(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let definition_digest = match Digest::parse(&id) {
        Ok(digest) => digest,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid refresh economic assessment digest"})),
            )
                .into_response();
        }
    };
    match state.store.refresh_economic_assessment(definition_digest) {
        Ok(Some(record)) => Json(json!({
            "schema": SCHEMA,
            "status": "shadow_audit_only",
            "record": inspection_record(&record)
        }))
        .into_response(),
        Ok(None) => {
            (StatusCode::NOT_FOUND, Json(json!({"error": "refresh economic assessment not found"})))
                .into_response()
        }
        Err(error) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": error.to_string()})))
                .into_response()
        }
    }
}

fn list_envelope(store: &RuntimeStore, limit: usize) -> Result<Value, String> {
    let items = store
        .refresh_economic_assessments(limit)
        .map_err(|error| error.to_string())?
        .iter()
        .map(inspection_record)
        .collect::<Vec<_>>();
    Ok(json!({
        "schema": SCHEMA,
        "status": "shadow_audit_only",
        "items": items,
        "bounded": {
            "limit": limit,
            "maximum": MAX_REFRESH_ECONOMIC_ASSESSMENT_LIST_LIMIT
        }
    }))
}

fn inspection_record(record: &RefreshEconomicAssessmentRecord) -> Value {
    let assessment = &record.assessment;
    let evidence = assessment.evidence.as_ref().map(|evidence| {
        json!({
            "format_revision": evidence.format_revision,
            "request": evidence.request,
            "action_contract": evidence.action_contract,
            "candidate_definition_digest": evidence.candidate_definition_digest,
            "operator_definition_digest": evidence.operator_definition_digest,
            "execution_scope_digest": evidence.execution_scope_digest,
            "basis": evidence.basis,
            "evidence_digest": evidence.evidence_digest,
            "pricing_revision": evidence.pricing_revision,
            "estimated_fresh_total_microusd":
                evidence.estimated_fresh_total_microusd.to_string(),
            "estimated_refresh_total_microusd":
                evidence.estimated_refresh_total_microusd.to_string(),
            "estimated_refresh_latency_micros": evidence.estimated_refresh_latency_micros,
            "definition_digest": evidence.definition_digest
        })
    });
    json!({
        "assessment": {
            "format_revision": assessment.format_revision,
            "definition_digest": assessment.definition_digest,
            "request": assessment.request,
            "action_contract": assessment.action_contract,
            "candidate_definition_digest": assessment.candidate_definition_digest,
            "operator_definition_digest": assessment.operator_definition_digest,
            "execution_scope_digest": assessment.execution_scope_digest,
            "policy": {
                "format_revision": assessment.policy.format_revision,
                "action_operational_policy_digest":
                    assessment.policy.action_operational_policy_digest,
                "refresh_policy_definition_digest":
                    assessment.policy.refresh_policy_definition_digest,
                "minimum_expected_net_microusd":
                    assessment.policy.minimum_expected_net_microusd.to_string(),
                "maximum_refresh_latency_micros":
                    assessment.policy.maximum_refresh_latency_micros,
                "definition_digest": assessment.policy.definition_digest
            },
            "evidence": evidence,
            "expected_net_microusd":
                assessment.expected_net_microusd.map(|value| value.to_string()),
            "decision": assessment.decision,
            "authority": assessment.authority
        },
        "selected_refresh_attempt": record.selected_refresh_attempt,
        "recorded_unix_ms": record.recorded_unix_ms
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use needle_core::{
        ActionContractId, ArtifactRequestId, RefreshCostEvidence, RefreshCostEvidenceBasis,
        RefreshCostEvidenceInput, RefreshEconomicAssessment, RefreshEconomicAssessmentInput,
        RefreshEconomicPolicy, RefreshEconomicPolicyInput,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn control_plane_envelope_is_bounded_shadow_and_read_only() {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let path = std::env::temp_dir().join(format!(
            "needle-refresh-economic-inspection-{}-{}.sqlite3",
            std::process::id(),
            nanos
        ));
        let store = RuntimeStore::new(&path);
        store.initialize().unwrap();
        let value = control_plane_envelope(&store).unwrap();
        assert_eq!(value["schema"], SCHEMA);
        assert_eq!(value["status"], "shadow_audit_only");
        assert_eq!(value["items"], json!([]));
        assert_eq!(value["bounded"]["limit"], DEFAULT_LIMIT);
        drop(store);
        for candidate in [
            path.clone(),
            PathBuf::from(format!("{}-wal", path.display())),
            PathBuf::from(format!("{}-shm", path.display())),
        ] {
            let _ = fs::remove_file(candidate);
        }
    }

    #[test]
    fn inspection_preserves_large_monetary_values_as_exact_decimal_strings() {
        let digest = |label: &str| Digest::blake3(label.as_bytes());
        let request = ArtifactRequestId::new(digest("request"));
        let action_contract = ActionContractId::new("needle.tests.inventory").unwrap();
        let candidate = digest("candidate");
        let operator = digest("operator");
        let scope = digest("scope");
        let policy = RefreshEconomicPolicy::new(RefreshEconomicPolicyInput {
            action_operational_policy_digest: digest("operational"),
            refresh_policy_definition_digest: digest("refresh-policy"),
            minimum_expected_net_microusd: 1,
            maximum_refresh_latency_micros: None,
        })
        .unwrap();
        let evidence = RefreshCostEvidence::new(RefreshCostEvidenceInput {
            request,
            action_contract: action_contract.clone(),
            candidate_definition_digest: candidate,
            operator_definition_digest: operator,
            execution_scope_digest: scope,
            basis: RefreshCostEvidenceBasis::ConfiguredStatic,
            evidence_digest: digest("evidence"),
            pricing_revision: None,
            estimated_fresh_total_microusd: i64::MAX as u64,
            estimated_refresh_total_microusd: 0,
            estimated_refresh_latency_micros: None,
        })
        .unwrap();
        let assessment = RefreshEconomicAssessment::new(RefreshEconomicAssessmentInput {
            request,
            action_contract,
            candidate_definition_digest: candidate,
            operator_definition_digest: operator,
            execution_scope_digest: scope,
            policy,
            evidence: Some(evidence),
        })
        .unwrap();
        let value = inspection_record(&RefreshEconomicAssessmentRecord {
            assessment,
            selected_refresh_attempt: None,
            recorded_unix_ms: 1,
        });
        assert_eq!(value["assessment"]["expected_net_microusd"], i64::MAX.to_string());
        assert_eq!(
            value["assessment"]["evidence"]["estimated_fresh_total_microusd"],
            i64::MAX.to_string()
        );
        assert!(value["assessment"]["expected_net_microusd"].is_string());
    }
}
