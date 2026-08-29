use super::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use needle_core::{Digest, PartitionManifestId};
use needle_runtime::{MAX_PARTITION_MANIFEST_LIST_LIMIT, RuntimeStore};
use serde::Deserialize;
use serde_json::{Value, json};

const SCHEMA: &str = "needle.partition-manifest-inspection/1";
const DEFAULT_LIMIT: usize = 20;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitQuery {
    limit: Option<usize>,
}

pub(super) fn routes(router: Router<AppState>) -> Router<AppState> {
    router
        .route("/api/v1/partition-manifests", get(list_partition_manifests))
        .route("/api/v1/partition-manifests/{id}", get(get_partition_manifest))
}

pub(super) fn control_plane_envelope(store: &RuntimeStore) -> Result<Value, String> {
    list_envelope(store, DEFAULT_LIMIT)
}

async fn list_partition_manifests(
    State(state): State<AppState>,
    query: Query<LimitQuery>,
) -> Response {
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    match list_envelope(&state.store, limit) {
        Ok(value) => Json(value).into_response(),
        Err(error) if limit == 0 || limit > MAX_PARTITION_MANIFEST_LIST_LIMIT => {
            (StatusCode::BAD_REQUEST, Json(json!({"error": error}))).into_response()
        }
        Err(error) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": error}))).into_response()
        }
    }
}

async fn get_partition_manifest(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let manifest = match Digest::parse(&id) {
        Ok(digest) => PartitionManifestId::new(digest),
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid partition manifest id"})),
            )
                .into_response();
        }
    };
    match state.store.partition_manifest_publication(manifest) {
        Ok(Some(publication)) => Json(json!({
            "schema": SCHEMA,
            "status": "shadow_only",
            "publication": publication
        }))
        .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "partition manifest not found"})))
            .into_response(),
        Err(error) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": error.to_string()})))
                .into_response()
        }
    }
}

fn list_envelope(store: &RuntimeStore, limit: usize) -> Result<Value, String> {
    let items =
        store.list_partition_manifest_summaries(limit).map_err(|error| error.to_string())?;
    Ok(json!({
        "schema": SCHEMA,
        "status": "shadow_only",
        "items": items,
        "bounded": {
            "limit": limit,
            "maximum": MAX_PARTITION_MANIFEST_LIST_LIMIT
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn control_plane_envelope_is_bounded_shadow_and_read_only() {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let path = std::env::temp_dir().join(format!(
            "needle-partition-inspection-{}-{}.sqlite3",
            std::process::id(),
            nanos
        ));
        let store = RuntimeStore::new(&path);
        store.initialize().unwrap();
        let value = control_plane_envelope(&store).unwrap();
        assert_eq!(value["schema"], SCHEMA);
        assert_eq!(value["status"], "shadow_only");
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
}
