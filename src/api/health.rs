use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::security::authenticate_key;

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub authenticated_role: String,
    pub storage_total_bytes: u64,
    pub storage_used_bytes: u64,
    pub storage_free_bytes: u64,
    pub recording_count: i64,
}

pub async fn get_health(
    State(state): State<crate::AppState>,
    headers: HeaderMap,
) -> Result<Json<HealthResponse>, (StatusCode, Json<serde_json::Value>)> {
    let api_key = headers.get("x-api-key").and_then(|v| v.to_str().ok());

    let role = match authenticate_key(api_key, &state.config) {
        Some(r) => r,
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "detail": "Missing or invalid API key" })),
            ));
        }
    };

    let count: (i64,) = sqlx::query_as("SELECT COUNT(id) FROM recordings")
        .fetch_one(&state.db)
        .await
        .unwrap_or((0,));

    let (total_b, used_b, free_b) = match sysinfo::Disks::new_with_refreshed_list()
        .iter()
        .find(|d| state.config.storage_dir.starts_with(d.mount_point()))
    {
        Some(disk) => (
            disk.total_space(),
            disk.total_space().saturating_sub(disk.available_space()),
            disk.available_space(),
        ),
        None => (0, 0, 0),
    };

    Ok(Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        authenticated_role: role.as_str().to_string(),
        storage_total_bytes: total_b,
        storage_used_bytes: used_b,
        storage_free_bytes: free_b,
        recording_count: count.0,
    }))
}
