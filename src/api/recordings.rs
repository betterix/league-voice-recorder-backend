use axum::extract::{Multipart, Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::audio::storage::{
    build_range_download_response, delete_recording_file, stream_save_upload, validate_game_id,
};
use crate::db::models::{now_iso, Recording, RecordingMetadataResponse};
use crate::security::{authenticate_key, Role};
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct ListRecordingsQuery {
    #[serde(default)]
    pub skip: i64,
    #[serde(default = "default_limit")]
    pub limit: i64,
    pub search: Option<String>,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Serialize)]
pub struct RecordingListResponse {
    pub items: Vec<RecordingMetadataResponse>,
    pub total: i64,
    pub skip: i64,
    pub limit: i64,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
    pub game_id: Option<String>,
}

fn require_read(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<Role, (StatusCode, Json<serde_json::Value>)> {
    let key = headers.get("x-api-key").and_then(|v| v.to_str().ok());
    match authenticate_key(key, &state.config) {
        Some(role) => Ok(role),
        None => Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "detail": "Missing or invalid API key" })),
        )),
    }
}

fn require_write(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<Role, (StatusCode, Json<serde_json::Value>)> {
    let role = require_read(headers, state)?;
    if role == Role::Pull {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "detail": "Forbidden: Pull key only possesses read-only permissions"
            })),
        ));
    }
    Ok(role)
}

fn require_admin(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<Role, (StatusCode, Json<serde_json::Value>)> {
    let role = require_read(headers, state)?;
    if role != Role::Admin {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "detail": "Forbidden: Administrator access required to delete recordings"
            })),
        ));
    }
    Ok(role)
}

pub async fn list_recordings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListRecordingsQuery>,
) -> Result<Json<RecordingListResponse>, (StatusCode, Json<serde_json::Value>)> {
    require_read(&headers, &state)?;

    let skip = query.skip.max(0);
    let limit = query.limit.clamp(1, 100);

    let (items, total): (Vec<Recording>, i64) = if let Some(search) = &query.search {
        let pattern = format!("%{}%", search.trim());
        let count_row: (i64,) = sqlx::query_as(
            "SELECT COUNT(id) FROM recordings WHERE game_id LIKE ?1 OR team_tag LIKE ?1",
        )
        .bind(&pattern)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "detail": e.to_string() })),
            )
        })?;

        let rows = sqlx::query_as::<_, Recording>(
            r#"
            SELECT id, game_id, filename, file_size, duration, bitrate, sample_rate,
                   sha256, team_tag, notes, match_date, created_at, updated_at
            FROM recordings
            WHERE game_id LIKE ?1 OR team_tag LIKE ?1
            ORDER BY created_at DESC
            LIMIT ?2 OFFSET ?3
            "#,
        )
        .bind(&pattern)
        .bind(limit)
        .bind(skip)
        .fetch_all(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "detail": e.to_string() })),
            )
        })?;

        (rows, count_row.0)
    } else {
        let count_row: (i64,) = sqlx::query_as("SELECT COUNT(id) FROM recordings")
            .fetch_one(&state.db)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "detail": e.to_string() })),
                )
            })?;

        let rows = sqlx::query_as::<_, Recording>(
            r#"
            SELECT id, game_id, filename, file_size, duration, bitrate, sample_rate,
                   sha256, team_tag, notes, match_date, created_at, updated_at
            FROM recordings
            ORDER BY created_at DESC
            LIMIT ?1 OFFSET ?2
            "#,
        )
        .bind(limit)
        .bind(skip)
        .fetch_all(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "detail": e.to_string() })),
            )
        })?;

        (rows, count_row.0)
    };

    let responses: Vec<RecordingMetadataResponse> = items.into_iter().map(Into::into).collect();

    Ok(Json(RecordingListResponse {
        items: responses,
        total,
        skip,
        limit,
    }))
}

pub async fn get_recording(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(game_id): AxumPath<String>,
) -> Result<Json<RecordingMetadataResponse>, (StatusCode, Json<serde_json::Value>)> {
    require_read(&headers, &state)?;
    let clean_id = validate_game_id(&game_id).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "detail": e.to_string() })),
        )
    })?;

    let row = sqlx::query_as::<_, Recording>(
        r#"
        SELECT id, game_id, filename, file_size, duration, bitrate, sample_rate,
               sha256, team_tag, notes, match_date, created_at, updated_at
        FROM recordings
        WHERE game_id = ?1
        "#,
    )
    .bind(&clean_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "detail": e.to_string() })),
        )
    })?;

    match row {
        Some(r) => Ok(Json(r.into())),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "detail": format!("Recording for Game ID '{clean_id}' not found")
            })),
        )),
    }
}

pub async fn download_recording(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(game_id): AxumPath<String>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    require_read(&headers, &state)?;
    let clean_id = validate_game_id(&game_id).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "detail": e.to_string() })),
        )
    })?;

    let exists: Option<(i64,)> = sqlx::query_as("SELECT id FROM recordings WHERE game_id = ?1")
        .bind(&clean_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "detail": e.to_string() })),
            )
        })?;

    if exists.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "detail": format!("Recording for Game ID '{clean_id}' not found in database")
            })),
        ));
    }

    let range_hdr = headers.get("range").and_then(|v| v.to_str().ok());
    build_range_download_response(&clean_id, range_hdr, &state.config.storage_dir, false)
        .await
        .map_err(|e| {
            let res: Response = e.into_response();
            (
                res.status(),
                Json(serde_json::json!({ "detail": "Range download failed" })),
            )
        })
}

pub async fn upload_recording(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(game_id): AxumPath<String>,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<RecordingMetadataResponse>), (StatusCode, Json<serde_json::Value>)> {
    require_write(&headers, &state)?;
    let clean_id = validate_game_id(&game_id).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "detail": e.to_string() })),
        )
    })?;

    // Check duplicate in DB
    let existing: Option<(i64,)> = sqlx::query_as("SELECT id FROM recordings WHERE game_id = ?1")
        .bind(&clean_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "detail": e.to_string() })),
            )
        })?;

    if existing.is_some() {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "detail": format!("Recording for Game ID '{clean_id}' already exists in database")
            })),
        ));
    }

    let mut team_tag: Option<String> = None;
    let mut notes: Option<String> = None;
    let mut match_date: Option<String> = None;
    let mut upload_processed = None;

    let expected_sha256 = headers
        .get("x-checksum-sha256")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "detail": format!("Invalid multipart data: {e}") })),
        )
    })? {
        let name = field.name().unwrap_or("").to_string();
        if name == "file" {
            let res = stream_save_upload(
                field,
                &clean_id,
                expected_sha256.as_deref(),
                &state.config.storage_dir,
                state.config.max_upload_bytes(),
                state.config.max_upload_mb,
            )
            .await
            .map_err(|e| {
                let err_str = e.to_string();
                let resp: Response = e.into_response();
                (
                    resp.status(),
                    Json(serde_json::json!({ "detail": err_str })),
                )
            })?;
            upload_processed = Some(res);
        } else if name == "team_tag" {
            if let Ok(text) = field.text().await {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    team_tag = Some(trimmed.to_string());
                }
            }
        } else if name == "notes" {
            if let Ok(text) = field.text().await {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    notes = Some(trimmed.to_string());
                }
            }
        } else if name == "match_date" {
            if let Ok(text) = field.text().await {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    match_date = Some(trimmed.to_string());
                }
            }
        }
    }

    let processed = match upload_processed {
        Some(p) => p,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "detail": "Missing required 'file' multipart field" })),
            ));
        }
    };

    let filename = format!("{clean_id}.mp3");
    let now_str = now_iso();

    let insert_res = sqlx::query(
        r#"
        INSERT INTO recordings (
            game_id, filename, file_size, duration, bitrate, sample_rate,
            sha256, team_tag, notes, match_date, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)
        "#,
    )
    .bind(&clean_id)
    .bind(&filename)
    .bind(processed.audio_info.file_size as i64)
    .bind(processed.audio_info.duration)
    .bind(processed.audio_info.bitrate)
    .bind(processed.audio_info.sample_rate)
    .bind(&processed.sha256)
    .bind(&team_tag)
    .bind(&notes)
    .bind(&match_date)
    .bind(&now_str)
    .execute(&state.db)
    .await;

    if let Err(e) = insert_res {
        delete_recording_file(&clean_id, &state.config.storage_dir).await;
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "detail": format!("Database insertion failed: {e}") })),
        ));
    }

    let metadata = RecordingMetadataResponse {
        game_id: clean_id,
        filename,
        file_size: processed.audio_info.file_size as i64,
        duration: processed.audio_info.duration,
        bitrate: processed.audio_info.bitrate,
        sample_rate: processed.audio_info.sample_rate,
        upload_timestamp: now_str,
        team_tag,
        notes,
        match_date,
        sha256: processed.sha256,
    };

    Ok((StatusCode::CREATED, Json(metadata)))
}

pub async fn delete_recording(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(game_id): AxumPath<String>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<serde_json::Value>)> {
    require_admin(&headers, &state)?;
    let clean_id = validate_game_id(&game_id).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "detail": e.to_string() })),
        )
    })?;

    let row: Option<(i64,)> = sqlx::query_as("SELECT id FROM recordings WHERE game_id = ?1")
        .bind(&clean_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "detail": e.to_string() })),
            )
        })?;

    if row.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "detail": format!("Recording for Game ID '{clean_id}' not found")
            })),
        ));
    }

    delete_recording_file(&clean_id, &state.config.storage_dir).await;
    let _ = sqlx::query("DELETE FROM recordings WHERE game_id = ?1")
        .bind(&clean_id)
        .execute(&state.db)
        .await;

    Ok(Json(MessageResponse {
        message: format!("Recording '{clean_id}' successfully deleted"),
        game_id: Some(clean_id),
    }))
}
