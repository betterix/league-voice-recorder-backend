use axum::extract::{Extension, Multipart, Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use crate::audio::storage::{
    build_range_download_response, delete_recording_file, stream_save_upload, validate_game_id,
};
use crate::db::models::{now_iso, IPActivity, Recording, RecordingMetadataResponse};
use crate::web::auth::{extract_basic_auth, is_web_ip_allowed, verify_basic_auth};
use crate::{AppState, ClientIp};

const DASHBOARD_HTML: &str = include_str!("dashboard.html");

#[derive(Debug, Deserialize)]
pub struct ActivityQuery {
    pub category: Option<String>,
    pub search: Option<String>,
    #[serde(default = "default_activity_limit")]
    pub limit: i64,
}

fn default_activity_limit() -> i64 {
    100
}

#[derive(Debug, Deserialize)]
pub struct BanIPPayload {
    pub reason: Option<String>,
}

async fn check_web_auth(
    client_ip: &str,
    headers: &HeaderMap,
    state: &AppState,
) -> Result<String, Response> {
    if !state.config.web_enabled {
        return Err((StatusCode::NOT_FOUND, "Not Found").into_response());
    }

    // 1. IP Whitelist - cloak with 404 for unauthorized IPs
    if !is_web_ip_allowed(client_ip, &state.config.web_allowed_ips) {
        return Err((StatusCode::NOT_FOUND, "Not Found").into_response());
    }

    // 2. Check if IP is blocked
    let (is_blocked, remaining) = state.rate_limiter.is_ip_blocked(client_ip);
    if is_blocked {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, remaining.to_string())],
            Json(serde_json::json!({
                "detail": format!("Too many failed attempts. Try again in {remaining} seconds.")
            })),
        )
            .into_response());
    }

    // 3. HTTP Basic Auth
    match extract_basic_auth(headers) {
        Some((user, pass)) => {
            if verify_basic_auth(&user, &pass, &state.config) {
                Ok(user)
            } else {
                state
                    .rate_limiter
                    .record_auth_failure(
                        Some(&state.db),
                        client_ip,
                        state.config.auth_failure_limit_per_minute,
                        60.0,
                        state.config.auth_block_duration_minutes,
                    )
                    .await;
                Err((
                    StatusCode::UNAUTHORIZED,
                    [(
                        header::WWW_AUTHENTICATE,
                        "Basic realm=\"League Voice Recorder Dashboard\"",
                    )],
                    Json(serde_json::json!({ "detail": "Invalid username or password" })),
                )
                    .into_response())
            }
        }
        None => Err((
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                "Basic realm=\"League Voice Recorder Dashboard\"",
            )],
            Json(serde_json::json!({ "detail": "Authentication required" })),
        )
            .into_response()),
    }
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

pub async fn get_dashboard_ui(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let username = check_web_auth(&client_ip, &headers, &state).await?;

    let rendered = DASHBOARD_HTML
        .replace("__CLIENT_IP__", &escape_html(&client_ip))
        .replace("__USERNAME__", &escape_html(&username));

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store, max-age=0"),
        ],
        Html(rendered),
    )
        .into_response())
}

pub async fn get_web_recordings(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, Response> {
    check_web_auth(&client_ip, &headers, &state).await?;

    let rows = sqlx::query_as::<_, Recording>(
        r#"
        SELECT id, game_id, filename, file_size, duration, bitrate, sample_rate,
               sha256, team_tag, notes, match_date, created_at, updated_at
        FROM recordings
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())?;

    let items: Vec<RecordingMetadataResponse> = rows.into_iter().map(Into::into).collect();

    let (total_b, used_b, free_b) = match sysinfo::Disks::new_with_refreshed_list() {
        Ok(disks) => match disks
            .iter()
            .find(|d| state.config.storage_dir.starts_with(d.mount_point()))
        {
            Some(disk) => (
                disk.total_space(),
                disk.total_space().saturating_sub(disk.available_space()),
                disk.available_space(),
            ),
            None => (0, 0, 0),
        },
        Err(_) => (0, 0, 0),
    };

    let blocked_ips_val = state.rate_limiter.get_blocked_ips();
    let blocked_count = blocked_ips_val.as_object().map(|m| m.len()).unwrap_or(0);

    Ok(Json(serde_json::json!({
        "items": items,
        "total": items.len(),
        "storage_total_bytes": total_b,
        "storage_used_bytes": used_b,
        "storage_free_bytes": free_b,
        "blocked_ips_count": blocked_count,
    })))
}

pub async fn get_blocked_ips(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, Response> {
    check_web_auth(&client_ip, &headers, &state).await?;

    let ips = state.rate_limiter.get_blocked_ips();
    Ok(Json(serde_json::json!({ "blocked_ips": ips })))
}

pub async fn unblock_banned_ip(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    headers: HeaderMap,
    AxumPath(ip): AxumPath<String>,
) -> Result<Json<serde_json::Value>, Response> {
    check_web_auth(&client_ip, &headers, &state).await?;

    let unblocked = state.rate_limiter.unblock_ip(Some(&state.db), &ip).await;
    let msg = if unblocked {
        format!("IP {ip} unblocked and rate limits reset")
    } else {
        format!("IP {ip} was not blocked, rate limits reset")
    };

    Ok(Json(serde_json::json!({
        "ip": ip,
        "unblocked": unblocked,
        "removed": unblocked,
        "success": true,
        "message": msg
    })))
}

pub async fn manual_ban_ip(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    headers: HeaderMap,
    AxumPath(ip): AxumPath<String>,
    payload: Option<Json<BanIPPayload>>,
) -> Result<Json<serde_json::Value>, Response> {
    check_web_auth(&client_ip, &headers, &state).await?;

    let reason = payload
        .and_then(|p| p.0.reason)
        .unwrap_or_else(|| "Manually banned by administrator".to_string());

    state
        .rate_limiter
        .ban_ip_permanent(Some(&state.db), &ip, &reason)
        .await;

    Ok(Json(serde_json::json!({
        "ip": ip,
        "banned": true,
        "success": true,
        "message": format!("IP {ip} permanently banned in database.")
    })))
}

pub async fn get_ip_activity(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    headers: HeaderMap,
    Query(query): Query<ActivityQuery>,
) -> Result<Json<serde_json::Value>, Response> {
    check_web_auth(&client_ip, &headers, &state).await?;

    let limit = query.limit.clamp(1, 200);

    let items = if let Some(cat) = &query.category {
        if cat != "all" {
            sqlx::query_as::<_, IPActivity>(
                r#"
                SELECT id, ip, method, path, status_code, category, details, created_at
                FROM ip_activity
                WHERE ip NOT IN ('127.0.0.1', '::1', 'localhost', 'testclient') AND category = ?1
                ORDER BY created_at DESC
                LIMIT ?2
                "#,
            )
            .bind(cat.to_lowercase())
            .bind(limit)
            .fetch_all(&state.db)
            .await
            .unwrap_or_default()
        } else {
            sqlx::query_as::<_, IPActivity>(
                r#"
                SELECT id, ip, method, path, status_code, category, details, created_at
                FROM ip_activity
                WHERE ip NOT IN ('127.0.0.1', '::1', 'localhost', 'testclient')
                ORDER BY created_at DESC
                LIMIT ?1
                "#,
            )
            .bind(limit)
            .fetch_all(&state.db)
            .await
            .unwrap_or_default()
        }
    } else {
        sqlx::query_as::<_, IPActivity>(
            r#"
            SELECT id, ip, method, path, status_code, category, details, created_at
            FROM ip_activity
            WHERE ip NOT IN ('127.0.0.1', '::1', 'localhost', 'testclient')
            ORDER BY created_at DESC
            LIMIT ?1
            "#,
        )
        .bind(limit)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default()
    };

    // Calculate category summary counts
    let count_all: (i64,) = sqlx::query_as(
        "SELECT COUNT(id) FROM ip_activity WHERE ip NOT IN ('127.0.0.1', '::1', 'localhost', 'testclient')",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or((0,));

    let count_download: (i64,) = sqlx::query_as(
        "SELECT COUNT(id) FROM ip_activity WHERE ip NOT IN ('127.0.0.1', '::1', 'localhost', 'testclient') AND category = 'download'",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or((0,));

    let count_suspicious: (i64,) = sqlx::query_as(
        "SELECT COUNT(id) FROM ip_activity WHERE ip NOT IN ('127.0.0.1', '::1', 'localhost', 'testclient') AND category = 'suspicious'",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or((0,));

    let count_blocked: (i64,) = sqlx::query_as(
        "SELECT COUNT(id) FROM ip_activity WHERE ip NOT IN ('127.0.0.1', '::1', 'localhost', 'testclient') AND category = 'blocked'",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or((0,));

    let count_api: (i64,) = sqlx::query_as(
        "SELECT COUNT(id) FROM ip_activity WHERE ip NOT IN ('127.0.0.1', '::1', 'localhost', 'testclient') AND category = 'api'",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or((0,));

    let counts = serde_json::json!({
        "all": count_all.0,
        "download": count_download.0,
        "suspicious": count_suspicious.0,
        "blocked": count_blocked.0,
        "api": count_api.0,
    });

    let mut enriched_items = Vec::new();
    for ev in items {
        let intel = state.ip_intel.get_ip_info(&ev.ip);
        let isp = intel
            .as_ref()
            .map(|i| {
                if !i.org.is_empty() {
                    i.org.clone()
                } else {
                    i.isp.clone()
                }
            })
            .unwrap_or_default();
        let is_datacenter = intel.as_ref().map(|i| i.is_datacenter).unwrap_or(false);

        enriched_items.push(serde_json::json!({
            "id": ev.id,
            "ip": ev.ip,
            "method": ev.method,
            "path": ev.path,
            "status_code": ev.status_code,
            "category": ev.category,
            "details": ev.details.unwrap_or_default(),
            "isp": isp,
            "is_datacenter": is_datacenter,
            "created_at": ev.created_at,
        }));
    }

    Ok(Json(serde_json::json!({
        "items": enriched_items,
        "total": enriched_items.len(),
        "counts": counts,
        "blocked_ips": state.rate_limiter.get_blocked_ips(),
    })))
}

pub async fn web_download_recording(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    headers: HeaderMap,
    AxumPath(game_id): AxumPath<String>,
) -> Result<Response, Response> {
    check_web_auth(&client_ip, &headers, &state).await?;

    let clean_id = validate_game_id(&game_id)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()).into_response())?;

    let range_hdr = headers.get("range").and_then(|v| v.to_str().ok());
    build_range_download_response(&clean_id, range_hdr, &state.config.storage_dir, false)
        .await
        .map_err(|e| e.into_response())
}

pub async fn web_stream_recording(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    headers: HeaderMap,
    AxumPath(game_id): AxumPath<String>,
) -> Result<Response, Response> {
    check_web_auth(&client_ip, &headers, &state).await?;

    let clean_id = validate_game_id(&game_id)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()).into_response())?;

    let range_hdr = headers.get("range").and_then(|v| v.to_str().ok());
    build_range_download_response(&clean_id, range_hdr, &state.config.storage_dir, true)
        .await
        .map_err(|e| e.into_response())
}

pub async fn web_upload_recording(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    headers: HeaderMap,
    AxumPath(game_id): AxumPath<String>,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<RecordingMetadataResponse>), Response> {
    check_web_auth(&client_ip, &headers, &state).await?;

    let clean_id = validate_game_id(&game_id)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()).into_response())?;

    let existing: Option<(i64,)> = sqlx::query_as("SELECT id FROM recordings WHERE game_id = ?1")
        .bind(&clean_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())?;

    if existing.is_some() {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "detail": format!("Recording for Game ID '{clean_id}' already exists")
            })),
        )
            .into_response());
    }

    let mut team_tag: Option<String> = None;
    let mut notes: Option<String> = None;
    let mut upload_processed = None;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid multipart data: {e}"),
        )
            .into_response()
    })? {
        let name = field.name().unwrap_or("").to_string();
        if name == "file" {
            let res = stream_save_upload(
                field,
                &clean_id,
                None,
                &state.config.storage_dir,
                state.config.max_upload_bytes(),
                state.config.max_upload_mb,
            )
            .await
            .map_err(|e| e.into_response())?;
            upload_processed = Some(res);
        } else if name == "team_tag" {
            if let Ok(text) = field.text().await {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    team_tag = Some(trimmed.to_uppercase());
                }
            }
        } else if name == "notes" {
            if let Ok(text) = field.text().await {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    notes = Some(trimmed.to_string());
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
            )
                .into_response());
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
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10, ?10)
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
    .bind(&now_str)
    .execute(&state.db)
    .await;

    if let Err(e) = insert_res {
        delete_recording_file(&clean_id, &state.config.storage_dir).await;
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "detail": format!("Database insertion failed: {e}") })),
        )
            .into_response());
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
        match_date: None,
        sha256: processed.sha256,
    };

    Ok((StatusCode::CREATED, Json(metadata)))
}

pub async fn web_delete_recording(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    headers: HeaderMap,
    AxumPath(game_id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, Response> {
    check_web_auth(&client_ip, &headers, &state).await?;

    let clean_id = validate_game_id(&game_id)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()).into_response())?;

    delete_recording_file(&clean_id, &state.config.storage_dir).await;
    let _ = sqlx::query("DELETE FROM recordings WHERE game_id = ?1")
        .bind(&clean_id)
        .execute(&state.db)
        .await;

    Ok(Json(serde_json::json!({
        "message": format!("Recording '{clean_id}' successfully deleted"),
        "game_id": clean_id,
    })))
}
