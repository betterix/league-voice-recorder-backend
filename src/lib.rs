#![allow(clippy::result_large_err)]

pub mod api;
pub mod audio;
pub mod bot_shield;
pub mod config;
pub mod db;
pub mod security;
pub mod web;

use axum::extract::{ConnectInfo, DefaultBodyLimit, Extension, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Json, Router};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::bot_shield::IPIntelService;
use crate::config::Config;
use crate::db::DbPool;
use crate::security::{
    authenticate_key, is_scanner_probe, is_trusted_ip, log_activity_event, InMemoryRateLimiter,
};
use crate::web::auth::is_web_ip_allowed;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: DbPool,
    pub rate_limiter: InMemoryRateLimiter,
    pub ip_intel: IPIntelService,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientIp(pub String);

pub fn get_client_ip(req: &Request, info: Option<ConnectInfo<SocketAddr>>) -> String {
    if let Some(connect_info) = info {
        return connect_info.0.ip().to_string();
    }
    if let Some(h) = req.headers().get("x-real-ip").and_then(|v| v.to_str().ok()) {
        return h.trim().to_string();
    }
    "127.0.0.1".to_string()
}

pub async fn security_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let connect_info = req.extensions().get::<ConnectInfo<SocketAddr>>().cloned();
    let client_ip = get_client_ip(&req, connect_info);
    req.extensions_mut().insert(ClientIp(client_ip.clone()));

    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let full_target = if query.is_empty() {
        path.clone()
    } else {
        format!("{path}?{query}")
    };

    let is_trusted = is_trusted_ip(&client_ip, &state.config.web_allowed_ips);

    // 1. Check if IP is blocked
    let (is_blocked, remaining) = state.rate_limiter.is_ip_blocked(&client_ip);
    if is_blocked {
        let reason = state.rate_limiter.get_block_reason(&client_ip);
        let status = StatusCode::TOO_MANY_REQUESTS;
        let body = serde_json::json!({
            "detail": format!("Too many failed requests. IP temporarily blocked. Try again in {remaining} seconds. Reason: {reason}")
        });
        return (
            status,
            [
                (header::RETRY_AFTER, remaining.to_string()),
                (header::CONTENT_TYPE, "application/json".to_string()),
            ],
            Json(body),
        )
            .into_response();
    }

    // 2. Vulnerability scanner and exploit probe detection
    if state.config.scanner_block_enabled && !is_trusted && is_scanner_probe(&method, &full_target)
    {
        let reason = format!("Malicious scanner probe ({method} {full_target})");
        state
            .rate_limiter
            .ban_ip_permanent(Some(&state.db), &client_ip, &reason)
            .await;

        log_activity_event(
            &state.db,
            &client_ip,
            &method,
            &path,
            StatusCode::FORBIDDEN.as_u16(),
            "blocked",
            Some(&reason),
        )
        .await;

        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "detail": "Access Denied: Vulnerability scanning signature detected" })),
        )
            .into_response();
    }

    // 3. Datacenter / VPS bot shield & Auth Failure tracking
    let api_key = req.headers().get("x-api-key").and_then(|v| v.to_str().ok());
    let (has_valid_api_key, is_invalid_api_key) = match api_key {
        Some(key) => {
            if authenticate_key(Some(key), &state.config).is_some() {
                (true, false)
            } else {
                (false, true)
            }
        }
        None => (false, false),
    };

    if is_invalid_api_key {
        state
            .rate_limiter
            .record_auth_failure(
                Some(&state.db),
                &client_ip,
                state.config.auth_failure_limit_per_minute,
                60.0,
                state.config.auth_block_duration_minutes,
            )
            .await;
    }

    if state.config.datacenter_block_enabled && !is_trusted && !has_valid_api_key {
        let (is_dc, provider) = state
            .ip_intel
            .is_datacenter_ip(Some(&state.db), &client_ip)
            .await;
        if is_dc {
            log_activity_event(
                &state.db,
                &client_ip,
                &method,
                &path,
                StatusCode::FORBIDDEN.as_u16(),
                "blocked",
                Some(&format!("Datacenter bot blocked: {provider}")),
            )
            .await;

            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "detail": "Access Denied: Datacenter and VPS automated traffic is forbidden"
                })),
            )
                .into_response();
        }
    }

    // 4. Rate limiting check
    let is_upload = path.starts_with("/api/v1/recordings") && method == "POST";
    let (category, limit) = if is_upload {
        ("upload", state.config.upload_rate_limit_per_minute)
    } else {
        ("general", state.config.rate_limit_per_minute)
    };

    let (allowed, remaining_quota, retry_after) = state
        .rate_limiter
        .check_rate_limit(&client_ip, category, limit, 60.0);

    if !allowed {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [
                (header::RETRY_AFTER, retry_after.to_string()),
                (header::CONTENT_TYPE, "application/json".to_string()),
            ],
            Json(serde_json::json!({ "detail": "Rate limit exceeded. Please slow down." })),
        )
            .into_response();
    }

    // Call inner handler
    let response = next.run(req).await;
    let status_code = response.status();

    // Heuristic probe tracker (400, 404, 405)
    if (status_code == StatusCode::NOT_FOUND
        || status_code == StatusCode::METHOD_NOT_ALLOWED
        || status_code == StatusCode::BAD_REQUEST)
        && !is_trusted
        && !has_valid_api_key
    {
        let reason = format!(
            "Scanner probe threshold exceeded (HTTP {})",
            status_code.as_u16()
        );
        state
            .rate_limiter
            .record_probe_failure(
                Some(&state.db),
                &client_ip,
                state.config.scanner_failure_threshold,
                state.config.scanner_failure_window_seconds,
                state.config.scanner_block_duration_minutes,
                &reason,
            )
            .await;
    }

    // Activity event logging (omit healthy health check logs)
    let is_health_check = path.starts_with("/api/v1/health") && status_code.is_success();
    if !is_health_check && path != "/favicon.ico" && !path.starts_with("/web/api/security/") {
        let cat = if path.contains("/download")
            && (status_code == StatusCode::OK || status_code == StatusCode::PARTIAL_CONTENT)
        {
            "download"
        } else if status_code.is_client_error() {
            "suspicious"
        } else {
            "api"
        };

        log_activity_event(
            &state.db,
            &client_ip,
            &method,
            &path,
            status_code.as_u16(),
            cat,
            None,
        )
        .await;
    }

    let mut resp = response;
    resp.headers_mut().insert(
        header::HeaderName::from_static("x-content-type-options"),
        header::HeaderValue::from_static("nosniff"),
    );
    resp.headers_mut().insert(
        header::HeaderName::from_static("x-frame-options"),
        header::HeaderValue::from_static("DENY"),
    );
    resp.headers_mut().insert(
        header::HeaderName::from_static("x-ratelimit-limit"),
        header::HeaderValue::from_str(&limit.to_string()).unwrap(),
    );
    resp.headers_mut().insert(
        header::HeaderName::from_static("x-ratelimit-remaining"),
        header::HeaderValue::from_str(&remaining_quota.to_string()).unwrap(),
    );

    resp
}

pub async fn root_handler(
    State(state): State<AppState>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
) -> Result<Redirect, (StatusCode, &'static str)> {
    if state.config.web_enabled && is_web_ip_allowed(&client_ip, &state.config.web_allowed_ips) {
        return Ok(Redirect::temporary("/web"));
    }
    Err((StatusCode::NOT_FOUND, "Not Found"))
}

pub async fn favicon_handler() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

pub fn create_app(state: AppState) -> Router {
    let mut app = Router::new()
        .route("/", get(root_handler))
        .route("/favicon.ico", get(favicon_handler))
        .nest("/api/v1", api::router());

    if state.config.web_enabled {
        app = app.nest("/web", web::router());
    }

    let max_upload_bytes = state.config.max_upload_bytes();

    app.layer(DefaultBodyLimit::max(max_upload_bytes))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_middleware,
        ))
        .with_state(state)
}
