pub mod auth;
pub mod router;

use axum::routing::{delete, get, post};
use axum::Router;

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(router::get_dashboard_ui))
        .route("/api/recordings", get(router::get_web_recordings))
        .route("/api/security/blocked-ips", get(router::get_blocked_ips))
        .route(
            "/api/security/unblock/{ip}",
            post(router::unblock_banned_ip),
        )
        .route("/api/security/block/{ip}", post(router::manual_ban_ip))
        .route("/api/security/activity", get(router::get_ip_activity))
        .route("/download/{game_id}", get(router::web_download_recording))
        .route("/stream/{game_id}", get(router::web_stream_recording))
        .route("/upload/{game_id}", post(router::web_upload_recording))
        .route(
            "/recordings/{game_id}",
            delete(router::web_delete_recording),
        )
}
