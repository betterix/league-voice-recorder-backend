pub mod health;
pub mod recordings;

use axum::routing::get;
use axum::Router;

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health::get_health))
        .route("/recordings", get(recordings::list_recordings))
        .route(
            "/recordings/{game_id}",
            get(recordings::get_recording)
                .post(recordings::upload_recording)
                .delete(recordings::delete_recording),
        )
        .route(
            "/recordings/{game_id}/download",
            get(recordings::download_recording),
        )
}
