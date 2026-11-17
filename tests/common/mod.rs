use axum::body::Body;
use axum::http::Request;
use axum::response::Response;
use axum::Router;
use std::sync::Arc;
use tower::ServiceExt;

use league_voice_recorder_backend::bot_shield::IPIntelService;
use league_voice_recorder_backend::config::Config;
use league_voice_recorder_backend::db::init_db;
use league_voice_recorder_backend::security::InMemoryRateLimiter;
use league_voice_recorder_backend::{create_app, AppState};

pub const TEST_UPLOAD_KEY: &str = "test-upload-key-secure-random-123456";
pub const TEST_PULL_KEY: &str = "test-pull-key-secure-random-654321";
pub const TEST_ADMIN_KEY: &str = "test-admin-key-secure-random-789012";
pub const TEST_WEB_USER: &str = "admin";
pub const TEST_WEB_PASS: &str = "test-secure-web-password-999";

#[allow(dead_code)]
pub struct TestApp {
    pub app: Router,
    pub state: AppState,
    pub temp_dir: tempfile::TempDir,
}

impl TestApp {
    pub async fn new() -> Self {
        let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
        let base = temp_dir.path();
        let storage_dir = base.join("recordings");
        let db_dir = base.join("db");
        let certs_dir = base.join("certs");

        std::fs::create_dir_all(&storage_dir).unwrap();
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::create_dir_all(&certs_dir).unwrap();

        let config = Config {
            domain_name: "voice.example.com".to_string(),
            port: 8443,
            environment: "test".to_string(),
            storage_dir,
            db_dir: db_dir.clone(),
            upload_key: TEST_UPLOAD_KEY.to_string(),
            pull_key: TEST_PULL_KEY.to_string(),
            admin_key: Some(TEST_ADMIN_KEY.to_string()),
            ssl_cert: certs_dir.join("cert.pem"),
            ssl_key: certs_dir.join("key.pem"),
            dev_self_signed_cert: true,
            max_upload_mb: 10,
            rate_limit_per_minute: 1000,
            upload_rate_limit_per_minute: 50,
            auth_failure_limit_per_minute: 5,
            auth_block_duration_minutes: 5,
            scanner_block_enabled: true,
            scanner_block_duration_minutes: 60,
            scanner_failure_threshold: 5,
            scanner_failure_window_seconds: 60.0,
            datacenter_block_enabled: true,
            web_enabled: true,
            web_allowed_ips: "127.0.0.1,::1,testclient,203.0.113.10".to_string(),
            web_username: TEST_WEB_USER.to_string(),
            web_password: TEST_WEB_PASS.to_string(),
        };

        let db = init_db(&db_dir.join("recordings.db")).await.unwrap();
        let rate_limiter = InMemoryRateLimiter::new();
        let ip_intel = IPIntelService::new();

        let state = AppState {
            config: Arc::new(config),
            db,
            rate_limiter,
            ip_intel,
        };

        let app = create_app(state.clone());

        Self {
            app,
            state,
            temp_dir,
        }
    }

    pub async fn request(&self, req: Request<Body>) -> Response {
        self.app.clone().oneshot(req).await.unwrap()
    }
}

#[allow(dead_code)]
pub fn generate_valid_mp3_bytes(num_frames: usize) -> Vec<u8> {
    // 0xFF 0xFB (sync word + MPEG 1 Layer 3 no CRC)
    // 0x90 (128kbps, 44100Hz, no padding)
    // 0x64 (Stereo, etc.)
    let frame_header = [0xFF, 0xFB, 0x90, 0x64];
    let mut frame = Vec::with_capacity(417);
    frame.extend_from_slice(&frame_header);
    frame.extend_from_slice(&vec![0u8; 413]);

    let mut output = Vec::with_capacity(417 * num_frames);
    for _ in 0..num_frames {
        output.extend_from_slice(&frame);
    }
    output
}

#[allow(dead_code)]
pub fn build_multipart(fields: &[(&str, Option<&str>, &[u8])]) -> (Vec<u8>, String) {
    let boundary = "------------------------boundary123456789";
    let mut body = Vec::new();
    for (name, filename, data) in fields {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        if let Some(fname) = filename {
            body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{fname}\"\r\nContent-Type: audio/mpeg\r\n\r\n")
                    .as_bytes(),
            );
        } else {
            body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
            );
        }
        body.extend_from_slice(data);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    let content_type = format!("multipart/form-data; boundary={boundary}");
    (body, content_type)
}
