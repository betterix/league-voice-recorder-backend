mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use sha2::{Digest, Sha256};

use common::{build_multipart, generate_valid_mp3_bytes, TestApp, TEST_PULL_KEY, TEST_UPLOAD_KEY};

#[tokio::test]
async fn test_upload_success_and_permissions() {
    let app = TestApp::new().await;
    let mp3_bytes = generate_valid_mp3_bytes(15);
    let sha256_hex = hex::encode(Sha256::digest(&mp3_bytes));

    let (body_bytes, content_type) = build_multipart(&[
        ("file", Some("scrim.mp3"), &mp3_bytes),
        ("team_tag", None, b"T1"),
        ("notes", None, b"Game 1 vs GenG"),
        ("match_date", None, b"2026-11-17"),
    ]);

    // 1. Unauthenticated -> 401
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/recordings/8018190134")
        .header("Content-Type", &content_type)
        .body(Body::from(body_bytes.clone()))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 2. Read-only PULL_KEY -> 403 Forbidden
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/recordings/8018190134")
        .header("X-API-Key", TEST_PULL_KEY)
        .header("Content-Type", &content_type)
        .body(Body::from(body_bytes.clone()))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 3. Valid UPLOAD_KEY with SHA256 checksum -> 201 Created
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/recordings/8018190134")
        .header("X-API-Key", TEST_UPLOAD_KEY)
        .header("X-Checksum-SHA256", &sha256_hex)
        .header("Content-Type", &content_type)
        .body(Body::from(body_bytes.clone()))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["game_id"], "8018190134");
    assert_eq!(json["team_tag"], "T1");
    assert_eq!(json["sha256"], sha256_hex);
    assert_eq!(json["sample_rate"], 44100);
    assert_eq!(json["bitrate"], 128000);

    // 4. Duplicate upload of same Game ID -> 409 Conflict
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/recordings/8018190134")
        .header("X-API-Key", TEST_UPLOAD_KEY)
        .header("Content-Type", &content_type)
        .body(Body::from(body_bytes.clone()))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_upload_checksum_mismatch() {
    let app = TestApp::new().await;
    let mp3_bytes = generate_valid_mp3_bytes(10);
    let (body_bytes, content_type) = build_multipart(&[("file", Some("audio.mp3"), &mp3_bytes)]);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/recordings/EUW1_8888")
        .header("X-API-Key", TEST_UPLOAD_KEY)
        .header(
            "X-Checksum-SHA256",
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .header("Content-Type", &content_type)
        .body(Body::from(body_bytes))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_upload_invalid_mp3() {
    let app = TestApp::new().await;
    let fake_data = b"This is not a valid MP3 byte stream with frames!";
    let (body_bytes, content_type) = build_multipart(&[("file", Some("audio.mp3"), fake_data)]);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/recordings/EUW1_7777")
        .header("X-API-Key", TEST_UPLOAD_KEY)
        .header("Content-Type", &content_type)
        .body(Body::from(body_bytes))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_upload_directory_traversal_rejected() {
    let app = TestApp::new().await;
    let mp3_bytes = generate_valid_mp3_bytes(5);
    let (body_bytes, content_type) = build_multipart(&[("file", Some("audio.mp3"), &mp3_bytes)]);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/recordings/..%2f..%2fetc%2fpasswd")
        .header("X-API-Key", TEST_UPLOAD_KEY)
        .header("Content-Type", &content_type)
        .body(Body::from(body_bytes))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
