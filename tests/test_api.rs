mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;

use common::{
    TEST_ADMIN_KEY, TEST_PULL_KEY, TEST_UPLOAD_KEY, TestApp, build_multipart,
    generate_valid_mp3_bytes,
};

#[tokio::test]
async fn test_health_check_permissions() {
    let app = TestApp::new().await;

    // 1. Missing API Key -> 401
    let req = Request::builder()
        .uri("/api/v1/health")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 2. Invalid API Key -> 401
    let req = Request::builder()
        .uri("/api/v1/health")
        .header("X-API-Key", "invalid-secret-key-12345")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 3. Valid PULL_KEY -> 200
    let req = Request::builder()
        .uri("/api/v1/health")
        .header("X-API-Key", TEST_PULL_KEY)
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["authenticated_role"], "pull");
    assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));

    // 4. Valid UPLOAD_KEY -> 200
    let req = Request::builder()
        .uri("/api/v1/health")
        .header("X-API-Key", TEST_UPLOAD_KEY)
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["authenticated_role"], "upload");

    // 5. Valid ADMIN_KEY -> 200
    let req = Request::builder()
        .uri("/api/v1/health")
        .header("X-API-Key", TEST_ADMIN_KEY)
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["authenticated_role"], "admin");
}

#[tokio::test]
async fn test_recordings_list_and_get() {
    let app = TestApp::new().await;

    // List empty recordings
    let req = Request::builder()
        .uri("/api/v1/recordings")
        .header("X-API-Key", TEST_PULL_KEY)
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total"], 0);
    assert!(json["items"].as_array().unwrap().is_empty());

    // Get non-existent recording -> 404
    let req = Request::builder()
        .uri("/api/v1/recordings/EUW1_9999999999")
        .header("X-API-Key", TEST_PULL_KEY)
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_recording_permissions() {
    let app = TestApp::new().await;

    // 1. Delete without API Key -> 401
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/recordings/EUW1_12345")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 2. Delete with PULL_KEY -> 403 Forbidden
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/recordings/EUW1_12345")
        .header("X-API-Key", TEST_PULL_KEY)
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 3. Delete with UPLOAD_KEY -> 403 Forbidden
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/recordings/EUW1_12345")
        .header("X-API-Key", TEST_UPLOAD_KEY)
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 4. Delete non-existent recording with ADMIN_KEY -> 404
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/recordings/EUW1_12345")
        .header("X-API-Key", TEST_ADMIN_KEY)
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_patch_recording_metadata() {
    let app = TestApp::new().await;
    let mp3_bytes = generate_valid_mp3_bytes(10);
    let (body_bytes, content_type) = build_multipart(&[
        ("file", Some("scrim.mp3"), &mp3_bytes),
        ("team_tag", None, b"T1"),
        ("notes", None, b"Initial note"),
        ("match_date", None, b"2026-11-27"),
    ]);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/recordings/4032473199")
        .header("X-API-Key", TEST_UPLOAD_KEY)
        .header("Content-Type", &content_type)
        .body(Body::from(body_bytes))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let patch_body = serde_json::json!({
        "notes": "Updated scrim notes",
        "team_tag": "G2"
    })
    .to_string();

    // 1. Unauthenticated PATCH -> 401
    let req = Request::builder()
        .method("PATCH")
        .uri("/api/v1/recordings/4032473199")
        .header("Content-Type", "application/json")
        .body(Body::from(patch_body.clone()))
        .unwrap();
    assert_eq!(app.request(req).await.status(), StatusCode::UNAUTHORIZED);

    // 2. PULL_KEY PATCH -> 403 Forbidden
    let req = Request::builder()
        .method("PATCH")
        .uri("/api/v1/recordings/4032473199")
        .header("X-API-Key", TEST_PULL_KEY)
        .header("Content-Type", "application/json")
        .body(Body::from(patch_body.clone()))
        .unwrap();
    assert_eq!(app.request(req).await.status(), StatusCode::FORBIDDEN);

    // 3. Non-existent game_id -> 404
    let req = Request::builder()
        .method("PATCH")
        .uri("/api/v1/recordings/9999999999")
        .header("X-API-Key", TEST_UPLOAD_KEY)
        .header("Content-Type", "application/json")
        .body(Body::from(patch_body.clone()))
        .unwrap();
    assert_eq!(app.request(req).await.status(), StatusCode::NOT_FOUND);

    // 4. Valid UPLOAD_KEY partial PATCH -> 200 OK, keeps match_date intact
    let req = Request::builder()
        .method("PATCH")
        .uri("/api/v1/recordings/4032473199")
        .header("X-API-Key", TEST_UPLOAD_KEY)
        .header("Content-Type", "application/json")
        .body(Body::from(patch_body))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["team_tag"], "G2");
    assert_eq!(json["notes"], "Updated scrim notes");
    assert_eq!(json["match_date"], "2026-11-27");

    // 5. Clear notes with null and verify GET reflects changes
    let clear_body = serde_json::json!({ "notes": null }).to_string();
    let req = Request::builder()
        .method("PATCH")
        .uri("/api/v1/recordings/4032473199")
        .header("X-API-Key", TEST_UPLOAD_KEY)
        .header("Content-Type", "application/json")
        .body(Body::from(clear_body))
        .unwrap();
    assert_eq!(app.request(req).await.status(), StatusCode::OK);

    let req = Request::builder()
        .uri("/api/v1/recordings/4032473199")
        .header("X-API-Key", TEST_PULL_KEY)
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["team_tag"], "G2");
    assert!(json["notes"].is_null());
    assert_eq!(json["match_date"], "2026-11-27");
}
