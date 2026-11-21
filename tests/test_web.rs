mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::Value;

use common::{TEST_WEB_PASS, TEST_WEB_USER, TestApp};

fn basic_auth_header(user: &str, pass: &str) -> String {
    let combined = format!("{user}:{pass}");
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, combined);
    format!("Basic {encoded}")
}

#[tokio::test]
async fn test_web_ip_cloaking_and_basic_auth() {
    let app = TestApp::new().await;
    let unauthorized_ip = "198.51.100.99";
    let allowed_ip = "203.0.113.10";

    // 1. Unauthorized IP -> 404 Cloaked
    let req = Request::builder()
        .uri("/web")
        .header("X-Real-IP", unauthorized_ip)
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 2. Allowed IP without Basic Auth -> 401 Unauthorized
    let req = Request::builder()
        .uri("/web")
        .header("X-Real-IP", allowed_ip)
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(resp.headers().contains_key(header::WWW_AUTHENTICATE));

    // 3. Allowed IP with invalid Basic Auth -> 401 Unauthorized
    let req = Request::builder()
        .uri("/web")
        .header("X-Real-IP", allowed_ip)
        .header(
            "Authorization",
            basic_auth_header("admin", "wrong-password"),
        )
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 4. Allowed IP with valid Basic Auth -> 200 OK HTML
    let req = Request::builder()
        .uri("/web")
        .header("X-Real-IP", allowed_ip)
        .header(
            "Authorization",
            basic_auth_header(TEST_WEB_USER, TEST_WEB_PASS),
        )
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body_str = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body_str.contains("League Voice Recorder"));
    assert!(body_str.contains(allowed_ip));
    assert!(body_str.contains(TEST_WEB_USER));
}

#[tokio::test]
async fn test_web_api_endpoints() {
    let app = TestApp::new().await;
    let auth = basic_auth_header(TEST_WEB_USER, TEST_WEB_PASS);

    // 1. Get recordings JSON
    let req = Request::builder()
        .uri("/web/api/recordings")
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total"], 0);

    // 2. Manual ban IP
    let req = Request::builder()
        .method("POST")
        .uri("/web/api/security/block/198.51.100.55")
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // 3. Verify blocked IPs list contains the IP
    let req = Request::builder()
        .uri("/web/api/security/blocked-ips")
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(json["blocked_ips"]["198.51.100.55"].is_object());

    // 4. Unblock the IP
    let req = Request::builder()
        .method("POST")
        .uri("/web/api/security/unblock/198.51.100.55")
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}
