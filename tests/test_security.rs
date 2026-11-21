mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};

use common::{TEST_UPLOAD_KEY, TestApp};

#[tokio::test]
async fn test_scanner_probe_instant_ban() {
    let app = TestApp::new().await;
    let untrusted_ip = "198.51.100.42";

    // Request to /.env from untrusted IP
    let req = Request::builder()
        .uri("/.env")
        .header("X-Real-IP", untrusted_ip)
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // IP is now permanently banned: subsequent normal request is blocked with 429
    let req2 = Request::builder()
        .uri("/api/v1/recordings")
        .header("X-Real-IP", untrusted_ip)
        .header("X-API-Key", TEST_UPLOAD_KEY)
        .body(Body::empty())
        .unwrap();
    let resp2 = app.request(req2).await;
    assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn test_suspicious_http_method_blocked() {
    let app = TestApp::new().await;
    let untrusted_ip = "198.51.100.43";

    let req = Request::builder()
        .method("PROPFIND")
        .uri("/")
        .header("X-Real-IP", untrusted_ip)
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_brute_force_auth_blocking() {
    let app = TestApp::new().await;
    let attack_ip = "198.51.100.77";

    // 4 failed auth attempts -> 401
    for _ in 0..4 {
        let req = Request::builder()
            .uri("/api/v1/health")
            .header("X-Real-IP", attack_ip)
            .header("X-API-Key", "wrong-password")
            .body(Body::empty())
            .unwrap();
        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // 5th failed attempt triggers block
    let req = Request::builder()
        .uri("/api/v1/health")
        .header("X-Real-IP", attack_ip)
        .header("X-API-Key", "wrong-password")
        .body(Body::empty())
        .unwrap();
    let _ = app.request(req).await;

    // Subsequent request is blocked with 429
    let req_blocked = Request::builder()
        .uri("/api/v1/health")
        .header("X-Real-IP", attack_ip)
        .header("X-API-Key", TEST_UPLOAD_KEY)
        .body(Body::empty())
        .unwrap();
    let resp_blocked = app.request(req_blocked).await;
    assert_eq!(resp_blocked.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(resp_blocked.headers().contains_key(header::RETRY_AFTER));
}
