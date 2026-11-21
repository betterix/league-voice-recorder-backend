mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;

use common::{TEST_PULL_KEY, TEST_UPLOAD_KEY, TestApp, build_multipart, generate_valid_mp3_bytes};

#[tokio::test]
async fn test_resumable_download_and_range_requests() {
    let app = TestApp::new().await;
    let mp3_bytes = generate_valid_mp3_bytes(20);
    let total_size = mp3_bytes.len() as u64;

    // Upload recording first
    let (body_bytes, content_type) = build_multipart(&[("file", Some("game.mp3"), &mp3_bytes)]);
    let upload_req = Request::builder()
        .method("POST")
        .uri("/api/v1/recordings/8018190134")
        .header("X-API-Key", TEST_UPLOAD_KEY)
        .header("Content-Type", &content_type)
        .body(Body::from(body_bytes))
        .unwrap();
    let upload_resp = app.request(upload_req).await;
    assert_eq!(upload_resp.status(), StatusCode::CREATED);

    // 1. Full Download (200 OK)
    let req = Request::builder()
        .uri("/api/v1/recordings/8018190134/download")
        .header("X-API-Key", TEST_PULL_KEY)
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get(header::ACCEPT_RANGES).unwrap(), "bytes");
    assert_eq!(
        resp.headers().get(header::CONTENT_LENGTH).unwrap(),
        &total_size.to_string()
    );
    let downloaded_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(downloaded_bytes.as_ref(), &mp3_bytes);

    // 2. Partial Content (206) with Range: bytes=0-100
    let req = Request::builder()
        .uri("/api/v1/recordings/8018190134/download")
        .header("X-API-Key", TEST_PULL_KEY)
        .header("Range", "bytes=0-100")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        resp.headers().get(header::CONTENT_RANGE).unwrap(),
        &format!("bytes 0-100/{total_size}")
    );
    assert_eq!(resp.headers().get(header::CONTENT_LENGTH).unwrap(), "101");
    let slice_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(slice_bytes.len(), 101);
    assert_eq!(slice_bytes.as_ref(), &mp3_bytes[0..=100]);

    // 3. Suffix Range: bytes=-200
    let req = Request::builder()
        .uri("/api/v1/recordings/8018190134/download")
        .header("X-API-Key", TEST_PULL_KEY)
        .header("Range", "bytes=-200")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    let expected_start = total_size - 200;
    assert_eq!(
        resp.headers().get(header::CONTENT_RANGE).unwrap(),
        &format!("bytes {expected_start}-{}/{total_size}", total_size - 1)
    );
    let suffix_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(suffix_bytes.len(), 200);

    // 4. Out of bounds Range -> 416 Range Not Satisfiable
    let req = Request::builder()
        .uri("/api/v1/recordings/8018190134/download")
        .header("X-API-Key", TEST_PULL_KEY)
        .header("Range", "bytes=9999999-")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        resp.headers().get(header::CONTENT_RANGE).unwrap(),
        &format!("bytes */{total_size}")
    );
}
