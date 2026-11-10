"""Recording download tests covering full transfers, HTTP Range requests, and permissions."""

from fastapi.testclient import TestClient

from tests.conftest import (
    TEST_ADMIN_KEY,
    TEST_PULL_KEY,
    TEST_UPLOAD_KEY,
    generate_valid_mp3_bytes,
)


def _upload_sample_recording(client: TestClient, game_id: str) -> bytes:
    """Helper to upload a sample recording."""
    mp3_data = generate_valid_mp3_bytes(num_frames=20)
    resp = client.post(
        f"/api/v1/recordings/{game_id}",
        files={"file": (f"{game_id}.mp3", mp3_data, "audio/mpeg")},
        headers={"X-API-Key": TEST_UPLOAD_KEY},
    )
    assert resp.status_code == 201
    return mp3_data


def test_full_download_success(client: TestClient):
    """Verify standard direct full MP3 file download."""
    game_id = "8018190200"
    raw_mp3 = _upload_sample_recording(client, game_id)

    # Download with pull key
    resp = client.get(
        f"/api/v1/recordings/{game_id}/download",
        headers={"X-API-Key": TEST_PULL_KEY},
    )
    assert resp.status_code == 200
    assert resp.headers["Content-Type"] == "audio/mpeg"
    assert resp.headers["Accept-Ranges"] == "bytes"
    assert resp.headers["Content-Length"] == str(len(raw_mp3))
    assert resp.headers["Content-Disposition"] == f'attachment; filename="{game_id}.mp3"'
    assert resp.content == raw_mp3


def test_range_request_byte_slice(client: TestClient):
    """Verify HTTP Range request with start and end bytes returns 206 Partial Content."""
    game_id = "8018190201"
    raw_mp3 = _upload_sample_recording(client, game_id)
    total_len = len(raw_mp3)

    start = 100
    end = 499
    expected_slice = raw_mp3[start : end + 1]

    resp = client.get(
        f"/api/v1/recordings/{game_id}/download",
        headers={
            "X-API-Key": TEST_PULL_KEY,
            "Range": f"bytes={start}-{end}",
        },
    )
    assert resp.status_code == 206
    assert resp.headers["Content-Range"] == f"bytes {start}-{end}/{total_len}"
    assert resp.headers["Content-Length"] == str(len(expected_slice))
    assert resp.headers["Accept-Ranges"] == "bytes"
    assert resp.content == expected_slice


def test_range_request_from_start_to_end(client: TestClient):
    """Verify HTTP Range request with open end (bytes=start-)."""
    game_id = "8018190202"
    raw_mp3 = _upload_sample_recording(client, game_id)
    total_len = len(raw_mp3)

    start = 500
    expected_slice = raw_mp3[start:]

    resp = client.get(
        f"/api/v1/recordings/{game_id}/download",
        headers={
            "X-API-Key": TEST_PULL_KEY,
            "Range": f"bytes={start}-",
        },
    )
    assert resp.status_code == 206
    assert resp.headers["Content-Range"] == f"bytes {start}-{total_len - 1}/{total_len}"
    assert resp.headers["Content-Length"] == str(len(expected_slice))
    assert resp.content == expected_slice


def test_range_request_suffix(client: TestClient):
    """Verify HTTP Range request with suffix length (bytes=-suffix)."""
    game_id = "8018190203"
    raw_mp3 = _upload_sample_recording(client, game_id)
    total_len = len(raw_mp3)

    suffix_len = 300
    start = total_len - suffix_len
    expected_slice = raw_mp3[start:]

    resp = client.get(
        f"/api/v1/recordings/{game_id}/download",
        headers={
            "X-API-Key": TEST_PULL_KEY,
            "Range": f"bytes=-{suffix_len}",
        },
    )
    assert resp.status_code == 206
    assert resp.headers["Content-Range"] == f"bytes {start}-{total_len - 1}/{total_len}"
    assert resp.content == expected_slice


def test_range_request_invalid_out_of_bounds(client: TestClient):
    """Verify out-of-bounds Range request returns HTTP 416 Range Not Satisfiable."""
    game_id = "8018190204"
    raw_mp3 = _upload_sample_recording(client, game_id)
    total_len = len(raw_mp3)

    resp = client.get(
        f"/api/v1/recordings/{game_id}/download",
        headers={
            "X-API-Key": TEST_PULL_KEY,
            "Range": "bytes=999999-1000000",
        },
    )
    assert resp.status_code == 416
    assert resp.headers["Content-Range"] == f"bytes */{total_len}"


def test_download_permissions(client: TestClient):
    """Verify download access across all authorized roles and unauthenticated callers."""
    game_id = "8018190205"
    _upload_sample_recording(client, game_id)

    # Pull key -> allowed
    assert (
        client.get(
            f"/api/v1/recordings/{game_id}/download",
            headers={"X-API-Key": TEST_PULL_KEY},
        ).status_code
        == 200
    )

    # Upload key -> allowed
    assert (
        client.get(
            f"/api/v1/recordings/{game_id}/download",
            headers={"X-API-Key": TEST_UPLOAD_KEY},
        ).status_code
        == 200
    )

    # Admin key -> allowed
    assert (
        client.get(
            f"/api/v1/recordings/{game_id}/download",
            headers={"X-API-Key": TEST_ADMIN_KEY},
        ).status_code
        == 200
    )

    # Unauthenticated -> 401
    assert client.get(f"/api/v1/recordings/{game_id}/download").status_code == 401

    # Invalid key -> 401
    assert (
        client.get(
            f"/api/v1/recordings/{game_id}/download",
            headers={"X-API-Key": "wrong-key"},
        ).status_code
        == 401
    )


def test_download_nonexistent_recording(client: TestClient):
    """Verify downloading a non-existent recording returns HTTP 404."""
    resp = client.get(
        "/api/v1/recordings/nonexistent999/download",
        headers={"X-API-Key": TEST_PULL_KEY},
    )
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_range_header_parsing_edge_cases():
    """Verify parse_range_header rejects malformed and multi-part specs."""
    from app.storage import parse_range_header

    # Invalid prefix
    assert parse_range_header("characters=0-10", 100) is None
    # Multiple ranges rejected
    assert parse_range_header("bytes=0-10,20-30", 100) is None
    # Malformed parts
    assert parse_range_header("bytes=abc-def", 100) is None
    assert parse_range_header("bytes=-", 100) is None
    assert parse_range_header("bytes=10-5", 100) is None
    assert parse_range_header("bytes=150-", 100) is None
    assert parse_range_header("bytes=-0", 100) is None
