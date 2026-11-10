"""API tests covering health checks, listing, search, metadata, and deletion."""

from fastapi.testclient import TestClient

from app.config import Settings
from tests.conftest import (
    TEST_ADMIN_KEY,
    TEST_PULL_KEY,
    TEST_UPLOAD_KEY,
    generate_valid_mp3_bytes,
)


def _seed_recordings(client: TestClient) -> list[str]:
    """Seed sample recordings for listing and query tests."""
    mp3_data = generate_valid_mp3_bytes(num_frames=5)
    samples = [
        ("8018190301", "T1", "Scrim vs Gen.G game 1", "2026-11-01"),
        ("8018190302", "T1", "Scrim vs Gen.G game 2", "2026-11-01"),
        ("8018190303", "FNC", "Scrim vs G2 game 1", "2026-11-02"),
        ("8018190304", "G2", "Scrim vs FNC game 1", "2026-11-02"),
    ]

    created = []
    for game_id, team, notes, date in samples:
        resp = client.post(
            f"/api/v1/recordings/{game_id}",
            files={"file": (f"{game_id}.mp3", mp3_data, "audio/mpeg")},
            data={"team_tag": team, "notes": notes, "match_date": date},
            headers={"X-API-Key": TEST_UPLOAD_KEY},
        )
        assert resp.status_code == 201
        created.append(game_id)
    return created


def test_health_endpoint_requires_api_key(client: TestClient):
    """Verify health endpoint strictly requires a valid API key."""
    # Unauthenticated request -> 401
    resp_unauth = client.get("/api/v1/health")
    assert resp_unauth.status_code == 401
    assert "Missing" in resp_unauth.json()["detail"]

    # Invalid key -> 401
    resp_invalid = client.get("/api/v1/health", headers={"X-API-Key": "wrong-key"})
    assert resp_invalid.status_code == 401
    assert "Invalid" in resp_invalid.json()["detail"]


def test_health_endpoint_authenticated(client: TestClient):
    """Verify authenticated health endpoint returns role and storage diagnostic metrics."""
    # Pull role
    resp_pull = client.get(
        "/api/v1/health",
        headers={"X-API-Key": TEST_PULL_KEY},
    )
    assert resp_pull.status_code == 200
    data_pull = resp_pull.json()
    assert data_pull["authenticated_role"] == "pull"
    assert data_pull["recording_count"] is not None

    # Upload role
    resp_upload = client.get(
        "/api/v1/health",
        headers={"X-API-Key": TEST_UPLOAD_KEY},
    )
    assert resp_upload.status_code == 200
    assert resp_upload.json()["authenticated_role"] == "upload"

    # Admin role
    resp_admin = client.get(
        "/api/v1/health",
        headers={"X-API-Key": TEST_ADMIN_KEY},
    )
    assert resp_admin.status_code == 200
    assert resp_admin.json()["authenticated_role"] == "admin"


def test_list_recordings_and_pagination(client: TestClient):
    """Verify listing recordings with pagination (skip and limit)."""
    _seed_recordings(client)

    # First page: limit 2
    resp1 = client.get(
        "/api/v1/recordings?skip=0&limit=2",
        headers={"X-API-Key": TEST_PULL_KEY},
    )
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["total"] >= 4
    assert len(data1["items"]) == 2
    assert data1["skip"] == 0
    assert data1["limit"] == 2

    # Second page: skip 2, limit 2
    resp2 = client.get(
        "/api/v1/recordings?skip=2&limit=2",
        headers={"X-API-Key": TEST_PULL_KEY},
    )
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert len(data2["items"]) == 2
    assert data2["skip"] == 2

    # Ensure items on second page are different from first
    ids1 = {item["game_id"] for item in data1["items"]}
    ids2 = {item["game_id"] for item in data2["items"]}
    assert ids1.isdisjoint(ids2)


def test_search_recordings(client: TestClient):
    """Verify search filter by Game ID or Team Tag."""
    _seed_recordings(client)

    # Search by team tag 'T1'
    resp_t1 = client.get(
        "/api/v1/recordings?search=T1",
        headers={"X-API-Key": TEST_PULL_KEY},
    )
    assert resp_t1.status_code == 200
    items_t1 = resp_t1.json()["items"]
    assert len(items_t1) == 2
    assert all(item["team_tag"] == "T1" for item in items_t1)

    # Search by specific Game ID
    resp_id = client.get(
        "/api/v1/recordings?search=8018190303",
        headers={"X-API-Key": TEST_PULL_KEY},
    )
    assert resp_id.status_code == 200
    items_id = resp_id.json()["items"]
    assert len(items_id) == 1
    assert items_id[0]["game_id"] == "8018190303"
    assert items_id[0]["team_tag"] == "FNC"

    # Search with no match
    resp_none = client.get(
        "/api/v1/recordings?search=nonexistentteam",
        headers={"X-API-Key": TEST_PULL_KEY},
    )
    assert resp_none.status_code == 200
    assert resp_none.json()["total"] == 0
    assert len(resp_none.json()["items"]) == 0


def test_get_recording_metadata(client: TestClient):
    """Verify retrieval of metadata for a single recording."""
    mp3_data = generate_valid_mp3_bytes()
    game_id = "8018190350"

    client.post(
        f"/api/v1/recordings/{game_id}",
        files={"file": (f"{game_id}.mp3", mp3_data, "audio/mpeg")},
        data={"team_tag": "GEN", "notes": "Mid-season scrim"},
        headers={"X-API-Key": TEST_UPLOAD_KEY},
    )

    resp = client.get(
        f"/api/v1/recordings/{game_id}",
        headers={"X-API-Key": TEST_PULL_KEY},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["game_id"] == game_id
    assert data["team_tag"] == "GEN"
    assert data["notes"] == "Mid-season scrim"
    assert data["duration"] > 0
    assert data["file_size"] == len(mp3_data)
    assert "upload_timestamp" in data


def test_get_nonexistent_metadata(client: TestClient):
    """Verify 404 for non-existent recording metadata."""
    resp = client.get(
        "/api/v1/recordings/doesnotexist999",
        headers={"X-API-Key": TEST_PULL_KEY},
    )
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_delete_recording_success(client: TestClient, test_settings: Settings):
    """Verify only admin can delete recordings from disk and database."""
    mp3_data = generate_valid_mp3_bytes()
    game_id = "8018190360"

    # Upload
    client.post(
        f"/api/v1/recordings/{game_id}",
        files={"file": (f"{game_id}.mp3", mp3_data, "audio/mpeg")},
        headers={"X-API-Key": TEST_UPLOAD_KEY},
    )

    disk_path = test_settings.STORAGE_DIR / f"{game_id}.mp3"
    assert disk_path.exists()

    # Attempt delete with PULL_KEY -> 403 Forbidden
    del_pull = client.delete(
        f"/api/v1/recordings/{game_id}",
        headers={"X-API-Key": TEST_PULL_KEY},
    )
    assert del_pull.status_code == 403

    # Attempt delete with UPLOAD_KEY -> 403 Forbidden
    del_upload = client.delete(
        f"/api/v1/recordings/{game_id}",
        headers={"X-API-Key": TEST_UPLOAD_KEY},
    )
    assert del_upload.status_code == 403

    # Delete with ADMIN_KEY -> 200 OK
    del_admin = client.delete(
        f"/api/v1/recordings/{game_id}",
        headers={"X-API-Key": TEST_ADMIN_KEY},
    )
    assert del_admin.status_code == 200
    assert f"'{game_id}' successfully deleted" in del_admin.json()["message"]

    # Verify file removed from disk
    assert not disk_path.exists()

    # Verify metadata returns 404
    get_resp = client.get(
        f"/api/v1/recordings/{game_id}",
        headers={"X-API-Key": TEST_PULL_KEY},
    )
    assert get_resp.status_code == 404


def test_delete_nonexistent_recording(client: TestClient):
    """Verify deleting a non-existent recording returns HTTP 404 for admin."""
    del_resp = client.delete(
        "/api/v1/recordings/missing888",
        headers={"X-API-Key": TEST_ADMIN_KEY},
    )
    assert del_resp.status_code == 404
    assert "not found" in del_resp.json()["detail"].lower()
