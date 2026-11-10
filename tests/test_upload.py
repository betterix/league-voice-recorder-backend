"""Upload verification, MP3 validation, checksum integrity, and sanitization tests."""

import hashlib

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import Recording
from tests.conftest import TEST_UPLOAD_KEY, generate_valid_mp3_bytes


def test_successful_mp3_upload(client: TestClient, test_settings: Settings, test_db: Session):
    """Test valid MP3 recording upload with metadata fields."""
    mp3_data = generate_valid_mp3_bytes(num_frames=10)
    game_id = "8018190134"

    response = client.post(
        f"/api/v1/recordings/{game_id}",
        files={"file": (f"{game_id}.mp3", mp3_data, "audio/mpeg")},
        data={
            "team_tag": "T1",
            "notes": "Game 1 vs Gen.G LCK Finals",
            "match_date": "2026-11-10",
        },
        headers={"X-API-Key": TEST_UPLOAD_KEY},
    )

    assert response.status_code == 201
    data = response.json()
    assert data["game_id"] == game_id
    assert data["filename"] == f"{game_id}.mp3"
    assert data["file_size"] == len(mp3_data)
    assert data["duration"] > 0
    assert data["bitrate"] > 0
    assert data["sample_rate"] == 44100
    assert data["team_tag"] == "T1"
    assert data["notes"] == "Game 1 vs Gen.G LCK Finals"
    assert data["match_date"] == "2026-11-10"
    assert data["sha256"] == hashlib.sha256(mp3_data).hexdigest()

    # Verify file exists on disk
    expected_path = test_settings.STORAGE_DIR / f"{game_id}.mp3"
    assert expected_path.exists()
    assert expected_path.read_bytes() == mp3_data

    # Verify database persistence
    rec = test_db.scalar(select(Recording).where(Recording.game_id == game_id))
    assert rec is not None
    assert rec.team_tag == "T1"
    assert rec.sha256 == hashlib.sha256(mp3_data).hexdigest()


def test_upload_with_matching_sha256_header(client: TestClient):
    """Verify upload succeeds when valid SHA-256 header is provided."""
    mp3_data = generate_valid_mp3_bytes()
    expected_hash = hashlib.sha256(mp3_data).hexdigest()
    game_id = "8018190135"

    response = client.post(
        f"/api/v1/recordings/{game_id}",
        files={"file": (f"{game_id}.mp3", mp3_data, "audio/mpeg")},
        headers={
            "X-API-Key": TEST_UPLOAD_KEY,
            "X-Checksum-SHA256": expected_hash,
        },
    )
    assert response.status_code == 201
    assert response.json()["sha256"] == expected_hash


def test_upload_with_mismatched_sha256_header(
    client: TestClient, test_settings: Settings, test_db: Session
):
    """Verify upload is rejected and cleaned up when SHA-256 header does not match."""
    mp3_data = generate_valid_mp3_bytes()
    fake_hash = "a" * 64
    game_id = "8018190136"

    response = client.post(
        f"/api/v1/recordings/{game_id}",
        files={"file": (f"{game_id}.mp3", mp3_data, "audio/mpeg")},
        headers={
            "X-API-Key": TEST_UPLOAD_KEY,
            "X-Checksum-SHA256": fake_hash,
        },
    )
    assert response.status_code == 400
    assert "checksum mismatch" in response.json()["detail"].lower()

    # Ensure no file was committed to storage
    assert not (test_settings.STORAGE_DIR / f"{game_id}.mp3").exists()

    # Ensure no temporary files left in storage
    temp_files = list(test_settings.STORAGE_DIR.glob(".tmp_*"))
    assert len(temp_files) == 0

    # Ensure no database record created
    rec = test_db.scalar(select(Recording).where(Recording.game_id == game_id))
    assert rec is None


def test_upload_corrupt_mp3_file_rejected(
    client: TestClient, test_settings: Settings, test_db: Session
):
    """Ensure non-MP3 files are rejected by content validation."""
    game_id = "8018190137"
    fake_data = b"This is a text file disguising as an MP3 audio recording."

    response = client.post(
        f"/api/v1/recordings/{game_id}",
        files={"file": (f"{game_id}.mp3", fake_data, "audio/mpeg")},
        headers={"X-API-Key": TEST_UPLOAD_KEY},
    )
    assert response.status_code == 400
    assert "Invalid or corrupted MP3" in response.json()["detail"]

    # Verify storage and db cleanliness
    assert not (test_settings.STORAGE_DIR / f"{game_id}.mp3").exists()
    assert len(list(test_settings.STORAGE_DIR.glob(".tmp_*"))) == 0


def test_upload_empty_file_rejected(client: TestClient):
    """Ensure empty files are rejected."""
    game_id = "8018190138"
    response = client.post(
        f"/api/v1/recordings/{game_id}",
        files={"file": (f"{game_id}.mp3", b"", "audio/mpeg")},
        headers={"X-API-Key": TEST_UPLOAD_KEY},
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_upload_size_limit_enforcement(client: TestClient, test_settings: Settings):
    """Ensure uploads exceeding MAX_UPLOAD_MB are rejected with HTTP 413."""
    # Temporarily set MAX_UPLOAD_MB to 1 MB for testing
    original_limit = test_settings.MAX_UPLOAD_MB
    test_settings.MAX_UPLOAD_MB = 1

    try:
        # Create 1.5 MB payload of synthetic frames
        oversized_data = generate_valid_mp3_bytes(num_frames=4000)
        assert len(oversized_data) > 1 * 1024 * 1024

        game_id = "8018190139"
        response = client.post(
            f"/api/v1/recordings/{game_id}",
            files={"file": (f"{game_id}.mp3", oversized_data, "audio/mpeg")},
            headers={"X-API-Key": TEST_UPLOAD_KEY},
        )
        assert response.status_code == 413
        assert "exceeds maximum allowable limit" in response.json()["detail"]

        # Ensure no residual temp files
        assert not (test_settings.STORAGE_DIR / f"{game_id}.mp3").exists()
        assert len(list(test_settings.STORAGE_DIR.glob(".tmp_*"))) == 0
    finally:
        test_settings.MAX_UPLOAD_MB = original_limit


def test_duplicate_game_id_conflict(client: TestClient):
    """Ensure uploading a duplicate Game ID returns HTTP 409 Conflict."""
    mp3_data = generate_valid_mp3_bytes()
    game_id = "8018190140"

    # First upload
    first_resp = client.post(
        f"/api/v1/recordings/{game_id}",
        files={"file": (f"{game_id}.mp3", mp3_data, "audio/mpeg")},
        headers={"X-API-Key": TEST_UPLOAD_KEY},
    )
    assert first_resp.status_code == 201

    # Second upload with same game_id
    second_resp = client.post(
        f"/api/v1/recordings/{game_id}",
        files={"file": (f"{game_id}.mp3", mp3_data, "audio/mpeg")},
        headers={"X-API-Key": TEST_UPLOAD_KEY},
    )
    assert second_resp.status_code == 409
    assert "already exists" in second_resp.json()["detail"]


def test_path_traversal_and_invalid_game_id_rejected(client: TestClient):
    """Verify strict rejection of path traversal sequences and invalid characters."""
    mp3_data = generate_valid_mp3_bytes()

    invalid_ids = [
        "../traversal",
        "..%2Ftraversal",
        "nested/subfolder",
        "nested\\subfolder",
        "game*id",
        "game:id",
        "game!id",
        "game id with spaces",
    ]

    for inv_id in invalid_ids:
        resp = client.post(
            f"/api/v1/recordings/{inv_id}",
            files={"file": ("recording.mp3", mp3_data, "audio/mpeg")},
            headers={"X-API-Key": TEST_UPLOAD_KEY},
        )
        # Should be 400 Bad Request or 404 (if URL path parsing failed in routing)
        assert resp.status_code in (400, 404)


def test_valid_game_id_formats_accepted(client: TestClient):
    """Verify standard alphanumeric, platform-prefixed, and hyphenated Game IDs work."""
    mp3_data = generate_valid_mp3_bytes()
    valid_ids = [
        "8018190141",
        "EUW1_12345678",
        "KR-98765432",
        "NA1_GAME_01",
    ]

    for valid_id in valid_ids:
        resp = client.post(
            f"/api/v1/recordings/{valid_id}",
            files={"file": (f"{valid_id}.mp3", mp3_data, "audio/mpeg")},
            headers={"X-API-Key": TEST_UPLOAD_KEY},
        )
        assert resp.status_code == 201
        assert resp.json()["game_id"] == valid_id
