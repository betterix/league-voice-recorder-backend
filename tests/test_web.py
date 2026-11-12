"""Unit and integration tests for Web Dashboard, IP authorization, and HTTP Basic Auth."""

import base64

from fastapi.testclient import TestClient

from app.config import Settings, set_settings
from app.main import create_app
from app.web.auth import is_web_ip_allowed
from tests.conftest import (
    TEST_WEB_PASS,
    TEST_WEB_USER,
    generate_valid_mp3_bytes,
)


def _make_basic_auth(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {token}"


def test_is_web_ip_allowed_logic():
    """Verify IP authorization evaluation with exact match, CIDR, wildcard, and localhost."""
    # Localhost defaults
    assert is_web_ip_allowed("127.0.0.1", "203.0.113.50") is True
    assert is_web_ip_allowed("::1", "203.0.113.50") is True
    assert is_web_ip_allowed("localhost", "203.0.113.50") is True
    assert is_web_ip_allowed("testclient", "203.0.113.50") is True

    # Exact match
    assert is_web_ip_allowed("203.0.113.50", "203.0.113.50") is True
    assert is_web_ip_allowed("203.0.113.51", "203.0.113.50") is False

    # Wildcard 0.0.0.0 / *
    assert is_web_ip_allowed("198.51.100.22", "0.0.0.0") is True
    assert is_web_ip_allowed("198.51.100.22", "*") is True

    # CIDR subnet
    assert is_web_ip_allowed("10.50.1.10", "10.50.1.0/24") is True
    assert is_web_ip_allowed("10.50.2.10", "10.50.1.0/24") is False


def test_web_dashboard_unauthenticated(client: TestClient):
    """Verify visiting /web without Basic Auth returns 401 with WWW-Authenticate header."""
    resp = client.get("/web")
    assert resp.status_code == 401
    assert "WWW-Authenticate" in resp.headers
    assert "Basic" in resp.headers["WWW-Authenticate"]


def test_web_dashboard_invalid_credentials(client: TestClient):
    """Verify incorrect credentials return 401 Unauthorized."""
    auth_header = _make_basic_auth("admin", "wrong-password")
    resp = client.get("/web", headers={"Authorization": auth_header})
    assert resp.status_code == 401
    assert "Invalid" in resp.json()["detail"]


def test_web_dashboard_success(client: TestClient):
    """Verify valid Basic Auth renders the HTML dashboard."""
    auth_header = _make_basic_auth(TEST_WEB_USER, TEST_WEB_PASS)
    resp = client.get("/web", headers={"Authorization": auth_header})
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "LEAGUE VOICE RECORDER" in resp.text
    assert "TLS 1.3 Active" in resp.text


def test_web_dashboard_ip_forbidden(client: TestClient, test_settings: Settings):
    """Verify client from unapproved IP receives 404 Not Found cloaking the dashboard."""
    # Configure settings allowing only specific IP
    strict_settings = test_settings.model_copy(update={"WEB_ALLOWED_IPS": "198.51.100.99"})
    set_settings(strict_settings)
    app = create_app()

    # TestClient default client host is 'testclient' which is normally treated as test,
    # so we test using a custom client simulating an unauthorized client host
    from starlette.testclient import TestClient as CustomClient

    c = CustomClient(app, client=("192.0.2.100", 50000))
    auth_header = _make_basic_auth(TEST_WEB_USER, TEST_WEB_PASS)
    resp = c.get("/web", headers={"Authorization": auth_header})
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Not Found"
    assert "WWW-Authenticate" not in resp.headers

    # Also verify unauthenticated request from unauthorized IP gives 404 without WWW-Authenticate
    resp_no_auth = c.get("/web")
    assert resp_no_auth.status_code == 404
    assert resp_no_auth.json()["detail"] == "Not Found"
    assert "WWW-Authenticate" not in resp_no_auth.headers

    # Restore settings
    set_settings(test_settings)


def test_root_endpoint_redirects_for_allowed_ip(client: TestClient):
    """Verify visiting / with an allowed IP redirects to /web."""
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 307
    assert resp.headers["location"] == "/web"


def test_root_endpoint_cloaked_for_unauthorized_ip(test_settings: Settings):
    """Verify visiting / with an unauthorized IP returns 404 Not Found."""
    strict_settings = test_settings.model_copy(update={"WEB_ALLOWED_IPS": "198.51.100.99"})
    set_settings(strict_settings)
    app = create_app()

    from starlette.testclient import TestClient as CustomClient

    c = CustomClient(app, client=("192.0.2.100", 50000))
    resp = c.get("/", follow_redirects=False)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Not Found"

    set_settings(test_settings)


def test_web_dashboard_wildcard_ip(test_settings: Settings):
    """Verify WEB_ALLOWED_IPS=0.0.0.0 allows any client IP."""
    wildcard_settings = test_settings.model_copy(update={"WEB_ALLOWED_IPS": "0.0.0.0"})
    set_settings(wildcard_settings)
    app = create_app()

    from starlette.testclient import TestClient as CustomClient

    c = CustomClient(app, client=("198.51.100.77", 45000))
    auth_header = _make_basic_auth(TEST_WEB_USER, TEST_WEB_PASS)
    resp = c.get("/web", headers={"Authorization": auth_header})
    assert resp.status_code == 200
    assert "LEAGUE VOICE RECORDER" in resp.text

    set_settings(test_settings)


def test_web_api_recordings_and_storage(client: TestClient):
    """Verify /web/api/recordings returns recording items and storage telemetry."""
    auth_header = _make_basic_auth(TEST_WEB_USER, TEST_WEB_PASS)
    resp = client.get("/web/api/recordings", headers={"Authorization": auth_header})
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert "storage_total_bytes" in data


def test_web_upload_stream_download_delete(client: TestClient):
    """Verify full browser lifecycle: upload, stream, download, and delete via /web."""
    auth_header = _make_basic_auth(TEST_WEB_USER, TEST_WEB_PASS)
    mp3_data = generate_valid_mp3_bytes(num_frames=10)
    game_id = "9918273645"

    # 1. Upload via /web/upload/{game_id}
    up_resp = client.post(
        f"/web/upload/{game_id}",
        files={"file": (f"{game_id}.mp3", mp3_data, "audio/mpeg")},
        data={"team_tag": "T1", "notes": "Web uploaded scrim"},
        headers={"Authorization": auth_header},
    )
    assert up_resp.status_code == 201
    assert up_resp.json()["game_id"] == game_id

    # 2. Download via /web/download/{game_id}
    dl_resp = client.get(
        f"/web/download/{game_id}",
        headers={"Authorization": auth_header},
    )
    assert dl_resp.status_code == 200
    assert dl_resp.headers["content-type"] == "audio/mpeg"
    assert "attachment" in dl_resp.headers["content-disposition"]
    assert len(dl_resp.content) == len(mp3_data)

    # 3. Stream inline via /web/stream/{game_id} with Range request
    stream_resp = client.get(
        f"/web/stream/{game_id}",
        headers={"Authorization": auth_header, "Range": "bytes=0-500"},
    )
    assert stream_resp.status_code == 206
    assert "inline" in stream_resp.headers["content-disposition"]
    assert len(stream_resp.content) == 501

    # 4. Delete via /web/recordings/{game_id}
    del_resp = client.delete(
        f"/web/recordings/{game_id}",
        headers={"Authorization": auth_header},
    )
    assert del_resp.status_code == 200
    assert f"'{game_id}' successfully deleted" in del_resp.json()["message"]


def test_web_disabled_returns_404(test_settings: Settings):
    """Verify all /web endpoints return 404 when WEB_ENABLED=False."""
    disabled_settings = test_settings.model_copy(update={"WEB_ENABLED": False})
    set_settings(disabled_settings)
    app = create_app()

    from starlette.testclient import TestClient as CustomClient

    c = CustomClient(app)
    auth_header = _make_basic_auth(TEST_WEB_USER, TEST_WEB_PASS)
    resp = c.get("/web", headers={"Authorization": auth_header})
    assert resp.status_code == 404

    set_settings(test_settings)


def test_web_security_activity_endpoint(client: TestClient):
    """Verify /web/api/security/activity returns categorized event audit trail."""
    auth_header = _make_basic_auth(TEST_WEB_USER, TEST_WEB_PASS)

    # 1. Unauthenticated request returns 401
    resp_unauth = client.get("/web/api/security/activity")
    assert resp_unauth.status_code == 401

    # 2. Authenticated request returns activity logs and counts
    resp = client.get("/web/api/security/activity", headers={"Authorization": auth_header})
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "counts" in data
    assert "all" in data["counts"]
    assert "download" in data["counts"]
    assert "suspicious" in data["counts"]
    assert "blocked" in data["counts"]
    assert "api" in data["counts"]
    assert "blocked_ips" in data

    # 3. Category filtering
    resp_dl = client.get(
        "/web/api/security/activity?category=download",
        headers={"Authorization": auth_header},
    )
    assert resp_dl.status_code == 200

    resp_suspicious = client.get(
        "/web/api/security/activity?category=suspicious&search=test",
        headers={"Authorization": auth_header},
    )
    assert resp_suspicious.status_code == 200


def test_web_security_manual_block_and_unblock(client: TestClient):
    """Verify manual IP blocking and unblocking via web endpoints."""
    auth_header = _make_basic_auth(TEST_WEB_USER, TEST_WEB_PASS)
    test_ip = "198.51.100.88"

    # 1. Block IP
    block_resp = client.post(
        f"/web/api/security/block/{test_ip}",
        json={"reason": "Manual web ban test"},
        headers={"Authorization": auth_header},
    )
    assert block_resp.status_code == 200
    assert block_resp.json()["success"] is True

    # 2. Verify IP is in blocked list
    act_resp = client.get("/web/api/security/activity", headers={"Authorization": auth_header})
    assert act_resp.status_code == 200
    blocked_ips = act_resp.json()["blocked_ips"]
    assert test_ip in blocked_ips
    assert blocked_ips[test_ip]["type"] == "permanent"
    assert "Manual web ban test" in blocked_ips[test_ip]["reason"]

    # 3. Unblock IP
    unblock_resp = client.post(
        f"/web/api/security/unblock/{test_ip}",
        headers={"Authorization": auth_header},
    )
    assert unblock_resp.status_code == 200
    assert unblock_resp.json()["removed"] is True

    # 4. Verify IP is removed from blocked list
    act_resp2 = client.get("/web/api/security/activity", headers={"Authorization": auth_header})
    assert test_ip not in act_resp2.json()["blocked_ips"]

    # 5. Unblocking non-existent IP returns removed=False
    unblock_again = client.post(
        f"/web/api/security/unblock/{test_ip}",
        headers={"Authorization": auth_header},
    )
    assert unblock_again.status_code == 200
    assert unblock_again.json()["removed"] is False
