"""Security, authentication, authorization, rate limiting, and TLS tests."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.security import (
    Role,
    authenticate_key,
    generate_self_signed_cert,
    is_scanner_probe,
    is_trusted_ip,
    rate_limiter,
    validate_tls_certificates,
    verify_secret_constant_time,
)
from tests.conftest import (
    TEST_ADMIN_KEY,
    TEST_PULL_KEY,
    TEST_UPLOAD_KEY,
    generate_valid_mp3_bytes,
)


def test_verify_secret_constant_time():
    """Verify secrets comparison behaves securely with matching and non-matching secrets."""
    assert verify_secret_constant_time("my-secret", "my-secret") is True
    assert verify_secret_constant_time("my-secret", "wrong-secret") is False
    assert verify_secret_constant_time("", "secret") is False
    assert verify_secret_constant_time(None, "secret") is False
    assert verify_secret_constant_time("secret", None) is False
    assert verify_secret_constant_time("  secret  ", "secret") is True


def test_authenticate_key(test_settings: Settings):
    """Verify role mapping according to provided API key."""
    assert authenticate_key(TEST_UPLOAD_KEY, test_settings) == Role.UPLOAD
    assert authenticate_key(TEST_PULL_KEY, test_settings) == Role.PULL
    assert authenticate_key(TEST_ADMIN_KEY, test_settings) == Role.ADMIN
    assert authenticate_key("invalid-secret-key", test_settings) is None
    assert authenticate_key("", test_settings) is None
    assert authenticate_key(None, test_settings) is None


def test_missing_and_invalid_api_key(client: TestClient):
    """Ensure missing and invalid keys return HTTP 401."""
    # Missing key
    resp = client.get("/api/v1/recordings")
    assert resp.status_code == 401
    assert "Missing" in resp.json()["detail"]

    # Invalid key
    resp = client.get("/api/v1/recordings", headers={"X-API-Key": "wrong-key"})
    assert resp.status_code == 401
    assert "Invalid" in resp.json()["detail"]


def test_pull_key_forbidden_on_write_endpoints(client: TestClient):
    """Ensure pull key is forbidden (HTTP 403) from write operations (upload, delete)."""
    mp3_data = generate_valid_mp3_bytes()

    # Upload attempt with pull key
    upload_resp = client.post(
        "/api/v1/recordings/8018190001",
        files={"file": ("8018190001.mp3", mp3_data, "audio/mpeg")},
        headers={"X-API-Key": TEST_PULL_KEY},
    )
    assert upload_resp.status_code == 403
    assert "Forbidden" in upload_resp.json()["detail"]

    # Delete attempt with pull key
    del_resp = client.delete(
        "/api/v1/recordings/8018190001",
        headers={"X-API-Key": TEST_PULL_KEY},
    )
    assert del_resp.status_code == 403
    assert "Forbidden" in del_resp.json()["detail"]


def test_upload_key_permissions(client: TestClient):
    """Ensure upload key has full read/write permissions for scrimmage recordings."""
    mp3_data = generate_valid_mp3_bytes()

    # Upload
    upload_resp = client.post(
        "/api/v1/recordings/8018190002",
        files={"file": ("8018190002.mp3", mp3_data, "audio/mpeg")},
        data={"team_tag": "T1"},
        headers={"X-API-Key": TEST_UPLOAD_KEY},
    )
    assert upload_resp.status_code == 201

    # Read / List
    list_resp = client.get(
        "/api/v1/recordings",
        headers={"X-API-Key": TEST_UPLOAD_KEY},
    )
    assert list_resp.status_code == 200
    assert list_resp.json()["total"] >= 1

    # Delete attempt with upload key must be rejected (403 Forbidden)
    del_resp = client.delete(
        "/api/v1/recordings/8018190002",
        headers={"X-API-Key": TEST_UPLOAD_KEY},
    )
    assert del_resp.status_code == 403
    assert "Administrator access required" in del_resp.json()["detail"]

    # Admin delete succeeds
    del_admin = client.delete(
        "/api/v1/recordings/8018190002",
        headers={"X-API-Key": TEST_ADMIN_KEY},
    )
    assert del_admin.status_code == 200


def test_admin_key_permissions(client: TestClient):
    """Ensure admin key possesses master permissions across read, write, and delete."""
    mp3_data = generate_valid_mp3_bytes()

    # Admin upload
    upload_resp = client.post(
        "/api/v1/recordings/8018190003",
        files={"file": ("8018190003.mp3", mp3_data, "audio/mpeg")},
        headers={"X-API-Key": TEST_ADMIN_KEY},
    )
    assert upload_resp.status_code == 201

    # Admin delete
    del_resp = client.delete(
        "/api/v1/recordings/8018190003",
        headers={"X-API-Key": TEST_ADMIN_KEY},
    )
    assert del_resp.status_code == 200


def test_brute_force_ip_blocking(client: TestClient, test_settings: Settings):
    """Ensure repeated authentication failures trigger temporary IP blocking."""
    # Send 5 invalid key requests (limit configured in test_settings)
    for _ in range(test_settings.AUTH_FAILURE_LIMIT_PER_MINUTE):
        resp = client.get("/api/v1/recordings", headers={"X-API-Key": "bad-key"})
        assert resp.status_code == 401

    # 6th request should now be blocked with HTTP 429 and Retry-After
    blocked_resp = client.get("/api/v1/recordings", headers={"X-API-Key": "bad-key"})
    assert blocked_resp.status_code == 429
    assert "Retry-After" in blocked_resp.headers
    assert "temporarily blocked" in blocked_resp.json()["detail"]

    # Even a request with valid credentials from this IP is now temporarily rejected
    valid_resp = client.get("/api/v1/recordings", headers={"X-API-Key": TEST_UPLOAD_KEY})
    assert valid_resp.status_code == 429


def test_rate_limiting_general(client: TestClient):
    """Ensure in-memory rate limiter enforces request limits per minute."""
    rate_limiter.reset()
    client_ip = "127.0.0.1"

    # Consume all available tokens for IP
    for _ in range(10):
        rate_limiter.check_rate_limit(ip=client_ip, category="general", limit_per_minute=10)

    # 11th request should be blocked
    allowed, remaining, retry_after = rate_limiter.check_rate_limit(
        ip=client_ip,
        category="general",
        limit_per_minute=10,
    )
    assert allowed is False
    assert remaining == 0
    assert retry_after > 0


def test_trusted_host_protection(client: TestClient):
    """Verify TrustedHostMiddleware rejects unexpected Host headers."""
    # Disallowed host header
    resp = client.get(
        "/api/v1/health",
        headers={"Host": "malicious-phishing-host.com"},
    )
    assert resp.status_code == 400

    # Allowed host header
    resp_ok = client.get(
        "/api/v1/health",
        headers={"Host": "voice.example.com", "X-API-Key": TEST_PULL_KEY},
    )
    assert resp_ok.status_code == 200


def test_tls_ecdsa_generation_and_validation(temp_workspace: dict[str, Path]):
    """Test ECDSA certificate generation, fingerprint extraction, and validation."""
    cert_path = temp_workspace["certs_dir"] / "test_cert.pem"
    key_path = temp_workspace["certs_dir"] / "test_key.pem"

    fingerprint = generate_self_signed_cert(
        cert_path=cert_path,
        key_path=key_path,
        domain="voice.example.com",
    )

    assert cert_path.exists()
    assert key_path.exists()
    assert len(fingerprint) == 64  # SHA-256 hex string

    valid, msg = validate_tls_certificates(cert_path, key_path)
    assert valid is True
    assert fingerprint in msg


def test_tls_validation_failures(temp_workspace: dict[str, Path]):
    """Ensure validate_tls_certificates safely handles missing and corrupted files."""
    missing_cert = temp_workspace["certs_dir"] / "missing.pem"
    missing_key = temp_workspace["certs_dir"] / "missing.key"

    valid, msg = validate_tls_certificates(missing_cert, missing_key)
    assert valid is False
    assert "not found" in msg

    # Corrupt content
    corrupt_cert = temp_workspace["certs_dir"] / "corrupt.pem"
    corrupt_cert.write_text("corrupted certificate content")
    valid, msg = validate_tls_certificates(corrupt_cert, corrupt_cert)
    assert valid is False
    assert "Failed to parse" in msg


def test_production_settings_validation():
    """Verify strict validation of credentials in production mode."""
    # Insecure default placeholder
    with pytest.raises(ValueError, match="Insecure production credential"):
        Settings(
            ENVIRONMENT="production",
            UPLOAD_KEY="generate-secure-random-upload-secret",
            PULL_KEY="another-random-token-string-12345678",
        )

    # Key too short (less than 32 characters)
    with pytest.raises(ValueError, match="too short"):
        Settings(
            ENVIRONMENT="production",
            UPLOAD_KEY="shortkey-12345678",
            PULL_KEY="another-random-token-string-12345678",
        )

    # Low entropy (repeated characters)
    with pytest.raises(ValueError, match="insufficient entropy"):
        Settings(
            ENVIRONMENT="production",
            UPLOAD_KEY="a" * 40,
            PULL_KEY="another-random-token-string-12345678",
        )

    # Identical keys
    with pytest.raises(ValueError, match="must not be identical"):
        Settings(
            ENVIRONMENT="production",
            UPLOAD_KEY="identical-token-string-1234567890123",
            PULL_KEY="identical-token-string-1234567890123",
        )


def test_generate_secure_api_key():
    """Verify cryptographic token generator format and entropy."""
    from app.security import Role, generate_secure_api_key

    upload_k = generate_secure_api_key(Role.UPLOAD)
    pull_k = generate_secure_api_key(Role.PULL)
    admin_k = generate_secure_api_key(Role.ADMIN)

    assert upload_k.startswith("lvr_upload_")
    assert pull_k.startswith("lvr_pull_")
    assert admin_k.startswith("lvr_admin_")

    # Minimum length and entropy
    assert len(upload_k) >= 40
    assert len(pull_k) >= 40
    assert len(admin_k) >= 40
    assert len(set(upload_k)) >= 16


def test_tls13_context_factory(temp_workspace: dict[str, Path]):
    """Verify tls13_ssl_context_factory creates SSLContext enforcing TLS 1.3."""
    import ssl

    from app.main import tls13_ssl_context_factory

    cert_path = temp_workspace["certs_dir"] / "cert.pem"
    key_path = temp_workspace["certs_dir"] / "key.pem"
    generate_self_signed_cert(cert_path, key_path, "voice.example.com")

    ctx = tls13_ssl_context_factory(
        certfile=str(cert_path),
        keyfile=str(key_path),
        alpn_protocols=["http/1.1"],
    )
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3


@pytest.mark.asyncio
async def test_lifespan_production_tls_success_and_failure(temp_workspace: dict[str, Path]):
    """Verify lifespan validates TLS in production mode and fails safely when invalid."""
    from app.config import set_settings
    from app.main import create_app, lifespan

    cert_path = temp_workspace["certs_dir"] / "prod_cert.pem"
    key_path = temp_workspace["certs_dir"] / "prod_key.pem"

    # 1. Missing cert in production -> raises RuntimeError
    prod_settings_invalid = Settings(
        ENVIRONMENT="production",
        DOMAIN_NAME="voice.example.com",
        UPLOAD_KEY="valid-random-upload-token-12345678",
        PULL_KEY="valid-random-pull-token-65432199",
        WEB_PASSWORD="web-auth-credential-secure-78901234",
        SSL_CERT=cert_path,
        SSL_KEY=key_path,
        STORAGE_DIR=temp_workspace["storage_dir"],
        DB_DIR=temp_workspace["db_dir"],
    )
    set_settings(prod_settings_invalid)
    app = create_app()

    with pytest.raises(RuntimeError, match="Production TLS Certificate validation failed"):
        async with lifespan(app):
            pass

    # 2. Valid cert in production -> succeeds
    generate_self_signed_cert(cert_path, key_path, "voice.example.com")
    prod_settings_valid = Settings(
        ENVIRONMENT="production",
        DOMAIN_NAME="voice.example.com",
        UPLOAD_KEY="valid-random-upload-token-12345678",
        PULL_KEY="valid-random-pull-token-65432199",
        WEB_PASSWORD="web-auth-credential-secure-78901234",
        SSL_CERT=cert_path,
        SSL_KEY=key_path,
        STORAGE_DIR=temp_workspace["storage_dir"],
        DB_DIR=temp_workspace["db_dir"],
    )
    set_settings(prod_settings_valid)
    app_valid = create_app()

    async with lifespan(app_valid):
        # Successfully started inside lifespan context
        assert True


def test_is_trusted_ip():
    """Verify trusted IP evaluation for loopback and configured management IPs."""
    # Loopback defaults
    assert is_trusted_ip("127.0.0.1", "") is True
    assert is_trusted_ip("::1", "") is True
    assert is_trusted_ip("localhost", "") is True
    assert is_trusted_ip("testclient", "") is True

    # Configured specific IP
    assert is_trusted_ip("203.0.113.10", "203.0.113.10,192.168.1.0/24") is True
    assert is_trusted_ip("203.0.113.99", "203.0.113.10,192.168.1.0/24") is False

    # Subnet
    assert is_trusted_ip("192.168.1.50", "203.0.113.10,192.168.1.0/24") is True
    assert is_trusted_ip("192.168.2.50", "203.0.113.10,192.168.1.0/24") is False

    # Wildcards do not grant trusted status from scanner protection
    assert is_trusted_ip("198.51.100.1", "0.0.0.0") is False
    assert is_trusted_ip("198.51.100.1", "*") is False


def test_is_scanner_probe_detection():
    """Verify scanner probe regex and suspicious method detection."""
    from starlette.requests import Request

    def _mock_request(method: str, path: str, query_string: bytes = b"") -> Request:
        scope = {
            "type": "http",
            "method": method,
            "path": path,
            "query_string": query_string,
            "headers": [],
        }
        return Request(scope)

    # Obvious vulnerability / exploit probes
    assert is_scanner_probe(_mock_request("GET", "/.env")) is True
    assert is_scanner_probe(_mock_request("GET", "/.git/config")) is True
    assert is_scanner_probe(_mock_request("GET", "/.DS_Store")) is True
    assert is_scanner_probe(_mock_request("GET", "/.vscode/sftp.json")) is True
    assert is_scanner_probe(_mock_request("GET", "/actuator/env")) is True
    assert is_scanner_probe(_mock_request("GET", "/telescope/requests")) is True
    assert is_scanner_probe(_mock_request("GET", "/trace.axd")) is True
    assert is_scanner_probe(_mock_request("GET", "/info.php")) is True
    assert is_scanner_probe(_mock_request("GET", "/console/")) is True
    assert is_scanner_probe(_mock_request("GET", "/login.action")) is True
    assert is_scanner_probe(_mock_request("GET", "/___proxy_subdomain_whm/login")) is True
    assert is_scanner_probe(_mock_request("GET", "/___proxy_subdomain_cpanel")) is True
    assert is_scanner_probe(_mock_request("GET", "/v2/_catalog")) is True
    assert is_scanner_probe(_mock_request("POST", "/graphql")) is True
    assert is_scanner_probe(_mock_request("POST", "/api/graphql")) is True
    assert is_scanner_probe(_mock_request("POST", "/api/gql")) is True
    assert is_scanner_probe(_mock_request("GET", "/", b"rest_route=/wp/v2/users/")) is True
    assert is_scanner_probe(_mock_request("GET", "/debug/default/view", b"panel=config")) is True
    assert is_scanner_probe(_mock_request("PROPFIND", "/")) is True

    # Legitimate application routes
    assert is_scanner_probe(_mock_request("GET", "/api/v1/health")) is False
    assert is_scanner_probe(_mock_request("GET", "/api/v1/recordings")) is False
    assert is_scanner_probe(_mock_request("GET", "/api/v1/recordings/8018190001")) is False
    assert is_scanner_probe(_mock_request("GET", "/web")) is False
    assert is_scanner_probe(_mock_request("GET", "/web/api/recordings")) is False
    assert is_scanner_probe(_mock_request("GET", "/favicon.ico")) is False


def test_instant_ip_ban_on_scanner_probe(test_settings: Settings):
    """Verify an instant permanent IP ban is enforced on zero-tolerance probes."""
    from starlette.testclient import TestClient as CustomClient

    from app.main import create_app

    app = create_app()
    scanner_ip = "198.51.100.77"
    client = CustomClient(app, client=(scanner_ip, 40000))

    # Probe /.env -> instant ban; gives them nothing (empty 403, connection close)
    resp = client.get("/.env")
    assert resp.status_code == 403
    assert len(resp.content) == 0
    assert resp.headers.get("connection") == "close"

    # Verify IP is tracked as permanently blocked in rate limiter and DB
    assert rate_limiter.is_ip_banned_permanent(scanner_ip) is True

    # Any subsequent request from this IP is now immediately rejected with empty 403
    subsequent = client.get("/api/v1/health", headers={"X-API-Key": TEST_PULL_KEY})
    assert subsequent.status_code == 403
    assert len(subsequent.content) == 0


def test_heuristic_scanner_threshold_ban(test_settings: Settings):
    """Verify repeated 404/400 errors from an untrusted client trigger a permanent IP ban in DB."""
    from starlette.testclient import TestClient as CustomClient

    from app.main import create_app

    app = create_app()
    scanner_ip = "198.51.100.88"
    client = CustomClient(app, client=(scanner_ip, 41000))

    # Probe 4 non-existent paths -> should return 404 without ban yet (threshold is 5)
    for i in range(4):
        resp = client.get(f"/nonexistent-path-{i}")
        assert resp.status_code == 404

    assert rate_limiter.is_ip_banned_permanent(scanner_ip) is False

    # 5th invalid request reaches threshold and triggers ban; gives them nothing
    resp_5 = client.get("/nonexistent-path-final")
    assert resp_5.status_code == 403
    assert len(resp_5.content) == 0

    # 6th request is blocked at middleware with empty 403
    resp_6 = client.get("/api/v1/health")
    assert resp_6.status_code == 403
    assert len(resp_6.content) == 0


def test_authenticated_404_does_not_trigger_scanner_ban(test_settings: Settings):
    """Verify authenticated clients requesting non-existent recordings do not get banned."""
    from starlette.testclient import TestClient as CustomClient

    from app.main import create_app

    app = create_app()
    player_ip = "198.51.100.99"
    client = CustomClient(app, client=(player_ip, 42000))

    # Legitimate authenticated client requests a missing recording 6 times
    for _ in range(6):
        resp = client.get(
            "/api/v1/recordings/9999999999",
            headers={"X-API-Key": TEST_PULL_KEY},
        )
        assert resp.status_code == 404

    # IP should NOT be blocked because it has valid authentication credentials
    is_blocked, _ = rate_limiter.is_ip_blocked(player_ip)
    assert is_blocked is False


def test_trusted_ip_exempt_from_scanner_ban(test_settings: Settings):
    """Verify configured WEB_ALLOWED_IPS and loopback addresses are never banned."""
    from starlette.testclient import TestClient as CustomClient

    from app.main import create_app

    app = create_app()
    # 203.0.113.10 is in test_settings.WEB_ALLOWED_IPS
    trusted_ip = "203.0.113.10"
    client = CustomClient(app, client=(trusted_ip, 43000))

    # Request exploit probe
    resp = client.get("/.env")
    # Trusted IP is exempt from scanner ban; reaches handler / 404
    assert resp.status_code == 404

    is_blocked, _ = rate_limiter.is_ip_blocked(trusted_ip)
    assert is_blocked is False


def test_favicon_endpoint(client: TestClient):
    """Verify /favicon.ico returns HTTP 204 No Content without 404 noise."""
    resp = client.get("/favicon.ico")
    assert resp.status_code == 204
    assert len(resp.content) == 0


def test_manual_ip_unblock_and_list():
    """Verify manual IP blocking, retrieval, and unblocking."""
    rate_limiter.reset()
    test_ip = "198.51.100.123"

    rate_limiter.block_ip(test_ip, duration_minutes=30, reason="Manual admin test ban")
    is_blocked, remaining = rate_limiter.is_ip_blocked(test_ip)
    assert is_blocked is True
    assert remaining > 0

    blocked_list = rate_limiter.get_blocked_ips()
    assert test_ip in blocked_list
    assert "Manual admin test ban" in blocked_list[test_ip]["reason"]

    # Unblock
    unblocked = rate_limiter.unblock_ip(test_ip)
    assert unblocked is True
    is_blocked_after, _ = rate_limiter.is_ip_blocked(test_ip)
    assert is_blocked_after is False


def test_web_security_blocked_ips_endpoints(client: TestClient):
    """Verify web dashboard security management endpoints."""
    import base64

    from tests.conftest import TEST_WEB_PASS, TEST_WEB_USER

    token = base64.b64encode(f"{TEST_WEB_USER}:{TEST_WEB_PASS}".encode()).decode()
    auth = {"Authorization": f"Basic {token}"}

    test_ip = "198.51.100.222"
    rate_limiter.block_ip(test_ip, duration_minutes=15, reason="Scanner test")

    # Get blocked list
    resp = client.get("/web/api/security/blocked-ips", headers=auth)
    assert resp.status_code == 200
    data = resp.json()
    assert "blocked_ips" in data
    assert test_ip in data["blocked_ips"]

    # Unblock IP via web API
    del_resp = client.post(f"/web/api/security/unblock/{test_ip}", headers=auth)
    assert del_resp.status_code == 200
    assert del_resp.json()["unblocked"] is True

    # Verify no longer blocked
    is_blocked, _ = rate_limiter.is_ip_blocked(test_ip)
    assert is_blocked is False


def test_banned_ips_db_persistence(test_settings: Settings):
    """Verify that banned IPs are persisted in the database and reloaded across restarts."""
    from sqlalchemy import select

    from app.database import get_session_factory
    from app.main import create_app
    from app.models import BannedIP

    # Ensure tables are created
    create_app()
    scanner_ip = "198.51.100.199"
    rate_limiter.reset()

    # Ban permanently
    rate_limiter.ban_ip_permanent(scanner_ip, reason="Database persistence test")
    assert rate_limiter.is_ip_banned_permanent(scanner_ip) is True

    # Check it exists in SQLite database
    session_maker = get_session_factory()
    with session_maker() as session:
        rec = session.scalar(select(BannedIP).where(BannedIP.ip == scanner_ip))
        assert rec is not None
        assert rec.ip == scanner_ip
        assert "persistence test" in rec.reason
        assert rec.violation_count == 1

    # Simulate server restart: clear memory cache
    rate_limiter.reset()
    assert rate_limiter.is_ip_banned_permanent(scanner_ip) is False

    # Reload from database (lifespan hook)
    loaded_count = rate_limiter.load_banned_ips_from_db()
    assert loaded_count >= 1
    assert rate_limiter.is_ip_banned_permanent(scanner_ip) is True

    # Unblock and verify removed from database
    rate_limiter.unblock_ip(scanner_ip)
    assert rate_limiter.is_ip_banned_permanent(scanner_ip) is False
    with session_maker() as session:
        rec_after = session.scalar(select(BannedIP).where(BannedIP.ip == scanner_ip))
        assert rec_after is None


def test_ip_intel_service_classification():
    """Verify IP intelligence service detects private IPs and caches classifications."""
    import asyncio

    from app.ip_intel import ip_intel_service

    # 1. Private and loopback IPs are not datacenter
    is_dc, info = asyncio.run(ip_intel_service.is_datacenter_ip("127.0.0.1"))
    assert is_dc is False
    assert "Private" in info or "Localhost" in info

    is_dc_priv, _ = asyncio.run(ip_intel_service.is_datacenter_ip("192.168.1.100"))
    assert is_dc_priv is False

    # 2. In-memory cache hit
    dummy_vps_ip = "198.51.100.123"
    with ip_intel_service._lock:
        ip_intel_service._cache[dummy_vps_ip] = {
            "is_datacenter": True,
            "isp": "DigitalOcean, LLC",
            "org": "DigitalOcean",
            "as_info": "AS14061",
            "country": "US",
        }

    is_dc_vps, provider = asyncio.run(ip_intel_service.is_datacenter_ip(dummy_vps_ip))
    assert is_dc_vps is True
    assert "DigitalOcean" in provider

    # 3. get_ip_info returns cached details
    cached_info = ip_intel_service.get_ip_info(dummy_vps_ip)
    assert cached_info is not None
    assert cached_info["is_datacenter"] is True


def test_datacenter_ip_blocked_unauthenticated(test_settings: Settings):
    """Verify unauthenticated requests from a VPS are dropped, but allowed with API key."""
    from starlette.testclient import TestClient as CustomClient

    from app.ip_intel import ip_intel_service
    from app.main import create_app

    vps_ip = "203.0.113.88"
    with ip_intel_service._lock:
        ip_intel_service._cache[vps_ip] = {
            "is_datacenter": True,
            "isp": "Amazon.com, Inc.",
            "org": "AWS EC2",
            "as_info": "AS16509",
            "country": "US",
        }

    app = create_app()
    client = CustomClient(app, client=(vps_ip, 50000))

    # 1. Unauthenticated request -> dropped with empty 403 & Connection: close
    resp_unauth = client.get("/api/v1/health")
    assert resp_unauth.status_code == 403
    assert len(resp_unauth.content) == 0
    assert resp_unauth.headers.get("connection") == "close"

    # 2. Authenticated request with valid X-API-Key -> ALLOWED (VPN player / coach bypass)
    resp_auth = client.get("/api/v1/health", headers={"X-API-Key": TEST_PULL_KEY})
    assert resp_auth.status_code == 200
    assert resp_auth.json()["status"] == "ok"
