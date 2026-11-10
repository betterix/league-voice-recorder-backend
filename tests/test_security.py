"""Security, authentication, authorization, rate limiting, and TLS tests."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.security import (
    Role,
    authenticate_key,
    generate_self_signed_cert,
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

    # Delete
    del_resp = client.delete(
        "/api/v1/recordings/8018190002",
        headers={"X-API-Key": TEST_UPLOAD_KEY},
    )
    assert del_resp.status_code == 200


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
