"""Authentication, role-based authorization, rate limiting, and TLS certificate security."""

import datetime
import logging
import secrets
import threading
import time
from enum import StrEnum
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import Header, HTTPException, Request, status

from app.config import Settings, get_settings

logger = logging.getLogger("league_backend.security")


class Role(StrEnum):
    """Authentication roles for the backend."""

    UPLOAD = "upload"
    PULL = "pull"
    ADMIN = "admin"


# -----------------------------------------------------------------------------
# In-Memory Rate Limiting & Brute-Force IP Blocker
# -----------------------------------------------------------------------------


class InMemoryRateLimiter:
    """Thread-safe, sliding-window in-memory rate limiter and IP blocker.

    Architectural Scope & Limitations:
    - Designed specifically for the direct-port single-process Uvicorn deployment.
    - Operates purely in-memory with zero external dependency (no Redis needed).
    - Rate limit state resides within the running process and resets upon restart.
    - Tracks client IP addresses directly from request.client.host.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # client_ip -> deque/list of timestamps (float)
        self._general_requests: dict[str, list[float]] = {}
        self._upload_requests: dict[str, list[float]] = {}
        # client_ip -> list of failure timestamps
        self._auth_failures: dict[str, list[float]] = {}
        # client_ip -> blocked_until timestamp (float)
        self._blocked_ips: dict[str, float] = {}

    def _cleanup_old_timestamps(
        self, timestamps: list[float], window_seconds: float
    ) -> list[float]:
        threshold = time.monotonic() - window_seconds
        return [ts for ts in timestamps if ts > threshold]

    def is_ip_blocked(self, ip: str) -> tuple[bool, int]:
        """Check if an IP is currently blocked due to repeated auth failures.

        Returns (is_blocked, remaining_seconds).
        """
        now = time.monotonic()
        with self._lock:
            blocked_until = self._blocked_ips.get(ip)
            if blocked_until is not None:
                if now < blocked_until:
                    remaining = int(blocked_until - now) + 1
                    return True, remaining
                else:
                    # Block expired
                    del self._blocked_ips[ip]
            return False, 0

    def record_auth_failure(
        self,
        ip: str,
        max_failures: int,
        window_seconds: float = 60.0,
        block_duration_minutes: int = 10,
    ) -> bool:
        """Record an authentication failure.

        Returns True if the IP is now blocked.
        """
        now = time.monotonic()
        with self._lock:
            failures = self._auth_failures.get(ip, [])
            failures = self._cleanup_old_timestamps(failures, window_seconds)
            failures.append(now)
            self._auth_failures[ip] = failures

            if len(failures) >= max_failures:
                blocked_until = now + (block_duration_minutes * 60.0)
                self._blocked_ips[ip] = blocked_until
                logger.warning(
                    "Brute-force protection: IP %s blocked for %d min (%d failed attempts)",
                    ip,
                    block_duration_minutes,
                    len(failures),
                )
                return True
            return False

    def check_rate_limit(
        self,
        ip: str,
        category: str,
        limit_per_minute: int,
        window_seconds: float = 60.0,
    ) -> tuple[bool, int, int]:
        """Check and consume rate limit token for an IP and category.

        Returns (allowed, remaining, retry_after).
        """
        now = time.monotonic()
        with self._lock:
            storage = self._upload_requests if category == "upload" else self._general_requests
            timestamps = storage.get(ip, [])
            timestamps = self._cleanup_old_timestamps(timestamps, window_seconds)

            if len(timestamps) >= limit_per_minute:
                oldest = timestamps[0]
                retry_after = max(1, int(oldest + window_seconds - now))
                return False, 0, retry_after

            timestamps.append(now)
            storage[ip] = timestamps
            remaining = max(0, limit_per_minute - len(timestamps))
            return True, remaining, 0

    def reset(self) -> None:
        """Clear all rate limiting and IP blocking state (used in testing)."""
        with self._lock:
            self._general_requests.clear()
            self._upload_requests.clear()
            self._auth_failures.clear()
            self._blocked_ips.clear()


# Global rate limiter instance
rate_limiter = InMemoryRateLimiter()


def get_client_ip(request: Request) -> str:
    """Extract client IP directly from the TCP connection.

    In direct-port architecture, X-Forwarded-For must NOT be trusted because there
    is no intermediate reverse proxy sanitizing headers.
    """
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


# -----------------------------------------------------------------------------
# API Key Verification & Permission Enforcement
# -----------------------------------------------------------------------------


def verify_secret_constant_time(provided: str | None, expected: str | None) -> bool:
    """Compare two secrets in constant time to prevent timing attacks."""
    if not provided or not expected:
        return False
    return secrets.compare_digest(provided.strip(), expected.strip())


def authenticate_key(provided_key: str | None, settings: Settings) -> Role | None:
    """Authenticate provided key against configured roles in constant time."""
    if not provided_key:
        return None

    # Check ADMIN_KEY first if configured
    if settings.ADMIN_KEY and verify_secret_constant_time(provided_key, settings.ADMIN_KEY):
        return Role.ADMIN

    # Check UPLOAD_KEY
    if verify_secret_constant_time(provided_key, settings.UPLOAD_KEY):
        return Role.UPLOAD

    # Check PULL_KEY
    if verify_secret_constant_time(provided_key, settings.PULL_KEY):
        return Role.PULL

    return None


def enforce_not_blocked(request: Request, settings: Settings) -> str:
    """Ensure client IP is not temporarily blocked."""
    ip = get_client_ip(request)
    is_blocked, remaining = rate_limiter.is_ip_blocked(ip)
    if is_blocked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                "Too many failed authentication attempts. IP temporarily blocked. "
                f"Try again in {remaining} seconds."
            ),
            headers={"Retry-After": str(remaining)},
        )
    return ip


def get_optional_role(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> Role | None:
    """Dependency for endpoints that allow public access but enhance details if authenticated."""
    settings = get_settings()
    ip = enforce_not_blocked(request, settings)

    if not x_api_key:
        return None

    role = authenticate_key(x_api_key, settings)
    if role is None:
        rate_limiter.record_auth_failure(
            ip=ip,
            max_failures=settings.AUTH_FAILURE_LIMIT_PER_MINUTE,
            block_duration_minutes=settings.AUTH_BLOCK_DURATION_MINUTES,
        )
        return None
    return role


def require_read_access(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> Role:
    """Require valid PULL_KEY, UPLOAD_KEY, or ADMIN_KEY."""
    settings = get_settings()
    ip = enforce_not_blocked(request, settings)

    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required X-API-Key header",
        )

    role = authenticate_key(x_api_key, settings)
    if role is None:
        rate_limiter.record_auth_failure(
            ip=ip,
            max_failures=settings.AUTH_FAILURE_LIMIT_PER_MINUTE,
            block_duration_minutes=settings.AUTH_BLOCK_DURATION_MINUTES,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    return role


def require_write_access(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> Role:
    """Require valid UPLOAD_KEY or ADMIN_KEY. PULL_KEY is forbidden."""
    settings = get_settings()
    ip = enforce_not_blocked(request, settings)

    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required X-API-Key header",
        )

    role = authenticate_key(x_api_key, settings)
    if role is None:
        rate_limiter.record_auth_failure(
            ip=ip,
            max_failures=settings.AUTH_FAILURE_LIMIT_PER_MINUTE,
            block_duration_minutes=settings.AUTH_BLOCK_DURATION_MINUTES,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    if role == Role.PULL:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Pull key only possesses read-only permissions",
        )

    return role


# -----------------------------------------------------------------------------
# TLS Certificate Management & Development Generation
# -----------------------------------------------------------------------------


def validate_tls_certificates(cert_path: Path, key_path: Path) -> tuple[bool, str]:
    """Validate existence, permissions, and cryptographic integrity of TLS cert and key."""
    if not cert_path.exists():
        return False, f"Certificate file not found at {cert_path}"
    if not key_path.exists():
        return False, f"Private key file not found at {key_path}"

    try:
        cert_bytes = cert_path.read_bytes()
        cert = x509.load_pem_x509_certificate(cert_bytes)
    except Exception as exc:
        return False, f"Failed to parse X.509 certificate: {exc}"

    try:
        key_bytes = key_path.read_bytes()
        serialization.load_pem_private_key(key_bytes, password=None)
    except Exception as exc:
        return False, f"Failed to parse private key: {exc}"

    # Verify certificate expiry
    now = datetime.datetime.now(datetime.UTC)
    if now < cert.not_valid_before_utc:
        return False, f"Certificate is not yet valid (valid from {cert.not_valid_before_utc})"
    if now > cert.not_valid_after_utc:
        return False, f"Certificate has expired on {cert.not_valid_after_utc}"

    fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
    return True, f"Valid certificate (SHA-256: {fingerprint})"


def generate_self_signed_cert(cert_path: Path, key_path: Path, domain: str) -> str:
    """Generate self-signed ECDSA certificate for development mode.

    Returns the uppercase SHA-256 certificate fingerprint.
    """
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    # Generate ECDSA private key with SECP256R1
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Build SAN entries
    san_entries: list[x509.GeneralName] = [
        x509.DNSName(domain),
        x509.DNSName("localhost"),
        x509.IPAddress(ip_address("127.0.0.1")),
    ]

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "League Voice Recorder Dev"),
        ]
    )

    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Write private key with restrictive 0o600 permissions
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(key_pem)
    key_path.chmod(0o600)

    # Write certificate
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_path.write_bytes(cert_pem)
    cert_path.chmod(0o644)

    fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
    return fingerprint


def generate_secure_api_key(role: Role | str = Role.UPLOAD) -> str:
    """Generate a high-entropy, cryptographically secure 256-bit random API key.

    Format: lvr_<role>_<32-bytes-urlsafe-base64>
    """
    role_str = role.value if isinstance(role, Role) else str(role).lower()
    entropy = secrets.token_urlsafe(32)
    return f"lvr_{role_str}_{entropy}"


if __name__ == "__main__":
    print("=== League Voice Recorder Cryptographically Secure Keys ===")
    print(f"UPLOAD_KEY={generate_secure_api_key(Role.UPLOAD)}")
    print(f"PULL_KEY={generate_secure_api_key(Role.PULL)}")
    print(f"ADMIN_KEY={generate_secure_api_key(Role.ADMIN)}")
