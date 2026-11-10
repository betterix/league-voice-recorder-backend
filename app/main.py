"""Main application entry point configuring FastAPI, TLS, middleware, and routers."""

import logging
import ssl
import sys
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request, status
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.api.health import router as health_router
from app.api.recordings import router as recordings_router
from app.config import get_settings
from app.database import init_db
from app.security import (
    generate_self_signed_cert,
    get_client_ip,
    rate_limiter,
    validate_tls_certificates,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("league_backend.main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Application lifespan manager initializing directories, database, and verifying TLS."""
    settings = get_settings()

    # Ensure required directories exist
    settings.ensure_directories()

    # Initialize SQLite tables
    init_db()
    logger.info("Database initialized at %s", settings.database_path)

    # Validate TLS configuration
    if settings.is_production:
        valid, msg = validate_tls_certificates(settings.SSL_CERT, settings.SSL_KEY)
        if not valid:
            logger.critical("Production TLS Certificate validation failed: %s", msg)
            raise RuntimeError(f"Production TLS Certificate validation failed: {msg}")
        logger.info("Production TLS configuration validated: %s", msg)
    else:
        # Development / Test mode fallback
        cert_exists = settings.SSL_CERT.exists()
        key_exists = settings.SSL_KEY.exists()
        if not cert_exists or not key_exists:
            if settings.DEV_SELF_SIGNED_CERT or settings.is_development:
                fingerprint = generate_self_signed_cert(
                    settings.SSL_CERT,
                    settings.SSL_KEY,
                    settings.DOMAIN_NAME,
                )
                logger.warning(
                    "⚠️  DEVELOPMENT MODE: Generated self-signed ECDSA certificate for '%s'.\n"
                    "    SHA-256 Fingerprint: %s\n"
                    "    WARNING: NOT publicly trusted. Never use this certificate in production.",
                    settings.DOMAIN_NAME,
                    fingerprint,
                )
            else:
                logger.info("Running in unencrypted test/dev mode without TLS certificates")

    yield

    logger.info("League Voice Recorder Backend shutting down")


def create_app() -> FastAPI:
    """FastAPI application factory."""
    settings = get_settings()

    app = FastAPI(
        title="League Voice Recorder Backend",
        description="Centralized Direct-Port Scrim Audio Backend for League Voice Recorder",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,  # Pure headless API - disable web Swagger UI
        redoc_url=None,  # Disable web ReDoc UI
        openapi_url="/openapi.json",  # Machine-readable schema for automated client generators
    )

    # HTTP Host Protection
    allowed_hosts = [
        settings.DOMAIN_NAME,
        f"*.{settings.DOMAIN_NAME}",
        "localhost",
        "127.0.0.1",
        "testserver",  # Used by Starlette / HTTPX TestClient
    ]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

    # Global Rate Limiting & IP Blocking Middleware
    @app.middleware("http")
    async def security_and_rate_limit_middleware(request: Request, call_next):
        client_ip = get_client_ip(request)

        # Check brute-force IP block
        is_blocked, remaining = rate_limiter.is_ip_blocked(client_ip)
        if is_blocked:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": (
                        "Too many failed authentication attempts. IP temporarily blocked. "
                        f"Try again in {remaining} seconds."
                    )
                },
                headers={"Retry-After": str(remaining)},
            )

        # General rate limit per minute
        allowed, remaining_quota, retry_after = rate_limiter.check_rate_limit(
            ip=client_ip,
            category="general",
            limit_per_minute=settings.RATE_LIMIT_PER_MINUTE,
        )
        if not allowed:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "General API rate limit exceeded. Please slow down."},
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(settings.RATE_LIMIT_PER_MINUTE),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response = await call_next(request)

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-RateLimit-Limit"] = str(settings.RATE_LIMIT_PER_MINUTE)
        response.headers["X-RateLimit-Remaining"] = str(remaining_quota)

        return response

    # Include versioned API routers
    app.include_router(health_router, prefix="/api/v1")
    app.include_router(recordings_router, prefix="/api/v1")

    return app


app = create_app()


def tls13_ssl_context_factory(*args, **kwargs) -> ssl.SSLContext:
    """Enforce native TLS 1.3 protocol and modern AEAD cipher suites.

    Supports both Uvicorn internal hook (config, default_factory) and direct invocation.
    """
    if len(args) >= 2 and callable(args[1]):
        ctx = args[1]()
    elif "default_factory" in kwargs and callable(kwargs["default_factory"]):
        ctx = kwargs["default_factory"]()
    else:
        certfile = kwargs.get("certfile") or (args[0] if len(args) > 0 else None)
        keyfile = kwargs.get("keyfile") or (args[1] if len(args) > 1 else None)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if certfile:
            ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)

    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


def run_server() -> None:
    """Start Uvicorn with native TLS 1.3 on the configured direct port."""
    settings = get_settings()

    kwargs = {
        "app": "app.main:app",
        "host": "0.0.0.0",
        "port": settings.PORT,
        "log_level": "info",
    }

    cert_path: Path = settings.SSL_CERT
    key_path: Path = settings.SSL_KEY

    # Auto-generate self-signed cert in development mode if missing
    if (settings.DEV_SELF_SIGNED_CERT or settings.is_development) and (
        not cert_path.exists() or not key_path.exists()
    ):
        generate_self_signed_cert(cert_path, key_path, settings.DOMAIN_NAME)

    if cert_path.exists() and key_path.exists():
        kwargs["ssl_certfile"] = str(cert_path)
        kwargs["ssl_keyfile"] = str(key_path)
        kwargs["ssl_context_factory"] = tls13_ssl_context_factory
        logger.info(
            "Configured native TLS 1.3 listener on port %d with cert %s",
            settings.PORT,
            cert_path,
        )
    else:
        if settings.is_production:
            logger.critical("Cannot start production server without valid SSL certificates")
            sys.exit(1)
        logger.warning("Starting server in unencrypted HTTP mode (development/test only)")

    uvicorn.run(**kwargs)


if __name__ == "__main__":
    run_server()
