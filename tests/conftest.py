"""Pytest fixtures and test environment setup."""

import os

# Set test environment before app imports
os.environ["ENVIRONMENT"] = "test"
os.environ["UPLOAD_KEY"] = "test-upload-key-secure-random-123456"
os.environ["PULL_KEY"] = "test-pull-key-secure-random-654321"
os.environ["ADMIN_KEY"] = "test-admin-key-secure-random-789012"

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings, set_settings
from app.database import Base, create_db_engine, get_db
from app.main import create_app
from app.security import rate_limiter

TEST_UPLOAD_KEY = "test-upload-key-secure-random-123456"
TEST_PULL_KEY = "test-pull-key-secure-random-654321"
TEST_ADMIN_KEY = "test-admin-key-secure-random-789012"


def generate_valid_mp3_bytes(num_frames: int = 15) -> bytes:
    """Generate a syntactically valid minimal MP3 byte stream with MPEG-1 Layer 3 frames.

    MPEG 1 Layer 3, 128kbps, 44100Hz -> 417 bytes per frame.
    """
    # 0xFF 0xFB (sync word + MPEG 1 Layer 3 no CRC)
    # 0x90 (128kbps, 44100Hz, no padding)
    # 0x64 (Stereo, etc.)
    frame_header = bytes([0xFF, 0xFB, 0x90, 0x64])
    frame = frame_header + (b"\x00" * 413)
    return frame * num_frames


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Ensure in-memory rate limiter and IP blocker are completely reset between test runs."""
    rate_limiter.reset()
    yield
    rate_limiter.reset()


@pytest.fixture
def temp_workspace() -> Generator[dict[str, Path]]:
    """Create isolated temporary directories for database, storage, and certs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        storage_dir = base / "recordings"
        db_dir = base / "db"
        certs_dir = base / "certs"

        storage_dir.mkdir(parents=True, exist_ok=True)
        db_dir.mkdir(parents=True, exist_ok=True)
        certs_dir.mkdir(parents=True, exist_ok=True)

        yield {
            "base": base,
            "storage_dir": storage_dir,
            "db_dir": db_dir,
            "certs_dir": certs_dir,
        }


@pytest.fixture
def test_settings(temp_workspace: dict[str, Path]) -> Settings:
    """Instantiate test-specific Settings."""
    settings = Settings(
        ENVIRONMENT="test",
        DOMAIN_NAME="lvr.szsolt.com",
        PORT=8443,
        STORAGE_DIR=temp_workspace["storage_dir"],
        DB_DIR=temp_workspace["db_dir"],
        UPLOAD_KEY=TEST_UPLOAD_KEY,
        PULL_KEY=TEST_PULL_KEY,
        ADMIN_KEY=TEST_ADMIN_KEY,
        SSL_CERT=temp_workspace["certs_dir"] / "cert.pem",
        SSL_KEY=temp_workspace["certs_dir"] / "key.pem",
        MAX_UPLOAD_MB=10,
        RATE_LIMIT_PER_MINUTE=1000,
        UPLOAD_RATE_LIMIT_PER_MINUTE=50,
        AUTH_FAILURE_LIMIT_PER_MINUTE=5,
        AUTH_BLOCK_DURATION_MINUTES=5,
    )
    set_settings(settings)
    return settings


@pytest.fixture
def test_engine(test_settings: Settings) -> Engine:
    """Create test SQLite engine and create tables."""
    engine = create_db_engine(test_settings.database_path)
    Base.metadata.create_all(bind=engine)
    return engine


@pytest.fixture
def test_db(test_engine: Engine) -> Generator[Session]:
    """Provide a database session fixture."""
    factory = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    session = factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(test_settings: Settings, test_engine: Engine) -> Generator[TestClient]:
    """TestClient configured with overridden database dependency and test settings."""
    app = create_app()

    factory = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    def override_get_db() -> Generator[Session]:
        session = factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app, base_url="http://testserver") as test_client:
        yield test_client

    app.dependency_overrides.clear()
