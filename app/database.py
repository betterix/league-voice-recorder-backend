"""SQLite database engine, session management, and connection pragmas."""

from collections.abc import Generator
from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    """Base class for SQLAlchemy declarative models."""

    pass


def create_db_engine(db_path: Path | None = None) -> Engine:
    """Create SQLite engine configured with connection timeouts and WAL pragma."""
    settings = get_settings()
    if db_path is None:
        target_path = settings.database_path
    else:
        target_path = db_path

    # Ensure parent directory exists
    target_path.parent.mkdir(parents=True, exist_ok=True)
    db_url = f"sqlite:///{target_path}"

    engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False, "timeout": 30.0},
        echo=False,
    )

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.execute("PRAGMA busy_timeout=30000;")
        cursor.close()

    return engine


# Default engine & sessionmaker
_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    """Retrieve or initialize default database engine."""
    global _engine
    if _engine is None:
        _engine = create_db_engine()
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    """Retrieve or initialize default sessionmaker factory."""
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=get_engine(),
        )
    return _session_factory


def init_db(engine: Engine | None = None) -> None:
    """Initialize database tables."""
    eng = engine or get_engine()
    Base.metadata.create_all(bind=eng)


def get_db() -> Generator[Session]:
    """FastAPI dependency for database session lifecycle."""
    session_maker = get_session_factory()
    session = session_maker()
    try:
        yield session
    finally:
        session.close()
