"""SQLAlchemy data models for recording metadata."""

from datetime import UTC, datetime

from sqlalchemy import BigInteger, DateTime, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC)


class Recording(Base):
    """Database model storing League Voice Recorder scrim audio metadata."""

    __tablename__ = "recordings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Riot Game ID (e.g., '8018190134' or 'EUW1_123456789')
    game_id: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False,
    )

    # Filename stored on disk (<game_id>.mp3)
    filename: Mapped[str] = mapped_column(String(128), nullable=False)

    # Audio metrics
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)  # bytes
    duration: Mapped[float] = mapped_column(Float, nullable=False)  # seconds
    bitrate: Mapped[int] = mapped_column(Integer, nullable=False)  # bps
    sample_rate: Mapped[int] = mapped_column(Integer, nullable=False)  # Hz

    # SHA-256 integrity checksum (64 hex characters)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)

    # Metadata & categorization
    team_tag: Mapped[str | None] = mapped_column(
        String(32),
        index=True,
        nullable=True,
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    match_date: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )

    __table_args__ = (
        Index("ix_recordings_game_id_team_tag", "game_id", "team_tag"),
        Index("ix_recordings_created_at", "created_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<Recording(game_id='{self.game_id}', "
            f"team_tag='{self.team_tag}', "
            f"duration={self.duration:.1f}s, "
            f"size={self.file_size})>"
        )


class BannedIP(Base):
    """Database model storing permanently banned scanner and exploit IP addresses."""

    __tablename__ = "banned_ips"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # IP address (IPv4 or IPv6)
    ip: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False,
    )

    # Reason for the ban (e.g. "Malicious scanner probe (GET /.env)")
    reason: Mapped[str] = mapped_column(String(255), nullable=False)

    # Total violation count
    violation_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<BannedIP(ip='{self.ip}', violations={self.violation_count})>"


class IPActivity(Base):
    """Database model logging IP access events, downloads, and suspicious scanner probes."""

    __tablename__ = "ip_activity"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Client IP address
    ip: Mapped[str] = mapped_column(String(64), index=True, nullable=False)

    # HTTP Method and Path
    method: Mapped[str] = mapped_column(String(16), nullable=False)
    path: Mapped[str] = mapped_column(String(255), nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)

    # Category: 'download', 'suspicious', 'blocked', 'api'
    category: Mapped[str] = mapped_column(String(32), index=True, nullable=False)

    # Extra details (e.g. Game ID or probe signature)
    details: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Timestamp
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        index=True,
        nullable=False,
    )

    __table_args__ = (
        Index("ix_ip_activity_created_at_desc", created_at.desc()),
        Index("ix_ip_activity_cat_created", "category", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<IPActivity(ip='{self.ip}', category='{self.category}', path='{self.path}')>"
