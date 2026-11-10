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
