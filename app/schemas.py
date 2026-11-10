"""Pydantic schemas for request validation and response serialization."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class HealthResponse(BaseModel):
    """Health check diagnostic response."""

    status: str = Field(default="ok", description="Service status indicator")
    version: str = Field(description="Application version")
    authenticated_role: str | None = Field(
        default=None,
        description="Caller role if authenticated (upload, pull, admin)",
    )
    storage_total_bytes: int | None = Field(
        default=None,
        description="Total storage disk capacity in bytes (authenticated only)",
    )
    storage_used_bytes: int | None = Field(
        default=None,
        description="Used storage disk space in bytes (authenticated only)",
    )
    storage_free_bytes: int | None = Field(
        default=None,
        description="Free storage disk space in bytes (authenticated only)",
    )
    recording_count: int | None = Field(
        default=None,
        description="Total count of stored recordings (authenticated only)",
    )


class RecordingMetadata(BaseModel):
    """Metadata response schema for a recorded scrimmage audio file."""

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    game_id: str = Field(description="Riot Game ID")
    filename: str = Field(description="Audio filename stored on disk")
    file_size: int = Field(description="File size in bytes")
    duration: float = Field(description="Duration in seconds")
    bitrate: int = Field(description="Audio bitrate in bits per second")
    sample_rate: int = Field(description="Sample rate in Hertz")
    upload_timestamp: datetime = Field(
        validation_alias="created_at",
        description="UTC timestamp when recording was uploaded",
    )
    team_tag: str | None = Field(default=None, description="Team or scrim identifier")
    notes: str | None = Field(default=None, description="Optional notes")
    match_date: str | None = Field(default=None, description="Optional match date string")
    sha256: str = Field(description="SHA-256 integrity hash")


class RecordingListResponse(BaseModel):
    """Paginated list of recordings metadata."""

    items: list[RecordingMetadata] = Field(description="List of recording metadata items")
    total: int = Field(ge=0, description="Total matching recordings count")
    skip: int = Field(ge=0, description="Offset used in pagination")
    limit: int = Field(ge=1, description="Limit used in pagination")


class MessageResponse(BaseModel):
    """Generic status response."""

    message: str
    game_id: str | None = None
