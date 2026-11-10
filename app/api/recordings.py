"""Recording endpoints: upload, list, retrieve metadata, download, and delete."""

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models import Recording
from app.schemas import MessageResponse, RecordingListResponse, RecordingMetadata
from app.security import (
    Role,
    get_client_ip,
    rate_limiter,
    require_read_access,
    require_write_access,
)
from app.storage import (
    create_download_response,
    delete_recording_file,
    save_upload_recording,
    validate_game_id,
)

router = APIRouter(prefix="/recordings", tags=["Recordings"])


def check_upload_rate_limit(request: Request) -> None:
    """Enforce rate limiting on upload operations."""
    settings = get_settings()
    ip = get_client_ip(request)
    allowed, remaining, retry_after = rate_limiter.check_rate_limit(
        ip=ip,
        category="upload",
        limit_per_minute=settings.UPLOAD_RATE_LIMIT_PER_MINUTE,
    )
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Upload rate limit exceeded. Please slow down.",
            headers={"Retry-After": str(retry_after)},
        )


@router.post(
    "/{game_id}",
    response_model=RecordingMetadata,
    status_code=status.HTTP_201_CREATED,
    summary="Upload scrimmage recording",
)
async def upload_recording(
    game_id: str,
    file: UploadFile = File(..., description="MP3 recording audio file"),
    team_tag: str | None = Form(
        default=None,
        description="Optional team identifier (e.g., T1, G2)",
    ),
    notes: str | None = Form(default=None, description="Optional scrim notes"),
    match_date: str | None = Form(
        default=None,
        description="Optional match date (ISO format recommended)",
    ),
    x_checksum_sha256: str | None = Header(
        default=None,
        alias="X-Checksum-SHA256",
        description="Optional SHA-256 hex digest for data integrity verification",
    ),
    role: Role = Depends(require_write_access),
    _rate_limit: None = Depends(check_upload_rate_limit),
    db: Session = Depends(get_db),
) -> RecordingMetadata:
    """Upload and process an MP3 recording file for a specific League of Legends game ID."""
    clean_id = validate_game_id(game_id)

    # Check for existing record in database
    existing = db.scalar(select(Recording).where(Recording.game_id == clean_id))
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Recording for Game ID '{clean_id}' already exists in database",
        )

    # Save to storage with validation and checksum verification
    audio_meta = await save_upload_recording(
        file=file,
        game_id=clean_id,
        expected_sha256=x_checksum_sha256,
    )

    try:
        recording = Recording(
            game_id=clean_id,
            filename=f"{clean_id}.mp3",
            file_size=audio_meta.file_size,
            duration=audio_meta.duration,
            bitrate=audio_meta.bitrate,
            sample_rate=audio_meta.sample_rate,
            sha256=audio_meta.sha256,
            team_tag=team_tag.strip() if team_tag else None,
            notes=notes.strip() if notes else None,
            match_date=match_date.strip() if match_date else None,
        )
        db.add(recording)
        db.commit()
        db.refresh(recording)
        return RecordingMetadata.model_validate(recording)
    except Exception:
        # Guarantee database / filesystem consistency by purging file if database insertion fails
        delete_recording_file(clean_id)
        db.rollback()
        raise


@router.get(
    "",
    response_model=RecordingListResponse,
    summary="List scrim recordings",
)
def list_recordings(
    skip: int = Query(default=0, ge=0, description="Offset records to skip"),
    limit: int = Query(default=50, ge=1, le=100, description="Maximum number of records to return"),
    search: str | None = Query(
        default=None,
        description="Search filter matching Game ID or Team Tag",
    ),
    role: Role = Depends(require_read_access),
    db: Session = Depends(get_db),
) -> RecordingListResponse:
    """List scrimmage recordings with pagination and search capability."""
    query = select(Recording)
    count_query = select(func.count(Recording.id))

    if search:
        search_pattern = f"%{search.strip()}%"
        search_filter = or_(
            Recording.game_id.ilike(search_pattern),
            Recording.team_tag.ilike(search_pattern),
        )
        query = query.where(search_filter)
        count_query = count_query.where(search_filter)

    total = db.scalar(count_query) or 0
    items = db.scalars(query.order_by(Recording.created_at.desc()).offset(skip).limit(limit)).all()

    return RecordingListResponse(
        items=[RecordingMetadata.model_validate(item) for item in items],
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/{game_id}",
    response_model=RecordingMetadata,
    summary="Retrieve recording metadata",
)
def get_recording_metadata(
    game_id: str,
    role: Role = Depends(require_read_access),
    db: Session = Depends(get_db),
) -> RecordingMetadata:
    """Retrieve metadata for a specific scrimmage recording."""
    clean_id = validate_game_id(game_id)
    recording = db.scalar(select(Recording).where(Recording.game_id == clean_id))
    if recording is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recording for Game ID '{clean_id}' not found",
        )

    return RecordingMetadata.model_validate(recording)


@router.get(
    "/{game_id}/download",
    summary="Download MP3 recording",
)
def download_recording(
    game_id: str,
    range: str | None = Header(default=None, alias="Range"),
    role: Role = Depends(require_read_access),
    db: Session = Depends(get_db),
) -> Response:
    """Directly stream MP3 recording with HTTP Range support for resumable transfers."""
    clean_id = validate_game_id(game_id)

    # Verify recording exists in database
    recording = db.scalar(select(Recording).where(Recording.game_id == clean_id))
    if recording is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recording for Game ID '{clean_id}' not found in database",
        )

    return create_download_response(game_id=clean_id, range_header=range)


@router.delete(
    "/{game_id}",
    response_model=MessageResponse,
    summary="Delete scrim recording",
)
def delete_recording(
    game_id: str,
    role: Role = Depends(require_write_access),
    db: Session = Depends(get_db),
) -> MessageResponse:
    """Delete recording file and its associated metadata."""
    clean_id = validate_game_id(game_id)

    recording = db.scalar(select(Recording).where(Recording.game_id == clean_id))
    if recording is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recording for Game ID '{clean_id}' not found",
        )

    # Remove from filesystem
    delete_recording_file(clean_id)

    # Remove from database
    db.delete(recording)
    db.commit()

    return MessageResponse(
        message=f"Recording '{clean_id}' successfully deleted",
        game_id=clean_id,
    )
