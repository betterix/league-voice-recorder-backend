"""FastAPI router for Web Dashboard endpoints."""

import shutil

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    Header,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.ip_intel import ip_intel_service
from app.models import IPActivity, Recording
from app.schemas import MessageResponse, RecordingMetadata
from app.security import get_client_ip, rate_limiter
from app.storage import (
    create_download_response,
    delete_recording_file,
    save_upload_recording,
    validate_game_id,
)
from app.web.auth import require_web_access
from app.web.views import render_dashboard

router = APIRouter(tags=["Web Dashboard"])


@router.get("", response_class=HTMLResponse, summary="Web Dashboard UI")
@router.get("/", response_class=HTMLResponse, summary="Web Dashboard UI")
def get_dashboard(
    request: Request,
    username: str = Depends(require_web_access),
) -> HTMLResponse:
    """Render the web administration dashboard for scrimmage recordings."""
    client_ip = get_client_ip(request)
    html_content = render_dashboard(client_ip=client_ip, username=username)
    return HTMLResponse(
        content=html_content,
        headers={"Cache-Control": "no-store, max-age=0"},
    )


@router.get("/api/recordings", summary="List recordings with storage telemetry")
def get_web_recordings(
    username: str = Depends(require_web_access),
    db: Session = Depends(get_db),
) -> dict:
    """Return JSON list of recordings and host disk storage telemetry for the dashboard."""
    settings = get_settings()

    recordings = db.scalars(select(Recording).order_by(Recording.created_at.desc())).all()

    items = [RecordingMetadata.model_validate(r).model_dump() for r in recordings]

    # Calculate disk usage
    total_b, used_b, free_b = 0, 0, 0
    try:
        usage = shutil.disk_usage(settings.STORAGE_DIR)
        total_b, used_b, free_b = usage.total, usage.used, usage.free
    except Exception:
        pass

    blocked_ips = rate_limiter.get_blocked_ips()

    return {
        "items": items,
        "total": len(items),
        "storage_total_bytes": total_b,
        "storage_used_bytes": used_b,
        "storage_free_bytes": free_b,
        "blocked_ips_count": len(blocked_ips),
    }


@router.get("/api/security/blocked-ips", summary="List actively banned scanner IPs")
def get_blocked_ips(
    username: str = Depends(require_web_access),
) -> dict:
    """Return actively banned IP addresses and remaining ban durations."""
    return {"blocked_ips": rate_limiter.get_blocked_ips()}


class BanIPRequest(BaseModel):
    reason: str = "Manually banned by administrator"


@router.post("/api/security/unblock/{ip}", summary="Unban an IP address")
def unblock_banned_ip(
    ip: str,
    username: str = Depends(require_web_access),
) -> dict:
    """Unblock an IP address from persistent database ban and reset rate limits."""
    unblocked = rate_limiter.unblock_ip(ip)
    return {
        "ip": ip,
        "unblocked": unblocked,
        "removed": unblocked,
        "success": True,
        "message": f"IP {ip} unblocked and rate limits reset"
        if unblocked
        else f"IP {ip} was not blocked, rate limits reset",
    }


@router.post("/api/security/block/{ip}", summary="Manually ban an IP address")
def manual_ban_ip(
    ip: str,
    payload: BanIPRequest | None = None,
    reason: str | None = None,
    username: str = Depends(require_web_access),
) -> dict:
    """Manually add an IP address to persistent database ban."""
    ban_reason = (
        payload.reason if payload and payload.reason else reason
    ) or "Manually banned by administrator"
    rate_limiter.ban_ip_permanent(ip, reason=ban_reason)
    return {
        "ip": ip,
        "banned": True,
        "success": True,
        "message": f"IP {ip} permanently banned in database.",
    }


@router.get("/api/security/activity", summary="Query IP activity audit log")
def get_ip_activity(
    category: str | None = None,
    search: str | None = None,
    limit: int = 100,
    username: str = Depends(require_web_access),
    db: Session = Depends(get_db),
) -> dict:
    """Return recent IP access activity categorized by downloads, suspicious probes, and API."""
    excluded_ips = ("127.0.0.1", "::1", "localhost")
    query = select(IPActivity).where(IPActivity.ip.not_in(excluded_ips))

    if category and category.lower() != "all":
        query = query.where(IPActivity.category == category.lower())

    if search and search.strip():
        term = f"%{search.strip()}%"
        query = query.where(
            or_(
                IPActivity.ip.ilike(term),
                IPActivity.path.ilike(term),
                IPActivity.details.ilike(term),
            )
        )

    # Order by newest first
    limit = min(max(1, limit), 200)
    items = db.scalars(query.order_by(IPActivity.created_at.desc()).limit(limit)).all()

    # Calculate category summary counts excluding loopback/localhost
    base_count = select(func.count(IPActivity.id)).where(IPActivity.ip.not_in(excluded_ips))
    counts = {
        "all": db.scalar(base_count) or 0,
        "download": db.scalar(base_count.where(IPActivity.category == "download")) or 0,
        "suspicious": db.scalar(base_count.where(IPActivity.category == "suspicious")) or 0,
        "blocked": db.scalar(base_count.where(IPActivity.category == "blocked")) or 0,
        "api": db.scalar(base_count.where(IPActivity.category == "api")) or 0,
    }

    return {
        "items": [
            {
                "id": ev.id,
                "ip": ev.ip,
                "method": ev.method,
                "path": ev.path,
                "status_code": ev.status_code,
                "category": ev.category,
                "details": ev.details or "",
                "isp": (ip_intel_service.get_ip_info(ev.ip) or {}).get("org")
                or (ip_intel_service.get_ip_info(ev.ip) or {}).get("isp")
                or "",
                "is_datacenter": (ip_intel_service.get_ip_info(ev.ip) or {}).get(
                    "is_datacenter", False
                ),
                "created_at": ev.created_at.isoformat() if ev.created_at else "",
            }
            for ev in items
        ],
        "total": len(items),
        "counts": counts,
        "blocked_ips": rate_limiter.get_blocked_ips(),
    }


@router.get("/download/{game_id}", summary="Download MP3 from Web Dashboard")
def web_download_recording(
    game_id: str,
    range: str | None = Header(default=None, alias="Range"),
    username: str = Depends(require_web_access),
    db: Session = Depends(get_db),
) -> Response:
    """Download scrimmage MP3 with full Range support for resumable browser downloads."""
    clean_id = validate_game_id(game_id)

    recording = db.scalar(select(Recording).where(Recording.game_id == clean_id))
    if recording is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recording for Game ID '{clean_id}' not found",
        )

    return create_download_response(game_id=clean_id, range_header=range)


@router.get("/stream/{game_id}", summary="Stream MP3 inline for browser player")
def web_stream_recording(
    game_id: str,
    range: str | None = Header(default=None, alias="Range"),
    username: str = Depends(require_web_access),
    db: Session = Depends(get_db),
) -> Response:
    """Stream scrimmage MP3 with inline Content-Disposition for browser audio player."""
    clean_id = validate_game_id(game_id)

    recording = db.scalar(select(Recording).where(Recording.game_id == clean_id))
    if recording is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recording for Game ID '{clean_id}' not found",
        )

    response = create_download_response(game_id=clean_id, range_header=range)
    # Set disposition to inline for browser audio element playback
    response.headers["Content-Disposition"] = f'inline; filename="{clean_id}.mp3"'
    return response


@router.post(
    "/upload/{game_id}",
    response_model=RecordingMetadata,
    status_code=status.HTTP_201_CREATED,
)
async def web_upload_recording(
    game_id: str,
    file: UploadFile = File(...),
    team_tag: str | None = Form(default=None),
    notes: str | None = Form(default=None),
    username: str = Depends(require_web_access),
    db: Session = Depends(get_db),
) -> RecordingMetadata:
    """Handle direct browser upload of scrimmage audio."""
    settings = get_settings()
    clean_id = validate_game_id(game_id)

    # Check duplicate
    existing = db.scalar(select(Recording).where(Recording.game_id == clean_id))
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Recording for Game ID '{clean_id}' already exists",
        )

    storage_res = await save_upload_recording(
        file=file,
        game_id=clean_id,
        expected_sha256=None,
        storage_dir=settings.STORAGE_DIR,
    )

    recording = Recording(
        game_id=clean_id,
        filename=f"{clean_id}.mp3",
        file_size=storage_res.file_size,
        duration=storage_res.duration,
        bitrate=storage_res.bitrate,
        sample_rate=storage_res.sample_rate,
        sha256=storage_res.sha256,
        team_tag=team_tag.strip().upper() if team_tag and team_tag.strip() else None,
        notes=notes.strip() if notes and notes.strip() else None,
    )

    try:
        db.add(recording)
        db.commit()
        db.refresh(recording)
    except Exception:
        db.rollback()
        delete_recording_file(clean_id, settings.STORAGE_DIR)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist recording metadata in database",
        ) from None

    return RecordingMetadata.model_validate(recording)


@router.delete("/recordings/{game_id}", response_model=MessageResponse)
def web_delete_recording(
    game_id: str,
    username: str = Depends(require_web_access),
    db: Session = Depends(get_db),
) -> MessageResponse:
    """Delete recording file and database record from the web dashboard."""
    clean_id = validate_game_id(game_id)

    recording = db.scalar(select(Recording).where(Recording.game_id == clean_id))
    if recording is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recording for Game ID '{clean_id}' not found",
        )

    delete_recording_file(clean_id)
    db.delete(recording)
    db.commit()

    return MessageResponse(
        message=f"Recording '{clean_id}' successfully deleted",
        game_id=clean_id,
    )
