"""Health check and diagnostic API endpoints."""

import shutil

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import __version__
from app.config import get_settings
from app.database import get_db
from app.models import Recording
from app.schemas import HealthResponse
from app.security import Role, require_read_access

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
def get_health(
    role: Role = Depends(require_read_access),
    db: Session = Depends(get_db),
) -> HealthResponse:
    """Return backend health and diagnostic status.

    Requires valid API authentication (PULL_KEY, UPLOAD_KEY, or ADMIN_KEY).
    Unauthenticated or invalid requests are strictly rejected with 401 Unauthorized.
    """
    settings = get_settings()

    # Authenticated diagnostic details
    total_bytes, used_bytes, free_bytes = 0, 0, 0
    try:
        usage = shutil.disk_usage(settings.STORAGE_DIR)
        total_bytes = usage.total
        used_bytes = usage.used
        free_bytes = usage.free
    except Exception:
        pass

    count = db.scalar(select(func.count(Recording.id))) or 0

    return HealthResponse(
        status="ok",
        version=__version__,
        authenticated_role=role.value,
        storage_total_bytes=total_bytes,
        storage_used_bytes=used_bytes,
        storage_free_bytes=free_bytes,
        recording_count=count,
    )
