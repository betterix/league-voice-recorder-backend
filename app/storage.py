"""Secure filesystem storage, MP3 validation, checksum verification, and chunked streaming."""

import hashlib
import re
import secrets
import uuid
from collections.abc import Generator
from dataclasses import dataclass
from pathlib import Path

from fastapi import HTTPException, Response, UploadFile, status
from fastapi.responses import StreamingResponse
from mutagen.mp3 import MP3, HeaderNotFoundError

from app.config import get_settings

# Strict Riot Game ID regex: alphanumeric, underscores, hyphens, 1-64 characters
GAME_ID_REGEX = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
CHUNK_SIZE = 64 * 1024  # 64 KB streaming chunk size


@dataclass(frozen=True)
class AudioMetadata:
    """Extracted audio metadata and file metrics."""

    duration: float
    bitrate: int
    sample_rate: int
    file_size: int
    sha256: str


def validate_game_id(game_id: str) -> str:
    """Sanitize and validate Riot Game ID to prevent path traversal and injection attacks."""
    if not game_id or not isinstance(game_id, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Game ID cannot be empty",
        )

    clean_id = game_id.strip()

    # Reject traversal sequences explicitly
    if ".." in clean_id or "/" in clean_id or "\\" in clean_id or "\x00" in clean_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Game ID: Directory traversal characters are forbidden",
        )

    if not GAME_ID_REGEX.match(clean_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Invalid Game ID format: Allowed characters are "
                "alphanumeric, underscores, and hyphens (1-64 chars)"
            ),
        )

    return clean_id


def get_recording_path(game_id: str, storage_dir: Path | None = None) -> Path:
    """Resolve and enforce that the recording path remains strictly inside STORAGE_DIR."""
    clean_id = validate_game_id(game_id)
    base_dir = (storage_dir or get_settings().STORAGE_DIR).resolve()
    target_path = (base_dir / f"{clean_id}.mp3").resolve()

    # Verify path confinement
    if not target_path.is_relative_to(base_dir):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Security violation: Path escapes configured storage directory",
        )

    return target_path


async def save_upload_recording(
    file: UploadFile,
    game_id: str,
    expected_sha256: str | None = None,
    storage_dir: Path | None = None,
) -> AudioMetadata:
    """Stream, validate, checksum, and atomically store uploaded MP3 recording."""
    settings = get_settings()
    clean_id = validate_game_id(game_id)
    target_path = get_recording_path(clean_id, storage_dir)
    active_storage_dir = target_path.parent
    active_storage_dir.mkdir(parents=True, exist_ok=True)

    # Collision check
    if target_path.exists():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Recording for Game ID '{clean_id}' already exists",
        )

    # Create temporary file for atomic write
    temp_filename = f".tmp_{clean_id}_{uuid.uuid4().hex}"
    temp_path = active_storage_dir / temp_filename

    hasher = hashlib.sha256()
    bytes_written = 0
    max_bytes = settings.max_upload_bytes

    try:
        with open(temp_path, "wb") as f_out:
            while True:
                chunk = await file.read(CHUNK_SIZE)
                if not chunk:
                    break

                bytes_written += len(chunk)
                if bytes_written > max_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        detail=(
                            f"Upload exceeds maximum allowable limit of {settings.MAX_UPLOAD_MB} MB"
                        ),
                    )

                hasher.update(chunk)
                f_out.write(chunk)

        if bytes_written == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty",
            )

        actual_sha256 = hasher.hexdigest().lower()

        # Validate checksum if client supplied one
        if expected_sha256:
            clean_expected = expected_sha256.strip().lower()
            if not secrets.compare_digest(actual_sha256, clean_expected):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"SHA-256 checksum mismatch (calculated: {actual_sha256})",
                )

        # Validate MP3 audio headers and extract metrics via Mutagen
        try:
            audio = MP3(str(temp_path))
            if audio.info is None or audio.info.length <= 0:
                raise ValueError("Parsed MP3 contains no audio frames or zero duration")

            duration = float(audio.info.length)
            bitrate = int(audio.info.bitrate or 0)
            sample_rate = int(audio.info.sample_rate or 0)
        except (HeaderNotFoundError, Exception) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid or corrupted MP3 file: {exc}",
            ) from exc

        # Atomic commit: move temporary file to final destination
        temp_path.replace(target_path)

        return AudioMetadata(
            duration=duration,
            bitrate=bitrate,
            sample_rate=sample_rate,
            file_size=bytes_written,
            sha256=actual_sha256,
        )

    except Exception:
        # Guarantee cleanup of temporary file on any error
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)
        raise


def file_chunk_generator(
    path: Path,
    start: int,
    length: int,
    chunk_size: int = CHUNK_SIZE,
) -> Generator[bytes]:
    """Efficiently stream a byte range from a file without loading it all into memory."""
    with open(path, "rb") as f:
        f.seek(start)
        remaining = length
        while remaining > 0:
            read_size = min(chunk_size, remaining)
            data = f.read(read_size)
            if not data:
                break
            remaining -= len(data)
            yield data


def parse_range_header(range_header: str, file_size: int) -> tuple[int, int] | None:
    """Parse HTTP Range header (bytes=start-end).

    Returns (start, end) or None if invalid.
    """
    if not range_header.startswith("bytes="):
        return None

    range_spec = range_header[6:].strip()
    if "," in range_spec:
        # Multiple ranges not supported; client can request single range
        return None

    parts = range_spec.split("-", 1)
    if len(parts) != 2:
        return None

    start_str, end_str = parts[0].strip(), parts[1].strip()

    try:
        if start_str and end_str:
            start = int(start_str)
            end = int(end_str)
            if start > end or start >= file_size:
                return None
            end = min(end, file_size - 1)
            return start, end
        elif start_str and not end_str:
            start = int(start_str)
            if start >= file_size:
                return None
            return start, file_size - 1
        elif not start_str and end_str:
            suffix_length = int(end_str)
            if suffix_length <= 0:
                return None
            start = max(0, file_size - suffix_length)
            return start, file_size - 1
        else:
            return None
    except ValueError:
        return None


def create_download_response(
    game_id: str,
    range_header: str | None = None,
    storage_dir: Path | None = None,
) -> Response:
    """Build streaming download response supporting HTTP Range requests."""
    target_path = get_recording_path(game_id, storage_dir)

    if not target_path.exists() or not target_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recording '{game_id}' not found on storage",
        )

    file_size = target_path.stat().st_size
    filename = f"{target_path.stem}.mp3"
    content_disposition = f'attachment; filename="{filename}"'

    common_headers = {
        "Accept-Ranges": "bytes",
        "Content-Disposition": content_disposition,
        "Cache-Control": "private, no-cache, no-transform",
    }

    if range_header:
        parsed_range = parse_range_header(range_header, file_size)
        if parsed_range is None:
            # 416 Range Not Satisfiable
            return Response(
                status_code=status.HTTP_416_RANGE_NOT_SATISFIABLE,
                headers={
                    "Content-Range": f"bytes */{file_size}",
                    "Accept-Ranges": "bytes",
                },
            )

        start, end = parsed_range
        content_length = end - start + 1
        headers = {
            **common_headers,
            "Content-Range": f"bytes {start}-{end}/{file_size}",
            "Content-Length": str(content_length),
        }

        return StreamingResponse(
            content=file_chunk_generator(target_path, start=start, length=content_length),
            status_code=status.HTTP_206_PARTIAL_CONTENT,
            media_type="audio/mpeg",
            headers=headers,
        )

    # Standard full file stream
    headers = {
        **common_headers,
        "Content-Length": str(file_size),
    }

    return StreamingResponse(
        content=file_chunk_generator(target_path, start=0, length=file_size),
        status_code=status.HTTP_200_OK,
        media_type="audio/mpeg",
        headers=headers,
    )


def delete_recording_file(game_id: str, storage_dir: Path | None = None) -> bool:
    """Delete recording file from filesystem if present."""
    target_path = get_recording_path(game_id, storage_dir)
    if target_path.exists():
        target_path.unlink()
        return True
    return False
