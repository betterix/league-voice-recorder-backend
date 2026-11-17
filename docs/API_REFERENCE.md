# REST API Reference (`/api/v1`)

All endpoints under `/api/v1` require authentication via the `X-API-Key` HTTP header.

---

## 1. Health & Diagnostics

### `GET /api/v1/health`
Returns runtime health status, version, storage capacity, and total recording count.

- **Required Roles**: `PULL`, `UPLOAD`, or `ADMIN`.
- **Response `200 OK`**:
```json
{
  "status": "ok",
  "version": "1.2.1",
  "authenticated_role": "pull",
  "storage_total_bytes": 104857600000,
  "storage_used_bytes": 12582912000,
  "storage_free_bytes": 92274688000,
  "recording_count": 42
}
```

---

## 2. Recordings API

### `POST /api/v1/recordings/{game_id}`
Uploads and registers a scrimmage audio recording.

- **Required Roles**: `UPLOAD` or `ADMIN`. (Callers with `PULL_KEY` receive `403 Forbidden`).
- **Headers**:
  - `X-API-Key`: Required upload or admin key.
  - `X-Checksum-SHA256`: Optional client-calculated 64-character SHA-256 hex digest for integrity verification.
- **Multipart Form Fields**:
  - `file`: Required MP3 binary file stream.
  - `team_tag`: Optional team identifier (e.g., `T1`, `G2`).
  - `notes`: Optional scrim notes or champion draft notes.
  - `match_date`: Optional ISO date string.
- **Response `201 Created`**:
```json
{
  "game_id": "8018190134",
  "filename": "8018190134.mp3",
  "file_size": 25165824,
  "duration": 1845.2,
  "bitrate": 128000,
  "sample_rate": 44100,
  "upload_timestamp": "2026-11-17T10:00:00Z",
  "team_tag": "T1",
  "notes": "Game 1 vs GenG",
  "match_date": "2026-11-17",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

---

### `GET /api/v1/recordings`
Lists recorded scrimmage audio files with pagination and search.

- **Required Roles**: `PULL`, `UPLOAD`, or `ADMIN`.
- **Query Parameters**:
  - `skip`: Records offset to skip (default: `0`).
  - `limit`: Maximum records to return (default: `50`, max: `100`).
  - `search`: Substring search matching `game_id` or `team_tag`.
- **Response `200 OK`**:
```json
{
  "items": [
    {
      "game_id": "8018190134",
      "filename": "8018190134.mp3",
      "file_size": 25165824,
      "duration": 1845.2,
      "bitrate": 128000,
      "sample_rate": 44100,
      "upload_timestamp": "2026-11-17T10:00:00Z",
      "team_tag": "T1",
      "notes": "Game 1 vs GenG",
      "match_date": "2026-11-17",
      "sha256": "e3b0c442..."
    }
  ],
  "total": 1,
  "skip": 0,
  "limit": 50
}
```

---

### `GET /api/v1/recordings/{game_id}`
Retrieves metadata for a specific game recording.

- **Required Roles**: `PULL`, `UPLOAD`, or `ADMIN`.
- **Response `200 OK`**: Returns `RecordingMetadataResponse` object.
- **Error `404 Not Found`**: When game ID does not exist.

---

### `GET /api/v1/recordings/{game_id}/download`
Streams the recording audio file with full HTTP Range request support.

- **Required Roles**: `PULL`, `UPLOAD`, or `ADMIN`.
- **Headers**:
  - `Range`: Optional byte range specification (`bytes=0-1048575`).
- **Response `200 OK`**: Full audio stream with `Content-Disposition: attachment`.
- **Response `206 Partial Content`**: Partial byte stream with `Content-Range: bytes start-end/total`.
- **Response `416 Range Not Satisfiable`**: If range is out of bounds.

---

### `DELETE /api/v1/recordings/{game_id}`
Deletes recording audio from storage and purges metadata from the database.

- **Required Roles**: `ADMIN` ONLY. (`UPLOAD` and `PULL` callers receive `403 Forbidden`).
- **Response `200 OK`**:
```json
{
  "message": "Recording '8018190134' successfully deleted",
  "game_id": "8018190134"
}
```
