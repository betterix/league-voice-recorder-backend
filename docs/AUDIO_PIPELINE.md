# Audio Pipeline & Storage Mechanics

The audio subsystem is built for streaming high-capacity audio uploads and resumable partial downloads while maintaining bounded memory consumption.

---

## 1. Upload Processing Pipeline

```mermaid
flowchart TD
    Client["Client: POST /api/v1/recordings/game_id"]
    
    Step1["1. Game ID Validation<br/>Regex: ^[a-zA-Z0-9_-]{1,64}$"]
    Err1["Reject Traversal Characters<br/>HTTP 400 Bad Request"]
    
    Step2["2. Duplicate Check in DB<br/>Query SQLite recordings table"]
    Err2["Abort Duplicate Game ID<br/>HTTP 409 Conflict"]
    
    Step3["3. Chunked Streaming Write<br/>• Stream 64 KB chunks to .tmp_game_id_uuid.mp3<br/>• Compute incremental SHA-256 hash<br/>• Enforce MAX_UPLOAD_MB limit"]
    Err3["Payload Too Large<br/>HTTP 413 Payload Too Large"]
    
    Step4["4. Checksum Verification<br/>Constant-time subtle::ConstantTimeEq"]
    Err4["Checksum Mismatch<br/>HTTP 400 Bad Request"]
    
    Step5["5. MPEG Audio Validation<br/>Pure Rust MPEG-1 Layer 3 frame parser<br/>• Extract duration, bitrate, sample rate"]
    Err5["Corrupt or Invalid MP3<br/>HTTP 400 Bad Request"]
    
    Step6["6. Atomic File Rename<br/>Atomically rename .tmp file to game_id.mp3"]
    
    Step7["7. SQLite DB Commit<br/>Insert match metadata into recordings<br/>Rollback and unlink file on error"]

    Client --> Step1
    Step1 -->|Invalid Path| Err1
    Step1 -->|Valid ID| Step2
    Step2 -->|Already Exists| Err2
    Step2 -->|New Game ID| Step3
    Step3 -->|Exceeds Limit| Err3
    Step3 -->|Write Complete| Step4
    Step4 -->|Hash Mismatch| Err4
    Step4 -->|Hash Verified| Step5
    Step5 -->|Invalid Frame Header| Err5
    Step5 -->|Valid MPEG-1 Layer 3| Step6
    Step6 --> Step7
```

### 1.1 Game ID Sanitization
- Validated against regex: `^[a-zA-Z0-9_-]{1,64}$`.
- Characters such as `/`, `\`, `..`, and null bytes are rejected with `400 Bad Request`.

### 1.2 Bounded Memory Streaming
- Audio is never buffered entirely into memory.
- Files stream chunk-by-chunk using a 64 KB buffer directly to disk.

### 1.3 Pure Rust MPEG Frame Parsing
- Inspects MPEG-1 Audio Layer III frame headers (skipping ID3v2 metadata if present).
- Calculates exact duration: `(total_frames * 1152) / sample_rate`.
- Extracts bitrate (kbps) and sample rate (Hz).
- Requires zero external C libraries (no ffmpeg, no libmp3lame).

---

## 2. Resumable Downloads & HTTP Range Requests

Clients, VLC players, synchronizers, and browsers query:
`GET /api/v1/recordings/{game_id}/download`

### 2.1 Range Header Support
The storage layer parses HTTP Range headers:
- `Range: bytes=0-1048575` (first 1 MB)
- `Range: bytes=1048576-` (from byte 1 MB to EOF)
- `Range: bytes=-524288` (suffix range: last 512 KB)

### 2.2 Response Specifications
- **Valid Range**: Returns `206 Partial Content` with `Content-Range: bytes start-end/total` and `Content-Length`.
- **Invalid / Out-of-bounds Range**: Returns `416 Range Not Satisfiable` with `Content-Range: bytes */total`.
- **Full File Request**: Returns `200 OK` with `Accept-Ranges: bytes` and `Content-Disposition: attachment; filename="<game_id>.mp3"`.
