# AGENTS.md — League Voice Recorder Backend

Welcome to the **League Voice Recorder Backend** developer and agent documentation. This document is tailored for AI agents, DevOps engineers, and backend developers to understand the architecture, security models, data flows, operational conventions, and extension guidelines for this codebase.

---

## 1. 🎯 Project Purpose & Mission

The `league-voice-recorder-backend` serves as the centralized remote audio storage service for the [League Voice Recorder](https://github.com/betterix/league-voice-recorder) desktop application.

It enables competitive esports teams, players, coaches, and analysts to:
1. **Securely Upload**: Players' desktop recording clients automatically stream recorded scrimmage voice audio to the backend immediately after each League of Legends match ends.
2. **Organize by Game ID**: Scrimmage recordings are stored as `<GAME_ID>.mp3` (e.g., `8018190134.mp3`) accompanied by rich metadata (match date, duration, bitrate, sample rate, team tag, notes, and SHA-256 integrity hashes).
3. **Stream & Download**: Coaches and analysts can query, browse, and directly stream or download audio files into VLC or the desktop synchronizer via resumable HTTP Range requests (`206 Partial Content`).
4. **Delete & Manage**: Authorized uploaders or administrators can delete scrimmage audio and purge its metadata cleanly.

---

## 2. 🧭 Core Architecture & Design Principles

### 2.1 Pure Headless API
- **No Web UI / Frontend**: No HTML templates, Jinja2, static assets, or browser admin interfaces.
- **RESTful JSON**: All API operations are versioned under `/api/v1` and strictly serialized via Pydantic schemas.

### 2.2 Direct-Port Ingress (Native TLS 1.3)
- **Direct Internet Exposure**: Runs on direct port `8443` (TCP) over HTTPS.
- **No Mandatory Reverse Proxy**: Uvicorn natively terminates TLS 1.3 with OpenSSL AEAD cipher suites (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`).
- **No CDN / Proxy Buffering**: Direct communication ensures large audio transfers (up to 250 MB) stream without intermediate upload truncations or proxy timeouts.
- **Certificate Support**: Production Let's Encrypt certificates (`/app/certs/cert.pem`, `/app/certs/key.pem`) and development ECDSA self-signed certificate generation with persistent SANs.

### 2.3 Strict Three-Key Authentication
All authenticated endpoints require the `X-API-Key` HTTP header:
- `UPLOAD_KEY`: Scrimmage recording clients / players (Upload, Download, List, Metadata, Delete).
- `PULL_KEY`: Analysts, coaches, and teammates (Download, List, Metadata). Write and delete attempts return `403 Forbidden`.
- `ADMIN_KEY`: Master administrative key granting full read, write, and telemetry access.
- **Constant-Time Verification**: All secret comparisons use `secrets.compare_digest()` to eliminate timing attacks.
- **Brute-Force IP Protection**: 5 failed authentication attempts from any IP within 60 seconds trigger a temporary 10-minute block across all endpoints (`429 Too Many Requests`).

### 2.4 Hardened SQLite WAL Storage
- SQLite configured with Write-Ahead Logging (`PRAGMA journal_mode=WAL;`), `synchronous=NORMAL;`, and 30-second busy timeout for safe concurrent reads and writes.
- Foreign keys enabled; query indexes on `game_id`, `team_tag`, and `created_at`.

---

## 3. 📁 Repository & Module Map

```text
league-voice-recorder-backend/
├── app/
│   ├── __init__.py           # Package version definition
│   ├── config.py             # Pydantic Settings, environment validator, and security checks
│   ├── security.py           # Role authorization, rate limiter, IP blocker, and key generation CLI
│   ├── database.py           # SQLite engine, connection pragmas, and session management
│   ├── models.py             # SQLAlchemy Declarative model for recordings
│   ├── schemas.py            # Pydantic request & response schemas
│   ├── storage.py            # MP3 chunked upload/streaming, Mutagen parsing, range requests
│   ├── main.py               # FastAPI application factory, middleware, TLS listener
│   └── api/
│       ├── __init__.py       # Router namespace
│       ├── health.py         # Authenticated health & storage diagnostics
│       └── recordings.py     # Endpoints: upload, list, get, download, delete
├── certs/
│   └── .gitkeep              # Mount point for TLS certificates
├── tests/
│   ├── __init__.py           # Test package
│   ├── conftest.py           # Test fixtures, test DB, synthetic MP3 generator
│   ├── test_security.py      # Auth, brute-force IP blocking, rate limits, TLS tests
│   ├── test_upload.py        # Streaming upload, Mutagen validation, checksum tests
│   ├── test_download.py      # Resumable range requests, partial content tests
│   └── test_api.py           # Health, query, search, and delete tests
├── .dockerignore             # Excludes .venv, data, certs from Docker build context
├── .env.example              # Clean configuration template with generic placeholders
├── .gitignore                # Excludes secrets, certificates, data, and cache
├── Dockerfile                # Multi-stage hardened Alpine container (UID 10001)
├── docker-compose.yml        # Production compose configuration
├── pyproject.toml            # Project dependencies, Ruff, and Pytest configuration
├── requirements.txt          # Production package pins
├── README.md                 # User & deployment guide
└── AGENTS.md                 # Agent and developer instruction manual
```

---

## 4. 🔑 Authentication & Permissions Reference

### Permission Matrix

| Operation | Endpoint | `PULL_KEY` | `UPLOAD_KEY` | `ADMIN_KEY` |
|---|---|:---:|:---:|:---:|
| **Health Check & Telemetry** | `GET /api/v1/health` | ✅ | ✅ | ✅ |
| **List Recordings** | `GET /api/v1/recordings` | ✅ | ✅ | ✅ |
| **Get Recording Metadata** | `GET /api/v1/recordings/{game_id}` | ✅ | ✅ | ✅ |
| **Download Recording (MP3)** | `GET /api/v1/recordings/{game_id}/download` | ✅ | ✅ | ✅ |
| **Upload Recording (MP3)** | `POST /api/v1/recordings/{game_id}` | ❌ *(403)* | ✅ | ✅ |
| **Delete Recording** | `DELETE /api/v1/recordings/{game_id}` | ❌ *(403)* | ✅ | ✅ |

### Key Generation CLI
To generate fresh, cryptographically secure 256-bit CSPRNG API keys:

```bash
uv run python -m app.security
```

Format of generated keys:
- Upload: `lvr_upload_<32_random_urlsafe_bytes>`
- Pull: `lvr_pull_<32_random_urlsafe_bytes>`
- Admin: `lvr_admin_<32_random_urlsafe_bytes>`

Tokens are placed in `.env` and are persistent across container restarts.

---

## 5. 🎧 Audio Pipeline & Storage Mechanics

### 5.1 Upload Pipeline (`app/storage.py`)
1. **Game ID Sanitization**: Regex `^[a-zA-Z0-9_-]{1,64}$`. Directory traversal sequences (`..`, `/`, `\`) are rejected with `400 Bad Request`.
2. **Duplicate Check**: Verifies whether `<game_id>.mp3` already exists on disk or database. Returns `409 Conflict` if present.
3. **Streaming Chunked Write**: Writes in 64 KB chunks to a temporary file (`.tmp_<game_id>_<uuid>`).
4. **Size Enforcement**: Aborts immediately with `413 Content Too Large` if bytes exceed `MAX_UPLOAD_MB`.
5. **On-The-Fly SHA-256**: Incremental hash computation during upload. Verified against client-supplied `X-Checksum-SHA256` header (constant time).
6. **MPEG Validation & Telemetry via Mutagen**: Parses MPEG audio frames using `mutagen.mp3.MP3`. Validates audio integrity and extracts duration, bitrate, and sample rate.
7. **Atomic Rename & Cleanup**: Atomically moves `.tmp_*` to `<game_id>.mp3`. On any failure, temp files are unlinked to avoid orphaned disk usage.

### 5.2 Resumable Downloads & HTTP Range Requests
- Parses `Range: bytes=start-end`, `bytes=start-`, and suffix `bytes=-suffix`.
- Valid ranges return `206 Partial Content` with `Content-Range: bytes start-end/total`.
- Out-of-bounds ranges return `416 Range Not Satisfiable` with `Content-Range: bytes */total`.
- Full downloads return `200 OK` with `Accept-Ranges: bytes` and `Content-Disposition: attachment; filename="<game_id>.mp3"`.

---

## 6. 🛠️ Development & Testing Workflows

### Environment Setup
```bash
# Create virtual environment and install dependencies
uv venv
uv pip install -r requirements.txt
uv pip install pytest pytest-asyncio httpx httpx2 coverage ruff
```

### Running Automated Tests
```bash
# Run pytest test suite
uv run pytest -v

# Run with test coverage report
uv run coverage run -m pytest
uv run coverage report -m
```

### Code Formatting & Quality
```bash
# Check formatting and linting
uv run ruff check .
uv run ruff format --check .

# Auto-fix linting and formatting
uv run ruff check . --fix
uv run ruff format .
```

---

## 7. 🤖 Guidelines for AI Agents Working on This Codebase

When modifying or extending this service:

1. **Maintain Headless Architecture**: Never introduce frontend templates, HTML views, static directories, or browser panels.
2. **Preserve Direct-Port Native TLS**: Do not alter Uvicorn TLS 1.3 configuration to require an external reverse proxy.
3. **Constant-Time Comparison**: Always use `secrets.compare_digest()` for any secret or token evaluation.
4. **Bounded Memory Operations**: Never read entire audio files into memory (`file.read()` all at once). Always stream in chunks (`CHUNK_SIZE = 64 * 1024`).
5. **Database / Storage Consistency**: If database insertion fails during upload, always delete the corresponding file from disk in an exception rollback block.
6. **No Real Secrets in Source Control**: Never commit active API keys, private keys, or `.env` files. Use generic placeholders in documentation.
7. **Keep Test Coverage High**: Maintain >= 90% test coverage. Add tests for all newly introduced endpoints or validation logic.
8. **Ruff Compliance**: Run `uv run ruff check .` and `uv run ruff format --check .` before concluding any modifications.
