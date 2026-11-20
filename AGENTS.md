# AGENTS.md — League Voice Recorder Backend (Rust Edition)

Welcome to the **League Voice Recorder Backend** developer and agent documentation. This document is tailored for AI agents, DevOps engineers, and backend developers to understand the architecture, security models, data flows, operational conventions, release pipelines, and extension guidelines for this codebase.

---

## 1. 🎯 Project Purpose & Mission

The `league-voice-recorder-backend` serves as the centralized remote audio storage service for the [League Voice Recorder](https://github.com/betterix/league-voice-recorder) desktop application.

It enables competitive esports teams, players, coaches, and analysts to:
1. **Securely Upload**: Players' desktop recording clients automatically stream recorded scrimmage voice audio to the backend immediately after each League of Legends match ends.
2. **Organize by Game ID**: Scrimmage recordings are stored as `<GAME_ID>.mp3` (e.g., `8018190134.mp3`) accompanied by rich metadata (match date, duration, bitrate, sample rate, team tag, notes, and SHA-256 integrity hashes).
3. **Stream & Download**: Coaches and analysts can query, browse, and directly stream or download audio files into VLC or the desktop synchronizer via resumable HTTP Range requests (`206 Partial Content`).
4. **Delete & Manage**: Authorized uploaders or administrators can delete scrimmage audio and purge its metadata cleanly.

---

## 2. 🧭 Core Architecture & Design Principles (v1.3.x)

### 2.1 Pure Rust Axum Engine & Ultra-Low Footprint
- **Engine**: Rewritten entirely in pure Rust using [Axum 0.8](https://github.com/tokio-rs/axum) and [Tokio](https://tokio.rs/).
- **Resource Footprint**: Consumes under **1.35 MiB resident RAM** in production (a ~99% reduction compared to the legacy ~150 MiB Python backend).
- **Deprecation of Legacy Versions**: Versions prior to 1.3.x (e.g. 1.2.x Python FastAPI) are completely deprecated, incompatible, and unsupported. All development and production deployments strictly target the 1.3.x stream on the `main` branch.

### 2.2 Direct-Port Ingress (Native TLS 1.3)
- **Direct Internet Exposure**: Runs directly on port `8443` (TCP) over HTTPS.
- **No Mandatory Reverse Proxy**: Axum natively terminates TLS 1.3 via `axum-server` and `rustls` using OpenSSL AEAD cipher suites (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`).
- **No CDN / Proxy Buffering**: Direct communication ensures large audio transfers (up to 250 MB) stream without intermediate upload truncations or proxy timeouts.
- **Certificate Support**: Production Let's Encrypt certificates (`/app/certs/cert.pem`, `/app/certs/key.pem`) and development ECDSA self-signed certificate generation with persistent SANs.

### 2.3 Strict Three-Key Authentication
All authenticated API endpoints require the `X-API-Key` HTTP header:
- `UPLOAD_KEY`: Scrimmage recording clients / players (Upload, Download, List, Metadata). Destructive delete attempts return `403 Forbidden`.
- `PULL_KEY`: Analysts, coaches, and teammates (Download, List, Metadata). Write and delete attempts return `403 Forbidden`.
- `ADMIN_KEY`: Master administrative key granting full read, write, delete, and telemetry access.
- **Constant-Time Verification**: All secret comparisons use `subtle::ConstantTimeEq` to eliminate timing attacks.

### 2.4 Multi-Tier Defense & Bot Shield
- **Brute-Force IP Protection**: 5 failed authentication attempts from any IP within 60 seconds trigger a temporary 10-minute block across all endpoints (`429 Too Many Requests`).
- **Automated Scanner & Exploit Probe Defense**: Zero-tolerance signature detection (`/.env`, `/.git`, `/actuator`, `/console`, `PROPFIND`, etc.) triggers an instant permanent IP ban. Heuristic probe defense tracks unauthenticated client errors (404/405/400) and automatically bans scanning IPs upon reaching threshold (5 attempts in 60s). Configured `WEB_ALLOWED_IPS` management hosts and loopback addresses are exempt.
- **Hybrid Datacenter / VPS Bot Shield**: Blocks automated crawler traffic from cloud hosts (DigitalOcean, AWS, Hetzner, OVH, Linode, etc.) via offline keyword checks and asynchronous `ip-api.com` categorization. Bypassed for authenticated API clients.
- **Cloaked Web Dashboard**: Zero-dependency embedded web interface at `/web` for browser review, playback, and manual uploads. Access is strictly IP-whitelisted and HTTP Basic Auth protected, returning `404 Not Found` for unauthorized IPs to cloak the endpoint from network scanners.

### 2.5 Real-Time Structured Access Logging & Noise Suppression
- **Structured Access Logs**: Every API request is logged in real-time with client IP, HTTP method, path, HTTP status code, and execution duration in microseconds/milliseconds.
- **Healthcheck Noise Suppression**: Successful `/api/v1/health` probes (`200 OK`) are automatically filtered out from console output to prevent Docker/Kubernetes container logs from being flooded every 30 seconds. If a health probe fails or returns an error, it is logged immediately.

### 2.6 Hardened SQLite WAL Storage
- SQLite configured via `sqlx::SqlitePool` with Write-Ahead Logging (`PRAGMA journal_mode=WAL;`), `synchronous=NORMAL;`, and 30-second busy timeout for safe concurrent reads and writes.
- Foreign keys enabled; query indexes on `game_id`, `team_tag`, and `created_at`.

---

## 3. 📁 Repository & Module Map

```text
league-voice-recorder-backend/
├── Cargo.toml                # Project dependencies, build targets, and metadata (v1.3.3)
├── Cargo.lock                # Deterministic dependency lockfile
├── Dockerfile                # Multi-stage hardened Alpine container (UID 10001 appuser)
├── docker-compose.yml        # Production Docker compose configuration
├── .dockerignore             # Excludes target, certs, data from Docker build context
├── .env.example              # Clean configuration template with generic placeholders
├── .gitignore                # Excludes secrets, certificates, target/, and data
├── LICENSE                   # GNU Affero General Public License v3.0 (AGPL-3.0)
├── CODE_OF_CONDUCT.md        # Contributor Covenant v2.1 code of conduct
├── CONTRIBUTING.md           # Contribution guidelines, code standards, CI verification
├── SECURITY.md               # Security policy: 1.3.x support statement, vulnerability reporting
├── README.md                 # User guide, quickstart, badges, benchmarks, AGPL-3.0
├── AGENTS.md                 # Agent and developer instruction manual (this file)
├── .github/
│   ├── CODEOWNERS            # Project code ownership definition
│   ├── dependabot.yml        # Cargo & GitHub Actions automated dependency scanning
│   ├── PULL_REQUEST_TEMPLATE.md # Standard PR checklist and architectural verification
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md     # Structured bug report template
│   │   ├── feature_request.md# Structured feature proposal template
│   │   └── config.yml        # Directs security issues to private disclosure
│   └── workflows/
│       ├── ci.yml            # Automated fmt, clippy, test, and container build checks
│       ├── codeql.yml        # GitHub Advanced Security CodeQL v4 static analysis
│       └── release.yml       # Multi-arch (amd64/arm64) native compilation & GHCR release
├── docs/                     # Modular documentation chapters
│   ├── ARCHITECTURE.md       # High-level architecture, thread safety, state management
│   ├── SECURITY_AND_BOT_SHIELD.md # Three-key auth, scanner/probe detection, hybrid VPS shield
│   ├── AUDIO_PIPELINE.md     # MP3 chunked upload, validation, SHA-256, Range streaming
│   ├── API_REFERENCE.md      # OpenAPI/REST endpoints reference
│   ├── WEB_DASHBOARD.md      # Embedded cloaked UI and security operations
│   └── DEPLOYMENT.md         # TLS setup, Docker, and production operations
├── src/
│   ├── main.rs               # Server startup, TLS listener, lifecycle hooks
│   ├── lib.rs                # Core router, access logging middleware, noise suppression
│   ├── config.rs             # Configuration validation and environment loader
│   ├── db/
│   │   ├── mod.rs            # Database connection pool (SqlitePool) & pragmas
│   │   └── models.rs         # Database schema structs (Recording, BannedIP, etc.)
│   ├── security/
│   │   ├── mod.rs            # Security module root
│   │   ├── auth.rs           # 3-key authentication & constant-time validation
│   │   ├── rate_limiter.rs   # Sliding window rate limiter & brute force protection
│   │   ├── scanner.rs        # Scanner probe signature detection & heuristic bans
│   │   └── cert.rs           # TLS cert validation and dev ECDSA self-signed generation
│   ├── bot_shield/
│   │   ├── mod.rs            # Bot shield module root
│   │   └── ip_intel.rs       # Hybrid Datacenter/VPS bot detection (offline + ip-api.com)
│   ├── audio/
│   │   ├── mod.rs            # Audio module root
│   │   ├── mp3.rs            # Pure Rust MP3 frame parser, duration, bitrate, sample rate
│   │   └── storage.rs        # Chunked streaming upload, hash computation, range streaming
│   ├── api/
│   │   ├── mod.rs            # API router (/api/v1)
│   │   ├── health.rs         # GET /api/v1/health
│   │   └── recordings.rs     # Upload, list, metadata, download, delete endpoints
│   └── web/
│       ├── mod.rs            # Web module router (/web)
│       ├── auth.rs           # IP whitelist & HTTP Basic Auth
│       ├── router.rs         # Dashboard endpoints, streaming, download, upload, security
│       └── dashboard.html    # Zero-dependency modern dark dashboard template
└── tests/
    ├── common/mod.rs         # Test fixtures, mock MP3 generator, test app builder
    ├── test_api.rs           # Health, query, pagination, delete tests
    ├── test_upload.rs        # Streaming upload, sha256 validation, duplicate check
    ├── test_download.rs      # Resumable range requests (206 Partial Content)
    ├── test_security.rs      # 3-key auth, brute-force IP blocking, scanner probe detection
    └── test_web.rs           # Web dashboard, basic auth, IP whitelisting
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
| **Delete Recording** | `DELETE /api/v1/recordings/{game_id}` | ❌ *(403)* | ❌ *(403)* | ✅ |

---

## 5. 🚢 Multi-Arch CI/CD & Release Pipeline

The repository uses GitHub Actions for continuous integration and automated multi-architecture releases:

### 5.1 Release Architecture (`release.yml`)
- **Parallel Native Compilation**: Instead of slow QEMU emulation, builds run natively on dedicated hardware:
  - `build-amd64`: Built natively on GitHub `ubuntu-latest` (x86_64).
  - `build-arm64`: Built natively on GitHub `ubuntu-24.04-arm` (aarch64).
- **Push-by-Digest**: Each runner pushes its platform layer to GHCR by raw SHA-256 digest (`push-by-digest=true`). No intermediate platform tags (`:amd64` or `:arm64`) are created.
- **Manifest Stitching (`create-manifest`)**: `docker buildx imagetools create` merges both digests into clean multi-architecture tags (`:latest` and `:<version>`).
- **Release Assets**: The compiled standalone binary for x86_64 is packaged with sha256 checksums and attached to the GitHub Release.

### 5.2 Branch Hygiene
- **Single Active Branch**: Only the `main` branch is maintained. Feature and temporary branches must be deleted upon merging to keep repository state deterministic and clutter-free.

---

## 6. 🛠️ Development & Testing Workflows

### Building the Project
```bash
# Check code compilation
cargo check

# Build debug binary
cargo build

# Build optimized production binary
cargo build --release
```

### Running Automated Tests
```bash
# Run all unit and integration tests
cargo test

# Run a specific test suite
cargo test --test test_api
cargo test --test test_upload
cargo test --test test_download
cargo test --test test_security
cargo test --test test_web
```

### Code Formatting & Quality
```bash
# Check formatting
cargo fmt --check

# Check clippy linter warnings
cargo clippy -- -D warnings

# Auto-format codebase
cargo fmt
```

---

## 7. 🤖 Guidelines for AI Agents Working on This Codebase

When modifying or extending this service:

1. **Maintain Secure Architecture**: Core audio APIs under `/api/v1` remain strictly headless RESTful JSON. The optional `/web` dashboard remains zero-dependency embedded without external CDN links or tracking scripts.
2. **Preserve Direct-Port Native TLS**: Do not alter Axum TLS 1.3 configuration to require an external reverse proxy.
3. **Constant-Time Comparison**: Always use `subtle::ConstantTimeEq` for any secret or token evaluation.
4. **Bounded Memory Operations**: Never read entire audio files into memory (`tokio::fs::read` all at once). Always stream in chunks (`CHUNK_SIZE = 64 * 1024`).
5. **Noise-Free Logging**: Ensure access logs capture real client interactions while preserving healthcheck noise filtering (`/api/v1/health` 200 OK suppression).
6. **Database / Storage Consistency**: If database insertion fails during upload, always delete the corresponding file from disk in an exception rollback block.
7. **No Real Secrets or User IPs in Source Control**: Never commit active API keys, private keys, `.env` files, or user IP addresses. Use generic placeholders (`203.0.113.x` RFC 5737 documentation prefix) in documentation and tests.
8. **Keep Test Coverage High**: Maintain 100% test pass rate across all suites in `tests/`. Add integration tests for all newly introduced endpoints or validation logic.
9. **Clippy & Rustfmt Compliance**: Run `cargo clippy -- -D warnings` and `cargo fmt --check` before concluding any modifications.
10. **Branch Discipline**: Work exclusively on `main` unless branched for a specific PR. Prune old/stale remote branches.
11. **Git Push Prohibition**: Never execute `git push` or push changes to remote repositories unless explicitly instructed by the user.
