# 🎧 League Voice Recorder Backend

<div align="center">

[![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![GitHub Release](https://img.shields.io/github/v/release/betterix/league-voice-recorder-backend?color=brightgreen&logo=github)](https://github.com/betterix/league-voice-recorder-backend/releases)
[![Docker Multi-Arch](https://img.shields.io/badge/Docker-amd64%20%7C%20arm64-2496ED?logo=docker&logoColor=white)](https://github.com/betterix/league-voice-recorder-backend/pkgs/container/league-voice-recorder-backend)
[![Security: TLS 1.3](https://img.shields.io/badge/Security-Native%20TLS%201.3-success?logo=shield)](docs/SECURITY_AND_BOT_SHIELD.md)
[![RAM Usage](https://img.shields.io/badge/RAM%20Footprint-1.35%20MiB-blueviolet)](https://github.com/tokio-rs/axum)
[![CI Status](https://github.com/betterix/league-voice-recorder-backend/actions/workflows/ci.yml/badge.svg)](https://github.com/betterix/league-voice-recorder-backend/actions/workflows/ci.yml)
[![CodeQL](https://github.com/betterix/league-voice-recorder-backend/actions/workflows/codeql.yml/badge.svg)](https://github.com/betterix/league-voice-recorder-backend/actions/workflows/codeql.yml)

**Ultra-fast, ultra-lean, centralized remote audio storage service for the [League Voice Recorder](https://github.com/betterix/league-voice-recorder) desktop application.**

*Engineered by **[Betterix](https://github.com/betterix)** in pure Rust with [Axum](https://github.com/tokio-rs/axum) and [Tokio](https://tokio.rs/). Built for rock-solid reliability, zero memory leaks, and resilient direct-internet exposure.*

---

[Key Highlights](#-key-highlights) • [Supported Versions](#-supported-versions--security) • [Quick Start](#-quick-start) • [Access Logging](#-real-time-access-logging) • [API Reference](#-api-endpoints) • [Documentation](#-documentation) • [Contributing](#-contributing) • [License](#-license)

---

</div>

## ⚡ Key Highlights

- 🏎️ **Ultra-Lean Resource Usage**: Operates under **1.35 MiB of resident RAM** in production. Bounded 64 KB chunked streaming guarantees zero memory bloat even when transferring hundreds of megabytes.
- 🔒 **Direct-Port Ingress (Native TLS 1.3)**: Binds directly to port `8443` (TCP) over native HTTPS with OpenSSL AEAD cipher suites (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`). No Nginx or reverse proxy required.
- 🐳 **Native Multi-Architecture OCI Images**: Automatically built and published to GHCR with native hardware compilation for both **`linux/amd64`** and **`linux/arm64`** without emulation slowdowns.
- 📊 **Real-Time Structured Access Logging**: Immediate terminal visibility into incoming traffic (client IP, HTTP method, target route, HTTP status, and μs/ms latency) paired with automated **healthcheck noise suppression** to keep Docker logs clean.
- 🛡️ **Three-Tier Constant-Time Authentication**:
  - `UPLOAD_KEY`: Client recording uploaders (Upload, Download, List, Metadata).
  - `PULL_KEY`: Analysts, coaches, and review tools (Download, List, Metadata).
  - `ADMIN_KEY`: Full administrative permissions, bans, and purges.
  - All token comparisons execute in constant time (`subtle::ConstantTimeEq`) to eliminate timing attacks.
- 🤖 **Automated Bot Shield & Exploit Defense**:
  - **Zero-Tolerance Scanner Traps**: Instant permanent IP ban on probe signatures (`/.env`, `/.git`, `/actuator`, `/console`, `PROPFIND`).
  - **Heuristic Error Ban**: Automatically blacklists scanning hosts exceeding error thresholds (5 invalid requests in 60s).
  - **Hybrid VPS / Datacenter Bot Defense**: Blocks automated scraping crawlers from cloud datacenters (AWS, DigitalOcean, Hetzner, OVH, Linode) while allowing genuine API clients.
  - **Brute-Force Protection**: 5 failed auth attempts trigger an instant 10-minute firewall block across all endpoints.
- 🎵 **Pure Rust MPEG-1 Layer 3 Audio Engine**: Pure-Rust frame parser validates audio stream integrity and extracts playback duration, bitrate, and sample rate with zero C dependencies.
- ⏯️ **Resumable HTTP Range Streaming**: Full `206 Partial Content` support for seamless streaming into VLC, media players, or resuming interrupted network transfers.
- 💾 **Hardened SQLite WAL Storage**: SQLite backend configured with Write-Ahead Logging (`WAL`), `synchronous=NORMAL`, and 30-second busy timeout for high-concurrency read/write safety.
- 🕵️ **Cloaked Embedded Dashboard**: Zero-dependency dark management interface at `/web` with IP whitelist cloaking (returns `404 Not Found` to unauthorized external scanners).

---

## 🛡️ Supported Versions & Security

> [!IMPORTANT]
> **Version 1.3.x is the latest and officially supported release stream.**  
> We strongly recommend all teams run **v1.3.x**. Legacy releases (< 1.3.0, including the old Python prototype) are **deprecated, incompatible, inefficient, and can be unsafe**. See [SECURITY.md](SECURITY.md) for full details.

| Version | Status | Memory (RAM) | TLS 1.3 | Engine |
| :--- | :---: | :---: | :---: | :--- |
| **`v1.3.x`** (Latest) | 🟢 **Active / Recommended** | **~1.35 MiB** | Native Direct Port | Pure Rust (Axum 0.8 + Tokio) |
| `v1.2.x` | 🔴 **End-of-Life / Incompatible** | ~150 MiB | Reverse Proxy Required | Python (FastAPI + Uvicorn) |
| `< v1.2.0` | 🔴 **End-of-Life** | Legacy | None | Prototype |

---

## 🚀 Quick Start

### Option A: Pull Multi-Arch Image from GHCR (Recommended)

Run the pre-built multi-architecture container (`amd64` and `arm64` supported automatically):

```bash
docker run -d \
  --name league-voice-recorder-backend \
  -p 8443:8443 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/certs:/app/certs \
  -e ADMIN_KEY="your-super-secret-admin-key" \
  -e UPLOAD_KEY="your-upload-api-key" \
  -e PULL_KEY="your-pull-api-key" \
  --restart unless-stopped \
  ghcr.io/betterix/league-voice-recorder-backend:latest
```

### Option B: Deploy with Docker Compose

1. **Clone the repository:**
   ```bash
   git clone https://github.com/betterix/league-voice-recorder-backend.git
   cd league-voice-recorder-backend
   ```

2. **Configure your environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your strong API keys and credentials
   ```

3. **Start the service:**
   ```bash
   docker compose up -d
   ```

4. **Verify health:**
   ```bash
   curl -k -H "X-API-Key: YOUR_PULL_KEY" https://localhost:8443/api/v1/health
   ```

---

## 📊 Real-Time Access Logging

The service outputs clean, structured real-time access logs for active API queries, uploads, and administrative actions:

```text
2026-11-17T12:00:01Z  INFO [HTTP] 198.51.100.12 POST /api/v1/recordings/8018190134 -> 200 OK (142ms)
2026-11-17T12:00:05Z  INFO [HTTP] 198.51.100.45 GET /api/v1/recordings/8018190134/download -> 206 Partial Content (8ms)
2026-11-17T12:00:15Z  WARN [HTTP] 203.0.113.88 GET /api/v1/recordings -> 401 Unauthorized (120µs)
```

### Intelligent Healthcheck Noise Suppression
Docker and Kubernetes monitoring agents query `/api/v1/health` every 15–30 seconds. To prevent spamming your logs, **successful healthchecks (`200 OK`) are automatically suppressed** from the console output. If a health probe ever encounters an error or authentication failure, it is instantly logged at warning/error level.

---

## 🔑 API Endpoints

All endpoints require the `X-API-Key` header with appropriate tier permissions:

| Operation | Endpoint | Method | `PULL_KEY` | `UPLOAD_KEY` | `ADMIN_KEY` |
|---|---|:---:|:---:|:---:|:---:|
| **Health & Telemetry** | `/api/v1/health` | `GET` | ✅ | ✅ | ✅ |
| **List Recordings** | `/api/v1/recordings` | `GET` | ✅ | ✅ | ✅ |
| **Get Metadata** | `/api/v1/recordings/{game_id}` | `GET` | ✅ | ✅ | ✅ |
| **Download Recording** | `/api/v1/recordings/{game_id}/download` | `GET` | ✅ | ✅ | ✅ |
| **Upload Recording** | `/api/v1/recordings/{game_id}` | `POST` | ❌ *(403)* | ✅ | ✅ |
| **Delete Recording** | `/api/v1/recordings/{game_id}` | `DELETE` | ❌ *(403)* | ❌ *(403)* | ✅ |

For complete schemas, request headers, query filters, and error representations, consult the [REST API Reference](docs/API_REFERENCE.md).

---

## 🧭 Documentation

Modular documentation is available in the [`docs/`](docs/) directory:

- 🏗️ **[System Architecture](docs/ARCHITECTURE.md)** — Axum concurrency, thread safety, state management, and memory benchmarks.
- 🛡️ **[Security & Bot Shield](docs/SECURITY_AND_BOT_SHIELD.md)** — Constant-time auth, IP brute-force lockouts, scanner honeypots, and cloud crawler filtering.
- 🎵 **[Audio Pipeline](docs/AUDIO_PIPELINE.md)** — Bounded chunked streaming, pure-Rust MPEG frame parsing, and HTTP Range downloads.
- 📡 **[REST API Reference](docs/API_REFERENCE.md)** — Complete OpenAPI/REST specification and query parameters.
- 🖥️ **[Web Dashboard](docs/WEB_DASHBOARD.md)** — Cloaked administrative web UI, threat audit log, and in-browser playback.
- 🚢 **[Deployment & Operations](docs/DEPLOYMENT.md)** — Production TLS certificates, multi-arch Docker deployment, and troubleshooting.

---

## 🛠️ Development & Quality Assurance

```bash
# Check formatting
cargo fmt --check

# Run strict linter (zero warnings policy)
cargo clippy -- -D warnings

# Run entire integration test suite
cargo test

# Build optimized release binary
cargo build --release
```

---

## 🤝 Contributing & Community

Contributions are welcome! Please read our community guidelines before opening a pull request:
- 📜 **[Code of Conduct](CODE_OF_CONDUCT.md)**: Contributor Covenant v2.1 standards.
- 🛠️ **[Contributing Guide](CONTRIBUTING.md)**: Development guidelines, memory constraints, and PR workflows.
- 🔒 **[Security Policy](SECURITY.md)**: Supported versions and responsible disclosure procedures.
- 🐛 **[Issue Templates](.github/ISSUE_TEMPLATE/)**: Templates for bug reports and feature requests.

---

## 📄 License

This project is open-source software licensed under the **[GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE)**.

Copyright (c) 2026 **[Betterix](https://github.com/betterix)**.
