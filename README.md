# 🎧 League Voice Recorder Backend

[![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)](Dockerfile)
[![TLS 1.3](https://img.shields.io/badge/Security-Native%20TLS%201.3-success)](docs/SECURITY_AND_BOT_SHIELD.md)

**High-performance, centralized remote audio storage service for the [League Voice Recorder](https://github.com/betterix/league-voice-recorder) desktop application.**

Written in pure **Rust** with [Axum](https://github.com/tokio-rs/axum) and [Tokio](https://tokio.rs/), built for low latency, zero memory leaks, and resilient direct-internet exposure.

---

## ⚡ Key Highlights

- **Blazing Fast in Rust**: Compiled native binary with bounded memory streaming (64 KB chunks).
- **Direct-Port TLS 1.3**: Listens directly on port `8443` without requiring Nginx or reverse proxy buffering.
- **Three-Tier Security**: Isolated API roles (`UPLOAD_KEY`, `PULL_KEY`, `ADMIN_KEY`) verified in constant time.
- **Automated Bot Shield**:
  - Zero-tolerance scanner signature detection (instant permanent ban).
  - Hybrid Datacenter / VPS bot detection (blocks automated cloud scrapers and crawlers).
  - In-memory sliding-window rate limiting & brute-force IP protection.
- **Resumable Audio Transfers**: Full HTTP Range support (`206 Partial Content`) for interrupted downloads or VLC streaming.
- **Pure Rust Audio Engine**: Fast MPEG-1 Layer 3 frame parsing to validate audio integrity and extract duration, bitrate, and sample rate without external C libraries.
- **Hardened SQLite WAL**: Concurrent non-blocking reads and writes with 30s busy timeouts.
- **Cloaked Web Dashboard**: Zero-CDN embedded dark dashboard at `/web` with IP whitelist cloaking (returns `404 Not Found` to unauthorized scanners).

---

## 🚀 Quick Start

### Running with Docker Compose

1. **Clone the repository:**
   ```bash
   git clone https://github.com/betterix/league-voice-recorder-backend.git
   cd league-voice-recorder-backend
   ```

2. **Configure your environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your keys and configuration
   ```

3. **Start the service:**
   ```bash
   docker compose up -d --build
   ```

4. **Verify service health:**
   ```bash
   curl -k -H "X-API-Key: YOUR_PULL_KEY" https://localhost:8443/api/v1/health
   ```

---

## 🧭 Documentation

Detailed technical guides and operational references are organized modularly in the [`docs/`](docs/) directory:

- 🏗️ **[System Architecture](docs/ARCHITECTURE.md)** — Architectural design, module layout, and state management.
- 🛡️ **[Security Model & Bot Shield](docs/SECURITY_AND_BOT_SHIELD.md)** — Three-key auth, rate limiting, scanner detection, and hybrid VPS shield.
- 🎵 **[Audio Pipeline](docs/AUDIO_PIPELINE.md)** — Chunked streaming uploads, Mutagen/MPEG verification, and Range requests.
- 📡 **[REST API Reference](docs/API_REFERENCE.md)** — Complete endpoint definitions for `/api/v1/health` and `/api/v1/recordings`.
- 🖥️ **[Web Dashboard](docs/WEB_DASHBOARD.md)** — Embedded cloaked administration UI, threat audit log, and streaming playback.
- 🚢 **[Deployment & Operations](docs/DEPLOYMENT.md)** — Production TLS certificates, Docker Compose, and native compilation.

---

## 🛠️ Development & Testing

```bash
# Check code formatting & clippy lints
cargo fmt --check
cargo clippy -- -D warnings

# Run full integration test suite
cargo test

# Build optimized production binary
cargo build --release
```

---

## 📄 License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
