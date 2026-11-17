# Contributing to League Voice Recorder Backend

First off, thank you for considering contributing to the **League Voice Recorder Backend**! It's contributions like yours that make this service reliable, secure, and blazing fast for esports teams worldwide.

---

## 🧭 Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please report any unacceptable behavior to [szabozsolt430@gmail.com](mailto:szabozsolt430@gmail.com).

---

## 🎯 Architecture & Versioning Notice

Starting with version **1.3.x**, the backend has been completely redesigned and rewritten in **pure Rust** (Axum 0.8 & Tokio):
- **Ultra-lean resource footprint**: Operates under **1.35 MiB** of resident RAM in production.
- **Native Direct-Port TLS 1.3**: Direct listener on port `8443` without requiring an external reverse proxy.
- **Strict Single-Branch Workflow**: Development occurs exclusively against the `main` branch.
- **Security-First**: Constant-time token verification, automated scanner honeypots, and hybrid datacenter/VPS crawler filtering.

Legacy versions (e.g. 1.2.x Python implementation) are completely deprecated, incompatible, and unsupported. All contributions must target the Rust v1.3.x codebase on the `main` branch.

---

## 🛠️ Setting Up Your Development Environment

### Prerequisites
- **Rust Toolchain**: `rustc` and `cargo` (1.80+ recommended). Install via [rustup.rs](https://rustup.rs/).
- **Docker & Docker Compose**: For containerized verification and multi-arch testing.
- **OpenSSL / Development Headers**: Standard development build tools (`build-essential`, `pkg-config`, `libssl-dev` on Debian/Ubuntu).

### Quick Setup

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/betterix/league-voice-recorder-backend.git
   cd league-voice-recorder-backend
   ```

2. **Prepare environment configuration:**
   ```bash
   cp .env.example .env
   ```

3. **Verify build and tests:**
   ```bash
   cargo check
   cargo test
   ```

4. **Run the local development server:**
   ```bash
   cargo run
   ```
   *Note: In development mode, the server automatically generates a temporary self-signed ECDSA certificate if no cert files are present.*

---

## 📋 Contribution Rules & Engineering Standards

All pull requests and code modifications must uphold the following architectural constraints:

### 1. Bounded Memory Streaming
- **Never** read entire audio recordings into memory at once (e.g., avoid unbounded `tokio::fs::read`).
- Always stream audio files in chunks (`CHUNK_SIZE = 64 * 1024` / 64 KB) across uploads and downloads.
- Honor HTTP Range headers (`206 Partial Content`) for resumable downloads.

### 2. Constant-Time Authentication
- Any token, password, or API key comparison must use constant-time algorithms (`subtle::ConstantTimeEq`) to prevent timing side-channel attacks.

### 3. Noise-Free Access Logging
- Real-time access logging is enabled for all API requests (reporting client IP, HTTP method, path, status, and duration).
- Healthcheck requests (`/api/v1/health`) that return success must remain suppressed in stdout logs to eliminate Docker monitoring noise.

### 4. Atomic Storage & Database Consistency
- If a database transaction or metadata insert fails during an audio upload, the staged audio file on disk must be unlinked/deleted immediately in a rollback handler.

### 5. Zero External Web Dependencies
- The embedded web dashboard (`/web`) must remain completely zero-dependency without external CDNs, Google Fonts, or external tracking scripts.

### 6. Secrets & PII Discipline
- Never commit real API keys, passwords, private keys, or actual user IP addresses.
- Use RFC 5737 documentation IP prefixes (`203.0.113.x` or `198.51.100.x`) in documentation, tests, and mock fixtures.

---

## 🧪 Quality Assurance & CI Checklist

Before opening a pull request, run the following verification pipeline locally:

```bash
# 1. Format verification
cargo fmt --check

# 2. Strict linter check (zero warnings tolerated)
cargo clippy -- -D warnings

# 3. Complete automated test suite
cargo test -- --nocapture
```

---

## 🔄 Pull Request Process

1. **Branch Naming**: Create a topic branch from `main`:
   ```bash
   git checkout -b feature/my-new-feature
   # or
   git checkout -b fix/issue-description
   ```
2. **Commit Messages**: Write concise, descriptive commit messages.
3. **Integration Tests**: If adding an endpoint, security policy, or audio parsing rule, include automated tests under `tests/`.
4. **Documentation**: Update [AGENTS.md](AGENTS.md), [README.md](README.md), or relevant chapters in `docs/` if your change modifies configuration, APIs, or architecture.
5. **Open Pull Request**: Submit your PR against `main`. Fill out the [Pull Request Template](.github/PULL_REQUEST_TEMPLATE.md) completely.
