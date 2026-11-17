# Security Policy

The **League Voice Recorder Backend** team takes the security and integrity of scrimmage audio and remote team data seriously. This document outlines our supported versions, threat model guidelines, and responsible vulnerability disclosure process.

---

## 🛡️ Supported Versions

> [!IMPORTANT]
> **Version 1.3.x is the latest and officially supported release stream.**
> We strongly recommend all operators, teams, and developers run **v1.3.x**.
> 
> All legacy versions (including the **1.2.x** Python implementation and earlier) are **deprecated, incompatible, inefficient, and can be unsafe**. Legacy versions will receive no further security patches, performance fixes, or maintenance.

| Version Stream | Release Architecture | Supported | Status |
| :--- | :--- | :---: | :--- |
| **`1.3.x`** | **Rust (Axum 0.8 + Tokio)** | ✅ **Yes** | **Active & Recommended** (Hardened TLS 1.3, constant-time auth, bot shield) |
| `1.2.x` | Python (FastAPI / Uvicorn) | ❌ **No** | **End-of-Life** (Incompatible, inefficient, non-hardened) |
| `< 1.2.0` | Legacy Scripts / Prototypes | ❌ **No** | **End-of-Life** (Unsupported) |

---

## ⚠️ Why 1.3.x is Required

The v1.3.x series represents a complete re-architecture from the ground up in memory-safe Rust:

1. **Memory Safety & Bounded Resource Consumption**: Operates under **1.35 MiB** of RAM in production. Audio streaming is strictly bounded in 64 KB chunks, mitigating denial-of-service (DoS) via memory exhaustion.
2. **Timing Attack Elimination**: All API credentials (`UPLOAD_KEY`, `PULL_KEY`, `ADMIN_KEY`) and web dashboard passwords are authenticated using `subtle::ConstantTimeEq`.
3. **Active Exploit & Scanner Defense**: Includes automated zero-tolerance bans for vulnerability scanner probes (`/.env`, `/.git`, `/actuator`, `PROPFIND`), sliding-window brute-force rate limiters, and hybrid datacenter/VPS bot filtering.
4. **Direct-Port TLS 1.3**: Direct native TLS termination eliminates the need for intermediate reverse proxy buffering, preventing truncation of large audio files.
5. **Schema Compatibility**: The database schema and audio integrity hashing in 1.3.x are not compatible with the outdated 1.2.x architecture.

---

## 🔒 Reporting a Vulnerability

If you discover a security vulnerability within the League Voice Recorder Backend, please follow responsible disclosure practices so we can address it before it is publicly revealed.

### Reporting Channels
- **GitHub Private Vulnerability Reporting**: Submit an advisory directly via the **Security** tab of the GitHub repository:  
  [https://github.com/betterix/league-voice-recorder-backend/security/advisories/new](https://github.com/betterix/league-voice-recorder-backend/security/advisories/new)
- **Direct Email**: You can also reach the project maintainer securely at:  
  **`szabozsolt430@gmail.com`**

### What to Include
To help us triage and resolve the issue quickly, please provide:
- A clear description of the vulnerability and its potential impact.
- Steps to reproduce, proof-of-concept (PoC) code, or HTTP request payloads (using RFC 5737 documentation IPs like `203.0.113.x`).
- The specific version of `league-voice-recorder-backend` and environment details (e.g. Docker container, host architecture amd64 or arm64).

### Response Timeline
- **Initial Acknowledgment**: Within **48 hours** of report receipt.
- **Triage & Assessment**: Within **5 business days**, detailing validation and expected remediation timeline.
- **Patch Release & Advisory**: Coordinated public disclosure once a patch is tested and released in a v1.3.x update.

---

## 🏅 Safe Harbor

We consider activities conducted in accordance with this policy to be authorized. We will not pursue legal action against researchers who:
- Make a good-faith effort to avoid privacy violations, data destruction, and service degradation.
- Give us reasonable time to remediate before disclosing vulnerability details publicly.
- Do not exploit a security issue beyond the minimum necessary to demonstrate its presence.
