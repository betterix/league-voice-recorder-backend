# Deployment & Operations

This document covers deployment options for the Rust backend: Docker Compose, native binary execution, and TLS certificates.

---

## 1. Quickstart with Docker Compose

### Prerequisites
- Docker Engine 24+ and Docker Compose v2.

### Step-by-Step Setup
1. Clone the repository and navigate to the directory:
   ```bash
   git clone https://github.com/betterix/league-voice-recorder-backend.git
   cd league-voice-recorder-backend
   ```

2. Copy the environment template:
   ```bash
   cp .env.example .env
   ```

3. Configure your production credentials in `.env`:
   - Set strong random 32+ character secrets for `UPLOAD_KEY`, `PULL_KEY`, and `ADMIN_KEY`.
   - Set `WEB_USERNAME` and a strong 16+ character `WEB_PASSWORD`.
   - Set `WEB_ALLOWED_IPS` to your management IP address (or `0.0.0.0` if your IP changes frequently).

4. Build and start the container:
   ```bash
   docker compose up -d --build
   ```

5. Verify health:
   ```bash
   docker compose ps
   curl -k -H "X-API-Key: YOUR_UPLOAD_KEY" https://localhost:8443/api/v1/health
   ```

---

## 2. TLS Certificate Management

The backend listens natively over TLS 1.3 on port `8443`.

### 2.1 Production: Let's Encrypt / CA Certificates
Place your certificate and private key in `./certs`:
- `./certs/cert.pem`: Full certificate chain (PEM format).
- `./certs/key.pem`: Private key (PEM format).

Verify file permissions:
```bash
chmod 600 certs/key.pem
chmod 644 certs/cert.pem
```

### 2.2 Development: Automatic Self-Signed Certificates
When running with `ENVIRONMENT=development` or `DEV_SELF_SIGNED_CERT=true`, the backend automatically generates a self-signed ECDSA certificate with Subject Alternative Names (SANs) for `localhost`, `127.0.0.1`, and your configured `DOMAIN_NAME` if missing from `./certs`.

---

## 3. Native Compilation

To compile and run directly on a host:

```bash
# Build release binary
cargo build --release

# Run binary with your .env
./target/release/league-voice-recorder-backend
```

Run tests:
```bash
cargo test
```
