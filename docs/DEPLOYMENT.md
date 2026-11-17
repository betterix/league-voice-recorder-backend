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

The backend listens natively over TLS 1.3 on direct port `8443` (or configured `$PORT`), terminating TLS via Axum and Rustls without requiring an external reverse proxy.

### 2.1 Production Setup with Let's Encrypt & Certbot

In a production environment (`ENVIRONMENT=production`), the service requires valid CA-signed certificates and executes a **fail-fast validation** on startup: if `cert.pem` or `key.pem` are missing, unreadable, or invalid, the container halts immediately to prevent unencrypted HTTP exposure.

#### Step 1: Issue Certificates via Certbot Standalone
Because the backend listens on port `8443`, standard HTTP/HTTPS ports (`80` and `443`) on the host are typically unoccupied. This allows Certbot to run seamlessly in standalone mode:

```bash
# Install Certbot (Debian/Ubuntu)
sudo apt update && sudo apt install -y certbot

# Request a certificate for your domain (replace with your actual domain)
sudo certbot certonly --standalone \
  -d recordings.example.com \
  --preferred-challenges http \
  --agree-tos \
  -m admin@example.com
```

> [!NOTE]
> If your host already runs a separate web service on port 80, you can issue the certificate using DNS challenge instead:
> `sudo certbot certonly --manual --preferred-challenges dns -d recordings.example.com`

#### Step 2: Install Certificates into `./certs`
Let's Encrypt places certificates under `/etc/letsencrypt/live/<DOMAIN>/`. Copy or link them into the repository's `./certs` directory:

```bash
# Ensure the certs directory exists
mkdir -p certs

# Copy fullchain and private key
sudo cp /etc/letsencrypt/live/recordings.example.com/fullchain.pem certs/cert.pem
sudo cp /etc/letsencrypt/live/recordings.example.com/privkey.pem certs/key.pem

# Set strict permissions (readable by container appuser UID 10001)
sudo chmod 644 certs/cert.pem
sudo chmod 640 certs/key.pem
sudo chown $(id -u):10001 certs/key.pem
```

#### Step 3: Configure Production Environment (`.env`)
In your production `.env` file, specify:

```bash
ENVIRONMENT=production
DOMAIN_NAME=recordings.example.com
PORT=8443

# Certificate paths inside container (mounted read-only from ./certs)
SSL_CERT=/app/certs/cert.pem
SSL_KEY=/app/certs/key.pem
DEV_SELF_SIGNED_CERT=false
```

#### Step 4: Automated Certificate Renewal Hook
Let's Encrypt certificates expire every 90 days. Set up an automated deploy hook so Certbot automatically updates the `./certs` directory and restarts the backend container on renewal:

Create `/etc/letsencrypt/renewal-hooks/deploy/reload-league-backend.sh`:
```bash
#!/bin/bash
set -euo pipefail

DOMAIN="recordings.example.com"
APP_DIR="/opt/league-voice-recorder-backend"

if [ "$RENEWED_LINEAGE" = "/etc/letsencrypt/live/$DOMAIN" ]; then
    echo "[$(date)] Updating certificates for $DOMAIN..."
    cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$APP_DIR/certs/cert.pem"
    cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$APP_DIR/certs/key.pem"
    chmod 644 "$APP_DIR/certs/cert.pem"
    chmod 640 "$APP_DIR/certs/key.pem"
    chown root:10001 "$APP_DIR/certs/key.pem"

    cd "$APP_DIR"
    docker compose restart league-scrim-backend
    echo "[$(date)] Backend restarted with renewed TLS certificate."
fi
```

Make the script executable:
```bash
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-league-backend.sh
```

Test dry-run renewal:
```bash
sudo certbot renew --dry-run
```

---

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
