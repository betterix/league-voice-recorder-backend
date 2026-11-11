# =============================================================================
# Stage 1: Build & Compilation Stage
# =============================================================================
FROM python:3.15-alpine AS builder

WORKDIR /build

# Install build dependencies for compiling Python native wheels
RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    make

COPY requirements.txt .

# Install dependencies into isolated installation prefix
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# =============================================================================
# Stage 2: Hardened Minimal Production Runtime
# =============================================================================
FROM python:3.15-alpine

# Metadata labels
LABEL org.opencontainers.image.title="League Voice Recorder Backend" \
    org.opencontainers.image.description="Centralized direct-port scrim audio backend for League Voice Recorder" \
    org.opencontainers.image.version="1.0.0" \
    org.opencontainers.image.authors="League Voice Recorder Team" \
    org.opencontainers.image.licenses="GPL-3.0"

# Install minimal runtime dependencies
RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache \
    openssl \
    curl \
    ca-certificates

RUN rm -rf /usr/local/lib/python3.14/site-packages/*

# Create secure non-root system user and group
RUN addgroup -g 10001 -S appuser && \
    adduser -u 10001 -S appuser -G appuser -h /app -s /sbin/nologin

WORKDIR /app

# Copy installed Python packages from builder stage
COPY --from=builder /install /usr/local

# Create persistent storage directories with proper ownership
RUN mkdir -p /app/data/recordings /app/data/db /app/certs && \
    chown -R appuser:appuser /app

# Copy application source code
COPY --chown=appuser:appuser . .

# Ensure storage directories are owned by appuser
RUN chown -R appuser:appuser /app/data

# Switch to non-root user
USER appuser

# Expose configurable direct HTTPS port
EXPOSE 8443

# Healthcheck testing direct TLS health endpoint with authenticated API key
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os, urllib.request, ssl; key = os.environ.get('PULL_KEY') or os.environ.get('UPLOAD_KEY') or ''; req = urllib.request.Request('https://localhost:8443/api/v1/health', headers={'X-API-Key': key}); ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE; urllib.request.urlopen(req, context=ctx, timeout=3)" || exit 1

# Launch application server
CMD ["python", "-m", "app.main"]
