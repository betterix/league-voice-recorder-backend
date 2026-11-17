# =============================================================================
# Stage 1: Build & Compilation Stage
# =============================================================================
FROM rust:alpine AS builder

WORKDIR /build

RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache \
    musl-dev \
    gcc \
    make \
    cmake \
    openssl-dev \
    perl

COPY Cargo.toml Cargo.lock* ./
COPY src ./src

RUN cargo build --release && \
    strip target/release/league-voice-recorder-backend

# =============================================================================
# Stage 2: Hardened Minimal Production Runtime
# =============================================================================
FROM alpine:3.24

LABEL org.opencontainers.image.title="League Voice Recorder Backend" \
    org.opencontainers.image.description="High-performance centralized direct-port scrim audio backend for League Voice Recorder" \
    org.opencontainers.image.version="1.3.1" \
    org.opencontainers.image.authors="Betterix" \
    org.opencontainers.image.licenses="AGPL-3.0"

RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache \
    openssl \
    ca-certificates \
    curl

# Create secure non-root system user and group
RUN addgroup -g 10001 -S appuser && \
    adduser -u 10001 -S appuser -G appuser -h /app -s /sbin/nologin

WORKDIR /app

# Copy compiled Rust static/optimized binary from builder stage
COPY --from=builder /build/target/release/league-voice-recorder-backend /app/league-voice-recorder-backend

# Create persistent storage directories with proper ownership
RUN mkdir -p /app/data/recordings /app/data/db /app/certs && \
    chown -R appuser:appuser /app && \
    chmod 750 /app/league-voice-recorder-backend

USER appuser

EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -k -s -f -H "X-API-Key: ${PULL_KEY:-${UPLOAD_KEY}}" "https://localhost:${PORT:-8443}/api/v1/health" > /dev/null || exit 1

ENTRYPOINT ["/app/league-voice-recorder-backend"]
