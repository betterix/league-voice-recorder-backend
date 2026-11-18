#!/usr/bin/env bash
set -e

# If a custom command was passed to the container, execute it directly
if [ "$#" -gt 0 ] && [ "$1" != "/app/league-voice-recorder-backend" ]; then
    exec "$@"
fi

# Only enable Fail2ban if explicitly requested via environment variable (ENABLE_FAIL2BAN=1 or true)
if [ "${ENABLE_FAIL2BAN:-0}" = "1" ] || [ "${ENABLE_FAIL2BAN:-false}" = "true" ]; then
    echo "🔒 [Fail2ban] Initializing Fail2ban security service..."

    # Ensure logging and state directories exist with correct permissions
    mkdir -p /var/log/league-backend /var/run/fail2ban /app/data/recordings /app/data/db
    touch /var/log/league-backend/access.log
    chown -R appuser:appuser /var/log/league-backend /app/data 2>/dev/null || true
    chmod 755 /var/log/league-backend

    # Clean up stale socket and default alpine ssh jail
    rm -f /var/run/fail2ban/fail2ban.sock /etc/fail2ban/jail.d/alpine-ssh.conf 2>/dev/null || true

    # Start fail2ban server in background
    fail2ban-server -b

    # Wait for fail2ban socket to become ready
    for i in $(seq 1 10); do
        if [ -S /var/run/fail2ban/fail2ban.sock ]; then
            break
        fi
        sleep 0.5
    done

    if fail2ban-client ping >/dev/null 2>&1; then
        echo "✅ [Fail2ban] Server ready and active."
        fail2ban-client status || true
    else
        echo "⚠️ [Fail2ban] Warning: fail2ban-server failed to start. Ensure NET_ADMIN capability is provided."
    fi

    # Trap shutdown signals to cleanly terminate both fail2ban and the backend
    cleanup() {
        echo "🛑 [Shutdown] Stopping services..."
        if [ -S /var/run/fail2ban/fail2ban.sock ]; then
            fail2ban-client stop >/dev/null 2>&1 || true
        fi
        if [ -n "$CHILD_PID" ]; then
            kill -TERM "$CHILD_PID" 2>/dev/null || true
        fi
    }
    trap cleanup SIGTERM SIGINT

    # Run the Rust backend as unprivileged appuser (if capabilities permit su-exec) or directly
    if su-exec appuser true 2>/dev/null; then
        su-exec appuser /app/league-voice-recorder-backend "$@" 2>&1 | tee -a /var/log/league-backend/access.log &
    else
        /app/league-voice-recorder-backend "$@" 2>&1 | tee -a /var/log/league-backend/access.log &
    fi
    CHILD_PID=$!

    wait "$CHILD_PID"
else
    # Fail2ban disabled: execute Rust backend directly (PID 1) with zero overhead
    if su-exec appuser true 2>/dev/null; then
        exec su-exec appuser /app/league-voice-recorder-backend "$@"
    else
        exec /app/league-voice-recorder-backend "$@"
    fi
fi

