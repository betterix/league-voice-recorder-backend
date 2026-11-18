# Security Model & Bot Shield

The backend implements a multi-layered defense architecture specifically designed for services directly exposed to the public internet.

---

## 1. Strict Three-Key Authentication

All API operations under `/api/v1` require the `X-API-Key` HTTP header:

| Key Role | Target Audience | Permissions |
|---|---|---|
| `UPLOAD_KEY` | Scrim recording clients / players | Upload scrimmage audio (`POST`), query recordings (`GET`), stream/download audio (`GET`), health check (`GET`). Destructive deletion attempts return `403 Forbidden`. |
| `PULL_KEY` | Coaches, analysts, synchronizers | Query recordings (`GET`), stream/download audio (`GET`), health check (`GET`). Write and delete attempts return `403 Forbidden`. |
| `ADMIN_KEY` | Master administrative operator | Unrestricted read, write, upload, delete (`DELETE`), and diagnostic access. |

### Constant-Time Verification
All key and credential evaluations use constant-time byte comparisons (`subtle::ConstantTimeEq`) to eliminate side-channel timing attacks.

---

## 2. Sliding-Window Rate Limiting

The in-memory rate limiter tracks requests per IP using sliding-window timestamps stored in thread-safe concurrent maps:

- **General API Limit**: 120 requests per IP per minute (configurable via `RATE_LIMIT_PER_MINUTE`).
- **Upload Endpoint Limit**: 10 uploads per IP per minute (configurable via `UPLOAD_RATE_LIMIT_PER_MINUTE`).
- When a limit is reached, the server responds with `429 Too Many Requests` along with a `Retry-After: <seconds>` HTTP header.

---

## 3. Brute-Force Authentication Defense

- Failed authentication attempts (invalid or missing `X-API-Key`, or invalid web dashboard credentials) are tracked per client IP.
- Upon reaching 5 failed attempts within 60 seconds (configurable via `AUTH_FAILURE_LIMIT_PER_MINUTE`), the IP is temporarily blocked across all endpoints for 10 minutes (`429 Too Many Requests`).

---

## 4. Zero-Tolerance Scanner & Exploit Probe Detection

Automated vulnerability scanners (e.g., Nikto, Censys, Shodan, automated WebDAV/PHP bots) are blocked before reaching application logic:

1. **Signature Detection**:
   - Sensitive dot files (`.env`, `.git`, `.aws`, `.ssh`, `.vscode`)
   - Directory traversal sequences (`../`, `..\`, `%2e%2e%2f`)
   - CMS reconnaissance (`/wp-`, `/wordpress`, `xmlrpc.php`, `rest_route=`)
   - Server-side script extensions (`.php`, `.asp`, `.aspx`, `.jsp`, `.cgi`)
   - Admin panels (`/phpmyadmin`, `/pma`, `/adminer`, `/cpanel`)
   - Spring Boot Actuators, consoles, metrics (`/actuator`, `/console`, `/metrics`, `/telescope`)
   - GraphQL and MCP probe signatures (`/graphql`, `/mcp`, `/v1/models`, `/sse`)
   - Suspicious HTTP methods (`PROPFIND`, `SEARCH`, `MKCOL`, `CONNECT`, etc.)

2. **Instant Permanent Ban**:
   - Any client IP matching scanner signatures is immediately banned permanently in the SQLite `banned_ips` table and rejected with `403 Forbidden`.
   - The ban persists across server restarts.

3. **Heuristic Client Error Tracker**:
   - Unauthenticated requests generating client errors (`400 Bad Request`, `404 Not Found`, or `405 Method Not Allowed`) are tracked.
   - If an IP accumulates 5 client errors within 60 seconds, it is automatically banned for 60 minutes.

---

## 5. Hybrid Datacenter / VPS Bot Shield

Most malicious scanning originates from cloud hosting providers, virtual private servers (VPS), and automated crawler networks rather than residential player connections.

The backend employs a two-tier hybrid classifier:

1. **Fast Offline Keyword Filter**:
   Evaluates Autonomous System (AS), Organization, and ISP strings against known cloud and hosting providers (`digitalocean`, `amazon`, `hetzner`, `ovh`, `linode`, `vultr`, `choopa`, `datacamp`, `censys`, `shodan`, `leaseweb`, `scaleway`, `alibaba`, `tencent`, `oracle`, etc.).

2. **Asynchronous External Intelligence**:
   For uncached public IPs, queries `ip-api.com` asynchronously (1.8-second timeout). If the `hosting` or `proxy` flag is true, or known provider keywords match, the IP is classified as `Datacenter/VPS`.

3. **Persistent Classification Cache**:
   Classifications are stored in memory (`DashMap`) and persisted to the SQLite `ip_intel` table.

4. **Bypass Policy**:
   Requests carrying a valid `X-API-Key` or originating from configured `WEB_ALLOWED_IPS` management hosts or local/private networks (`127.0.0.1`, RFC1918) are completely exempt from datacenter blocking.

---

## 6. Container-Level Fail2ban Integration (`ENABLE_FAIL2BAN`)

For environments requiring active kernel/firewall packet rejection directly inside the container, an optional **Fail2ban service** is integrated into the production image.

### 6.1 Conditional Activation (Disabled by Default)
To preserve the minimal 1.35 MiB resident footprint, Fail2ban is **strictly optional and only starts if explicitly enabled**:
- **Disabled (`ENABLE_FAIL2BAN=0` or omitted)**: The container entrypoint executes the Rust binary directly as unprivileged `appuser` (PID 1) with zero daemon overhead.
- **Enabled (`ENABLE_FAIL2BAN=1` or `true`)**: The entrypoint boots `fail2ban-server` in the background, sets up graceful shutdown traps, and streams structured access logs to `/var/log/league-backend/access.log`.

### 6.2 Docker Compose Configuration
To enable Fail2ban, provide `ENABLE_FAIL2BAN=1` and `cap_add: [NET_ADMIN]` in your `docker-compose.yml`:

```yaml
services:
  league-scrim-backend:
    image: ghcr.io/betterix/league-voice-recorder-backend:latest
    environment:
      - ENABLE_FAIL2BAN=1
    cap_add:
      - NET_ADMIN
    user: "0:0"
    volumes:
      - ./data/recordings:/app/data/recordings
      - ./data/db:/app/data/db
      - ./certs:/app/certs:ro
      - ./fail2ban-jail.local:/etc/fail2ban/jail.d/user-jail.local:ro
```

### 6.3 Custom Jail Overrides (`fail2ban-jail.local`)
Following the [Docker Mailserver](https://github.com/docker-mailserver/docker-mailserver) configuration pattern, user overrides can be mounted into `/etc/fail2ban/jail.d/user-jail.local:ro`:

```ini
[DEFAULT]
bantime  = 1d
bantime.increment = true
bantime.multipliers = 1 2 4 8 16 32 64
bantime.maxtime = 4w
findtime = 10m
maxretry = 3
ignoreip = 127.0.0.1/8 ::1

[league-backend]
enabled  = true
port     = 8443
filter   = league-backend
logpath  = /var/log/league-backend/access.log
maxretry = 3
findtime = 10m
bantime  = 1d
```

### 6.4 How It Works
1. Axum structured access logs stream to `/var/log/league-backend/access.log`.
2. Fail2ban's `league-backend` filter continuously parses for authentication failures and repeated client errors (`401`, `403`, `429`).
3. Upon exceeding `maxretry` (default: 3 failures within 10 minutes), Fail2ban inserts an `iptables` rule into the `f2b-league-backend` chain:
   ```text
   REJECT all -- 203.0.113.88  0.0.0.0/0  reject-with icmp-port-unreachable
   ```
4. Blocked packets are rejected at the container's network stack before initiating TLS 1.3 handshakes.
