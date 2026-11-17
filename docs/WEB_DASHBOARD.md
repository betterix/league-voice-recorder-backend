# Embedded Web Dashboard (`/web`)

The backend includes a zero-dependency, self-contained administrative web interface embedded directly into the compiled binary.

---

## 1. Security & IP Cloaking

Access to `/web` is protected by two layers:

1. **IP Whitelist Enforcement**:
   - Only client IPs matching `WEB_ALLOWED_IPS` (comma-separated IP addresses or subnets) can access the interface.
   - Unauthorized IPs receive `404 Not Found` (rather than `401` or `403`), completely cloaking the existence of the management dashboard from port scanners.
   - Localhost (`127.0.0.1`, `::1`) and local Docker bridge networks are permitted by default for local maintenance. Set `0.0.0.0` to permit access from any IP.

2. **HTTP Basic Authentication**:
   - Prompts for `WEB_USERNAME` and `WEB_PASSWORD` (configured in `.env`).
   - Constant-time verification prevents brute-force timing attacks.
   - 5 failed attempts trigger a 10-minute ban on the client IP.

---

## 2. Dashboard Features

### 2.1 Scrim Recordings View
- Real-time disk storage capacity cards (Total, Used, Free).
- Interactive search filter matching Game IDs, team tags, or match dates.
- In-browser HTML5 audio player (`/web/stream/{game_id}`) for instant review.
- Direct MP3 download button (`/web/download/{game_id}`).
- Manual file upload form with progress indicator.
- Administrative delete button with confirmation dialog.

### 2.2 Security & Threat Audit View
- Live counter of actively blocked scanner IPs.
- Categorized IP traffic stream (`download`, `suspicious`, `blocked`, `api`).
- **Bot Shield Badges**:
  - 🏠 **Residential ISP**: Normal human player connections.
  - ☁️ **Datacenter / VPS**: Automated scanners, AWS/DigitalOcean bots, and cloud crawlers.
- One-click IP unban and quota reset.
- Manual IP permanent ban form.
