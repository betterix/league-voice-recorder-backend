"""HTML view rendering for the Web Dashboard."""

import html
from pathlib import Path

_HTML_FILE = Path(__file__).parent / "dashboard.html"
_CACHED_HTML = _HTML_FILE.read_text(encoding="utf-8")


def render_dashboard(client_ip: str, username: str) -> str:
    """Render the dashboard HTML with injected dynamic client and user data."""
    safe_ip = html.escape(client_ip)
    safe_user = html.escape(username)
    return _CACHED_HTML.replace("__CLIENT_IP__", safe_ip).replace("__USERNAME__", safe_user)
