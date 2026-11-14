"""IP Intelligence Service for detecting Datacenter, VPS, and Cloud hosting bots."""

import asyncio
import json
import logging
import threading
import urllib.request
from ipaddress import ip_address, ip_network

logger = logging.getLogger("league_backend.ip_intel")

RFC1918_NETWORKS = (
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
)


def is_local_or_private(ip: str) -> bool:
    """Check if IP is local, loopback, or private internal network."""
    if ip in ("127.0.0.1", "::1", "localhost", "testclient"):
        return True
    try:
        addr = ip_address(ip)
        if addr.is_loopback:
            return True
        return any(addr in net for net in RFC1918_NETWORKS)
    except ValueError:
        return True


DATACENTER_KEYWORDS = (
    "digitalocean",
    "amazon",
    "aws",
    "microsoft",
    "azure",
    "google cloud",
    "google-cloud",
    "hetzner",
    "ovh",
    "linode",
    "akamai",
    "vultr",
    "choopa",
    "datacamp",
    "censys",
    "shodan",
    "shadowserver",
    "leaseweb",
    "scaleway",
    "alibaba",
    "tencent",
    "oracle",
    "contabo",
    "m247",
    "cogent",
)


class IPIntelService:
    """Thread-safe hybrid IP intelligence and Datacenter/VPS classifier."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # In-memory fast cache: ip -> dict
        self._cache: dict[str, dict[str, any]] = {}

    def load_cache_from_db(self) -> None:
        """Load previously classified IPs from SQLite database on application startup."""
        try:
            from sqlalchemy import select

            from app.database import get_session_factory
            from app.models import IPIntel

            session_maker = get_session_factory()
            with session_maker() as session:
                rows = session.scalars(select(IPIntel)).all()
                with self._lock:
                    for r in rows:
                        self._cache[r.ip] = {
                            "is_datacenter": r.is_datacenter,
                            "isp": r.isp or "",
                            "org": r.org or "",
                            "as_info": r.as_info or "",
                            "country": r.country or "",
                        }
            logger.info("Loaded %d IP intelligence records from database cache", len(self._cache))
        except Exception as exc:
            logger.warning("Could not load IP intelligence records from database: %s", exc)

    def _sync_fetch_intel(self, ip: str) -> dict | None:
        """Query ip-api.com for autonomous system and hosting categorization."""
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,isp,org,as,hosting,proxy"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "LeagueVoiceRecorder/1.2.0 (Security Bot Classifier)"},
        )
        try:
            with urllib.request.urlopen(req, timeout=1.8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("status") == "success":
                    return data
        except Exception as exc:
            logger.debug("IP intelligence lookup failed for %s: %s", ip, exc)
        return None

    def _save_intel_to_db(
        self,
        ip: str,
        is_datacenter: bool,
        isp: str = "",
        org: str = "",
        as_info: str = "",
        country: str = "",
    ) -> None:
        """Persist IP classification to SQLite database."""
        try:
            from app.database import get_session_factory
            from app.models import IPIntel

            session_maker = get_session_factory()
            with session_maker() as session:
                existing = session.get(IPIntel, ip)
                if not existing:
                    entry = IPIntel(
                        ip=ip,
                        is_datacenter=is_datacenter,
                        isp=isp[:128] if isp else None,
                        org=org[:128] if org else None,
                        as_info=as_info[:128] if as_info else None,
                        country=country[:64] if country else None,
                    )
                    session.add(entry)
                    session.commit()
        except Exception as exc:
            logger.debug("Failed to persist IP intelligence for %s: %s", ip, exc)

    async def is_datacenter_ip(self, ip: str) -> tuple[bool, str]:
        """Check if client IP belongs to a Datacenter/VPS/Hosting provider.

        Returns (is_datacenter: bool, classification_reason_or_provider: str).
        """
        # 1. Skip private / loopback addresses
        if is_local_or_private(ip):
            return False, "Private / Localhost"

        # 2. Check in-memory fast cache ($O(1)$)
        with self._lock:
            cached = self._cache.get(ip)
            if cached is not None:
                provider = cached.get("org") or cached.get("isp") or "Datacenter / VPS"
                return cached["is_datacenter"], provider

        # 3. Query external intelligence service asynchronously
        data = await asyncio.to_thread(self._sync_fetch_intel, ip)
        if data:
            isp = data.get("isp") or ""
            org = data.get("org") or ""
            as_info = data.get("as") or ""
            country = data.get("country") or ""

            # Check hosting flag or known keywords in ISP/Org/AS
            is_hosting = bool(data.get("hosting") or data.get("proxy"))
            full_text = f"{isp} {org} {as_info}".lower()
            keyword_match = any(kw in full_text for kw in DATACENTER_KEYWORDS)

            is_dc = is_hosting or keyword_match
            provider_name = org or isp or "Hosting Network"

            # Cache in memory and SQLite
            with self._lock:
                self._cache[ip] = {
                    "is_datacenter": is_dc,
                    "isp": isp,
                    "org": org,
                    "as_info": as_info,
                    "country": country,
                }
            self._save_intel_to_db(
                ip=ip,
                is_datacenter=is_dc,
                isp=isp,
                org=org,
                as_info=as_info,
                country=country,
            )

            if is_dc:
                logger.info(
                    "🚫 Datacenter/VPS IP identified: %s (%s, %s)", ip, provider_name, country
                )
            return is_dc, provider_name

        # 4. Fail-safe fallback if external lookup times out
        return False, "Residential (Unclassified)"

    def get_ip_info(self, ip: str) -> dict | None:
        """Get full cached intelligence for an IP address (memory with SQLite fallback)."""
        with self._lock:
            cached = self._cache.get(ip)
            if cached is not None:
                return cached

        # Check database fallback
        try:
            from app.database import get_session_factory
            from app.models import IPIntel

            session_maker = get_session_factory()
            with session_maker() as session:
                entry = session.get(IPIntel, ip)
                if entry:
                    data = {
                        "is_datacenter": entry.is_datacenter,
                        "isp": entry.isp or "",
                        "org": entry.org or "",
                        "as_info": entry.as_info or "",
                        "country": entry.country or "",
                    }
                    with self._lock:
                        self._cache[ip] = data
                    return data
        except Exception:
            pass
        return None


# Global singleton instance
ip_intel_service = IPIntelService()
