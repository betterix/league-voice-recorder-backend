"""Security, IP whitelist, and HTTP Basic Authentication for Web Dashboard."""

import secrets
from ipaddress import ip_address, ip_network

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from app.config import get_settings
from app.security import enforce_not_blocked, get_client_ip, rate_limiter

security = HTTPBasic(auto_error=False)


def is_web_ip_allowed(client_ip: str, allowed_ips_str: str) -> bool:
    """Evaluate whether client_ip is permitted to access the web interface.

    - Localhost ('127.0.0.1', '::1', 'localhost', 'testclient') and local Docker
      bridge gateways (172.16.0.0/12) are always allowed by default for testing.
    - If '0.0.0.0' or '*' is in allowed_ips_str, all IPs are permitted.
    - Specific IPs and CIDR subnets (e.g. 192.168.1.0/24) are supported.
    """
    if client_ip in ("127.0.0.1", "::1", "localhost", "testclient"):
        return True

    try:
        addr = ip_address(client_ip)
        if addr.is_loopback or addr in ip_network("172.16.0.0/12"):
            return True
    except ValueError:
        pass

    allowed_list = [ip.strip() for ip in allowed_ips_str.split(",") if ip.strip()]

    # 0.0.0.0 or wildcard grants access to any IP
    if "0.0.0.0" in allowed_list or "*" in allowed_list:
        return True

    try:
        client_addr = ip_address(client_ip)
    except ValueError:
        return client_ip in allowed_list

    for entry in allowed_list:
        try:
            if "/" in entry:
                if client_addr in ip_network(entry, strict=False):
                    return True
            else:
                if client_addr == ip_address(entry):
                    return True
        except ValueError:
            if entry == client_ip:
                return True

    return False


def require_web_access(
    request: Request,
    credentials: HTTPBasicCredentials | None = Depends(security),
) -> str:
    """Enforce IP whitelist restriction and HTTP Basic Auth credentials for /web."""
    settings = get_settings()

    if not settings.WEB_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not Found",
        )

    client_ip = get_client_ip(request)

    # 1. Check IP authorization whitelist: cloaks web dashboard with 404 for unauthorized IPs
    if not is_web_ip_allowed(client_ip, settings.WEB_ALLOWED_IPS):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not Found",
        )

    # 2. Check brute force IP block
    enforce_not_blocked(request, settings)

    # 3. Check HTTP Basic Auth credentials
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": 'Basic realm="League Voice Recorder Dashboard"'},
        )

    user_matches = secrets.compare_digest(credentials.username, settings.WEB_USERNAME)
    pass_matches = secrets.compare_digest(credentials.password, settings.WEB_PASSWORD)

    if not (user_matches and pass_matches):
        rate_limiter.record_auth_failure(
            ip=client_ip,
            max_failures=settings.AUTH_FAILURE_LIMIT_PER_MINUTE,
            block_duration_minutes=settings.AUTH_BLOCK_DURATION_MINUTES,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": 'Basic realm="League Voice Recorder Dashboard"'},
        )

    return credentials.username
