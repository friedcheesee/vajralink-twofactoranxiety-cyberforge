"""
DAST Safety Guardrail (PRD Safety Rule #1).
Ensures scans ONLY target localhost / approved local instances.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import urllib.parse
from typing import Optional, Tuple


def assert_safe_target(target_url: str) -> None:
    """Validate that target_url resolves to a permitted local or loopback test instance.
    Raises ValueError if external or unauthorized target is specified.
    """
    parsed = urllib.parse.urlparse(target_url)
    hostname = (parsed.hostname or "").lower()

    if not hostname:
        raise ValueError(f"Invalid target URL: {target_url}")

    if hostname in {"localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal"}:
        return

    # Check for private network IP ranges (e.g. docker bridge networks 172.*, 10.*, 192.168.*)
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_loopback or ip.is_private:
            return
    except ValueError:
        pass

    # Not a literal IP: could be a Docker Compose service name (e.g. "vulnerableapp") resolved by the
    # container's own embedded DNS. Resolve it and apply the same private/loopback check to the result,
    # instead of trusting the name - a real external hostname still gets blocked once resolved.
    try:
        resolved_ip = ipaddress.ip_address(socket.gethostbyname(hostname))
        if resolved_ip.is_loopback or resolved_ip.is_private:
            return
    except (socket.gaierror, ValueError, OSError):
        pass

    raise ValueError(
        f"BLOCKED BY PRD SAFETY RULE: Target '{target_url}' is not a local test instance. "
        "Scanning external sites is strictly forbidden."
    )


_LOOPBACK_NAMES = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


def running_in_docker() -> bool:
    """True inside the VajraLink container (docker-compose sets VAJRA_IN_DOCKER=1; /.dockerenv is the fallback)."""
    flag = os.getenv("VAJRA_IN_DOCKER")
    if flag is not None:
        return flag.strip().lower() in {"1", "true", "yes"}
    return os.path.exists("/.dockerenv")


def docker_reachable_url(target_url: str) -> Tuple[str, Optional[str]]:
    """Inside a container, localhost / 127.0.0.1 is the container itself, not the user's machine. When VajraLink
    runs in Docker, rewrite a loopback target to the host alias (host.docker.internal, see docker-compose.yml) so
    "the app on my machine" is actually reached. Returns (url_to_use, note); note is None when nothing changed.
    The rewritten target is still loopback/private, so the PRD scan-only-local rule is unaffected."""
    parsed = urllib.parse.urlparse(target_url)
    host = (parsed.hostname or "").lower()
    if not running_in_docker() or host not in _LOOPBACK_NAMES:
        return target_url, None
    alias = os.getenv("VAJRA_HOST_ALIAS", "host.docker.internal")
    netloc = alias + (f":{parsed.port}" if parsed.port else "")
    if parsed.username:
        netloc = f"{parsed.username}{':' + parsed.password if parsed.password else ''}@{netloc}"
    new_url = urllib.parse.urlunparse(parsed._replace(netloc=netloc))
    return new_url, (f"VajraLink is running in Docker, where {host} is the container itself; "
                     f"probing your machine at {new_url} instead.")
