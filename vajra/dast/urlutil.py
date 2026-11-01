"""Small URL helpers shared by the DAST crawler/runner: context-path handling that never doubles a prefix."""
from __future__ import annotations

import re
import urllib.parse
from typing import Callable, List, Optional, Tuple

from vajra.models import RouteEntry

_PATH_TEMPLATE = re.compile(r"\{[^}]*\}|<[^>]*>|(?<=/):[A-Za-z_]\w*")
_PATH_VAR_NAME = re.compile(r"\{\s*([A-Za-z_]\w*)\s*(?::[^}]*)?\}|<(?:[A-Za-z_]\w*:)?([A-Za-z_]\w*)>|(?<=/):([A-Za-z_]\w*)")


def norm_ctx(context_path: Optional[str]) -> str:
    c = (context_path or "").strip().strip("/")
    return f"/{c}" if c else ""


def split_target(base_url: str, context_path: Optional[str] = "") -> Tuple[str, str]:
    """Return (origin, prefix). `prefix` is the path every app URL starts with: the configured context path,
    or whatever path the operator already put in the target URL. Never both stacked on top of each other."""
    parsed = urllib.parse.urlparse(base_url.rstrip("/"))
    origin = f"{parsed.scheme}://{parsed.netloc}"
    base_path = parsed.path.rstrip("/")
    ctx = norm_ctx(context_path)
    if base_path:
        if not ctx or base_path.lower().endswith(ctx.lower()):
            return origin, base_path
        return origin, base_path + ctx
    return origin, ctx


def strip_prefix(path: str, prefix: str) -> str:
    u = "/" + (path or "").strip("/")
    if prefix:
        pl = prefix.lower()
        if u.lower() == pl:
            return "/"
        if u.lower().startswith(pl + "/"):
            u = u[len(prefix):]
    return u


def path_vars(template: str) -> List[str]:
    out: List[str] = []
    for m in _PATH_VAR_NAME.finditer(template or ""):
        name = next((g for g in m.groups() if g), None)
        if name and name not in out:
            out.append(name)
    return out


def concretize(template: str) -> str:
    return _PATH_TEMPLATE.sub("1", template)


def build_route_matcher(routes: Optional[List[RouteEntry]], prefix: str = "") -> Callable[[str, str], Optional[RouteEntry]]:
    """Resolve a concrete URL path to the RouteEntry whose pattern matches it (real data only)."""
    compiled: List[Tuple[re.Pattern, RouteEntry]] = []
    for r in routes or []:
        pat = strip_prefix(r.url_pattern, prefix)
        rx = ""
        pos = 0
        for m in _PATH_TEMPLATE.finditer(pat):
            rx += re.escape(pat[pos:m.start()]) + r"[^/]+"
            pos = m.end()
        rx += re.escape(pat[pos:])
        rx = rx.replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
        try:
            compiled.append((re.compile("^" + rx.rstrip("/") + "/?$", re.IGNORECASE), r))
        except re.error:
            continue

    def match(path: str, method: str = "GET") -> Optional[RouteEntry]:
        p = strip_prefix(path, prefix)
        fallback = None
        for rx, r in compiled:
            if rx.match(p):
                if r.http_method.upper() == method.upper():
                    return r
                fallback = fallback or r
        return fallback

    return match
