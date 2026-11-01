"""
Real independent endpoint discovery via ProjectDiscovery's katana crawler (optional, auto-detected).

Why this exists: the rest of the "independent DAST discovery" path (crawler.py) only re-walks the route
table that SAST's AST parser already extracted - it isn't actually independent of source code at all, and
it falls back to nothing useful on an app whose AST route extractor didn't recognize its framework. katana
is a real, generic, app-agnostic crawler: it fetches pages and parses the actual HTML/CSS/JS for links,
scripts, forms and sitemap/robots entries - genuinely zero-knowledge of the source tree.

This is entirely optional. If the `katana` binary isn't on PATH (or at VAJRA_KATANA_BIN), every caller gets
back an empty, clearly-labeled "unavailable" result instead of a crash or a faked result.

Install (not required for VajraLink to run - everything else works without it):
    go install github.com/projectdiscovery/katana/cmd/katana@latest
or download a release binary from https://github.com/projectdiscovery/katana/releases and put it on PATH.

Headless crawling (-hl) is deliberately NOT used here: on some Windows setups, Defender flags go-rod's
helper binary and headless mode silently finds 0 endpoints. The DOM/JS-execution job already belongs to
the Playwright XSS stage elsewhere in this pipeline; katana here only has to do static link/form/script
discovery, which needs no browser.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import urllib.parse
from typing import Any, Dict, List, Optional

from vajra.dast.safety import assert_safe_target

log = logging.getLogger("vajra.dast.katana")

_KATANA_BIN_CACHE: Optional[str] = None
_KATANA_CHECKED = False


def locate_katana_binary() -> Optional[str]:
    """Find a real katana executable, or None. Cached after the first check so a missing binary doesn't
    get re-probed on every DAST run."""
    global _KATANA_BIN_CACHE, _KATANA_CHECKED
    if _KATANA_CHECKED:
        return _KATANA_BIN_CACHE
    _KATANA_CHECKED = True

    candidates = []
    env_bin = os.getenv("VAJRA_KATANA_BIN", "").strip()
    if env_bin:
        candidates.append(env_bin)
    which = shutil.which("katana") or shutil.which("katana.exe")
    if which:
        candidates.append(which)
    home = os.path.expanduser("~")
    candidates.append(os.path.join(home, "go", "bin", "katana.exe"))
    candidates.append(os.path.join(home, "go", "bin", "katana"))

    for c in candidates:
        if c and os.path.isfile(c):
            _KATANA_BIN_CACHE = c
            return c
    return None


def _same_origin_scope(base_url: str) -> str:
    """A crawl-scope regex katana enforces itself, as defense in depth on top of its own default host
    scoping - belt and suspenders for the PRD's 'scan only the test app' rule."""
    host = urllib.parse.urlparse(base_url).netloc
    return re.escape(host)


async def katana_crawl(
    base_url: str,
    depth: int = 3,
    duration_s: int = 20,
    concurrency: int = 10,
    rate_limit: int = 60,
    session_cookie: Optional[str] = None,
) -> Dict[str, Any]:
    """Run a real katana crawl against base_url (localhost/private only - enforced before any subprocess
    runs) and return discovered (method, url) pairs with full provenance. Never raises on a missing binary,
    a crawl timeout, or a parse failure - callers get an honest 'available: False' instead.
    """
    binary = locate_katana_binary()
    if not binary:
        return {
            "available": False,
            "reason": "katana binary not found on PATH or VAJRA_KATANA_BIN "
                       "(optional: go install github.com/projectdiscovery/katana/cmd/katana@latest)",
            "endpoints": [],
        }

    assert_safe_target(base_url)  # re-validated here too, independent of the caller

    clean_base = base_url.rstrip("/") + "/"
    cmd = [
        binary, "-u", clean_base,
        "-depth", str(depth),
        "-crawl-duration", f"{duration_s}s",
        "-concurrency", str(concurrency),
        "-rate-limit", str(rate_limit),
        "-jsonl", "-silent", "-omit-body", "-omit-raw", "-no-color",
        "-timeout", "8",
        "-crawl-scope", _same_origin_scope(clean_base),
        "-known-files", "all",
        "-form-extraction",
    ]
    if session_cookie:
        cmd += ["-headers", f"Cookie: {session_cookie}"]

    import asyncio

    try:
        proc = await asyncio.to_thread(
            subprocess.run, cmd, capture_output=True, text=True, timeout=duration_s + 20, check=False,
        )
    except subprocess.TimeoutExpired:
        return {"available": True, "reason": "katana crawl exceeded its own duration + 20s hard timeout", "endpoints": []}
    except Exception as e:
        return {"available": True, "reason": f"katana invocation failed: {str(e)[:150]}", "endpoints": []}

    if proc.returncode not in (0, None) and not (proc.stdout or "").strip():
        return {
            "available": True,
            "reason": f"katana exited {proc.returncode}: {(proc.stderr or proc.stdout or '').strip()[:200]}",
            "endpoints": [],
        }

    _STATIC_EXT = (
        ".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".pdf",
    )
    seed_path = urllib.parse.urlparse(clean_base).path.rstrip("/")
    endpoints: List[Dict[str, Any]] = []
    seen = set()
    forms_found = 0
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        req = rec.get("request") or {}
        url = req.get("endpoint")
        method = (req.get("method") or "GET").upper()
        if not url:
            continue
        url_path = urllib.parse.urlparse(url).path
        if url_path.lower().endswith(_STATIC_EXT):
            continue
        if url_path.rstrip("/") == seed_path:
            continue  # the seed page itself, not a discovered endpoint
        key = (method, url.split("?", 1)[0])
        if key in seen:
            continue
        seen.add(key)
        params: List[str] = []
        if "?" in url:
            params = list(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys())
        forms = req.get("forms") or rec.get("response", {}).get("forms")
        if forms:
            forms_found += 1
        endpoints.append({
            "url": url,
            "method": method,
            "params": params,
            "tag": req.get("tag"),           # e.g. "a", "script", "form", "sitemap"
            "source_page": req.get("source"),
        })

    return {
        "available": True,
        "reason": None,
        "binary": binary,
        "endpoints": endpoints,
        "forms_seen": forms_found,
        "command": " ".join(cmd[:3]) + " ...",
    }
