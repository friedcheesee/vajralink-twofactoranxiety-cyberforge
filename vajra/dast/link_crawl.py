"""Built-in same-origin link/form crawler (stdlib html.parser + httpx), used when katana is not installed.

It only follows <a href> and <form action> found in real HTTP responses from the target, never leaves the
origin that already passed assert_safe_target, and is bounded (pages / depth). Returns the same shape as
katana_crawl so the caller can treat both alike. Nothing is invented: every endpoint was seen in a response.
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Optional

import httpx

from vajra.dast.inputs import _PageParser
from vajra.dast.safety import assert_safe_target

_STATIC_EXT = (".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
               ".ttf", ".eot", ".mp4", ".webm", ".pdf", ".zip")


async def link_crawl(seed_url: str, *, session_cookie: Optional[str] = None, max_pages: int = 60,
                     max_depth: int = 3) -> Dict[str, Any]:
    assert_safe_target(seed_url)
    seed = urllib.parse.urlparse(seed_url)
    netloc = seed.netloc
    seed_key = seed.path.rstrip("/")
    queue: List[tuple] = [(seed_url, 0)]
    visited = set()
    found: Dict[tuple, Dict[str, Any]] = {}
    pages = 0
    async with httpx.AsyncClient(timeout=3.0, verify=False, follow_redirects=False,
                                 headers={"Cookie": session_cookie} if session_cookie else None) as client:
        while queue and pages < max_pages:
            url, depth = queue.pop(0)
            norm = url.split("#")[0].split("?")[0]
            if norm in visited:
                continue
            visited.add(norm)
            try:
                resp = await client.get(url)
            except Exception:
                continue
            pages += 1
            if "html" not in resp.headers.get("content-type", "").lower():
                continue
            parser = _PageParser()
            try:
                parser.feed(resp.text)
            except Exception:
                continue
            targets: List[tuple] = []
            for href in parser.links:
                targets.append(("GET", urllib.parse.urljoin(url, href), [], "a"))
            for f in parser.forms:
                targets.append((f["method"] if f["method"] in ("GET", "POST") else "POST",
                                urllib.parse.urljoin(url, f["action"]), list(f["fields"].keys()), "form"))
            for method, tgt, fields, tag in targets:
                u = urllib.parse.urlparse(tgt)
                if u.scheme not in ("http", "https") or u.netloc != netloc:
                    continue
                if u.path.lower().endswith(_STATIC_EXT) or u.path.rstrip("/") == seed_key:
                    continue
                params = list(dict.fromkeys(list(urllib.parse.parse_qs(u.query).keys()) + fields))
                key = (method, u.path)
                rec = found.setdefault(key, {"url": f"{u.scheme}://{u.netloc}{u.path}", "method": method,
                                             "params": [], "tag": tag, "source_page": url})
                rec["params"] = list(dict.fromkeys(rec["params"] + params))
                if method == "GET" and depth < max_depth:
                    queue.append((f"{u.scheme}://{u.netloc}{u.path}", depth + 1))
    return {"available": True, "reason": None, "binary": "built-in link crawl",
            "pages_fetched": pages, "endpoints": list(found.values())}
