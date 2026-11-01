"""B-1 auto-verify: try to prove Code-only findings at runtime with the existing DAST probes.

For every Code-only issue whose CWE an HTTP probe can prove, find the routes whose handler reaches that
sink (same fgraph.route_node + fgraph.forward_path(max_hops=8) test engine.py uses), probe those routes with
the existing payload library, and return any NEW DAST findings (discovery="auto-verify", live-http).
Nothing here sets an issue to Confirmed: the caller re-runs correlate_findings with the extra findings, so
the normal engine (and its wrong-link guards) decides whether a link is made.
"""
from __future__ import annotations

import asyncio
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

import httpx

from vajra.dast.crawler import DastTargetEndpoint, _canon_path
from vajra.dast.http_verifier import verify_endpoint_vulnerabilities
from vajra.dast.playwright_verifier import verify_dom_xss_with_playwright
from vajra.dast.runner import PROBEABLE_CWES
from vajra.dast.safety import assert_safe_target, docker_reachable_url
from vajra.models import CommonFinding, RouteEntry


def _path(u: Optional[str]) -> str:
    return urllib.parse.urlparse(u or "").path.rstrip("/").lower()


async def auto_verify_code_only(
    issues: List[Any],
    dast_findings: List[CommonFinding],
    routes: List[RouteEntry],
    fgraph: Any,
    target_url: str,
    *,
    context_path: str = "",
    session_cookie: Optional[str] = None,
    screenshot_dir: str = "screenshots",
    time_budget_s: float = 120.0,
    concurrency: int = 4,
    max_hops: int = 8,
) -> Tuple[List[CommonFinding], Dict[str, Any]]:
    """Returns (new_dast_findings, stats{attempted, upgraded, still_code_only, elapsed_s, ...})."""
    t0 = time.time()
    assert_safe_target(target_url)
    target_url, _ = docker_reachable_url(target_url)
    origin_p = urllib.parse.urlparse(target_url.rstrip("/"))
    origin = f"{origin_p.scheme}://{origin_p.netloc}"
    ctx = "/" + context_path.strip("/") if context_path.strip("/") else ""

    code_only = [i for i in issues if getattr(i, "status", "") == "Code only" and i.cwe in PROBEABLE_CWES
                 and i.file_path and fgraph is not None]
    covered = {(d.cwe, _path(d.url)) for d in dast_findings}

    # (url, method, cwe) -> endpoint; remember which issues each probe serves
    plan: Dict[Tuple[str, str, str], Tuple[DastTargetEndpoint, List[Any]]] = {}
    for i in code_only:
        lines = (i.vector_breakdown or {}).get("sink_lines") or [i.line]
        sinks = {fgraph.innermost_node_at(i.file_path, ln or 0) for ln in lines} - {None}
        for r in routes:
            if r.is_secure_variant:
                continue
            entry = fgraph.route_node(r)
            if not entry or not any(fgraph.forward_path(entry, s, max_hops=max_hops) is not None for s in sinks):
                continue
            url = f"{origin}{ctx}{_canon_path(r.url_pattern)}"
            if (i.cwe, _path(url)) in covered:
                continue
            key = (url, r.http_method.upper(), i.cwe)
            if key not in plan:
                plan[key] = (DastTargetEndpoint(url=url, method=r.http_method, params=list(r.params), route_ref=r,
                                                cwe_hints=[i.cwe], discovery="auto-verify"), [])
            plan[key][1].append(i)

    new: List[CommonFinding] = []
    attempted = 0
    skipped_budget = 0
    sem = asyncio.Semaphore(max(1, concurrency))
    headers = {"Cookie": session_cookie} if session_cookie else None

    async with httpx.AsyncClient(timeout=4.0, verify=False, headers=headers) as client:
        async def one(ep: DastTargetEndpoint, cwe: str) -> List[CommonFinding]:
            nonlocal attempted, skipped_budget
            async with sem:
                if time.time() - t0 > time_budget_s:
                    skipped_budget += 1
                    return []
                attempted += 1
                try:
                    res = await verify_endpoint_vulnerabilities(ep, client)
                    if not res and cwe == "CWE-79":
                        res = await verify_dom_xss_with_playwright(ep, screenshot_dir, http_client=client,
                                                                   session_cookie=session_cookie)
                except Exception:
                    return []
                res = [f for f in res if f.cwe == cwe]
                for f in res:
                    f.discovery = "auto-verify"
                    f.evidence_origin = "live-http"
                return res

        batches = await asyncio.gather(*(one(ep, k[2]) for k, (ep, _) in plan.items()))
    for b in batches:
        new.extend(b)

    proven = {(f.cwe, _path(f.url)) for f in new}
    upgraded = {id(i) for k, (ep, iss) in plan.items() if (k[2], _path(ep.url)) in proven for i in iss}
    stats = {
        "code_only_probeable": len(code_only),
        "attempted": attempted,
        "skipped_time_budget": skipped_budget,
        "new_findings": len(new),
        "upgraded": len(upgraded),  # issues with >=1 route proven; final status is decided by correlate_findings
        "still_code_only": len(code_only) - len(upgraded),
        "elapsed_s": round(time.time() - t0, 2),
    }
    return new, stats
