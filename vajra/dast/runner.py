"""
5-Stage Active DAST Pipeline Orchestrator (FR-2, FR-3, FR-4) with SAST hand-off.

Modes
  * sast_guided            - probe only the routes SAST handed over (the function graph says they reach a flagged
                             sink); SAST's CWE hints select the probes instead of guessing from route names
  * sast_guided+independent- guided routes first, then every other route / live-discovered endpoint on DAST's own
  * independent            - zero-knowledge scan of all routes (no SAST hints) - the baseline

Every finding is tagged
  discovery       = sast-guided | dast-independent | decoy-audit
  evidence_origin = live-http   (every finding comes from a real HTTP exchange; an unreachable target yields
                                 zero findings and stats["target_online"] = False with a reason)

Stages: 1 header/TLS audit, 2 differential HTTP probes, 3 headless-Chromium DOM XSS proof, 4 decoy audit
(re-probe routes SAST declared safe).
"""
from __future__ import annotations

import asyncio
import os
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

import httpx

from vajra.dast.crawler import crawl_target_endpoints
from vajra.dast.http_verifier import verify_endpoint_vulnerabilities
from vajra.dast.inputs import derive_inputs
from vajra.dast.urlutil import split_target
from vajra.dast.nuclei_headers_tls import audit_security_headers_and_tls
from vajra.dast.playwright_verifier import verify_dom_xss_with_playwright
from vajra.dast.safety import assert_safe_target, docker_reachable_url
from vajra.models import CommonFinding, RouteEntry
from vajra.sast.function_graph import canon_url

# CWE classes an HTTP probe can actually prove (everything else stays Code-only)
# (SSRF CWE-918 / IDOR CWE-639 are deliberately absent: there is no generic probe for them, so they stay Code-only.)
PROBEABLE_CWES = {"CWE-89", "CWE-78", "CWE-22", "CWE-601", "CWE-611", "CWE-79"}


async def run_dast_scan_detailed(
    target_base_url: str = "http://127.0.0.1:9090",
    routes: Optional[List[RouteEntry]] = None,
    screenshot_dir: str = "screenshots",
    *,
    plan: Optional[Dict[str, Dict[str, Any]]] = None,
    sast_guided: bool = False,
    independent: bool = True,
    include_policy: bool = True,
    decoy_audit: bool = False,
    context_path: str = "",
    session_cookie: Optional[str] = None,
) -> Tuple[List[CommonFinding], Dict[str, Any]]:
    """Run DAST and return (findings, run_stats).

    session_cookie: raw `Cookie:` header value (e.g. "JSESSIONID=abc123") from a session you already
    authenticated yourself (log in via a real browser, copy the cookie, paste it here). Sent on every
    HTTP probe and every Playwright browser context for this run, so routes gated behind a login wall
    (e.g. WebGoat) are actually exercised instead of just bouncing to the login page.
    """
    assert_safe_target(target_base_url)
    target_base_url, target_note = docker_reachable_url(target_base_url)
    assert_safe_target(target_base_url)
    t0 = time.time()
    clean_base = target_base_url.rstrip("/")
    origin, ctx = split_target(clean_base, context_path)
    common_headers = {"Cookie": session_cookie} if session_cookie else None
    plan = plan or {}
    if not plan:
        sast_guided = False
        independent = True

    findings: List[CommonFinding] = []
    seen_keys = set()
    sim_ctx = ["dast-independent"]
    offline_reason = ""
    request_counter = {"n": 0}
    state = {"online": False}

    def add_finding(f: CommonFinding) -> None:
        key = (f.cwe, f.url, f.parameter)
        if key in seen_keys:
            return
        seen_keys.add(key)
        if f.evidence_origin is None:
            f.evidence_origin = "live-http"
        if f.discovery is None:
            f.discovery = sim_ctx[0]
        findings.append(f)

    async def _count_request(_request: httpx.Request) -> None:
        request_counter["n"] += 1

    # Liveness: ANY HTTP response (404 / 5xx included) proves a server is listening; only connection-level
    # failures count as unreachable. Retry a few times so a slow start is not mistaken for "offline".
    last_err = ""
    for attempt in range(4):
        try:
            async with httpx.AsyncClient(timeout=4.0, verify=False, headers=common_headers) as test_client:
                await test_client.get(clean_base + "/")
            state["online"] = True
            break
        except Exception as e:
            last_err = f"{type(e).__name__}: {str(e)[:120]}"
            await asyncio.sleep(1.0 * (attempt + 1))
    if not state["online"]:
        offline_reason = f"target {clean_base} did not answer any HTTP request after 4 attempts ({last_err}); no DAST probes were sent"
    is_online = state["online"]

    endpoints: List[Any] = []
    katana_meta: Dict[str, Any] = {"available": False, "reason": "target offline, crawl not attempted", "new_endpoints": 0}
    if is_online:
        # Stage 1: global transport policy audit (headers / CORS / TLS)
        if include_policy:
            for hf in await audit_security_headers_and_tls(clean_base, session_cookie=session_cookie):
                hf.discovery = hf.discovery or "dast-independent"
                add_finding(hf)

        # Stage 2 & 3: SAST-guided and/or independent endpoint verification
        endpoints, katana_meta = await crawl_target_endpoints(
            clean_base,
            routes=routes,
            plan=plan,
            include_guided=sast_guided,
            include_independent=independent,
            include_decoy_audit=decoy_audit and independent,
            context_path=context_path,
            session_cookie=session_cookie,
        )

        def _is_xss_candidate(ep: Any) -> bool:
            v_hint = (ep.vulnerability_hint or "").upper()
            if "XSS" in v_hint or "xss" in ep.url.lower() or "CWE-79" in ep.cwe_hints:
                return True
            # Route with inputs but no SAST hint at all (unseen app): reflected XSS is one of the core classes,
            # so it gets the real-browser check too instead of being skipped.
            return bool(ep.params or ep.path_vars) and not ep.cwe_hints

        # Derive each endpoint's real inputs once (route params, path variables, HTML form fields on its own
        # baseline page, generic names last) so every later stage - HTTP probes and the browser - uses them.
        async with httpx.AsyncClient(timeout=4.0, verify=False, headers=common_headers) as prep_client:
            prep_sem = asyncio.Semaphore(20)

            async def _prep(ep: Any) -> None:
                async with prep_sem:
                    await derive_inputs(ep, prep_client)

            await asyncio.gather(*(_prep(ep) for ep in endpoints))

        pw_cm = None
        pw_instance = None
        shared_browser = None
        if any(_is_xss_candidate(ep) for ep in endpoints):
            try:
                from playwright.async_api import async_playwright

                pw_cm = async_playwright()
                pw_instance = await pw_cm.start()
                shared_browser = await pw_instance.chromium.launch(headless=True)
            except Exception:
                shared_browser = None

        decoy_violations: List[CommonFinding] = []
        try:
            http_sem = asyncio.Semaphore(20)
            pw_sem = asyncio.Semaphore(4)
            async with httpx.AsyncClient(
                timeout=4.0, verify=False, event_hooks={"request": [_count_request]}, headers=common_headers,
            ) as http_client:

                async def _scan_one_ep(ep: Any) -> List[CommonFinding]:
                    local_res: List[CommonFinding] = []
                    async with http_sem:
                        local_res.extend(await verify_endpoint_vulnerabilities(ep, http_client))
                    if _is_xss_candidate(ep) and not local_res:
                        async with pw_sem:
                            local_res.extend(
                                await verify_dom_xss_with_playwright(
                                    ep, screenshot_dir, shared_browser=shared_browser, http_client=http_client,
                                    session_cookie=session_cookie,
                                )
                            )
                    for item in local_res:
                        item.discovery = ep.discovery
                        item.evidence_origin = "live-http"
                    return local_res

                batches = await asyncio.gather(*(_scan_one_ep(ep) for ep in endpoints))
                for batch in batches:
                    for item in batch:
                        if item.discovery == "decoy-audit":
                            decoy_violations.append(item)
                        else:
                            add_finding(item)
        finally:
            if shared_browser is not None:
                try:
                    await shared_browser.close()
                except Exception:
                    pass
            if pw_instance is not None:
                try:
                    await pw_instance.stop()
                except Exception:
                    pass

        # Decoys that DAST managed to exploit are SAST false negatives -> surface them
        for item in decoy_violations:
            item.vuln_type = f"SAST decoy violated: {item.vuln_type}"
            add_finding(item)


    # ------------------------------------------------------------------ run statistics
    unique_routes_total = len(
        {(canon_url(r.url_pattern), r.http_method.upper()) for r in (routes or []) if not r.is_secure_variant}
    )
    by_disc: Dict[str, int] = {}
    for f in findings:
        by_disc[f.discovery or "unknown"] = by_disc.get(f.discovery or "unknown", 0) + 1
    ep_by_disc: Dict[str, int] = {}
    for ep in endpoints:
        ep_by_disc[ep.discovery] = ep_by_disc.get(ep.discovery, 0) + 1

    def _fkey(f: CommonFinding) -> Tuple[str, str]:
        return (f.cwe, canon_url(urllib.parse.urlparse(f.url or "").path))

    guided_keys = {_fkey(f) for f in findings if f.discovery == "sast-guided"}
    independent_new = [
        f for f in findings
        if f.discovery == "dast-independent" and f.cwe != "CWE-693" and _fkey(f) not in guided_keys
    ]
    # Route-map coverage: of the endpoints probed, how many resolve to a real RouteEntry, and (separately) how
    # many of the URLs found by crawling (katana / built-in link crawl) did. Computed from the real endpoint list.
    by_source: Dict[str, Dict[str, int]] = {}
    unresolved: List[str] = []
    for ep in endpoints:
        src = getattr(ep, "source", "route-table")
        row = by_source.setdefault(src, {"total": 0, "resolved": 0})
        row["total"] += 1
        if ep.route_ref is not None:
            row["resolved"] += 1
        elif len(unresolved) < 10:
            unresolved.append(f"{ep.method} {ep.url}")
    crawl_rows = [v for k, v in by_source.items() if k != "route-table"]
    route_coverage = {
        "endpoints_probed": len(endpoints),
        "resolved_to_route": sum(v["resolved"] for v in by_source.values()),
        "by_source": by_source,
        "crawled_urls_new": sum(v["total"] for v in crawl_rows),
        "crawled_urls_resolved": sum(v["resolved"] for v in crawl_rows),
        "unresolved_examples": unresolved,
    }
    decoy_probed = ep_by_disc.get("decoy-audit", 0)
    decoy_violated = [f for f in findings if f.discovery == "decoy-audit"]
    mode = (
        "sast_guided+independent" if (sast_guided and independent)
        else "sast_guided" if sast_guided
        else "independent"
    )
    stats: Dict[str, Any] = {
        "mode": mode,
        "target_online": is_online,
        "evidence_origin": "live-http" if is_online else "none",
        "offline_reason": offline_reason or None,
        "context_path": ctx,
        "route_coverage": route_coverage,
        "unique_routes_total": unique_routes_total,
        "targeted_routes": len(plan) if sast_guided else 0,
        "endpoints_probed": len(endpoints),
        "endpoints_by_discovery": ep_by_disc,
        "requests_sent": request_counter["n"],
        "findings_total": len(findings),
        "findings_by_discovery": by_disc,
        "independent_new_findings": len(independent_new),
        "independent_new_examples": [
            {"cwe": f.cwe, "url": f.url, "param": f.parameter, "type": f.vuln_type} for f in independent_new[:8]
        ],
        "decoy_audit": {
            "enabled": bool(decoy_audit and independent),
            "routes_probed": decoy_probed,
            "violations": len(decoy_violated),
            "validated_safe": max(0, decoy_probed - len(decoy_violated)),
        },
        "policy_audit": include_policy,
        "katana": katana_meta,
        "traffic_reduction_pct": round(100.0 * (1 - len(plan) / unique_routes_total), 1)
        if (sast_guided and not independent and unique_routes_total)
        else 0.0,
        "target_used": target_base_url,
        "target_note": target_note,
        "elapsed_sec": round(time.time() - t0, 2),
    }
    return findings, stats


def run_dast_scan_sync(
    target_base_url: str = "http://127.0.0.1:9090",
    routes: Optional[List[RouteEntry]] = None,
    screenshot_dir: str = "screenshots",
    **kwargs: Any,
) -> List[CommonFinding]:
    """Synchronous wrapper for run_dast_scan."""
    return asyncio.run(run_dast_scan(target_base_url, routes, screenshot_dir, **kwargs))


async def run_dast_scan(
    target_base_url: str = "http://127.0.0.1:9090",
    routes: Optional[List[RouteEntry]] = None,
    screenshot_dir: str = "screenshots",
    **kwargs: Any,
) -> List[CommonFinding]:
    """Backward-compatible wrapper returning only the findings (independent full scan by default)."""
    findings, _stats = await run_dast_scan_detailed(target_base_url, routes, screenshot_dir, **kwargs)
    return findings
