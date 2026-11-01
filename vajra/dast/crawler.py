"""
Hybrid DAST Endpoint Crawler & AST Parameter Seeder (FR-2, FR-4).

Endpoints come from these places and are tagged with HOW they were discovered:
  * "sast-guided"      - the route was handed over by SAST (the function graph says it can reach a flagged sink);
                         the CWE hints from SAST drive which probes are used.
  * "dast-independent" - DAST found it by itself: the rest of the route table (no SAST hint), a live
                         app-specific discovery endpoint if the target happens to publish one, and a real
                         katana crawl (vajra/dast/katana_crawl.py) of the running app's actual HTML/JS/forms -
                         the only one of these three that is genuinely independent of the source tree, and
                         the only one that still works on an app our AST route extractor doesn't recognize.
  * "decoy-audit"      - a route SAST declared safe (Variant.SECURE) that DAST re-probes to validate the suppression.
"""
from __future__ import annotations

import asyncio
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

from vajra.dast.katana_crawl import katana_crawl
from vajra.dast.link_crawl import link_crawl
from vajra.dast.safety import assert_safe_target
from vajra.dast.urlutil import build_route_matcher, concretize, split_target, strip_prefix
from vajra.models import RouteEntry
from vajra.routemap.java_spring import get_route_inputs
from vajra.sast.function_graph import canon_url


def _canon_template(p: str, prefix: str = "") -> str:
    """Route path with the context path removed; path variables ({id}, <int:id>, :id) left as a template."""
    return strip_prefix(p, prefix)


def _canon_path(p: str, prefix: str = "") -> str:
    """Concrete path (variables replaced by a value so the request reaches the handler), context path removed."""
    return concretize(_canon_template(p, prefix))


class DastTargetEndpoint:
    def __init__(
        self,
        url: str,
        method: str = "GET",
        params: Optional[List[str]] = None,
        route_ref: Optional[RouteEntry] = None,
        vulnerability_hint: Optional[str] = None,
        cwe_hints: Optional[List[str]] = None,
        discovery: str = "dast-independent",
        guard_context: Optional[List[Dict[str, Any]]] = None,
        url_template: Optional[str] = None,
        source: str = "route-table",
    ):
        self.url = url
        # URL with {path variables} left in place (None = no variables); `path_vars`, `form_defaults` and
        # `params_origin` are filled in by vajra.dast.inputs.derive_inputs from live evidence.
        self.url_template = url_template or url
        self.source = source
        self.path_vars: List[str] = []
        self.form_defaults: Dict[str, str] = {}
        self.params_origin: str = "route"
        self.inputs_resolved = False
        # "json" when the handler binds a @RequestBody-style entity, else form-encoded bodies (415 -> JSON retry)
        self.body_format: str = "form"
        self.method = method.upper()
        self.params = params or []
        self.route_ref = route_ref
        self.vulnerability_hint = vulnerability_hint
        self.cwe_hints: List[str] = list(cwe_hints or [])
        self.discovery = discovery
        # Real SAST guard/sink context per CWE this route reaches (file, guard_snippet, code_snippet,
        # function_name) - lets the DAST verifier ground an AI-crafted bypass in actual source code
        # instead of a generic payload. Empty when SAST found no filter guarding the sink.
        self.guard_context: List[Dict[str, Any]] = list(guard_context or [])


async def crawl_target_endpoints(
    base_url: str,
    routes: Optional[List[RouteEntry]] = None,
    *,
    plan: Optional[Dict[str, Dict[str, Any]]] = None,
    include_guided: bool = True,
    include_independent: bool = True,
    include_decoy_audit: bool = False,
    context_path: str = "",
    session_cookie: Optional[str] = None,
    use_katana: bool = True,
) -> Tuple[List[DastTargetEndpoint], Dict[str, Any]]:
    """Discover attack endpoints. Returns (endpoints, katana_meta) - katana_meta always has an "available"
    key so callers can show an honest status even when the binary isn't installed.

    plan: SAST hand-off from FunctionGraph.targeted_route_plan()["routes"] -> {"GET /X/LEVEL_1": {"cwes": [...]}}
    include_guided: emit the routes SAST handed over (tagged sast-guided, with CWE hints)
    include_independent: also emit every other route + live discovery (tagged dast-independent)
    include_decoy_audit: also emit routes SAST marked Variant.SECURE (tagged decoy-audit)
    use_katana: also run a real katana crawl (vajra/dast/katana_crawl.py) for genuinely source-independent
        discovery; no-ops cleanly if the binary isn't installed.
    """
    assert_safe_target(base_url)
    origin, ctx = split_target(base_url, context_path)
    endpoints: List[DastTargetEndpoint] = []
    seen: Set[Tuple[str, str]] = set()
    plan = plan or {}

    guided: List[DastTargetEndpoint] = []
    independent: List[DastTargetEndpoint] = []
    audit: List[DastTargetEndpoint] = []
    match_route = build_route_matcher(routes, ctx)

    def _mk(r: RouteEntry, template: str, **kw: Any) -> DastTargetEndpoint:
        ep = DastTargetEndpoint(
            url=f"{origin}{ctx}{concretize(template)}", url_template=f"{origin}{ctx}{template}",
            method=r.http_method, route_ref=r, **kw,
        )
        if get_route_inputs(r).get("body") == "json":
            ep.body_format = "json"
        return ep

    for r in routes or []:
        template = _canon_template(r.url_pattern, ctx)
        canon = concretize(template)
        key = (canon, r.http_method.upper())
        plan_key = f"{r.http_method.upper()} {canon_url(r.url_pattern)}"
        if key in seen:
            continue

        if r.is_secure_variant:
            if include_decoy_audit:
                seen.add(key)
                audit.append(_mk(r, template, params=list(r.params),
                                 vulnerability_hint=r.vulnerability_type_tag or r.class_name, discovery="decoy-audit"))
            continue

        in_plan = plan_key in plan
        if in_plan and include_guided:
            seen.add(key)
            guided.append(_mk(
                r, template,
                params=list(plan[plan_key].get("params") or r.params) or list(r.params),
                vulnerability_hint=None,
                cwe_hints=list(plan[plan_key].get("cwes", [])), discovery="sast-guided",
                guard_context=list(plan[plan_key].get("guard_context", [])),
            ))
        elif include_independent and not (in_plan and include_guided):
            seen.add(key)
            independent.append(_mk(r, template, params=list(r.params),
                                   vulnerability_hint=r.vulnerability_type_tag or r.class_name,
                                   discovery="dast-independent"))

    # Optional discovery source: some apps publish an endpoint listing at /allEndPointJson. Silently no-ops
    # everywhere else; never the main source of endpoints.
    if include_independent:
        try:
            async with httpx.AsyncClient(
                timeout=3.0, verify=False,
                headers={"Cookie": session_cookie} if session_cookie else None,
            ) as client:
                resp = await client.get(f"{origin}{ctx}/allEndPointJson")
                if resp.status_code == 200 and "json" in resp.headers.get("content-type", "").lower():
                    for item in resp.json():
                        v_name = item.get("vulnerabilityType", "")
                        for lvl in item.get("levels", []):
                            path = f"/{v_name}/{lvl.get('level', '')}"
                            if (path, "GET") in seen or (path, "POST") in seen:
                                continue
                            seen.add((path, "GET"))
                            independent.append(DastTargetEndpoint(
                                url=f"{origin}{ctx}{path}", method="GET", params=[], vulnerability_hint=v_name,
                                discovery="dast-independent", source="live-discovery",
                            ))
        except Exception:
            pass

    katana_meta: Dict[str, Any] = {"available": False, "reason": "not attempted", "new_endpoints": 0}
    if include_independent and use_katana:
        try:
            result = await katana_crawl(f"{origin}{ctx}", session_cookie=session_cookie)
        except Exception as e:
            result = {"available": False, "reason": f"katana crawl errored: {str(e)[:150]}", "endpoints": []}
        katana_meta = {k: v for k, v in result.items() if k != "endpoints"}
        crawled = [dict(item, _src="katana") for item in result.get("endpoints", [])]
        # katana unavailable (or found nothing): fall back to the built-in same-origin link/form crawl
        if not crawled:
            try:
                lc = await link_crawl(f"{origin}{ctx}/", session_cookie=session_cookie)
            except Exception as e:
                lc = {"available": False, "reason": f"link crawl errored: {str(e)[:150]}", "endpoints": []}
            katana_meta["link_crawl"] = {k: v for k, v in lc.items() if k != "endpoints"}
            crawled = [dict(item, _src="link-crawl") for item in lc.get("endpoints", [])]
        new_from_crawl = 0
        for item in crawled:
            path = urllib.parse.urlparse(item["url"]).path
            canon = _canon_path(path, ctx)
            method = item["method"]
            key = (canon, method)
            if key in seen:
                continue
            seen.add(key)
            new_from_crawl += 1
            hit = match_route(canon, method)
            independent.append(DastTargetEndpoint(
                url=f"{origin}{ctx}{canon}", method=method,
                params=list(item.get("params") or (hit.params if hit else [])),
                route_ref=hit,
                vulnerability_hint=f"{item['_src']}: {item.get('tag') or 'crawled'}",
                discovery="dast-independent", source=item["_src"],
            ))
        katana_meta["new_endpoints"] = new_from_crawl

    endpoints.extend(guided)
    endpoints.extend(independent)
    endpoints.extend(audit)
    return endpoints, katana_meta
