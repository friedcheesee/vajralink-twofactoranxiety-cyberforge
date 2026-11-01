"""Input (parameter) derivation for DAST endpoints - no app-specific names.

Order of evidence for which inputs an endpoint takes:
  1. the RouteEntry / SAST hand-off params (already on the endpoint),
  2. path variables in the URL template (substituted into the path),
  3. query-string keys on the endpoint URL itself,
  4. HTML form fields / link query strings found on the endpoint's own baseline page (stdlib html.parser),
  5. only last, a short generic list of conventional names, filtered to those the live app reacts to.
"""
from __future__ import annotations

import re
import urllib.parse
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple

import httpx

from vajra.dast.urlutil import path_vars

GENERIC_PARAMS: List[str] = ["id", "q", "name", "url", "file", "path", "host", "next", "redirect",
                             "search", "query", "username", "filename", "page"]

# Conventional, framework-neutral names per vulnerability class, tried first among the generic names.
GENERIC_PARAMS_BY_CWE: Dict[str, List[str]] = {
    "CWE-89": ["id", "q", "name", "username", "search", "query"],
    "CWE-78": ["host", "ip", "cmd", "address", "target"],
    "CWE-22": ["file", "filename", "path", "name", "page"],
    "CWE-601": ["next", "redirect", "url", "return", "goto"],
    "CWE-611": ["xml_body"],
}

_SKIP_INPUT_TYPES = {"submit", "button", "image", "reset", "file", "checkbox", "radio"}
_SKIP_NAME = re.compile(r"csrf|xsrf|token|_method|authenticity", re.I)


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: List[Dict[str, Any]] = []
        self.links: List[str] = []
        self._cur: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = {"action": a.get("action", ""), "method": (a.get("method") or "GET").upper(), "fields": {}}
            self.forms.append(self._cur)
        elif tag in ("input", "select", "textarea") and self._cur is not None:
            name = a.get("name", "")
            if name and a.get("type", "text").lower() not in _SKIP_INPUT_TYPES and not _SKIP_NAME.search(name):
                self._cur["fields"][name] = a.get("value", "")
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._cur = None


def parse_page_inputs(body: str, page_url: str) -> Dict[str, Any]:
    """Return {"forms": [{path, method, fields}], "link_params": {path: [keys]}} for same-page inputs."""
    p = _PageParser()
    try:
        p.feed(body or "")
    except Exception:
        pass
    forms = []
    for f in p.forms:
        target = urllib.parse.urlparse(urllib.parse.urljoin(page_url, f["action"]))
        forms.append({"path": target.path, "method": f["method"], "fields": f["fields"],
                      "query": list(urllib.parse.parse_qs(target.query).keys())})
    link_params: Dict[str, List[str]] = {}
    for href in p.links:
        u = urllib.parse.urlparse(urllib.parse.urljoin(page_url, href))
        keys = list(urllib.parse.parse_qs(u.query).keys())
        if keys:
            link_params.setdefault(u.path, [])
            link_params[u.path].extend(k for k in keys if k not in link_params[u.path])
    return {"forms": forms, "link_params": link_params}


def _reacts(base: Tuple[Optional[int], str], got: Tuple[Optional[int], str], marker: str) -> bool:
    if got[0] is None:
        return False
    body = (got[1] or "").replace(marker, "")
    return got[0] != base[0] or body.strip() != (base[1] or "").strip()


async def derive_inputs(ep: Any, client: httpx.AsyncClient) -> None:
    """Populate ep.path_vars / ep.params / ep.form_defaults (once). Real evidence first, generic names last."""
    if getattr(ep, "inputs_resolved", False):
        return
    ep.inputs_resolved = True
    template = getattr(ep, "url_template", None) or ep.url
    ep.path_vars = path_vars(urllib.parse.urlparse(template).path)
    params = [p for p in ep.params if p not in ep.path_vars]
    origin = "route"
    parsed_url = urllib.parse.urlparse(ep.url)
    for k in urllib.parse.parse_qs(parsed_url.query).keys():
        if k not in params:
            params.append(k)
            origin = origin if origin != "route" or len(params) > 1 else "url-query"

    if not params and not ep.path_vars:
        pages: List[str] = []
        try:
            r = await client.request(ep.method, ep.url, timeout=3.0, follow_redirects=False)
            pages.append(r.text)
            if ep.method != "GET":
                r2 = await client.get(ep.url, timeout=3.0, follow_redirects=False)
                pages.append(r2.text)
        except Exception:
            pass
        for body in pages:
            info = parse_page_inputs(body, ep.url)
            for f in info["forms"]:
                if f["path"].rstrip("/") == parsed_url.path.rstrip("/"):
                    for name, default in f["fields"].items():
                        if name not in params:
                            params.append(name)
                            ep.form_defaults[name] = default
                    for name in f["query"]:
                        if name not in params:
                            params.append(name)
            for name in info["link_params"].get(parsed_url.path, []):
                if name not in params:
                    params.append(name)
        if params:
            origin = "html-baseline"

    if not params and not ep.path_vars:
        # Last resort: conventional names, kept only if the live app visibly reacts to them.
        marker = "vajractl7"
        try:
            b = await client.request(ep.method, ep.url, timeout=3.0, follow_redirects=False)
            base = (b.status_code, b.text)
        except Exception:
            base = (None, "")
        reacting: List[str] = []
        if base[0] is not None:
            for name in GENERIC_PARAMS:
                try:
                    if ep.method == "GET":
                        r = await client.get(ep.url, params={name: marker}, timeout=3.0, follow_redirects=False)
                    else:
                        r = await client.request(ep.method, ep.url, data={name: marker}, timeout=3.0, follow_redirects=False)
                    if _reacts(base, (r.status_code, r.text), marker):
                        reacting.append(name)
                except Exception:
                    continue
        params = reacting[:6]
        if params:
            origin = "generic-reacting"
    ep.params = params
    ep.params_origin = origin if params or ep.path_vars else "none"
