"""
Classic Java EE Servlet Route Extractor (pre-Spring).

Many real vulnerable-app benchmarks (e.g. IBM AltoroJ, older OWASP demos) predate Spring and route
HTTP requests either via WEB-INF/web.xml <servlet>/<servlet-mapping> declarations, or via the
Servlet 3.0+ @WebServlet(urlPatterns=... / value=...) annotation. vajra.routemap.java_spring only understands
Spring MVC annotations, so it finds zero routes for these apps. This module fills that gap with the same
honesty standard: every RouteEntry it returns points at a real doGet/doPost/doPut/doDelete (or service) method
span in a real file, and params are real request.getParameter(...) calls found in that method body - nothing
is guessed or padded.

Handled: every web.xml in the tree, several <url-pattern> per <servlet-mapping>, several mappings per servlet,
@WebServlet(urlPatterns / value / name=..., arrays, constants). Path-prefix patterns (`/admin/*`) are emitted
without the trailing wildcard; extension patterns (`*.do`) cannot be turned into a URL and are skipped.
"""
from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Set, Tuple

from vajra.models import RouteEntry
from vajra.routemap.java_spring import _balanced_end, _eval_values, _parse_ann_args, extract_constants

_PARAM_RE = re.compile(r'getParameter(?:Values)?\(\s*["\']([^"\']+)["\']')
_METHOD_RE = re.compile(
    r'(?:protected|public)\s+void\s+(doGet|doPost|doPut|doDelete|doPatch|service)\s*\([^)]*\)\s*'
    r'(?:throws\s+[\w,.\s]+)?\s*\{'
)
_WEBSERVLET_RE = re.compile(r"@WebServlet\b")
_CLASS_RE = re.compile(r"\s*(?:@[\w.]+(?:\s*\([^)]*\))?\s*)*(?:public\s+|final\s+|abstract\s+)*class\s+(\w+)")
_VERB_TO_HTTP = {"doGet": "GET", "doPost": "POST", "doPut": "PUT", "doDelete": "DELETE", "doPatch": "PATCH"}
_SKIP_DIRS = (".git", "target", "build", "node_modules")


def _find_java_file_for_class(source_root: str, class_name: str) -> Optional[str]:
    """Locate the .java file of a (possibly fully qualified) servlet class; the package path wins over a
    same-named class elsewhere."""
    simple = class_name.split(".")[-1] + ".java"
    pkg_path = class_name.replace(".", os.sep) + ".java"
    fallback = None
    for cur, dirs, files in os.walk(source_root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        if simple in files:
            full = os.path.join(cur, simple)
            if full.endswith(pkg_path):
                return full
            fallback = fallback or full
    return fallback


def _brace_match_end(content: str, open_brace_idx: int) -> int:
    """Index just after the '}' that closes the brace opened at open_brace_idx (which must be '{')."""
    depth = 1
    i = open_brace_idx + 1
    while i < len(content) and depth > 0:
        if content[i] == "{":
            depth += 1
        elif content[i] == "}":
            depth -= 1
        i += 1
    return i


def _extract_servlet_methods(file_path: str) -> Dict[str, Tuple[int, int, List[str]]]:
    """Return {"doGet": (start_line, end_line, params), ...} for one servlet .java file."""
    try:
        content = open(file_path, "r", encoding="utf-8", errors="ignore").read()
    except Exception:
        return {}
    out: Dict[str, Tuple[int, int, List[str]]] = {}
    for m in _METHOD_RE.finditer(content):
        verb = m.group(1)
        open_brace_idx = m.end() - 1
        end_idx = _brace_match_end(content, open_brace_idx)
        body_text = content[open_brace_idx + 1:end_idx - 1]
        params = sorted(set(_PARAM_RE.findall(body_text)))
        start_line = content.count("\n", 0, m.start()) + 1
        end_line = content.count("\n", 0, end_idx) + 1
        out[verb] = (start_line, end_line, params)
    return out


def _normalize_pattern(url_pattern: str) -> Optional[str]:
    p = (url_pattern or "").strip()
    if not p or p.startswith("*."):
        return None  # extension mapping: no concrete URL can be derived
    if p.endswith("/*"):
        p = p[:-2] or "/"
    return "/" + p.lstrip("/")


def _routes_for_mapping(url_pattern: str, class_name: str, file_path: str, source_root: str,
                         seen: Set[Tuple[str, str]]) -> List[RouteEntry]:
    methods = _extract_servlet_methods(file_path)
    if not methods:
        return []
    clean_pattern = _normalize_pattern(url_pattern)
    if clean_pattern is None:
        return []
    rel_path = os.path.relpath(file_path, source_root).replace("\\", "/")
    out: List[RouteEntry] = []
    for verb, (s_line, e_line, params) in methods.items():
        if verb == "service":
            # service() handles every verb the container dispatches; a GET and a POST route is what is observable
            verbs = ["GET", "POST"]
        else:
            v = _VERB_TO_HTTP.get(verb)
            verbs = [v] if v else []
        for http_method in verbs:
            key = (http_method, clean_pattern)
            if key in seen:
                continue
            seen.add(key)
            out.append(RouteEntry(
                http_method=http_method, url_pattern=clean_pattern, handler_name=verb,
                class_name=class_name, file_path=rel_path, start_line=s_line, end_line=e_line,
                params=list(params),
            ))
    return out


def _webxml_files(source_root: str) -> List[str]:
    found: List[str] = []
    for cur, dirs, files in os.walk(source_root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        if "web.xml" in files:
            found.append(os.path.join(cur, "web.xml"))
    return found


def extract_servlet_routes(source_root: str) -> List[RouteEntry]:
    """Parse WEB-INF/web.xml <servlet-mapping> declarations and @WebServlet annotations.

    Returns [] (not an error) when the app has neither - it's simply not a classic-Servlet app,
    e.g. a pure Spring Boot or non-Java target where java_spring.py or another extractor applies.
    """
    routes: List[RouteEntry] = []
    seen: Set[Tuple[str, str]] = set()

    # 1) web.xml-declared servlets (classic routing: <servlet> name->class, <servlet-mapping> name->patterns)
    for webxml_path in _webxml_files(source_root):
        servlet_class_by_name: Dict[str, str] = {}
        mappings: List[Tuple[str, str]] = []
        try:
            raw = open(webxml_path, "r", encoding="utf-8", errors="ignore").read()
            # Strip all namespace declarations AND any namespaced attribute (e.g. xsi:schemaLocation) -
            # ElementTree errors on an unbound prefix once its xmlns: declaration is gone, and we only
            # need the element text content (servlet-name/class/url-pattern), never these attributes.
            raw_no_ns = re.sub(r'\s+[\w.-]+:[\w.-]+\s*=\s*"[^"]*"', "", raw)
            raw_no_ns = re.sub(r'\s+xmlns\s*=\s*"[^"]*"', "", raw_no_ns)
            root = ET.fromstring(raw_no_ns)
        except Exception:
            root = None
        if root is None:
            continue

        def _tag(el) -> str:
            return el.tag.split("}")[-1]

        for el in root.iter():
            tag = _tag(el)
            if tag == "servlet":
                name = cls = None
                for c in el:
                    if _tag(c) == "servlet-name":
                        name = (c.text or "").strip()
                    elif _tag(c) == "servlet-class":
                        cls = (c.text or "").strip()
                if name and cls:
                    servlet_class_by_name[name] = cls
            elif tag == "servlet-mapping":
                name = None
                patterns: List[str] = []
                for c in el:
                    if _tag(c) == "servlet-name":
                        name = (c.text or "").strip()
                    elif _tag(c) == "url-pattern":
                        patterns.append((c.text or "").strip())
                for pattern in patterns:
                    if name and pattern:
                        mappings.append((name, pattern))

        for servlet_name, url_pattern in mappings:
            cls = servlet_class_by_name.get(servlet_name)
            if not cls:
                continue
            java_file = _find_java_file_for_class(source_root, cls)
            if not java_file:
                continue
            routes.extend(_routes_for_mapping(url_pattern, cls.split(".")[-1], java_file, source_root, seen))

    # 2) @WebServlet(urlPatterns=... | value=... | "..." | {"a","b"}) annotation mapping (Servlet 3.0+)
    for cur, dirs, files in os.walk(source_root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fname in files:
            if not fname.endswith(".java"):
                continue
            fpath = os.path.join(cur, fname)
            try:
                content = open(fpath, "r", encoding="utf-8", errors="ignore").read()
            except Exception:
                continue
            if "@WebServlet" not in content:
                continue
            consts = extract_constants(content)
            for m in _WEBSERVLET_RE.finditer(content):
                pos = m.end()
                args = {}
                if re.match(r"\s*\(", content[pos:pos + 20]):
                    open_idx = content.index("(", pos)
                    end = _balanced_end(content, open_idx)
                    if end < 0:
                        continue
                    args = _parse_ann_args(content[open_idx + 1:end])
                    pos = end + 1
                cm = _CLASS_RE.match(content, pos)
                if not cm:
                    continue
                patterns = _eval_values(args.get("urlPatterns") or args.get("value"), consts)
                for pat in patterns:
                    routes.extend(_routes_for_mapping(pat, cm.group(1), fpath, source_root, seen))

    return routes
