"""
Vajra Route Mapping Module (FR-4).
"""
from __future__ import annotations

import os
from typing import List
from vajra.models import RouteEntry
from vajra.routemap.java_jaxrs import extract_jaxrs_routes
from vajra.routemap.java_servlet import extract_servlet_routes
from vajra.routemap.java_spring import extract_java_routes
from vajra.routemap.python_web import extract_python_routes


def extract_routes(source_root: str) -> List[RouteEntry]:
    """Extract all routes: Java Spring MVC, classic Servlets (web.xml / @WebServlet), JAX-RS, and Python web apps.
    Routes are de-duplicated by (method, pattern, file, start line), so a caller that also runs one of the
    framework extractors itself (api.py's servlet call) cannot double-count."""
    routes: List[RouteEntry] = []
    seen = set()

    def _add(rs: List[RouteEntry]) -> None:
        for r in rs:
            key = (r.http_method.upper(), r.url_pattern, r.file_path, r.start_line)
            if key not in seen:
                seen.add(key)
                routes.append(r)

    has_java = any(f.endswith(".java") for _, _, files in os.walk(source_root) for f in files)
    if has_java:
        _add(extract_java_routes(source_root))
        _add(extract_servlet_routes(source_root))
        _add(extract_jaxrs_routes(source_root))

    has_python = any(f.endswith(".py") for _, _, files in os.walk(source_root) for f in files)
    if has_python:
        _add(extract_python_routes(source_root))

    return routes
