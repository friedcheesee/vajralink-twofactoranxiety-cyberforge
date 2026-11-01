"""
Python route map + call chains (FR-4, B-7): Flask, FastAPI / Starlette routers, and Django urls.py.

For every route it records:
  * url_pattern / method / handler file + line span
  * params: path variables, function arguments, and every request input the handler reads
    (request.args.get("id"), request.form["q"], request.json.get(..), request.GET.get(..), Query(...))
  * called_helpers: project-internal call chains up to 3 hops, in the same
    "hop=N|kind=AST|file:start-end|a() -> b()" format the correlation engine uses for Java, so a SAST sink in
    a helper (route -> service -> db function) is linked with a proven code path, not a guess.
"""
from __future__ import annotations

import ast
import os
import re
from collections import deque
from typing import Dict, List, Optional, Set, Tuple

from vajra.models import RouteEntry

_SKIP_DIRS = {".git", ".venv", "venv", "env", ".env", "site-packages", "node_modules", "__pycache__", ".tox", "build", "dist"}
_HTTP_VERBS = {"GET", "POST", "PUT", "DELETE", "PATCH"}
_REQ_SOURCES = {"args", "form", "values", "json", "cookies", "headers", "files", "GET", "POST", "query_params", "data"}
_PATH_VAR = re.compile(r"<(?:[^:<>]+:)?([^<>]+)>|\{([^}:]+)(?::[^}]*)?\}|:([A-Za-z_]\w*)")


def _const_str(node: Optional[ast.AST]) -> Optional[str]:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _request_inputs(fn: ast.AST) -> List[str]:
    """Names of request inputs read inside a handler body (Flask / Django / Starlette idioms)."""
    names: List[str] = []
    for n in ast.walk(fn):
        # request.args.get("id") / request.GET.get("q")
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("get", "getlist", "get_json"):
            src = n.func.value
            if isinstance(src, ast.Attribute) and src.attr in _REQ_SOURCES and n.args:
                s = _const_str(n.args[0])
                if s:
                    names.append(s)
        # request.args["id"]
        if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Attribute) and n.value.attr in _REQ_SOURCES:
            s = _const_str(n.slice if not isinstance(n.slice, ast.Index) else n.slice.value)  # type: ignore[attr-defined]
            if s:
                names.append(s)
    return names


class _FuncIndex:
    """Every function / method defined in the project: name -> [(file, start, end, node)]."""

    def __init__(self) -> None:
        self.by_name: Dict[str, List[Tuple[str, int, int, ast.AST]]] = {}

    def add_module(self, rel: str, tree: ast.AST) -> None:
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.by_name.setdefault(n.name, []).append((rel, n.lineno, getattr(n, "end_lineno", n.lineno), n))


def _called_names(fn: ast.AST) -> Set[str]:
    out: Set[str] = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            if isinstance(n.func, ast.Name):
                out.add(n.func.id)
            elif isinstance(n.func, ast.Attribute):
                out.add(n.func.attr)
    return out


def _call_chains(entry: ast.AST, entry_label: str, idx: _FuncIndex, max_hops: int = 3) -> List[str]:
    edges: List[str] = []
    seen: Set[Tuple[str, int]] = set()
    dq: deque = deque([(entry, 0, entry_label)])
    while dq:
        node, depth, chain = dq.popleft()
        if depth >= max_hops:
            continue
        for name in sorted(_called_names(node)):
            for f, s, e, fn in idx.by_name.get(name, []):
                if (f, s) in seen or fn is entry:
                    continue
                seen.add((f, s))
                new_chain = f"{chain} -> {name}()"
                edges.append(f"hop={depth + 1}|kind=AST|{f.replace(os.sep, '/')}:{s}-{e}|{new_chain}")
                dq.append((fn, depth + 1, new_chain))
    return edges


class PythonRouteVisitor(ast.NodeVisitor):
    def __init__(self, rel_path: str, idx: _FuncIndex, prefixes: Dict[str, str]):
        self.rel_path = rel_path
        self.idx = idx
        self.prefixes = prefixes  # router / blueprint variable -> url prefix
        self.routes: List[RouteEntry] = []
        self._class: str = ""

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        prev, self._class = self._class, node.name
        self.generic_visit(node)
        self._class = prev

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check(node)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def _check(self, node: ast.AST) -> None:
        for dec in getattr(node, "decorator_list", []):
            if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)):
                continue
            verb = dec.func.attr.upper()
            url = _const_str(dec.args[0]) if dec.args else None
            if url is None:
                for kw in dec.keywords:
                    if kw.arg in ("path", "rule"):
                        url = _const_str(kw.value)
            if url is None:
                continue
            methods: List[str]
            if verb in _HTTP_VERBS:
                methods = [verb]
            elif verb in ("ROUTE", "API_ROUTE", "WEBSOCKET"):
                methods = ["GET"]
                for kw in dec.keywords:
                    if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                        methods = [m.upper() for m in (_const_str(e) for e in kw.value.elts) if m] or ["GET"]
            else:
                continue
            owner = dec.func.value.id if isinstance(dec.func.value, ast.Name) else ""
            full_url = (self.prefixes.get(owner, "").rstrip("/") + "/" + url.lstrip("/")) if owner in self.prefixes else url
            self._add(node, full_url, methods)

    def _add(self, node: ast.AST, url: str, methods: List[str]) -> None:
        name = getattr(node, "name", "handler")
        start, end = getattr(node, "lineno", 1), getattr(node, "end_lineno", getattr(node, "lineno", 1))
        params: List[str] = []
        for m in _PATH_VAR.finditer(url):
            params.append(next(g for g in m.groups() if g))
        args = getattr(node, "args", None)
        for a in (args.args + args.kwonlyargs) if args else []:
            if a.arg not in {"self", "cls", "request", "req", "db", "session", "current_user", "background_tasks"}:
                params.append(a.arg)
        params.extend(_request_inputs(node))
        params = list(dict.fromkeys(params))
        label = f"{self._class + '.' if self._class else ''}{name}()"
        helpers = _call_chains(node, label, self.idx)
        for meth in methods:
            self.routes.append(RouteEntry(
                http_method=meth, url_pattern=url, handler_name=name,
                class_name=self._class or os.path.splitext(os.path.basename(self.rel_path))[0],
                file_path=self.rel_path.replace(os.sep, "/"), start_line=start, end_line=end,
                params=params, called_helpers=helpers, is_secure_variant=False,
            ))


def _router_prefixes(tree: ast.AST) -> Dict[str, str]:
    """`bp = Blueprint("x", __name__, url_prefix="/api")` / `router = APIRouter(prefix="/api")`."""
    out: Dict[str, str] = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            for kw in n.value.keywords:
                if kw.arg in ("url_prefix", "prefix"):
                    p = _const_str(kw.value)
                    if p:
                        out[n.targets[0].id] = p
    return out


def _django_routes(rel: str, tree: ast.AST, idx: _FuncIndex) -> List[RouteEntry]:
    """urls.py: path("orders/<int:id>/", views.order_detail) -> the view function's span."""
    out: List[RouteEntry] = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("path", "re_path") and len(n.args) >= 2:
            url = _const_str(n.args[0])
            view = n.args[1]
            vname = view.attr if isinstance(view, ast.Attribute) else (view.id if isinstance(view, ast.Name) else None)
            if url is None or not vname:
                continue
            for f, s, e, fn in idx.by_name.get(vname, [])[:1]:
                v = PythonRouteVisitor(f, idx, {})
                v._add(fn, "/" + url.lstrip("^").rstrip("$").lstrip("/"), ["GET", "POST"])
                out.extend(v.routes)
    return out


def extract_python_routes(source_root: str) -> List[RouteEntry]:
    modules: List[Tuple[str, ast.AST]] = []
    for root, dirs, files in os.walk(source_root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for file in files:
            if not file.endswith(".py"):
                continue
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, source_root)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    modules.append((rel_path, ast.parse(f.read(), filename=rel_path)))
            except Exception:
                continue
    idx = _FuncIndex()
    for rel, tree in modules:
        idx.add_module(rel.replace(os.sep, "/"), tree)
    routes: List[RouteEntry] = []
    for rel, tree in modules:
        v = PythonRouteVisitor(rel, idx, _router_prefixes(tree))
        v.visit(tree)
        routes.extend(v.routes)
        if os.path.basename(rel) == "urls.py":
            routes.extend(_django_routes(rel, tree, idx))
    return routes
