"""
Python SAST taint engine (B-7): Flask / FastAPI / Django / plain Python web code, stdlib `ast` only.

Per function: request-controlled names are the function's parameters plus anything read from a request object
(request.args / form / json / GET / POST / query_params / cookies / headers), propagated forward through
assignments, string concatenation, f-strings, % and .format(). Sinks of the PRD's core classes are flagged when
a tainted value reaches them, and the matching SAFE patterns are emitted as suppressed decoys so they are never
reported (B-2):

  CWE-89  cursor/connection .execute/.executemany/.raw/text(...) with a query built from input
          safe: constant query + separate parameters tuple/dict
  CWE-78  os.system / os.popen / subprocess.* (shell=True or a string command) with input
          safe: argument list without shell=True
  CWE-22  open / send_file / FileResponse / Path(...).read_* with an input-derived path
          safe: os.path.basename / secure_filename / an allow-list membership check on the value
  CWE-601 redirect / RedirectResponse / HttpResponseRedirect to an input-derived URL
          safe: value chosen from an allow-list (x if x in ALLOWED else ...)
  CWE-79  HTML built by string concatenation / f-string with input and returned / wrapped in HTMLResponse,
          render_template_string, Markup(...)
          safe: html.escape / markupsafe.escape / bleach.clean applied to the input
  CWE-798 module- or class-level NAME = "literal" where NAME looks like a credential
"""
from __future__ import annotations

import ast
import os
import re
from typing import Dict, List, Optional, Set, Tuple

from vajra.models import CommonFinding, canonicalize_cwe
from vajra.sast.engines import ENGINE_DECOY as DECOY_ENGINE, ENGINE_SINK_SIG as ENGINE

SCANNER = "Vajra-Python-Taint"
_SKIP_DIRS = {".git", ".venv", "venv", "env", "site-packages", "node_modules", "__pycache__", ".tox", "build", "dist"}
_REQ_ATTRS = {"args", "form", "values", "json", "GET", "POST", "query_params", "cookies", "headers", "data", "files", "path_params"}
_SANITIZERS = {"escape", "basename", "secure_filename", "clean", "quote", "int", "float", "bool", "uuid", "abs"}
_SECRET_NAME = re.compile(r"(passw(or)?d|passwd|pwd|secret|api_?key|apikey|token|private_?key|access_?key|client_?secret)", re.I)
_PLACEHOLDER = re.compile(r"^(changeme|change_me|your[_-].*|xxx+|<.*>|\$\{.*\}|todo|none|null|test|example.*)$", re.I)


def _name_of(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _dotted(func: ast.AST) -> str:
    parts: List[str] = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))


class _Fn:
    """Taint state for one function body."""

    def __init__(self, fn: ast.AST):
        self.fn = fn
        args = fn.args  # type: ignore[attr-defined]
        self.tainted: Set[str] = {a.arg for a in args.args + args.kwonlyargs if a.arg not in ("self", "cls")}
        self.sanitized: Set[str] = set()
        self.allowlisted: Set[str] = set()
        # forward propagation, two passes to catch out-of-order helper variables
        for _ in range(2):
            for node in ast.walk(fn):
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    value = node.value
                    if value is None:
                        continue
                    for t in targets:
                        for n in ast.walk(t):
                            if isinstance(n, ast.Name):
                                if self.expr_sanitized(value):
                                    self.sanitized.add(n.id)
                                elif self.is_allowlist_choice(value):
                                    self.allowlisted.add(n.id)
                                elif self.expr_tainted(value):
                                    self.tainted.add(n.id)

    def is_request_read(self, e: ast.AST) -> bool:
        for n in ast.walk(e):
            if isinstance(n, ast.Attribute) and n.attr in _REQ_ATTRS and isinstance(n.value, ast.Name) and n.value.id in ("request", "req", "self"):
                return True
        return False

    def expr_sanitized(self, e: ast.AST) -> bool:
        return isinstance(e, ast.Call) and _name_of(e.func) in _SANITIZERS and any(self.expr_tainted(a) for a in e.args)

    def is_allowlist_choice(self, e: ast.AST) -> bool:
        """x if x in ALLOWED else default  /  ALLOWED.get(x, default)"""
        if isinstance(e, ast.IfExp) and isinstance(e.test, ast.Compare) and any(isinstance(op, (ast.In,)) for op in e.test.ops):
            return True
        if isinstance(e, ast.Call) and isinstance(e.func, ast.Attribute) and e.func.attr == "get" and self.expr_tainted(e.args[0] if e.args else ast.Constant(None)):
            return isinstance(e.func.value, ast.Name) and e.func.value.id.isupper()
        return False

    def expr_tainted(self, e: Optional[ast.AST]) -> bool:
        """True if input reaches `e` other than through a sanitiser call (html.escape(x), basename(x), int(x)...)."""
        if e is None:
            return False
        if isinstance(e, ast.Call) and _name_of(e.func) in _SANITIZERS:
            return False
        if isinstance(e, ast.Attribute) and e.attr in _REQ_ATTRS and isinstance(e.value, ast.Name) and e.value.id in ("request", "req"):
            return True
        if isinstance(e, ast.Name):
            return e.id in self.tainted and e.id not in self.sanitized and e.id not in self.allowlisted
        return any(self.expr_tainted(ch) for ch in ast.iter_child_nodes(e))

    def expr_guarded(self, e: ast.AST) -> Optional[str]:
        for n in ast.walk(e):
            if isinstance(n, ast.Name) and n.id in self.sanitized:
                return f"'{n.id}' is sanitised before use"
            if isinstance(n, ast.Name) and n.id in self.allowlisted:
                return f"'{n.id}' is chosen from an allow-list"
            if isinstance(n, ast.Call) and _name_of(n.func) in _SANITIZERS:
                return f"input passes through {_name_of(n.func)}()"
        return None


def _is_built_string(e: ast.AST) -> bool:
    if isinstance(e, ast.JoinedStr):
        return True
    if isinstance(e, ast.BinOp) and isinstance(e.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(e, ast.Call) and isinstance(e.func, ast.Attribute) and e.func.attr == "format":
        return True
    return False


def _has_html_literal(e: ast.AST) -> bool:
    return any(isinstance(n, ast.Constant) and isinstance(n.value, str) and "<" in n.value for n in ast.walk(e))


def scan_python_source(content: str, rel_path: str) -> Tuple[List[CommonFinding], List[CommonFinding]]:
    try:
        tree = ast.parse(content)
    except Exception:
        return [], []
    lines = content.splitlines()
    active: List[CommonFinding] = []
    safe: List[CommonFinding] = []
    seen: Set[Tuple[str, int]] = set()

    def snippet(n: ast.AST) -> str:
        s, e = getattr(n, "lineno", 1), getattr(n, "end_lineno", getattr(n, "lineno", 1))
        return "\n".join(lines[s - 1:min(e, s + 3)]).strip()[:300]

    def emit(rule: str, cwe: str, vtype: str, sev: str, node: ast.AST, fn_name: Optional[str], decoy: Optional[str] = None) -> None:
        ln = getattr(node, "lineno", 0)
        if (cwe, ln) in seen:
            return
        seen.add((cwe, ln))
        f = CommonFinding(
            finding_id=f"SAST-PYTAINT-{rule}-{rel_path}-{ln}", stage="SAST", scanner=SCANNER,
            cwe=canonicalize_cwe(cwe), raw_cwe=cwe, vuln_type=vtype, severity=sev,  # type: ignore[arg-type]
            file_path=rel_path, line=ln, end_line=getattr(node, "end_lineno", ln), function_name=fn_name,
            code_snippet=snippet(node), is_safe_decoy=bool(decoy), suppression_reason=decoy,
            engines=[ENGINE] + ([DECOY_ENGINE] if decoy else []),
            vault_candidate=(cwe == "CWE-798"),
        )
        (safe if decoy else active).append(f)

    # ---- hard-coded credentials at module / class level --------------------------------------------
    for node in list(tree.body) + [b for c in tree.body if isinstance(c, ast.ClassDef) for b in c.body]:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for t in node.targets:
                if isinstance(t, ast.Name) and _SECRET_NAME.search(t.id):
                    v = node.value.value
                    if len(v) >= 6 and not _PLACEHOLDER.match(v) and " " not in v:
                        emit("hardcoded-secret", "CWE-798", "Hard-coded Secret", "HIGH", node, None)

    # ---- per-function taint ----------------------------------------------------------------------
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        st = _Fn(fn)
        name = fn.name
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                callee, dotted = _name_of(node.func), _dotted(node.func)
                first = node.args[0] if node.args else None
                # SQL
                if callee in ("execute", "executemany", "executescript", "raw", "text", "query") and first is not None:
                    q = first
                    if isinstance(q, ast.Name) and q.id in st.tainted:
                        emit("sqli", "CWE-89", "SQL Injection", "CRITICAL", node, name)
                    elif _is_built_string(q) and st.expr_tainted(q):
                        emit("sqli", "CWE-89", "SQL Injection", "CRITICAL", node, name)
                    elif isinstance(q, ast.Constant) and len(node.args) >= 2 and st.expr_tainted(node.args[1]):
                        emit("sqli-param", "CWE-89", "SQL Injection", "CRITICAL", node, name,
                             decoy="parameterised query: constant SQL with separately bound parameters")
                # OS command
                elif dotted in ("os.system", "os.popen") or (dotted.startswith("subprocess.") and callee in ("run", "call", "check_output", "check_call", "Popen", "getoutput", "getstatusoutput")):
                    if first is not None and st.expr_tainted(first):
                        shell = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value for k in node.keywords)
                        if dotted.startswith("os.") or shell or callee in ("getoutput", "getstatusoutput") or not isinstance(first, (ast.List, ast.Tuple)):
                            emit("cmdi", "CWE-78", "OS Command Injection", "CRITICAL", node, name)
                        else:
                            emit("cmdi-list", "CWE-78", "OS Command Injection", "CRITICAL", node, name,
                                 decoy="argument list without shell=True: input cannot add shell syntax")
                # Path traversal
                elif callee in ("open", "send_file", "FileResponse", "read_text", "read_bytes", "send_from_directory") and first is not None:
                    arg = node.args[-1] if callee == "send_from_directory" and len(node.args) >= 2 else first
                    if st.expr_tainted(arg):
                        why = st.expr_guarded(arg)
                        if why or callee == "send_from_directory":
                            emit("path-safe", "CWE-22", "Path Traversal", "HIGH", node, name,
                                 decoy=why or "send_from_directory() rejects paths escaping its folder")
                        else:
                            emit("path", "CWE-22", "Path Traversal", "HIGH", node, name)
                # Open redirect
                elif callee in ("redirect", "RedirectResponse", "HttpResponseRedirect", "HttpResponsePermanentRedirect") and first is not None:
                    if st.expr_tainted(first):
                        emit("redirect", "CWE-601", "Open Redirect", "MEDIUM", node, name)
                    elif st.expr_guarded(first):
                        emit("redirect-safe", "CWE-601", "Open Redirect", "MEDIUM", node, name, decoy=st.expr_guarded(first))
                # XSS via explicit HTML response helpers
                elif callee in ("HTMLResponse", "render_template_string", "Markup", "make_response", "HttpResponse") and first is not None:
                    if st.expr_tainted(first):
                        why = st.expr_guarded(first)
                        if why:
                            emit("xss-safe", "CWE-79", "Cross-Site Scripting (XSS)", "HIGH", node, name, decoy=why)
                        else:
                            emit("xss", "CWE-79", "Cross-Site Scripting (XSS)", "HIGH", node, name)
            # XSS: handler returns an HTML string built from input
            if isinstance(node, ast.Return) and node.value is not None and _is_built_string(node.value) and _has_html_literal(node.value):
                if st.expr_tainted(node.value):
                    emit("xss-return", "CWE-79", "Cross-Site Scripting (XSS)", "HIGH", node, name)
                elif st.expr_guarded(node.value):
                    emit("xss-return-safe", "CWE-79", "Cross-Site Scripting (XSS)", "HIGH", node, name, decoy=st.expr_guarded(node.value))
    return active, safe


def scan_python_project(source_root: str) -> Tuple[List[CommonFinding], List[CommonFinding]]:
    active: List[CommonFinding] = []
    safe: List[CommonFinding] = []
    for root, dirs, files in os.walk(source_root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]
        for f in files:
            if not f.endswith(".py") or f.startswith("test_") or f.endswith("_test.py"):
                continue
            full = os.path.join(root, f)
            rel = os.path.relpath(full, source_root).replace(os.sep, "/")
            try:
                content = open(full, "r", encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            a, s = scan_python_source(content, rel)
            active.extend(a)
            safe.extend(s)
    return active, safe
