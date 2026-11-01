"""
Java Spring & SasanLabs/VulnerableApp Route and Inter-Procedural Call-Graph Extractor (FR-4).
Parses Spring Boot controllers, custom VulnerableApp annotations, Java constant symbol tables,
and computes a bounded 3-hop inter-procedural call-graph closure across intra-class helpers
(including overloaded methods) and constructor/field-injected @Service / Validator beans.
"""
from __future__ import annotations

import os
import re
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from vajra.models import RouteEntry

JAVA_CONTROL_KEYWORDS: Set[str] = {
    "if", "for", "while", "catch", "switch", "synchronized", "new",
    "super", "this", "return", "throw", "else", "try", "equals",
}


class JavaClassInfo:
    def __init__(self, file_path: str, class_name: str, package_name: str):
        self.file_path = file_path
        self.class_name = class_name
        self.package_name = package_name
        self.base_paths: List[str] = []
        self.constants: Dict[str, str] = {}

        # Primary (start_line, end_line) per method name
        self.methods: Dict[str, Tuple[int, int]] = {}
        # Full list of overloads: method_name -> [(start_line, end_line, called_methods, extracted_params)]
        self.method_defs: Dict[str, List[Tuple[int, int, List[str], List[str]]]] = {}
        # field_name -> ServiceClassName
        self.injected_services: Dict[str, str] = {}


_STRING_LITERAL = r'"(?:[^"\\\n]|\\.)*"'
_CONST_DECL = re.compile(r'\bString\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*((?:' + _STRING_LITERAL + r'|[A-Za-z_][\w.]*)(?:\s*\+\s*(?:' + _STRING_LITERAL + r'|[A-Za-z_][\w.]*))*)\s*;')


def _eval_concat(expr: str, constants: Dict[str, str]) -> Optional[str]:
    """Evaluate `"a" + CONST + "b"` against known constants; None if any term is unknown."""
    out = ""
    for term in _split_top(expr, "+"):
        term = term.strip()
        if len(term) >= 2 and term[0] == '"' and term[-1] == '"':
            out += term[1:-1]
        elif term in constants:
            out += constants[term]
        elif term.split(".")[-1] in constants:
            out += constants[term.split(".")[-1]]
        else:
            return None
    return out


def extract_constants(content: str, class_name: str = "", known: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Extract String constants like `static final String IP_ADDRESS = "ipaddress";` (also `"a" + OTHER` forms).
    `known` lets constants defined in other classes/files be used on the right-hand side."""
    constants: Dict[str, str] = {}
    scope = dict(known or {})
    for _ in range(2):  # second pass resolves constants declared after their first use
        for match in _CONST_DECL.finditer(content):
            val = _eval_concat(match.group(2), scope)
            if val is None:
                continue
            c_name = match.group(1)
            constants[c_name] = val
            scope[c_name] = val
            if class_name:
                constants[f"{class_name}.{c_name}"] = val
                scope[f"{class_name}.{c_name}"] = val
    return constants


def _split_top(text: str, sep: str = ",") -> List[str]:
    """Split on `sep` at nesting depth 0 (ignores separators inside (), {}, <>, [] and string literals)."""
    parts: List[str] = []
    depth = 0
    cur: List[str] = []
    in_str: Optional[str] = None
    i = 0
    while i < len(text):
        ch = text[i]
        if in_str:
            cur.append(ch)
            if ch == "\\" and i + 1 < len(text):
                cur.append(text[i + 1])
                i += 1
            elif ch == in_str:
                in_str = None
        elif ch in ('"', "'"):
            in_str = ch
            cur.append(ch)
        elif ch in "({[<":
            depth += 1
            cur.append(ch)
        elif ch in ")}]>":
            depth -= 1
            cur.append(ch)
        elif ch == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return [p for p in parts if p.strip()]


def _balanced_end(content: str, open_idx: int) -> int:
    """Index of the ')' matching the '(' at open_idx (string-aware); -1 if unbalanced."""
    depth = 0
    in_str: Optional[str] = None
    i = open_idx
    while i < len(content):
        ch = content[i]
        if in_str:
            if ch == "\\":
                i += 1
            elif ch == in_str:
                in_str = None
        elif ch in ('"', "'"):
            in_str = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _parse_ann_args(arg_text: str) -> Dict[str, str]:
    """`value = "/a", method = {GET}` -> {"value": '"/a"', "method": "{GET}"}; a lone positional arg is `value`."""
    out: Dict[str, str] = {}
    for idx, part in enumerate(_split_top(arg_text or "")):
        m = re.match(r"\s*([A-Za-z_]\w*)\s*=(?!=)\s*([\s\S]*)$", part)
        if m:
            out[m.group(1)] = m.group(2).strip()
        elif idx == 0:
            out["value"] = part.strip()
    return out


def _eval_values(expr: Optional[str], constants: Dict[str, str]) -> List[str]:
    """Resolve an annotation attribute (string, constant, concatenation, or {array of those}) to strings."""
    if expr is None:
        return []
    expr = expr.strip()
    if expr.startswith("{") and expr.endswith("}"):
        items = _split_top(expr[1:-1])
    else:
        items = [expr]
    vals: List[str] = []
    for it in items:
        v = _eval_concat(it, constants)
        if v is None:
            tok = it.strip()
            if re.fullmatch(r"[A-Za-z_][\w.]*", tok):
                v = tok.split(".")[-1]  # unresolved constant: fall back to its name (same as before)
            else:
                continue
        vals.append(v)
    return vals


def extract_called_methods(method_body: str) -> List[str]:
    """Extract method invocations inside a method body (e.g. this.readFile(...) or authLoginService.authenticate(...))."""
    calls: Set[str] = set()
    for match in re.finditer(r'(?:this\.|[A-Za-z0-9_]+\.)?([A-Za-z0-9_]+)\s*\(', method_body):
        name = match.group(1)
        if name not in JAVA_CONTROL_KEYWORDS and not name[0].isupper():
            calls.add(name)
    return sorted(calls)


def extract_method_defs(
    lines: List[str],
    constants: Optional[Dict[str, str]] = None,
) -> Tuple[Dict[str, Tuple[int, int]], Dict[str, List[Tuple[int, int, List[str], List[str]]]]]:
    """Determine accurate (start_line, end_line) spans for all Java methods (single-line, multi-line, and overloaded)."""
    consts = constants or {}
    methods_primary: Dict[str, Tuple[int, int]] = {}
    method_defs: Dict[str, List[Tuple[int, int, List[str], List[str]]]] = {}

    header_re = re.compile(
        r'^\s*(?:(?:public|protected|private|static|final|synchronized|abstract)\s+)*'
        r'(?:[\w<>\[\],\.\?]+(?:\s+[\w<>\[\],\.\?]+)*)\s+'
        r'([A-Za-z_][A-Za-z0-9_]*)\s*\(([^;{}]*)\)\s*(?:throws\s+[\w,\.\s]+)?\s*\{'
    )

    total_lines = len(lines)
    idx = 0
    while idx < total_lines:
        raw_line = lines[idx]
        stripped = raw_line.strip()
        if (
            not stripped
            or stripped.startswith("//")
            or stripped.startswith("/*")
            or stripped.startswith("*")
            or stripped.startswith("@")
        ):
            idx += 1
            continue

        # Join up to 6 lines if a method signature (including return type on its own line) wraps before '{'
        joined = raw_line
        join_end_idx = idx
        if "{" not in raw_line and ";" not in raw_line and "}" not in raw_line and "=" not in raw_line:
            for lookahead in range(idx + 1, min(idx + 10, total_lines)):
                nxt = lines[lookahead]
                if nxt.strip().startswith("//"):
                    continue
                joined += " " + nxt.strip()
                join_end_idx = lookahead
                if "{" in nxt or ";" in nxt:
                    break

        m = header_re.match(joined)
        if m:
            method_name = m.group(1)
            params_sig = m.group(2)
            if method_name not in JAVA_CONTROL_KEYWORDS:
                start_line = idx + 1
                end_line = start_line
                brace_count = 0
                found_first_brace = False
                in_str: Optional[str] = None
                for j in range(idx, total_lines):
                    cur_line = lines[j]
                    # Ignore line comments outside strings
                    k = 0
                    while k < len(cur_line):
                        ch = cur_line[k]
                        if in_str:
                            if ch == "\\" and k + 1 < len(cur_line):
                                k += 2
                                continue
                            if ch == in_str:
                                in_str = None
                        else:
                            if ch == "/" and k + 1 < len(cur_line) and cur_line[k + 1] == "/":
                                break
                            if ch in ('"', "'"):
                                in_str = ch
                            elif ch == "{":
                                brace_count += 1
                                found_first_brace = True
                            elif ch == "}":
                                brace_count -= 1
                        k += 1
                    if found_first_brace and brace_count <= 0:
                        end_line = j + 1
                        break

                body_text = "\n".join(lines[idx:end_line])
                called = [c for c in extract_called_methods(body_text) if c != method_name or len(method_defs.get(method_name, [])) >= 0]
                extracted_params = _extract_params_from_sig_and_body(params_sig, body_text, consts)

                if method_name not in methods_primary:
                    methods_primary[method_name] = (start_line, end_line)
                method_defs.setdefault(method_name, []).append(
                    (start_line, end_line, called, extracted_params)
                )
                idx = max(idx + 1, join_end_idx + 1)
                continue

        idx += 1

    return methods_primary, method_defs


def extract_method_ranges(lines: List[str]) -> Dict[str, Tuple[int, int]]:
    """Backwards-compatible helper returning method_name -> (start_line, end_line)."""
    primary, _ = extract_method_defs(lines)
    return primary


def find_enclosing_method(
    lines: List[str],
    target_line: Optional[int],
) -> Tuple[Optional[str], Optional[int], Optional[int], Optional[str]]:
    """Locate the innermost Java method enclosing `target_line` (1-indexed) and extract preceding guard lines."""
    if not target_line or target_line < 1 or not lines:
        return None, None, None, None

    _, method_defs = extract_method_defs(lines)
    best_name: Optional[str] = None
    best_span: Optional[Tuple[int, int]] = None

    for m_name, overloads in method_defs.items():
        for m_start, m_end, _, _ in overloads:
            if m_start <= target_line <= m_end:
                if best_span is None or (m_end - m_start) < (best_span[1] - best_span[0]):
                    best_name = m_name
                    best_span = (m_start, m_end)

    if not best_name or not best_span:
        return None, None, None, None

    m_start, m_end = best_span
    guard_start = max(m_start, target_line - 8)
    guard_lines: List[str] = []
    for ln_idx in range(guard_start - 1, target_line - 1):
        if 0 <= ln_idx < len(lines):
            s = lines[ln_idx].strip()
            if any(
                kw in s.lower()
                for kw in (
                    "if ", "if(", "pattern", "matcher", "replace", "filter",
                    "validator", "valid", "escape", "encode", "contains", "whitelist", "allow",
                )
            ):
                guard_lines.append(s)

    guard_snippet = "\n".join(guard_lines[:5]) if guard_lines else None
    return best_name, m_start, m_end, guard_snippet


# Side table: per route (file, start_line) inputs that are NOT query/body parameters, plus the body encoding.
#   {"header": [...], "cookie": [...], "body": "json" | "form" | None}
ROUTE_INPUTS: Dict[Tuple[str, int], Dict[str, object]] = {}

_SIMPLE_TYPES = {
    "String", "int", "Integer", "long", "Long", "boolean", "Boolean", "double", "Double", "float", "Float",
    "short", "Short", "byte", "Byte", "char", "Character", "BigDecimal", "BigInteger", "UUID", "Date",
    "LocalDate", "LocalDateTime", "Object", "MultipartFile",
}
_INFRA_TYPES = {
    "HttpServletRequest", "HttpServletResponse", "HttpSession", "Model", "ModelMap", "ModelAndView", "Principal",
    "BindingResult", "Authentication", "Locale", "WebRequest", "RedirectAttributes", "InputStream", "OutputStream",
    "Reader", "Writer", "HttpHeaders", "HttpEntity", "RequestEntity", "ServletRequest", "ServletResponse",
    "Pageable", "UriComponentsBuilder", "TimeZone", "HttpMethod",
}


def _split_param_decl(decl: str) -> Tuple[List[Tuple[str, str]], str, str]:
    """One formal parameter -> ([(annotation name, raw args)], type, variable name)."""
    anns: List[Tuple[str, str]] = []
    rest = decl.strip()
    while rest.startswith("@"):
        m = re.match(r"@([\w.]+)\s*", rest)
        if not m:
            break
        name = m.group(1).split(".")[-1]
        rest = rest[m.end():]
        args = ""
        if rest.startswith("("):
            end = _balanced_end(rest, 0)
            if end < 0:
                break
            args = rest[1:end]
            rest = rest[end + 1:].lstrip()
        anns.append((name, args))
    rest = re.sub(r"\bfinal\s+", "", rest).strip()
    m = re.match(r"([\s\S]+?)\s+([A-Za-z_]\w*)\s*$", rest)
    if not m:
        return anns, "", ""
    return anns, m.group(1).strip(), m.group(2)


def _extract_params_from_sig_and_body(
    params_sig: str,
    method_body: str,
    constants: Dict[str, str],
    class_fields: Optional[Dict[str, List[str]]] = None,
    side: Optional[Dict[str, object]] = None,
) -> List[str]:
    """Declared HTTP input names from the handler signature and body.

    Query/form/body names go into the returned list: @RequestParam (every form), @PathVariable (the name also
    appears in the URL template - the DAST layer substitutes it into the path), fields of @RequestBody /
    @ModelAttribute / implicit-model DTOs found in the repo, queryParams.get(..), request.getParameter(..).
    Headers and cookies (@RequestHeader / @CookieValue) are recorded in `side`, not as parameters.
    """
    extracted: List[str] = []
    if side is None:
        side = {}

    def _add(p: str) -> None:
        p_clean = (p or "").strip()
        if (
            p_clean
            and p_clean not in extracted
            and p_clean not in {"queryParams", "requestEntity", "request", "headers", "true", "false"}
            and not p_clean.startswith("required")
        ):
            extracted.append(p_clean)

    def _ann_name(args: str, var_name: str) -> str:
        a = _parse_ann_args(args)
        expr = a.get("value") or a.get("name")
        if expr:
            v = _eval_concat(expr, constants)
            if v is not None:
                return v
        return var_name

    map_vars: List[str] = []
    for decl in _split_top(params_sig or ""):
        anns, ptype, var = _split_param_decl(decl)
        if not var:
            continue
        names = {n for n, _ in anns}
        args_of = {n: a for n, a in anns}
        base_type = re.sub(r"<.*$", "", ptype).split(".")[-1].replace("[]", "")
        if "RequestParam" in names:
            if "Map" in base_type:
                map_vars.append(var)
            else:
                _add(_ann_name(args_of["RequestParam"], var))
        elif "PathVariable" in names:
            if "Map" not in base_type:
                _add(_ann_name(args_of["PathVariable"], var))
        elif "RequestHeader" in names:
            side.setdefault("header", []).append(_ann_name(args_of["RequestHeader"], var))  # type: ignore[union-attr]
        elif "CookieValue" in names:
            side.setdefault("cookie", []).append(_ann_name(args_of["CookieValue"], var))  # type: ignore[union-attr]
        elif "RequestBody" in names or "ModelAttribute" in names or (
            not names and base_type not in _SIMPLE_TYPES and base_type not in _INFRA_TYPES
            and "Map" not in base_type and base_type in (class_fields or {})
        ):
            fields = (class_fields or {}).get(base_type)
            if fields:
                for fname in fields:
                    _add(fname)
                side["body"] = "json" if "RequestBody" in names else side.get("body") or "form"
            elif "RequestBody" in names:
                side["body"] = "json"

    # Map<String,String> params: names read through map.get("x") / map.get(CONST)
    for mv in map_vars:
        for call in re.finditer(r'\b' + re.escape(mv) + r'\.get\s*\(\s*([A-Za-z0-9_.]+|"[^"]+")\s*\)', method_body):
            v = _eval_concat(call.group(1), constants)
            if v:
                _add(v)

    # queryParams.get(Constants.ID) / queryParams.get("id")
    for param_call in re.finditer(r'queryParams\.get\s*\(\s*([A-Za-z0-9_.]+|"[^"]+"|\'[^\']+\')\s*\)', method_body):
        raw_arg = param_call.group(1)
        if raw_arg.startswith(('"', "'")):
            _add(raw_arg.strip('"').strip("'"))
        else:
            v = _eval_concat(raw_arg, constants)
            if v:
                _add(v)

    # request.getParameter("...")
    for get_param_call in re.finditer(r'getParameter\s*\(\s*([A-Za-z0-9_.]+|"[^"]+"|\'[^\']+\')\s*\)', method_body):
        raw_arg = get_param_call.group(1)
        if raw_arg.startswith(('"', "'")):
            _add(raw_arg.strip('"').strip("'"))
        else:
            v = _eval_concat(raw_arg, constants)
            if v:
                _add(v)

    return extracted


def _resolve_constant_token(raw_token: str, constants: Dict[str, str], default_val: str = "") -> str:
    tok = raw_token.strip().strip('"').strip("'")
    if tok in constants:
        return constants[tok]
    short_tok = tok.split(".")[-1]
    if short_tok in constants:
        return constants[short_tok]
    return default_val or tok


_MAPPING_NAMES = ("VulnerableAppRequestMapping", "GetMapping", "PostMapping", "PutMapping", "DeleteMapping",
                  "PatchMapping", "RequestMapping")
_FIXED_VERB = {"GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT", "DeleteMapping": "DELETE",
               "PatchMapping": "PATCH"}
_MAPPING_RE = re.compile(r"@(" + "|".join(_MAPPING_NAMES) + r")\b")
_SIG_RE = re.compile(
    r"\s*(?:(?:public|protected|private|static|final|synchronized|abstract|default)\s+)*"
    r"(?:<[^>]*>\s*)?[\w<>\[\],\s\?\.]+?\s+([A-Za-z_]\w*)\s*\("
)


def _http_methods(args: Dict[str, str], ann_name: str, class_methods: List[str]) -> List[str]:
    if ann_name in _FIXED_VERB:
        return [_FIXED_VERB[ann_name]]
    found: List[str] = []
    for key in ("method", "requestMethod"):
        for m in re.finditer(r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b", args.get(key, "")):
            if m.group(1) not in found:
                found.append(m.group(1))
    return found or class_methods or ["GET"]


def _join_path(base: str, sub: str) -> str:
    b = base.strip("/")
    s = sub.strip("/")
    return "/" + "/".join(x for x in (b, s) if x)


def collect_class_fields(content: str) -> Dict[str, List[str]]:
    """DTO index for one file: class/record name -> instance field (component) names. Used for @RequestBody /
    @ModelAttribute binding."""
    out: Dict[str, List[str]] = {}
    for m in re.finditer(r"\brecord\s+([A-Z]\w*)\s*\(([^)]*)\)", content):
        names = []
        for decl in _split_top(m.group(2)):
            _, _t, var = _split_param_decl(decl)
            if var:
                names.append(var)
        if names:
            out[m.group(1)] = names
    for m in re.finditer(r"\bclass\s+([A-Z]\w*)\b[^{;]*\{", content):
        depth, i = 1, m.end()
        while i < len(content) and depth:
            depth += {"{": 1, "}": -1}.get(content[i], 0)
            i += 1
        body = content[m.end():i - 1]
        flat = []
        d = 0
        for ch in body:  # keep only depth-0 text (field declarations), drop method bodies
            if ch == "{":
                d += 1
            elif ch == "}":
                d -= 1
            elif d == 0:
                flat.append(ch)
        names = []
        for fm in re.finditer(
            r"(?:(?:private|protected|public)\s+)?(?:final\s+)?[\w<>\[\],.? ]+?\s+([a-z_]\w*)\s*(?:=[^;]*)?;",
            "".join(flat),
        ):
            decl = fm.group(0)
            if re.search(r"\bstatic\b", decl) or "(" in decl.split("=")[0]:
                continue
            names.append(fm.group(1))
        if names:
            out.setdefault(m.group(1), names)
    return out


def parse_java_file(
    file_path: str,
    project_root: str,
    global_constants: Optional[Dict[str, str]] = None,
    class_fields: Optional[Dict[str, List[str]]] = None,
    consts_by_class: Optional[Dict[str, Dict[str, str]]] = None,
) -> Tuple[JavaClassInfo, List[RouteEntry]]:
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    lines = content.splitlines()
    total_lines = len(lines)
    rel_path = os.path.relpath(file_path, project_root).replace("\\", "/")

    pkg_match = re.search(r"package\s+([A-Za-z0-9_.]+);", content)
    pkg_name = pkg_match.group(1) if pkg_match else ""

    cls_match = re.search(r"public\s+(?:abstract\s+|final\s+)?(?:class|interface)\s+([A-Za-z0-9_]+)", content)
    if not cls_match:
        cls_match = re.search(r"(?:class|interface)\s+([A-Za-z0-9_]+)", content)
    class_name = cls_match.group(1) if cls_match else Path(file_path).stem

    class_info = JavaClassInfo(rel_path, class_name, pkg_name)
    # Constants visible here: everything known repo-wide, static imports, then this file's own declarations.
    scope: Dict[str, str] = dict(global_constants or {})
    for sm in re.finditer(r"^\s*import\s+static\s+([\w.]+?)\.(\w+|\*)\s*;", content, re.MULTILINE):
        owner = sm.group(1).split(".")[-1]
        for k, v in (consts_by_class or {}).get(owner, {}).items():
            if "." in k:
                continue
            if sm.group(2) in ("*", k):
                scope[k] = v
    scope.update(extract_constants(content, class_name=class_name, known=scope))
    class_info.constants = scope
    class_info.methods, class_info.method_defs = extract_method_defs(lines, class_info.constants)

    # Injected @Service / Validator / Helper beans (supports `private final AuthLoginService authLoginService;`)
    for match in re.finditer(
        r"(?:private|protected|public)?\s*(?:final\s+)?([A-Z][A-Za-z0-9_]*(?:Service|Validator|Helper|Repository))\s+([A-Za-z0-9_]+)\s*;",
        content,
    ):
        class_info.injected_services[match.group(2)] = match.group(1)

    # ---- class-level mapping: @RequestMapping / @VulnerableAppRestController (value/path, arrays, method=)
    cls_pos = cls_match.start() if cls_match else len(content)
    header_content = content[:cls_pos]
    base_paths: List[str] = []
    class_methods: List[str] = []
    for hm in re.finditer(r"@(RequestMapping|VulnerableAppRestController)\b\s*(\()?", header_content):
        args: Dict[str, str] = {}
        if hm.group(2):
            end = _balanced_end(header_content, hm.end() - 1)
            if end > 0:
                args = _parse_ann_args(header_content[hm.end():end])
        vals = _eval_values(args.get("value") or args.get("path"), class_info.constants)
        for v in vals:
            p = "/" + v.strip("/") if v.strip("/") else ""
            if p and p not in base_paths:
                base_paths.append(p)
        if hm.group(1) == "RequestMapping" and "method" in args:
            class_methods = _http_methods(args, "RequestMapping", [])
    if not base_paths:
        base_paths = [""]
    class_info.base_paths = base_paths
    routes: List[RouteEntry] = []

    # ---- handler methods: any mapping annotation followed (after more annotations) by a method signature
    for mm in _MAPPING_RE.finditer(content, cls_pos):
        ann_name = mm.group(1)
        pos = mm.end()
        arg_text = ""
        if re.match(r"\s*\(", content[pos:pos + 40]):
            open_idx = content.index("(", pos)
            end = _balanced_end(content, open_idx)
            if end < 0:
                continue
            arg_text = content[open_idx + 1:end]
            pos = end + 1
        ann_text = content[mm.start():pos]
        between_start = pos
        # skip any further annotations stacked between the mapping and the signature
        while True:
            am = re.match(r"\s*@([\w.]+)", content[pos:])
            if not am:
                break
            pos += am.end()
            if re.match(r"\s*\(", content[pos:pos + 40]):
                end = _balanced_end(content, content.index("(", pos))
                if end < 0:
                    break
                pos = end + 1
        between = content[between_start:pos]
        sm = _SIG_RE.match(content, pos)
        if not sm:
            continue
        sig_head = content[pos:sm.end()]
        if re.search(r"\b(class|interface|enum|record|new)\b", sig_head):
            continue
        handler_name = sm.group(1)
        p_open = sm.end() - 1
        p_end = _balanced_end(content, p_open)
        if p_end < 0:
            continue
        params_sig = content[p_open + 1:p_end]
        if not re.match(r"\s*(?:throws\s+[\w,.\s]+)?\s*\{", content[p_end + 1:]):
            continue
        ann_line_no = content.count("\n", 0, mm.start()) + 1
        handler_line_no = content.count("\n", 0, sm.start(1)) + 1

        method_range = (handler_line_no, min(handler_line_no + 35, total_lines))
        for m_start, m_end, _, _ in class_info.method_defs.get(handler_name, []):
            if abs(m_start - handler_line_no) <= 4:
                method_range = (m_start, m_end)
                break

        args = _parse_ann_args(arg_text)
        http_methods = _http_methods(args, ann_name, class_methods)
        subpaths = _eval_values(args.get("value") or args.get("path"), class_info.constants) or [""]

        start_idx = max(0, method_range[0] - 1)
        end_idx = min(total_lines, method_range[1])
        method_body = "\n".join(lines[start_idx:end_idx])

        side: Dict[str, object] = {}
        extracted_params = _extract_params_from_sig_and_body(params_sig, method_body, class_info.constants,
                                                             class_fields, side)
        if not extracted_params and "HttpServletRequest" in params_sig and "getInputStream" in method_body:
            extracted_params = ["xml_body"]
        ROUTE_INPUTS[(rel_path, method_range[0])] = side

        called_helpers = extract_called_methods(method_body)

        # Look above the mapping annotation (up to 35 lines, stopping at previous method closing brace `}`)
        # for @AttackVector & Variant.SECURE
        pre_lines: List[str] = []
        for back_idx in range(ann_line_no - 2, max(-1, ann_line_no - 38), -1):
            if 0 <= back_idx < total_lines:
                prev_l = lines[back_idx]
                if prev_l.strip() == "}":
                    break
                pre_lines.append(prev_l)
        pre_ann = "\n".join(reversed(pre_lines)) + "\n" + ann_text + "\n" + between

        is_secure = "Variant.SECURE" in pre_ann
        vuln_tag = None
        av_match = re.search(r"vulnerabilityExposed\s*=\s*\{?\s*VulnerabilityType\.([A-Za-z0-9_]+)", pre_ann)
        if av_match:
            vuln_tag = av_match.group(1)

        seen_urls = set()
        for bp in base_paths:
            for sp in subpaths:
                full_url = _join_path(bp, sp)
                for verb in http_methods:
                    if (full_url, verb) in seen_urls:
                        continue
                    seen_urls.add((full_url, verb))
                    routes.append(
                        RouteEntry(
                            http_method=verb,
                            url_pattern=full_url,
                            handler_name=handler_name,
                            class_name=class_name,
                            file_path=rel_path,
                            start_line=method_range[0],
                            end_line=method_range[1],
                            params=list(extracted_params),
                            called_helpers=list(called_helpers),
                            is_secure_variant=is_secure,
                            vulnerability_type_tag=vuln_tag,
                        )
                    )

    return class_info, routes


def get_route_inputs(route: RouteEntry) -> Dict[str, object]:
    """Header / cookie names and body encoding ("json"/"form"/None) recorded for a parsed route."""
    return ROUTE_INPUTS.get((route.file_path, route.start_line), {})


def extract_java_routes(source_root: str) -> List[RouteEntry]:
    """Scan entire directory for Java files and resolve bounded 3-hop inter-procedural route call graphs."""
    all_routes: List[RouteEntry] = []
    classes_by_name: Dict[str, JavaClassInfo] = {}

    java_files: List[str] = []
    for root, _, files in os.walk(source_root):
        if "/src/test/" in root.replace("\\", "/"):
            continue
        for file in files:
            if file.endswith(".java"):
                java_files.append(os.path.join(root, file))

    # Pass 0: repo-wide constant table (qualified Class.NAME and unambiguous bare NAME) and DTO field index.
    consts_by_class: Dict[str, Dict[str, str]] = {}
    bare_seen: Dict[str, Set[str]] = {}
    class_fields: Dict[str, List[str]] = {}
    for fp in java_files:
        try:
            text = open(fp, "r", encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        cm = re.search(r"(?:class|interface|enum)\s+([A-Za-z0-9_]+)", text)
        cname = cm.group(1) if cm else Path(fp).stem
        consts = extract_constants(text, class_name=cname)
        consts_by_class.setdefault(cname, {}).update(consts)
        for k, v in consts.items():
            if "." not in k:
                bare_seen.setdefault(k, set()).add(v)
        for k, v in collect_class_fields(text).items():
            class_fields.setdefault(k, v)
    global_constants: Dict[str, str] = {}
    for consts in consts_by_class.values():
        for k, v in consts.items():
            if "." in k:
                global_constants[k] = v
    for k, vals in bare_seen.items():
        if len(vals) == 1:
            global_constants[k] = next(iter(vals))

    for full_path in java_files:
        try:
            cls_info, routes = parse_java_file(full_path, source_root, global_constants, class_fields, consts_by_class)
            classes_by_name[cls_info.class_name] = cls_info
            all_routes.extend(routes)
        except Exception:
            pass


    # Pass 2: Bounded 3-Hop Transitive Inter-Procedural Call-Graph Closure
    # Resolves:
    #   Hop 1: Controller.handler() -> this.helper() OR injectedService.method()
    #   Hop 2: helper1() -> helper2() (including Java method overloads!) OR helper() -> injectedService.method()
    #   Hop 3: serviceMethod() -> internalServiceHelper()
    MAX_HOPS = 3
    for r in all_routes:
        root_cls = classes_by_name.get(r.class_name)
        if not root_cls:
            continue

        resolved_edges: List[str] = []
        visited_spans: Set[Tuple[str, int, int]] = {(r.file_path, r.start_line, r.end_line)}
        discovered_params: List[str] = list(r.params)

        # Queue items: (curr_class_info, curr_called_names, hop_depth, chain_prefix, is_di_hop)
        queue: deque[Tuple[JavaClassInfo, List[str], int, str, bool]] = deque()
        queue.append(
            (
                root_cls,
                list(r.called_helpers),
                1,
                f"{r.class_name}.{r.handler_name}()[L{r.start_line}]",
                False,
            )
        )

        while queue:
            curr_cls, called_names, depth, chain_prefix, via_di = queue.popleft()
            if depth > MAX_HOPS:
                continue

            for callee_name in called_names:
                # A) Intra-class helper overloads
                if callee_name in curr_cls.method_defs:
                    for m_start, m_end, next_calls, helper_params in curr_cls.method_defs[callee_name]:
                        span_key = (curr_cls.file_path, m_start, m_end)
                        if span_key in visited_spans:
                            continue
                        visited_spans.add(span_key)

                        for hp in helper_params:
                            if hp not in discovered_params:
                                discovered_params.append(hp)

                        hop_kind = "DI" if via_di else "AST"
                        new_chain = f"{chain_prefix} -> {curr_cls.class_name}.{callee_name}()[L{m_start}]"
                        resolved_edges.append(
                            f"hop={depth}|kind={hop_kind}|{curr_cls.file_path}:{m_start}-{m_end}|{new_chain}"
                        )
                        if depth < MAX_HOPS and next_calls:
                            queue.append((curr_cls, next_calls, depth + 1, new_chain, via_di))

                # B) Cross-class @Autowired / Constructor-Injected @Service or Validator beans
                for field_name, s_class_name in curr_cls.injected_services.items():
                    s_info = classes_by_name.get(s_class_name)
                    if s_info and callee_name in s_info.method_defs:
                        for m_start, m_end, next_calls, svc_params in s_info.method_defs[callee_name]:
                            span_key = (s_info.file_path, m_start, m_end)
                            if span_key in visited_spans:
                                continue
                            visited_spans.add(span_key)

                            for sp in svc_params:
                                if sp not in discovered_params:
                                    discovered_params.append(sp)

                            eff_hop = max(2, depth)  # Cross-bean DI hop is at least 2-tier architectural hop
                            new_chain = f"{chain_prefix} -[@Service:{field_name}]-> {s_class_name}.{callee_name}()[L{m_start}]"
                            resolved_edges.append(
                                f"hop={eff_hop}|kind=DI|{s_info.file_path}:{m_start}-{m_end}|{new_chain}"
                            )
                            if depth < MAX_HOPS and next_calls:
                                queue.append((s_info, next_calls, depth + 1, new_chain, True))

        r.called_helpers = resolved_edges
        r.params = discovered_params

    return all_routes
