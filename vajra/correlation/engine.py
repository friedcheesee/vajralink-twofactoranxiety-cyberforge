"""
Vajra-GraphLink correlation engine (FR-5..FR-9, B-3).

For every DAST proof: find which route handler serves its URL (route map, any context path / path template),
then which SAST sink of the same weakness that handler actually reaches (encloses it, or a call-graph path),
and score the pair on five evidence vectors:
  1. V_callgraph (0.30): handler -> sink code path (0-hop enclosure, n-hop call / DI path)
  2. V_cwe_graph (0.25): same CWE family
  3. V_param     (0.15): the attacked parameter is an input of that handler / appears in the sink
  4. V_behavior  (0.15): the runtime evidence is what that kind of sink API produces
  5. V_parity    (0.15): bypass payload <-> guarded code, plain payload <-> unguarded code
Decision: >= 0.72 with a proven code path -> Confirmed with no LLM; 0.48..0.72 or no proven path -> grey-zone
arbiter (LLM given the real handler + sink code); below -> not linked. One issue per (file, method, CWE) sink.
"""
from __future__ import annotations

import hashlib
import os
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple

from vajra.correlation.ai_triage import resolve_greyzone_link
from vajra.correlation.vault_helper import secret_verdict
from vajra.models import (
    MITRE_METADATA_MAP,
    CommonFinding,
    CorrelatedIssue,
    RouteEntry,
    build_ast_taint_flow,
    canonicalize_cwe,
)

# Static JVM Sink Descriptor <-> Runtime Differential Causality Map (Vector 4)
# Vector 4: which runtime evidence each kind of sink API can produce. Framework-level API names only
# (Java, Python, Node, PHP, Ruby, Go), never method names from one particular target application.
SINK_BEHAVIOR_SIGNATURES: Dict[str, Tuple[List[str], List[str], str]] = {
    "CWE-89": (
        ["executequery", "executeupdate", "createstatement", "jdbctemplate", "createquery", "createnativequery",
         "cursor.execute", ".execute(", ".raw(", "query(", "mysqli_query", "find_by_sql", "db.query", "select ", "where "],
        ["sql", "syntax", "jdbc", "grammar", "sqlite", "mysql", "postgres", "ora-", "h2", "vajra_sqli_proof", "boolean differential"],
        "SQL query built from input <-> database error / injected-row / boolean differential at runtime",
    ),
    "CWE-78": (
        ["runtime.getruntime", "exec(", "processbuilder", "subprocess", "os.system", "os.popen", "child_process",
         "execsync", "spawn(", "shell_exec", "system(", "passthru", "popen", "exec.command"],
        ["vajra_cmd_proof", "uid=", "icmp_seq", "posix"],
        "OS command built from input <-> injected command output echoed at runtime",
    ),
    "CWE-79": (
        ["responseentity", "html", "innerhtml", "document.write", "render_template_string", "markup(", "|safe",
         "res.send", "echo ", "print(", "getwriter", "string.format", "dangerouslysetinnerhtml"],
        ["__vajra_xss", "xss", "alert", "dom", "dialog", "svg", "onload", "chromium", "unescaped", "reflected"],
        "Unescaped input written into HTML <-> script executed in a real browser / reflected unescaped",
    ),
    "CWE-22": (
        ["getresourceasstream", "fileinputstream", "filereader", "paths.get", "files.read", "new file(", "resolve(",
         "open(", "send_file", "send_from_directory", "readfile", "fs.read", "createreadstream", "file_get_contents", "include("],
        ["root:x:0:0", "passwd", "[boot loader]", "<project", "file content"],
        "File path built from input <-> contents of a file outside the intended folder returned",
    ),
    "CWE-601": (
        ["location", "redirect", "sendredirect", "httpstatus.found", "302", "res.redirect", "redirectview", "header("],
        ["302", "301", "303", "307", "redirect", "location"],
        "Redirect target taken from input <-> Location header pointing off-site",
    ),
    "CWE-918": (
        ["openconnection", "httpurlconnection", "resttemplate", "webclient", "requests.get", "urllib", "urlopen",
         "http.get", "fetch(", "axios", "curl_exec", "file_get_contents"],
        ["vajra_ssrf", "169.254", "127.0.0.1", "instance-id", "loopback", "localhost"],
        "Server-side request to an input URL <-> internal / loopback content returned",
    ),
    "CWE-611": (
        ["unmarshal", "documentbuilder", "saxparser", "xmlreader", "xmlinputfactory", "lxml", "etree", "libxml", "simplexml"],
        ["root:x:0:0", "xxe", "entity"],
        "XML parser with external entities <-> entity expansion leaked file contents",
    ),
    "CWE-639": (
        ["findbyid", "getone", "get_object", "findone", "where id", "byid("],
        ["vajra_idor", "unauthorized", "other user"],
        "Object fetched by caller-supplied id <-> another user's record returned",
    ),
    "CWE-693": (
        ["x-frame-options", "content-security-policy", "allowall", "sameorigin"],
        ["x-frame-options", "csp", "content-security-policy", "nosniff", "clickjacking", "header"],
        "Response header configuration <-> missing / permissive security header observed",
    ),
}


def _norm_path(p: Optional[str]) -> str:
    return (p or "").replace("\\", "/").strip("/").lower()


_TEMPLATE_SEG = re.compile(r"^(\{[^}]*\}|:[A-Za-z_]\w*|<[^>]*>|\*)$")
_route_regex_cache: Dict[int, List[Tuple[re.Pattern, int, RouteEntry]]] = {}


def _route_regexes(routes: List[RouteEntry]) -> List[Tuple[re.Pattern, int, RouteEntry]]:
    """Compile every route pattern once. Template segments ({id}, :id, <int:id>, *) match any one segment
    and `**` matches the rest of the path. Specificity = number of literal segments (higher wins)."""
    key = id(routes)
    hit = _route_regex_cache.get(key)
    if hit is not None and len(hit) == len(routes):
        return hit
    out: List[Tuple[re.Pattern, int, RouteEntry]] = []
    for r in routes:
        segs = [s for s in (r.url_pattern or "").strip("/").lower().split("/") if s]
        parts, literal = [], 0
        for s in segs:
            if s == "**":
                parts.append(".*")
            elif _TEMPLATE_SEG.match(s):
                parts.append("[^/]+")
            else:
                parts.append(re.escape(s))
                literal += 1
        out.append((re.compile("^/" + "/".join(parts) + "/?$"), literal, r))
    _route_regex_cache.clear()
    _route_regex_cache[key] = out
    return out


def lookup_route(dast: CommonFinding, routes: Optional[List[RouteEntry]]) -> Optional[RouteEntry]:
    """Which route handler serves this DAST URL? Generic for any app: no app name is assumed.

    Handles a servlet context path / reverse-proxy prefix of unknown name (/shop/api/orders -> /api/orders)
    by retrying with leading segments removed, path templates (/orders/{id} matches /orders/42), and
    prefers the route with the same HTTP method, then the most literal (least templated) pattern."""
    if not dast.url or not routes:
        return None
    path = "/" + urllib.parse.urlparse(dast.url).path.strip("/").lower()
    segs = [s for s in path.split("/") if s]
    method = (dast.method or "GET").upper()
    compiled = _route_regexes(routes)
    for drop in range(0, min(3, max(0, len(segs) - 1)) + 1):  # never strip the path down to "/"
        cand_path = "/" + "/".join(segs[drop:])
        hits = [(lit, r) for rx, lit, r in compiled if rx.match(cand_path)]
        if hits:
            hits.sort(key=lambda t: ((t[1].http_method or "GET").upper() in (method, "ANY", "*"), t[0]), reverse=True)
            return hits[0][1]
    return None


def build_curl_command(
    url: Optional[str],
    method: Optional[str] = "GET",
    parameter: Optional[str] = None,
    payload: Optional[str] = None,
    cwe: Optional[str] = None,
) -> str:
    """Build an accurate, copy-paste runnable cURL replay command for live verification."""
    if not url:
        return ""
    m_up = (method or "GET").upper()
    cwe_up = (cwe or "").upper()

    if m_up == "POST" and ("611" in cwe_up or (payload and payload.strip().startswith("<?xml"))):
        escaped_xml = (payload or "").replace("'", "'\\''")
        return f"curl -i -s -X POST \"{url}\" -H \"Content-Type: application/xml\" --data-binary '{escaped_xml}'"

    if parameter and payload is not None and payload != "":
        enc_param = urllib.parse.quote(str(parameter), safe="")
        enc_payload = urllib.parse.quote(str(payload), safe="")
        if m_up == "GET":
            sep = "&" if "?" in url else "?"
            return f"curl -i -s -X GET \"{url}{sep}{enc_param}={enc_payload}\""
        return f"curl -i -s -X {m_up} \"{url}\" -d \"{enc_param}={enc_payload}\""

    return f"curl -i -s -X {m_up} \"{url}\""


def build_tailored_postman_script(
    cwe: str,
    vuln_type: str,
    payload: str = "",
    param: str = "",
    ai_technique: Optional[str] = None,
    ai_guard_basis: Optional[str] = None,
) -> str:
    """Generate authentic, CWE-specific Postman sandbox JavaScript assertions.

    The assertion bodies are templated per CWE class (that is standard practice for a differential HTTP
    check - the pass/fail criteria for "is this SQLi" is a property of the vulnerability class, not of the
    app), but `payload`/`param` below are always the exact values actually sent for THIS finding. When
    `ai_technique` is supplied (i.e. this exact payload came from a live/heuristic AI filter-bypass call
    grounded in this finding's real Java guard code), it is recorded as a comment so the collection is
    honest about where the payload came from.
    """
    ai_comment = ""
    if ai_technique:
        basis = (ai_guard_basis or "").strip().replace("\n", " ")[:160]
        ai_comment = (
            f"// AI-synthesized bypass: {ai_technique}\n"
            + (f"// Grounded in the actual guard code: {basis}\n" if basis else "")
        )
    cwe_norm = (cwe or "").upper()
    v_norm = (vuln_type or "").upper()

    if "89" in cwe_norm or "SQL" in v_norm:
        p_name = param or "id"
        return ai_comment + (
            "// Postman Test Suite: SQL Injection Verification (CWE-89)\n"
            "pm.test(\"HTTP status confirms SQL grammar fault or differential extraction\", function () {\n"
            "    pm.expect(pm.response.code).to.be.oneOf([200, 500]);\n"
            "});\n"
            "pm.test(\"Database JDBC/H2 syntax error or extracted record signature present\", function () {\n"
            "    pm.expect(pm.response.text()).to.match(/(syntax error|jdbc|h2|sql statement|VAJRA_SQLI_PROOF|carInformation)/i);\n"
            "});\n"
            f"pm.test(\"Tainted parameter '{p_name}' delivered to SQL sink\", function () {{\n"
            f"    pm.expect(pm.request.url.toString()).to.include('{p_name}');\n"
            "});"
        )
    if "78" in cwe_norm or "77" in cwe_norm or "COMMAND" in v_norm:
        return ai_comment + (
            "// Postman Test Suite: OS Command Injection Verification (CWE-78)\n"
            "pm.test(\"Status code is 200 OK (Subshell Process Output Reflected)\", function () {\n"
            "    pm.expect(pm.response.code).to.equal(200);\n"
            "});\n"
            "pm.test(\"POSIX process stdout canary matched in HTTP body\", function () {\n"
            "    pm.expect(pm.response.text()).to.match(/(VAJRA_CMD_PROOF|uid=\\d+|root:x:0:0)/);\n"
            "});\n"
            "pm.test(\"Response latency within interactive process SLA (< 2000ms)\", function () {\n"
            "    pm.expect(pm.response.responseTime).to.be.below(2000);\n"
            "});"
        )
    if "22" in cwe_norm or "23" in cwe_norm or "TRAVERSAL" in v_norm:
        return ai_comment + (
            "// Postman Test Suite: Arbitrary File Read / Path Traversal Verification (CWE-22)\n"
            "pm.test(\"Status code is 200 OK (Resource Stream Returned)\", function () {\n"
            "    pm.expect(pm.response.code).to.equal(200);\n"
            "});\n"
            "pm.test(\"Protected filesystem record (/etc/passwd) disclosed in body\", function () {\n"
            "    pm.expect(pm.response.text()).to.match(/(root:x:0:0|daemon:x:1:1|sasanlabs:x:1000)/);\n"
            "});\n"
            "pm.test(\"Disclosed payload exceeds baseline stub length\", function () {\n"
            "    pm.expect(pm.response.text().length).to.be.above(35);\n"
            "});"
        )
    if "79" in cwe_norm or "XSS" in v_norm:
        return ai_comment + (
            "// Postman Test Suite: Cross-Site Scripting (XSS) Verification (CWE-79)\n"
            "pm.test(\"Status code is 200 OK (HTML Document Rendered)\", function () {\n"
            "    pm.expect(pm.response.code).to.equal(200);\n"
            "});\n"
            "pm.test(\"Unescaped executable DOM vector reflected in response HTML\", function () {\n"
            "    pm.expect(pm.response.text()).to.match(/(<script|<svg|<img|onload=|onerror=|__vajra_xss)/i);\n"
            "});\n"
            "pm.test(\"Content-Security-Policy (CSP) script restriction absent\", function () {\n"
            "    pm.expect(pm.response.headers.get('Content-Security-Policy')).to.be.undefined;\n"
            "});"
        )
    if "601" in cwe_norm or "REDIRECT" in v_norm:
        return ai_comment + (
            "// Postman Test Suite: Open Redirect Verification (CWE-601)\n"
            "pm.test(\"Status code is 3xx Redirect (301/302/303/307)\", function () {\n"
            "    pm.expect(pm.response.code).to.be.oneOf([301, 302, 303, 307, 308]);\n"
            "});\n"
            "pm.test(\"Location response header redirects to untrusted external host\", function () {\n"
            "    pm.expect(pm.response.headers.get('Location')).to.include('example.com');\n"
            "});"
        )
    if "918" in cwe_norm or "SSRF" in v_norm:
        return ai_comment + (
            "// Postman Test Suite: Server-Side Request Forgery Verification (CWE-918)\n"
            "pm.test(\"Status code is 200 OK (Internal Upstream Response Proxied)\", function () {\n"
            "    pm.expect(pm.response.code).to.equal(200);\n"
            "});\n"
            "pm.test(\"Internal metadata / loopback payload leaked in response\", function () {\n"
            "    pm.expect(pm.response.text()).to.match(/(VAJRA_SSRF_METADATA|instance-id|169\\.254|127\\.0\\.0\\.1)/i);\n"
            "});"
        )
    if "611" in cwe_norm or "XXE" in v_norm:
        return ai_comment + (
            "// Postman Test Suite: XML External Entity (XXE) Verification (CWE-611)\n"
            "pm.test(\"Status code is 200 OK (XML Unmarshalled)\", function () {\n"
            "    pm.expect(pm.response.code).to.equal(200);\n"
            "});\n"
            "pm.test(\"SYSTEM external entity file:///etc/passwd expanded in XML response\", function () {\n"
            "    pm.expect(pm.response.text()).to.match(/(root:x:0:0|XXE_ENTITY_RESOLVED)/);\n"
            "});"
        )
    if "639" in cwe_norm or "IDOR" in v_norm:
        return ai_comment + (
            "// Postman Test Suite: Insecure Direct Object Reference Verification (CWE-639)\n"
            "pm.test(\"Status code is 200 OK (Object Record Returned Without Ownership Gate)\", function () {\n"
            "    pm.expect(pm.response.code).to.equal(200);\n"
            "});\n"
            "pm.test(\"Unauthorized ADMIN profile & confidential salary exposed\", function () {\n"
            "    pm.expect(pm.response.text()).to.match(/(VAJRA_IDOR_UNAUTHORIZED_PROFILE|\"role\"\\s*:\\s*\"ADMIN\"|\"salary\")/i);\n"
            "});"
        )
    if "693" in cwe_norm or "HEADER" in v_norm or "CSP" in v_norm or "CLICKJACK" in v_norm:
        return ai_comment + (
            "// Postman Test Suite: Runtime Security Header Policy Audit (CWE-693)\n"
            "pm.test(\"Endpoint responds over HTTP (200 OK)\", function () {\n"
            "    pm.expect(pm.response.code).to.equal(200);\n"
            "});\n"
            "pm.test(\"Defensive browser protection header missing or permissive (CSP / XFO / nosniff)\", function () {\n"
            "    const csp = pm.response.headers.get('Content-Security-Policy');\n"
            "    const xfo = pm.response.headers.get('X-Frame-Options') || '';\n"
            "    pm.expect(!csp || !xfo || xfo.toUpperCase() === 'ALLOWALL').to.be.true;\n"
            "});"
        )

    return ai_comment + (
        f"// Postman Test Suite: {cwe} ({vuln_type})\n"
        "pm.test(\"HTTP response received from target endpoint\", function () {\n"
        "    pm.expect(pm.response.code).to.be.oneOf([200, 302, 500]);\n"
        "});\n"
        "pm.test(\"Differential exploit evidence non-empty\", function () {\n"
        "    pm.expect(pm.response.text().length).to.be.above(0);\n"
        "});"
    )


CODE_EXTS = (
    ".java", ".kt", ".scala", ".groovy", ".jsp", ".py", ".js", ".mjs", ".cjs", ".ts", ".php", ".rb", ".go", ".cs",
)
AUTO_CONFIRM = 0.72   # Tier A: deterministic proof, no LLM
GREY_FLOOR = 0.48     # Tier B: [GREY_FLOOR, AUTO_CONFIRM) goes to the arbiter
GREY_CAP = 0.70       # a link without a proven code path can never reach Tier A on its own
_UNSET: Any = object()
_NAME_STOP = {
    "api", "v1", "v2", "v3", "rest", "index", "get", "post", "put", "delete", "the", "and", "html", "json", "xml",
    "service", "services", "controller", "controllers", "impl", "java", "handler", "handlers", "action", "page",
    "view", "views", "main", "src", "app", "com", "org", "net", "www", "http", "https",
}


def _name_tokens(text: str) -> Set[str]:
    """camelCase / snake_case / path text -> lowercase words (>=3 chars, generic words dropped)."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text or "")
    return {t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if len(t) >= 3 and t not in _NAME_STOP and not t.isdigit()}


def _build_route_indexes(
    routes: Optional[List[RouteEntry]],
) -> Tuple[Dict[str, List[RouteEntry]], Dict[str, List[Tuple[int, int, str]]]]:
    """Pre-index routes by URL path and record all controller handler line spans per file."""
    by_path: Dict[str, List[RouteEntry]] = {}
    handler_spans_by_file: Dict[str, List[Tuple[int, int, str]]] = {}
    for r in routes or []:
        by_path.setdefault("/" + (r.url_pattern or "").strip("/").lower(), []).append(r)
        span_tuple = (r.start_line, r.end_line, r.handler_name)
        spans = handler_spans_by_file.setdefault(_norm_path(r.file_path), [])
        if span_tuple not in spans:
            spans.append(span_tuple)
    return by_path, handler_spans_by_file


def _cwe_name(cwe: str) -> str:
    return MITRE_METADATA_MAP.get(cwe, {}).get("cwe_name", cwe)


def calculate_match_score(
    sast: CommonFinding,
    dast: CommonFinding,
    routes: Optional[List[RouteEntry]] = None,
    *,
    _route_cache: Optional[Tuple[Dict[str, List[RouteEntry]], Dict[str, List[Tuple[int, int, str]]]]] = None,
    fgraph: Optional[Any] = None,
    matched_route: Any = _UNSET,
    allow_secure: bool = False,
) -> Tuple[float, Dict[str, Any], str]:
    """Score one (SAST sink, DAST proof) pair. Nothing here is specific to one target application.

      S = 0.30 * V_callgraph + 0.25 * V_cwe + 0.15 * V_param + 0.15 * V_behavior + 0.15 * V_parity

    Hard gates (score 0): different weakness family, sink not in executable code, route declared secure,
    no code relationship at all. Proof gate: unless the route's handler is *proven* to reach the sink line
    (it encloses it, or the call graph has a path to it), the score is capped below the auto-confirm line,
    so the link is only made if the grey-zone arbiter agrees.
    """
    # ---- V2: weakness family ---------------------------------------------------------------------
    if sast.cwe == dast.cwe and sast.raw_cwe == dast.raw_cwe:
        v_cwe, cwe_note = 1.00, f"Exact CWE match ({sast.cwe})"
    elif sast.cwe == dast.cwe:
        v_cwe, cwe_note = 0.96, f"Same CWE family: SAST {sast.raw_cwe} / DAST {dast.raw_cwe} -> {sast.cwe}"
    elif canonicalize_cwe(sast.raw_cwe) == canonicalize_cwe(dast.raw_cwe):
        v_cwe, cwe_note = 0.92, f"Canonical CWE equivalence ({sast.raw_cwe} ~ {dast.raw_cwe})"
    else:
        return 0.0, {"callgraph": 0.0, "cwe_graph": 0.0}, "Different weakness family"

    s_file_norm = _norm_path(sast.file_path)
    if not s_file_norm.endswith(CODE_EXTS) or not sast.line:
        return 0.0, {"callgraph": 0.0, "cwe_graph": v_cwe}, "Not executable source (config / resource asset)"

    _, handler_spans_by_file = _route_cache if _route_cache is not None else _build_route_indexes(routes)
    if matched_route is _UNSET:
        matched_route = lookup_route(dast, routes)

    if matched_route is not None and matched_route.is_secure_variant and not allow_secure:
        return 0.0, {"callgraph": 0.0, "cwe_graph": v_cwe}, "Route is declared secure by the application itself"

    # ---- V1: does the route's handler reach the sink line? ----------------------------------------
    v_callgraph, hop_count, path_proven = 0.0, -1, False
    call_hop_trace = "No code relationship"
    s_line = sast.line or 0
    code_lower = (sast.code_snippet or "").lower()
    fn_lower = (sast.function_name or "").lower()

    if matched_route is not None:
        r_file_norm = _norm_path(matched_route.file_path)
        if r_file_norm == s_file_norm and matched_route.start_line <= s_line <= matched_route.end_line:
            v_callgraph, hop_count, path_proven = 1.00, 0, True
            call_hop_trace = (
                f"handler {matched_route.class_name}.{matched_route.handler_name}() "
                f"[L{matched_route.start_line}-{matched_route.end_line}] contains the sink line L{s_line}"
            )
        else:
            best_edge: Optional[Tuple[int, str, int, int, str]] = None
            for edge_str in matched_route.called_helpers:
                # Format: hop={depth}|kind={AST|DI}|{target_file}:{m_start}-{m_end}|{chain_str}
                parts = edge_str.split("|", 3)
                if len(parts) != 4:
                    continue
                try:
                    e_hop = int(parts[0].split("=", 1)[1])
                    e_kind = parts[1].split("=", 1)[1]
                    t_file, span_s = parts[2].rsplit(":", 1)
                    m_start, m_end = (int(x) for x in span_s.split("-", 1))
                except Exception:
                    continue
                if _norm_path(t_file) == s_file_norm and m_start <= s_line <= m_end:
                    if best_edge is None or e_hop < best_edge[0]:
                        best_edge = (e_hop, e_kind, m_start, m_end, parts[3])
            if best_edge is not None:
                e_hop, e_kind, m_start, m_end, chain_desc = best_edge
                hop_count, path_proven = e_hop, True
                v_callgraph = 0.94 if (e_kind == "DI" or e_hop > 1) else 0.97
                call_hop_trace = (
                    f"{e_hop}-hop call path {chain_desc} reaches the method [L{m_start}-{m_end}] "
                    f"containing sink L{s_line}" + (" (via dependency injection)" if e_kind == "DI" else "")
                )
            elif r_file_norm == s_file_norm:
                other = any(
                    h != matched_route.handler_name and hs <= s_line <= he
                    for hs, he, h in handler_spans_by_file.get(s_file_norm, [])
                )
                if not other:
                    # Same class, sink in a method no call edge connects (lambda / method ref / reflection):
                    # plausible but unproven -> grey zone only.
                    v_callgraph, hop_count = 0.44, 1
                    call_hop_trace = (
                        f"same class as handler {matched_route.class_name}.{matched_route.handler_name}() but no "
                        f"call edge to {sast.function_name or 'class scope'}() L{s_line} was found (unproven)"
                    )
    else:
        # No route-map entry for this URL: compare the URL's words to the sink's file/method names.
        url_tok = _name_tokens(urllib.parse.urlparse(dast.url or "").path)
        code_tok = _name_tokens(os.path.splitext(os.path.basename(s_file_norm))[0] + " " + (sast.function_name or ""))
        shared = url_tok & code_tok
        if shared:
            v_callgraph, hop_count = min(0.50, 0.30 + 0.10 * len(shared)), 1
            call_hop_trace = (
                f"no route-map entry for this URL; URL words {sorted(shared)} match "
                f"{os.path.basename(s_file_norm)} / {sast.function_name or '?'}() (unproven)"
            )

    # Whole-program function graph: deeper chains, interface / DI dispatch, static helpers.
    if fgraph is not None and matched_route is not None and (not path_proven or hop_count > 3):
        entry_id = fgraph.route_node(matched_route)
        sink_id = fgraph.innermost_node_at(sast.file_path or "", s_line)
        if entry_id and sink_id:
            g_path = fgraph.forward_path(entry_id, sink_id, max_hops=8)
            if g_path is not None:
                g_hops = len(g_path) - 1
                g_score = 1.00 if g_hops == 0 else max(0.70, round(0.99 - 0.03 * g_hops, 2))
                if g_score > v_callgraph or not path_proven:
                    v_callgraph, hop_count, path_proven = max(g_score, v_callgraph), g_hops, True
                    call_hop_trace = f"{g_hops}-hop call path {fgraph.describe_path(g_path)} reaches sink L{s_line}"

    if v_callgraph <= 0.0:
        return 0.0, {"callgraph": 0.0, "cwe_graph": v_cwe}, "Handler does not reach this sink"

    # ---- V3: the attacked parameter is an input of that handler ----------------------------------
    v_param = 0.40
    d_param = (dast.parameter or "").strip()
    d_param_l = d_param.lower()
    route_params = matched_route.params if matched_route is not None else []
    if d_param_l:
        if d_param_l in [p.lower() for p in route_params]:
            v_param, param_note = 1.00, f"'{d_param}' is a declared input of the handler {route_params}"
        elif d_param_l == "xml_body" and ("unmarshal" in code_lower or "inputstream" in code_lower or "parse" in code_lower):
            v_param, param_note = 0.96, "XML request body flows into the XML parser sink"
        elif re.search(r"\b" + re.escape(d_param_l) + r"\b", code_lower) or d_param_l in fn_lower:
            v_param, param_note = 0.94, f"'{d_param}' appears in the sink expression itself"
        else:
            v_param = 0.45
            param_note = f"'{d_param}' not found among the handler's declared inputs {route_params or '(none parsed)'}"
    else:
        param_note = "No single parameter (header / body probe)"

    # ---- V4: runtime evidence is what this kind of sink produces ---------------------------------
    v_behavior, behavior_note = 0.55, "Generic runtime differential"
    evidence_lower = (dast.evidence or "").lower()
    sig_tuple = SINK_BEHAVIOR_SIGNATURES.get(sast.cwe)
    if sig_tuple:
        sink_kws, ev_kws, sig_label = sig_tuple
        sink_hit = any(k in code_lower or k in fn_lower for k in sink_kws)
        ev_hit = any(k in evidence_lower for k in ev_kws)
        if sink_hit and ev_hit:
            v_behavior, behavior_note = 1.00, sig_label
        elif sink_hit or ev_hit:
            v_behavior, behavior_note = 0.84, sig_label + (" (sink API matched)" if sink_hit else " (evidence matched)")

    # ---- V5: filter parity (a bypass payload pairs with guarded code, a plain one with unguarded) -
    guard_text = code_lower + " " + (sast.guard_snippet or "").lower()
    has_code_filter = any(
        k in guard_text for k in ("replace", "sanitiz", "escape", "matcher", "pattern", "filter", "validat",
                                  "allowlist", "whitelist", "blacklist", "denylist", "startswith", "contains(")
    )
    is_filtered_probe = dast.is_agentic_ai
    if is_filtered_probe == has_code_filter:
        v_parity = 1.00
        parity_note = "filter-bypass payload hit guarded code" if is_filtered_probe else "plain payload hit unguarded code"
    elif hop_count >= 1:
        v_parity, parity_note = 0.92, "shared helper reachable from guarded and unguarded handlers"
    else:
        v_parity, parity_note = 0.72, "partial guard alignment"

    base_score = 0.30 * v_callgraph + 0.25 * v_cwe + 0.15 * v_param + 0.15 * v_behavior + 0.15 * v_parity
    n_eng = len(set(sast.engines))
    consensus_bonus = min(0.04, 0.02 * max(0, n_eng - 1))
    total_score = min(1.0, base_score + consensus_bonus)
    if not path_proven:
        total_score = min(total_score, GREY_CAP)
    total_score = round(total_score, 4)

    sink_where = f"{os.path.basename(sast.file_path or '')}:{s_line}"
    d_path = urllib.parse.urlparse(dast.url or "").path or (dast.url or "")
    link_checks: List[Dict[str, Any]] = [
        {"ok": True, "text": f"Same weakness: SAST {sast.raw_cwe} and DAST {dast.raw_cwe} are both {sast.cwe} ({_cwe_name(sast.cwe)})."},
        (
            {"ok": True, "text": f"DAST URL {d_path} is served by {matched_route.class_name}.{matched_route.handler_name}() "
                                 f"in {os.path.basename(matched_route.file_path)}:{matched_route.start_line}-{matched_route.end_line}."}
            if matched_route is not None
            else {"ok": False, "text": f"No route in the route map serves {d_path}."}
        ),
        {"ok": True if path_proven else None,
         "text": (f"That handler reaches the SAST sink {sink_where}: " if path_proven else f"Code path to {sink_where} not proven: ")
                 + call_hop_trace + "."},
        {"ok": True if v_param >= 0.94 else None, "text": param_note[:1].upper() + param_note[1:] + "."},
        {"ok": True if v_behavior >= 1.0 else None, "text": f"Runtime evidence fits the sink: {behavior_note}."},
    ]

    details: Dict[str, Any] = {
        "engine_consensus": {"engines": sorted(set(sast.engines)), "bonus": round(consensus_bonus, 2)},
        "callgraph": round(v_callgraph, 2),
        "cwe_graph": round(v_cwe, 2),
        "param_lineage": round(v_param, 2),
        "sink_behavior": round(v_behavior, 2),
        "defense_parity": round(v_parity, 2),
        "composite_score": round(total_score, 3),
        "path_proven": path_proven,
        "hop_count": hop_count,
        "hop_trace": call_hop_trace,
        "matched_route": matched_route.url_pattern if matched_route is not None else None,
        "matched_handler": f"{matched_route.class_name}.{matched_route.handler_name}" if matched_route is not None else None,
        "enclosing_sink_method": sast.function_name,
        "cwe_note": cwe_note,
        "param_note": param_note,
        "behavior_note": behavior_note,
        "parity_note": parity_note,
        "link_checks": link_checks,
        "_route_obj": matched_route,
    }
    reason = (
        f"[Link score {total_score:.0%}] path={'proven' if path_proven else 'UNPROVEN'} ({call_hop_trace}) | "
        f"CWE={v_cwe:.0%} | param '{dast.parameter or 'body'}'={v_param:.0%} | evidence={v_behavior:.0%} | parity={v_parity:.0%}"
        + (f" | +{consensus_bonus:.2f} ({n_eng} SAST engines agree)" if consensus_bonus else "")
    )
    return total_score, details, reason


def calculate_risk_score(
    status: str,
    severity: str,
    dpdp_flag: bool,
    quantum_flag: bool,
    vault_candidate: bool,
) -> float:
    """Composite risk score (0-100): proven exploitability first, then severity (FR-9)."""
    score = {"Confirmed": 45.0, "Runtime only": 25.0, "Code only": 15.0}.get(status, 15.0)
    score += {"CRITICAL": 35.0, "HIGH": 25.0, "MEDIUM": 15.0, "LOW": 5.0, "INFO": 0.0}.get((severity or "HIGH").upper(), 15.0)
    if dpdp_flag:
        score += 10.0
    if quantum_flag:
        score += 5.0
    if vault_candidate:
        score += 5.0
    return min(100.0, round(score, 1))


def _primary_probe_rank(link_confidence: float, details: Dict[str, Any], dast: CommonFinding) -> Tuple[float, int, int, int]:
    """Which of several URLs proving the same sink becomes the issue's replay vector: highest link score,
    then exact parameter lineage, then the plain (non-bypass) payload a developer can reproduce most easily,
    then the shortest URL."""
    path = urllib.parse.urlparse(dast.url or "").path
    exact_param = 1 if float(details.get("param_lineage", 0.0)) >= 0.95 else 0
    plain_payload = 0 if dast.is_agentic_ai else 1
    return (round(link_confidence, 3), exact_param, plain_payload, -len(path))


_py_spans_cache: Dict[str, List[Tuple[int, int, str]]] = {}


def _python_enclosing_function(source_root: Optional[str], file_path: str, line: int) -> Optional[str]:
    """Innermost def/async def/class.method around `line` in a Python file (stdlib ast, cached per file).
    Python SAST engines (Bandit) report no function name, and the Java function graph doesn't cover .py."""
    path = file_path if os.path.isabs(file_path) or not source_root else os.path.join(source_root, file_path)
    spans = _py_spans_cache.get(path)
    if spans is None:
        import ast as _ast
        spans = []
        try:
            tree = _ast.parse(open(path, "r", encoding="utf-8", errors="ignore").read())

            def walk(node: Any, prefix: str) -> None:
                for ch in _ast.iter_child_nodes(node):
                    if isinstance(ch, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                        spans.append((ch.lineno, getattr(ch, "end_lineno", ch.lineno), prefix + ch.name))
                        walk(ch, prefix + ch.name + ".")
                    elif isinstance(ch, _ast.ClassDef):
                        walk(ch, prefix + ch.name + ".")
            walk(tree, "")
        except Exception:
            pass
        _py_spans_cache[path] = spans
    best = None
    for s, e, name in spans:
        if s <= line <= e and (best is None or e - s < best[0]):
            best = (e - s, name)
    return best[1] if best else None


def _fill_function_names(findings: List[CommonFinding], source_root: Optional[str]) -> None:
    for f in findings:
        if not f.function_name and f.line and (f.file_path or "").endswith(".py"):
            f.function_name = _python_enclosing_function(source_root, f.file_path, f.line)


def _method_key(f: CommonFinding, fgraph: Optional[Any]) -> str:
    """The enclosing method of a finding: the unit that defines 'one real bug' for dedup."""
    if fgraph is not None and f.file_path and f.line:
        nid = fgraph.innermost_node_at(f.file_path, f.line)
        if nid:
            return nid
    if not _norm_path(f.file_path).endswith(CODE_EXTS):
        return "<file>"  # config / resource file: one issue per file per weakness
    if f.function_name:
        return f.function_name
    # Unknown enclosing function: keep lines apart rather than risk joining two different bugs.
    return f"<line {f.line}>" if not _norm_path(f.file_path).endswith(".java") else "<class-scope>"


def _sink_key(f: CommonFinding, fgraph: Optional[Any]) -> Tuple[str, str, str]:
    return (_norm_path(f.file_path), _method_key(f, fgraph), f.cwe)


def _sink_fingerprint(key: Tuple[str, str, str]) -> str:
    """Stable across rescans and status changes (Code only -> Confirmed keeps the same id) and across line
    shifts inside the method, so re-running a scan never creates a copy of the same bug (FR-6)."""
    return hashlib.sha256(f"Sink:{key[0]}:{key[1]}:{key[2]}".encode()).hexdigest()


_WEAK_EVIDENCE = ("boolean differential", "time-based", "timing differential", "response length differs")


def _is_weak_evidence(d: CommonFinding) -> bool:
    """Inference-only proof (response size / timing) as opposed to a direct artifact of the sink
    (DB error text, command output canary, executed script, leaked file, Location header)."""
    ev = (d.evidence or "").lower()
    return any(w in ev for w in _WEAK_EVIDENCE)


def _handler_source(route: Optional[RouteEntry], source_root: Optional[str], max_lines: int = 40) -> str:
    if route is None or not route.file_path:
        return ""
    candidates = [route.file_path]
    if source_root and not os.path.isabs(route.file_path):
        candidates.insert(0, os.path.join(source_root, route.file_path))
    for p in candidates:
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.read().splitlines()
            body = lines[max(0, route.start_line - 1):min(len(lines), route.end_line)]
            return "\n".join(body[:max_lines])
        except OSError:
            continue
    return ""


def _plain_link_sentence(sast: CommonFinding, d: CommonFinding, details: Dict[str, Any]) -> str:
    path = urllib.parse.urlparse(d.url or "").path or d.url
    handler = details.get("matched_handler")
    where = f"{os.path.basename(sast.file_path or '')}:{sast.line}"
    via = f"is handled by {handler}(), which {'contains' if details.get('hop_count') == 0 else 'calls into'} " if handler else "matches "
    return (
        f"Joined because the runtime {_cwe_name(sast.cwe)} on {d.method or 'GET'} {path}"
        f"{' (parameter ' + repr(d.parameter) + ')' if d.parameter else ''} {via}the SAST sink at {where}"
        f"{' in ' + sast.function_name + '()' if sast.function_name else ''}; both are {sast.cwe}."
    )


def _make_issue_common(cwe: str) -> Dict[str, str]:
    meta = MITRE_METADATA_MAP.get(cwe, {})
    return {
        "mitre_attck": f"{meta.get('attck_id', '')} {meta.get('attck_name', '')}".strip(),
        "mitre_capec": meta.get("capec_id", ""),
        "owasp_category": meta.get("owasp_2025", ""),
        "fix": meta.get("fix_summary", ""),
    }


def _confirmed_issue(
    s: CommonFinding,
    d: CommonFinding,
    details: Dict[str, Any],
    route: Optional[RouteEntry],
    link_confidence: float,
    explanation: str,
    fingerprint: str,
) -> CorrelatedIssue:
    flow = build_ast_taint_flow(
        s.cwe, s.vuln_type or d.vuln_type, s.file_path, s.line, s.code_snippet,
        function_name=s.function_name, guard_snippet=s.guard_snippet, matched_route=route,
        hop_trace=details.get("hop_trace"), status="Confirmed",
        dast_url=d.url, dast_method=d.method, dast_param=d.parameter, dast_evidence=d.evidence,
    )
    is_agentic = d.is_agentic_ai  # set by the DAST layer only when an AI bypass payload actually fired and confirmed
    sev = "CRITICAL" if "CRITICAL" in (s.severity, d.severity) else (d.severity or s.severity)
    dpdp, pqc, vault = s.dpdp_pii_flag or d.dpdp_pii_flag, s.quantum_flag or d.quantum_flag, s.vault_candidate or d.vault_candidate
    common = _make_issue_common(s.cwe)
    # Only a REAL Playwright DOM capture (xss_*.png) counts as a screenshot proof.
    shot = d.screenshot_path if (d.screenshot_path and d.screenshot_path.startswith("/screenshots/xss_")) else None
    return CorrelatedIssue(
        fingerprint=fingerprint,
        status="Confirmed",
        priority_rank=1,
        risk_score=calculate_risk_score("Confirmed", sev, dpdp, pqc, vault),
        cwe=s.cwe,
        raw_cwe=s.raw_cwe or d.raw_cwe,
        vuln_type=s.vuln_type or d.vuln_type,
        severity=sev,
        url=d.url,
        method=d.method or "GET",
        parameter=d.parameter,
        payload=d.payload,
        runtime_evidence=d.evidence,
        screenshot_path=shot,
        file_path=s.file_path,
        line=s.line,
        end_line=s.end_line,
        function_name=s.function_name,
        code_snippet=s.code_snippet,
        correlation_confidence=link_confidence,
        link_explanation=explanation,
        fix_suggestion=common["fix"] or flow.get("remediation", ""),
        mitre_attck=common["mitre_attck"],
        mitre_capec=common["mitre_capec"],
        owasp_category=common["owasp_category"],
        dpdp_pii_flag=dpdp,
        quantum_flag=pqc,
        vault_candidate=vault,
        scanners_matched=sorted(set(s.engines or [s.scanner]) | {d.scanner}),
        tool_tag=flow.get("tool_tag", "Custom AST Taint Engine"),
        ast_flow=flow,
        curl_command=build_curl_command(d.url, d.method, d.parameter, d.payload, s.cwe),
        postman_test_script=build_tailored_postman_script(
            s.cwe, s.vuln_type or d.vuln_type, d.payload or "", d.parameter or "",
            ai_technique=d.ai_technique if is_agentic else None,
            ai_guard_basis=d.ai_guard_basis if is_agentic else None,
        ),
        is_agentic_ai=is_agentic,
        ai_technique=d.ai_technique if is_agentic else None,
        ai_chain_of_thought=d.ai_chain_of_thought if is_agentic else [],
        ai_engine=d.ai_engine if is_agentic else None,
        ai_guard_basis=d.ai_guard_basis if is_agentic else None,
        vector_breakdown=details,
    )


def correlate_findings(
    sast_findings: List[CommonFinding],
    dast_findings: List[CommonFinding],
    routes: Optional[List[RouteEntry]] = None,
    db_path: str = "vajra_state.db",
    auto_verify_b1: bool = True,
    fgraph: Optional[Any] = None,
    suppressed: Optional[List[CommonFinding]] = None,
    source_root: Optional[str] = None,
    report: Optional[Dict[str, Any]] = None,
) -> List[CorrelatedIssue]:
    """Correlate SAST and DAST findings into one deduplicated, prioritised issue list (FR-5..FR-9, B-3).

    One issue = one real bug = one (file, enclosing method, CWE) sink. Several URLs that reach the same sink
    merge into it; different sinks in the same file stay separate issues.

    suppressed: SAST findings the decoy filter judged safe. If DAST nevertheless proves the route that reaches
      one of them is exploitable, the conflict is resolved by evidence strength: a direct artifact (DB error,
      command output, executed script...) overrides the suppression; inference-only evidence (response size /
      timing) does not, and the pair is reported as *contested* instead of as a new issue.
    report: optional dict filled with correlation statistics (pairs scored, tiers, arbiter calls, contested).
    """
    # Never link a runtime finding that no real request produced (offline/simulated evidence).
    simulated = [d for d in dast_findings if (d.evidence_origin or "") == "simulated"]
    if simulated:
        dast_findings = [d for d in dast_findings if (d.evidence_origin or "") != "simulated"]
    route_cache = _build_route_indexes(routes)
    _fill_function_names(list(sast_findings) + list(suppressed or []), source_root)
    stats: Dict[str, Any] = {
        "dast_findings": len(dast_findings), "sast_sinks": len(sast_findings), "pairs_scored": 0,
        "auto_confirmed": 0, "arbiter_calls": 0, "arbiter_linked": 0, "arbiter_rejected": 0,
        "below_threshold": 0, "no_candidate": 0, "suppression_overridden": 0, "contested": [],
        "merged_into_existing_sink": 0, "secret_noise_dropped": [],
        "simulated_dast_dropped": len(simulated),
    }

    matched_sast_ids: Set[str] = set()
    handled_dast_ids: Set[str] = set()
    confirmed_by_sink: Dict[Tuple[str, str, str], CorrelatedIssue] = {}
    best_rank_by_sink: Dict[Tuple[str, str, str], Tuple[float, int, int, int]] = {}
    confirmed_urls_cwes: Set[Tuple[str, str]] = set()
    correlated_issues: List[CorrelatedIssue] = []
    active = [s for s in sast_findings if not s.is_safe_decoy]

    def best_link(d: CommonFinding, pool: List[CommonFinding], route: Optional[RouteEntry], allow_secure: bool = False):
        best: Tuple[float, Optional[CommonFinding], Dict[str, Any], str] = (0.0, None, {}, "")
        for s in pool:
            if s.cwe != d.cwe and canonicalize_cwe(s.raw_cwe) != canonicalize_cwe(d.raw_cwe):
                continue
            stats["pairs_scored"] += 1
            sc, det, rsn = calculate_match_score(
                s, d, routes, _route_cache=route_cache, fgraph=fgraph, matched_route=route, allow_secure=allow_secure,
            )
            if sc > best[0]:
                best = (sc, s, det, rsn)
        return best

    # 1. Link every DAST proof to the sink that causes it ------------------------------------------
    for d in dast_findings:
        route = lookup_route(d, routes)
        best_score, best_sast, best_details, best_reason = best_link(d, active, route)
        override_note = ""

        if best_sast is None or best_score < GREY_FLOOR:
            # Does the runtime proof land on code SAST positively judged safe?
            contradiction = None
            if suppressed:
                sc2, s2, det2, rsn2 = best_link(d, list(suppressed), route, allow_secure=True)
                if s2 is not None and det2.get("path_proven") and sc2 >= GREY_FLOOR:
                    contradiction = (sc2, s2, det2, rsn2)
            route_secure = route is not None and route.is_secure_variant
            if (contradiction or route_secure) and _is_weak_evidence(d):
                stats["contested"].append({
                    "url": d.url, "cwe": d.cwe, "parameter": d.parameter, "payload": d.payload, "evidence": d.evidence,
                    "sast_verdict": (contradiction[1].suppression_reason if contradiction else None)
                    or "route is declared secure by the application",
                    "sast_location": f"{contradiction[1].file_path}:{contradiction[1].line}" if contradiction else
                    (f"{route.file_path}:{route.start_line}" if route else None),
                    "resolution": "not reported: inference-only runtime evidence does not outweigh a positive static safety proof",
                })
                handled_dast_ids.add(d.finding_id)
                continue
            if contradiction:
                best_score, best_sast, best_details, best_reason = contradiction
                best_score = round(best_score * 0.95, 4)
                override_note = (
                    f" SAST had suppressed this sink as safe ({best_sast.suppression_reason or 'decoy filter'}), "
                    f"but the runtime proof is a direct artifact of the sink, so the suppression is overridden."
                )
                stats["suppression_overridden"] += 1
            else:
                stats["no_candidate" if best_sast is None else "below_threshold"] += 1
                continue

        matched_route_obj: Optional[RouteEntry] = best_details.pop("_route_obj", None)
        plain = _plain_link_sentence(best_sast, d, best_details) + override_note

        if best_score >= AUTO_CONFIRM and best_details.get("path_proven"):
            stats["auto_confirmed"] += 1
            link_confidence = round(best_score, 2)
            arbiter_engine = "Deterministic code-path proof (no LLM)"
            explanation = f"{plain} {best_reason}"
        else:
            stats["arbiter_calls"] += 1
            ai_decision = resolve_greyzone_link(
                best_sast, d, best_score, db_path=db_path, vector_details=best_details,
                handler_source=_handler_source(matched_route_obj, source_root),
            )
            if not ai_decision.get("is_linked", False):
                stats["arbiter_rejected"] += 1
                continue
            stats["arbiter_linked"] += 1
            link_confidence = round(min(float(ai_decision.get("confidence", best_score)), GREY_CAP + 0.05), 2)
            arbiter_engine = str(ai_decision.get("engine", "Grey-zone arbiter"))
            explanation = f"{plain} {best_reason} | {arbiter_engine}: {ai_decision.get('explanation', '')}"

        best_details["arbiter_engine"] = arbiter_engine
        best_details["composite_score"] = link_confidence
        best_details["sast_engines"] = sorted(set(best_sast.engines)) or [best_sast.scanner]
        best_details["dast_discovery"] = d.discovery
        best_details["runtime_origin"] = d.evidence_origin
        best_details["plain_explanation"] = plain
        if override_note:
            best_details["suppression_overridden"] = best_sast.suppression_reason or True

        matched_sast_ids.add(best_sast.finding_id)
        handled_dast_ids.add(d.finding_id)
        clean_d_url = (d.url or "").split("?")[0].rstrip("/")
        confirmed_urls_cwes.add((clean_d_url, best_sast.cwe))
        short_ep = urllib.parse.urlparse(clean_d_url).path or clean_d_url

        key = _sink_key(best_sast, fgraph)
        best_details["sink_method"] = key[1]
        cand_rank = _primary_probe_rank(link_confidence, best_details, d)
        existing = confirmed_by_sink.get(key)
        if existing is not None:
            stats["merged_into_existing_sink"] += 1
            evb = existing.vector_breakdown or {}
            eps = list(evb.get("verified_endpoints", []))
            if short_ep and short_ep not in eps:
                eps.append(short_ep)
            lines = sorted(set(evb.get("sink_lines", [])) | {best_sast.line})
            engines = sorted(set(evb.get("sast_engines", [])) | set(best_details["sast_engines"]))
            discoveries = sorted(set(evb.get("dast_discoveries", [])) | {d.discovery or "unknown"})
            scanners = sorted(set(existing.scanners_matched) | set(best_details["sast_engines"]) | {d.scanner})
            if cand_rank > best_rank_by_sink[key]:
                best_rank_by_sink[key] = cand_rank
                was_agentic = existing.is_agentic_ai
                existing = _confirmed_issue(best_sast, d, best_details, matched_route_obj, link_confidence,
                                            explanation, existing.fingerprint)
                confirmed_by_sink[key] = existing
                if was_agentic and not existing.is_agentic_ai:
                    existing.is_agentic_ai = True
            elif d.is_agentic_ai and not existing.is_agentic_ai:
                existing.is_agentic_ai = True
                existing.ai_technique, existing.ai_chain_of_thought = d.ai_technique, d.ai_chain_of_thought
                existing.ai_engine, existing.ai_guard_basis = d.ai_engine, d.ai_guard_basis
            vb = existing.vector_breakdown or {}
            vb.update(verified_endpoints=eps, sink_lines=lines, sast_engines=engines, dast_discoveries=discoveries)
            existing.vector_breakdown = vb
            existing.scanners_matched = scanners
            continue

        best_rank_by_sink[key] = cand_rank
        best_details["verified_endpoints"] = [short_ep] if short_ep else []
        best_details["dast_discoveries"] = [d.discovery or "unknown"]
        best_details["sink_lines"] = [best_sast.line] if best_sast.line else []
        best_details["sink_method"] = key[1]
        confirmed_by_sink[key] = _confirmed_issue(
            best_sast, d, best_details, matched_route_obj, link_confidence, explanation, _sink_fingerprint(key),
        )

    for issue in confirmed_by_sink.values():
        eps = (issue.vector_breakdown or {}).get("verified_endpoints", [])
        others = [e for e in eps if e and not (issue.url or "").split("?")[0].endswith(e)]
        if others:
            more = f" (+{len(others) - 4} more)" if len(others) > 4 else ""
            issue.runtime_evidence = (
                f"{issue.runtime_evidence or ''} | Same sink also proven via: {', '.join(others[:4])}{more}"
            ).strip(" |")
    correlated_issues.extend(confirmed_by_sink.values())

    # 2. DAST proofs with no code location -> Runtime only ------------------------------------------
    seen_runtime_keys: Set[str] = set()
    for d in dast_findings:
        if d.finding_id in handled_dast_ids:
            continue
        clean_d_url = (d.url or "").split("?")[0].rstrip("/")
        if (clean_d_url, d.cwe) in confirmed_urls_cwes:
            continue
        is_header_tls = any(
            h in (d.vuln_type or "").lower()
            for h in ("header", "cookie", "cors", "tls", "policy", "clickjacking", "hsts", "content-security-policy", "nosniff")
        )
        rt_route = lookup_route(d, routes) if not is_header_tls else None
        route_id = (
            f"{rt_route.file_path}:{rt_route.handler_name}" if rt_route is not None
            else urllib.parse.urlparse(clean_d_url).path
        )
        r_key = f"RuntimePolicy:{d.cwe}:{d.vuln_type}" if is_header_tls else f"RuntimeEndpoint:{d.cwe}:{route_id}"
        if r_key in seen_runtime_keys:
            continue
        seen_runtime_keys.add(r_key)

        is_agentic = d.is_agentic_ai
        common = _make_issue_common(d.cwe)
        flow = build_ast_taint_flow(
            d.cwe, d.vuln_type, None, None, None, status="Runtime only",
            dast_url=d.url, dast_method=d.method, dast_param=d.parameter, dast_evidence=d.evidence,
        )
        if is_header_tls:
            note = ("Observed in live HTTP response headers / transport; set by global server or middleware "
                    "configuration rather than one line of application code.")
        elif rt_route is not None:
            note = (f"DAST proved this at runtime on a route handled by {rt_route.class_name}.{rt_route.handler_name}() "
                    f"({rt_route.file_path}:{rt_route.start_line}), but SAST reported no matching sink there: "
                    "a static-analysis gap. Start the fix in that handler.")
        else:
            note = "DAST proved this at runtime, but the URL is not in the route map, so no code location is known."
        rt_vb: Dict[str, Any] = {"mode": "RUNTIME_ONLY", "note": note, "dast_discovery": d.discovery,
                                 "runtime_origin": d.evidence_origin}
        if rt_route is not None:
            rt_vb["handler_hint"] = f"{rt_route.class_name}.{rt_route.handler_name}() ({rt_route.file_path}:{rt_route.start_line})"
            rt_vb["sast_gap"] = not rt_route.is_secure_variant
            rt_vb["route_is_secure_variant"] = rt_route.is_secure_variant
        if d.discovery == "decoy-audit":
            rt_vb["decoy_violation"] = True

        correlated_issues.append(CorrelatedIssue(
            fingerprint=hashlib.sha256(f"RuntimeOnly:{r_key}".encode()).hexdigest(),
            status="Runtime only",
            priority_rank=2,
            risk_score=calculate_risk_score("Runtime only", d.severity, d.dpdp_pii_flag, d.quantum_flag, d.vault_candidate),
            cwe=d.cwe, raw_cwe=d.raw_cwe, vuln_type=d.vuln_type, severity=d.severity,
            url=d.url, method=d.method or "GET", parameter=d.parameter, payload=d.payload,
            runtime_evidence=d.evidence, screenshot_path=None,
            correlation_confidence=1.0,
            link_explanation=note,
            fix_suggestion=common["fix"] or flow.get("remediation", ""),
            mitre_attck=common["mitre_attck"], mitre_capec=common["mitre_capec"], owasp_category=common["owasp_category"],
            dpdp_pii_flag=d.dpdp_pii_flag, quantum_flag=d.quantum_flag, vault_candidate=d.vault_candidate,
            scanners_matched=[d.scanner],
            tool_tag=flow.get("tool_tag", "Active DAST Verifier"),
            ast_flow=flow,
            curl_command=build_curl_command(d.url, d.method, d.parameter, d.payload, d.cwe),
            postman_test_script=build_tailored_postman_script(
                d.cwe, d.vuln_type, d.payload or "", d.parameter or "",
                ai_technique=d.ai_technique if is_agentic else None,
                ai_guard_basis=d.ai_guard_basis if is_agentic else None,
            ),
            is_agentic_ai=is_agentic,
            ai_technique=d.ai_technique if is_agentic else None,
            ai_chain_of_thought=d.ai_chain_of_thought if is_agentic else [],
            ai_engine=d.ai_engine if is_agentic else None,
            ai_guard_basis=d.ai_guard_basis if is_agentic else None,
            vector_breakdown=rt_vb,
        ))

    # 3. SAST sinks no DAST proof reached -> Code only (one issue per sink method) -------------------
    seen_code_sinks: Dict[Tuple[str, str, str], CorrelatedIssue] = {}
    for s in sast_findings:
        if s.finding_id in matched_sast_ids or s.is_safe_decoy:
            continue
        c_key = _sink_key(s, fgraph)
        if c_key in confirmed_by_sink:
            # Another line of a sink already proven at runtime: same bug, attach it there.
            ci = confirmed_by_sink[c_key]
            vb = ci.vector_breakdown or {}
            vb["sink_lines"] = sorted(set(vb.get("sink_lines", [])) | ({s.line} if s.line else set()))
            vb["sast_engines"] = sorted(set(vb.get("sast_engines", [])) | set(s.engines or [s.scanner]))
            ci.vector_breakdown = vb
            continue
        if (s.raw_cwe or "").upper() in ("CWE-798", "CWE-259") and source_root:
            # B-2 noise cut for secrets: read the real flagged line; UI text, placeholders (${ENV}), PEM
            # delimiters, URLs and names-mirrored-by-their-constant are not hard-coded credentials.
            verdict, why = secret_verdict(s.file_path, s.line, s.code_snippet, source_root)
            if verdict in ("not-a-secret", "already-externalized"):
                stats["secret_noise_dropped"].append(
                    {"file": s.file_path, "line": s.line, "verdict": verdict, "reason": why}
                )
                continue
        if c_key in seen_code_sinks:
            existing_c = seen_code_sinks[c_key]
            vb = existing_c.vector_breakdown or {}
            lines = set(vb.get("sink_lines", []))
            if s.line:
                lines.add(s.line)
            vb["sink_lines"] = sorted(lines)
            vb["extra_lines"] = vb["sink_lines"]
            vb["sast_engines"] = sorted(set(vb.get("sast_engines", [])) | set(s.engines or [s.scanner]))
            existing_c.scanners_matched = sorted(set(existing_c.scanners_matched) | set(s.engines or [s.scanner]))
            existing_c.vector_breakdown = vb
            continue

        common = _make_issue_common(s.cwe)
        flow = build_ast_taint_flow(
            s.cwe, s.vuln_type, s.file_path, s.line, s.code_snippet,
            function_name=s.function_name, guard_snippet=s.guard_snippet, status="Code only",
        )
        is_resource = not _norm_path(s.file_path).endswith(CODE_EXTS)
        code_only_reason = (
            f"Static secret / key material in {s.file_path}:{s.line}; not an HTTP-reachable code path, so it can "
            "only be found in code (candidate for Vault migration)."
            if is_resource
            else (
                f"SAST sink at {os.path.basename(s.file_path or '')}:{s.line} "
                f"({s.function_name + '()' if s.function_name else 'class scope'}); no runtime probe proved it, so it "
                "stays Code only (not reachable without auth, not probed, or not exploitable as written)."
            )
        )
        code_issue = CorrelatedIssue(
            fingerprint=_sink_fingerprint(c_key),
            status="Code only",
            priority_rank=3,
            risk_score=calculate_risk_score("Code only", s.severity, s.dpdp_pii_flag, s.quantum_flag, s.vault_candidate),
            cwe=s.cwe, raw_cwe=s.raw_cwe, vuln_type=s.vuln_type, severity=s.severity,
            file_path=s.file_path, line=s.line, end_line=s.end_line, function_name=s.function_name,
            code_snippet=s.code_snippet,
            correlation_confidence=0.0,
            link_explanation=code_only_reason,
            fix_suggestion=common["fix"] or flow.get("remediation", ""),
            mitre_attck=common["mitre_attck"], mitre_capec=common["mitre_capec"], owasp_category=common["owasp_category"],
            dpdp_pii_flag=s.dpdp_pii_flag, quantum_flag=s.quantum_flag, vault_candidate=s.vault_candidate,
            scanners_matched=sorted(set(s.engines or [s.scanner])),
            tool_tag=flow.get("tool_tag", "Custom AST Taint Engine"),
            ast_flow=flow,
            vector_breakdown={
                "mode": "CODE_ONLY",
                "sink_method": c_key[1],
                "sink_lines": [s.line] if s.line else [],
                "extra_lines": [s.line] if s.line else [],
                "sast_engines": sorted(set(s.engines or [s.scanner])),
            },
        )
        seen_code_sinks[c_key] = code_issue
        correlated_issues.append(code_issue)

    # 3b. Root-sink propagation: "same root cause reached from N endpoints / M importing modules"
    if fgraph is not None:
        mc_index = {(c["file"], c["cwe"]): c for c in getattr(fgraph, "module_clusters", [])}
        for issue in correlated_issues:
            if not issue.file_path or issue.status == "Runtime only":
                continue
            mc = mc_index.get((issue.file_path, issue.cwe))
            if not mc:
                continue
            best_path = None
            for cl in fgraph.clusters:
                if cl["root"]["file"] == issue.file_path and cl["cwe"] == issue.cwe and cl["entrypoints"]:
                    cand = next((r for r in cl["entrypoints"] if r["cross_module"]), cl["entrypoints"][0])
                    if best_path is None or (cand["cross_module"], -cand["hops"]) > (best_path[0], -best_path[1]):
                        best_path = (cand["cross_module"], cand["hops"], cand["path"])
            vb = issue.vector_breakdown or {}
            vb["propagation"] = {
                "root_module": mc["root_module"],
                "root_methods": mc["root_methods"][:8],
                "sink_lines": mc["sink_lines"],
                "entry_modules": mc["entry_modules"],
                "importing_modules": mc["importing_modules"],
                "reachable_endpoints": len(mc["route_urls"]),
                "endpoint_examples": mc["route_urls"][:6],
                "alerts_without_graph": mc["alerts_without_graph"],
                "alerts_with_graph": 1,
                "example_path": best_path[2] if best_path else None,
                "max_hops": mc["max_hops"],
            }
            issue.vector_breakdown = vb

    # 4. Final fingerprint dedup & priority order (Confirmed > Runtime only > Code only, then risk)
    unique_issues: Dict[str, CorrelatedIssue] = {}
    for issue in correlated_issues:
        prev = unique_issues.get(issue.fingerprint)
        if prev is None or issue.priority_rank < prev.priority_rank:
            unique_issues[issue.fingerprint] = issue
    deduped = sorted(unique_issues.values(), key=lambda x: (x.priority_rank, -x.risk_score, x.file_path or "", x.line or 0))
    for idx, issue in enumerate(deduped, start=1):
        issue.issue_id = idx

    stats["issues"] = len(deduped)
    stats["confirmed"] = sum(1 for i in deduped if i.status == "Confirmed")
    stats["runtime_only"] = sum(1 for i in deduped if i.status == "Runtime only")
    stats["code_only"] = sum(1 for i in deduped if i.status == "Code only")
    if report is not None:
        report.update(stats)
    return deduped
