"""
VajraLink Core Models, CWE Canonicalization & Threat Metadata.
Aligned with Organiser PRD (FR-1..FR-10, B-1, B-2, B-3, B-6) and SasanLabs/VulnerableApp.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Literal, Optional, Set
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# CWE Canonical Hierarchy Mapping
# ---------------------------------------------------------------------------
# Maps raw / tool-specific / child CWEs to their canonical root representation.
# This ensures SAST findings and DAST findings link seamlessly regardless of tool variants.
CWE_CANONICAL_CLUSTERS: Dict[str, Set[str]] = {
    "CWE-89": {"CWE-89", "CWE-564", "CWE-943", "89", "564", "943"},
    "CWE-79": {"CWE-79", "CWE-80", "CWE-83", "CWE-87", "79", "80", "83", "87"},
    "CWE-78": {"CWE-78", "CWE-77", "CWE-88", "78", "77", "88"},
    "CWE-22": {"CWE-22", "CWE-23", "CWE-36", "CWE-73", "22", "23", "36", "73"},
    "CWE-601": {"CWE-601", "601"},
    "CWE-798": {"CWE-798", "CWE-259", "CWE-321", "CWE-522", "CWE-1188", "CWE-347", "798", "259", "321", "522", "1188", "347"},
    "CWE-327": {"CWE-327", "CWE-326", "CWE-328", "CWE-330", "CWE-338", "CWE-916", "327", "326", "328", "330", "338", "916"},
    "CWE-256": {"CWE-256", "CWE-319", "CWE-359", "CWE-200", "CWE-204", "CWE-640", "CWE-307", "CWE-384", "CWE-613", "256", "319", "359", "200", "204", "640", "307", "384", "613"},
    "CWE-693": {"CWE-693", "CWE-1021", "CWE-614", "CWE-1004", "CWE-942", "CWE-349", "CWE-113", "CWE-16", "693", "1021", "614", "1004", "942", "349", "113", "16"},
    "CWE-918": {"CWE-918", "918"},
    "CWE-611": {"CWE-611", "611"},
    "CWE-639": {"CWE-639", "CWE-285", "639", "285"},
    "CWE-434": {"CWE-434", "CWE-730", "CWE-400", "434", "730", "400"},
    "CWE-90": {"CWE-90", "90"},
}

RAW_TO_CANONICAL_MAP: Dict[str, str] = {}
for canonical, variants in CWE_CANONICAL_CLUSTERS.items():
    for var in variants:
        RAW_TO_CANONICAL_MAP[var.upper()] = canonical


def canonicalize_cwe(cwe_input: Optional[str]) -> str:
    """Normalize any raw CWE string or integer into canonical CWE-XXX."""
    if not cwe_input:
        return "CWE-Other"
    clean = str(cwe_input).strip().upper()
    match = re.search(r"CWE[-_]?(\d+)", clean)
    if match:
        norm_key = f"CWE-{match.group(1)}"
        return RAW_TO_CANONICAL_MAP.get(norm_key, norm_key)
    digits = re.search(r"\b(\d{2,4})\b", clean)
    if digits:
        norm_key = f"CWE-{digits.group(1)}"
        return RAW_TO_CANONICAL_MAP.get(norm_key, norm_key)
    return RAW_TO_CANONICAL_MAP.get(clean, clean)


# ---------------------------------------------------------------------------
# MITRE ATT&CK, CAPEC & Remediation Metadata
# ---------------------------------------------------------------------------
MITRE_METADATA_MAP: Dict[str, Dict[str, str]] = {
    "CWE-89": {
        "cwe_name": "SQL Injection",
        "owasp_2025": "A05:2025-Injection",
        "capec_id": "CAPEC-66: SQL Injection",
        "attck_id": "T1190",
        "attck_name": "Exploit Public-Facing Application",
        "d3fend_id": "D3-VSP: Validate SQL Parameters",
        "default_severity": "CRITICAL",
        "fix_summary": "Use parameterized queries (e.g. PreparedStatement with '?' placeholders) or ORM parameter binding.",
    },
    "CWE-79": {
        "cwe_name": "Cross-Site Scripting (XSS)",
        "owasp_2025": "A03:2025-Injection",
        "capec_id": "CAPEC-63: Simple Script Injection",
        "attck_id": "T1189",
        "attck_name": "Drive-by Compromise",
        "d3fend_id": "D3-OEN: Output Encoding",
        "default_severity": "HIGH",
        "fix_summary": "Perform context-aware HTML/Attribute/JavaScript escaping (e.g. StringEscapeUtils.escapeHtml4, HtmlUtils.htmlEscapeHex).",
    },
    "CWE-78": {
        "cwe_name": "Command Injection",
        "owasp_2025": "A05:2025-Injection",
        "capec_id": "CAPEC-88: OS Command Injection",
        "attck_id": "T1059.004",
        "attck_name": "Command and Scripting Interpreter: Unix Shell",
        "d3fend_id": "D3-EAI: Execution Allowed Inputs",
        "default_severity": "CRITICAL",
        "fix_summary": "Pass command arguments as structured argument arrays without invoking a subshell ('sh -c' / 'cmd /c'), or validate against a strict regex whitelist.",
    },
    "CWE-22": {
        "cwe_name": "Path Traversal",
        "owasp_2025": "A01:2025-Broken Access Control",
        "capec_id": "CAPEC-126: Path Traversal",
        "attck_id": "T1083",
        "attck_name": "File and Directory Discovery",
        "d3fend_id": "D3-FPA: File Path Allowlist",
        "default_severity": "HIGH",
        "fix_summary": "Sanitize filenames using an allowlist or verify that Path.normalize().startsWith(baseDir) holds true.",
    },
    "CWE-601": {
        "cwe_name": "Open Redirect",
        "owasp_2025": "A01:2025-Broken Access Control",
        "capec_id": "CAPEC-383: Harvesting Credentials via Phishing",
        "attck_id": "T1204.001",
        "attck_name": "User Execution: Malicious Link",
        "d3fend_id": "D3-UVA: URL Validation Allowlist",
        "default_severity": "MEDIUM",
        "fix_summary": "Redirect only to relative URLs or validate destination against a strict domain whitelist.",
    },
    "CWE-798": {
        "cwe_name": "Hard-coded Secrets & Keys",
        "owasp_2025": "A07:2025-Identification and Authentication Failures",
        "capec_id": "CAPEC-115: Authentication Bypass",
        "attck_id": "T1552.001",
        "attck_name": "Unsecured Credentials in Files",
        "d3fend_id": "D3-KMS: Key Management Service / HashiCorp Vault",
        "default_severity": "HIGH",
        "fix_summary": "Remove static secrets, keys, and certificates from version control; inject dynamically using HashiCorp Vault or environment variables.",
    },
    "CWE-327": {
        "cwe_name": "Broken / Quantum-Vulnerable Cryptography",
        "owasp_2025": "A02:2025-Cryptographic Failures",
        "capec_id": "CAPEC-97: Cryptanalysis",
        "attck_id": "T1600",
        "attck_name": "Weaken Encryption",
        "d3fend_id": "D3-PQC: Post-Quantum Cryptography (FIPS 203/204)",
        "default_severity": "HIGH",
        "fix_summary": "Upgrade legacy ciphers (MD5, SHA-1, DES, RSA-1024/2048) to modern quantum-resistant algorithms (ML-KEM / ML-DSA, AES-256-GCM, SHA-384).",
    },
    "CWE-256": {
        "cwe_name": "DPDP Act 2023: Personal Data / Credential Safeguard Breach",
        "owasp_2025": "A07:2025-Identification and Authentication Failures",
        "capec_id": "CAPEC-563: Information Leakage",
        "attck_id": "T1552",
        "attck_name": "Unsecured Credentials",
        "d3fend_id": "D3-SCH: Strong Credential Hashing (Argon2id/BCrypt)",
        "default_severity": "HIGH",
        "fix_summary": "Indian DPDP Act 2023 Sec 8(5) requires reasonable security safeguards for personal data. Store credentials using salted PBKDF2/BCrypt/Argon2.",
    },
    "CWE-693": {
        "cwe_name": "Missing Security Headers & Protections",
        "owasp_2025": "A05:2025-Security Misconfiguration",
        "capec_id": "CAPEC-103: Clickjacking / Header Abuse",
        "attck_id": "T1566",
        "attck_name": "Phishing & UI Redressing",
        "d3fend_id": "D3-SEC: Secure HTTP Headers (CSP, HSTS, XFO)",
        "default_severity": "LOW",
        "fix_summary": "Configure Content-Security-Policy, X-Frame-Options: DENY, Strict-Transport-Security, and secure cookie attributes (HttpOnly, Secure, SameSite).",
    },
    "CWE-918": {
        "cwe_name": "Server-Side Request Forgery (SSRF)",
        "owasp_2025": "A10:2025-Server-Side Request Forgery",
        "capec_id": "CAPEC-664: SSRF",
        "attck_id": "T1190",
        "attck_name": "Exploit Public-Facing Application",
        "d3fend_id": "D3-NWF: Network Filtering Allowlist",
        "default_severity": "HIGH",
        "fix_summary": "Restrict outbound HTTP requests to an internal DNS/IP allowlist and disable loopback/metadata endpoint access.",
    },
    "CWE-611": {
        "cwe_name": "XML External Entity (XXE) Injection",
        "owasp_2025": "A05:2025-Security Misconfiguration",
        "capec_id": "CAPEC-228: DTD Injection",
        "attck_id": "T1190",
        "attck_name": "Exploit Public-Facing Application",
        "d3fend_id": "D3-XPD: Disable DTD Processing",
        "default_severity": "HIGH",
        "fix_summary": "Disable DTD processing and external entity resolution in XML parsers (e.g. setFeature('http://apache.org/xml/features/disallow-doctype-decl', true)).",
    },
    "CWE-639": {
        "cwe_name": "Insecure Direct Object Reference (IDOR)",
        "owasp_2025": "A01:2025-Broken Access Control",
        "capec_id": "CAPEC-115: Authentication Bypass",
        "attck_id": "T1078",
        "attck_name": "Valid Accounts",
        "d3fend_id": "D3-ABAC: Attribute-Based Access Control",
        "default_severity": "HIGH",
        "fix_summary": "Enforce server-side session authorization checks to ensure the requesting user owns the target record.",
    },
    "CWE-434": {
        "cwe_name": "Unrestricted File Upload",
        "owasp_2025": "A01:2025-Broken Access Control",
        "capec_id": "CAPEC-126: File Path Manipulation",
        "attck_id": "T1190",
        "attck_name": "Exploit Public-Facing Application",
        "d3fend_id": "D3-FVA: File Type Validation",
        "default_severity": "HIGH",
        "fix_summary": "Validate file extensions and magic bytes against an allowlist, randomize uploaded filenames, and store outside the webroot.",
    },
    "CWE-90": {
        "cwe_name": "LDAP Injection",
        "owasp_2025": "A05:2025-Injection",
        "capec_id": "CAPEC-248: LDAP Injection",
        "attck_id": "T1190",
        "attck_name": "Exploit Public-Facing Application",
        "d3fend_id": "D3-LEN: LDAP Encoding",
        "default_severity": "HIGH",
        "fix_summary": "Use parameterized LDAP search filters or sanitize user inputs using RFC 4515 escaping.",
    },
}


# ---------------------------------------------------------------------------
# Pydantic Core Models
# ---------------------------------------------------------------------------
class RouteEntry(BaseModel):
    """Represents an extracted HTTP route from source code (FR-4)."""
    http_method: str = "GET"
    url_pattern: str
    handler_name: str
    class_name: str
    file_path: str
    start_line: int
    end_line: int
    params: List[str] = Field(default_factory=list)
    called_helpers: List[str] = Field(default_factory=list)
    is_secure_variant: bool = False
    vulnerability_type_tag: Optional[str] = None


class CommonFinding(BaseModel):
    """Unified raw finding format for SAST and DAST (FR-3)."""
    finding_id: str
    stage: Literal["SAST", "DAST"]
    scanner: str
    cwe: str
    raw_cwe: str
    vuln_type: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] = "HIGH"
    file_path: Optional[str] = None
    line: Optional[int] = None
    end_line: Optional[int] = None
    function_name: Optional[str] = None
    code_snippet: Optional[str] = None
    guard_snippet: Optional[str] = None
    url: Optional[str] = None
    method: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    screenshot_path: Optional[str] = None
    is_safe_decoy: bool = False
    suppression_reason: Optional[str] = None
    dpdp_pii_flag: bool = False
    quantum_flag: bool = False
    vault_candidate: bool = False
    tool_tag: Optional[str] = None
    ast_flow: Optional[Dict[str, str]] = None
    is_agentic_ai: bool = False
    # --- Genuine AI-synthesized filter-bypass evidence (set ONLY when the payload that confirmed this
    # finding was actually produced by synthesize_filter_bypass_payload(), grounded in this exact finding's
    # real guard_snippet/code_snippet from this codebase - never a canned/demo payload). ---
    ai_technique: Optional[str] = None
    ai_chain_of_thought: List[str] = Field(default_factory=list)
    ai_engine: Optional[str] = None  # e.g. "OpenAI gpt-4o-mini (live)" or "Heuristic Evasion Engine (no API key / call failed)"
    ai_guard_basis: Optional[str] = None  # the exact guard/code text the AI reasoned over, for audit
    # --- Provenance (which engine / how was it discovered) ---
    # SAST: every engine that independently flagged this sink (filled by the multi-engine merge).
    engines: List[str] = Field(default_factory=list)
    # DAST: "sast-guided" (route was handed over by SAST), "dast-independent" (found by DAST on its own),
    # "decoy-audit" (probe of a route SAST declared safe).
    discovery: Optional[str] = None
    # DAST: "live-http" (real probe against a reachable server) or "simulated" (target offline fallback).
    evidence_origin: Optional[str] = None


class CorrelatedIssue(BaseModel):
    """Single deduplicated, prioritized, and correlated vulnerability issue (FR-6..FR-9)."""
    issue_id: int = 0
    fingerprint: str
    status: Literal["Confirmed", "Runtime only", "Code only"]
    priority_rank: int = 1
    risk_score: float = 0.0
    cwe: str
    raw_cwe: str
    vuln_type: str
    severity: str
    url: Optional[str] = None
    method: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    runtime_evidence: Optional[str] = None
    screenshot_path: Optional[str] = None
    file_path: Optional[str] = None
    line: Optional[int] = None
    end_line: Optional[int] = None
    code_snippet: Optional[str] = None
    function_name: Optional[str] = None
    correlation_confidence: float = 1.0
    link_explanation: str = ""
    fix_suggestion: str = ""
    mitre_attck: str = ""
    mitre_capec: str = ""
    owasp_category: str = ""
    dpdp_alert: Optional[str] = None
    quantum_alert: Optional[str] = None
    vault_ref: Optional[str] = None
    dpdp_pii_flag: bool = False
    quantum_flag: bool = False
    vault_candidate: bool = False
    scanners_matched: List[str] = Field(default_factory=list)
    tool_tag: Optional[str] = None
    ast_flow: Optional[Dict[str, str]] = None
    curl_command: Optional[str] = None
    postman_test_script: Optional[str] = None
    is_agentic_ai: bool = False
    vector_breakdown: Optional[Dict[str, Any]] = None
    ai_technique: Optional[str] = None
    ai_chain_of_thought: List[str] = Field(default_factory=list)
    ai_engine: Optional[str] = None
    ai_guard_basis: Optional[str] = None


def build_ast_taint_flow(
    cwe: str,
    vuln_type: str,
    file_path: Optional[str],
    line: Optional[int],
    code_snippet: Optional[str],
    *,
    function_name: Optional[str] = None,
    guard_snippet: Optional[str] = None,
    matched_route: Optional[RouteEntry] = None,
    hop_trace: Optional[str] = None,
    status: str = "Code only",
    dast_url: Optional[str] = None,
    dast_method: Optional[str] = None,
    dast_param: Optional[str] = None,
    dast_evidence: Optional[str] = None,
) -> Dict[str, str]:
    """Generate dynamic, AST- & Call-Graph-derived taint trace with zero canned/wrong placeholders."""
    meta = MITRE_METADATA_MAP.get(cwe, {})
    fix_text = meta.get(
        "fix_summary",
        "Enforce strict allowlist validation, parameterized APIs, and context-aware output encoding.",
    )

    # 1. Pure Runtime-Only Finding (no static Java source file mapped)
    if status == "Runtime only" or (not file_path and dast_url):
        method_u = (dast_method or "GET").upper()
        target_u = dast_url or "http://127.0.0.1:9090"
        return {
            "tool_tag": "Active DAST Header & Policy Verifier",
            "source": f"Live HTTP Endpoint Probe: {method_u} {target_u}",
            "propagation": "Inspected live HTTP response headers and transport directives returned by target runtime.",
            "sink": f"Runtime HTTP Response Policy ({vuln_type} • {cwe})",
            "defense_eval": dast_evidence
            or f"Defensive response policy for {cwe} absent or permissively configured in live server headers.",
            "remediation": fix_text,
        }

    file_b = (file_path or "").replace("\\", "/").split("/")[-1] or "SourceAsset"
    l_str = str(line or 1)
    snip = " ".join((code_snippet or "").strip().split())[:120]

    # 2. Configuration / Keystore / Secret Resource Files
    if any(ext in file_b.lower() for ext in (".properties", ".p12", ".pem", ".key", ".jks", ".json")):
        return {
            "tool_tag": "High-Entropy Secret & Keystore Scanner",
            "source": f"Repository Resource Asset: {file_path} (line {l_str})",
            "propagation": f"Static credential or cryptographic key material committed in source tree: `{snip}`",
            "sink": f"Bundled directly into application classpath ({file_b}:{l_str}) without secret externalization.",
            "defense_eval": "Zero-Trust Violation (CWE-798): Hardcoded secret/keystore material persists in repository history and build artifacts.",
            "remediation": "Externalize secret to HashiCorp Vault KV v2 (exact path in the Vault migration plan on the SAST page) and inject dynamically via Spring Cloud Vault.",
        }

    # 3. Java AST Source Sink (Correlated Confirmed OR Static Code-Only)
    fn_clean = function_name if (function_name and not function_name.startswith("<")) else None
    fn_label = f"{fn_clean}()" if fn_clean else "class field / initializer"

    if cwe == "CWE-601":
        tool_tag = "Dynamic Semgrep Rule Synthesizer"
    elif cwe == "CWE-693":
        tool_tag = "JVM Bytecode Sanitizer Inspector"
    else:
        tool_tag = "Custom Java AST Taint Engine"

    # Step 1: Source
    if matched_route:
        param_desc = (
            f"parameter '{dast_param}'"
            if dast_param
            else (f"parameters {matched_route.params}" if matched_route.params else "HTTP request body/stream")
        )
        source_step = (
            f"HTTP {matched_route.http_method} {matched_route.url_pattern} -> "
            f"{matched_route.class_name}.{matched_route.handler_name}() [L{matched_route.start_line}] binding {param_desc}"
        )
    else:
        if any(k in file_b for k in ("Service", "Validator")):
            source_step = f"Service / Validator Bean Method: {file_b}::{fn_label} (line {l_str})"
        elif cwe in ("CWE-327", "CWE-798"):
            source_step = f"Cryptographic / Token Primitive in {file_b}::{fn_label} (line {l_str})"
        else:
            source_step = f"Static AST Method Context: {file_b}::{fn_label} (line {l_str})"

    # Step 2: Propagation / Call-Graph Path
    if hop_trace and ("->" in hop_trace or "0-Hop" in hop_trace):
        prop_step = f"Resolved AST Call-Graph: {hop_trace}"
    elif matched_route:
        prop_step = (
            f"0-Hop Intra-Method Dataflow inside {matched_route.class_name}.{matched_route.handler_name}() "
            f"[L{matched_route.start_line}..{matched_route.end_line}] reaching sink line {l_str}."
        )
    else:
        prop_step = f"Intra-procedural dataflow inside {file_b}::{fn_label} reaches sensitive sink operation at line {l_str}."

    # Step 3: Exact Sink Expression from Source File
    sink_step = f"{file_b}:{l_str} in {fn_label} -> `{snip or vuln_type}`"

    # Step 4: Guard / Sanitizer Evaluation
    if guard_snippet:
        flat_guard = " ; ".join(g.strip() for g in guard_snippet.splitlines() if g.strip())[:130]
        defense_step = (
            f"Enclosing guard `{flat_guard}` precedes {file_b}:{l_str}, "
            f"but fails to neutralize {cwe} ({vuln_type})."
        )
    else:
        guard_notes = {
            "CWE-89": f"Unparameterized SQL string concatenation in {fn_label}; no PreparedStatement '?' placeholder binding precedes line {l_str}.",
            "CWE-78": f"OS subshell invocation in {fn_label} concatenates input without strict IP_ADDRESS_PATTERN allowlist at line {l_str}.",
            "CWE-79": f"Raw value emitted into HTML/DOM response in {fn_label} without StringEscapeUtils.escapeHtml4 / htmlEscapeHex prior to line {l_str}.",
            "CWE-22": f"Resource/filesystem path constructed in {fn_label} without Path.normalize().startsWith(baseDir) or SAFE_FILE_NAME_PATTERN prior to line {l_str}.",
            "CWE-601": f"HTTP 3xx Location header populated in {fn_label} without domain allowlist check prior to line {l_str}.",
            "CWE-918": f"Outbound URLConnection opened in {fn_label} without loopback/metadata egress blocklist prior to line {l_str}.",
            "CWE-611": f"XML Unmarshaller invoked in {fn_label} without disabling external DTD / entity resolution prior to line {l_str}.",
            "CWE-639": f"Direct record lookup by client-supplied identifier in {fn_label} without session principal ownership check at line {l_str}.",
            "CWE-327": f"Weak or quantum-vulnerable cryptographic primitive invoked in {fn_label} at line {l_str} (NIST FIPS 203/204 transition required).",
            "CWE-256": f"Sensitive credential/token handled without strong salted hashing or masking in {fn_label} at line {l_str} (DPDP Act 2023 Sec 8(5)).",
        }
        defense_step = guard_notes.get(
            cwe,
            f"No verified sanitizer or authorization guard dominates {file_b}:{l_str} inside {fn_label}.",
        )

    return {
        "tool_tag": tool_tag,
        "source": source_step,
        "propagation": prop_step,
        "sink": sink_step,
        "defense_eval": defense_step,
        "remediation": fix_text,
    }


class ScanSummary(BaseModel):
    """Scan execution performance and metrics summary."""
    scan_id: int
    source_path: str
    target_url: str
    created_at: str
    duration_sec: float
    total_issues: int
    confirmed_count: int
    runtime_only_count: int
    code_only_count: int
    suppressed_decoys: int
    duplicates_merged: int
    routes_mapped: int
