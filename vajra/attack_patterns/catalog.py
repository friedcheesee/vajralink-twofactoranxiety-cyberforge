"""
First-class Attack Pattern Catalog.

Answers "What attack patterns do you cover, and how do you approach each one in SAST, DAST and SCA?"
Each pattern is a typed record that ties together:
    taxonomy   : MITRE CAPEC, ATT&CK technique, CWE family (canonical + aliases), OWASP Top-10 2021 category
    SAST       : the exact Java sink APIs / preconditions we look for, which engines cover it, which guards make it safe
    DAST       : the probe strategy and the evidence that proves it, the probe ids used by vajra.dast.http_verifier
    SCA        : library advisories / symbols that implement the same attack
    AI         : how the AI micro-agent adapts payloads to filter tiers (e.g. progressively stricter filter tiers)

`compute_coverage()` overlays live scan results so the UI can show, per pattern, how many sinks / probes /
confirmed issues / engines matched.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from pydantic import BaseModel, Field

from vajra.models import canonicalize_cwe


class AttackPattern(BaseModel):
    pattern_id: str
    name: str
    summary: str
    capec: List[str] = Field(default_factory=list)
    capec_note: Optional[str] = None
    attck: List[str] = Field(default_factory=list)
    canonical_cwe: str
    cwe_aliases: List[str] = Field(default_factory=list)
    owasp: str
    severity: str = "HIGH"
    # SAST
    sast_sinks: List[str] = Field(default_factory=list)
    sast_guards: List[str] = Field(default_factory=list)
    sast_engines: List[str] = Field(default_factory=list)
    # DAST
    dast_probe_ids: List[str] = Field(default_factory=list)
    dast_strategy: str = ""
    dast_proof: str = ""
    dast_verifiable: bool = True
    # SCA
    sca_links: List[str] = Field(default_factory=list)
    # AI
    ai_adaptation: str = ""
    remediation: str = ""
    # ILLUSTRATIVE ONLY: class names from the bundled demo app (SasanLabs/VulnerableApp) showing what this pattern looks like.
    # Static documentation, never scan output; the UI must not present these as findings from the scanned project.
    illustrative_examples: List[str] = Field(default_factory=list)


E_AST = "Java AST Taint"
E_SIG = "Sink-Signature Scanner"
E_SEC = "Secret & Key Scanner"
E_SEM = "Semgrep (synthesized Java rules)"
E_DEC = "Sanitizer / Decoy Inspector"

ATTACK_PATTERN_CATALOG: List[AttackPattern] = [
    AttackPattern(
        pattern_id="AP-01-SQLI", name="SQL Injection", capec=["CAPEC-66"], attck=["T1190"],
        summary="Attacker-controlled data is concatenated into a SQL statement, changing its structure.",
        canonical_cwe="CWE-89", cwe_aliases=["CWE-564", "CWE-943"], owasp="A03:2021-Injection", severity="CRITICAL",
        sast_sinks=["JdbcTemplate.query/update/execute(<dynamic SQL>)", "Statement.executeQuery/executeUpdate", "Connection.prepareStatement(<concat>)", "EntityManager.createNativeQuery(<concat>)"],
        sast_guards=["PreparedStatement '?' placeholders + setString/setInt", "Variant.SECURE", "ORM parameter binding"],
        sast_engines=[E_AST, E_SIG, E_SEM, E_DEC],
        dast_probe_ids=["sqli_quote", "sqli_agentic_comment_bypass", "sqli_boolean_true", "sqli_union"],
        dast_strategy="Baseline-vs-diagnostic differential: single quote for grammar fault, boolean TRUE/FALSE body diff, UNION marker echo; AI comment-whitespace bypass when a naive keyword filter is detected.",
        dast_proof="DB grammar error absent in baseline, or VAJRA_SQLI_PROOF marker reflected, or TRUE/FALSE response-size differential.",
        sca_links=["com.h2database:h2 (JDBC driver advisories)", "Hibernate/JPA advisories"],
        ai_adaptation="Reads the guard snippet (space/comment strip) and switches to /**/ comment whitespace or case-folded keywords.",
        remediation="Parameterised queries (PreparedStatement '?') or ORM binding; never concatenate request data into SQL.",
        illustrative_examples=["ErrorBasedSQLInjectionVulnerability", "UnionBasedSQLInjectionVulnerability", "BlindSQLInjectionVulnerability", "AuthLoginService (cross-class @Service)"],
    ),
    AttackPattern(
        pattern_id="AP-02-CMDINJ", name="OS Command Injection", capec=["CAPEC-88"], attck=["T1059.004"],
        summary="Request data reaches a shell / process launcher, letting the attacker append commands.",
        canonical_cwe="CWE-78", cwe_aliases=["CWE-77", "CWE-88"], owasp="A03:2021-Injection", severity="CRITICAL",
        sast_sinks=["new ProcessBuilder(\"sh\",\"-c\", \"…\" + input)", "Runtime.getRuntime().exec(<dynamic>)"],
        sast_guards=["IP_ADDRESS_PATTERN regex allow-list", "argument array without a subshell"],
        sast_engines=[E_AST, E_SIG, E_SEM, E_DEC],
        dast_probe_ids=["cmd_sh", "cmd_agentic_ifs"],
        dast_strategy="Append `; echo VAJRA_CMD_PROOF` (and ${IFS} space-free variant for blacklist tiers).",
        dast_proof="Canary string present in response only when the injected command ran.",
        ai_adaptation="Replaces blacklisted spaces with ${IFS} / tabs when the guard strips whitespace.",
        remediation="Pass arguments as an array without a subshell, or validate against a strict allow-list.",
        illustrative_examples=["CommandInjection (5 levels -> 1 shared helper sink)"],
    ),
    AttackPattern(
        pattern_id="AP-03-PATHTRAV", name="Path Traversal / Arbitrary File Read", capec=["CAPEC-126"], attck=["T1083"],
        summary="User-supplied file name escapes the intended directory (../ sequences, encodings).",
        canonical_cwe="CWE-22", cwe_aliases=["CWE-23", "CWE-36", "CWE-73"], owasp="A01:2021-Broken Access Control", severity="HIGH",
        sast_sinks=["Class.getResourceAsStream(base + name)", "new FileInputStream/File(<dynamic>)", "Paths.get/Files.read*(<dynamic>)"],
        sast_guards=["SAFE_FILE_NAME_PATTERN", "ALLOWED_FILE_NAMES", "Path.normalize().startsWith(base)"],
        sast_engines=[E_AST, E_SIG, E_SEM, E_DEC],
        dast_probe_ids=["trav_etc", "trav_agentic_nested"],
        dast_strategy="../../../../etc/passwd and nested ....// sequences that survive single-pass replace().",
        dast_proof="root:x:0:0 marker in the body, absent from the baseline.",
        ai_adaptation="Chooses nested/encoded sequences when the guard replaces '../' once.",
        remediation="Canonicalise and verify containment inside the base directory; allow-list file names.",
        illustrative_examples=["PathTraversalVulnerability.readFile"],
    ),
    AttackPattern(
        pattern_id="AP-04-XSS", name="Cross-Site Scripting (reflected / stored / DOM)", capec=["CAPEC-591", "CAPEC-592", "CAPEC-588"], attck=["T1189"],
        summary="Unescaped request data is emitted into an HTML/JS context and executes in the victim's browser.",
        canonical_cwe="CWE-79", cwe_aliases=["CWE-80", "CWE-83", "CWE-87"], owasp="A03:2021-Injection", severity="HIGH",
        sast_sinks=["ResponseEntity<String> built from String.format/concat with HTML", "template placeholders without escaping"],
        sast_guards=["StringEscapeUtils.escapeHtml4", "HtmlUtils.htmlEscape/htmlEscapeHex", "Encode.forHtml"],
        sast_engines=[E_AST, E_DEC],
        dast_probe_ids=["xss_canary_script", "xss_canary_svg_onload", "xss_canary_img_onerror", "xss_attribute_breakout"],
        dast_strategy="Inject window.__vajra_xss canary payloads; confirm execution in headless Chromium (HTTP-reflection fallback if the browser is unavailable).",
        dast_proof="window.__vajra_xss === 1 and a screenshot of the executed DOM.",
        ai_adaptation="Switches from <script> to <svg onload>, <img onerror> or attribute breakout depending on tag/quote filters.",
        remediation="Context-aware output encoding; Content-Security-Policy as defence in depth.",
        illustrative_examples=["XSSWithHtmlTagInjection", "XSSInImgTagAttribute", "PersistentXSSInHTMLTagVulnerability"],
    ),
    AttackPattern(
        pattern_id="AP-05-SSRF", name="Server-Side Request Forgery", capec=["CAPEC-664"], attck=["T1190"],
        summary="The server fetches an attacker-chosen URL, reaching internal services / cloud metadata.",
        canonical_cwe="CWE-918", owasp="A10:2021-Server-Side Request Forgery", severity="HIGH",
        sast_sinks=["URL.openConnection() / openStream() with request-derived URL", "RestTemplate.getForObject(<dynamic>)"],
        sast_guards=["WHITELISTED_URLS allow-list", "private-address / loopback blocklist"],
        sast_engines=[E_AST, E_SIG, E_DEC],
        dast_probe_ids=["ssrf_metadata"],
        dast_strategy="Point the URL parameter at 169.254.169.254 / loopback and look for metadata markers.",
        dast_proof="Internal metadata marker in the proxied response.",
        remediation="Allow-list destinations; block loopback, link-local and private ranges; no redirects.",
        illustrative_examples=["SSRFVulnerability (2-hop helper sink)"],
    ),
    AttackPattern(
        pattern_id="AP-06-XXE", name="XML External Entity Injection", capec=["CAPEC-221"],
        capec_note="CAPEC-201 (Serialized Data External Linking) is the related parent.", attck=["T1190"],
        summary="An XML parser resolves attacker-defined external entities (file read, SSRF).",
        canonical_cwe="CWE-611", owasp="A05:2021-Security Misconfiguration", severity="HIGH",
        sast_sinks=["JAXB Unmarshaller.unmarshal(<request stream>)", "DocumentBuilderFactory / SAXParserFactory without hardening"],
        sast_guards=["disallow-doctype-decl", "XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES=false", "FEATURE_SECURE_PROCESSING"],
        sast_engines=[E_AST, E_SIG, E_DEC],
        dast_probe_ids=["xxe_external_entity"],
        dast_strategy="POST a DOCTYPE with SYSTEM entity file:///etc/passwd.",
        dast_proof="root:x:0:0 expanded inside the XML response.",
        sca_links=["org.glassfish.jaxb:jaxb-runtime", "javax.xml.bind:jaxb-api"],
        remediation="Disable DTDs and external entity resolution on every parser.",
        illustrative_examples=["XXEVulnerability"],
    ),
    AttackPattern(
        pattern_id="AP-07-IDOR", name="Insecure Direct Object Reference / Broken Object-Level Authorization", capec=["CAPEC-1", "CAPEC-122"],
        capec_note="No dedicated CAPEC; closest is access-control bypass (CAPEC-1) / privilege abuse (CAPEC-122).", attck=["T1078"],
        summary="A client-supplied identifier selects a record without an ownership check.",
        canonical_cwe="CWE-639", cwe_aliases=["CWE-285"], owasp="A01:2021-Broken Access Control", severity="HIGH",
        sast_sinks=["repository/jdbc lookup by request id without principal comparison", "role taken from client cookie"],
        sast_guards=["server-side session principal match", "Variant.SECURE"],
        sast_engines=[E_AST, E_DEC],
        dast_probe_ids=["idor_id_swap"],
        dast_strategy="Request another user's identifier and compare the body to the baseline record.",
        dast_proof="Foreign record (profile / salary) returned.",
        remediation="Authorise every object access against the authenticated principal.",
        illustrative_examples=["IDORVulnerability LEVEL_1..4"],
    ),
    AttackPattern(
        pattern_id="AP-08-OPENREDIR", name="Open Redirect", capec=[], capec_note="No dedicated CAPEC entry; tracked via CWE-601 and ATT&CK T1204.001 (malicious link).", attck=["T1204.001"],
        summary="A redirect target is taken from the request, enabling phishing via a trusted domain.",
        canonical_cwe="CWE-601", owasp="A01:2021-Broken Access Control", severity="MEDIUM",
        sast_sinks=["headers.add(\"Location\", <request value>)", "response.sendRedirect(<dynamic>)"],
        sast_guards=["REDIRECT_DESTINATIONS lookup map", "WHITELISTED_URLS set", "relative-URL check"],
        sast_engines=[E_AST, E_SIG, E_DEC],
        dast_probe_ids=["open_redirect", "open_redirect_schema_less"],
        dast_strategy="Supply https:// and //host destinations; inspect the 3xx Location header without following it.",
        dast_proof="3xx status with Location pointing at the injected host.",
        remediation="Redirect only to server-side-mapped or relative destinations.",
        illustrative_examples=["Http3xxStatusCodeBasedInjection"],
    ),
    AttackPattern(
        pattern_id="AP-09-JWT", name="JWT / Token Forgery & Weak Signature Handling", capec=["CAPEC-196"], attck=["T1550.001"],
        summary="Tokens are accepted with alg=none, weak HMAC secrets, client-controlled keys or missing validation.",
        canonical_cwe="CWE-798", cwe_aliases=["CWE-347", "CWE-522", "CWE-1188"], owasp="A02:2021-Cryptographic Failures", severity="HIGH",
        sast_sinks=["custom HMAC validator skipping signature", "NONE_ALGORITHM accepted", "weak/static signing key", "token stored client-side"],
        sast_guards=["library-verified signature with algorithm allow-list", "Variant.SECURE"],
        sast_engines=[E_AST, E_DEC],
        dast_strategy="Code-level weakness: not provable by a single stateless probe in this build (stays Code-only).",
        dast_proof="n/a (SAST-confirmed)", dast_verifiable=False,
        sca_links=["com.nimbusds:nimbus-jose-jwt"],
        remediation="Verify signatures with a vetted library, pin algorithms, keep keys in a vault, rotate secrets.",
        illustrative_examples=["JWTVulnerability", "JWTValidator"],
    ),
    AttackPattern(
        pattern_id="AP-10-CRYPTO", name="Weak / Quantum-Vulnerable Cryptography", capec=["CAPEC-97"], attck=["T1600"],
        summary="Broken hashes, ciphers, RNGs or RSA-class asymmetric crypto that falls to Shor/Grover-era attacks.",
        canonical_cwe="CWE-327", cwe_aliases=["CWE-326", "CWE-328", "CWE-330", "CWE-338", "CWE-916"], owasp="A02:2021-Cryptographic Failures", severity="HIGH",
        sast_sinks=["MessageDigest.getInstance(MD5|SHA-1)", "Cipher.getInstance(DES|RC4|AES/ECB)", "new Random() for tokens", "BCrypt cost < 12"],
        sast_guards=["SecureRandom", "Argon2 / BCrypt(12+)", "SHA-256+ with salt"],
        sast_engines=[E_AST, E_SIG, E_DEC],
        dast_strategy="Code/config property; TLS cipher audit is covered by the header/TLS stage.", dast_proof="n/a (SAST-confirmed)", dast_verifiable=False,
        sca_links=["org.bouncycastle:bcprov-jdk18on"],
        remediation="Move to AES-256-GCM, SHA-384+, Argon2id; plan NIST FIPS 203/204 (ML-KEM / ML-DSA) migration.",
        illustrative_examples=["CryptographicFailuresVulnerability", "PasswordHashingUtils"],
    ),
    AttackPattern(
        pattern_id="AP-11-SECRETS", name="Hard-coded Secrets & Key Material", capec=["CAPEC-191"], attck=["T1552.001"],
        summary="Passwords, tokens, keystores and private keys committed to source or resources.",
        canonical_cwe="CWE-798", cwe_aliases=["CWE-259", "CWE-321"], owasp="A07:2021-Identification and Authentication Failures", severity="HIGH",
        sast_sinks=["String PASSWORD/SECRET/TOKEN = \"literal\"", "*.properties credentials", ".p12/.pem key files"],
        sast_guards=["environment / HashiCorp Vault injection"],
        sast_engines=[E_SEC, E_SIG, E_AST],
        dast_strategy="Not network-observable; Vault KV v2 migration plan is generated from the findings.", dast_proof="n/a (SAST-confirmed)", dast_verifiable=False,
        remediation="Externalise to HashiCorp Vault KV v2 / env; rotate anything ever committed.",
        illustrative_examples=["messages.properties", "sasanlabs.p12", "private_key.pem"],
    ),
    AttackPattern(
        pattern_id="AP-12-UPLOAD", name="Unrestricted File Upload", capec=["CAPEC-650"], attck=["T1505.003"],
        summary="Uploaded files are stored under attacker-chosen names/types without validation.",
        canonical_cwe="CWE-434", cwe_aliases=["CWE-730", "CWE-400"], owasp="A04:2021-Insecure Design", severity="HIGH",
        sast_sinks=["MultipartFile.getOriginalFilename() used in a path", "Files.copy / transferTo without type check"],
        sast_guards=["extension + magic-byte allow-list", "random server-side name", "store outside web root"],
        sast_engines=[E_AST, E_SIG],
        dast_strategy="Multipart upload probes are not part of this build (stays Code-only).", dast_proof="n/a (SAST-confirmed)", dast_verifiable=False,
        sca_links=["commons-fileupload:commons-fileupload"],
        remediation="Validate type/extension/content, randomise names, store outside the web root.",
        illustrative_examples=["UnrestrictedFileUpload"],
    ),
    AttackPattern(
        pattern_id="AP-13-LDAPI", name="LDAP Injection", capec=["CAPEC-136"], attck=["T1190"],
        summary="User input is concatenated into an LDAP filter or DN.",
        canonical_cwe="CWE-90", owasp="A03:2021-Injection", severity="HIGH",
        sast_sinks=["connection.search(base, scope, <concatenated filter>)"],
        sast_guards=["Filter.encodeValue", "LdapEncoder"],
        sast_engines=[E_AST, E_SIG, E_DEC],
        dast_strategy="Wildcard / tautology filter probe (not enabled in this build).", dast_proof="n/a (SAST-confirmed)", dast_verifiable=False,
        sca_links=["com.unboundid:unboundid-ldapsdk"],
        remediation="Escape filter values (RFC 4515) or use parameterised filters.",
        illustrative_examples=["LDAPInjectionVulnerability"],
    ),
    AttackPattern(
        pattern_id="AP-14-HEADERS", name="Security Misconfiguration: Clickjacking & Missing Headers", capec=["CAPEC-103"], attck=[], capec_note="ATT&CK has no clickjacking technique; tracked via CAPEC-103 and CWE-1021.",
        summary="Responses omit CSP / X-Frame-Options / nosniff or set them permissively (ALLOWALL).",
        canonical_cwe="CWE-693", cwe_aliases=["CWE-1021", "CWE-614", "CWE-1004", "CWE-942", "CWE-349"], owasp="A05:2021-Security Misconfiguration", severity="MEDIUM",
        sast_sinks=["headers.add(\"X-Frame-Options\", \"ALLOWALL\")", "missing frame-ancestors"],
        sast_guards=["X-Frame-Options: DENY/SAMEORIGIN", "CSP frame-ancestors"],
        sast_engines=[E_AST, E_SIG],
        dast_probe_ids=["header_audit"],
        dast_strategy="Passive response-header / cookie / CORS / TLS audit on every reachable origin.",
        dast_proof="Absent or permissive header observed in the live response.",
        remediation="Set CSP, X-Frame-Options, X-Content-Type-Options, HSTS and secure cookie attributes globally.",
        illustrative_examples=["ClickjackingVulnerability", "global response headers"],
    ),
    AttackPattern(
        pattern_id="AP-15-AUTH", name="Broken Authentication, Session & Password-Reset Logic", capec=["CAPEC-50", "CAPEC-60"], attck=["T1110", "T1550"],
        summary="Plaintext credentials, predictable reset tokens / session ids, user enumeration, no rate limiting, session fixation.",
        canonical_cwe="CWE-256", cwe_aliases=["CWE-200", "CWE-204", "CWE-307", "CWE-319", "CWE-384", "CWE-613", "CWE-640"], owasp="A07:2021-Identification and Authentication Failures", severity="HIGH",
        sast_sinks=["plaintext password compare/log", "reset token = 'reset-' + userId", "Random for session ids", "no attempt counter"],
        sast_guards=["Argon2/BCrypt(12)", "SecureRandom / UUID tokens", "session regeneration on login"],
        sast_engines=[E_AST, E_SIG, E_DEC],
        dast_strategy="Stateful multi-step flows; stays Code-only in this build.", dast_proof="n/a (SAST-confirmed)", dast_verifiable=False,
        remediation="Strong salted hashing, unpredictable tokens, uniform errors, rate limiting, session rotation (DPDP Act 2023 Sec 8(5)).",
        illustrative_examples=["AuthLoginService", "PasswordResetService", "SessionManagementService"],
    ),
]

_PATTERN_BY_CWE: Dict[str, AttackPattern] = {}
for _p in ATTACK_PATTERN_CATALOG:
    _PATTERN_BY_CWE[_p.canonical_cwe] = _p
    for _a in _p.cwe_aliases:
        _PATTERN_BY_CWE.setdefault(canonicalize_cwe(_a), _p)
# AP-09 / AP-11 share the CWE-798 cluster; keep JWT as the default owner and route secrets by finding type below
_SECRETS = next(p for p in ATTACK_PATTERN_CATALOG if p.pattern_id == "AP-11-SECRETS")
_JWT = next(p for p in ATTACK_PATTERN_CATALOG if p.pattern_id == "AP-09-JWT")


def pattern_for(cwe: str, vuln_type: str = "", file_path: str = "") -> Optional[AttackPattern]:
    """Map a finding to its attack pattern (CWE-798 is split between JWT forgery and hard-coded secrets)."""
    canon = canonicalize_cwe(cwe)
    if canon == "CWE-798":
        text = f"{vuln_type} {file_path}".lower()
        if "jwt" in text or "jwtvalidator" in text or "jwtvulnerability" in text:
            return _JWT
        return _SECRETS
    return _PATTERN_BY_CWE.get(canon)


def compute_coverage(
    sast_active: Iterable[Any],
    dast_findings: Iterable[Any],
    issues: Iterable[Any],
    sca_report: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Overlay live scan results onto the catalog."""
    rows: Dict[str, Dict[str, Any]] = {
        p.pattern_id: {
            "pattern": p.model_dump(),
            "sast_sinks": 0,
            "sast_engines_seen": {},
            "dast_probes": 0,
            "dast_discovery": {},
            "confirmed": 0,
            "runtime_only": 0,
            "code_only": 0,
            "sca_findings": 0,
        }
        for p in ATTACK_PATTERN_CATALOG
    }
    for f in sast_active:
        p = pattern_for(f.cwe, f.vuln_type or "", f.file_path or "")
        if not p:
            continue
        r = rows[p.pattern_id]
        r["sast_sinks"] += 1
        for e in (f.engines or [f.scanner]):
            r["sast_engines_seen"][e] = r["sast_engines_seen"].get(e, 0) + 1
    for d in dast_findings:
        p = pattern_for(d.cwe, d.vuln_type or "", d.url or "")
        if not p:
            continue
        r = rows[p.pattern_id]
        r["dast_probes"] += 1
        disc = getattr(d, "discovery", None) or "unknown"
        r["dast_discovery"][disc] = r["dast_discovery"].get(disc, 0) + 1
    for i in issues:
        p = pattern_for(i.cwe, i.vuln_type or "", i.file_path or i.url or "")
        if not p:
            continue
        r = rows[p.pattern_id]
        if i.status == "Confirmed":
            r["confirmed"] += 1
        elif i.status == "Runtime only":
            r["runtime_only"] += 1
        else:
            r["code_only"] += 1
    if sca_report:
        text_links = {pid: [l.lower() for l in p.sca_links] for pid, p in ((p.pattern_id, p) for p in ATTACK_PATTERN_CATALOG)}
        for v in sca_report.get("vulnerabilities", []):
            pkg = (v.get("package") or "").lower()
            for pid, links in text_links.items():
                if any(pkg and (pkg in l or l.split(" ")[0] == pkg) for l in links):
                    rows[pid]["sca_findings"] += 1
    out: List[Dict[str, Any]] = []
    for pid, r in rows.items():
        r["covered_static"] = r["sast_sinks"] > 0
        r["covered_dynamic"] = r["dast_probes"] > 0
        out.append(r)
    return out
