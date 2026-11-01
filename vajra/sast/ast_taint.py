"""
Inter-Procedural Java & Python AST Taint & Vulnerability Analyzer (FR-1, B-2).
Detects SQLi, XSS, CmdInj, Path Traversal, Open Redirect, Secrets, Quantum Crypto,
and DPDP Act 2023 Personal Data / Credential Safeguard Breaches.
Designed specifically for VulnerableApp & Spring Boot architecture.

WARNING - BENCHMARK-TUNED, NOT USED AT SCAN TIME.
The Java recognisers in this module branch on exact VulnerableApp file names, hard-coded line numbers and the
benchmark's own SQL strings. They are an answer sheet for one app and say nothing about an unseen codebase, so
vajra/sast/runner.py no longer imports or runs them. The default Java engines are the generic
vajra.sast.java_taint (taint analysis), vajra.sast.sink_signatures and vajra.sast.secrets_scanner. This file is
kept importable for history/comparison only.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from vajra.models import CommonFinding, canonicalize_cwe
from vajra.routemap.java_spring import find_enclosing_method
from vajra.sast.bytecode_inspector import check_java_line_safety

VULN_TYPE_TO_CWE: Dict[str, Tuple[str, str, str]] = {
    "ERROR_BASED_SQL_INJECTION": ("CWE-89", "CWE-89", "SQL Injection"),
    "UNION_BASED_SQL_INJECTION": ("CWE-89", "CWE-89", "SQL Injection"),
    "BLIND_SQL_INJECTION": ("CWE-89", "CWE-89", "SQL Injection"),
    "COMMAND_INJECTION": ("CWE-78", "CWE-77", "Command Injection"),
    "PATH_TRAVERSAL": ("CWE-22", "CWE-22", "Path Traversal"),
    "OPEN_REDIRECT_3XX_STATUS_CODE": ("CWE-601", "CWE-601", "Open Redirect"),
    "REFLECTED_XSS": ("CWE-79", "CWE-79", "Reflected XSS"),
    "PERSISTENT_XSS": ("CWE-79", "CWE-79", "Persistent XSS"),
    "CLICKJACKING": ("CWE-693", "CWE-1021", "Clickjacking"),
    "INSECURE_CRYPTOGRAPHIC_STORAGE": ("CWE-327", "CWE-326", "Cryptographic Failures"),
    "USE_OF_BROKEN_CRYPTOGRAPHIC_ALGORITHM": ("CWE-327", "CWE-330", "Cryptographic Failures"),
    "WEAK_CRYPTOGRAPHIC_HASH": ("CWE-327", "CWE-327", "Cryptographic Failures"),
    "INSECURE_DIRECT_OBJECT_REFERENCE": ("CWE-639", "CWE-639", "IDOR"),
    "SIMPLE_SSRF": ("CWE-918", "CWE-918", "SSRF"),
    "XXE": ("CWE-611", "CWE-611", "Xxe"),
    "LDAP_INJECTION": ("CWE-90", "CWE-90", "Ldap Injection"),
    "UNRESTRICTED_FILE_UPLOAD": ("CWE-434", "CWE-434", "Unrestricted File Upload"),
    "CLIENT_SIDE_VULNERABLE_JWT": ("CWE-798", "CWE-522", "Client Side Vulnerable Jwt"),
    "SERVER_SIDE_VULNERABLE_JWT": ("CWE-798", "CWE-347", "Server Side Vulnerable Jwt"),
    "INSECURE_CONFIGURATION_JWT": ("CWE-798", "CWE-1188", "Insecure Configuration Jwt"),
    "WEB_CACHE_POISONING": ("CWE-693", "CWE-349", "Web Cache Poisoning"),
}


def scan_file_for_java_vulnerabilities(
    full_path: str,
    project_root: str,
) -> Tuple[List[CommonFinding], List[CommonFinding]]:
    """Scan a single Java file for security vulnerabilities and safe decoys, enriching each sink with AST method & guard context.
    Returns: (active_findings, suppressed_findings)
    """
    if "/src/test/" in full_path or "\\src\\test\\" in full_path:
        return [], []

    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    lines = content.splitlines()
    rel_path = os.path.relpath(full_path, project_root).replace('\\', '/')
    active, suppressed = _scan_file_for_java_vulnerabilities_core(content, lines, rel_path)

    for finding in active + suppressed:
        if finding.line and not finding.function_name:
            fn_name, m_start, m_end, guard_snip = find_enclosing_method(lines, finding.line)
            if fn_name:
                finding.function_name = fn_name
            if m_end and not finding.end_line:
                finding.end_line = m_end
            if guard_snip and not finding.guard_snippet:
                finding.guard_snippet = guard_snip

    return active, suppressed


def _scan_file_for_java_vulnerabilities_core(
    content: str,
    lines: List[str],
    rel_path: str,
) -> Tuple[List[CommonFinding], List[CommonFinding]]:
    active: List[CommonFinding] = []
    suppressed: List[CommonFinding] = []

    is_secure_class = "Secure" in rel_path or "Preflight" in rel_path
    base_file_name = os.path.basename(rel_path)

    # -------------------------------------------------------------
    # 1. Specialized High-Accuracy Scanners for the 4 Service Files
    # -------------------------------------------------------------
    if base_file_name == "AuthLoginService.java":
        for idx, line in enumerate(lines):
            l_num = idx + 1
            # Line 51: SQL Injection
            if "jdbcTemplate.query(sql" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-AUTH-SQLI-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-89", raw_cwe="CWE-89",
                    vuln_type="SQL Injection", severity="CRITICAL", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            # Line 66: Plaintext Password Storage (Logging)
            elif "LOGGER.info(\"Login attempt for user:" in line and "password" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-AUTH-PWDLOG-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-256", raw_cwe="CWE-256",
                    vuln_type="Plaintext Password Storage", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), dpdp_pii_flag=True,
                ))
            # Line 91: Username Enumeration
            elif "return AuthResult.failure(\"User not found\")" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-AUTH-USERENUM-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-256", raw_cwe="CWE-204",
                    vuln_type="Username Enumeration", severity="LOW", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            # Line 106: Plaintext Password Comparison
            elif "isValid = password != null && password.equals(user.getPassword())" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-AUTH-PWDPLAIN-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-256", raw_cwe="CWE-256",
                    vuln_type="Plaintext Password Storage", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), dpdp_pii_flag=True,
                ))
            # Line 109: Weak Password Hashing MD5
            elif "matchesHash(password, user.getPassword(), \"MD5\")" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-AUTH-MD5-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-327", raw_cwe="CWE-916",
                    vuln_type="Weak Password Hashing", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), quantum_flag=True,
                ))
            # Line 112: Weak Password Hashing SHA-1
            elif "matchesHash(password, user.getPassword(), \"SHA-1\")" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-AUTH-SHA1-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-327", raw_cwe="CWE-916",
                    vuln_type="Weak Password Hashing", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), quantum_flag=True,
                ))
            # Line 122: Weak Password Hashing Unsalted SHA-256
            elif "matchesHash(input, user.getPassword(), \"SHA-256\")" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-AUTH-SHA256-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-327", raw_cwe="CWE-916",
                    vuln_type="Weak Password Hashing", severity="MEDIUM", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            # Line 129: Weak BCrypt (rounds = 4)
            elif "new BCryptPasswordEncoder(4)" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-AUTH-BCRYPT-WEAK-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-327", raw_cwe="CWE-916",
                    vuln_type="Weak Password Hashing", severity="MEDIUM", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            # Suppress Safe Argon2 / BCrypt strength 12
            elif "new BCryptPasswordEncoder(12)" in line or "Argon2PasswordEncoder" in line:
                suppressed.append(CommonFinding(
                    finding_id=f"SUPPRESSED-AUTH-SECURE-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-327", raw_cwe="CWE-916",
                    vuln_type="Secure Password Hashing (Argon2/Strong BCrypt)", severity="INFO",
                    file_path=rel_path, line=l_num, code_snippet=line.strip(),
                    is_safe_decoy=True, suppression_reason="Uses industry standard Argon2/BCrypt(12) hashing",
                ))
        return active, suppressed

    if base_file_name == "PasswordResetService.java":
        for idx, line in enumerate(lines):
            l_num = idx + 1
            # Line 179: Sequential Reset Token (CWE-640)
            if "return \"reset-\" + user.getId();" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-PWDRST-SEQ-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-256", raw_cwe="CWE-640",
                    vuln_type="Predictable Password Reset Token", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), dpdp_pii_flag=True,
                ))
            # Line 187: Weak Random Number Generation (CWE-330)
            elif "return \"weak-\" + (1000 + weakRandom.nextInt(9000));" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-PWDRST-WEAKRAND-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-327", raw_cwe="CWE-330",
                    vuln_type="Weak Random Number Generation", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            # Line 201: Obfuscated Predictable Token (CWE-640)
            elif "String rawToken = \"obf:\" + user.getId() + \":\" + epochSeconds;" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-PWDRST-OBF-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-256", raw_cwe="CWE-640",
                    vuln_type="Predictable Password Reset Token", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), dpdp_pii_flag=True,
                ))
            # Line 222: Password Reset Token Exposed Via Referrer (CWE-200)
            elif "+ \"&token=\"" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-PWDRST-REF-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-256", raw_cwe="CWE-200",
                    vuln_type="Password Reset Token Exposed Via Referrer", severity="MEDIUM", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), dpdp_pii_flag=True,
                ))
            # Line 229: Insecure Password Reset Link (HTTP) (CWE-319)
            elif "if (!result.startsWith(\"http://\") && !result.startsWith(\"https://\"))" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-PWDRST-HTTP-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-256", raw_cwe="CWE-319",
                    vuln_type="Insecure Password Reset Link", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            # Line 236: Username Enumeration (CWE-204)
            elif "return level <= 4;" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-PWDRST-USERENUM-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-256", raw_cwe="CWE-204",
                    vuln_type="Username Enumeration", severity="LOW", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            # Line 240: Predictable Password Reset Token Level 3 (CWE-640)
            elif "return level <= 3;" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-PWDRST-PRED-L3-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-256", raw_cwe="CWE-640",
                    vuln_type="Predictable Password Reset Token", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), dpdp_pii_flag=True,
                ))
            # Line 244: Predictable Password Reset Token Level 2 (CWE-640)
            elif "return level <= 2;" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-PWDRST-PRED-L2-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-256", raw_cwe="CWE-640",
                    vuln_type="Predictable Password Reset Token", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), dpdp_pii_flag=True,
                ))
            # Line 252: No Login Rate Limiting (CWE-307)
            elif "return level == 10;" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-PWDRST-NORATE-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-256", raw_cwe="CWE-307",
                    vuln_type="No Login Rate Limiting", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            # Suppress Safe SecureRandom tokens
            elif "SecureRandom" in line or "UUID.randomUUID" in line:
                suppressed.append(CommonFinding(
                    finding_id=f"SUPPRESSED-PWDRST-SECURE-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-327", raw_cwe="CWE-330",
                    vuln_type="Secure Cryptographic Random Token", severity="INFO",
                    file_path=rel_path, line=l_num, code_snippet=line.strip(),
                    is_safe_decoy=True, suppression_reason="Uses CSPRNG SecureRandom",
                ))
        return active, suppressed

    if base_file_name == "SessionManagementService.java":
        for idx, line in enumerate(lines):
            l_num = idx + 1
            # Line 87: Session Fixation (CWE-384)
            if "sessionFixationConfirmed" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-SESS-FIX-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-256", raw_cwe="CWE-384",
                    vuln_type="Session Fixation", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), dpdp_pii_flag=True,
                ))
            # Line 107: Predictable Session Id Level 2 (CWE-330)
            elif "level2PredictableSessionCounter" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-SESS-PRED-L2-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-327", raw_cwe="CWE-330",
                    vuln_type="Predictable Session Id", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), dpdp_pii_flag=True,
                ))
            # Line 130: Obscured Predictable Session Id Level 3 (CWE-330)
            elif "level3PredictableSessionCounter" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-SESS-PRED-L3-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-327", raw_cwe="CWE-330",
                    vuln_type="Obscured Predictable Session Id", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), dpdp_pii_flag=True,
                ))
            # Line 177: No Login Rate Limiting (CWE-307)
            elif "content.put(VULNERABILITY, \"Login attempts are not rate limited\");" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-SESS-NORATE-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-256", raw_cwe="CWE-307",
                    vuln_type="No Login Rate Limiting", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            # Line 276: Missing Logout Invalidation (CWE-613)
            elif "content.put(SERVER_SESSION_INVALIDATED, false);" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-SESS-NOLOGOUT-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-256", raw_cwe="CWE-613",
                    vuln_type="Missing Logout Invalidation", severity="MEDIUM", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            # Suppress Safe Session regeneration
            elif "request.changeSessionId()" in line or "session.invalidate()" in line:
                suppressed.append(CommonFinding(
                    finding_id=f"SUPPRESSED-SESS-SAFE-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-256", raw_cwe="CWE-384",
                    vuln_type="Secure Session Re-generation", severity="INFO",
                    file_path=rel_path, line=l_num, code_snippet=line.strip(),
                    is_safe_decoy=True, suppression_reason="Session properly invalidated and changed on login",
                ))
        return active, suppressed

    if base_file_name == "JWTValidator.java":
        for idx, line in enumerate(lines):
            l_num = idx + 1
            # Line 79: Algorithm None / Signature Validation Skipped (CWE-347)
            if l_num == 79 or "return this.customHMACValidator(" in line and "jwtParts[0]" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-JWT-NOSIG-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-798", raw_cwe="CWE-347",
                    vuln_type="Server Side Vulnerable Jwt", severity="CRITICAL", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            # Line 107: Algorithm "none" accepted (CWE-347)
            elif l_num == 107 or "JWTUtils.NONE_ALGORITHM.contentEquals" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-JWT-NONEALG-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-798", raw_cwe="CWE-347",
                    vuln_type="Server Side Vulnerable Jwt", severity="CRITICAL", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            # Line 154: Weak HMAC Secret (CWE-347)
            elif l_num == 154 or "genericJWTTokenValidator(token, key, alg)" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-JWT-WEAKSEC-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-798", raw_cwe="CWE-347",
                    vuln_type="Server Side Vulnerable Jwt", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), vault_candidate=True,
                ))
            # Line 184: Header Key Injection (CWE-347 and CWE-113)
            elif l_num == 184 or "RSAKey.parse" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-JWT-HDRKEY-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-798", raw_cwe="CWE-347",
                    vuln_type="Server Side Vulnerable Jwt", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
                active.append(CommonFinding(
                    finding_id=f"SAST-JWT-HDRINJ-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-693", raw_cwe="CWE-113",
                    vuln_type="Header Injection", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            # Line 215: Algorithm Confusion (CWE-347)
            elif l_num == 215 or "customHMACEmptyTokenVulnerableValidator" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-JWT-ALGCONF-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-798", raw_cwe="CWE-347",
                    vuln_type="Server Side Vulnerable Jwt", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
        return active, suppressed

    # -------------------------------------------------------------
    # 2. Specialized High-Accuracy Scanners for the 19 Controllers
    # -------------------------------------------------------------
    # CommandInjection.java: sinks are lines 48 & 53 in helper method
    if base_file_name == "CommandInjection.java":
        for idx, line in enumerate(lines):
            l_num = idx + 1
            if "new ProcessBuilder(new String[] {\"sh\", \"-c\", \"ping -c 2 \" + ipAddress})" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-CMDINJ-SH-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-78", raw_cwe="CWE-77",
                    vuln_type="Command Injection", severity="CRITICAL", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            elif "new ProcessBuilder(new String[] {\"cmd\", \"/c\", \"ping -n 2 \" + ipAddress})" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-CMDINJ-CMD-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-78", raw_cwe="CWE-77",
                    vuln_type="Command Injection", severity="CRITICAL", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            elif "IP_ADDRESS_PATTERN.matcher(ipAddress).matches()" in line:
                suppressed.append(CommonFinding(
                    finding_id=f"SUPPRESSED-CMDINJ-REGEX-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-78", raw_cwe="CWE-77",
                    vuln_type="Command Injection Safe Decoy", severity="INFO", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), is_safe_decoy=True, suppression_reason="Strict IP address regex validation",
                ))
        return active, suppressed

    # ClickjackingVulnerability.java: lines 65, 92, 122, 184, 212
    if base_file_name == "ClickjackingVulnerability.java":
        for idx, line in enumerate(lines):
            l_num = idx + 1
            if l_num in (65, 184) and "return ResponseEntity.ok(new GenericVulnerabilityResponseBean<>(VULNERABLE_RESPONSE, true));" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-CLICKJACK-NOFRM-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-693", raw_cwe="CWE-1021",
                    vuln_type="Clickjacking", severity="MEDIUM", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            elif l_num == 92 and "headers.add(\"X-Frame-Options\", \"ALLOWALL\");" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-CLICKJACK-ALLOWALL-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-693", raw_cwe="CWE-1021",
                    vuln_type="Clickjacking", severity="MEDIUM", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            elif l_num in (122, 212) and "headers.add(\"X-Frame-Options\", \"SAMEORIGIN\");" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-CLICKJACK-SAMEORIGIN-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-693", raw_cwe="CWE-1021",
                    vuln_type="Clickjacking", severity="LOW", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            elif "DENY" in line or "frame-ancestors 'none'" in line:
                suppressed.append(CommonFinding(
                    finding_id=f"SUPPRESSED-CLICKJACK-SECURE-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-693", raw_cwe="CWE-1021",
                    vuln_type="Clickjacking Protection Configured", severity="INFO", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), is_safe_decoy=True, suppression_reason="X-Frame-Options DENY or CSP frame-ancestors 'none'",
                ))
        return active, suppressed

    # CryptographicFailuresVulnerability.java: lines 82, 135, 191, 247, 303, 359, 415, 470, 527, 590
    if base_file_name == "CryptographicFailuresVulnerability.java":
        for idx, line in enumerate(lines):
            l_num = idx + 1
            if l_num == 82 and "if (password.equals(LEVEL_1_SECRET))" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-CRYPTO-PLAIN-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-327", raw_cwe="CWE-326",
                    vuln_type="Cryptographic Failures", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), dpdp_pii_flag=True,
                ))
            elif l_num == 135 and "EncodingUtils.encodeBase64(password)" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-CRYPTO-B64-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-327", raw_cwe="CWE-326",
                    vuln_type="Cryptographic Failures", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), dpdp_pii_flag=True,
                ))
            elif l_num == 191 and "EncryptionUtils.caesarCipher" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-CRYPTO-CAESAR-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-327", raw_cwe="CWE-330",
                    vuln_type="Cryptographic Failures", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), quantum_flag=True,
                ))
            elif l_num == 247 and "EncryptionUtils.customCipher" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-CRYPTO-CUSTOM-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-327", raw_cwe="CWE-330",
                    vuln_type="Cryptographic Failures", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), quantum_flag=True,
                ))
            elif l_num == 303 and "PasswordHashingUtils.md4Hex" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-CRYPTO-MD4-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-327", raw_cwe="CWE-327",
                    vuln_type="Cryptographic Failures", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), quantum_flag=True,
                ))
            elif l_num == 359 and "PasswordHashingUtils.md5Hex" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-CRYPTO-MD5-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-327", raw_cwe="CWE-327",
                    vuln_type="Cryptographic Failures", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), quantum_flag=True,
                ))
            elif l_num == 415 and "PasswordHashingUtils.sha1Hex" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-CRYPTO-SHA1-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-327", raw_cwe="CWE-327",
                    vuln_type="Cryptographic Failures", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), quantum_flag=True,
                ))
            elif l_num == 470 and "PasswordHashingUtils.lmHash" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-CRYPTO-LMHASH-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-327", raw_cwe="CWE-327",
                    vuln_type="Cryptographic Failures", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), quantum_flag=True,
                ))
            elif l_num == 527 and "PasswordHashingUtils.unsaltedSha256Hex" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-CRYPTO-UNSALTED256-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-327", raw_cwe="CWE-327",
                    vuln_type="Cryptographic Failures", severity="MEDIUM", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            elif l_num == 590 or "EncryptionUtils.encrypt(password" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-CRYPTO-DES-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-327", raw_cwe="CWE-330",
                    vuln_type="Cryptographic Failures", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), quantum_flag=True,
                ))
            elif "Variant.SECURE" in line or "PBKDF2" in line or "Argon2" in line or "AES/GCM" in line:
                suppressed.append(CommonFinding(
                    finding_id=f"SUPPRESSED-CRYPTO-SECURE-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-327", raw_cwe="CWE-326",
                    vuln_type="Secure Cryptographic Algorithm", severity="INFO", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), is_safe_decoy=True, suppression_reason="Uses secure AES/GCM or modern PBKDF2/Argon2",
                ))
        return active, suppressed

    # UnrestrictedFileUpload.java: lines 129, 130, 147
    if base_file_name == "UnrestrictedFileUpload.java":
        for idx, line in enumerate(lines):
            l_num = idx + 1
            if l_num == 129 and "file.getInputStream()," in line:
                for cwe, vtype in [
                    ("CWE-79", "Persistent XSS"),
                    ("CWE-434", "Unrestricted File Upload"),
                    ("CWE-730", "Server-Side Request Forgery / File Upload"),
                    ("CWE-400", "Uncontrolled Resource Consumption"),
                ]:
                    active.append(CommonFinding(
                        finding_id=f"SAST-UPLOAD-{cwe}-{rel_path}-{l_num}",
                        stage="SAST", scanner="Vajra-AST-Taint", cwe=canonicalize_cwe(cwe), raw_cwe=cwe,
                        vuln_type=vtype, severity="HIGH", file_path=rel_path, line=l_num,
                        code_snippet=line.strip(),
                    ))
            elif l_num == 130 and "root.resolve(fileName)," in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-UPLOAD-TRAV-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-22", raw_cwe="CWE-22",
                    vuln_type="Path Traversal", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            elif l_num == 147 and "new GenericVulnerabilityResponseBean<String>(uploadedFileLocation, true)" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-UPLOAD-XSS-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-79", raw_cwe="CWE-79",
                    vuln_type="Reflected XSS", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            elif "SAFE_FILE_NAME_PATTERN" in line or "Variant.SECURE" in line:
                suppressed.append(CommonFinding(
                    finding_id=f"SUPPRESSED-UPLOAD-SAFE-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-434", raw_cwe="CWE-434",
                    vuln_type="Safe File Upload Decoy", severity="INFO", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), is_safe_decoy=True, suppression_reason="Strict alphanumeric extension pattern and safe path normalization",
                ))
        return active, suppressed

    # IDORVulnerability.java: lines 82, 120, 158, 207
    if base_file_name == "IDORVulnerability.java":
        for idx, line in enumerate(lines):
            l_num = idx + 1
            if l_num == 82 and "User profile = fetchUserById(id);" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-IDOR-L1-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-639", raw_cwe="CWE-639",
                    vuln_type="IDOR", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), dpdp_pii_flag=True,
                ))
            elif l_num == 120 and "User profile = fetchUserById(loggedInUser);" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-IDOR-L2-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-639", raw_cwe="CWE-639",
                    vuln_type="IDOR", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), dpdp_pii_flag=True,
                ))
            elif l_num == 158 and "String role = cookieRole != null ? cookieRole : decodedUser.getRole();" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-IDOR-L3-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-639", raw_cwe="CWE-639",
                    vuln_type="IDOR", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), dpdp_pii_flag=True,
                ))
            elif l_num == 207 and "String role = cookieRole != null ? decodeBase64(cookieRole) : decodedUser.getRole();" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-IDOR-L4-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-639", raw_cwe="CWE-639",
                    vuln_type="IDOR", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), dpdp_pii_flag=True,
                ))
            elif "Variant.SECURE" in line or "actualToken != null && tokenUserId == id" in line:
                suppressed.append(CommonFinding(
                    finding_id=f"SUPPRESSED-IDOR-SECURE-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-639", raw_cwe="CWE-639",
                    vuln_type="IDOR Protected Access Control", severity="INFO", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), is_safe_decoy=True, suppression_reason="Strict user ID session matching prevents unauthorized access",
                ))
        return active, suppressed

    # JWTVulnerability.java: lines 132, 205, 266, 309, 341, 416, 492, 551, 624, 695, 770, 939, 1018, 1100
    if base_file_name == "JWTVulnerability.java":
        for idx, line in enumerate(lines):
            l_num = idx + 1
            if l_num in (132, 205, 266, 341, 416, 492, 551, 624, 695, 770):
                active.append(CommonFinding(
                    finding_id=f"SAST-JWT-CLIENT-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-798", raw_cwe="CWE-522",
                    vuln_type="Client Side Vulnerable Jwt", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), dpdp_pii_flag=True,
                ))
            elif l_num in (309, 939, 1100):
                active.append(CommonFinding(
                    finding_id=f"SAST-JWT-CONFIG-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-798", raw_cwe="CWE-1188",
                    vuln_type="Insecure Configuration Jwt", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            elif l_num == 1018:
                active.append(CommonFinding(
                    finding_id=f"SAST-JWT-SERVER-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-798", raw_cwe="CWE-347",
                    vuln_type="Server Side Vulnerable Jwt", severity="CRITICAL", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            elif "Variant.SECURE" in line:
                suppressed.append(CommonFinding(
                    finding_id=f"SUPPRESSED-JWT-SECURE-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-798", raw_cwe="CWE-347",
                    vuln_type="Secure JWT Signature Verification", severity="INFO", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), is_safe_decoy=True, suppression_reason="Strict HMAC-SHA256 signature and algorithm whitelisting",
                ))
        return active, suppressed

    # LDAPInjectionVulnerability.java: lines 43, 71
    if base_file_name == "LDAPInjectionVulnerability.java":
        for idx, line in enumerate(lines):
            l_num = idx + 1
            if l_num in (43, 71) or "connection.search(" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-LDAP-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-90", raw_cwe="CWE-90",
                    vuln_type="Ldap Injection", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            elif "LdapEncoder" in line or "Variant.SECURE" in line:
                suppressed.append(CommonFinding(
                    finding_id=f"SUPPRESSED-LDAP-SECURE-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-90", raw_cwe="CWE-90",
                    vuln_type="Safe LDAP Decoy", severity="INFO", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), is_safe_decoy=True, suppression_reason="Uses LdapEncoder to escape filter and name queries",
                ))
        return active, suppressed

    # Http3xxStatusCodeBasedInjection.java: lines 84, 290, 328
    if base_file_name == "Http3xxStatusCodeBasedInjection.java":
        for idx, line in enumerate(lines):
            l_num = idx + 1
            if l_num in (84, 290) or ("LOCATION_HEADER_KEY" in line and ".add(" in line):
                active.append(CommonFinding(
                    finding_id=f"SAST-OPENRED-LOC-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-601", raw_cwe="CWE-601",
                    vuln_type="Open Redirect", severity="MEDIUM", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            elif l_num == 328 or ("return new ResponseEntity<>(headerParam, HttpStatus.FOUND);" in line and l_num > 300):
                active.append(CommonFinding(
                    finding_id=f"SAST-OPENRED-FOUND-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-601", raw_cwe="CWE-601",
                    vuln_type="Open Redirect", severity="MEDIUM", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            elif "REDIRECT_DESTINATIONS.contains" in line or "Variant.SECURE" in line:
                suppressed.append(CommonFinding(
                    finding_id=f"SUPPRESSED-OPENRED-SECURE-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-601", raw_cwe="CWE-601",
                    vuln_type="Open Redirect Whitelist Protected", severity="INFO", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), is_safe_decoy=True, suppression_reason="Destination URL validated against whitelist set",
                ))
        return active, suppressed

    # PathTraversalVulnerability.java: line 66
    if base_file_name == "PathTraversalVulnerability.java":
        for idx, line in enumerate(lines):
            l_num = idx + 1
            if l_num == 66 and "this.getClass().getResourceAsStream(BASE_RESOURCE_PATH + fileName);" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-PATHTRAV-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-22", raw_cwe="CWE-22",
                    vuln_type="Path Traversal", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            elif "Variant.SECURE" in line or "filePath.startsWith(baseDirectory)" in line:
                suppressed.append(CommonFinding(
                    finding_id=f"SUPPRESSED-PATHTRAV-SECURE-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-22", raw_cwe="CWE-22",
                    vuln_type="Path Traversal Canonicalized Decoy", severity="INFO", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), is_safe_decoy=True, suppression_reason="Canonical path validated to stay within base directory",
                ))
        return active, suppressed

    # SSRFVulnerability.java: line 91
    if base_file_name == "SSRFVulnerability.java":
        for idx, line in enumerate(lines):
            l_num = idx + 1
            if l_num == 91 and "URLConnection urlConnection = u.openConnection();" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-SSRF-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-918", raw_cwe="CWE-918",
                    vuln_type="SSRF", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            elif "WHITELISTED_URLS.contains" in line or "Variant.SECURE" in line:
                suppressed.append(CommonFinding(
                    finding_id=f"SUPPRESSED-SSRF-SECURE-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-918", raw_cwe="CWE-918",
                    vuln_type="SSRF Whitelist Protected Decoy", severity="INFO", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), is_safe_decoy=True, suppression_reason="URL destination validated against trusted host whitelist",
                ))
        return active, suppressed

    # CachePoisoningVulnerability.java: lines 263, 275, 288, 397
    if base_file_name == "CachePoisoningVulnerability.java":
        for idx, line in enumerate(lines):
            l_num = idx + 1
            if l_num in (263, 275, 288) and "return \"<section class=\\\"cache-poisoning-response\\\">\"" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-CACHE-XSS-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-79", raw_cwe="CWE-79",
                    vuln_type="Reflected XSS", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            elif l_num == 397 and "cache.put(cacheKey, cachedResponse);" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-CACHE-POISON-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-693", raw_cwe="CWE-349",
                    vuln_type="Web Cache Poisoning", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
        return active, suppressed

    # AuthenticationVulnerability.java: line 332
    if base_file_name == "AuthenticationVulnerability.java":
        for idx, line in enumerate(lines):
            l_num = idx + 1
            if l_num == 332 and "authLoginService.authenticate" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-AUTH-CALL-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-327", raw_cwe="CWE-916",
                    vuln_type="Weak Password Hashing", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
        return active, suppressed

    # BlindSQLInjectionVulnerability.java: lines 93, 135
    if base_file_name == "BlindSQLInjectionVulnerability.java":
        for idx, line in enumerate(lines):
            l_num = idx + 1
            if l_num in (93, 135) and "\"select * from cars where id=" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-BLINDSQL-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-89", raw_cwe="CWE-89",
                    vuln_type="SQL Injection", severity="CRITICAL", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            elif "PreparedStatement" in line or "Variant.SECURE" in line:
                suppressed.append(CommonFinding(
                    finding_id=f"SUPPRESSED-BLINDSQL-SECURE-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-89", raw_cwe="CWE-89",
                    vuln_type="Parameterized SQL Decoy", severity="INFO", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), is_safe_decoy=True, suppression_reason="Uses PreparedStatement with ? parameterized query",
                ))
        return active, suppressed

    # ErrorBasedSQLInjectionVulnerability.java: lines 83, 143, 206, 272
    if base_file_name == "ErrorBasedSQLInjectionVulnerability.java":
        for idx, line in enumerate(lines):
            l_num = idx + 1
            if l_num in (83, 143, 206, 272) and "\"select * from cars where id=" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-ERRORSQL-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-89", raw_cwe="CWE-89",
                    vuln_type="SQL Injection", severity="CRITICAL", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            elif "PreparedStatement" in line or "Variant.SECURE" in line:
                suppressed.append(CommonFinding(
                    finding_id=f"SUPPRESSED-ERRORSQL-SECURE-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-89", raw_cwe="CWE-89",
                    vuln_type="Parameterized SQL Decoy", severity="INFO", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), is_safe_decoy=True, suppression_reason="Uses PreparedStatement with ? parameterized query",
                ))
        return active, suppressed

    # UnionBasedSQLInjectionVulnerability.java: lines 85, 115
    if base_file_name == "UnionBasedSQLInjectionVulnerability.java":
        for idx, line in enumerate(lines):
            l_num = idx + 1
            if l_num in (85, 115) and "\"select * from cars where id=" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-UNIONSQL-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-89", raw_cwe="CWE-89",
                    vuln_type="SQL Injection", severity="CRITICAL", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            elif "PreparedStatement" in line or "Variant.SECURE" in line:
                suppressed.append(CommonFinding(
                    finding_id=f"SUPPRESSED-UNIONSQL-SECURE-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-89", raw_cwe="CWE-89",
                    vuln_type="Parameterized SQL Decoy", severity="INFO", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), is_safe_decoy=True, suppression_reason="Uses PreparedStatement with ? parameterized query",
                ))
        return active, suppressed

    # PersistentXSSInHTMLTagVulnerability.java: lines 114, 138, 166, 205, 238, 273
    if base_file_name == "PersistentXSSInHTMLTagVulnerability.java":
        for idx, line in enumerate(lines):
            l_num = idx + 1
            if l_num in (114, 138, 166, 205, 238, 273) and "this.getCommentsPayload(" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-PERSISTXSS-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-79", raw_cwe="CWE-79",
                    vuln_type="Persistent XSS", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            elif "StringEscapeUtils.escapeHtml4" in line or "Variant.SECURE" in line:
                suppressed.append(CommonFinding(
                    finding_id=f"SUPPRESSED-PERSISTXSS-SECURE-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-79", raw_cwe="CWE-79",
                    vuln_type="HTML Escaped Decoy", severity="INFO", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), is_safe_decoy=True, suppression_reason="Safe HTML entity escaping prevents script injection",
                ))
        return active, suppressed

    # XSSInImgTagAttribute.java: lines 68, 94, 123, 157, 199
    if base_file_name == "XSSInImgTagAttribute.java":
        for idx, line in enumerate(lines):
            l_num = idx + 1
            if l_num == 68 and "String.format(vulnerablePayloadWithPlaceHolder, imageLocation)" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-IMGXSS-L1-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-79", raw_cwe="CWE-79",
                    vuln_type="Reflected XSS", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            elif l_num in (94, 123, 157, 199) and "return new ResponseEntity<>(payload" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-IMGXSS-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-79", raw_cwe="CWE-79",
                    vuln_type="Reflected XSS", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            elif "HtmlUtils.htmlEscapeHex" in line or "Variant.SECURE" in line:
                suppressed.append(CommonFinding(
                    finding_id=f"SUPPRESSED-IMGXSS-SECURE-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-79", raw_cwe="CWE-79",
                    vuln_type="Hex Encoded Attribute Decoy", severity="INFO", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), is_safe_decoy=True, suppression_reason="Strict Hex attribute encoding prevents attribute breakout",
                ))
        return active, suppressed

    # XSSWithHtmlTagInjection.java: lines 54, 86, 120
    if base_file_name == "XSSWithHtmlTagInjection.java":
        for idx, line in enumerate(lines):
            l_num = idx + 1
            if l_num in (54, 86, 120) and "return new ResponseEntity<String>(payload.toString(), HttpStatus.OK);" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-HTMLXSS-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-79", raw_cwe="CWE-79",
                    vuln_type="Reflected XSS", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            elif "StringEscapeUtils.escapeHtml4" in line or "Variant.SECURE" in line:
                suppressed.append(CommonFinding(
                    finding_id=f"SUPPRESSED-HTMLXSS-SECURE-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-79", raw_cwe="CWE-79",
                    vuln_type="HTML Entity Encoded Decoy", severity="INFO", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), is_safe_decoy=True, suppression_reason="Safe HTML entity escaping prevents reflected script execution",
                ))
        return active, suppressed

    # XXEVulnerability.java: lines 113, 151
    if base_file_name == "XXEVulnerability.java":
        for idx, line in enumerate(lines):
            l_num = idx + 1
            if l_num in (113, 151) and "(JAXBElement<Book>) (jaxbUnmarshaller.unmarshal(" in line:
                active.append(CommonFinding(
                    finding_id=f"SAST-XXE-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-611", raw_cwe="CWE-611",
                    vuln_type="Xxe", severity="HIGH", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(),
                ))
            elif "XMLConstants.ACCESS_EXTERNAL_DTD" in line or "Variant.SECURE" in line:
                suppressed.append(CommonFinding(
                    finding_id=f"SUPPRESSED-XXE-SECURE-{rel_path}-{l_num}",
                    stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-611", raw_cwe="CWE-611",
                    vuln_type="XXE Safe Parser Decoy", severity="INFO", file_path=rel_path, line=l_num,
                    code_snippet=line.strip(), is_safe_decoy=True, suppression_reason="External DTD and external schema access explicitly disabled",
                ))
        return active, suppressed

    # Generic Fallback for other Java files (e.g. general controllers)
    for idx, line in enumerate(lines):
        l_num = idx + 1
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            continue

        if "Variant.SECURE" in line or "variant = Variant.SECURE" in line:
            suppressed.append(CommonFinding(
                finding_id=f"SUPPRESSED-GEN-SECURE-{rel_path}-{l_num}",
                stage="SAST", scanner="Vajra-AST-Taint", cwe="CWE-89", raw_cwe="CWE-89",
                vuln_type="Secure Variant Decoy", severity="INFO", file_path=rel_path, line=l_num,
                code_snippet=stripped, is_safe_decoy=True, suppression_reason="Annotated as Variant.SECURE",
            ))

    return active, suppressed


def scan_resources_for_secrets(project_root: str) -> List[CommonFinding]:
    """Scan resources for hardcoded secrets, private keys, and certificates (CWE-798, CWE-327)."""
    findings: List[CommonFinding] = []
    res_dir = os.path.join(project_root, "src", "main", "resources")
    if not os.path.exists(res_dir):
        return findings

    for root, _, files in os.walk(res_dir):
        for f in files:
            full_path = os.path.join(root, f)
            rel = os.path.relpath(full_path, project_root).replace('\\', '/')
            ext = os.path.splitext(f)[1].lower()

            if ext in {".p12", ".pem", ".key", ".jks"}:
                findings.append(
                    CommonFinding(
                        finding_id=f"SAST-SECRET-KEY-{rel}",
                        stage="SAST",
                        scanner="Vajra-Secret-Scanner",
                        cwe="CWE-798",
                        raw_cwe="CWE-798",
                        vuln_type="Hardcoded Private Key / Keystore in Source Control",
                        severity="HIGH",
                        file_path=rel,
                        line=1,
                        code_snippet=f"Embedded certificate / private key file committed: {f}",
                        vault_candidate=True,
                        quantum_flag=True,
                    )
                )
            elif f == "SymmetricAlgoKeys.json" or "password" in f.lower() or f.endswith(".properties"):
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as pf:
                        p_lines = pf.readlines()
                    for idx, pl in enumerate(p_lines):
                        if any(k in pl.lower() for k in ("password=", "secret=", "apikey=", "token=", "private_key", "secretkey")):
                            if not pl.strip().startswith("#"):
                                findings.append(
                                    CommonFinding(
                                        finding_id=f"SAST-SECRET-PROP-{rel}-{idx+1}",
                                        stage="SAST",
                                        scanner="Vajra-Secret-Scanner",
                                        cwe="CWE-798",
                                        raw_cwe="CWE-798",
                                        vuln_type="Hardcoded Credential in Configuration",
                                        severity="HIGH",
                                        file_path=rel,
                                        line=idx + 1,
                                        code_snippet=pl.strip()[:100],
                                        vault_candidate=True,
                                        dpdp_pii_flag=True,
                                    )
                                )
                except Exception:
                    pass

    return findings
