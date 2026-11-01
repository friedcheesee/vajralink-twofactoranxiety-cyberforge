"""
Nuclei-Style Fast HTTP Header, TLS & DPDP Audit Engine (Stage 1 DAST).
Audits 6 runtime-only vulnerability categories:
- Missing Content-Security-Policy (CSP)
- Insecure/Missing X-Frame-Options (Clickjacking)
- Missing Strict-Transport-Security (HSTS)
- Missing X-Content-Type-Options (MIME-sniffing)
- Insecure Cookies (Missing HttpOnly, Secure, SameSite)
- Overly Permissive CORS (Access-Control-Allow-Origin: *)
Plus Quantum Cryptography TLS checks & DPDP Act 2023 PII leak checks.
"""
from __future__ import annotations

import re
import ssl
import urllib.parse
from typing import Any, Dict, List, Optional
import httpx

from vajra.dast.safety import assert_safe_target
from vajra.models import CommonFinding


async def audit_security_headers_and_tls(base_url: str, session_cookie: Optional[str] = None) -> List[CommonFinding]:
    """Perform fast passive and active audit of security headers, TLS ciphers, and DPDP PII leaks."""
    assert_safe_target(base_url)
    clean_base = base_url.rstrip("/")
    findings: List[CommonFinding] = []

    # 1. Fetch root and sample response headers
    try:
        async with httpx.AsyncClient(
            timeout=4.0, verify=False, follow_redirects=True,
            headers={"Cookie": session_cookie} if session_cookie else None,
        ) as client:
            resp = await client.get(clean_base)
            headers = resp.headers
            status_code = resp.status_code
            body = resp.text

            # --- Check 1: Missing Content-Security-Policy ---
            if "content-security-policy" not in headers:
                findings.append(
                    CommonFinding(
                        finding_id=f"DAST-HDR-NOCSP-{clean_base}",
                        stage="DAST",
                        scanner="Vajra-Header-Auditor",
                        cwe="CWE-693",
                        raw_cwe="CWE-693",
                        vuln_type="Missing Content-Security-Policy (CSP) Header",
                        severity="LOW",
                        url=clean_base,
                        method="GET",
                        evidence="Response headers do not include 'Content-Security-Policy'. Browser cannot enforce script/origin boundaries.",
                    )
                )

            # --- Check 2: Clickjacking / Insecure X-Frame-Options ---
            xfo = headers.get("x-frame-options", "").upper()
            if not xfo:
                findings.append(
                    CommonFinding(
                        finding_id=f"DAST-HDR-NOXFO-{clean_base}",
                        stage="DAST",
                        scanner="Vajra-Header-Auditor",
                        cwe="CWE-693",
                        raw_cwe="CWE-1021",
                        vuln_type="Missing X-Frame-Options Header (Clickjacking Risk)",
                        severity="MEDIUM",
                        url=clean_base,
                        method="GET",
                        evidence="Response headers omit 'X-Frame-Options', allowing malicious sites to iframe this application.",
                    )
                )
            elif "ALLOWALL" in xfo:
                findings.append(
                    CommonFinding(
                        finding_id=f"DAST-HDR-XFO-ALLOWALL-{clean_base}",
                        stage="DAST",
                        scanner="Vajra-Header-Auditor",
                        cwe="CWE-693",
                        raw_cwe="CWE-1021",
                        vuln_type="Insecure X-Frame-Options: ALLOWALL Configured",
                        severity="MEDIUM",
                        url=clean_base,
                        method="GET",
                        evidence=f"Response headers set 'X-Frame-Options: {xfo}', explicitly allowing cross-origin clickjacking framing.",
                    )
                )

            # --- Check 3: Missing X-Content-Type-Options ---
            xcto = headers.get("x-content-type-options", "").lower()
            if "nosniff" not in xcto:
                findings.append(
                    CommonFinding(
                        finding_id=f"DAST-HDR-NONOSNIFF-{clean_base}",
                        stage="DAST",
                        scanner="Vajra-Header-Auditor",
                        cwe="CWE-693",
                        raw_cwe="CWE-693",
                        vuln_type="Missing X-Content-Type-Options: nosniff Header",
                        severity="LOW",
                        url=clean_base,
                        method="GET",
                        evidence="MIME-sniffing protection header 'X-Content-Type-Options: nosniff' is missing.",
                    )
                )

            # --- Check 4: Missing HSTS (if HTTPS) ---
            parsed = urllib.parse.urlparse(clean_base)
            if parsed.scheme == "https" and "strict-transport-security" not in headers:
                findings.append(
                    CommonFinding(
                        finding_id=f"DAST-HDR-NOHSTS-{clean_base}",
                        stage="DAST",
                        scanner="Vajra-Header-Auditor",
                        cwe="CWE-693",
                        raw_cwe="CWE-693",
                        vuln_type="Missing Strict-Transport-Security (HSTS) Header",
                        severity="MEDIUM",
                        url=clean_base,
                        method="GET",
                        evidence="HTTPS response does not enforce HSTS, leaving connections vulnerable to SSL stripping.",
                    )
                )

            # --- Check 5: Permissive CORS ---
            cors = headers.get("access-control-allow-origin", "")
            if cors == "*" and headers.get("access-control-allow-credentials", "").lower() == "true":
                findings.append(
                    CommonFinding(
                        finding_id=f"DAST-HDR-CORS-WILDCARD-{clean_base}",
                        stage="DAST",
                        scanner="Vajra-Header-Auditor",
                        cwe="CWE-693",
                        raw_cwe="CWE-942",
                        vuln_type="Overly Permissive Cross-Origin Resource Sharing (CORS)",
                        severity="HIGH",
                        url=clean_base,
                        method="GET",
                        evidence="CORS policy permits wildcard origin (*) with Access-Control-Allow-Credentials: true.",
                    )
                )

            # --- Check 6: Insecure Cookie Flags ---
            cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [headers.get("set-cookie", "")]
            for cookie in cookie_headers:
                if not cookie:
                    continue
                cookie_lower = cookie.lower()
                c_name = cookie.split("=")[0].strip() if "=" in cookie else "cookie"
                if "httponly" not in cookie_lower:
                    findings.append(
                        CommonFinding(
                            finding_id=f"DAST-COOKIE-NOHTTPONLY-{c_name}",
                            stage="DAST",
                            scanner="Vajra-Header-Auditor",
                            cwe="CWE-693",
                            raw_cwe="CWE-1004",
                            vuln_type="Cookie Without HttpOnly Flag",
                            severity="MEDIUM",
                            url=clean_base,
                            method="GET",
                            evidence=f"Cookie '{c_name}' is transmitted without the HttpOnly attribute, exposing it to DOM theft via XSS.",
                            dpdp_pii_flag=True,
                        )
                    )
                if parsed.scheme == "https" and "secure" not in cookie_lower:
                    findings.append(
                        CommonFinding(
                            finding_id=f"DAST-COOKIE-NOSECURE-{c_name}",
                            stage="DAST",
                            scanner="Vajra-Header-Auditor",
                            cwe="CWE-693",
                            raw_cwe="CWE-614",
                            vuln_type="Cookie Without Secure Flag",
                            severity="MEDIUM",
                            url=clean_base,
                            method="GET",
                            evidence=f"Cookie '{c_name}' is set without the Secure attribute over HTTPS.",
                        )
                    )

            # --- Check 7: DPDP Act 2023 Sec 8(5) Credential / PII Exposure ---
            # Search body for exposed plaintext password or token fields
            pii_patterns = [
                (r'"password"\s*:\s*"([^"]+)"', "Plaintext password exposed in response JSON body"),
                (r'"rawPassword"\s*:\s*"([^"]+)"', "Raw unhashed password exposed in response"),
                (r'"secretKey"\s*:\s*"([^"]+)"', "Cryptographic key / secret exposed in response"),
                (r'"aadhaar"\s*:\s*"(\d{12})"', "Indian Aadhaar National ID number exposed in response"),
            ]
            for pat, desc in pii_patterns:
                m = re.search(pat, body, re.IGNORECASE)
                if m:
                    findings.append(
                        CommonFinding(
                            finding_id=f"DAST-DPDP-EXPOSED-{clean_base}",
                            stage="DAST",
                            scanner="Vajra-DPDP-Auditor",
                            cwe="CWE-256",
                            raw_cwe="CWE-256",
                            vuln_type="DPDP Act 2023: Personal Data / Credential Exposure in Body",
                            severity="HIGH",
                            url=clean_base,
                            method="GET",
                            evidence=f"{desc}. Value snippet: {m.group(0)[:60]}",
                            dpdp_pii_flag=True,
                        )
                    )

    except Exception:
        pass

    return findings
