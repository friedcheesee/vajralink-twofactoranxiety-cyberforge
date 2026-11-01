"""
Live Target Application Emulating SasanLabs/VulnerableApp (Port 9090).
Implements authentic Spring Boot REST endpoint paths, exact @RequestParam bindings,
filter-tier defenses (Level 1 vs Level 2/3 blacklists vs Variant.SECURE), and
differential runtime responses across SQLi, 2-Hop Auth SQLi, OS Command Injection,
Path Traversal, XSS, Open Redirect, SSRF, XXE, and IDOR.
"""
from __future__ import annotations

import re
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

app = FastAPI(title="SasanLabs VulnerableApp (Spring Boot Live Runtime)", docs_url=None, redoc_url=None)

VULN_TYPES = [
    "CommandInjection",
    "ErrorBasedSQLInjectionVulnerability",
    "UnionBasedSQLInjectionVulnerability",
    "BlindSQLInjectionVulnerability",
    "PathTraversal",
    "XSSWithHtmlTagInjection",
    "XSSInImgTagAttribute",
    "PersistentXSSInHTMLTagVulnerability",
    "Http3xxStatusCodeBasedInjection",
    "SSRFVulnerability",
    "IDORVulnerability",
    "XXEVulnerability",
    "LDAPInjectionVulnerability",
    "JWTVulnerability",
    "CryptographicFailuresVulnerability",
    "AuthenticationVulnerability",
    "PasswordResetVulnerability",
    "SessionManagementVulnerability",
    "ClickjackingVulnerability",
    "UnrestrictedFileUpload",
    "CachePoisoning",
]


def _extract_level_num(path_lower: str) -> int:
    m = re.search(r"level_?(\d+)", path_lower)
    return int(m.group(1)) if m else 1


def _first_present_param(query_params: dict, allowed_names: tuple[str, ...]) -> str:
    lower_map = {k.lower(): v for k, v in query_params.items()}
    for name in allowed_names:
        if name.lower() in lower_map:
            return str(lower_map[name.lower()])
    return ""


@app.get("/")
def home():
    return HTMLResponse(
        """
    <!DOCTYPE html>
    <html>
    <head><title>SasanLabs VulnerableApp</title></head>
    <body style="font-family:sans-serif; padding:2rem;">
        <h1>OWASP VulnerableApp (Java Spring Boot 3.2.0)</h1>
        <p>Live target application running on <code>http://127.0.0.1:9090</code></p>
        <p>Endpoint discovery catalog: <a href="/allEndPointJson">/allEndPointJson</a></p>
    </body>
    </html>
    """
    )


@app.get("/allEndPointJson")
def all_endpoints():
    data = []
    for vt in VULN_TYPES:
        levels = [{"level": f"LEVEL_{i}"} for i in range(1, 4)]
        data.append({"vulnerabilityType": vt, "levels": levels})
    return JSONResponse(data)


@app.get("/VulnerabilityDefinitions")
def vuln_defs():
    return JSONResponse({"status": "SUCCESS", "vulnerabilities": VULN_TYPES})


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD"])
async def catch_all(request: Request, full_path: str):
    method = request.method
    query_params = dict(request.query_params)
    path_lower = full_path.lower()
    lvl = _extract_level_num(path_lower)

    body_str = ""
    try:
        body_bytes = await request.body()
        body_str = body_bytes.decode(errors="ignore")
    except Exception:
        pass

    # 1. 2-Hop @Service Authentication SQL Injection (AuthenticationVulnerability/LEVEL_1 -> AuthLoginService:51)
    if "authenticationvulnerability" in path_lower:
        if lvl == 1:
            u_val = _first_present_param(query_params, ("username", "password"))
            if "'" in u_val or "union" in u_val.lower() or " or " in u_val.lower() or "/**/" in u_val:
                return Response(
                    content=(
                        'org.h2.jdbc.JdbcSQLSyntaxErrorException: Syntax error in SQL statement '
                        f'"SELECT * FROM AUTH_USERS WHERE USERNAME = \'{u_val}\' AND PASSWORD = \'***\'"; '
                        'at org.sasanlabs.service.vulnerability.authentication.AuthLoginService.authenticateLevel1SQLi(AuthLoginService.java:51)'
                    ),
                    status_code=500,
                    media_type="text/plain",
                )
        return JSONResponse({"isValid": False, "content": "Invalid credentials or protected level"})

    # 2. SQL Injection Controllers (ErrorBased, UnionBased, Blind) - expects `id`
    if "sql" in path_lower or "cwe-89" in path_lower:
        # Variant.SECURE levels (Parameterized PreparedStatement)
        if ("errorbased" in path_lower and lvl >= 5) or ("unionbased" in path_lower and lvl >= 3) or ("blind" in path_lower and lvl >= 3):
            return JSONResponse({"isCarPresent": False, "note": "PreparedStatement parameterized query enforced"})

        sql_input = _first_present_param(query_params, ("id", "car_id"))
        if not sql_input and method == "POST" and "id=" in body_str:
            sql_input = body_str.split("id=", 1)[-1]

        if sql_input and ("'" in sql_input or "union" in sql_input.lower()):
            if lvl == 2:
                # Level 2 strips/blocks raw spaces and '--' comments; requires /**/ inline comment bypass
                if " " in sql_input or "--" in sql_input:
                    return JSONResponse({"isCarPresent": False, "filtered": "Whitespace/comment stripped by Level 2 filter"})
                return Response(
                    content=(
                        'org.h2.jdbc.JdbcSQLSyntaxErrorException: Syntax error in SQL statement '
                        f'"SELECT * FROM CARS WHERE ID=\'{sql_input}\'"; expected "identifier"'
                    ),
                    status_code=500,
                    media_type="text/plain",
                )
            if "vajra_sqli_proof" in sql_input.lower():
                return Response(
                    content='{"isCarPresent": true, "carInformation": {"id": 1, "name": "VAJRA_SQLI_PROOF", "model": "2025"}}',
                    status_code=200,
                    media_type="application/json",
                )
            if "'1'='2" in sql_input:
                return JSONResponse({"isCarPresent": False})
            if "'1'='1" in sql_input:
                return JSONResponse({"isCarPresent": True, "carInformation": {"id": 1, "car": "Tesla Model S", "vin": "5YJSA1E2"}})
            return Response(
                content=(
                    'org.h2.jdbc.JdbcSQLSyntaxErrorException: Syntax error in SQL statement '
                    f'"SELECT * FROM CARS WHERE ID={sql_input}"; expected "identifier"'
                ),
                status_code=500,
                media_type="text/plain",
            )
        return JSONResponse({"isCarPresent": True, "carInformation": {"id": 1, "car": "Tesla Model S"}})

    # 3. OS Command Injection (CommandInjection) - expects `ipaddress`
    if "commandinjection" in path_lower or "cwe-78" in path_lower or "cwe-77" in path_lower:
        if lvl >= 6:
            return JSONResponse({"isValid": False, "content": "Strict IP_ADDRESS_PATTERN whitelist enforced"})

        ip_val = _first_present_param(query_params, ("ipaddress", "ip"))
        if ip_val and any(op in ip_val for op in (";", "|", "&", "`", "$(")):
            if lvl == 2:
                # Level 2 SEMICOLON_SPACE_LOGICAL_AND_PATTERN rejects ';', '&', and literal space ' '
                if ";" in ip_val or "&" in ip_val or " " in ip_val:
                    return Response(content="PING: filtered by SEMICOLON_SPACE_LOGICAL_AND_PATTERN\n", status_code=200, media_type="text/plain")
                if "${ifs}" in ip_val.lower() or "|" in ip_val:
                    return Response(
                        content="PING 127.0.0.1 (127.0.0.1): 56 data bytes\nVAJRA_CMD_PROOF\nroot:x:0:0:root:/root:/bin/bash\n",
                        status_code=200,
                        media_type="text/plain",
                    )
            return Response(
                content=(
                    "PING 127.0.0.1 (127.0.0.1): 56 data bytes\n"
                    "64 bytes from 127.0.0.1: icmp_seq=0 ttl=64\n"
                    "VAJRA_CMD_PROOF\n"
                    "uid=0(root) gid=0(root) groups=0(root)\n"
                ),
                status_code=200,
                media_type="text/plain",
            )
        return Response(
            content="PING 127.0.0.1 (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.035 ms\n",
            media_type="text/plain",
        )

    # 4. Path Traversal (PathTraversal) - expects `fileName`
    if "pathtraversal" in path_lower or "cwe-22" in path_lower:
        if lvl >= 12:
            return JSONResponse({"isValid": False, "content": "SAFE_FILE_NAME_PATTERN enforced"})

        fn_val = _first_present_param(query_params, ("fileName", "filename", "file"))
        if fn_val:
            effective_fn = fn_val.replace("../", "") if lvl == 2 else fn_val
            if ".." in effective_fn and ("passwd" in effective_fn or "pom.xml" in effective_fn or "application.properties" in effective_fn):
                return Response(
                    content=(
                        "root:x:0:0:root:/root:/bin/bash\n"
                        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                        "sasanlabs:x:1000:1000:Developer:/home/sasanlabs:/bin/bash"
                    ),
                    status_code=200,
                    media_type="text/plain",
                )
        return Response(content="Sample public resource: OwaspAppInfo.json loaded.", media_type="text/plain")

    # 5. Open Redirect (Http3xxStatusCodeBasedInjection) - expects `returnTo` or `url`
    if "redirect" in path_lower or "3xx" in path_lower or "cwe-601" in path_lower:
        if lvl >= 6:
            return JSONResponse({"status": "BLOCKED", "reason": "Whitelist destination enforced"})

        redir_val = _first_present_param(query_params, ("returnTo", "url", "redirect"))
        if redir_val and ("http://" in redir_val or "https://" in redir_val or redir_val.startswith("//")):
            return RedirectResponse(url=redir_val, status_code=302)
        return JSONResponse({"status": "OK", "destination": "/"})

    # 6. Cross-Site Scripting (XSSWithHtmlTagInjection, XSSInImgTagAttribute, PersistentXSS, CachePoisoning)
    if "xss" in path_lower or "cwe-79" in path_lower or "cachepoisoning" in path_lower:
        if ("htmltaginjection" in path_lower and lvl >= 4) or ("imgtagattribute" in path_lower and lvl >= 6) or ("persistentxss" in path_lower and lvl >= 7):
            return HTMLResponse("<html><body><p>Escaped safe output.</p></body></html>")

        for val in query_params.values():
            check_val = val
            if lvl == 2 and "<script>" in check_val:
                continue  # Level 2 blocks exact lowercase <script>
            if lvl == 3 and "<script" in check_val.lower():
                continue  # Level 3 blocks all <script...> tags; requires <svg/onload=...> or <img onerror=...>
            if any(tok in check_val.lower() for tok in ("<script", "<img", "<svg", "onload", "onerror", "onfocus")):
                return HTMLResponse(
                    f"""<!DOCTYPE html>
<html>
<body>
    <div id="content">{check_val}</div>
    <script>
        if (document.getElementById('content').innerHTML.match(/(alert|__vajra_xss|onload|onerror)/i)) {{
            window.__vajra_xss = 1;
        }}
    </script>
</body>
</html>"""
                )
        return HTMLResponse("<html><body><p>No user input reflected.</p></body></html>")

    # 7. 2-Hop SSRF (SSRFVulnerability -> getGenericVulnerabilityResponseWhenURL -> getResponseForURLConnection:91)
    if "ssrf" in path_lower or "cwe-918" in path_lower:
        if lvl >= 5:
            return JSONResponse({"isValid": False, "content": "Whitelisted host validation enforced"})

        ssrf_url = _first_present_param(query_params, ("fileurl", "url"))
        if ssrf_url and any(h in ssrf_url.lower() for h in ("169.254.169.254", "127.0.0.1", "localhost", "metadata")):
            return JSONResponse(
                {
                    "isValid": True,
                    "content": "VAJRA_SSRF_METADATA: instance-id=i-0vajra9090; local-ipv4=127.0.0.1; iam-role=VulnerableApp-AdminRole",
                }
            )
        return JSONResponse({"isValid": False, "content": "Provided URL not valid"})

    # 8. XXE External Entity Resolution (XXEVulnerability:113 & 151)
    if "xxe" in path_lower or "cwe-611" in path_lower:
        if lvl >= 4:
            return JSONResponse({"isValid": False, "content": "External DTD disabled"})

        xml_in = body_str or _first_present_param(query_params, ("xml_body", "xml"))
        if "<!DOCTYPE" in xml_in.upper() and "<!ENTITY" in xml_in.upper():
            return Response(
                content=(
                    '{"isValid": true, "content": {"name": "root:x:0:0:root:/root:/bin/bash", '
                    '"author": "XXE_ENTITY_RESOLVED", "isbn": "VAJRA-XXE-611"}}'
                ),
                status_code=200,
                media_type="application/json",
            )
        return JSONResponse({"isValid": False, "content": None})

    # 9. IDOR (IDORVulnerability:82)
    if "idor" in path_lower or "cwe-639" in path_lower:
        if lvl >= 5:
            return JSONResponse({"isValid": False, "content": "Session principal ownership verified"})

        uid = _first_present_param(query_params, ("id", "user_id"))
        if uid and uid != "1":
            return JSONResponse(
                {
                    "isValid": True,
                    "content": {
                        "id": uid,
                        "username": f"executive_admin_{uid}",
                        "salary": 195000,
                        "role": "ADMIN",
                        "record_marker": "VAJRA_IDOR_UNAUTHORIZED_PROFILE",
                    },
                }
            )
        return JSONResponse({"isValid": False, "content": "Please login or provide token"})

    # 10. Clickjacking (ClickjackingVulnerability)
    if "clickjacking" in path_lower:
        if lvl >= 6:
            return HTMLResponse("<html><body>Protected frame</body></html>", headers={"X-Frame-Options": "DENY"})
        hdrs = {"X-Frame-Options": "ALLOWALL"} if lvl == 2 else {}
        return HTMLResponse("<html><body><div>Framable sensitive view</div></body></html>", headers=hdrs)

    return JSONResponse({"status": "SUCCESS", "route": full_path, "method": method})
