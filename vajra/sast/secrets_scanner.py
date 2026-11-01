"""
Generic hard-coded-secret scanner (CWE-798): Java string literals assigned to secret-looking names / passed to
credential APIs, plus resource files (properties / yaml / .env) and committed key material.  Target-agnostic.
Placeholders (${ENV}, empty, <angle-bracket> templates) are not reported.
"""
from __future__ import annotations

import os
import re
from typing import List

from vajra.models import CommonFinding

SCANNER = "Vajra-Secret-Scanner"
_NAME = re.compile(r"(?:passw(?:or)?d|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|private[_-]?key|"
                   r"credential|signing[_-]?key|client[_-]?secret|encryption[_-]?key|jwt[_-]?(?:secret|key)|token)", re.I)
_NAME_NEG = re.compile(r"(?:_|^)(?:NAME|HEADER|PARAM|PARAMETER|FIELD|ATTR|ATTRIBUTE|PATH|URL|URI|TYPE|PREFIX|SUFFIX|PATTERN|"
                       r"REGEX|LABEL|MESSAGE|MSG|ERROR|FORMAT|ALGORITHM|ALGO|COOKIE|ENDPOINT|EXPIRY|EXPIRES|TTL|LENGTH|SIZE|"
                       r"CLAIM|ROLE|SCOPE)$|(?:Name|Header|Param|Field|Attr|Path|Url|Type|Prefix|Label|Pattern|Length)$")
_SELF_WORDS = {"password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "username", "user", "key", "authorization",
               "bearer", "none", "null", "true", "false", "x-auth-token", "access_token", "refresh_token", "csrf", "xsrf-token"}
_JAVA_ASSIGN = re.compile(r'(?:\b(?:String|char\s*\[\s*\]|byte\s*\[\s*\])\s+)?\b([A-Za-z_]\w*)\s*=\s*"((?:\\.|[^"\\])*)"\s*(?:\.getBytes\([^)]*\))?\s*;')
_JAVA_CALLS = [
    (re.compile(r'\.\s*(?:setPassword|password|setSecret|secret|setApiKey|apiKey|setToken)\s*\(\s*"((?:\\.|[^"\\])+)"'), "credential setter"),
    (re.compile(r'\bAlgorithm\s*\.\s*HMAC\d+\s*\(\s*"((?:\\.|[^"\\])+)"'), "JWT HMAC signing key"),
    (re.compile(r'\bKeys\s*\.\s*hmacShaKeyFor\s*\(\s*"((?:\\.|[^"\\])+)"'), "JWT HMAC signing key"),
    (re.compile(r'\.\s*signWith\s*\([^;]*?,\s*"((?:\\.|[^"\\])+)"'), "JWT signing key"),
    (re.compile(r'\bnew\s+SecretKeySpec\s*\(\s*"((?:\\.|[^"\\])+)"'), "symmetric key"),
    (re.compile(r'\bDriverManager\s*\.\s*getConnection\s*\(\s*[^,]+,\s*[^,]+,\s*"((?:\\.|[^"\\])+)"'), "JDBC password"),
]
_PLACEHOLDER = re.compile(r"^\s*(?:\$\{.*\}|<.*>|\{\{.*\}\}|%\(.*\)s|x{3,}|\*+|)\s*$", re.I)
_PROP_KEY = re.compile(r"(?:passw(?:or)?d|secret|api[_.-]?key|apikey|auth[_.-]?token|access[_.-]?token|private[_.-]?key|"
                       r"credentials?|signing[_.-]?key|client[_.-]?secret|token)", re.I)


def _mk(rel: str, line: int, vt: str, snippet: str, rule: str) -> CommonFinding:
    return CommonFinding(
        finding_id=f"SAST-SECRET-{rule}-{rel}-{line}", stage="SAST", scanner=SCANNER, cwe="CWE-798", raw_cwe="CWE-798",
        vuln_type=vt, severity="HIGH", file_path=rel, line=line, code_snippet=snippet.strip()[:120], vault_candidate=True,
        dpdp_pii_flag=rule == "PROP")


def _looks_secret(name: str, value: str) -> bool:
    if not _NAME.search(name) or _NAME_NEG.search(name) or _PLACEHOLDER.match(value):
        return False
    if value.lower() in _SELF_WORDS or len(value) < 4:
        return False
    return True


def scan_secrets(source_root: str) -> List[CommonFinding]:
    out: List[CommonFinding] = []
    seen = set()
    for root, _, files in os.walk(source_root):
        norm = root.replace("\\", "/") + "/"
        if any(x in norm for x in ("/.git/", "/build/", "/target/", "/node_modules/", "/src/test/", "/.venv")):
            continue
        for fn in files:
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, source_root).replace("\\", "/")
            ext = os.path.splitext(fn)[1].lower()
            if ext in (".p12", ".pem", ".key", ".jks", ".pfx") and "/resources/" in norm:
                f = _mk(rel, 1, "Hardcoded Private Key / Keystore in Source Control", f"Key material committed: {fn}", "KEY")
                f.quantum_flag = True
                out.append(f)
                continue
            if ext == ".java":
                try:
                    lines = open(full, encoding="utf-8", errors="ignore").read().splitlines()
                except OSError:
                    continue
                for i, ln in enumerate(lines):
                    s = ln.strip()
                    if s.startswith(("//", "*", "/*", "import ")):
                        continue
                    for m in _JAVA_ASSIGN.finditer(ln):
                        if _looks_secret(m.group(1), m.group(2)) and (rel, i) not in seen:
                            seen.add((rel, i))
                            out.append(_mk(rel, i + 1, f"Hard-coded Secret ({m.group(1)})", s, "JAVA"))
                    for pat, label in _JAVA_CALLS:
                        m = pat.search(ln)
                        if m and not _PLACEHOLDER.match(m.group(1)) and (rel, i) not in seen:
                            seen.add((rel, i))
                            out.append(_mk(rel, i + 1, f"Hard-coded {label}", s, "JAVA"))
            elif ext in (".properties", ".yml", ".yaml", ".env", ".conf") or fn.startswith(".env"):
                if "/resources/" not in norm and ext != ".env" and not fn.startswith(".env"):
                    continue
                try:
                    lines = open(full, encoding="utf-8", errors="ignore").read().splitlines()
                except OSError:
                    continue
                for i, ln in enumerate(lines):
                    s = ln.strip()
                    if not s or s.startswith(("#", "!", "//")):
                        continue
                    m = re.match(r"([\w.\-\[\]]+)\s*[=:]\s*(.*)$", s)
                    if not m or not _PROP_KEY.search(m.group(1)):
                        continue
                    val = m.group(2).strip().strip("'\"")
                    if _PLACEHOLDER.match(val) or "${" in val or val.lower() in _SELF_WORDS:
                        continue
                    if re.search(r"(?i)(?:expir\w*|ttl|length|enabled|header|prefix|path|url|type|name)$", m.group(1)):
                        continue
                    out.append(_mk(rel, i + 1, "Hardcoded Credential in Configuration", s, "PROP"))
    return out
