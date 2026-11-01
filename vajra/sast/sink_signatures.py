"""
Vajra Sink-Signature Scanner - a *generic*, target-agnostic Java SAST engine.

This engine (no benchmark-specific recognisers) only
uses well-known sink APIs plus a light "is the sink argument attacker-influenced?" check:

  1. find a sink call (JdbcTemplate.query, ProcessBuilder, getResourceAsStream, openConnection, unmarshal, ...)
  2. extract the sink argument and decide whether it is dynamic (concatenation / method parameter / variable
     assigned from a dynamic expression) or a compile-time constant
  3. look for a dominating sanitizer or a ``Variant.SECURE`` marker -> emit a *suppressed decoy* instead

It therefore gives an independent second opinion that can be graded against ground truth on its own.
"""
from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Tuple

from vajra.models import CommonFinding, canonicalize_cwe
from vajra.routemap.java_spring import extract_method_defs
from vajra.sast.engines import ENGINE_DECOY, ENGINE_SINK_SIG

SCANNER = "Vajra-SinkSig"
# Variant.SECURE is a VulnerableApp-only annotation. It is NOT used for decoy suppression unless explicitly enabled
# (VAJRA_USE_VARIANT_HINT=1); decoys are recognised from the code itself (placeholders, validators, sanitizers).
USE_VARIANT_HINT = os.getenv("VAJRA_USE_VARIANT_HINT", "0") == "1"

_JAVA_NON_DYNAMIC = {
    "new", "this", "class", "null", "true", "false", "getclass", "length", "string", "int", "long", "boolean",
    "return", "super", "instanceof", "final", "void", "var", "get", "toString".lower(), "stream", "classloader",
    "getclassloader", "getname", "values", "of", "asList".lower(), "conn", "connection", "ps",
}

_STRING_LIT = re.compile(r'"(?:\\.|[^"\\])*"')
_CHAR_LIT = re.compile(r"'(?:\\.|[^'\\])'")
_CONST_TOKEN = re.compile(r"\b[A-Z][A-Z0-9_]{2,}\b")
_QUALIFIED_CONST = re.compile(r"\b[A-Z][A-Za-z0-9_]*\.[A-Z][A-Z0-9_]+\b")
_TYPE_TOKEN = re.compile(r"\b[A-Z][A-Za-z0-9_]*\b")
_IDENT = re.compile(r"\b[a-z_][A-Za-z0-9_]*\b")


def _balanced_args(text: str, open_idx: int) -> str:
    """Return the text between the parenthesis at `open_idx` and its matching ')'."""
    depth = 0
    in_str: Optional[str] = None
    i = open_idx
    start = open_idx + 1
    while i < len(text):
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
        else:
            if ch in ('"', "'"):
                in_str = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return text[start:i]
        i += 1
    return text[start:]


def _split_top_level(args: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    cur: List[str] = []
    in_str: Optional[str] = None
    i = 0
    while i < len(args):
        ch = args[i]
        if in_str:
            cur.append(ch)
            if ch == "\\" and i + 1 < len(args):
                cur.append(args[i + 1])
                i += 2
                continue
            if ch == in_str:
                in_str = None
        else:
            if ch in ('"', "'"):
                in_str = ch
                cur.append(ch)
            elif ch in "([{<" and ch != "<":
                depth += 1
                cur.append(ch)
            elif ch in ")]}":
                depth -= 1
                cur.append(ch)
            elif ch == "," and depth == 0:
                parts.append("".join(cur))
                cur = []
            else:
                cur.append(ch)
        i += 1
    if cur:
        parts.append("".join(cur))
    return [p.strip() for p in parts]


def _is_dynamic(expr: str, method_text: str, depth: int = 0) -> bool:
    """True if `expr` can carry attacker data (non-constant identifier, method param, dynamic local)."""
    if not expr:
        return False
    if depth == 0:
        method_text = _STRING_LIT.sub('""', method_text)  # never resolve identifiers inside string literals
    cleaned = _STRING_LIT.sub('""', expr)
    cleaned = _CHAR_LIT.sub("''", cleaned)
    cleaned = _QUALIFIED_CONST.sub("", cleaned)
    cleaned = _CONST_TOKEN.sub("", cleaned)
    cleaned = re.sub(r"\bnew\s+[A-Za-z0-9_<>\[\]\.]+", " ", cleaned)
    # drop method-call names but keep their arguments: foo.bar(x) -> x
    cleaned = re.sub(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\(", "(", cleaned)
    cleaned = _TYPE_TOKEN.sub("", cleaned)
    tokens = [t for t in _IDENT.findall(cleaned) if t.lower() not in _JAVA_NON_DYNAMIC]
    if not tokens:
        return False
    for tok in tokens:
        assigns = re.findall(rf"\b{re.escape(tok)}\s*=(?!=)\s*([^;]+);", method_text)
        if assigns and depth < 3:
            if any(_is_dynamic(rhs, method_text, depth + 1) for rhs in assigns):
                return True
            continue  # every assignment is constant -> this token is constant
        return True  # parameter / field / unknown -> assume attacker-influenced
    return False


def _validated_any(expr, method_text: str) -> bool:
    """Generic validator check: some identifier of `expr` is regex-matched / allow-list-checked in the method."""
    from vajra.sast.java_taint import validated_classes, ALL
    if isinstance(expr, list):
        expr = " ".join(expr)
    cleaned = _STRING_LIT.sub('""', expr or "")
    for tok in set(re.findall(r"\b[A-Za-z_]\w*\b", cleaned)):
        if validated_classes(tok, method_text) == ALL:
            return True
    return False


class _FileCtx:
    def __init__(self, content: str, rel_path: str):
        self.content = content
        self.rel_path = rel_path
        self.lines = content.splitlines()
        _, self.method_defs = extract_method_defs(self.lines)
        self.spans: List[Tuple[int, int, str]] = []
        for name, overloads in self.method_defs.items():
            for s, e, _, _ in overloads:
                self.spans.append((s, e, name))

    def enclosing(self, line_no: int) -> Tuple[Optional[str], int, int]:
        best: Optional[Tuple[int, int, str]] = None
        for s, e, n in self.spans:
            if s <= line_no <= e and (best is None or (e - s) < (best[1] - best[0])):
                best = (s, e, n)
        if not best:
            return None, 1, len(self.lines)
        return best[2], best[0], best[1]

    def method_text(self, start: int, end: int) -> str:
        return "\n".join(self.lines[start - 1:end])

    def statement(self, idx: int, max_lines: int = 10) -> str:
        buf = []
        for j in range(idx, min(len(self.lines), idx + max_lines)):
            buf.append(self.lines[j])
            t = self.lines[j].rstrip()
            if t.endswith(";") or t.endswith("{") or t.endswith("}"):
                break
        return "\n".join(buf)

    def is_secure_variant(self, method_start: int) -> bool:
        if not USE_VARIANT_HINT:
            return False
        for back in range(method_start - 2, max(-1, method_start - 40), -1):
            prev = self.lines[back].strip()
            if prev == "}" or prev.endswith("{") and "(" not in prev and "@" not in prev:
                break
            if "Variant.SECURE" in prev:
                return True
        return False


def _mk(ctx: _FileCtx, rule: str, cwe: str, raw: str, vtype: str, sev: str, line_no: int, snippet: str,
        *, fn: Optional[str], end: int, decoy_reason: Optional[str] = None, **flags) -> CommonFinding:
    engines = [ENGINE_SINK_SIG] + ([ENGINE_DECOY] if decoy_reason else [])
    return CommonFinding(
        finding_id=f"SAST-SINKSIG-{rule}-{ctx.rel_path}-{line_no}",
        stage="SAST",
        scanner=SCANNER,
        cwe=canonicalize_cwe(cwe),
        raw_cwe=raw,
        vuln_type=vtype,
        severity=sev,  # type: ignore[arg-type]
        file_path=ctx.rel_path,
        line=line_no,
        end_line=end,
        function_name=fn,
        code_snippet=snippet.strip()[:300],
        is_safe_decoy=bool(decoy_reason),
        suppression_reason=decoy_reason,
        engines=engines,
        **flags,
    )


# --------------------------------------------------------------------------------------
# Rules. Each returns Optional[(verdict, extra)] where verdict is "vuln" | "safe" | None
# --------------------------------------------------------------------------------------
_SQL_CALL = re.compile(
    r"\b(?:\w*[jJ]dbc\w*|jdbc|namedParameterJdbcTemplate)\s*\.\s*(?:query|queryForObject|queryForList|queryForMap|update|execute|batchUpdate)\s*\("
    r"|\.\s*(?:executeQuery|executeUpdate|createNativeQuery|createQuery)\s*\("
    r"|\.\s*prepareStatement\s*\("
)
_CMD_CALL = re.compile(r"\bnew\s+ProcessBuilder\s*\(|Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(")
_PATH_CALL = re.compile(
    r"\.\s*getResourceAsStream\s*\(|\bnew\s+FileInputStream\s*\(|\bnew\s+File\s*\(|\bPaths\s*\.\s*get\s*\("
    r"|\bFiles\s*\.\s*(?:readAllBytes|readString|newInputStream|readAllLines)\s*\("
)
_SSRF_CALL = re.compile(r"\.\s*openConnection\s*\(\s*\)|\.\s*openStream\s*\(\s*\)|\brestTemplate\s*\.\s*(?:getForObject|getForEntity|exchange|postForObject)\s*\(")
_XXE_CALL = re.compile(r"\.\s*unmarshal\s*\(")
_REDIR_CALL = re.compile(
    r"\.\s*(?:add|set|put|header|setHeader|addHeader)\s*\(\s*(?:\"Location\"|\"location\"|\w*LOCATION\w*|HttpHeaders\s*\.\s*LOCATION)\s*,"
    r"|\.\s*(?:sendRedirect|location|setLocation)\s*\(|\bnew\s+RedirectView\s*\(")
_LDAP_CALL = re.compile(r"\bconnection\s*\.\s*search\s*\(|\bldap\w*\s*\.\s*search\s*\(")
_HASH_CALL = re.compile(r"MessageDigest\s*\.\s*getInstance\s*\(\s*\"(MD2|MD4|MD5|SHA-?1|SHA1)\"", re.IGNORECASE)
_CIPHER_CALL = re.compile(r"Cipher\s*\.\s*getInstance\s*\(\s*\"((?:DES|DESede|RC2|RC4|Blowfish)[^\"]*|AES/ECB[^\"]*)\"", re.IGNORECASE)
_RANDOM_CALL = re.compile(r"\bnew\s+Random\s*\(")
_BCRYPT_LOW = re.compile(r"new\s+BCryptPasswordEncoder\s*\(\s*([0-9]|1[01])\s*\)")
_HEADER_PERMISSIVE = re.compile(r"\.\s*add\s*\(\s*\"X-Frame-Options\"\s*,\s*\"ALLOWALL\"")
_UPLOAD_CALL = re.compile(r"getOriginalFilename\s*\(\s*\)")
_SECRET_LIT = re.compile(
    r"\b(?:static\s+)?(?:final\s+)?String\s+([A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|API_?KEY|PRIVATE_?KEY|TOKEN)[A-Za-z0-9_]*)\s*=\s*\"([^\"]{6,})\"\s*;",
    re.IGNORECASE,
)
_TOKENISH_FILE = re.compile(r"(token|otp|session|password|nonce|csrf)", re.IGNORECASE)

_SQL_SAFE = re.compile(r"\bsetString\b|\bsetInt\b|\bsetLong\b|PreparedStatementSetter|\.setObject\b")
_XXE_HARDEN = re.compile(r"disallow-doctype-decl|IS_SUPPORTING_EXTERNAL_ENTITIES\s*,\s*(?:false|Boolean\.FALSE)|SUPPORT_DTD\s*,\s*(?:false|Boolean\.FALSE)|XMLConstants\.FEATURE_SECURE_PROCESSING")


def scan_java_source(content: str, rel_path: str) -> Tuple[List[CommonFinding], List[CommonFinding]]:
    ctx = _FileCtx(content, rel_path)
    active: List[CommonFinding] = []
    suppressed: List[CommonFinding] = []
    seen: set = set()
    file_tokenish = bool(_TOKENISH_FILE.search(os.path.basename(rel_path)) or _TOKENISH_FILE.search(content[:4000]))

    def emit(f: CommonFinding) -> None:
        key = (f.line, f.cwe, f.is_safe_decoy)
        if key in seen:
            return
        seen.add(key)
        (suppressed if f.is_safe_decoy else active).append(f)

    for idx, line in enumerate(ctx.lines):
        ln = idx + 1
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "*", "/*", "import ", "package ")):
            continue
        fn, m_start, m_end = ctx.enclosing(ln)
        m_text = ctx.method_text(m_start, m_end)
        secure_variant = ctx.is_secure_variant(m_start) if fn else False

        # ---------- SQL injection ----------
        m = _SQL_CALL.search(line)
        if m:
            stmt = ctx.statement(idx)
            call_pos = stmt.find(m.group(0))
            open_idx = stmt.find("(", call_pos + len(m.group(0)) - 1)
            args = _split_top_level(_balanced_args(stmt, open_idx))
            first = args[0] if args else ""
            if ".prepareStatement" in m.group(0) and first.startswith('"') and "?" in first and not re.search(r'"\s*\+', first):
                emit(_mk(ctx, "SQLI-PARAM", "CWE-89", "CWE-89", "Parameterized SQL (safe)", "INFO", ln, stripped,
                         fn=fn, end=m_end, decoy_reason="Parameterized PreparedStatement binding with '?' placeholders"))
            elif _is_dynamic(first, m_text):
                if secure_variant or (_SQL_SAFE.search(m_text) and "?" in m_text):
                    emit(_mk(ctx, "SQLI-SAFE", "CWE-89", "CWE-89", "SQL Injection (guarded)", "INFO", ln, stripped,
                             fn=fn, end=m_end, decoy_reason="Variant.SECURE or '?'-parameterised query with setter binding"))
                else:
                    emit(_mk(ctx, "SQLI", "CWE-89", "CWE-89", "SQL Injection", "CRITICAL", ln, stripped, fn=fn, end=m_end))

        # ---------- OS command injection ----------
        if _CMD_CALL.search(line):
            stmt = ctx.statement(idx)
            cmm = _CMD_CALL.search(stmt)
            open_idx = (cmm.end() - 1) if cmm else stmt.find("(")
            args = _balanced_args(stmt, open_idx)
            if _is_dynamic(args, m_text):
                if secure_variant or _validated_any(args, m_text):
                    emit(_mk(ctx, "CMDI-SAFE", "CWE-78", "CWE-77", "Command Injection (guarded)", "INFO", ln, stripped,
                             fn=fn, end=m_end, decoy_reason="Input validated against strict allow-list regex"))
                else:
                    emit(_mk(ctx, "CMDI", "CWE-78", "CWE-77", "Command Injection", "CRITICAL", ln, stripped, fn=fn, end=m_end))

        # ---------- Path traversal ----------
        if _PATH_CALL.search(line):
            stmt = ctx.statement(idx)
            pm = _PATH_CALL.search(stmt)
            open_idx = stmt.find("(", pm.start() + len(pm.group(0)) - 1)
            first = (_split_top_level(_balanced_args(stmt, open_idx)) or [""])[0]
            if _is_dynamic(first, m_text):
                if secure_variant or _validated_any(first, m_text) or re.search(r"startsWith\s*\(|getCanonicalPath", m_text):
                    emit(_mk(ctx, "PATH-SAFE", "CWE-22", "CWE-22", "Path Traversal (guarded)", "INFO", ln, stripped,
                             fn=fn, end=m_end, decoy_reason="Filename allow-list / canonical path containment check"))
                else:
                    emit(_mk(ctx, "PATH", "CWE-22", "CWE-22", "Path Traversal", "HIGH", ln, stripped, fn=fn, end=m_end))

        # ---------- SSRF ----------
        if _SSRF_CALL.search(line):
            url_args = re.findall(r"new\s+URL\s*\(([^)]*)\)", m_text)
            param_driven = bool(re.search(r"\(\s*(?:final\s+)?(?:String|URL|URI)\s+\w+", m_text.split("{", 1)[0])) or any(
                _is_dynamic(a, m_text) for a in url_args
            )
            if param_driven:
                if secure_variant or re.search(r"(?i)allow\w*\.\s*contains|isPrivateAddress|isAllowed\w*\s*\(", m_text):
                    emit(_mk(ctx, "SSRF-SAFE", "CWE-918", "CWE-918", "SSRF (guarded)", "INFO", ln, stripped,
                             fn=fn, end=m_end, decoy_reason="Destination validated against allow-list"))
                else:
                    emit(_mk(ctx, "SSRF", "CWE-918", "CWE-918", "SSRF", "HIGH", ln, stripped, fn=fn, end=m_end))

        # ---------- XXE ----------
        if _XXE_CALL.search(line):
            if _XXE_HARDEN.search(m_text) or secure_variant:
                emit(_mk(ctx, "XXE-SAFE", "CWE-611", "CWE-611", "XXE (hardened parser)", "INFO", ln, stripped,
                         fn=fn, end=m_end, decoy_reason="External entities / DTD disabled on the parser"))
            else:
                emit(_mk(ctx, "XXE", "CWE-611", "CWE-611", "XXE", "HIGH", ln, stripped, fn=fn, end=m_end))

        # ---------- Open redirect ----------
        if _REDIR_CALL.search(line):
            stmt = ctx.statement(idx)
            rm = _REDIR_CALL.search(stmt)
            open_idx = stmt.find("(", rm.start())
            args = _split_top_level(_balanced_args(stmt, open_idx))
            target = args[1] if len(args) > 1 else (args[0] if args else "")
            if _is_dynamic(target, m_text):
                if secure_variant or _validated_any(target, m_text):
                    emit(_mk(ctx, "REDIR-SAFE", "CWE-601", "CWE-601", "Open Redirect (guarded)", "INFO", ln, stripped,
                             fn=fn, end=m_end, decoy_reason="Redirect destination validated / looked up server-side"))
                else:
                    emit(_mk(ctx, "REDIR", "CWE-601", "CWE-601", "Open Redirect", "MEDIUM", ln, stripped, fn=fn, end=m_end))

        # ---------- LDAP injection ----------
        if _LDAP_CALL.search(line):
            if secure_variant or re.search(r"Filter\.encodeValue|LdapEncoder|escapeLDAP", m_text):
                emit(_mk(ctx, "LDAP-SAFE", "CWE-90", "CWE-90", "LDAP Injection (guarded)", "INFO", ln, stripped,
                         fn=fn, end=m_end, decoy_reason="LDAP filter value encoded"))
            elif re.search(r"\bfilter\b", m_text) and re.search(r'"\s*\+|String\.format', m_text):
                emit(_mk(ctx, "LDAP", "CWE-90", "CWE-90", "LDAP Injection", "HIGH", ln, stripped, fn=fn, end=m_end))

        # ---------- Weak crypto / randomness ----------
        hm = _HASH_CALL.search(line)
        if hm:
            emit(_mk(ctx, "HASH", "CWE-327", "CWE-327", f"Weak Hash Algorithm ({hm.group(1).upper()})", "HIGH", ln, stripped,
                     fn=fn, end=m_end, quantum_flag=True))
        cm = _CIPHER_CALL.search(line)
        if cm:
            emit(_mk(ctx, "CIPHER", "CWE-327", "CWE-327", f"Weak Cipher ({cm.group(1)})", "HIGH", ln, stripped,
                     fn=fn, end=m_end, quantum_flag=True))
        if _RANDOM_CALL.search(line) and file_tokenish and "SecureRandom" not in line:
            emit(_mk(ctx, "RANDOM", "CWE-327", "CWE-330", "Insecure Randomness (java.util.Random)", "MEDIUM", ln, stripped,
                     fn=fn, end=m_end))
        if _BCRYPT_LOW.search(line):
            emit(_mk(ctx, "BCRYPT", "CWE-327", "CWE-916", "Weak Password Hashing (low BCrypt cost)", "MEDIUM", ln, stripped,
                     fn=fn, end=m_end))

        # ---------- Security headers ----------
        if _HEADER_PERMISSIVE.search(line):
            emit(_mk(ctx, "XFO", "CWE-693", "CWE-1021", "Permissive X-Frame-Options (ALLOWALL)", "MEDIUM", ln, stripped,
                     fn=fn, end=m_end))

        # ---------- Unrestricted upload ----------
        if _UPLOAD_CALL.search(line) and re.search(r"Paths\s*\.\s*get|\.resolve\s*\(|new\s+File\s*\(|Files\s*\.\s*copy", ctx.statement(idx)):
            if not re.search(r"\.endsWith\s*\(|ALLOWED_EXT|contentType|getContentType", m_text):
                emit(_mk(ctx, "UPLOAD", "CWE-434", "CWE-434", "Unrestricted File Upload", "HIGH", ln, stripped, fn=fn, end=m_end))

        # ---------- Hard-coded secrets in Java ----------
        sm = _SECRET_LIT.search(line)
        if sm:
            emit(_mk(ctx, "SECRET", "CWE-798", "CWE-798", f"Hard-coded Secret ({sm.group(1)})", "HIGH", ln, stripped,
                     fn=fn, end=m_end, vault_candidate=True))

    return active, suppressed


def scan_file_sink_signatures(full_path: str, project_root: str) -> Tuple[List[CommonFinding], List[CommonFinding]]:
    norm = full_path.replace("\\", "/")
    if "/src/test/" in norm:
        return [], []
    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    rel = os.path.relpath(full_path, project_root).replace("\\", "/")
    return scan_java_source(content, rel)
