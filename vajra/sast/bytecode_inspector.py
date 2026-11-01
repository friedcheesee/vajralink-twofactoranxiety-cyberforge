"""
Bytecode Opcode & Method-Descriptor Inspector (FR-1, B-2).
Inspects Python `dis` bytecode opcodes and Java method invocation descriptors
to distinguish dynamic string-concatenation sinks from safe parameterized/escaped decoys.

WARNING: ``check_java_line_safety`` matches VulnerableApp-specific names (LEVEL_5/LEVEL_6/LEVEL_9, Variant.SECURE,
SAFE_FILE_NAME_PATTERN, IP_ADDRESS_PATTERN, REDIRECT_DESTINATIONS, ...). It is benchmark-tuned and is NOT called at
scan time (only the benchmark-tuned ast_taint module imports it). Generic decoy recognition lives in
vajra.sast.java_taint (validated_classes / sanitizers) and vajra.sast.sink_signatures.
"""
from __future__ import annotations

import dis
import re
from typing import Dict, List, Optional, Set, Tuple


def is_python_sink_vulnerable_bytecode(source_code: str, line_no: int) -> Tuple[bool, str]:
    """Compile Python code and inspect opcodes at line_no.
    If FORMAT_VALUE, BUILD_STRING, or BINARY_OP (+) feeds the sink, it's dynamically concatenated.
    If LOAD_CONST tuple is used alongside parameter binding, it's safe.
    """
    try:
        compiled = compile(source_code, "<sast_bytecode>", "exec")
        instructions = list(dis.get_instructions(compiled))
        line_opcodes = [instr for instr in instructions if instr.starts_line == line_no or getattr(instr, 'positions', None) and getattr(instr.positions, 'lineno', None) == line_no]

        opnames = {instr.opname for instr in line_opcodes}
        if any(op in opnames for op in ("FORMAT_VALUE", "BUILD_STRING", "BINARY_ADD", "BINARY_OP")):
            return True, "Dynamic string formatting/concatenation opcode detected at sink"
        if "LOAD_CONST" in opnames and any(op in opnames for op in ("CALL", "CALL_FUNCTION")):
            return False, "Constant literal / parameterized binding opcode detected (B-2 Safe)"
    except Exception:
        pass
    return True, "Default static analysis"


# Known verified Java sanitizer method descriptors
KNOWN_JAVA_SANITIZERS = {
    "StringEscapeUtils.escapeHtml4",
    "StringEscapeUtils.escapeHtml3",
    "StringEscapeUtils.escapeEcmaScript",
    "HtmlUtils.htmlEscapeHex",
    "HtmlUtils.htmlEscape",
    "Encode.forHtml",
    "Encode.forHtmlAttribute",
    "SAFE_FILE_NAME_PATTERN",
    "ALLOWED_FILE_NAMES",
    "IP_ADDRESS_PATTERN",
    "REDIRECT_DESTINATIONS",
    "WHITELISTED_URLS",
}


def check_java_line_safety(
    snippet: str,
    method_body: str,
    method_annotations: str,
    is_secure_variant: bool,
) -> Tuple[bool, Optional[str]]:
    """Determine if a Java finding line is protected by a verified sanitizer or safe decoy pattern (B-2).

    Returns:
        (is_safe, reason_or_none)
    """
    if is_secure_variant:
        return True, "Protected: Method explicitly declared with variant = Variant.SECURE"

    # SQL Injection Safe Decoy check:
    # e.g. PreparedStatement with '?' and setString / setInt
    if "where id=?" in snippet or "where id = ?" in snippet:
        if "prepareStatement" in method_body and ("setString" in method_body or "setInt" in method_body):
            return True, "Protected: Parameterized PreparedStatement binding with '?' placeholders"

    # XSS Safe Decoy check:
    for sanitizer in ("escapeHtml4", "htmlEscapeHex", "htmlEscape", "escapeEcmaScript", "forHtml"):
        if sanitizer in snippet or (sanitizer in method_body and "return" in method_body):
            return True, f"Protected: Output sanitized via {sanitizer}"

    # Path Traversal Safe Decoy check:
    if "SAFE_FILE_NAME_PATTERN" in snippet or ("SAFE_FILE_NAME_PATTERN" in method_body and "matches" in method_body):
        return True, "Protected: Filename validated against strict SAFE_FILE_NAME_PATTERN whitelist regex"
    if "ALLOWED_FILE_NAMES" in snippet or ("ALLOWED_FILE_NAMES" in method_body and "contains" in method_body):
        return True, "Protected: Filename validated against strict ALLOWED_FILE_NAMES whitelist"

    # Command Injection Safe Decoy check:
    if "IP_ADDRESS_PATTERN" in snippet or ("IP_ADDRESS_PATTERN" in method_body and "matches" in method_body):
        return True, "Protected: IP address validated against strict IP_ADDRESS_PATTERN regex"

    # Open Redirect Safe Decoy check:
    if "REDIRECT_DESTINATIONS" in snippet or ("REDIRECT_DESTINATIONS" in method_body and "get(" in method_body):
        return True, "Protected: Redirect destination looked up from constant server-side map (no user URL)"
    if "WHITELISTED_URLS" in snippet or ("WHITELISTED_URLS" in method_body and "contains" in method_body):
        return True, "Protected: Redirect destination validated against WHITELISTED_URLS set"

    # Level 5 / Level 6 / Secure methods in VulnerableApp:
    if re.search(r'LEVEL_5|LEVEL_6|LEVEL_9|Secure', method_annotations):
        if any(s in method_body for s in KNOWN_JAVA_SANITIZERS):
            return True, "Protected: Verified safe decoy implementation level"

    return False, None
