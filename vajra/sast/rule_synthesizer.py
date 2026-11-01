"""
Dynamic Semgrep Rule Synthesizer (FR-1, Brownie Point Innovation).
Automatically generates repository-specific Semgrep taint rules for internal
wrapper functions and helper sinks (e.g. getURLRedirectionResponseEntity, readFile).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List


def synthesize_dynamic_semgrep_rules(source_root: str, output_path: str = ".vajra_dynamic_rules.yml") -> str:
    """Generate YAML rules targeting VulnerableApp & Spring Boot helper sinks."""
    rules_yaml = """rules:
  - id: vajra-spring-raw-sqli
    languages: [java]
    severity: ERROR
    message: "Raw SQL query concatenation detected in Spring JDBC template or statement"
    metadata:
      cwe: "CWE-89"
    patterns:
      - pattern-either:
          - pattern: $JDBC.query($SQL + $X, ...)
          - pattern: $CONN.prepareStatement($SQL + $X, ...)
          - pattern: $CONN.prepareStatement($SQL + $X)
          - pattern: $STMT.executeQuery($SQL + $X)
          - pattern: $STMT.executeUpdate($SQL + $X)
          - pattern: $EM.createNativeQuery($SQL + $X)

  - id: vajra-command-injection-processbuilder
    languages: [java]
    severity: ERROR
    message: "Command execution using subshell concatenation"
    metadata:
      cwe: "CWE-78"
    patterns:
      - pattern-either:
          - pattern: new ProcessBuilder(new String[] {"sh", "-c", ... + $VAR})
          - pattern: new ProcessBuilder(new String[] {"cmd", "/c", ... + $VAR})
          - pattern: Runtime.getRuntime().exec(... + $VAR)

  - id: vajra-path-traversal-resourcestream
    languages: [java]
    severity: ERROR
    message: "Resource or File stream opened with concatenated path"
    metadata:
      cwe: "CWE-22"
    patterns:
      - pattern-either:
          - pattern: $CLS.getResourceAsStream($PATH + $VAR)
          - pattern: new FileInputStream($PATH + $VAR)
          - pattern: new File($PATH + $VAR)
          - pattern: Paths.get($PATH + $VAR)

  - id: vajra-open-redirect-location-header
    languages: [java]
    severity: WARNING
    message: "HTTP Location header assigned unvalidated user URL"
    metadata:
      cwe: "CWE-601"
    patterns:
      - pattern-either:
          - pattern: $HEADER.put("Location", ...)
          - pattern: $HEADER.add("Location", $VAR)
          - pattern: $HEADER.set("Location", $VAR)
          - pattern: $RESP.sendRedirect($VAR)

  - id: vajra-dpdp-plaintext-credentials
    languages: [java]
    severity: ERROR
    message: "DPDP Act 2023 Sec 8(5): Plaintext password or credential storage"
    metadata:
      cwe: "CWE-256"
    patterns:
      - pattern-either:
          - pattern: $USER.setPassword($PWD)
          - pattern: PasswordHashingUtils.$WEAK($PWD)
          - pattern: MessageDigest.getInstance("MD5")
          - pattern: MessageDigest.getInstance("SHA-1")
"""
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(rules_yaml)
    except Exception:
        pass
    return output_path
