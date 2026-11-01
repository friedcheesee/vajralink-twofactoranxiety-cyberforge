"""
SAST engine registry & attribution.

Every SAST finding records which engine(s) independently flagged it, so the UI/report can answer
"who found this?" and the correlator can use multi-engine agreement as evidence.

Engines (honest descriptions of what each one really does):
  * AST_TAINT   - Vajra Java AST Taint Engine: method-span aware, benchmark-tuned sink recognisers
                  (includes file-specific recognisers for the VulnerableApp service classes).
  * SINK_SIG    - Vajra Sink-Signature Scanner: *generic*, target-agnostic rules over Java sink APIs
                  (JdbcTemplate, ProcessBuilder, getResourceAsStream, openConnection, unmarshal, Location header,
                  MessageDigest, Random, LDAP search ...) with a lightweight "is the argument dynamic?" check.
  * SEMGREP     - Semgrep OSS with Vajra-synthesised Java rules. Native CLI where it works (Linux/macOS); on Windows it
                  runs through the official semgrep/semgrep Docker image.
  * BANDIT      - Bandit, the Python AST security linter (runs only when the target contains Python source).
  * SECRETS     - Entropy / key-material scanner over resource files.
  * DECOY       - Sanitizer / Variant.SECURE inspector (source-level descriptor checks). It does not emit
                  vulnerabilities; it *suppresses* safe decoys.
"""
from __future__ import annotations

import shutil
import subprocess
from typing import Dict, List, Optional

ENGINE_AST_TAINT = "Java AST Taint"
ENGINE_SINK_SIG = "Sink-Signature Scanner"
ENGINE_SEMGREP = "Semgrep (synthesized Java rules)"
ENGINE_SECRETS = "Secret & Key Scanner"
ENGINE_BANDIT = "Bandit (Python)"
ENGINE_DECOY = "Sanitizer / Decoy Inspector"

# raw scanner string (CommonFinding.scanner) -> engine label
SCANNER_TO_ENGINE: Dict[str, str] = {
    "Vajra-AST-Taint": ENGINE_AST_TAINT,
    "Vajra-SinkSig": ENGINE_SINK_SIG,
    "Semgrep": ENGINE_SEMGREP,
    "Vajra-Secret-Scanner": ENGINE_SECRETS,
    "Bandit": ENGINE_BANDIT,
}

ENGINE_META: Dict[str, Dict[str, str]] = {
    ENGINE_AST_TAINT: {
        "key": "ast",
        "color": "#3b82f6",
        "icon": "🔵",
        "kind": "Custom AST / call-graph",
        "java_optimizations": "Method-span resolution, constant folding, @Service DI tracking",
    },
    ENGINE_SINK_SIG: {
        "key": "sinksig",
        "color": "#f59e0b",
        "icon": "🟠",
        "kind": "Generic sink-API signatures",
        "java_optimizations": "JDBC/ProcessBuilder/URLConnection/JAXB/Location-header sink catalog + dynamic-argument check",
    },
    ENGINE_SEMGREP: {
        "key": "semgrep",
        "color": "#a855f7",
        "icon": "🟣",
        "kind": "Semgrep OSS + synthesized rules",
        "java_optimizations": "Repo-specific rules for Spring meta-annotations and helper wrappers",
    },
    ENGINE_SECRETS: {
        "key": "secrets",
        "color": "#ef4444",
        "icon": "🔴",
        "kind": "Secret / key-material scanner",
        "java_optimizations": "Keystores (.p12), PEM keys, properties credentials",
    },
    ENGINE_BANDIT: {
        "key": "bandit",
        "color": "#0d9488",
        "icon": "🟦",
        "kind": "Bandit - Python AST security linter",
        "java_optimizations": "Python sources only: subprocess/shell, eval/exec, pickle/yaml deserialisation, weak hashes, SQL string building, hard-coded passwords, requests verify=False",
    },
    ENGINE_DECOY: {
        "key": "decoy",
        "color": "#10b981",
        "icon": "🟢",
        "kind": "Sanitizer / safe-variant gate",
        "java_optimizations": "PreparedStatement '?' binding, HTML encoders, regex allow-lists, Variant.SECURE",
    },
}


def engine_for_scanner(scanner: Optional[str]) -> str:
    return SCANNER_TO_ENGINE.get(scanner or "", scanner or "Unknown")


def semgrep_available() -> Dict[str, object]:
    """Back-compat shim: see vajra.sast.semgrep_runner.semgrep_backend (native -> Docker fallback)."""
    from vajra.sast.semgrep_runner import semgrep_backend

    return semgrep_backend()


def add_engine(finding, engine: str) -> None:
    """Idempotently attribute `engine` to a CommonFinding."""
    if engine and engine not in finding.engines:
        finding.engines.append(engine)
