"""
Bandit engine (Python AST security linter).

Bandit only understands Python, so on a Java target it is reported NOT_APPLICABLE instead of silently doing nothing.
When Python source is present (Flask/Django/FastAPI services, scripts, the VajraLink code itself) every Bandit issue
becomes a SAST finding with its CWE (Bandit >= 1.7.5 ships one per test), severity and a source snippet.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

from vajra.models import CommonFinding, canonicalize_cwe

EXCLUDE_DIRS = {".git", ".venv", ".venv-win", "venv", "env", "node_modules", "site-packages", "__pycache__", "build", "dist", ".tox"}
BANDIT_EXCLUDE = ",".join(f"*/{d}/*" for d in sorted(EXCLUDE_DIRS)) + ",*/.venv*"
# B101 (assert_used) is pure noise outside production code; override with VAJRA_BANDIT_SKIP="" to keep it
SKIP_TESTS = os.getenv("VAJRA_BANDIT_SKIP", "B101") or "B000"
_SEV = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}


def python_files(root: str, limit: int = 1) -> List[str]:
    found: List[str] = []
    for r, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".venv")]
        for f in files:
            if f.endswith(".py"):
                found.append(os.path.join(r, f))
                if len(found) >= limit:
                    return found
    return found


def bandit_installed() -> Optional[str]:
    try:
        p = subprocess.run([sys.executable, "-m", "bandit", "--version"], capture_output=True, text=True, timeout=30)
        if p.returncode == 0:
            return (p.stdout.strip().splitlines() or [""])[0]
    except Exception:
        pass
    return None


def run_bandit(source_root: str, timeout: int = 180) -> Tuple[List[CommonFinding], Dict[str, Any]]:
    from vajra.sast.engines import ENGINE_BANDIT

    ver = bandit_installed()
    if not ver:
        return [], {"status": "UNAVAILABLE", "reason": "bandit is not installed in this environment (pip install bandit)"}
    n_py = len(python_files(source_root, limit=10_000))
    if n_py == 0:
        return [], {"status": "NOT_APPLICABLE", "version": ver, "reason": "no Python source in the target (Bandit analyses Python only)", "python_files": 0}
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "bandit", "-r", source_root, "-f", "json", "-q", "-x", BANDIT_EXCLUDE, "-s", SKIP_TESTS],
            capture_output=True, text=True, timeout=timeout,
        )
        data = json.loads(proc.stdout) if proc.stdout.strip() else {}
    except Exception as exc:
        return [], {"status": "FAILED", "version": ver, "reason": f"{type(exc).__name__}: {exc}"[:300]}

    findings: List[CommonFinding] = []
    for r in data.get("results", []):
        rel = os.path.relpath(r["filename"], source_root).replace("\\", "/")
        cwe_id = (r.get("issue_cwe") or {}).get("id")
        raw_cwe = f"CWE-{cwe_id}" if cwe_id else "CWE-Other"
        sev = _SEV.get(str(r.get("issue_severity", "MEDIUM")).upper(), "MEDIUM")
        code = (r.get("code") or "").strip().splitlines()
        snippet = next((ln.split(None, 1)[1].strip() for ln in code if ln.split(None, 1)[0].isdigit() and int(ln.split(None, 1)[0]) == r["line_number"] and len(ln.split(None, 1)) > 1), "")
        findings.append(
            CommonFinding(
                finding_id=f"SAST-BANDIT-{r['test_id']}-{rel}-{r['line_number']}",
                stage="SAST",
                scanner="Bandit",
                cwe=canonicalize_cwe(raw_cwe),
                raw_cwe=raw_cwe,
                vuln_type=f"{r['test_id']} {r.get('issue_text', '')}"[:80],
                severity=sev,  # type: ignore[arg-type]
                file_path=rel,
                line=r["line_number"],
                code_snippet=snippet or (code[0] if code else ""),
                engines=[ENGINE_BANDIT],
            )
        )
    return findings, {
        "status": "OK", "version": ver, "python_files": n_py,
        "by_confidence": {k: sum(1 for r in data.get("results", []) if r.get("issue_confidence") == k) for k in ("HIGH", "MEDIUM", "LOW")},
    }
