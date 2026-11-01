"""
Semgrep backend that works on Windows.

Semgrep OSS has no native Windows build (the pip package installs a launcher but not `semgrep-core`), so the runner
picks the first backend that actually works:

  1. native   - a `semgrep` CLI on PATH that answers `--version` (Linux / macOS / WSL)
  2. docker   - the official `semgrep/semgrep` image: the source tree and the rules directory are bind-mounted read-only,
                nothing is written into the target. This is the Windows path.

Rules: the repo-specific rules synthesised by `rule_synthesizer` (spring meta-annotations, helper wrappers ...).
Optional registry packs (e.g. `p/java`) can be enabled with VAJRA_SEMGREP_PACKS="p/java,p/owasp-top-ten" (needs network).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from vajra.models import CommonFinding, canonicalize_cwe
from vajra.routemap.java_spring import find_enclosing_method

DOCKER_IMAGE = os.getenv("VAJRA_SEMGREP_IMAGE", "semgrep/semgrep:latest")
_SEV = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


def _run(cmd: List[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _native_works() -> Optional[str]:
    exe = shutil.which("semgrep")
    if not exe:
        return None
    try:
        p = _run([exe, "--version"], 30)
        out = (p.stdout or "").strip().splitlines()
        if p.returncode == 0 and out and re.match(r"^\d+\.\d+", out[-1]):
            return out[-1]
    except Exception:
        pass
    return None


def _docker_ready() -> Tuple[bool, str]:
    if not shutil.which("docker"):
        return False, "docker CLI not found"
    try:
        if _run(["docker", "info", "--format", "{{.ServerVersion}}"], 20).returncode != 0:
            return False, "Docker daemon is not running"
        if _run(["docker", "image", "inspect", DOCKER_IMAGE], 20).returncode != 0:
            return False, f"image {DOCKER_IMAGE} not installed - run: docker pull {DOCKER_IMAGE}"
        return True, "ok"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"[:160]


def semgrep_backend() -> Dict[str, Any]:
    """{"available": bool, "mode": "native"|"docker", "version": ..., "reason": ...}"""
    ver = _native_works()
    if ver:
        return {"available": True, "mode": "native", "version": ver}
    ok, why = _docker_ready()
    if ok:
        try:
            v = _run(["docker", "run", "--rm", DOCKER_IMAGE, "semgrep", "--version"], 60)
            version = (v.stdout or "").strip().splitlines()[-1] if v.returncode == 0 and v.stdout.strip() else ""
        except Exception:
            version = ""
        return {"available": True, "mode": "docker", "version": version}
    return {"available": False, "mode": None, "reason": f"native semgrep unavailable on this OS; Docker fallback: {why}"}


def _docker_path(p: str) -> str:
    return os.path.abspath(p).replace("\\", "/")


def _cwe_from_meta(meta: Dict[str, Any]) -> str:
    cwe = meta.get("cwe")
    if isinstance(cwe, list) and cwe:
        cwe = cwe[0]
    m = re.search(r"CWE-\d+", str(cwe or ""))
    return m.group(0) if m else "CWE-Other"


def run_semgrep(rules_file: str, source_root: str, timeout: int = 300) -> Tuple[List[CommonFinding], Dict[str, Any]]:
    from vajra.sast.engines import ENGINE_SEMGREP

    be = semgrep_backend()
    if not be["available"]:
        return [], {"status": "UNAVAILABLE", "reason": be["reason"]}

    packs = [x.strip() for x in os.getenv("VAJRA_SEMGREP_PACKS", "").split(",") if x.strip()]
    rules_abs = os.path.abspath(rules_file)
    try:
        if be["mode"] == "native":
            cmd = [shutil.which("semgrep") or "semgrep", "scan", "--config", rules_abs]
            for pk in packs:
                cmd += ["--config", pk]
            cmd += ["--json", "--metrics=off", "--disable-version-check", "--quiet", "--timeout", "15", source_root]
            root_prefix = None
        else:
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{_docker_path(source_root)}:/src:ro",
                "-v", f"{_docker_path(os.path.dirname(rules_abs))}:/rules:ro",
                DOCKER_IMAGE, "semgrep", "scan", "--config", f"/rules/{os.path.basename(rules_abs)}",
            ]
            for pk in packs:
                cmd += ["--config", pk]
            cmd += ["--json", "--metrics=off", "--disable-version-check", "--quiet", "--timeout", "15", "/src"]
            root_prefix = "/src/"
        proc = _run(cmd, timeout)
        if not proc.stdout.strip():
            return [], {"status": "FAILED", "mode": be["mode"], "reason": (proc.stderr or "no output")[-300:]}
        data = json.loads(proc.stdout)
    except Exception as exc:
        return [], {"status": "FAILED", "mode": be["mode"], "reason": f"{type(exc).__name__}: {exc}"[:300]}

    hard_errors = [e for e in data.get("errors", []) if e.get("level") == "error" and e.get("code") in (2, 7)]
    if hard_errors and not data.get("results"):
        return [], {"status": "FAILED", "mode": be["mode"], "reason": str(hard_errors[0].get("message"))[:300]}

    findings: List[CommonFinding] = []
    line_cache: Dict[str, List[str]] = {}
    for res in data.get("results", []):
        path = res.get("path", "")
        rel = path[len(root_prefix):] if root_prefix and path.startswith(root_prefix) else (
            os.path.relpath(path, source_root) if os.path.isabs(path) else path
        )
        rel = rel.replace("\\", "/")
        line_no = res.get("start", {}).get("line", 1)
        meta = res.get("extra", {}).get("metadata", {}) or {}
        raw_cwe = _cwe_from_meta(meta)
        if rel not in line_cache:
            try:
                line_cache[rel] = open(os.path.join(source_root, rel), encoding="utf-8", errors="ignore").read().splitlines()
            except Exception:
                line_cache[rel] = []
        lines = line_cache[rel]
        snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else (res.get("extra", {}).get("lines") or "")
        fn, _s, m_end, guard = find_enclosing_method(lines, line_no) if lines else (None, None, None, None)
        rule = res.get("check_id", "semgrep-rule").split(".")[-1]
        findings.append(
            CommonFinding(
                finding_id=f"SAST-SEMGREP-{rule}-{rel}-{line_no}",
                stage="SAST",
                scanner="Semgrep",
                cwe=canonicalize_cwe(raw_cwe),
                raw_cwe=raw_cwe,
                vuln_type=(res.get("extra", {}).get("message") or rule)[:60],
                severity=_SEV.get((res.get("extra", {}).get("severity") or "").upper(), "MEDIUM"),  # type: ignore[arg-type]
                file_path=rel,
                line=line_no,
                end_line=m_end,
                function_name=fn,
                guard_snippet=guard,
                code_snippet=snippet,
                engines=[ENGINE_SEMGREP],
            )
        )
    return findings, {
        "status": "OK", "mode": be["mode"], "version": be.get("version", ""), "rules": rules_abs and os.path.basename(rules_abs),
        "registry_packs": packs, "rule_errors": len([e for e in data.get("errors", []) if e.get("level") == "warn" or e.get("type") == "RuleParseError" or "pattern" in str(e.get("type", "")).lower()]),
    }
