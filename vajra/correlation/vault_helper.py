"""
HashiCorp Vault Secret Migration Helper.

Builds a KV v2 migration plan from the REAL hard-coded-secret findings SAST produced for the current target
(findings flagged vault_candidate / CWE-798). Every entry points at a real file:line; the secret key name is the
real property / constant name read from that line; values are masked in the plan (never echoed in full); Vault
paths, the Spring Cloud Vault config and the `vault kv put` commands are derived from what was actually found -
nothing is padded with example paths.

execute_vault_sync() performs a REAL write to a Vault server over its HTTP API (KV v2) - only when VAULT_ADDR and
VAULT_TOKEN are explicitly configured - and reports honestly when it is not configured or not reachable.
"""
from __future__ import annotations

import base64
import os
import re
from typing import Any, Dict, List, Optional, Tuple

import httpx

_PROP_RE = re.compile(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*[=:]\s*(.*?)\s*$")
_JAVA_CONST_RE = re.compile(r"\bString\s+([A-Za-z0-9_]+)\s*=\s*\"([^\"]*)\"")
_JSON_KV_RE = re.compile(r"\"([A-Za-z0-9_.\-]+)\"\s*:\s*\"([^\"]*)\"")
_KEYSTORE_EXT = (".p12", ".pfx", ".jks", ".pem", ".key", ".keystore")


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-") or "app"


def _mask(v: str) -> str:
    if not v:
        return ""
    if len(v) <= 4:
        return "*" * len(v)
    return f"{v[:2]}{'*' * min(8, len(v) - 4)}{v[-2:]}  ({len(v)} chars)"


def _read_line(source_root: Optional[str], rel: str, line: int) -> str:
    if not source_root:
        return ""
    try:
        with open(os.path.join(source_root, rel), "r", encoding="utf-8", errors="ignore") as fh:
            for i, ln in enumerate(fh, 1):
                if i == line:
                    return ln.rstrip("\n")
    except Exception:
        pass
    return ""


def _classify(file_path: str, line_text: str, snippet: str) -> Tuple[str, str, str, str]:
    """-> (kind, secret_key, secret_value, how_to_inject) from the real source line."""
    base = os.path.basename(file_path)
    low = base.lower()
    if low.endswith(_KEYSTORE_EXT):
        return "keystore", _slug(base).replace("-", "_"), "", f"binary file - store base64 and materialise at startup (or move to Vault PKI)"
    text = line_text or snippet or ""
    if low.endswith((".properties", ".yml", ".yaml", ".env")):
        m = _PROP_RE.match(text)
        if m:
            return "config-property", m.group(1), m.group(2).strip().strip('"\''), f"delete `{m.group(1)}` from {base}; Spring Cloud Vault injects the same property name"
    if low.endswith(".java"):
        m = _JAVA_CONST_RE.search(text)
        if m:
            prop = re.sub(r"_+", ".", m.group(1).lower())
            return "java-constant", prop, m.group(2), f"replace constant {m.group(1)} with @Value(\"${{{prop}}}\")"
    if low.endswith(".json"):
        m = _JSON_KV_RE.search(text)
        if m:
            return "json-key", m.group(1), m.group(2), f"load `{m.group(1)}` from Vault instead of {base}"
    return "other", _slug(base).replace("-", "_") + "_secret", "", "review manually - secret value not parseable from the flagged line"


def _triage(kind: str, key: str, value: str, file_path: str) -> Tuple[str, str]:
    """-> (verdict, reason). Only 'migrate' entries go to Vault; the rest are shown with the reason they were held back."""
    base = os.path.basename(file_path).lower()
    if kind == "keystore":
        return "migrate", "private key / keystore material committed to git"
    if kind == "other":
        return "review", "flagged line could not be parsed into a key/value - check manually"
    v = value.strip()
    if re.fullmatch(r"\$\{[^}]+\}", v):
        return "already-externalized", f"value is the placeholder {v} - already injected from the environment"
    if base.startswith("messages") and base.endswith(".properties"):
        return "not-a-secret", "i18n UI text bundle (messages*.properties), not credentials"
    if not v:
        return "not-a-secret", "empty value"
    if re.match(r"^-{3,}(BEGIN|END) ", v):
        return "not-a-secret", "PEM header/footer delimiter string, not key material"
    if v.startswith(("/", "?", "http://", "https://")):
        return "not-a-secret", "URL / path literal"
    if len(v.split()) >= 2:
        return "not-a-secret", "human-readable message text"
    flat_v, flat_k = re.sub(r"[^a-z0-9]", "", v.lower()), re.sub(r"[^a-z0-9]", "", key.lower())
    if flat_v and flat_v in flat_k:
        return "not-a-secret", f"value '{v}' is just an identifier/name mirrored by the constant name"
    return "migrate", "literal credential value in source"


def secret_verdict(file_path: Optional[str], line: Optional[int], snippet: Optional[str], source_root: Optional[str]) -> Tuple[str, str]:
    """Triage one hard-coded-secret finding from its real source line -> (verdict, reason).
    Same rules the Vault plan uses: migrate / review / already-externalized / not-a-secret."""
    if not file_path:
        return "review", "no file"
    line_text = _read_line(source_root, file_path, line or 0)
    kind, key, value, _ = _classify(file_path, line_text, snippet or "")
    return _triage(kind, key, value, file_path)


def generate_vault_migration_plan(
    candidates: List[Any],
    source_root: Optional[str] = None,
    vault_addr: Optional[str] = None,
    app_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a KV v2 migration plan from real SAST secret findings (objects or dicts)."""
    def g(c: Any, k: str, d: Any = None) -> Any:
        return c.get(k, d) if isinstance(c, dict) else getattr(c, k, d)

    app = _slug(app_name or (os.path.basename(os.path.normpath(source_root)) if source_root else "app"))
    addr = vault_addr or os.getenv("VAULT_ADDR") or "http://127.0.0.1:8200"
    seen = set()
    flagged: List[Dict[str, Any]] = []
    for c in candidates:
        if g(c, "is_safe_decoy", False):
            continue
        # Only findings a secret scanner actually raised. NOT the normalised cwe == CWE-798 bucket: that also holds
        # JWT logic flaws (CWE-347/522/1188) which are not stored secrets and have nothing to move into Vault.
        if not (g(c, "vault_candidate", False) or g(c, "raw_cwe") in ("CWE-798", "CWE-259")):
            continue
        fp = (g(c, "file_path") or "").replace("\\", "/")
        ln = int(g(c, "line") or 1)
        if not fp or (fp, ln) in seen:
            continue
        seen.add((fp, ln))
        line_text = _read_line(source_root, fp, ln)
        kind, key, value, inject = _classify(fp, line_text, g(c, "code_snippet") or "")
        group = "certificates" if kind == "keystore" else _slug(os.path.splitext(os.path.basename(fp))[0])
        verdict, why = _triage(kind, key, value, fp)
        flagged.append({
            "source_file": fp, "source_line": ln, "vuln_type": g(c, "vuln_type") or "Hard-coded secret",
            "scanner": g(c, "scanner"), "kind": kind, "secret_key": key, "masked_value": _mask(value),
            "has_value": bool(value), "vault_path": f"secret/{app}/{group}", "group": group, "inject": inject,
            "verdict": verdict, "verdict_reason": why,
            "code_snippet": (line_text or g(c, "code_snippet") or "").strip()[:160],
        })
    secrets = [s for s in flagged if s["verdict"] == "migrate"]

    groups: Dict[str, List[Dict[str, Any]]] = {}
    for s in secrets:
        groups.setdefault(s["group"], []).append(s)

    cli: List[str] = []
    for grp, items in groups.items():
        parts = []
        for s in items:
            if s["kind"] == "keystore":
                parts.append(f"{s['secret_key']}=@<(base64 -w0 {s['source_file']})")
            else:
                parts.append(f"{s['secret_key']}=\"$NEW_{_slug(s['secret_key']).replace('-', '_').upper()}\"")
        cli.append(f"vault kv put secret/{app}/{grp} " + " ".join(dict.fromkeys(parts)))

    yaml = ""
    if groups:
        profiles = "\n".join(f"          - {grp}" for grp in groups)
        yaml = (
            f"# Generated by Vajra-Link from {len(secrets)} real secret finding(s)\n"
            f"spring:\n  application:\n    name: {app}\n  config:\n    import: vault://\n  cloud:\n    vault:\n"
            f"      uri: {addr}\n      authentication: TOKEN\n      token: ${{VAULT_TOKEN}}\n      kv:\n        enabled: true\n"
            f"        backend: secret\n        default-context: {app}\n        profiles:\n{profiles}\n"
        )

    by_kind: Dict[str, int] = {}
    for s in secrets:
        by_kind[s["kind"]] = by_kind.get(s["kind"], 0) + 1
    by_verdict: Dict[str, int] = {}
    for s in flagged:
        by_verdict[s["verdict"]] = by_verdict.get(s["verdict"], 0) + 1
    files = sorted({s["source_file"] for s in secrets})
    return {
        "app_name": app, "vault_address": addr, "mount_path": f"secret/data/{app}",
        "total_flagged": len(flagged), "by_verdict": by_verdict,
        "total_secrets": len(secrets), "files_affected": len(files), "files": files, "by_kind": by_kind,
        "vault_paths": [f"secret/{app}/{grp}" for grp in groups], "secrets": secrets,
        "held_back": [s for s in flagged if s["verdict"] != "migrate"],
        "spring_cloud_vault_config": yaml, "cli_commands": cli,
        "vault_configured": bool(os.getenv("VAULT_ADDR") and os.getenv("VAULT_TOKEN")),
    }


def _real_value(source_root: str, s: Dict[str, Any]) -> Optional[str]:
    if s["kind"] == "keystore":
        try:
            with open(os.path.join(source_root, s["source_file"]), "rb") as fh:
                return base64.b64encode(fh.read()).decode()
        except Exception:
            return None
    line = _read_line(source_root, s["source_file"], s["source_line"])
    _, _, value, _ = _classify(s["source_file"], line, "")
    return value or None


def execute_vault_sync(plan: Dict[str, Any], source_root: str,
                       vault_addr: Optional[str] = None, vault_token: Optional[str] = None) -> Dict[str, Any]:
    """Write the plan's secrets (their current real values, so the app keeps working until rotation) into a real
    Vault KV v2 mount via HTTP. Never pretends: reports NOT_CONFIGURED / OFFLINE / AUTH_FAILED as they are."""
    addr = (vault_addr or os.getenv("VAULT_ADDR") or "").rstrip("/")
    token = vault_token or os.getenv("VAULT_TOKEN")
    if not addr or not token:
        return {"status": "NOT_CONFIGURED", "migrated_count": 0,
                "reason": "Set VAULT_ADDR and VAULT_TOKEN in the server's environment to push to a real Vault. "
                          "Nothing was written; use the generated CLI commands instead."}
    if not plan["secrets"]:
        return {"status": "NOTHING_TO_DO", "migrated_count": 0, "reason": "No secret findings in the current SAST run."}
    hdr = {"X-Vault-Token": token}
    try:
        with httpx.Client(timeout=8.0) as cl:
            health = cl.get(f"{addr}/v1/sys/health")
            if health.status_code not in (200, 429, 472, 473):
                return {"status": "OFFLINE", "migrated_count": 0, "reason": f"Vault health check returned HTTP {health.status_code}"}
            if cl.get(f"{addr}/v1/auth/token/lookup-self", headers=hdr).status_code != 200:
                return {"status": "AUTH_FAILED", "migrated_count": 0, "reason": "VAULT_TOKEN was rejected by the server."}
            data_by_group: Dict[str, Dict[str, str]] = {}
            skipped: List[str] = []
            for s in plan["secrets"]:
                v = _real_value(source_root, s)
                if v is None:
                    skipped.append(f"{s['source_file']}:{s['source_line']}")
                    continue
                data_by_group.setdefault(s["group"], {})[s["secret_key"]] = v
            written: List[Dict[str, Any]] = []
            for grp, data in data_by_group.items():
                r = cl.post(f"{addr}/v1/secret/data/{plan['app_name']}/{grp}", headers=hdr, json={"data": data})
                if r.status_code not in (200, 204):
                    return {"status": "WRITE_FAILED", "migrated_count": sum(len(w["keys"]) for w in written), "written": written,
                            "reason": f"POST secret/data/{plan['app_name']}/{grp} -> HTTP {r.status_code}: {r.text[:200]}"}
                version = (r.json().get("data") or {}).get("version") if r.content else None
                written.append({"path": f"secret/{plan['app_name']}/{grp}", "keys": sorted(data), "version": version})
    except httpx.HTTPError as exc:
        return {"status": "OFFLINE", "migrated_count": 0, "reason": f"Cannot reach Vault at {addr}: {type(exc).__name__}"}
    return {"status": "SUCCESS", "vault_address": addr, "migrated_count": sum(len(w["keys"]) for w in written),
            "written": written, "skipped_unparseable": skipped,
            "next_step": "Rotate every migrated secret (it was in git history), then remove it from the source files."}
