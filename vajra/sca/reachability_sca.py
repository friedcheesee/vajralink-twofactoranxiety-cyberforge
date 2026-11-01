"""
Reachability-Aware SCA + Container / K8s SBOM.

Five steps (per the bonus-feature handout):
  1. Inventory   - build.gradle (+ Spring Boot BOM transitives), Dockerfile(s), docker-compose*.yml, K8s manifests
                   -> CycloneDX 1.5 SBOM that keeps the transitive path (`via`)
  2. Advisories  - OSV (GHSA/CVE) per Maven coordinate; CVSS from the vector, EPSS (FIRST.org), CISA KEV
                   Live when the network is reachable, otherwise the bundled snapshot (clearly labelled)
  3. Function map- vulnerable symbols per advisory: curated map (from advisory text / fix commits) with a fallback that
                   extracts class names from the advisory text
  4. Call graph  - HTTP entrypoint -> app method -> library symbol, using the SAST function graph.
                   Status: Reachable | Imported-only | Present-only | Unknown   (Unknown is never downgraded)
  5. Supply chain- unpinned/unlocked deps, floating :latest tags, unpinned base images, root containers,
                   repository order / dependency-confusion exposure, typosquat distance, apt pins
"""
from __future__ import annotations

import json
import math
import os
import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

try:  # PyYAML ships with semgrep / is a transitive dep; degrade gracefully if absent
    import yaml
except Exception:  # pragma: no cover
    yaml = None

CACHE_PATH = os.path.join(os.path.dirname(__file__), "advisory_snapshot.json")

STATUS_REACHABLE = "Reachable"
STATUS_IMPORTED = "Imported-only"
STATUS_PRESENT = "Present-only"
STATUS_UNKNOWN = "Unknown"

# ----------------------------------------------------------------------------------------------
# Curated data
# ----------------------------------------------------------------------------------------------
SPRING_BOOT_BOM_VERSION = "2.7.18"
# Managed versions for Spring Boot 2.7.18 (spring-boot-dependencies). Marked "curated" in the SBOM.
BOOT_BOM: Dict[str, str] = {
    "org.springframework:spring-webmvc": "5.3.31", "org.springframework:spring-web": "5.3.31",
    "org.springframework:spring-core": "5.3.31", "org.springframework:spring-context": "5.3.31",
    "org.springframework:spring-beans": "5.3.31", "org.springframework:spring-aop": "5.3.31",
    "org.springframework:spring-expression": "5.3.31", "org.springframework:spring-jdbc": "5.3.31",
    "org.springframework:spring-orm": "5.3.31", "org.springframework:spring-tx": "5.3.31",
    "org.springframework:spring-context-support": "5.3.31",
    "org.apache.tomcat.embed:tomcat-embed-core": "9.0.83", "org.apache.tomcat.embed:tomcat-embed-websocket": "9.0.83",
    "com.fasterxml.jackson.core:jackson-databind": "2.13.5", "com.fasterxml.jackson.core:jackson-core": "2.13.5",
    "org.yaml:snakeyaml": "1.30", "com.h2database:h2": "2.1.214",
    "org.apache.logging.log4j:log4j-core": "2.17.2", "org.apache.logging.log4j:log4j-api": "2.17.2",
    "org.hibernate:hibernate-core": "5.6.15.Final", "org.springframework.data:spring-data-jpa": "2.7.18",
    "org.springframework.security:spring-security-crypto": "5.7.11",
    "org.springframework.boot:spring-boot": "2.7.18", "org.springframework.boot:spring-boot-autoconfigure": "2.7.18",
}
STARTER_TRANSITIVES: Dict[str, List[str]] = {
    "org.springframework.boot:spring-boot-starter-web": [
        "org.springframework:spring-webmvc", "org.springframework:spring-web", "org.springframework:spring-core",
        "org.springframework:spring-context", "org.apache.tomcat.embed:tomcat-embed-core",
        "org.apache.tomcat.embed:tomcat-embed-websocket", "com.fasterxml.jackson.core:jackson-databind",
        "com.fasterxml.jackson.core:jackson-core", "org.yaml:snakeyaml", "org.springframework.boot:spring-boot",
        "org.springframework.boot:spring-boot-autoconfigure",
    ],
    "org.springframework.boot:spring-boot-starter-data-jpa": [
        "org.hibernate:hibernate-core", "org.springframework.data:spring-data-jpa", "org.springframework:spring-orm",
        "org.springframework:spring-jdbc", "org.springframework:spring-tx",
    ],
    "org.springframework.boot:spring-boot-starter-log4j2": [
        "org.apache.logging.log4j:log4j-core", "org.apache.logging.log4j:log4j-api",
    ],
    "org.springframework.boot:spring-boot-starter-mail": ["org.springframework:spring-context-support"],
}

# Java package roots per artifact (for import detection); default = group id
PACKAGE_ROOTS: Dict[str, List[str]] = {
    "org.apache.commons:commons-text": ["org.apache.commons.text"],
    "org.apache.commons:commons-lang3": ["org.apache.commons.lang3"],
    "org.json:json": ["org.json"],
    "commons-io:commons-io": ["org.apache.commons.io"],
    "commons-fileupload:commons-fileupload": ["org.apache.commons.fileupload"],
    "commons-codec:commons-codec": ["org.apache.commons.codec"],
    "org.apache.commons:commons-csv": ["org.apache.commons.csv"],
    "com.nimbusds:nimbus-jose-jwt": ["com.nimbusds"],
    "org.bouncycastle:bcprov-jdk18on": ["org.bouncycastle"],
    "javax.xml.bind:jaxb-api": ["javax.xml.bind"],
    "org.glassfish.jaxb:jaxb-runtime": ["org.glassfish.jaxb", "com.sun.xml.bind"],
    "com.unboundid:unboundid-ldapsdk": ["com.unboundid"],
    "org.springframework.security:spring-security-crypto": ["org.springframework.security.crypto"],
    "org.springframework:spring-web": ["org.springframework.web", "org.springframework.http"],
    "org.springframework:spring-webmvc": ["org.springframework.web.servlet"],
    "org.yaml:snakeyaml": ["org.yaml.snakeyaml"],
    "com.h2database:h2": ["org.h2"],
    "org.hibernate:hibernate-core": ["org.hibernate"],
    "io.github.sasanlabs:facade-schema": ["org.sasanlabs.vulnerability"],
}
# Loaded/dispatched by the framework (no direct call sites in app code) -> reachability depends on runtime wiring
RUNTIME_MANAGED_PREFIXES = (
    "org.apache.tomcat.embed:", "com.h2database:h2", "org.hibernate:", "org.apache.logging.log4j:",
    "com.fasterxml.jackson.", "org.springframework.boot:", "org.yaml:snakeyaml", "org.springframework.data:",
    "org.springframework:spring-core", "org.springframework:spring-beans", "org.springframework:spring-context",
    "org.springframework:spring-aop", "org.springframework:spring-expression", "org.springframework:spring-jdbc",
    "org.springframework:spring-orm", "org.springframework:spring-tx", "org.springframework:spring-webmvc",
    "javax.xml.bind:jaxb-api", "org.glassfish.jaxb:",
)

# Vulnerable-function map. Key = any advisory alias (CVE/GHSA). Source: advisory text and fix-commit diffs.
VULN_SYMBOL_MAP: Dict[str, Dict[str, Any]] = {
    "CVE-2022-42889": {"symbols": ["org.apache.commons.text.StringSubstitutor#createInterpolator", "org.apache.commons.text.StringSubstitutor#replace",
                                     "org.apache.commons.text.lookup.StringLookupFactory#interpolatorStringLookup"],
                       "note": "Text4Shell: interpolation lookups (script/dns/url) reachable via StringSubstitutor.createInterpolator()"},
    "CVE-2022-45688": {"symbols": ["org.json.XML#toJSONObject"], "note": "Stack overflow in XML.toJSONObject on deeply nested input"},
    "CVE-2023-5072": {"symbols": ["org.json.JSONObject#<init>"], "note": "DoS while parsing attacker-controlled JSON text in JSONObject"},
    "CVE-2024-47554": {"symbols": ["org.apache.commons.io.input.XmlStreamReader#<init>"], "note": "Uncontrolled resource consumption in XmlStreamReader"},
    "CVE-2024-22243": {"symbols": ["org.springframework.web.util.UriComponentsBuilder#fromUriString", "org.springframework.web.util.UriComponentsBuilder#fromHttpUrl"],
                       "note": "Open redirect / SSRF via UriComponentsBuilder host parsing"},
    "CVE-2024-22259": {"symbols": ["org.springframework.web.util.UriComponentsBuilder#fromUriString", "org.springframework.web.util.UriComponentsBuilder#fromHttpUrl"],
                       "note": "Open redirect / SSRF via UriComponentsBuilder host validation"},
    "CVE-2024-22262": {"symbols": ["org.springframework.web.util.UriComponentsBuilder#fromUriString", "org.springframework.web.util.UriComponentsBuilder#fromHttpUrl"],
                       "note": "Open redirect / SSRF via UriComponentsBuilder host validation"},
    "CVE-2022-1471": {"symbols": ["org.yaml.snakeyaml.Yaml#load", "org.yaml.snakeyaml.Yaml#loadAll", "org.yaml.snakeyaml.Yaml#loadAs"],
                      "note": "Unsafe deserialisation when the default Constructor is used"},
    "CVE-2023-52428": {"symbols": ["com.nimbusds.jose.crypto.PasswordBasedDecrypter#decrypt"], "note": "PBES2 p2c DoS in PasswordBasedDecrypter"},
}

POPULAR_ARTIFACTS = [
    "commons-io", "commons-lang3", "commons-text", "commons-codec", "commons-csv", "commons-fileupload", "jackson-databind",
    "spring-core", "spring-web", "spring-webmvc", "snakeyaml", "log4j-core", "log4j-api", "gson", "guava", "slf4j-api", "h2",
    "nimbus-jose-jwt", "bcprov-jdk18on", "json", "jaxb-api", "hibernate-core", "junit-jupiter", "mockito-core",
]

WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Pod", "Job", "CronJob", "ReplicaSet"}


# ----------------------------------------------------------------------------------------------
# Small utilities
# ----------------------------------------------------------------------------------------------
def _levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> Optional[float]:
    """CVSS v3.x base score from a vector string, None if unparsable."""
    try:
        parts = dict(p.split(":") for p in vector.split("/")[1:])
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[parts["AV"]]
        ac = {"L": 0.77, "H": 0.44}[parts["AC"]]
        scope_changed = parts["S"] == "C"
        pr = ({"N": 0.85, "L": 0.68, "H": 0.5} if scope_changed else {"N": 0.85, "L": 0.62, "H": 0.27})[parts["PR"]]
        ui = {"N": 0.85, "R": 0.62}[parts["UI"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        iss = 1 - (1 - cia[parts["C"]]) * (1 - cia[parts["I"]]) * (1 - cia[parts["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        expl = 8.22 * av * ac * pr * ui
        if impact <= 0:
            return 0.0
        raw = min(1.08 * (impact + expl), 10) if scope_changed else min(impact + expl, 10)
        return _roundup(raw)
    except Exception:
        return None


LABEL_SCORE = {"LOW": 3.0, "MODERATE": 5.5, "MEDIUM": 5.5, "HIGH": 7.5, "CRITICAL": 9.5}


def _version_tuple(v: str) -> Tuple:
    out: List[Any] = []
    for tok in re.split(r"[.\-_]", v or ""):
        out.append((0, int(tok)) if tok.isdigit() else (1, tok))
    return tuple(out)


# ----------------------------------------------------------------------------------------------
# Step 1 - inventory
# ----------------------------------------------------------------------------------------------
def parse_gradle(path: str) -> Dict[str, Any]:
    text = open(path, encoding="utf-8", errors="ignore").read()
    code = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    lines_clean = [re.sub(r"//.*$", "", ln) for ln in code.splitlines()]
    deps: List[Dict[str, Any]] = []
    cfg_re = r"(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|annotationProcessor)"
    for idx, ln in enumerate(lines_clean, 1):
        m = re.search(cfg_re + r"\s*\(?\s*group\s*:\s*['\"]([^'\"]+)['\"]\s*,\s*name\s*:\s*['\"]([^'\"]+)['\"](?:\s*,\s*version\s*:\s*['\"]([^'\"]+)['\"])?", ln)
        if m:
            deps.append({"scope": m.group(1), "group": m.group(2), "artifact": m.group(3), "version": m.group(4), "line": idx})
            continue
        m = re.search(cfg_re + r"\s*\(?\s*['\"]([^:'\"]+):([^:'\"]+)(?::([^'\"]+))?['\"]", ln)
        if m:
            deps.append({"scope": m.group(1), "group": m.group(2), "artifact": m.group(3), "version": m.group(4), "line": idx})
    plugins = [
        {"id": m.group(1), "version": m.group(2), "line": text[: m.start()].count("\n") + 1}
        for m in re.finditer(r"id\s*\(?\s*['\"]([^'\"]+)['\"]\s*\)?(?:\s*version\s+['\"]([^'\"]+)['\"])?", text.split("dependencies", 1)[0])
        if m.group(2)
    ]
    repos: List[Dict[str, Any]] = []
    rm = re.search(r"repositories\s*\{(.*?)\n\}", text, flags=re.DOTALL)
    if rm:
        base_line = text[: rm.start()].count("\n") + 1
        for off, ln in enumerate(rm.group(1).splitlines()):
            t = ln.strip()
            if t and not t.startswith("//"):
                repos.append({"name": t, "line": base_line + off})
    jib_images = [
        {"image": m.group(1), "line": text[: m.start()].count("\n") + 1}
        for m in re.finditer(r"image\s*=\s*['\"]([^'\"]+)['\"]", text)
    ]
    boot_ver = next((p["version"] for p in plugins if p["id"] == "org.springframework.boot"), None)
    return {"dependencies": deps, "plugins": plugins, "repositories": repos, "jib_images": jib_images, "boot_version": boot_ver}


def parse_dockerfile(path: str) -> Dict[str, Any]:
    lines = open(path, encoding="utf-8", errors="ignore").read().splitlines()
    froms, apt_pkgs, users, exposes = [], [], [], []
    for i, ln in enumerate(lines, 1):
        t = ln.strip()
        m = re.match(r"FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+\S+)?", t, re.IGNORECASE)
        if m:
            froms.append({"image": m.group(1), "line": i})
        if re.match(r"USER\s+", t, re.IGNORECASE):
            users.append(t.split(None, 1)[1])
        if re.match(r"EXPOSE\s+", t, re.IGNORECASE):
            exposes.extend(t.split()[1:])
    joined = " ".join(l.strip().rstrip("\\") for l in lines)
    for m in re.finditer(r"apt-get\s+install\s+(?:-[a-z]+\s+)*([^&;]+)", joined):
        for pkg in m.group(1).split():
            if not pkg.startswith("-"):
                apt_pkgs.append(pkg)
    return {"froms": froms, "apt_packages": apt_pkgs, "users": users, "exposes": exposes}


def parse_compose(path: str) -> List[Dict[str, Any]]:
    if yaml is None:
        return []
    try:
        data = yaml.safe_load(open(path, encoding="utf-8", errors="ignore")) or {}
    except Exception:
        return []
    out: List[Dict[str, Any]] = []
    for name, svc in (data.get("services") or {}).items():
        if not isinstance(svc, dict):
            continue
        out.append({
            "service": name, "image": svc.get("image"), "ports": svc.get("ports") or [],
            "privileged": bool(svc.get("privileged")), "user": svc.get("user"), "file": os.path.basename(path),
            "build": bool(svc.get("build")),
        })
    return out


def parse_k8s(path: str) -> List[Dict[str, Any]]:
    if yaml is None:
        return []
    out: List[Dict[str, Any]] = []
    try:
        docs = list(yaml.safe_load_all(open(path, encoding="utf-8", errors="ignore")))
    except Exception:
        return []
    for d in docs:
        if not isinstance(d, dict) or d.get("kind") not in WORKLOAD_KINDS:
            continue
        spec = d.get("spec") or {}
        pod = (spec.get("template") or {}).get("spec") or spec.get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec") or spec
        for c in (pod.get("containers") or []) + (pod.get("initContainers") or []):
            sc = c.get("securityContext") or {}
            out.append({
                "kind": d.get("kind"), "name": (d.get("metadata") or {}).get("name"), "container": c.get("name"),
                "image": c.get("image"), "privileged": bool(sc.get("privileged")),
                "run_as_non_root": sc.get("runAsNonRoot"), "has_limits": bool((c.get("resources") or {}).get("limits")),
                "file": os.path.basename(path),
            })
    return out


def build_inventory(source_root: str) -> Dict[str, Any]:
    gradle_path = os.path.join(source_root, "build.gradle")
    gradle = parse_gradle(gradle_path) if os.path.exists(gradle_path) else {
        "dependencies": [], "plugins": [], "repositories": [], "jib_images": [], "boot_version": None}
    components: Dict[str, Dict[str, Any]] = {}

    def add(g: str, a: str, v: Optional[str], scope: str, direct: bool, via: Optional[str], vsrc: str, line: Optional[int]) -> None:
        key = f"{g}:{a}"
        if key in components:
            if direct and not components[key]["direct"]:
                components[key].update({"direct": True, "via": None, "scope": scope, "line": line})
            return
        components[key] = {
            "type": "library", "group": g, "name": a, "version": v, "scope": scope, "direct": direct, "via": via,
            "version_source": vsrc, "line": line, "purl": f"pkg:maven/{g}/{a}@{v}" if v else f"pkg:maven/{g}/{a}",
            "ecosystem": "Maven",
        }

    boot = gradle.get("boot_version")
    for d in gradle["dependencies"]:
        key = f"{d['group']}:{d['artifact']}"
        ver = d["version"]
        vsrc = "build.gradle"
        if not ver and boot and key in BOOT_BOM:
            ver, vsrc = BOOT_BOM[key], f"spring-boot-{boot}-bom (curated)"
        scope = "test" if d["scope"].startswith("test") else ("runtime" if d["scope"] == "runtimeOnly" else "compile")
        add(d["group"], d["artifact"], ver, scope, True, None, vsrc if ver else "unresolved", d["line"])
        for t in STARTER_TRANSITIVES.get(key, []):
            tg, ta = t.split(":")
            add(tg, ta, BOOT_BOM.get(t), scope, False, key, f"spring-boot-{boot}-bom (curated)", None)

    containers: List[Dict[str, Any]] = []
    os_packages: List[Dict[str, Any]] = []
    dockerfiles: List[Dict[str, Any]] = []
    compose: List[Dict[str, Any]] = []
    k8s: List[Dict[str, Any]] = []
    gradle_lock = False
    verification = False
    for root, dirs, files in os.walk(source_root):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "build", ".gradle"}]
        rel_root = os.path.relpath(root, source_root).replace("\\", "/")
        if rel_root.startswith("src/test") or rel_root.startswith(".github"):
            continue
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, source_root).replace("\\", "/")
            if f == "gradle.lockfile":
                gradle_lock = True
            if f == "verification-metadata.xml":
                verification = True
            if f.startswith("Dockerfile"):
                df = parse_dockerfile(full)
                df["file"] = rel
                dockerfiles.append(df)
                for fr in df["froms"]:
                    containers.append({"image": fr["image"], "source": rel, "role": "base-image", "line": fr["line"]})
                for pkg in df["apt_packages"]:
                    os_packages.append({"name": pkg, "source": rel, "pinned": "=" in pkg})
            elif re.match(r"docker-compose.*\.ya?ml$", f):
                for svc in parse_compose(full):
                    compose.append({**svc, "file": rel})
                    if svc.get("image"):
                        containers.append({"image": svc["image"], "source": rel, "role": f"compose:{svc['service']}", "line": None})
            elif f.endswith((".yaml", ".yml")) and "src/main/resources" not in rel:
                for c in parse_k8s(full):
                    k8s.append({**c, "file": rel})
                    if c.get("image"):
                        containers.append({"image": c["image"], "source": rel, "role": f"k8s:{c['kind']}/{c['name']}", "line": None})
    # jib base/target images
    for j in gradle["jib_images"]:
        containers.append({"image": j["image"], "source": "build.gradle", "role": "jib", "line": j["line"]})

    return {
        "gradle": gradle, "components": list(components.values()), "containers": containers, "os_packages": os_packages,
        "dockerfiles": dockerfiles, "compose": compose, "k8s": k8s, "gradle_lockfile": gradle_lock,
        "dependency_verification": verification,
    }


def merge_image_scan(inv: Dict[str, Any], info: Dict[str, Any]) -> Dict[str, Any]:
    """Replace curated/declared versions with the versions actually shipped in the container image."""
    summary = {"jars": len(info.get("jars", [])), "replaced_versions": 0, "added_components": 0, "unresolved_jars": 0}
    by_key = {f"{c['group']}:{c['name']}": c for c in inv["components"]}
    by_artifact: Dict[str, List[Dict[str, Any]]] = {}
    for c in inv["components"]:
        by_artifact.setdefault(c["name"], []).append(c)
    for j in info.get("jars", []):
        group = j["group"]
        if not group:
            cands = by_artifact.get(j["artifact"], [])
            if len(cands) == 1:
                group = cands[0]["group"]
            else:
                summary["unresolved_jars"] += 1
                continue
        key = f"{group}:{j['artifact']}"
        comp = by_key.get(key)
        if comp:
            if comp.get("version") != j["version"]:
                comp["declared_version"] = comp.get("version")
                comp["version"] = j["version"]
                comp["purl"] = f"pkg:maven/{group}/{j['artifact']}@{j['version']}"
                summary["replaced_versions"] += 1
            comp["version_source"] = f"container image {info['image']} (resolved jar)"
        else:
            comp = {
                "type": "library", "group": group, "name": j["artifact"], "version": j["version"], "scope": "compile",
                "direct": False, "via": None, "version_source": f"container image {info['image']} (resolved jar)", "line": None,
                "purl": f"pkg:maven/{group}/{j['artifact']}@{j['version']}", "ecosystem": "Maven",
            }
            inv["components"].append(comp)
            by_key[key] = comp
            summary["added_components"] += 1
    distro = (info.get("facts", {}).get("os_id") or "debian").lower()
    inv["os_packages"] = [
        {"name": p["name"], "version": p["version"], "source": info["image"], "pinned": True, "distro": distro}
        for p in info.get("os_packages", [])
    ] + [p for p in inv["os_packages"] if p.get("source") != info["image"]]
    summary["os_packages"] = len(info.get("os_packages", []))
    return summary


# ----------------------------------------------------------------------------------------------
# Step 2 - advisories (OSV + EPSS + KEV) with cache
# ----------------------------------------------------------------------------------------------
def _load_cache(path: str) -> Dict[str, Any]:
    try:
        return json.load(open(path, encoding="utf-8"))
    except Exception:
        return {"osv": {}, "vulns": {}, "epss": {}, "kev": {"cves": [], "version": None}, "central": {}, "fetched_at": None}


def _save_cache(path: str, cache: Dict[str, Any]) -> None:
    try:
        json.dump(cache, open(path, "w", encoding="utf-8"), indent=1, sort_keys=True)
    except Exception:
        pass


def fetch_advisories(components: List[Dict[str, Any]], use_network: bool, cache_path: str) -> Tuple[Dict[str, List[Dict[str, Any]]], Dict[str, Any], Dict[str, Any]]:
    """Returns ({component_key: [vuln records]}, epss_map, meta)."""
    cache = _load_cache(cache_path)
    meta = {"osv": "snapshot", "epss": "snapshot", "kev": "snapshot", "snapshot_fetched_at": cache.get("fetched_at")}
    queries = [(f"{c['group']}:{c['name']}", c["version"]) for c in components if c.get("version") and c["ecosystem"] == "Maven"]
    if use_network:
        try:
            with httpx.Client(timeout=20.0) as client:
                payload = {"queries": [{"package": {"name": n, "ecosystem": "Maven"}, "version": v} for n, v in queries]}
                r = client.post("https://api.osv.dev/v1/querybatch", json=payload)
                r.raise_for_status()
                results = r.json().get("results", [])
                ids_by_key: Dict[str, List[str]] = {}
                for (n, v), res in zip(queries, results):
                    ids_by_key[f"{n}@{v}"] = [x["id"] for x in res.get("vulns", [])]
                all_ids = sorted({i for ids in ids_by_key.values() for i in ids})

                def get_vuln(vid: str) -> Tuple[str, Optional[Dict[str, Any]]]:
                    try:
                        with httpx.Client(timeout=20.0) as c2:
                            rr = c2.get(f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(vid)}")
                            return vid, rr.json() if rr.status_code == 200 else None
                    except Exception:
                        return vid, None

                with ThreadPoolExecutor(max_workers=8) as pool:
                    for vid, rec in pool.map(get_vuln, all_ids):
                        if rec:
                            cache["vulns"][vid] = rec
                cache["osv"].update(ids_by_key)
                meta["osv"] = "live"
                cves = sorted({a for vid in all_ids for a in (cache["vulns"].get(vid, {}).get("aliases") or []) if a.startswith("CVE-")})
                try:
                    for i in range(0, len(cves), 50):
                        er = client.get("https://api.first.org/data/v1/epss", params={"cve": ",".join(cves[i:i + 50])})
                        for row in er.json().get("data", []):
                            cache["epss"][row["cve"]] = {"epss": float(row["epss"]), "percentile": float(row["percentile"]), "date": row.get("date")}
                    meta["epss"] = "live"
                except Exception:
                    pass
                try:
                    kr = client.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=40.0)
                    kj = kr.json()
                    cache["kev"] = {"cves": sorted(v["cveID"] for v in kj.get("vulnerabilities", [])), "version": kj.get("catalogVersion")}
                    meta["kev"] = "live"
                except Exception:
                    pass
                cache["fetched_at"] = datetime.now(timezone.utc).isoformat()
                _save_cache(cache_path, cache)
        except Exception as exc:
            meta["osv_error"] = f"{type(exc).__name__}: {exc}"[:160]
    out: Dict[str, List[Dict[str, Any]]] = {}
    for c in components:
        key = f"{c['group']}:{c['name']}"
        ids = cache["osv"].get(f"{key}@{c.get('version')}", [])
        recs = [cache["vulns"][i] for i in ids if i in cache["vulns"]]
        out[key] = recs
    meta["kev_catalog_version"] = (cache.get("kev") or {}).get("version")
    return out, cache, meta


def _fixed_versions(rec: Dict[str, Any], package: str) -> List[str]:
    fixed: Set[str] = set()
    for aff in rec.get("affected", []):
        if (aff.get("package") or {}).get("name") != package:
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixed.add(ev["fixed"])
    return sorted(fixed, key=_version_tuple)


def _is_applicable(rec: Dict[str, Any], package: str, version: str) -> bool:
    """OSV already filtered by version; keep as sanity (withdrawn advisories removed)."""
    return not rec.get("withdrawn")


def _score(rec: Dict[str, Any]) -> Tuple[Optional[float], str, Optional[str]]:
    for sev in rec.get("severity", []):
        if sev.get("type") == "CVSS_V3":
            sc = cvss3_base_score(sev.get("score", ""))
            if sc is not None:
                label = "CRITICAL" if sc >= 9 else "HIGH" if sc >= 7 else "MEDIUM" if sc >= 4 else "LOW"
                return sc, label, sev.get("score")
    lab = ((rec.get("database_specific") or {}).get("severity") or "").upper()
    if lab in LABEL_SCORE:
        return LABEL_SCORE[lab], "MEDIUM" if lab == "MODERATE" else lab, None
    return None, "UNKNOWN", None


# ----------------------------------------------------------------------------------------------
# Steps 3 & 4 - function map + call graph reachability
# ----------------------------------------------------------------------------------------------
class _SourceIndex:
    """Imports and call sites in app code, mapped to function-graph method nodes."""

    def __init__(self, source_root: str, fgraph: Optional[Any]):
        self.root = source_root
        self.fgraph = fgraph
        self.imports_by_file: Dict[str, Set[str]] = {}
        self.text_by_file: Dict[str, List[str]] = {}
        for r, dirs, files in os.walk(os.path.join(source_root, "src", "main")):
            dirs[:] = [d for d in dirs if d != "resources"]
            for f in files:
                if not f.endswith(".java"):
                    continue
                full = os.path.join(r, f)
                rel = os.path.relpath(full, source_root).replace("\\", "/")
                content = open(full, encoding="utf-8", errors="ignore").read()
                self.imports_by_file[rel] = set(re.findall(r"^\s*import\s+(?:static\s+)?([\w.*]+);", content, flags=re.MULTILINE))
                self.text_by_file[rel] = content.splitlines()

    def files_importing(self, prefixes: List[str]) -> List[str]:
        return [f for f, imps in self.imports_by_file.items() if any(i.startswith(p) for i in imps for p in prefixes)]

    def class_imported_in(self, fqcn: str) -> List[str]:
        pkg = fqcn.rsplit(".", 1)[0]
        return [f for f, imps in self.imports_by_file.items() if fqcn in imps or f"{pkg}.*" in imps]

    def call_sites(self, symbol: str) -> List[Dict[str, Any]]:
        """Method nodes (and lines) where `pkg.Class#method` is invoked."""
        fqcn, _, meth = symbol.partition("#")
        simple = fqcn.rsplit(".", 1)[-1]
        sites: List[Dict[str, Any]] = []
        for rel in self.class_imported_in(fqcn):
            lines = self.text_by_file[rel]
            for i, ln in enumerate(lines, 1):
                if ln.strip().startswith(("import ", "//", "*", "/*")):
                    continue
                hit = False
                if meth == "<init>":
                    hit = bool(re.search(rf"\bnew\s+{simple}\s*\(", ln))
                else:
                    hit = bool(re.search(rf"\b{re.escape(meth)}\s*\(", ln)) and (
                        simple in ln or any(re.search(rf"\b{simple}\b[^;]*\b(\w+)\s*[;=]", l2) for l2 in lines[max(0, i - 60):i])
                    )
                if hit:
                    nid = self.fgraph.innermost_node_at(rel, i) if self.fgraph else None
                    sites.append({"file": rel, "line": i, "node_id": nid, "snippet": ln.strip()[:140]})
        return sites

    def reachable_path(self, node_id: Optional[str]) -> Optional[Dict[str, Any]]:
        if not self.fgraph or not node_id:
            return None
        g = self.fgraph
        entry_ids = {n for n, d in g.nodes.items() if d.get("routes")}
        best: Optional[List[Tuple[str, str]]] = None
        # reverse BFS from the call-site method
        prev: Dict[str, Tuple[str, str]] = {}
        seen = {node_id}
        from collections import deque

        dq: deque = deque([(node_id, 0)])
        found: Optional[str] = node_id if node_id in entry_ids else None
        while dq and not found:
            cur, d = dq.popleft()
            if d >= 8:
                continue
            for caller, kind in g.inc.get(cur, []):
                if caller in seen:
                    continue
                seen.add(caller)
                prev[caller] = (cur, kind)
                if caller in entry_ids:
                    found = caller
                    break
                dq.append((caller, d + 1))
        if not found:
            return None
        chain: List[Tuple[str, str]] = [(found, "entry")]
        cur = found
        while cur != node_id:
            nxt, kind = prev[cur]
            chain.append((nxt, kind))
            cur = nxt
        best = chain
        routes = [r["url"] for r in g.nodes[found].get("routes", []) if not r.get("secure")][:4]
        return {"entry": g.nodes[found]["label"], "routes": routes, "hops": len(best) - 1,
                "path": g.describe_path(best), "path_nodes": [n for n, _ in best]}


def _symbols_for(rec: Dict[str, Any], comp: Dict[str, Any]) -> Tuple[List[str], str, Optional[str]]:
    """Function map: curated per-alias symbols, else class names mentioned in the advisory text."""
    ids = [rec.get("id", "")] + list(rec.get("aliases") or [])
    for i in ids:
        if i in VULN_SYMBOL_MAP:
            return VULN_SYMBOL_MAP[i]["symbols"], "curated (advisory text / fix commit)", VULN_SYMBOL_MAP[i].get("note")
    roots = PACKAGE_ROOTS.get(f"{comp['group']}:{comp['name']}", [comp["group"]])
    text = f"{rec.get('summary', '')}\n{rec.get('details', '')}"
    found: List[str] = []
    for root in roots:
        for m in re.finditer(rf"\b({re.escape(root)}(?:\.[a-z0-9_]+)*\.[A-Z]\w+)\b", text):
            if m.group(1) not in found:
                found.append(m.group(1))
    if found:
        return [f"{c}#*" for c in found[:6]], "derived from advisory text (class-level)", None
    return [], "none", None


def _is_runtime_managed(key: str) -> bool:
    return key.startswith(RUNTIME_MANAGED_PREFIXES)


def analyze_reachability(comp: Dict[str, Any], rec: Dict[str, Any], idx: _SourceIndex) -> Dict[str, Any]:
    key = f"{comp['group']}:{comp['name']}"
    roots = PACKAGE_ROOTS.get(key, [comp["group"]])
    symbols, sym_source, note = _symbols_for(rec, comp)
    importing = idx.files_importing(roots)
    res: Dict[str, Any] = {
        "symbols": symbols, "symbol_source": sym_source, "symbol_note": note, "importing_files": importing[:8],
        "call_sites": [], "path": None, "status": STATUS_UNKNOWN, "reason": "",
    }
    if comp.get("scope") == "test":
        res["status"], res["reason"] = STATUS_PRESENT, "Declared with test scope only - not on the production classpath."
        return res
    managed = _is_runtime_managed(key)
    if symbols:
        concrete = [s for s in symbols if not s.endswith("#*")]
        class_level = [s for s in symbols if s.endswith("#*")]
        sites: List[Dict[str, Any]] = []
        for s in concrete:
            sites.extend(idx.call_sites(s))
        for s in class_level:
            cls = s[:-2]
            simple = cls.rsplit(".", 1)[-1]
            for rel in idx.class_imported_in(cls):
                for i, ln in enumerate(idx.text_by_file[rel], 1):
                    if not ln.strip().startswith(("import ", "//", "*")) and re.search(rf"\b{simple}\b", ln):
                        nid = idx.fgraph.innermost_node_at(rel, i) if idx.fgraph else None
                        sites.append({"file": rel, "line": i, "node_id": nid, "snippet": ln.strip()[:140]})
        res["call_sites"] = sites[:12]
        for site in sites:
            path = idx.reachable_path(site["node_id"])
            if path:
                res["status"] = STATUS_REACHABLE
                res["path"] = path
                res["reason"] = f"{path['entry']} reaches the vulnerable symbol in {os.path.basename(site['file'])}:{site['line']} ({path['hops']} hops)."
                return res
        if sites:
            res["status"] = STATUS_IMPORTED
            res["reason"] = "Vulnerable symbol is referenced, but no HTTP entrypoint reaches that code."
            return res
        if importing:
            res["status"] = STATUS_IMPORTED
            res["reason"] = f"Package imported by {len(importing)} file(s), but the vulnerable symbol is never called."
            return res
        if managed:
            res["status"] = STATUS_UNKNOWN
            res["reason"] = "Framework-managed library: symbols are invoked by the runtime, so app-level call-graph cannot rule them out."
            return res
        res["status"], res["reason"] = STATUS_PRESENT, "Declared in the build manifest but never imported by application code."
        return res
    # no function map available
    if managed or importing:
        res["status"] = STATUS_UNKNOWN
        res["reason"] = ("No vulnerable-function map for this advisory; library is " +
                         ("loaded/dispatched by the framework." if managed else f"imported by {len(importing)} file(s)."))
        return res
    res["status"], res["reason"] = STATUS_PRESENT, "Declared in the build manifest but never imported by application code."
    return res


# ----------------------------------------------------------------------------------------------
# Step 5 - supply chain
# ----------------------------------------------------------------------------------------------
def _check_central(group: str, artifact: str, cache: Dict[str, Any], use_network: bool) -> Optional[bool]:
    key = f"{group}:{artifact}"
    if key in cache.setdefault("central", {}):
        return cache["central"][key]
    if not use_network:
        return None
    try:
        url = f"https://repo1.maven.org/maven2/{group.replace('.', '/')}/{artifact}/maven-metadata.xml"
        ok = httpx.head(url, timeout=10.0, follow_redirects=True).status_code == 200
        cache["central"][key] = ok
        return ok
    except Exception:
        return None


def supply_chain_checks(inv: Dict[str, Any], cache: Dict[str, Any], use_network: bool) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    def add(cid: str, sev: str, cat: str, title: str, detail: str, evidence: str) -> None:
        out.append({"id": cid, "severity": sev, "category": cat, "title": title, "detail": detail, "evidence": evidence})

    gradle = inv["gradle"]
    if not inv["gradle_lockfile"]:
        versionless = [f"{c['group']}:{c['name']}" for c in inv["components"] if c["direct"] and "bom" in (c["version_source"] or "")]
        add("SC-LOCK", "MEDIUM", "unpinned-lockfile", "No Gradle lockfile - resolved dependency versions are not locked",
            f"{len(versionless)} direct dependencies take their version from the Spring Boot BOM and no gradle.lockfile pins the "
            "transitive graph, so a rebuild can silently pull different artifacts.", ", ".join(versionless[:6]) or "build.gradle")
    if not inv["dependency_verification"]:
        add("SC-VERIFY", "LOW", "unverified-artifacts", "No dependency verification metadata",
            "gradle/verification-metadata.xml is absent: downloaded artifacts are not checked against pinned checksums/signatures.",
            "gradle/verification-metadata.xml missing")
    repos = gradle.get("repositories", [])
    names = [r["name"] for r in repos]
    if any("mavenLocal" in n for n in names):
        ml_idx = next(i for i, n in enumerate(names) if "mavenLocal" in n)
        mc_idx = next((i for i, n in enumerate(names) if "mavenCentral" in n), None)
        before = mc_idx is None or ml_idx < mc_idx
        add("SC-MAVENLOCAL", "MEDIUM" if before else "LOW", "dependency-confusion",
            "mavenLocal() repository enabled" + (" BEFORE mavenCentral()" if before else " (after mavenCentral)"),
            "mavenLocal() resolves artifacts from ~/.m2 that were never verified against a registry; "
            + ("because it is listed first it can shadow public artifacts." if before else "it is consulted after Central so public artifacts win, but a missing artifact is still taken from an unverified local cache."),
            f"build.gradle:{repos[ml_idx]['line']} order = {', '.join(names)}")
    for c in inv["components"]:
        if not c["direct"]:
            continue
        g, a = c["group"], c["name"]
        for pop in POPULAR_ARTIFACTS:
            if a != pop and abs(len(a) - len(pop)) <= 2 and _levenshtein(a, pop) <= 2 and len(a) > 5:
                add(f"SC-TYPO-{a}", "MEDIUM", "typosquat", f"Artifact '{g}:{a}' is within edit distance 2 of popular '{pop}'",
                    "Possible typosquat - verify the coordinates are intentional.", f"build.gradle:{c['line']}")
        if g.startswith(("io.github.", "com.github.")):
            present = _check_central(g, a, cache, use_network)
            if present is False:
                add(f"SC-CONFUSION-{a}", "HIGH", "dependency-confusion", f"'{g}:{a}' is not published on Maven Central",
                    "Namespace looks internal; with mavenLocal()/private repos an attacker could publish a same-named public artifact.", f"build.gradle:{c['line']}")
            elif present is True:
                add(f"SC-NS-{a}", "INFO", "dependency-confusion", f"'{g}:{a}' resolves from Maven Central",
                    "Third-party namespace (io.github.*): confirm the owning account is trusted; no confusion risk detected.", f"build.gradle:{c['line']}")
    for ct in inv["containers"]:
        img = ct["image"]
        if "${" in img:
            continue
        name, _, tag = img.partition(":")
        has_digest = "@sha256:" in img
        if has_digest:
            continue
        if not tag or tag == "latest":
            add(f"SC-LATEST-{img}", "MEDIUM", "floating-tag", f"Floating tag: {img}",
                "':latest' / untagged images change without notice (non-reproducible, unreviewed updates).", f"{ct['source']} ({ct['role']})")
        else:
            add(f"SC-NODIGEST-{img}", "LOW", "unpinned-image", f"Image pinned by tag only (no @sha256 digest): {img}",
                "Tags are mutable; pin the digest for reproducible, tamper-evident builds.", f"{ct['source']} ({ct['role']})")
    for df in inv["dockerfiles"]:
        if not df["users"]:
            add(f"SC-ROOT-{df['file']}", "MEDIUM", "container-privilege", f"{df['file']}: no USER instruction - container runs as root",
                "Add a non-root USER to limit blast radius of an RCE.", df["file"])
        for pkg in df["apt_packages"]:
            if "=" not in pkg:
                add(f"SC-APT-{pkg}", "LOW", "unpinned-os-package", f"Unpinned OS package '{pkg}' installed via apt-get",
                    "OS packages float to whatever the mirror serves at build time.", df["file"])
    for svc in inv["compose"]:
        if svc.get("privileged"):
            add(f"SC-PRIV-{svc['service']}", "HIGH", "container-privilege", f"compose service '{svc['service']}' runs privileged", "", svc["file"])
    for k in inv["k8s"]:
        if k.get("privileged"):
            add(f"SC-K8S-PRIV-{k['name']}", "HIGH", "container-privilege", f"K8s {k['kind']}/{k['name']} container privileged", "", k["file"])
        if not k.get("has_limits"):
            add(f"SC-K8S-LIMITS-{k['name']}", "LOW", "resource-limits", f"K8s {k['kind']}/{k['name']} has no resource limits", "", k["file"])
    merged: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for f in out:
        k = (f["category"], f["title"])
        if k in merged:
            if f["evidence"] not in merged[k]["evidence"].split("; "):
                merged[k]["evidence"] += "; " + f["evidence"]
        else:
            merged[k] = dict(f)
    out[:] = list(merged.values())
    if not inv["k8s"]:
        add("SC-K8S-NONE", "INFO", "coverage", "No Kubernetes manifests found in the repository",
            "K8s SBOM/policy checks ran but there is nothing to inspect (docker-compose and Dockerfiles were analysed instead).", "repo scan")
    return out


# ----------------------------------------------------------------------------------------------
# CycloneDX 1.5
# ----------------------------------------------------------------------------------------------
def to_cyclonedx(target: str, inv: Dict[str, Any], vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
    comps: List[Dict[str, Any]] = []
    for c in inv["components"]:
        comps.append({
            "type": "library", "bom-ref": c["purl"], "group": c["group"], "name": c["name"], "version": c.get("version") or "",
            "purl": c["purl"], "scope": "optional" if c["scope"] == "test" else "required",
            "properties": [
                {"name": "vajra:direct", "value": str(c["direct"]).lower()},
                {"name": "vajra:via", "value": c.get("via") or ""},
                {"name": "vajra:version-source", "value": c.get("version_source") or ""},
            ],
        })
    for ct in inv["containers"]:
        name, _, tag = ct["image"].partition(":")
        comps.append({"type": "container", "bom-ref": f"pkg:docker/{name}@{tag or 'latest'}", "name": name, "version": tag or "latest",
                      "purl": f"pkg:docker/{name}@{tag or 'latest'}", "properties": [{"name": "vajra:source", "value": f"{ct['source']} ({ct['role']})"}]})
    for p in inv["os_packages"]:
        dist = p.get("distro", "debian")
        purl = f"pkg:deb/{dist}/{p['name']}" + (f"@{p['version']}" if p.get("version") else "")
        comps.append({"type": "library", "bom-ref": purl, "name": p["name"], "version": p.get("version", ""), "purl": purl,
                      "properties": [{"name": "vajra:source", "value": p["source"]}]})
    state_map = {STATUS_REACHABLE: ("exploitable", None), STATUS_IMPORTED: ("not_affected", "code_not_reachable"),
                 STATUS_PRESENT: ("not_affected", "code_not_present"), STATUS_UNKNOWN: ("in_triage", None)}
    cdx_vulns = []
    for v in vulns:
        state, just = state_map[v["status"]]
        analysis: Dict[str, Any] = {"state": state, "detail": v["status_reason"]}
        if just:
            analysis["justification"] = just
        cdx_vulns.append({
            "id": v["id"], "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{v['id']}"},
            "ratings": [{"method": "CVSSv31", "score": v["cvss"], "severity": (v["severity"] or "unknown").lower(), "vector": v.get("cvss_vector")}] if v.get("cvss") is not None else [],
            "description": v["summary"], "analysis": analysis,
            "affects": [{"ref": f"pkg:maven/{v['package'].replace(':', '/')}@{v['version']}"}],
            "properties": [{"name": "vajra:reachability", "value": v["status"]}, {"name": "epss", "value": str(v.get("epss"))}, {"name": "cisa-kev", "value": str(v.get("kev")).lower()}],
        })
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(), "tools": [{"vendor": "VajraLink", "name": "reachability-sca"}],
                     "component": {"type": "application", "name": os.path.basename(target.rstrip("/\\")) or "target"}},
        "components": comps, "vulnerabilities": cdx_vulns,
    }


# ----------------------------------------------------------------------------------------------
# Orchestration
# ----------------------------------------------------------------------------------------------
def build_sca_report(
    source_root: str,
    fgraph: Optional[Any] = None,
    use_network: bool = True,
    cache_path: str = CACHE_PATH,
    image: Optional[str] = "auto",
) -> Dict[str, Any]:
    t0 = time.time()
    inv = build_inventory(source_root)
    image_info: Dict[str, Any] = {"available": False, "reason": "image scan disabled"}
    image_summary: Dict[str, Any] = {}
    if image:
        from vajra.sca import image_inspector as _ii

        chosen = image
        if image == "auto":
            chosen = next(
                (c["image"] for c in inv["containers"]
                 if (c["role"].startswith("compose:") or c["role"] == "jib") and "${" not in c["image"]
                 and not any(x in c["image"] for x in ("mongo", "ollama", "mailpit", "llmforge", "-jsp", "-php", "-facade", "-base"))
                 and _ii.docker_available() and _ii.image_present(c["image"])),
                None,
            )
        if chosen:
            image_info = _ii.inspect_image(chosen)
            if image_info.get("available"):
                image_summary = merge_image_scan(inv, image_info)
        else:
            image_info = {"available": False, "reason": "no locally available application image found (docker pull it to enable)"}
    adv_by_key, cache, meta = fetch_advisories(inv["components"], use_network, cache_path)
    idx = _SourceIndex(source_root, fgraph)
    epss_map = cache.get("epss", {})
    kev_set = set((cache.get("kev") or {}).get("cves", []))

    vulns: List[Dict[str, Any]] = []
    for comp in inv["components"]:
        key = f"{comp['group']}:{comp['name']}"
        for rec in adv_by_key.get(key, []):
            if not _is_applicable(rec, key, comp.get("version") or ""):
                continue
            cvss, sev, vector = _score(rec)
            cves = [a for a in (rec.get("aliases") or []) if a.startswith("CVE-")]
            epss = max((epss_map.get(c, {}).get("epss", 0.0) for c in cves), default=None) if cves else None
            kev = any(c in kev_set for c in cves)
            reach = analyze_reachability(comp, rec, idx)
            weight = {STATUS_REACHABLE: 1.0, STATUS_UNKNOWN: 0.6, STATUS_IMPORTED: 0.25, STATUS_PRESENT: 0.1}[reach["status"]]
            risk = weight * (0.5 * ((cvss or 5.0) / 10.0) + 0.3 * (epss or 0.0) + 0.2 * (1.0 if kev else 0.0))
            vulns.append({
                "id": rec["id"], "aliases": rec.get("aliases", []), "cves": cves, "package": key, "version": comp.get("version"),
                "via": comp.get("via"), "direct": comp["direct"], "scope": comp["scope"],
                "summary": rec.get("summary", ""), "cvss": cvss, "cvss_vector": vector, "severity": sev,
                "epss": round(epss, 4) if epss is not None else None, "kev": kev,
                "fixed_versions": _fixed_versions(rec, key), "status": reach["status"], "status_reason": reach["reason"],
                "symbols": reach["symbols"], "symbol_source": reach["symbol_source"], "symbol_note": reach["symbol_note"],
                "call_sites": reach["call_sites"], "call_path": reach["path"], "importing_files": reach["importing_files"],
                "priority_score": round(risk * 100, 1),
                "references": [r.get("url") for r in rec.get("references", [])][:3],
            })
    order = {STATUS_REACHABLE: 0, STATUS_UNKNOWN: 1, STATUS_IMPORTED: 2, STATUS_PRESENT: 3}
    vulns.sort(key=lambda v: (order[v["status"]], -v["priority_score"]))

    supply = supply_chain_checks(inv, cache, use_network)
    if image_info.get("available") and image_info["facts"].get("runs_as_uid") == 0:
        supply.append({
            "id": "SC-IMG-ROOT", "severity": "MEDIUM", "category": "container-privilege",
            "title": f"Running image {image_info['image']} executes as root (uid 0)",
            "detail": "Verified by running `id -u` inside the real image: an RCE in the app would run as root.",
            "evidence": f"docker run {image_info['image']} id -u -> 0",
        })
    # Malicious-package check: OSV also serves the OpenSSF malicious-packages feed (advisory ids "MAL-*"), and the
    # same per-package OSV query above already returns those records - so any MAL-* hit is a real known-malicious artifact.
    mal_checked = 0
    for comp in inv["components"]:
        key = f"{comp['group']}:{comp['name']}"
        if f"{key}@{comp.get('version')}" in cache.get("osv", {}):
            mal_checked += 1
        for rec in adv_by_key.get(key, []):
            if str(rec.get("id", "")).startswith("MAL-"):
                supply.append({
                    "id": f"SC-MAL-{comp['name']}", "severity": "HIGH", "category": "malicious-package",
                    "title": f"Known-malicious package: {key}:{comp.get('version') or '?'} ({rec['id']})",
                    "detail": rec.get("summary") or "Listed in the OpenSSF malicious-packages database via OSV.",
                    "evidence": f"OSV {rec['id']}",
                })
    if not any(s["category"] == "malicious-package" for s in supply):
        supply.append({
            "id": "SC-MAL-NONE", "severity": "INFO", "category": "malicious-package",
            "title": f"No known-malicious packages ({mal_checked} components checked against OSV MAL-* feed)",
            "detail": "OSV aggregates the OpenSSF malicious-packages database; none of the inventoried components appear in it."
                      if mal_checked else "No component had an OSV result (OSV unreachable / no cache), so this is NOT a clean result.",
            "evidence": f"OSV source: {meta['osv']} · {mal_checked}/{len(inv['components'])} components have OSV results",
        })
    if use_network:
        _save_cache(cache_path, cache)

    by_status = {s: sum(1 for v in vulns if v["status"] == s) for s in (STATUS_REACHABLE, STATUS_UNKNOWN, STATUS_IMPORTED, STATUS_PRESENT)}
    deprioritised = by_status[STATUS_IMPORTED] + by_status[STATUS_PRESENT]
    components = [dict(c, vulnerabilities=sum(1 for v in vulns if v["package"] == f"{c['group']}:{c['name']}")) for c in inv["components"]]

    # canvas graph: entrypoint -> app method -> library symbol (one chain per reachable vuln + hubs for the others)
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, str]] = []
    for v in vulns:
        if v["status"] == STATUS_UNKNOWN or v["status"] == STATUS_PRESENT:
            continue  # no call-path information to draw; listed in the table instead
        lib_id = f"lib:{v['package']}"
        nodes.setdefault(lib_id, {"id": lib_id, "label": f"{v['package']}:{v['version']}", "kind": "library", "status": v["status"], "layer": 3})
        sym = (v["symbols"][0] if v["symbols"] else None)
        vid = f"vuln:{v['id']}"
        nodes[vid] = {"id": vid, "label": v["cves"][0] if v["cves"] else v["id"], "kind": "advisory", "status": v["status"], "layer": 4,
                      "cvss": v["cvss"], "kev": v["kev"], "epss": v["epss"]}
        edges.append({"src": lib_id, "dst": vid, "kind": "advisory"})
        if v["status"] == STATUS_REACHABLE and v["call_path"]:
            p = v["call_path"]
            ent_id = f"entry:{p['path_nodes'][0]}"
            nodes.setdefault(ent_id, {"id": ent_id, "label": p["entry"], "kind": "entrypoint", "status": v["status"], "layer": 0,
                                      "routes": p["routes"]})
            app_id = f"app:{p['path_nodes'][-1]}"
            last = fgraph.nodes[p["path_nodes"][-1]]["label"] if fgraph else p["path_nodes"][-1]
            nodes.setdefault(app_id, {"id": app_id, "label": last, "kind": "app-method", "status": v["status"], "layer": 1})
            sym_id = f"sym:{sym}"
            nodes.setdefault(sym_id, {"id": sym_id, "label": (sym or "").split(".")[-1], "kind": "symbol", "status": v["status"], "layer": 2})
            edges.append({"src": ent_id, "dst": app_id, "kind": "call-path", "hops": p["hops"]})
            edges.append({"src": app_id, "dst": sym_id, "kind": "calls"})
            edges.append({"src": sym_id, "dst": lib_id, "kind": "belongs-to"})
        elif sym and v["status"] == STATUS_IMPORTED:
            sym_id = f"sym:{sym}"
            nodes.setdefault(sym_id, {"id": sym_id, "label": sym.split(".")[-1], "kind": "symbol", "status": v["status"], "layer": 2})
            edges.append({"src": sym_id, "dst": lib_id, "kind": "belongs-to"})

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_sec": round(time.time() - t0, 2),
        "target": source_root,
        "data_sources": {
            "osv": meta["osv"], "epss": meta["epss"], "kev": meta["kev"], "kev_catalog_version": meta.get("kev_catalog_version"),
            "snapshot_fetched_at": meta.get("snapshot_fetched_at"), "spring_boot_bom": f"{inv['gradle'].get('boot_version')} (curated table)",
            "function_map": "curated per-advisory symbols + advisory-text class extraction",
            "container_advisories": "not queried (OS-package CVEs need an image scanner such as Trivy/Grype); Java jars inside the image ARE queried",
            "image_scan": (f"{image_info['image']} (real jars + dpkg)" if image_info.get("available") else image_info.get("reason")),
            "osv_error": meta.get("osv_error"),
        },
        "summary": {
            "components": len(inv["components"]),
            "direct": sum(1 for c in inv["components"] if c["direct"]),
            "transitive": sum(1 for c in inv["components"] if not c["direct"]),
            "container_images": len({c["image"] for c in inv["containers"]}),
            "os_packages": len(inv["os_packages"]),
            "vulnerabilities": len(vulns),
            "by_status": by_status,
            "deprioritised_by_reachability": deprioritised,
            "kev_total": sum(1 for v in vulns if v["kev"]),
            "kev_reachable": sum(1 for v in vulns if v["kev"] and v["status"] == STATUS_REACHABLE),
            "kev_not_reachable": sum(1 for v in vulns if v["kev"] and v["status"] in (STATUS_IMPORTED, STATUS_PRESENT)),
            "supply_chain_findings": sum(1 for s in supply if s["severity"] != "INFO"),
        },
        "components": components,
        "vulnerabilities": vulns,
        "supply_chain": supply,
        "image_sbom": {**{k: v for k, v in image_info.items() if k not in ("jars", "os_packages")}, "merge": image_summary, "jars": len(image_info.get("jars", [])),
                       "os_packages_count": len(image_info.get("os_packages", []))},
        "docker": {"containers": inv["containers"], "dockerfiles": inv["dockerfiles"], "compose": inv["compose"], "k8s": inv["k8s"], "os_packages": inv["os_packages"]},
        "canvas": {"nodes": list(nodes.values()), "edges": edges},
        "cyclonedx": to_cyclonedx(source_root, inv, vulns),
    }
    return report
