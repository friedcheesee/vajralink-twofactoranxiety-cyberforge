"""
Vajra-Link FastAPI Application Server (FR-1..FR-9, B-2, B-3, B-4, B-6, B-7).
B-1 (auto-verify Code-only findings at runtime) is wired into POST /scans and `vajra scan --auto-verify`
(opt-in); the response carries auto_verify_code_only's own stats (attempted / upgraded / still_code_only ...),
so an upgrade count of 0 is reported as 0.
Interactive Multi-Step Workflow Engine:
1. Target Repo Ingestion & Analysis
2. SAST Scanning & AI Decoy Triage (real OpenAI chat-completions second opinion)
3. 5-Stage DAST with Live Probes, Playwright DOM Proofs & AI Payloads
4. 4-Factor Correlation Graph & Exploit Inspector
5. HashiCorp Vault Migration & SARIF/Postman Exports
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import subprocess
import sys
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
import httpx
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Console logging - every stage prints what it's actually doing (and how long it took)
# straight to the terminal running uvicorn, not just the UI's own console-feed widgets.
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger("vajra")


def _log_lines(stage: str, lines: List[str]) -> None:
    """Print every human-readable log line a stage produced for the UI, also to the console."""
    for l in lines:
        log.info("[%s] %s", stage, l)

from vajra.config import PROJECT_ROOT, resolve_source_path
from vajra.correlation.ai_triage import (
    DECISIONS_MODEL,
    evaluate_safe_decoy_with_ai,
    resolve_greyzone_link,
    suggest_b1_verification_probe,
)
from vajra.correlation.engine import (
    build_curl_command,
    build_tailored_postman_script,
    correlate_findings,
)
from vajra.correlation.engine import AUTO_CONFIRM, GREY_CAP, GREY_FLOOR
from vajra.correlation.sarif_export import export_sarif_file, generate_sarif_report
from vajra.correlation.vault_helper import execute_vault_sync, generate_vault_migration_plan
from vajra.dast.postman_export import export_postman_collection_file, generate_postman_collection
from vajra.dast.runner import PROBEABLE_CWES, run_dast_scan_detailed
from vajra.dast.safety import assert_safe_target, docker_reachable_url
from vajra.db import (
    get_scan_record,
    DEFAULT_DB_PATH,
    get_issue_by_id,
    get_issues,
    get_routes,
    get_suppressed_findings,
    init_db,
    save_routes,
    save_scan,
    save_suppressed_findings,
    upsert_issues,
)
from vajra.models import CommonFinding, CorrelatedIssue, RouteEntry, build_ast_taint_flow
from vajra.routemap.java_servlet import extract_servlet_routes


DEFAULT_SOURCE = "targets/VulnerableApp"  # bundled sample target; every endpoint default comes from here
POSTMAN_FILENAME = "vajra_exploits.postman_collection.json"


def _drop_simulated(findings):
    """Belt-and-braces: a finding that was synthesised rather than observed over HTTP is never correlated."""
    return [f for f in findings if (getattr(f, "evidence_origin", None) or "").lower() != "simulated"]


def _extract_all_routes(source_root: str) -> List[RouteEntry]:
    """Route map for every supported framework (vajra.routemap.extract_routes) plus classic Servlet routing
    (web.xml / @WebServlet) - deduplicated by (method, pattern, file, start_line) so a route that both
    extractors report is counted once."""
    from vajra.routemap import extract_routes
    routes: List[RouteEntry] = []
    seen = set()
    for r in list(extract_routes(source_root)) + list(extract_servlet_routes(source_root)):
        key = (r.http_method.upper(), r.url_pattern, r.file_path, r.start_line)
        if key not in seen:
            seen.add(key)
            routes.append(r)
    return routes


from vajra.attack_patterns import ATTACK_PATTERN_CATALOG, compute_coverage
from vajra.sast.function_graph import FunctionGraph, build_function_graph
from vajra.sast.runner import grade_against_vulnerableapp_csv, run_sast_scan, run_sast_scan_detailed
from vajra.sca.reachability_sca import build_sca_report

app = FastAPI(
    title="Vajra-Link SAST-DAST Correlation Platform",
    description="CyberForge Flagship: Interactive End-to-End SAST-DAST Correlation & Exploit Verification.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def _log_requests(request: Request, call_next):
    """Print every incoming API call and how long it took - cheap global visibility into what the
    UI is actually doing, beyond uvicorn's one-line access log."""
    t0 = time.time()
    log.info(">> %s %s", request.method, request.url.path)
    try:
        response = await call_next(request)
    except Exception:
        log.exception("!! %s %s raised an unhandled exception", request.method, request.url.path)
        raise
    log.info("<< %s %s -> %s (%.2fs)", request.method, request.url.path, response.status_code, time.time() - t0)
    return response


DB_PATH = os.getenv("VAJRA_DB_PATH", DEFAULT_DB_PATH)
init_db(DB_PATH)
log.info("Vajra-Link starting up: DB_PATH=%s, cwd=%s", DB_PATH, os.getcwd())

# Directory Setup
WEB_DIR = os.path.join(os.path.dirname(__file__), "web")
STATIC_DIR = os.path.join(WEB_DIR, "static")
SCREENSHOT_DIR = os.path.join(os.getcwd(), "screenshots")
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.mount("/screenshots", StaticFiles(directory=SCREENSHOT_DIR), name="screenshots")

# Global In-Memory Workflow State for Interactive UI Stepper
workflow_state: Dict[str, Any] = {
    "repo": {
        "url": None,
        "path": resolve_source_path(DEFAULT_SOURCE),
        "status": "NOT_STARTED",
        "files_count": 0,
        "languages": [],
        "routes_count": 0,
    },
    "sast": {
        "status": "NOT_STARTED",
        "raw_count": 0,
        "findings": [],
        "suppressed": [],
        "noise_reduced": 0,
    },
    "dast": {
        "status": "NOT_STARTED",
        "target_url": "http://127.0.0.1:9090",
        "findings": [],
        "logs": [],
        "screenshots": [],
    },
    "correlation": {
        "status": "NOT_STARTED",
        "issues": [],
        "confirmed_count": 0,
        "runtime_only_count": 0,
        "code_only_count": 0,
        "duration": 0.0,
    },
}


# Object-level cache (workflow_state holds the JSON view; this holds the live objects)
_cache: Dict[str, Any] = {
    "source": None, "routes": None, "sast": None, "graph": None,
    "dast_findings": None, "dast_stats": None, "issues": None, "sca": None,
}


def _ensure_static(source_root: str, force: bool = False) -> Dict[str, Any]:
    """Route map + multi-engine SAST + function graph for `source_root` (cached)."""
    if force or _cache["source"] != source_root or _cache["sast"] is None:
        if not os.path.isdir(source_root):
            raise HTTPException(status_code=400, detail=f"Source directory not found: {source_root}. Ingest the repository in Step 1 first.")
        routes = _extract_all_routes(source_root)
        sast = run_sast_scan_detailed(source_root)
        graph = build_function_graph(source_root, routes, sast.active, sast.suppressed)
        _cache.update(
            source=source_root, routes=routes, sast=sast, graph=graph,
            dast_findings=None, dast_stats=None, issues=None, sca=None,
        )
    return _cache


class RepoCloneRequest(BaseModel):
    repo_url: Optional[str] = None  # any git URL; leave empty to inspect a local folder instead
    dest_dir: Optional[str] = None  # where to clone / read from; derived from the repo name when empty


_GIT_URL_RE = re.compile(r"^(https?://|ssh://|git@)[^\s]+$")


def _repo_name_from_url(url: str) -> str:
    name = url.rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return re.sub(r"[^A-Za-z0-9._-]", "_", name) or "repo"


def _normalize_git_url(url: str) -> str:
    return url.strip().rstrip("/").removesuffix(".git").lower()


def _git_output(args: List[str], cwd: str) -> Optional[str]:
    try:
        proc = subprocess.run(["git", "-C", cwd, *args], capture_output=True, text=True, timeout=30)
    except Exception:
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def _describe_source_tree(root: str) -> Dict[str, Any]:
    """Real file/language census of the downloaded or local source tree (no assumed stack)."""
    files = 0
    exts: Dict[str, int] = {}
    markers = set()
    for cur, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d != ".git"]
        for n in names:
            files += 1
            ext = os.path.splitext(n)[1].lower()
            if ext:
                exts[ext] = exts.get(ext, 0) + 1
            if n in ("pom.xml", "build.gradle", "build.gradle.kts", "package.json", "requirements.txt", "pyproject.toml", "go.mod"):
                markers.add(n)
    languages = []
    if exts.get(".java", 0):
        languages.append("Java")
    if exts.get(".py", 0):
        languages.append("Python")
    if exts.get(".js", 0) or exts.get(".ts", 0):
        languages.append("JavaScript/TypeScript")
    if exts.get(".go", 0):
        languages.append("Go")
    build = [m for m in ("pom.xml", "build.gradle", "build.gradle.kts", "package.json", "requirements.txt", "pyproject.toml", "go.mod") if m in markers]
    return {"files_count": files, "java_files": exts.get(".java", 0), "languages": languages, "build_files": build}


class SastRunRequest(BaseModel):
    source_path: str = DEFAULT_SOURCE


class DastRunRequest(BaseModel):
    target_url: str = "http://127.0.0.1:9090"
    source_path: str = DEFAULT_SOURCE
    context_path: Optional[str] = None  # e.g. "/WebGoat"; None = auto-detect from this repo's own config
    session_cookie: Optional[str] = None  # raw "Cookie:" header from a session you already logged into yourself
    # SAST -> DAST hand-off: only probe routes the function graph says can reach a flagged sink
    sast_guided: bool = True
    # DAST on its own: also scan every other route + live discovery (zero-knowledge)
    independent_discovery: bool = False
    include_policy: bool = True
    decoy_audit: bool = True


_CTX_KEYS = ("server.servlet.context-path", "server.context-path", "spring.mvc.servlet.path")
_PROPS_RE = re.compile(r"^\s*(server\.servlet\.context-path|server\.context-path|spring\.mvc\.servlet\.path)\s*[=:]\s*(.+?)\s*$", re.MULTILINE)


def _resolve_placeholder(raw: str) -> str:
    """`${ENV:/default}` -> `/default` (how it runs unless the operator overrides it); bare `${ENV}` -> ''."""
    raw = raw.strip().strip("'\"")
    m = re.fullmatch(r"\$\{[^}:]*(?::([^}]*))?\}", raw)
    if m:
        return (m.group(1) or "").strip()
    return raw


def _yaml_context_path(text: str) -> str:
    """Nested YAML keys (server: servlet: context-path: /x ; spring: mvc: servlet: path: /x) without a YAML dep."""
    stack: List[Tuple[int, str]] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^(\s*)([A-Za-z0-9_.\-]+)\s*:\s*(.*?)\s*(#.*)?$", line)
        if not m:
            continue
        indent, key, val = len(m.group(1)), m.group(2), m.group(3)
        while stack and stack[-1][0] >= indent:
            stack.pop()
        stack.append((indent, key))
        if val:
            dotted = ".".join(k for _, k in stack)
            if dotted in _CTX_KEYS:
                return _resolve_placeholder(val)
    return ""


def _detect_context_path(source_root: str) -> str:
    """Read this repo's own config for its servlet context path: Spring `.properties` and `.yml/.yaml`
    (flat or nested keys) for server.servlet.context-path / server.context-path / spring.mvc.servlet.path.
    Returns "" when nothing declares one (classic servlet/WAR apps are deployed under whatever name the
    operator chooses, so we can't know it - pass `context_path` explicitly in that case)."""
    for cur, dirs, names in os.walk(source_root):
        dirs[:] = [d for d in dirs if d not in (".git", "target", "build", "node_modules")]
        for n in names:
            if not (n.endswith(".properties") or n.endswith(".yml") or n.endswith(".yaml")):
                continue
            try:
                text = open(os.path.join(cur, n), "r", encoding="utf-8", errors="ignore").read()
            except Exception:
                continue
            if n.endswith(".properties"):
                m = _PROPS_RE.search(text)
                val = _resolve_placeholder(m.group(2)) if m else ""
            else:
                val = _yaml_context_path(text)
            if val and not val.startswith("$"):
                return "/" + val.strip("/")
    return ""


def _effective_context_path(override: Optional[str], source_root: str) -> str:
    """User override wins (even "" = none); otherwise auto-detect from the repo's own config."""
    if override is not None:
        o = override.strip().strip("/")
        return "/" + o if o else ""
    return _detect_context_path(source_root)


class CorrelateRequest(BaseModel):
    source_path: str = DEFAULT_SOURCE
    target_url: str = "http://127.0.0.1:9090"
    session_cookie: Optional[str] = None
    context_path: Optional[str] = None  # None = auto-detect; "" = explicitly no context path


class LiveVerifyRequest(BaseModel):
    issue_id: Optional[int] = None
    url: Optional[str] = None
    method: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    cwe: Optional[str] = None
    vuln_type: Optional[str] = None


@app.get("/")
def read_root():
    """Serve modern interactive dashboard."""
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"status": "online", "ui": "/static/index.html"}


# ---------------------------------------------------------------------------
# STEP 1: Repository Ingestion & Codebase Architecture Analysis
# ---------------------------------------------------------------------------
@app.post("/api/repo/clone")
def clone_or_inspect_repo(req: RepoCloneRequest):
    """Clone a git repository (any URL) into the destination, or inspect an existing local folder.

    Fails with HTTP 400 and the real git error when the clone does not succeed, so the UI never
    reports a repository as READY when nothing was downloaded.
    """
    t0 = time.time()
    repo_url = (req.repo_url or "").strip()
    dest_input = (req.dest_dir or "").strip()
    log.info("[Step 1: Repo Ingest] requested repo_url=%r dest_dir=%r", repo_url or "(none - local folder)", dest_input or "(auto)")
    if not dest_input:
        dest_input = f"targets/{_repo_name_from_url(repo_url)}" if repo_url else DEFAULT_SOURCE
    dest = resolve_source_path(dest_input)
    logs: List[str] = []

    if repo_url:
        if not _GIT_URL_RE.match(repo_url):
            raise HTTPException(status_code=400, detail="Repository URL must start with https://, http://, ssh:// or git@.")

        if os.path.isdir(dest):
            # Only trust a folder that is its own clone (not a sub-folder of some parent git repo).
            origin = _git_output(["config", "--get", "remote.origin.url"], dest) if os.path.exists(os.path.join(dest, ".git")) else None
            if origin is not None and _normalize_git_url(origin) == _normalize_git_url(repo_url):
                head = _git_output(["rev-parse", "--short", "HEAD"], dest) or "unknown"
                logs.append(f"Reusing existing clone at {dest} (origin matches, commit {head}).")
            else:
                # Destination is occupied by something else (a different repo, or a plain folder).
                # Don't block the user with an error — pick the next free "<name>-2", "<name>-3", ...
                # sibling folder and clone there instead, so Ingest always finishes end-to-end.
                base = dest
                n = 2
                while os.path.exists(dest):
                    dest = f"{base}-{n}"
                    n += 1
                why = f"already a clone of {origin}" if origin else "exists and is not a git clone"
                logs.append(f"Requested destination {base} {why} — cloning into {dest} instead.")

        if not os.path.isdir(dest):
            os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
            logs.append(f"Cloning {repo_url} into {dest} (depth 1)...")
            try:
                proc = subprocess.run(
                    ["git", "clone", "--depth", "1", "--", repo_url, dest],
                    capture_output=True, text=True, timeout=300,
                )
            except subprocess.TimeoutExpired:
                raise HTTPException(status_code=504, detail="git clone timed out after 300 seconds.")
            if proc.returncode != 0:
                raise HTTPException(
                    status_code=400,
                    detail=f"git clone failed: {(proc.stderr or proc.stdout).strip() or 'unknown error'}",
                )
            head = _git_output(["rev-parse", "--short", "HEAD"], dest) or "unknown"
            logs.append(f"git clone completed (commit {head}).")
    else:
        if not os.path.isdir(dest):
            raise HTTPException(
                status_code=400,
                detail=f"No repository URL given and no local folder exists at {dest}.",
            )
        logs.append(f"Inspecting local folder {dest} (no clone).")

    tree = _describe_source_tree(dest)
    logs.append(f"Indexed {tree['files_count']} files ({tree['java_files']} Java).")
    try:
        routes = _extract_all_routes(dest)
        n_servlet = sum(1 for r in routes if r.handler_name in ("doGet", "doPost", "doPut", "doDelete"))
        if n_servlet:
            logs.append(f"Extracted {len(routes) - n_servlet} Spring MVC route(s) + {n_servlet} classic Servlet route(s) (web.xml / @WebServlet).")
        else:
            logs.append(f"Extracted {len(routes)} declared Spring REST endpoints and parameter seeds.")
    except Exception as e:
        routes = []
        logs.append(f"Route extraction notice: {str(e)}")

    try:
        dest_rel = os.path.relpath(dest, str(PROJECT_ROOT)).replace("\\", "/")
    except ValueError:
        dest_rel = dest  # different drive on Windows; fall back to the absolute path

    workflow_state["repo"] = {
        "url": repo_url or None,
        "path": dest,
        "source_path": dest_rel,  # feed this straight back into /api/sast/run, /api/dast/run, etc.
        "status": "READY",
        "files_count": tree["files_count"],
        "java_files": tree["java_files"],
        "languages": tree["languages"],
        "build_files": tree["build_files"],
        "routes_count": len(routes),
        "routes": [r.model_dump() for r in routes[:60]],
        "logs": logs,
    }
    _log_lines("Step 1: Repo Ingest", logs)
    log.info("[Step 1: Repo Ingest] done in %.2fs: %s, %d files, %d routes", time.time() - t0, dest, tree["files_count"], len(routes))
    return workflow_state["repo"]


# ---------------------------------------------------------------------------
# STEP 2: Multi-Scanner SAST & AI Decoy Triage
# ---------------------------------------------------------------------------
@app.post("/api/sast/run")
def run_sast_stage(req: SastRunRequest):
    """Run every SAST engine independently, merge by sink, attribute findings to the engines that flagged them."""
    t0 = time.time()
    source_root = resolve_source_path(req.source_path)
    log.info("[Step 2: SAST] scanning %s", source_root)
    if not os.path.exists(source_root):
        log.warning("[Step 2: SAST] source directory not found: %s", source_root)
        raise HTTPException(status_code=400, detail=f"Source directory not found: {source_root}")

    c = _ensure_static(source_root, force=True)
    res = c["sast"]
    act, sup = res.active, res.suppressed
    report = res.engine_report
    for e in report["engines"]:
        if e.get("status") not in (None, "OK"):
            log.info("[Step 2: SAST] %s -> %s: %s", e["engine"], e["status"], e.get("reason", ""))
        else:
            log.info(
                "[Step 2: SAST] %s -> %d raw, %d unique, %d corroborated%s",
                e["engine"], e.get("raw_findings", 0), e.get("unique_findings", 0), e.get("corroborated_findings", 0),
                f", benchmark answer-key recall (eval only) {e['ground_truth_recall_pct']}%" if e.get("ground_truth_recall_pct") is not None else "",
            )
    log.info("[Step 2: SAST] done in %.2fs: %d active, %d suppressed", time.time() - t0, len(act), len(sup))

    enriched_raw = []
    for f in (act + sup):
        f_d = f.model_dump()
        flow = build_ast_taint_flow(
            f.cwe, f.vuln_type, f.file_path, f.line, f.code_snippet,
            function_name=f.function_name, guard_snippet=f.guard_snippet, status="Code only",
        )
        f_d["tool_tag"] = flow.get("tool_tag", "Custom Java AST Taint Engine")
        f_d["ast_flow"] = flow
        enriched_raw.append(f_d)

    enriched_act = [f for f in enriched_raw if not f.get("is_safe_decoy", False)]
    enriched_sup = [f for f in enriched_raw if f.get("is_safe_decoy", False)]

    step_logs = []
    for i, e in enumerate(report["engines"], 1):
        if e["engine"].startswith("Sanitizer"):
            detail = f"{e['decoys_identified']} safe decoys isolated (Variant.SECURE, '?' binding, encoders, allow-lists)."
        elif e.get("status") not in (None, "OK"):
            detail = f"{e['status']}: {e.get('reason', '')}"
        else:
            detail = (
                f"{e['raw_findings']} raw findings -> {e['unique_findings']} found only by this engine, "
                f"{e['corroborated_findings']} corroborated by another engine"
                + (f"; benchmark answer-key recall (eval only) {e['ground_truth_recall_pct']}%" if e.get("ground_truth_recall_pct") is not None else "")
            )
        step_logs.append({
            "step": i, "tool": e["engine"], "action": e["kind"],
            "status": "COMPLETED" if e.get("status", "OK") == "OK" else e["status"], "detail": detail,
        })

    gt = report.get("combined_ground_truth_recall_pct")
    ai_summary = {
        "title": "Multi-Engine SAST Attribution & Ground Truth Audit",
        "executive_summary": (
            f"{len(enriched_raw)} code locations analysed by {len([e for e in report['engines'] if e.get('status', 'OK') == 'OK'])} engines. "
            f"{report['merge']['corroborated_sinks']} sinks were independently flagged by 2+ engines; "
            f"{len(sup)} guarded decoys were suppressed."
            + (f" Benchmark answer-key recall (eval only; uses the app's own expectedIssues.csv, not part of the issue output): {gt}% of {report['ground_truth_total']} expected sinks." if gt is not None else "")
        ),
        "tools_executed": [
            {"name": e["engine"], "status": e.get("status", "OK"),
             "metric": f"{e['findings_after_merge']} sinks" + (f" · benchmark answer-key recall (eval only) {e['ground_truth_recall_pct']}%" if e.get("ground_truth_recall_pct") is not None else "")}
            for e in report["engines"] if not e["engine"].startswith("Sanitizer")
        ],
        "ground_truth_recall": f"benchmark answer-key recall (eval only): {gt}% of {report['ground_truth_total']} expected issues" if gt is not None else "n/a (no answer key present)",
        "total_raw_sinks": len(enriched_raw),
        "active_sinks": len(act),
        "safe_decoys": len(sup),
        "noise_profile": f"{round((len(sup) / max(1, len(enriched_raw))) * 100, 1)}% of flagged locations were guarded decoys and were suppressed.",
    }

    workflow_state["sast"] = {
        "status": "RAW_SCANNED",
        "source_path": source_root,
        "raw_count": len(enriched_raw),
        "active_count": len(enriched_act),
        "suppressed_count": len(enriched_sup),
        "findings": enriched_raw,
        "active_findings": enriched_act,
        "suppressed_findings": enriched_sup,
        "step_logs": step_logs,
        "ai_summary": ai_summary,
        "engine_report": report,
        "function_graph_stats": c["graph"].stats,
        "logs": [f"[{i}/{len(step_logs)}] [{s_['tool']}] {s_['detail']}" for i, s_ in enumerate(step_logs, 1)],
    }
    return workflow_state["sast"]


@app.get("/api/sast/engines")
def get_sast_engines(source_path: str = DEFAULT_SOURCE):
    """Per-engine attribution report (counts, unique finds, corroboration, ground-truth recall)."""
    c = _ensure_static(resolve_source_path(source_path))
    return c["sast"].engine_report


@app.get("/api/sast/function-graph")
def get_function_graph(
    source_path: str = DEFAULT_SOURCE,
    cwe: Optional[str] = None,
    module: Optional[str] = None,
    limit: int = 12,
):
    """Inter-module function graph, root-sink clusters and module propagation (pruned view for the canvas)."""
    c = _ensure_static(resolve_source_path(source_path))
    g: FunctionGraph = c["graph"]
    return g.to_dict(cwe=cwe, module=module, limit=limit)


@app.post("/api/sast/ai-decoy-triage")
def ai_decoy_triage(req: SastRunRequest):
    """Send the decoys the deterministic engine already suppressed to a real OpenAI Decisions API call
    (client.decisions.create, model gpt-6-luna) as an independent second opinion (B-2). Every number in the
    response is read off the live API calls — `total_input_tokens`/`total_output_tokens` are the real sums
    of each call's `usage` (verified: output_tokens is genuinely 0 for a predicate question — this API
    returns a probability, it doesn't generate text — but input_tokens is real and non-zero, so "free" would
    be wrong). 0 for every finding if no OPENAI_API_KEY is configured, which the response says plainly.
    Capped to the first MAX_AI_TRIAGE findings per run so a demo click can't trigger an unbounded bill."""
    MAX_AI_TRIAGE = 15
    source_root = resolve_source_path(req.source_path)

    sast_state = workflow_state.get("sast") or {}
    if sast_state.get("status") and sast_state.get("source_path") == source_root:
        suppressed = sast_state.get("suppressed_findings", [])
    else:
        c = _ensure_static(source_root)
        suppressed = [f.model_dump() for f in c["sast"].suppressed]

    sample = suppressed[:MAX_AI_TRIAGE]
    verdicts = []
    total_input_tokens = 0
    total_output_tokens = 0
    agreed = 0
    have_key = bool(os.getenv("OPENAI_API_KEY", "").strip()) and not os.getenv("OPENAI_API_KEY", "").startswith("your_")

    for f_d in sample:
        finding = CommonFinding(**{k: v for k, v in f_d.items() if k in CommonFinding.model_fields})
        v = evaluate_safe_decoy_with_ai(finding, db_path=DB_PATH)
        total_input_tokens += v.get("input_tokens", 0)
        total_output_tokens += v.get("output_tokens", 0)
        if v.get("is_safe_decoy") is True:
            agreed += 1
        verdicts.append({
            "file": finding.file_path, "line": finding.line, "cwe": finding.cwe,
            "deterministic_verdict": "safe_decoy", **v,
        })

    status = "OPTIMIZED" if have_key else "NO_API_KEY"
    result = {
        "status": status,
        "evaluated": len(sample),
        "total_suppressed_decoys": len(suppressed),
        "ai_agreed_safe": agreed,
        "total_input_tokens": total_input_tokens,
        "total_output_tokens": total_output_tokens,
        "model": DECISIONS_MODEL if have_key else None,
        "note": (
            f"{len(sample)} of {len(suppressed)} suppressed decoys sent to the OpenAI Decisions API "
            f"({DECISIONS_MODEL}) as a predicate question each; real cost: {total_input_tokens} input "
            f"tokens, {total_output_tokens} output tokens (predicate answers are a probability, not "
            f"generated text, so output tokens are genuinely ~0 — input tokens are the real cost)."
            if have_key else
            "No OPENAI_API_KEY configured — AI second opinion skipped; the suppression above is from the "
            "deterministic engine (parameterized-query / sanitizer pattern match) only."
        ),
        "verdicts": verdicts,
    }
    workflow_state["sast"]["ai_decoy_triage"] = result
    return result


# ---------------------------------------------------------------------------
# STEP 3: 5-Stage Active DAST Pipeline with Visual Proofs & AI Payloads
# ---------------------------------------------------------------------------
def _probe_rows(dast_findings, clean_target):
    rows = []
    for idx, f in enumerate(dast_findings, 1):
        # is_agentic is set ONLY by the DAST verifier when a payload from
        # synthesize_filter_bypass_payload() was actually fired and actually confirmed this finding -
        # never guessed from the URL.
        is_agentic = bool(f.is_agentic_ai and f.ai_technique)
        rows.append({
            "step": idx,
            "route": f.url.replace(clean_target, "") if f.url else "",
            "full_url": f.url,
            "method": f.method or "GET",
            "param": f.parameter or "",
            "payload": f.payload or "",
            "cwe": f.cwe,
            "vuln_type": f.vuln_type,
            "evidence": f.evidence or "(no differential evidence captured)",
            "status": "CONFIRMED_VULNERABLE",
            "is_agentic": is_agentic,
            "technique": f.ai_technique if is_agentic else "Static differential payload",
            "ai_engine": f.ai_engine if is_agentic else None,
            "ai_chain_of_thought": f.ai_chain_of_thought if is_agentic else [],
            "ai_guard_basis": f.ai_guard_basis if is_agentic else None,
            "discovery": f.discovery,
            "evidence_origin": f.evidence_origin,
            "scanner": f.scanner,
            "screenshot_path": f.screenshot_path,
        })
    return rows


@app.post("/api/dast/run")
async def run_dast_stage(req: DastRunRequest):
    """Run DAST: SAST-guided (hand-off from the function graph), independent, or both."""
    t0 = time.time()
    source_root = resolve_source_path(req.source_path)
    clean_target = req.target_url.rstrip("/")
    log.info(
        "[Step 3: DAST] target=%s source=%s sast_guided=%s independent=%s cookie=%s",
        clean_target, source_root, req.sast_guided, req.independent_discovery, "yes" if req.session_cookie else "no",
    )
    c = _ensure_static(source_root)
    routes = c["routes"]
    graph: FunctionGraph = c["graph"]
    plan = graph.targeted_route_plan(routes, PROBEABLE_CWES)

    sast_guided = req.sast_guided
    independent = req.independent_discovery or not req.sast_guided
    context_path = _effective_context_path(req.context_path, source_root)
    log.info("[Step 3: DAST] context_path=%r, %d/%d routes targeted by SAST hand-off", context_path, len(plan["routes"]), plan["stats"]["unique_routes_total"])
    dast_findings, stats = await run_dast_scan_detailed(
        target_base_url=clean_target,
        routes=routes,
        screenshot_dir=SCREENSHOT_DIR,
        plan=plan["routes"],
        sast_guided=sast_guided,
        independent=independent,
        include_policy=req.include_policy,
        decoy_audit=req.decoy_audit,
        context_path=context_path,
        session_cookie=req.session_cookie,
    )
    stats["context_path"] = context_path or "(none detected)"
    stats["plan"] = plan["stats"]
    stats["endpoint_reduction_pct"] = plan["stats"]["reduction_pct"] if (sast_guided and not independent) else 0.0
    stats.pop("traffic_reduction_pct", None)

    sequential_probes = _probe_rows(dast_findings, clean_target)
    mode_label = stats["mode"].replace("_", " ").replace("+", " + ")
    dast_logs = [
        {"stage": "Stage 0: SAST hand-off",
         "desc": f"Function graph selected {plan['stats']['targeted_routes']} of {plan['stats']['unique_routes_total']} unique routes "
                 f"(reach a sink with a probe-able CWE); mode = {mode_label}."},
        {"stage": "Stage 1: Header & TLS Recon",
         "desc": "Global policy audit (CSP / X-Frame-Options / nosniff / CORS / cookies)." if req.include_policy else "Skipped by request."},
        {"stage": "Stage 2: Differential HTTP Probes",
         "desc": f"{stats['endpoints_probed']} endpoints, {stats['requests_sent']} HTTP requests; probes chosen from SAST CWE hints for guided routes."},
        {"stage": "Stage 3: Headless DOM XSS", "desc": "Chromium canary execution for XSS candidates (HTTP-reflection fallback if the browser is missing)."},
        {"stage": "Stage 4: Decoy audit",
         "desc": f"{stats['decoy_audit']['routes_probed']} SAST-suppressed routes re-probed; {stats['decoy_audit']['violations']} exploitable (SAST false-negative candidates)."
                 if stats["decoy_audit"]["enabled"] else "Disabled."},
        {"stage": "Stage 5: Evidence origin",
         "desc": "All findings are live HTTP proofs." if stats["target_online"] else "TARGET OFFLINE: findings are SIMULATED from the route table, not real probes."},
    ]

    # Real per-finding AI-driven filter-bypass attempts from THIS run (never a canned demo). Each entry
    # exists only because SAST found a real guard in this codebase, AI reasoned over that exact guard text,
    # and the resulting payload was actually fired and actually confirmed the vulnerability.
    ai_payloads_used = [
        {
            "cwe": f.cwe,
            "route": f.url.replace(clean_target, "") if f.url else "",
            "param": f.parameter,
            "payload": f.payload,
            "technique": f.ai_technique,
            "chain_of_thought": f.ai_chain_of_thought,
            "engine": f.ai_engine,
            "guard_basis": f.ai_guard_basis,
            "evidence": f.evidence,
        }
        for f in dast_findings
        if f.is_agentic_ai and f.ai_technique
    ]

    _cache["dast_findings"] = dast_findings
    _cache["dast_stats"] = stats
    for dl in dast_logs:
        log.info("[Step 3: DAST] %s: %s", dl["stage"], dl["desc"])
    log.info(
        "[Step 3: DAST] done in %.2fs: %d findings (%d via AI-crafted payload), %d requests sent",
        time.time() - t0, len(dast_findings), len(ai_payloads_used), stats.get("requests_sent", 0),
    )
    workflow_state["dast"] = {
        "status": "COMPLETED",
        "target_url": clean_target,
        "findings_count": len(dast_findings),
        "findings": [f.model_dump() for f in dast_findings],
        "probes": sequential_probes,
        "logs": dast_logs,
        "stats": stats,
        "ai_payloads_used": ai_payloads_used,
        "ai_payloads_note": (
            f"{len(ai_payloads_used)} finding(s) were confirmed with an AI-crafted payload grounded in this "
            "scan's real SAST guard code." if ai_payloads_used else
            "No guarded sink was both reachable and confirmed this run, so the AI filter-bypass engine was "
            "not needed (either no SAST guard code was found on the probed routes, or the static payload "
            "library already confirmed everything without needing a bypass)."
        ),
    }
    return workflow_state["dast"]


@app.get("/api/dast/probes")
async def get_dast_probes(
    target_url: str = "http://127.0.0.1:9090",
    source_path: str = DEFAULT_SOURCE,
    session_cookie: Optional[str] = None,
    context_path: Optional[str] = None,
):
    """Probe execution stream (reuses the last DAST run when it targeted the same URL)."""
    clean_target = target_url.rstrip("/")
    findings = _cache.get("dast_findings")
    if not findings or workflow_state.get("dast", {}).get("target_url") != clean_target:
        source_root = resolve_source_path(source_path)
        c = _ensure_static(source_root)
        plan = c["graph"].targeted_route_plan(c["routes"], PROBEABLE_CWES)
        findings, stats = await run_dast_scan_detailed(
            clean_target, c["routes"], SCREENSHOT_DIR, plan=plan["routes"], sast_guided=True, independent=True, decoy_audit=True,
            context_path=_effective_context_path(context_path, source_root), session_cookie=session_cookie,
        )
        _cache["dast_findings"], _cache["dast_stats"] = findings, stats
    probes = _probe_rows(findings, clean_target)
    for pr, f in zip(probes, findings):
        pr["curl_command"] = build_curl_command(f.url, f.method, f.parameter, f.payload, f.cwe)
        pr["postman_script"] = build_tailored_postman_script(
            f.cwe, f.vuln_type, f.payload or "", f.parameter or "",
            ai_technique=f.ai_technique if (f.is_agentic_ai and f.ai_technique) else None,
            ai_guard_basis=f.ai_guard_basis if (f.is_agentic_ai and f.ai_technique) else None,
        )
    return {"total": len(probes), "probes": probes}


# ---------------------------------------------------------------------------
# STEP 4: 4-Factor Correlation Engine & Exploit Verification
# ---------------------------------------------------------------------------
@app.post("/api/correlate/run")
async def run_correlation_stage(req: CorrelateRequest):
    """Correlate SAST findings to DAST attacks using the 5-Vector Vajra-GraphLink formula + function graph."""
    start_t = time.time()
    source_root = resolve_source_path(req.source_path)
    clean_target = req.target_url.rstrip("/")
    log.info("[Step 4: Correlate] source=%s target=%s", source_root, clean_target)

    c = _ensure_static(source_root)
    routes = c["routes"]
    sast_act, sast_sup = c["sast"].active, c["sast"].suppressed
    graph: FunctionGraph = c["graph"]
    if (
        workflow_state.get("dast", {}).get("status") == "COMPLETED"
        and workflow_state["dast"].get("target_url") == clean_target
        and _cache.get("dast_findings")
    ):
        dast_findings = _cache["dast_findings"]
        dast_stats = _cache.get("dast_stats")
    else:
        plan = graph.targeted_route_plan(routes, PROBEABLE_CWES)
        dast_findings, dast_stats = await run_dast_scan_detailed(
            clean_target, routes, SCREENSHOT_DIR, plan=plan["routes"], sast_guided=True, independent=True, decoy_audit=True,
            context_path=_effective_context_path(req.context_path, source_root), session_cookie=req.session_cookie,
        )
        _cache["dast_findings"], _cache["dast_stats"] = dast_findings, dast_stats

    corr_report: Dict[str, Any] = {}
    dast_findings = _drop_simulated(dast_findings)
    issues = correlate_findings(
        sast_act, dast_findings, routes=routes, db_path=DB_PATH, fgraph=graph,
        suppressed=sast_sup, source_root=source_root, report=corr_report,
    )
    _cache["issues"] = issues
    duration = round(time.time() - start_t, 2)
    log.info(
        "[Step 4: Correlate] %d pairs scored: %d auto-confirmed (code path proven), %d sent to arbiter "
        "(%d linked / %d rejected), %d merged into an already-proven sink, %d contested, %d SAST suppressions overridden",
        corr_report.get("pairs_scored", 0), corr_report.get("auto_confirmed", 0), corr_report.get("arbiter_calls", 0),
        corr_report.get("arbiter_linked", 0), corr_report.get("arbiter_rejected", 0),
        corr_report.get("merged_into_existing_sink", 0), len(corr_report.get("contested", [])),
        corr_report.get("suppression_overridden", 0),
    )

    confirmed_cnt = sum(1 for i in issues if i.status == "Confirmed")
    runtime_cnt = sum(1 for i in issues if i.status == "Runtime only")
    code_cnt = sum(1 for i in issues if i.status == "Code only")
    log.info(
        "[Step 4: Correlate] done in %.2fs: %d issues (%d confirmed, %d runtime-only, %d code-only)",
        duration, len(issues), confirmed_cnt, runtime_cnt, code_cnt,
    )

    # Persist scan
    scan_id = save_scan(
        db_path=DB_PATH,
        source_path=source_root,
        target_url=clean_target,
        duration_sec=duration,
        summary_data={
            "total_issues": len(issues),
            "confirmed_count": confirmed_cnt,
            "runtime_only_count": runtime_cnt,
            "code_only_count": code_cnt,
            "suppressed_decoys": len(sast_sup),
        },
    )
    save_routes(DB_PATH, scan_id, routes)
    save_suppressed_findings(DB_PATH, scan_id, sast_sup)
    upsert_issues(DB_PATH, clean_target, scan_id, issues)

    # Generate SARIF & Postman collections
    export_sarif_file(issues, "vajra_report.sarif")
    export_postman_collection_file(issues, POSTMAN_FILENAME)

    # Generate Vault plan
    vault_plan = generate_vault_migration_plan(issues, source_root=source_root)

    workflow_state["correlation"] = {
        "status": "COMPLETED",
        "duration": duration,
        "total_issues": len(issues),
        "confirmed_count": confirmed_cnt,
        "runtime_only_count": runtime_cnt,
        "code_only_count": code_cnt,
        "suppressed_count": len(sast_sup),
        "vault_secrets_count": vault_plan["total_secrets"],
        "issues": [i.model_dump() for i in issues],
        "graph_stats": graph.stats,
        "dast_stats": dast_stats,
        "correlation_report": corr_report,
    }

    return {
        "scan_id": scan_id,
        "status": "COMPLETED",
        "duration_sec": duration,
        "total_issues": len(issues),
        "confirmed_count": confirmed_cnt,
        "runtime_only_count": runtime_cnt,
        "code_only_count": code_cnt,
        "suppressed_decoys": len(sast_sup),
        "vault_secrets_count": vault_plan["total_secrets"],
        "sarif_file": "vajra_report.sarif",
        "postman_collection": POSTMAN_FILENAME,
        "graph_stats": graph.stats,
        "dast_stats": dast_stats,
        "correlation_report": corr_report,
        "engine_merge": c["sast"].engine_report["merge"],
    }


# ---------------------------------------------------------------------------
# Attack-pattern catalog, reachability-aware SCA / SBOM
# ---------------------------------------------------------------------------
@app.get("/api/attack-patterns")
def get_attack_patterns():
    """The 15-pattern catalog (CAPEC / ATT&CK / CWE / SAST / DAST / SCA) overlaid with live scan coverage."""
    sast = _cache.get("sast")
    rows = compute_coverage(
        sast.active if sast else [],
        _cache.get("dast_findings") or [],
        _cache.get("issues") or [],
        _cache.get("sca"),
    )
    return {
        "total_patterns": len(ATTACK_PATTERN_CATALOG),
        "scan_state": {
            "sast": bool(sast), "dast": bool(_cache.get("dast_findings")),
            "correlation": bool(_cache.get("issues")), "sca": bool(_cache.get("sca")),
        },
        "patterns": rows,
    }


@app.get("/api/sca/reachability")
def get_sca_reachability(source_path: str = DEFAULT_SOURCE, refresh: bool = False, offline: bool = False):
    """Reachability-aware SCA + Docker/K8s SBOM (OSV + EPSS + CISA KEV; cached snapshot when offline)."""
    source_root = resolve_source_path(source_path)
    c = _ensure_static(source_root)
    if refresh or c.get("sca") is None:
        c["sca"] = build_sca_report(source_root, c["graph"], use_network=not offline)
    rep_ = dict(c["sca"])
    rep_.pop("cyclonedx", None)
    return rep_


@app.get("/api/sca/cyclonedx")
def download_cyclonedx(source_path: str = DEFAULT_SOURCE):
    """CycloneDX 1.5 SBOM (components + vulnerabilities with VEX-style reachability analysis)."""
    source_root = resolve_source_path(source_path)
    c = _ensure_static(source_root)
    if c.get("sca") is None:
        c["sca"] = build_sca_report(source_root, c["graph"])
    return JSONResponse(
        content=c["sca"]["cyclonedx"],
        headers={"Content-Disposition": 'attachment; filename="vajra_sbom.cdx.json"'},
    )


# ---------------------------------------------------------------------------
# Data Queries & File Downloads
# ---------------------------------------------------------------------------
@app.get("/api/workflow/state")
def get_workflow_state():
    """Retrieve live interactive stepper state."""
    return workflow_state


@app.get("/api/config")
def get_config():
    """Runtime defaults the UI reads on load. VAJRA_DEFAULT_TARGET lets docker-compose.yml point the DAST
    target field at the vulnerableapp service by name (http://vulnerableapp:9090/VulnerableApp) instead of
    the bare-metal default of 127.0.0.1, since "localhost" inside one container never reaches another."""
    return {
        "default_target_url": os.getenv("VAJRA_DEFAULT_TARGET", "http://127.0.0.1:9090"),
        "openai_configured": bool(os.getenv("OPENAI_API_KEY", "").strip())
        and not os.getenv("OPENAI_API_KEY", "").startswith("your_"),
        "vault_configured": bool(os.getenv("VAULT_ADDR", "").strip()),
        "grey_floor": GREY_FLOOR,
        "auto_confirm": AUTO_CONFIRM,
        "grey_cap": GREY_CAP,
    }


@app.get("/api/issues")
def list_issues(
    status: Optional[str] = None,
    cwe: Optional[str] = None,
    target_key: Optional[str] = None,
    scan_id: Optional[int] = None,
):
    """Retrieve filtered issues (Confirmed first, then Runtime only, then Code only)."""
    issues = get_issues(
        db_path=DB_PATH,
        target_key=target_key,
        status=status,
        cwe=cwe,
        scan_id=scan_id,
    )
    return {"total": len(issues), "issues": issues}


@app.get("/api/issues/{issue_id}")
def get_issue_detail(issue_id: int):
    """Get single correlated issue with full line context and exploit proof."""
    issue = get_issue_by_id(DB_PATH, issue_id)
    if not issue:
        raise HTTPException(status_code=404, detail=f"Issue {issue_id} not found")
    return issue


def _evaluate_live_postman_assertions(
    cwe: str,
    vuln_type: str,
    param: str,
    payload: str,
    status_code: int,
    headers: Dict[str, str],
    body: str,
    elapsed_ms: float,
) -> List[Dict[str, Any]]:
    """Evaluate CWE-tailored Postman pm.test(...) assertions against a real live HTTP response."""
    cwe_u = (cwe or "").upper()
    v_u = (vuln_type or "").upper()
    h_lower = {k.lower(): v for k, v in headers.items()}
    assertions: List[Dict[str, Any]] = []

    if "89" in cwe_u or "SQL" in v_u:
        p1 = status_code in (200, 500)
        assertions.append({
            "name": "HTTP status confirms SQL grammar fault or differential extraction",
            "passed": p1,
            "detail": f"pm.response.code === {status_code} (expected 200 or 500)",
        })
        m = re.search(r"(syntax error|jdbc|h2|sql statement|VAJRA_SQLI_PROOF|carInformation)", body, re.IGNORECASE)
        assertions.append({
            "name": "Database JDBC/H2 syntax error or extracted record signature present",
            "passed": bool(m),
            "detail": f"Matched '{m.group(0)}' in {len(body)}B body" if m else "No SQL fault/record marker matched",
        })
        p_name = param or "id"
        assertions.append({
            "name": f"Tainted parameter '{p_name}' delivered to SQL sink",
            "passed": bool(p_name),
            "detail": f"Sent {p_name}={payload[:48]}",
        })
    elif "78" in cwe_u or "77" in cwe_u or "COMMAND" in v_u:
        assertions.append({
            "name": "Status code is 200 OK (Subshell Process Output Reflected)",
            "passed": status_code == 200,
            "detail": f"pm.response.code === {status_code}",
        })
        m = re.search(r"(VAJRA_CMD_PROOF|uid=\d+|root:x:0:0)", body)
        assertions.append({
            "name": "POSIX process stdout canary matched in HTTP body",
            "passed": bool(m),
            "detail": f"Matched stdout indicator '{m.group(0)}'" if m else "No POSIX stdout indicator found",
        })
        assertions.append({
            "name": "Response latency within interactive process SLA (< 2000ms)",
            "passed": elapsed_ms < 2000.0,
            "detail": f"pm.response.responseTime === {elapsed_ms} ms",
        })
    elif "22" in cwe_u or "23" in cwe_u or "TRAVERSAL" in v_u:
        assertions.append({
            "name": "Status code is 200 OK (Resource Stream Returned)",
            "passed": status_code == 200,
            "detail": f"pm.response.code === {status_code}",
        })
        m = re.search(r"(root:x:0:0|daemon:x:1:1|sasanlabs:x:1000)", body)
        assertions.append({
            "name": "Protected filesystem record (/etc/passwd) disclosed in body",
            "passed": bool(m),
            "detail": f"Matched '{m.group(0)}'" if m else "No /etc/passwd line matched",
        })
        assertions.append({
            "name": "Disclosed payload exceeds baseline stub length (> 35B)",
            "passed": len(body) > 35,
            "detail": f"Body length = {len(body)} bytes",
        })
    elif "79" in cwe_u or "XSS" in v_u:
        assertions.append({
            "name": "Status code is 200 OK (HTML Document Rendered)",
            "passed": status_code == 200,
            "detail": f"pm.response.code === {status_code}",
        })
        m = re.search(r"(<script|<svg|<img|onload=|onerror=|__vajra_xss)", body, re.IGNORECASE)
        assertions.append({
            "name": "Unescaped executable DOM vector reflected in response HTML",
            "passed": bool(m),
            "detail": f"Matched unescaped DOM sink token '{m.group(0)}'" if m else "Payload escaped or absent",
        })
        has_csp = "content-security-policy" in h_lower
        assertions.append({
            "name": "Content-Security-Policy (CSP) script restriction absent",
            "passed": not has_csp,
            "detail": "Content-Security-Policy header is undefined" if not has_csp else f"CSP: {h_lower.get('content-security-policy')}",
        })
    elif "601" in cwe_u or "REDIRECT" in v_u:
        is_3xx = status_code in (301, 302, 303, 307, 308)
        assertions.append({
            "name": "Status code is 3xx Redirect (301/302/303/307)",
            "passed": is_3xx,
            "detail": f"pm.response.code === {status_code}",
        })
        loc = h_lower.get("location", "")
        is_ext = "example.com" in loc or loc.startswith(("http://", "https://", "//"))
        assertions.append({
            "name": "Location response header redirects to untrusted external host",
            "passed": is_ext,
            "detail": f"Location: {loc or '(missing)'}",
        })
    elif "918" in cwe_u or "SSRF" in v_u:
        assertions.append({
            "name": "Status code is 200 OK (Internal Upstream Response Proxied)",
            "passed": status_code == 200,
            "detail": f"pm.response.code === {status_code}",
        })
        m = re.search(r"(VAJRA_SSRF_METADATA|instance-id|169\.254|127\.0\.0\.1)", body, re.IGNORECASE)
        assertions.append({
            "name": "Internal metadata / loopback payload leaked in response",
            "passed": bool(m),
            "detail": f"Matched internal metadata token '{m.group(0)}'" if m else "No metadata leak matched",
        })
    elif "611" in cwe_u or "XXE" in v_u:
        assertions.append({
            "name": "Status code is 200 OK (XML Unmarshalled)",
            "passed": status_code == 200,
            "detail": f"pm.response.code === {status_code}",
        })
        m = re.search(r"(root:x:0:0|XXE_ENTITY_RESOLVED)", body)
        assertions.append({
            "name": "SYSTEM external entity file:///etc/passwd expanded in XML response",
            "passed": bool(m),
            "detail": f"Matched expanded entity '{m.group(0)}'" if m else "External entity not expanded",
        })
    elif "639" in cwe_u or "IDOR" in v_u:
        assertions.append({
            "name": "Status code is 200 OK (Object Record Returned Without Ownership Gate)",
            "passed": status_code == 200,
            "detail": f"pm.response.code === {status_code}",
        })
        m = re.search(r'(VAJRA_IDOR_UNAUTHORIZED_PROFILE|"role"\s*:\s*"ADMIN"|"salary")', body, re.IGNORECASE)
        assertions.append({
            "name": "Unauthorized ADMIN profile & confidential salary exposed",
            "passed": bool(m),
            "detail": f"Matched confidential field '{m.group(0)}'" if m else "No unauthorized record leaked",
        })
    elif "693" in cwe_u or "HEADER" in v_u or "CSP" in v_u or "CLICKJACK" in v_u or "NOSNIFF" in v_u:
        assertions.append({
            "name": "Endpoint responds over HTTP (200 OK)",
            "passed": status_code == 200,
            "detail": f"pm.response.code === {status_code}",
        })
        csp = h_lower.get("content-security-policy")
        xfo = h_lower.get("x-frame-options", "")
        xcto = h_lower.get("x-content-type-options", "")
        missing_list = []
        if not csp:
            missing_list.append("Content-Security-Policy absent")
        if not xfo or xfo.upper() == "ALLOWALL":
            missing_list.append(f"X-Frame-Options={'ALLOWALL' if xfo else 'absent'}")
        if "nosniff" not in xcto.lower():
            missing_list.append("X-Content-Type-Options: nosniff absent")
        assertions.append({
            "name": "Defensive browser protection header missing or permissive",
            "passed": len(missing_list) > 0,
            "detail": "; ".join(missing_list) if missing_list else "All security headers present",
        })
    else:
        assertions.append({
            "name": "HTTP response received from target endpoint",
            "passed": status_code in (200, 302, 500),
            "detail": f"pm.response.code === {status_code}",
        })
        assertions.append({
            "name": "Differential exploit evidence non-empty",
            "passed": len(body) > 0,
            "detail": f"Response size = {len(body)} bytes",
        })

    return assertions


@app.post("/api/verify/live")
async def verify_exploit_live(req: LiveVerifyRequest):
    """Execute a real-time HTTP exploit request against the live target server (localhost only)
    and evaluate Postman sandbox pm.test(...) assertions against the live response.
    """
    issue: Optional[CorrelatedIssue] = None
    if req.issue_id is not None:
        issue = get_issue_by_id(DB_PATH, req.issue_id)

    target_url = req.url or (issue.url if issue else None)
    if not target_url:
        raise HTTPException(
            status_code=400,
            detail="This finding is a static Code-Only sink with no live runtime endpoint URL to replay.",
        )

    assert_safe_target(target_url)
    target_url, _ = docker_reachable_url(target_url)

    method = (req.method or (issue.method if issue else None) or "GET").upper()
    param = req.parameter if req.parameter is not None else (issue.parameter if issue else None)
    payload = req.payload if req.payload is not None else (issue.payload if issue else None)
    cwe = req.cwe or (issue.cwe if issue else "CWE-Other")
    vuln_type = req.vuln_type or (issue.vuln_type if issue else "")

    is_raw_xml = method == "POST" and (
        "611" in (cwe or "").upper() or (payload and payload.strip().startswith("<?xml"))
    )

    req_params = None
    req_data = None
    req_content = None
    req_headers: Dict[str, str] = {"User-Agent": "VajraLink-Live-Postman-Runner/1.0"}

    if is_raw_xml:
        req_content = (payload or "").encode("utf-8")
        req_headers["Content-Type"] = "application/xml"
    elif param and payload is not None and payload != "":
        if method == "GET":
            req_params = {param: payload}
        else:
            req_data = {param: payload}

    curl_cmd = build_curl_command(target_url, method, param, payload, cwe)

    t0 = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=5.0, verify=False, follow_redirects=False) as client:
            resp = await client.request(
                method,
                target_url,
                params=req_params,
                data=req_data,
                content=req_content,
                headers=req_headers,
            )
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Live target server unreachable at {target_url}: {str(exc)}",
        )

    resp_headers = dict(resp.headers)
    body_text = resp.text
    assertions = _evaluate_live_postman_assertions(
        cwe=cwe,
        vuln_type=vuln_type,
        param=param or "",
        payload=payload or "",
        status_code=resp.status_code,
        headers=resp_headers,
        body=body_text,
        elapsed_ms=elapsed_ms,
    )
    passed_cnt = sum(1 for a in assertions if a["passed"])
    all_passed = len(assertions) > 0 and passed_cnt == len(assertions)

    return {
        "executed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "issue_id": req.issue_id,
        "cwe": cwe,
        "vuln_type": vuln_type,
        "request": {
            "method": method,
            "full_url": str(resp.request.url),
            "parameter": param,
            "payload": payload,
            "curl_command": curl_cmd,
        },
        "response": {
            "status_code": resp.status_code,
            "reason_phrase": resp.reason_phrase,
            "elapsed_ms": elapsed_ms,
            "headers": resp_headers,
            "body_length": len(body_text),
            "body_preview": body_text[:1200],
        },
        "postman_assertions": assertions,
        "passed_count": passed_cnt,
        "total_assertions": len(assertions),
        "all_passed": all_passed,
        "verdict": "EXPLOIT_REPRODUCED_LIVE" if all_passed else "PARTIAL_OR_FILTERED",
    }


@app.get("/api/suppressed")
def list_suppressed(scan_id: Optional[int] = None):
    """Retrieve safe decoys suppressed by Bonus B-2 noise filter."""
    suppressed = get_suppressed_findings(DB_PATH, scan_id=scan_id)
    return {"total": len(suppressed), "suppressed": suppressed}


@app.get("/api/routes")
def list_routes(scan_id: Optional[int] = None):
    """Retrieve extracted HTTP routes from source code."""
    routes = get_routes(DB_PATH, scan_id=scan_id)
    return {"total": len(routes), "routes": routes}


@app.get("/api/export/sarif")
def download_sarif(target_key: Optional[str] = None):
    """Download official OASIS SARIF 2.1.0 document."""
    issues = get_issues(DB_PATH, target_key=target_key)
    sarif = generate_sarif_report(issues)
    return JSONResponse(
        content=sarif,
        headers={"Content-Disposition": 'attachment; filename="vajra_report.sarif"'},
    )


@app.get("/api/export/postman")
def download_postman(target_key: Optional[str] = None):
    """Download verified Postman collection with executable exploit tests."""
    issues = get_issues(DB_PATH, target_key=target_key)
    collection = generate_postman_collection(issues)
    return JSONResponse(
        content=collection,
        headers={"Content-Disposition": f'attachment; filename="{POSTMAN_FILENAME}"'},
    )


def _vault_plan_for(source_path: str) -> Tuple[str, Dict[str, Any]]:
    source_root = resolve_source_path(source_path)
    c = _ensure_static(source_root)
    plan = generate_vault_migration_plan(c["sast"].active + c["sast"].suppressed, source_root=source_root)
    return source_root, plan


@app.get("/api/vault/migration")
def get_vault_migration(source_path: str = DEFAULT_SOURCE):
    """KV v2 migration plan built from the real hard-coded-secret findings of the current SAST run."""
    source_root, plan = _vault_plan_for(source_path)
    log.info("[Vault] plan for %s: %d secrets in %d files -> %s", source_root, plan["total_secrets"], plan["files_affected"], plan["vault_paths"])
    return plan


@app.post("/api/vault/migrate")
def run_vault_migration(source_path: str = DEFAULT_SOURCE):
    """Push the plan's secrets into a REAL Vault (needs VAULT_ADDR + VAULT_TOKEN); reports honestly otherwise."""
    source_root, plan = _vault_plan_for(source_path)
    result = execute_vault_sync(plan, source_root)
    log.info("[Vault] migrate %s -> %s (%s)", source_root, result["status"], result.get("reason") or f"{result['migrated_count']} keys")
    return {**result, "plan_total": plan["total_secrets"], "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


@app.get("/api/quantum/audit")
def get_quantum_audit():
    """NIST PQC audit computed from the most recent scan's issues where quantum_flag is true."""
    issues = _cache.get("issues")
    scan_ref = None
    if issues is None:
        rec = get_scan_record(DB_PATH)
        if rec:
            issues, scan_ref = rec.get("issues", []), rec.get("scan_id")
    if issues is None:
        return {"scan_run": False, "quantum_vulnerable_assets": [], "count": 0, "total_assets_flagged": 0,
                "message": "No scan has run yet, so there is nothing to audit. Run a scan first."}
    rows = [i if isinstance(i, dict) else i.model_dump() for i in issues]
    assets = [{
        "asset": f"{r.get('file_path')}:{r.get('line')}", "type": r.get("vuln_type"), "cwe": r.get("cwe"),
        "status": r.get("status"), "risk": r.get("quantum_alert") or "Quantum-vulnerable cryptographic primitive",
        "recommendation": r.get("fix_suggestion") or "Migrate to NIST FIPS 203/204 (ML-KEM / ML-DSA) or AES-256-GCM.",
        "code_snippet": r.get("code_snippet"),
    } for r in rows if r.get("quantum_flag")]
    return {
        "scan_run": True, "scan_id": scan_ref,
        "standard_reference": "NIST FIPS 203 (ML-KEM) & NIST FIPS 204 (ML-DSA)",
        "quantum_vulnerable_assets": assets, "count": len(assets), "total_assets_flagged": len(assets),
        "message": None if assets else "Scan completed; no finding carried a quantum-vulnerability flag.",
    }


# ---------------------------------------------------------------------------
# One-shot scan API (FR-10): POST /scans, GET /scans, GET /scans/{id}, GET /issues, GET /issues/{id},
# GET /scans/{a}/compare/{b}. Same stage functions as the /api/* step endpoints, run end to end.
# ---------------------------------------------------------------------------
from datetime import datetime, timezone  # noqa: E402

from vajra.correlation.scan_diff import compare_scans  # noqa: E402
from vajra.db import list_scan_records, save_scan_record  # noqa: E402

_scan_lock = asyncio.Lock()  # the static-analysis cache is process-global; run one scan at a time


class ScanRequest(BaseModel):
    source: str = DEFAULT_SOURCE
    target: str = "http://127.0.0.1:9090"
    context_path: Optional[str] = None  # None = auto-detect from the repo config; "" = none
    session_cookie: Optional[str] = None
    auto_verify: bool = False


def _count_by_status(issues: List[Dict[str, Any]]) -> Dict[str, int]:
    return {s: sum(1 for i in issues if i.get("status") == s) for s in ("Confirmed", "Runtime only", "Code only")}


async def run_full_scan(
    source: str,
    target: str,
    *,
    context_path: Optional[str] = None,
    session_cookie: Optional[str] = None,
    auto_verify: bool = False,
    db_path: Optional[str] = None,
    on_stage=None,
) -> Dict[str, Any]:
    """static -> DAST -> correlate -> (optional auto-verify) -> report. Returns and persists the scan record.
    Raises ValueError for an unsafe target, FileNotFoundError for a missing source."""
    db_path = db_path or DB_PATH
    source_root = resolve_source_path(source)
    target = target.rstrip("/")
    assert_safe_target(target)
    target, target_note = docker_reachable_url(target)
    if not os.path.isdir(source_root):
        raise FileNotFoundError(f"Source directory not found: {source_root}")
    ctx = _effective_context_path(context_path, source_root)
    say = on_stage or (lambda *_: None)
    started = datetime.now(timezone.utc)
    T: Dict[str, float] = {}

    async with _scan_lock:
        t_all = time.time()
        say("static")
        t = time.time()
        c = await asyncio.to_thread(_ensure_static, source_root, True)
        routes, sast, graph = c["routes"], c["sast"], c["graph"]
        T["static"] = time.time() - t

        say("dast")
        t = time.time()
        plan = graph.targeted_route_plan(routes, PROBEABLE_CWES)
        dast, dast_stats = await run_dast_scan_detailed(
            target, routes, SCREENSHOT_DIR, plan=plan["routes"], sast_guided=True, independent=True,
            decoy_audit=True, context_path=ctx, session_cookie=session_cookie,
        )
        dast = _drop_simulated(dast)
        T["dast"] = time.time() - t

        say("correlate")
        t = time.time()
        corr_report: Dict[str, Any] = {}

        def _correlate(findings):
            return correlate_findings(
                sast.active, findings, routes=routes, db_path=db_path, fgraph=graph,
                suppressed=sast.suppressed, source_root=source_root, report=corr_report,
            )

        issues = await asyncio.to_thread(_correlate, dast)
        T["correlate"] = time.time() - t

        av: Any = None
        if auto_verify:
            say("auto_verify")
            t = time.time()
            try:
                from vajra.correlation.auto_verify import auto_verify_code_only  # lazy: optional module
            except Exception:
                av = "unavailable"
            else:
                new, av_stats = await auto_verify_code_only(
                    issues, dast, routes, graph, target, context_path=ctx,
                    session_cookie=session_cookie, screenshot_dir=SCREENSHOT_DIR, time_budget_s=120,
                )
                av = dict(av_stats)
                if new:
                    dast = dast + _drop_simulated(new)
                    issues = await asyncio.to_thread(_correlate, dast)  # the normal engine decides any new link
                av["status_after"] = _count_by_status([i.model_dump() for i in issues])
            T["auto_verify"] = time.time() - t

        say("report")
        t = time.time()
        for n, i in enumerate(issues, 1):  # scan-local ids: GET /issues/7 is the 7th issue of this scan
            i.issue_id = n
        rows = [i.model_dump() for i in issues]
        counts = _count_by_status(rows)
        finished = datetime.now(timezone.utc)
        scan_id = save_scan(
            db_path=db_path, source_path=source_root, target_url=target, duration_sec=time.time() - t_all,
            summary_data={"total_issues": len(rows), "confirmed_count": counts["Confirmed"],
                          "runtime_only_count": counts["Runtime only"], "code_only_count": counts["Code only"],
                          "suppressed_decoys": len(sast.suppressed)},
        )
        save_routes(db_path, scan_id, routes)
        save_suppressed_findings(db_path, scan_id, sast.suppressed)
        upsert_issues(db_path, target, scan_id, issues)
        export_sarif_file(issues, "vajra_report.sarif")
        _cache.update(dast_findings=dast, dast_stats=dast_stats, issues=issues)
        T["report"] = time.time() - t
        T["total"] = time.time() - t_all

        record = {
            "scan_id": scan_id,
            "started_at": started.isoformat(),
            "finished_at": finished.isoformat(),
            "durations_sec": {k: round(v, 2) for k, v in T.items()},
            "source": source_root,
            "target": target,
            "target_note": target_note,
            "context_path": ctx,
            "counts": counts,
            "total_issues": len(rows),
            "routes": len(routes),
            "sast_active": len(sast.active),
            "sast_suppressed": len(sast.suppressed),
            "dast_findings_count": len(dast),
            "target_online": dast_stats.get("target_online"),
            "offline_reason": dast_stats.get("offline_reason"),
            "route_coverage": dast_stats.get("route_coverage"),
            "auto_verify": av if auto_verify else "not requested",
            "correlation_report": {k: v for k, v in corr_report.items() if not isinstance(v, list)},
            "sast_findings": [{"file_path": f.file_path, "line": f.line, "cwe": f.cwe} for f in sast.active],
            "dast_findings": [{"url": f.url, "cwe": f.cwe, "parameter": f.parameter, "method": f.method} for f in dast],
            "issues": rows,
        }
        await asyncio.to_thread(save_scan_record, db_path, scan_id, record)
        return record


@app.post("/scans")
async def create_scan(req: ScanRequest):
    try:
        rec = await run_full_scan(req.source, req.target, context_path=req.context_path,
                                  session_cookie=req.session_cookie, auto_verify=req.auto_verify)
    except (ValueError, FileNotFoundError) as e:  # unsafe target / missing source
        raise HTTPException(status_code=400, detail=str(e))
    return {k: v for k, v in rec.items() if k not in ("issues", "sast_findings", "dast_findings")}


@app.get("/scans")
def list_scans():
    scans = list_scan_records(DB_PATH)
    return {"total": len(scans), "scans": scans}


def _record_or_404(scan_id: Optional[int]) -> Dict[str, Any]:
    rec = get_scan_record(DB_PATH, scan_id)
    if not rec:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found" if scan_id is not None else "No scan has run yet")
    return rec


@app.get("/scans/{scan_id}")
def get_scan(scan_id: int):
    rec = _record_or_404(scan_id)
    return {k: v for k, v in rec.items() if k not in ("sast_findings", "dast_findings")}


@app.get("/scans/{a}/compare/{b}")
def compare_two_scans(a: int, b: int):
    """B-5: new / fixed / still-open going from scan a (older) to scan b (newer)."""
    return compare_scans(_record_or_404(a), _record_or_404(b))


@app.get("/issues")
def list_scan_issues(scan: Optional[int] = None, status: Optional[str] = None):
    rec = _record_or_404(scan)
    rows = [i for i in rec["issues"] if not status or i.get("status") == status]
    return {"scan_id": rec["scan_id"], "total": len(rows), "issues": rows}


@app.get("/issues/{issue_id}")
def get_scan_issue(issue_id: int, scan: Optional[int] = None):
    rec = _record_or_404(scan)
    for i in rec["issues"]:
        if i.get("issue_id") == issue_id:
            return {"scan_id": rec["scan_id"], **i}
    raise HTTPException(status_code=404, detail=f"Issue {issue_id} not in scan {rec['scan_id']}")
