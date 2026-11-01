"""
SQLite State Manager & Idempotent Deduplication Engine (FR-6, B-2).
Persists full 5-Vector Neuro-Symbolic Correlation traces, AST taint flows,
tailored Postman test suites, and cURL replay commands without loss.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from vajra.models import CommonFinding, CorrelatedIssue, RouteEntry, build_ast_taint_flow

DEFAULT_DB_PATH = "vajra_state.db"


def get_db_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Initialize database tables, indexes, and non-destructive column migrations."""
    with get_db_connection(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_path TEXT NOT NULL,
                target_url TEXT NOT NULL,
                created_at TEXT NOT NULL,
                duration_sec REAL DEFAULT 0.0,
                summary_json TEXT DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS routes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                http_method TEXT NOT NULL,
                url_pattern TEXT NOT NULL,
                handler_name TEXT NOT NULL,
                class_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                start_line INTEGER NOT NULL,
                end_line INTEGER NOT NULL,
                params_json TEXT DEFAULT '[]',
                helpers_json TEXT DEFAULT '[]',
                is_secure_variant INTEGER DEFAULT 0,
                vuln_type_tag TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS issues (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_key TEXT NOT NULL,
                fingerprint TEXT UNIQUE NOT NULL,
                status TEXT NOT NULL,
                priority_rank INTEGER DEFAULT 1,
                risk_score REAL DEFAULT 0.0,
                cwe TEXT NOT NULL,
                raw_cwe TEXT NOT NULL,
                vuln_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                url TEXT,
                method TEXT,
                parameter TEXT,
                payload TEXT,
                runtime_evidence TEXT,
                screenshot_path TEXT,
                file_path TEXT,
                line INTEGER,
                end_line INTEGER,
                code_snippet TEXT,
                function_name TEXT,
                correlation_confidence REAL DEFAULT 1.0,
                link_explanation TEXT,
                fix_suggestion TEXT,
                mitre_attck TEXT,
                mitre_capec TEXT,
                owasp_category TEXT,
                dpdp_alert TEXT,
                quantum_alert TEXT,
                vault_ref TEXT,
                scanners_json TEXT DEFAULT '[]',
                tool_tag TEXT,
                ast_flow_json TEXT,
                curl_command TEXT,
                postman_test_script TEXT,
                vector_breakdown_json TEXT,
                is_agentic_ai INTEGER DEFAULT 0,
                ai_technique TEXT,
                ai_chain_of_thought_json TEXT,
                ai_engine TEXT,
                ai_guard_basis TEXT,
                first_seen_scan INTEGER,
                last_seen_scan INTEGER
            );

            CREATE TABLE IF NOT EXISTS suppressed_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                file_path TEXT NOT NULL,
                line INTEGER,
                cwe TEXT NOT NULL,
                scanner TEXT NOT NULL,
                reason TEXT NOT NULL,
                snippet TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS ai_decision_cache (
                cache_key TEXT PRIMARY KEY,
                response_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_records (
                scan_id INTEGER PRIMARY KEY,
                created_at TEXT NOT NULL,
                record_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_issues_target ON issues(target_key);
            CREATE INDEX IF NOT EXISTS idx_issues_status ON issues(status);
            CREATE INDEX IF NOT EXISTS idx_issues_rank ON issues(priority_rank);
            CREATE INDEX IF NOT EXISTS idx_routes_scan ON routes(scan_id);
            """
        )

        # Safe additive migrations for existing SQLite databases
        migration_cols = [
            ("end_line", "INTEGER"),
            ("correlation_confidence", "REAL DEFAULT 1.0"),
            ("tool_tag", "TEXT"),
            ("ast_flow_json", "TEXT"),
            ("curl_command", "TEXT"),
            ("postman_test_script", "TEXT"),
            ("vector_breakdown_json", "TEXT"),
            ("is_agentic_ai", "INTEGER DEFAULT 0"),
            ("ai_technique", "TEXT"),
            ("ai_chain_of_thought_json", "TEXT"),
            ("ai_engine", "TEXT"),
            ("ai_guard_basis", "TEXT"),
        ]
        for col_name, col_type in migration_cols:
            try:
                conn.execute(f"ALTER TABLE issues ADD COLUMN {col_name} {col_type}")
            except sqlite3.OperationalError:
                pass


def save_scan(
    db_path: str,
    source_path: str,
    target_url: str,
    duration_sec: float,
    summary_data: Dict[str, Any],
) -> int:
    init_db(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with get_db_connection(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO scans (source_path, target_url, created_at, duration_sec, summary_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (source_path, target_url, now, duration_sec, json.dumps(summary_data)),
        )
        return cursor.lastrowid or 0


def save_routes(db_path: str, scan_id: int, routes: List[RouteEntry]) -> None:
    init_db(db_path)
    with get_db_connection(db_path) as conn:
        for r in routes:
            conn.execute(
                """
                INSERT INTO routes (
                    scan_id, http_method, url_pattern, handler_name, class_name,
                    file_path, start_line, end_line, params_json, helpers_json,
                    is_secure_variant, vuln_type_tag
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    r.http_method,
                    r.url_pattern,
                    r.handler_name,
                    r.class_name,
                    r.file_path,
                    r.start_line,
                    r.end_line,
                    json.dumps(r.params),
                    json.dumps(r.called_helpers),
                    1 if r.is_secure_variant else 0,
                    r.vulnerability_type_tag,
                ),
            )


def get_routes(db_path: str, scan_id: Optional[int] = None) -> List[RouteEntry]:
    init_db(db_path)
    with get_db_connection(db_path) as conn:
        if scan_id is not None:
            rows = conn.execute("SELECT * FROM routes WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()
        else:
            row = conn.execute("SELECT MAX(scan_id) FROM routes").fetchone()
            latest_id = row[0] if (row and row[0] is not None) else None
            if latest_id is not None:
                rows = conn.execute("SELECT * FROM routes WHERE scan_id = ? ORDER BY id", (latest_id,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM routes ORDER BY id").fetchall()
        result: List[RouteEntry] = []
        for row in rows:
            result.append(
                RouteEntry(
                    http_method=row["http_method"],
                    url_pattern=row["url_pattern"],
                    handler_name=row["handler_name"],
                    class_name=row["class_name"],
                    file_path=row["file_path"],
                    start_line=row["start_line"],
                    end_line=row["end_line"],
                    params=json.loads(row["params_json"] or "[]"),
                    called_helpers=json.loads(row["helpers_json"] or "[]"),
                    is_secure_variant=bool(row["is_secure_variant"]),
                    vulnerability_type_tag=row["vuln_type_tag"],
                )
            )
        return result


def upsert_issues(
    db_path: str,
    target_key: str,
    scan_id: int,
    issues: List[CorrelatedIssue],
) -> int:
    """Idempotently replace/upsert issues for the latest scan preserving full correlation provenance (FR-6)."""
    init_db(db_path)
    rank_map = {"Confirmed": 1, "Runtime only": 2, "Code only": 3}

    with get_db_connection(db_path) as conn:
        conn.execute("DELETE FROM issues WHERE target_key = ? OR last_seen_scan < ?", (target_key, scan_id))
        for issue in issues:
            sem_rank = rank_map.get(issue.status, issue.priority_rank if issue.priority_rank in (1, 2, 3) else 3)
            conn.execute(
                """
                INSERT INTO issues (
                    target_key, fingerprint, status, priority_rank, risk_score,
                    cwe, raw_cwe, vuln_type, severity, url, method, parameter,
                    payload, runtime_evidence, screenshot_path, file_path, line, end_line,
                    code_snippet, function_name, correlation_confidence, link_explanation,
                    fix_suggestion, mitre_attck, mitre_capec, owasp_category, dpdp_alert,
                    quantum_alert, vault_ref, scanners_json, tool_tag, ast_flow_json,
                    curl_command, postman_test_script, vector_breakdown_json, is_agentic_ai,
                    ai_technique, ai_chain_of_thought_json, ai_engine, ai_guard_basis,
                    first_seen_scan, last_seen_scan
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                ON CONFLICT(fingerprint) DO UPDATE SET
                    status = excluded.status,
                    priority_rank = excluded.priority_rank,
                    risk_score = excluded.risk_score,
                    url = excluded.url,
                    method = excluded.method,
                    payload = excluded.payload,
                    parameter = excluded.parameter,
                    runtime_evidence = COALESCE(excluded.runtime_evidence, issues.runtime_evidence),
                    screenshot_path = COALESCE(excluded.screenshot_path, issues.screenshot_path),
                    correlation_confidence = excluded.correlation_confidence,
                    link_explanation = excluded.link_explanation,
                    fix_suggestion = excluded.fix_suggestion,
                    tool_tag = excluded.tool_tag,
                    ast_flow_json = excluded.ast_flow_json,
                    curl_command = excluded.curl_command,
                    postman_test_script = excluded.postman_test_script,
                    vector_breakdown_json = excluded.vector_breakdown_json,
                    is_agentic_ai = excluded.is_agentic_ai,
                    ai_technique = excluded.ai_technique,
                    ai_chain_of_thought_json = excluded.ai_chain_of_thought_json,
                    ai_engine = excluded.ai_engine,
                    ai_guard_basis = excluded.ai_guard_basis,
                    scanners_json = excluded.scanners_json,
                    last_seen_scan = excluded.last_seen_scan
                """,
                (
                    target_key,
                    issue.fingerprint,
                    issue.status,
                    sem_rank,
                    issue.risk_score,
                    issue.cwe,
                    issue.raw_cwe,
                    issue.vuln_type,
                    issue.severity,
                    issue.url,
                    issue.method,
                    issue.parameter,
                    issue.payload,
                    issue.runtime_evidence,
                    issue.screenshot_path,
                    issue.file_path,
                    issue.line,
                    issue.end_line,
                    issue.code_snippet,
                    issue.function_name,
                    issue.correlation_confidence,
                    issue.link_explanation,
                    issue.fix_suggestion,
                    issue.mitre_attck,
                    issue.mitre_capec,
                    issue.owasp_category,
                    issue.dpdp_alert or ("DPDP Act 2023 Sec 8(5) Personal Data Breach" if getattr(issue, "dpdp_pii_flag", False) else None),
                    issue.quantum_alert or ("Post-Quantum Cryptography migration needed" if getattr(issue, "quantum_flag", False) else None),
                    issue.vault_ref or ("secret/vulnerableapp" if getattr(issue, "vault_candidate", False) else None),
                    json.dumps(issue.scanners_matched),
                    issue.tool_tag,
                    json.dumps(issue.ast_flow) if issue.ast_flow else None,
                    issue.curl_command,
                    issue.postman_test_script,
                    json.dumps(issue.vector_breakdown) if issue.vector_breakdown else None,
                    1 if issue.is_agentic_ai else 0,
                    issue.ai_technique,
                    json.dumps(issue.ai_chain_of_thought) if issue.ai_chain_of_thought else None,
                    issue.ai_engine,
                    issue.ai_guard_basis,
                    scan_id,
                    scan_id,
                ),
            )
        return len(issues)


def _row_to_correlated_issue(r: sqlite3.Row) -> CorrelatedIssue:
    keys = set(r.keys())

    flow: Optional[Dict[str, str]] = None
    if "ast_flow_json" in keys and r["ast_flow_json"]:
        try:
            flow = json.loads(r["ast_flow_json"])
        except Exception:
            flow = None
    if not flow:
        flow = build_ast_taint_flow(
            r["cwe"],
            r["vuln_type"],
            r["file_path"],
            r["line"],
            r["code_snippet"],
            function_name=r["function_name"],
            status=r["status"],
            dast_url=r["url"],
            dast_method=r["method"],
            dast_param=r["parameter"],
            dast_evidence=r["runtime_evidence"],
        )

    vb: Optional[Dict[str, Any]] = None
    if "vector_breakdown_json" in keys and r["vector_breakdown_json"]:
        try:
            vb = json.loads(r["vector_breakdown_json"])
        except Exception:
            vb = None

    curl_c = (r["curl_command"] if ("curl_command" in keys and r["curl_command"]) else None)
    if not curl_c and r["url"]:
        from vajra.correlation.engine import build_curl_command
        curl_c = build_curl_command(r["url"], r["method"], r["parameter"], r["payload"], r["cwe"])

    pm_s = (r["postman_test_script"] if ("postman_test_script" in keys and r["postman_test_script"]) else None)
    if not pm_s and r["url"]:
        from vajra.correlation.engine import build_tailored_postman_script
        pm_s = build_tailored_postman_script(
            r["cwe"], r["vuln_type"], r["payload"] or "", r["parameter"] or "",
            ai_technique=(r["ai_technique"] if ("ai_technique" in keys and r["ai_technique"]) else None),
            ai_guard_basis=(r["ai_guard_basis"] if ("ai_guard_basis" in keys and r["ai_guard_basis"]) else None),
        )

    # Trust the stored flag; it is only ever set True when a payload from synthesize_filter_bypass_payload()
    # was actually fired and actually confirmed the finding - never guessed from the URL text.
    is_agentic = bool(r["is_agentic_ai"]) if ("is_agentic_ai" in keys and r["is_agentic_ai"] is not None) else False
    ai_cot: List[str] = []
    if "ai_chain_of_thought_json" in keys and r["ai_chain_of_thought_json"]:
        try:
            ai_cot = json.loads(r["ai_chain_of_thought_json"])
        except Exception:
            ai_cot = []
    tool_t = (r["tool_tag"] if ("tool_tag" in keys and r["tool_tag"]) else None) or flow.get(
        "tool_tag", "Custom Java AST Taint Engine"
    )
    conf_val = float(r["correlation_confidence"]) if ("correlation_confidence" in keys and r["correlation_confidence"] is not None) else 1.0
    end_ln = r["end_line"] if "end_line" in keys else None

    rank_map = {"Confirmed": 1, "Runtime only": 2, "Code only": 3}
    sem_rank = rank_map.get(r["status"], r["priority_rank"])

    return CorrelatedIssue(
        issue_id=r["id"],
        fingerprint=r["fingerprint"],
        status=r["status"],
        priority_rank=sem_rank,
        risk_score=r["risk_score"],
        cwe=r["cwe"],
        raw_cwe=r["raw_cwe"],
        vuln_type=r["vuln_type"],
        severity=r["severity"],
        url=r["url"],
        method=r["method"],
        parameter=r["parameter"],
        payload=r["payload"],
        runtime_evidence=r["runtime_evidence"],
        screenshot_path=r["screenshot_path"],
        file_path=r["file_path"],
        line=r["line"],
        end_line=end_ln,
        code_snippet=r["code_snippet"],
        function_name=r["function_name"],
        correlation_confidence=conf_val,
        link_explanation=r["link_explanation"] or "",
        fix_suggestion=r["fix_suggestion"] or flow.get("remediation", ""),
        mitre_attck=r["mitre_attck"] or "",
        mitre_capec=r["mitre_capec"] or "",
        owasp_category=r["owasp_category"] or "",
        dpdp_alert=r["dpdp_alert"],
        quantum_alert=r["quantum_alert"],
        vault_ref=r["vault_ref"],
        dpdp_pii_flag=bool(r["dpdp_alert"]),
        quantum_flag=bool(r["quantum_alert"]),
        vault_candidate=bool(r["vault_ref"]),
        scanners_matched=json.loads(r["scanners_json"] or "[]"),
        tool_tag=tool_t,
        ast_flow=flow,
        curl_command=curl_c,
        postman_test_script=pm_s,
        is_agentic_ai=is_agentic,
        ai_technique=(r["ai_technique"] if ("ai_technique" in keys and r["ai_technique"]) else None),
        ai_chain_of_thought=ai_cot,
        ai_engine=(r["ai_engine"] if ("ai_engine" in keys and r["ai_engine"]) else None),
        ai_guard_basis=(r["ai_guard_basis"] if ("ai_guard_basis" in keys and r["ai_guard_basis"]) else None),
        vector_breakdown=vb,
    )


def get_issues(
    db_path: str,
    target_key: Optional[str] = None,
    status: Optional[str] = None,
    cwe: Optional[str] = None,
    scan_id: Optional[int] = None,
) -> List[CorrelatedIssue]:
    init_db(db_path)
    with get_db_connection(db_path) as conn:
        if scan_id is None and not target_key:
            row = conn.execute("SELECT MAX(id) FROM scans").fetchone()
            if row and row[0] is not None:
                scan_id = row[0]

        query = "SELECT * FROM issues WHERE 1=1"
        params: List[Any] = []
        if scan_id is not None:
            query += " AND last_seen_scan = ?"
            params.append(scan_id)
        elif target_key:
            query += " AND target_key = ?"
            params.append(target_key)
        if status:
            query += " AND status = ?"
            params.append(status)
        if cwe:
            query += " AND (cwe = ? OR raw_cwe = ?)"
            params.extend([cwe, cwe])
        query += " ORDER BY priority_rank ASC, risk_score DESC, id ASC"

        rows = conn.execute(query, params).fetchall()
        return [_row_to_correlated_issue(r) for r in rows]


def get_issue_by_id(db_path: str, issue_id: int) -> Optional[CorrelatedIssue]:
    init_db(db_path)
    with get_db_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM issues WHERE id = ?", (issue_id,)).fetchone()
        if not row:
            return None
        return _row_to_correlated_issue(row)


def save_suppressed_findings(db_path: str, scan_id: int, suppressed: List[CommonFinding]) -> None:
    init_db(db_path)
    with get_db_connection(db_path) as conn:
        for f in suppressed:
            conn.execute(
                """
                INSERT INTO suppressed_findings (scan_id, file_path, line, cwe, scanner, reason, snippet)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    f.file_path or "",
                    f.line or 0,
                    f.cwe,
                    f.scanner,
                    f.suppression_reason or "Safe decoy or protected pattern",
                    f.code_snippet or "",
                ),
            )


def get_suppressed_findings(db_path: str, scan_id: Optional[int] = None) -> List[Dict[str, Any]]:
    init_db(db_path)
    with get_db_connection(db_path) as conn:
        if scan_id is not None:
            rows = conn.execute("SELECT * FROM suppressed_findings WHERE scan_id = ?", (scan_id,)).fetchall()
        else:
            row = conn.execute("SELECT MAX(scan_id) FROM suppressed_findings").fetchone()
            latest_id = row[0] if (row and row[0] is not None) else None
            if latest_id is not None:
                rows = conn.execute("SELECT * FROM suppressed_findings WHERE scan_id = ?", (latest_id,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM suppressed_findings ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]


def get_ai_cache(db_path: str, cache_key: str) -> Optional[str]:
    init_db(db_path)
    with get_db_connection(db_path) as conn:
        row = conn.execute("SELECT response_json FROM ai_decision_cache WHERE cache_key = ?", (cache_key,)).fetchone()
        return row["response_json"] if row else None


def set_ai_cache(db_path: str, cache_key: str, response_json: str) -> None:
    init_db(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with get_db_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO ai_decision_cache (cache_key, response_json, created_at)
            VALUES (?, ?, ?)
            ON CONFLICT(cache_key) DO UPDATE SET response_json = excluded.response_json
            """,
            (cache_key, response_json, now),
        )


# ---------------------------------------------------------------------------
# One-shot scan records (POST /scans): the full result of one pipeline run, kept as a snapshot so scans
# can be listed, re-read and diffed later even after the live `issues` table has moved on to a newer scan.
# ---------------------------------------------------------------------------
def save_scan_record(db_path: str, scan_id: int, record: Dict[str, Any]) -> None:
    init_db(db_path)
    with get_db_connection(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO scan_records (scan_id, created_at, record_json) VALUES (?, ?, ?)",
            (scan_id, datetime.now(timezone.utc).isoformat(), json.dumps(record, default=str)),
        )


def get_scan_record(db_path: str, scan_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """The stored record for `scan_id`, or the most recent one when scan_id is None."""
    init_db(db_path)
    with get_db_connection(db_path) as conn:
        if scan_id is None:
            row = conn.execute("SELECT record_json FROM scan_records ORDER BY scan_id DESC LIMIT 1").fetchone()
        else:
            row = conn.execute("SELECT record_json FROM scan_records WHERE scan_id = ?", (scan_id,)).fetchone()
    return json.loads(row[0]) if row else None


def list_scan_records(db_path: str) -> List[Dict[str, Any]]:
    """Summaries (no issue lists) of every stored scan record, newest first."""
    init_db(db_path)
    with get_db_connection(db_path) as conn:
        rows = conn.execute("SELECT record_json FROM scan_records ORDER BY scan_id DESC").fetchall()
    out = []
    for (blob,) in rows:
        r = json.loads(blob)
        out.append({k: v for k, v in r.items() if k not in ("issues", "sast_findings", "dast_findings")})
    return out
