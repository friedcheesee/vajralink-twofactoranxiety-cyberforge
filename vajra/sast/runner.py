"""
Multi-Engine SAST Orchestrator & VulnerableApp Grader (FR-1, B-2).

Runs every engine independently, remembers which engine flagged what, merges duplicates, and reports
per-engine counts / unique contributions / ground-truth recall so the UI can show *who found what*.
"""
from __future__ import annotations

import csv
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from vajra.models import CommonFinding, canonicalize_cwe
from vajra.sast.java_taint import scan_java_project
from vajra.sast.secrets_scanner import scan_secrets as scan_resources_for_secrets
from vajra.sast.decoy_filter import merge_findings
from vajra.sast.engines import (
    ENGINE_AST_TAINT,
    ENGINE_BANDIT,
    ENGINE_DECOY,
    ENGINE_META,
    ENGINE_SECRETS,
    ENGINE_SEMGREP,
    ENGINE_SINK_SIG,
    add_engine,
)
from vajra.sast.bandit_runner import run_bandit
from vajra.sast.python_taint import scan_python_project
from vajra.sast.router import detect_project_profile
from vajra.sast.rule_synthesizer import synthesize_dynamic_semgrep_rules
from vajra.sast.semgrep_runner import run_semgrep
from vajra.sast.sink_signatures import scan_file_sink_signatures

GROUND_TRUTH_REL = "src/main/resources/scanner/sast/expectedIssues.csv"


@dataclass
class SastScanResult:
    active: List[CommonFinding]
    suppressed: List[CommonFinding]
    engine_report: Dict[str, Any] = field(default_factory=dict)


def _load_expected(csv_path: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with open(csv_path, "r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append(
                {
                    "cwe": r["CWE"].strip(),
                    "type": r["Vulnerability Type"].strip(),
                    "file": r["File"].strip(),
                    "line": int(r["Line"].strip()),
                    "canonical_cwe": canonicalize_cwe(r["CWE"].strip()),
                }
            )
    return rows


def _matched_expected_indexes(findings: List[CommonFinding], expected: List[Dict[str, Any]]) -> set:
    matched = set()
    for idx, exp in enumerate(expected):
        for f in findings:
            if not f.file_path or not f.line:
                continue
            if (f.file_path.endswith(exp["file"]) or exp["file"].endswith(f.file_path)) and abs(f.line - exp["line"]) <= 8:
                if f.cwe == exp["canonical_cwe"] or f.raw_cwe == exp["cwe"]:
                    matched.add(idx)
                    break
    return matched


def run_sast_scan_detailed(source_root: str, grade: bool = True) -> SastScanResult:
    profile = detect_project_profile(source_root)
    rules_file = synthesize_dynamic_semgrep_rules(source_root)

    per_engine_raw: Dict[str, List[CommonFinding]] = {
        ENGINE_AST_TAINT: [],
        ENGINE_SECRETS: [],
        ENGINE_SINK_SIG: [],
        ENGINE_SEMGREP: [],
        ENGINE_BANDIT: [],
    }
    per_engine_decoys: Dict[str, int] = {ENGINE_AST_TAINT: 0, ENGINE_SINK_SIG: 0}

    if "java" in profile.languages:
        # Generic taint engine (project-wide: needs the whole method table for call propagation).
        t_act, t_sup = scan_java_project(source_root)
        for f in t_act + t_sup:
            add_engine(f, ENGINE_AST_TAINT)
        per_engine_raw[ENGINE_AST_TAINT].extend(t_act + t_sup)
        per_engine_decoys[ENGINE_AST_TAINT] += len(t_sup)

        for root, _, files in os.walk(source_root):
            norm = root.replace("\\", "/")
            if "/.git" in norm or "/build/" in norm:
                continue
            for file in files:
                if not file.endswith(".java"):
                    continue
                full_p = os.path.join(root, file)
                s_act, s_sup = scan_file_sink_signatures(full_p, source_root)
                per_engine_raw[ENGINE_SINK_SIG].extend(s_act + s_sup)
                per_engine_decoys[ENGINE_SINK_SIG] += len(s_sup)

    # Secrets: language-agnostic (Java literals, config files, key material)
    sec = scan_resources_for_secrets(source_root)
    for f in sec:
        add_engine(f, ENGINE_SECRETS)
    per_engine_raw[ENGINE_SECRETS].extend(sec)

    # Python (Flask / FastAPI / Django) taint engine: same engine slot as the Java sink-signature scanner.
    py_act, py_sup = scan_python_project(source_root)
    per_engine_raw[ENGINE_SINK_SIG].extend(py_act + py_sup)
    per_engine_decoys[ENGINE_SINK_SIG] += len(py_sup)

    sg_findings, sg_status = run_semgrep(rules_file, source_root)
    per_engine_raw[ENGINE_SEMGREP].extend(sg_findings)
    bd_findings, bd_status = run_bandit(source_root)
    per_engine_raw[ENGINE_BANDIT].extend(bd_findings)

    # Merge priority: AST taint first (stable ordering), then secrets, sink-signatures, semgrep
    ordered: List[CommonFinding] = []
    for eng in (ENGINE_AST_TAINT, ENGINE_SECRETS, ENGINE_SINK_SIG, ENGINE_SEMGREP, ENGINE_BANDIT):
        ordered.extend(per_engine_raw[eng])

    active, suppressed, merge_stats = merge_findings(ordered)

    # Per-engine accounting on the merged result
    expected: List[Dict[str, Any]] = []
    csv_path = os.path.join(source_root, GROUND_TRUTH_REL)
    if grade and os.path.exists(csv_path):
        try:
            expected = _load_expected(csv_path)
        except Exception:
            expected = []

    engines_report: List[Dict[str, Any]] = []
    for eng in (ENGINE_AST_TAINT, ENGINE_SINK_SIG, ENGINE_SEMGREP, ENGINE_BANDIT, ENGINE_SECRETS):
        raw = [f for f in per_engine_raw[eng] if not f.is_safe_decoy]
        flagged_after_merge = [f for f in active if eng in f.engines]
        unique_only = [f for f in active if f.engines == [eng]]
        shared = [f for f in active if eng in f.engines and len(f.engines) > 1]
        meta = ENGINE_META[eng]
        entry: Dict[str, Any] = {
            "engine": eng,
            "key": meta["key"],
            "icon": meta["icon"],
            "color": meta["color"],
            "kind": meta["kind"],
            "java_optimizations": meta["java_optimizations"],
            "status": "OK",
            "raw_findings": len(raw),
            "findings_after_merge": len(flagged_after_merge),
            "unique_findings": len(unique_only),
            "corroborated_findings": len(shared),
            "decoys_identified": per_engine_decoys.get(eng, 0),
        }
        if eng == ENGINE_SEMGREP:
            entry.update(sg_status)
        if eng == ENGINE_BANDIT:
            entry.update(bd_status)
        if expected:
            hits = _matched_expected_indexes(raw, expected)
            entry["ground_truth_detected"] = len(hits)
            entry["ground_truth_recall_pct"] = round(len(hits) / len(expected) * 100.0, 2)
        engines_report.append(entry)

    decoy_meta = ENGINE_META[ENGINE_DECOY]
    engines_report.append(
        {
            "engine": ENGINE_DECOY,
            "key": decoy_meta["key"],
            "icon": decoy_meta["icon"],
            "color": decoy_meta["color"],
            "kind": decoy_meta["kind"],
            "java_optimizations": decoy_meta["java_optimizations"],
            "status": "OK",
            "raw_findings": 0,
            "findings_after_merge": 0,
            "unique_findings": 0,
            "corroborated_findings": 0,
            "decoys_identified": len(suppressed),
        }
    )

    combined_recall: Optional[float] = None
    if expected:
        hits = _matched_expected_indexes(active, expected)
        combined_recall = round(len(hits) / len(expected) * 100.0, 2)

    combo_counts: Dict[str, int] = {}
    for f in active:
        combo = " + ".join(sorted(f.engines)) if f.engines else "Unknown"
        combo_counts[combo] = combo_counts.get(combo, 0) + 1

    report = {
        "engines": engines_report,
        "merge": merge_stats,
        "combined_ground_truth_recall_pct": combined_recall,
        "ground_truth_total": len(expected),
        "engine_combinations": [{"engines": k, "count": v} for k, v in sorted(combo_counts.items(), key=lambda kv: -kv[1])],
        "notes": [
            "Java AST Taint is the generic vajra.sast.java_taint engine; the old benchmark-tuned ast_taint recognisers "
            "are no longer on the scan path. Sink-Signature Scanner is generic and is graded independently.",
            "Semgrep has no native Windows build: it runs through the official semgrep/semgrep Docker image there (status shows mode=docker). Bandit analyses Python only and is NOT_APPLICABLE on a Java target.",
        ],
    }
    return SastScanResult(active=active, suppressed=suppressed, engine_report=report)


def run_sast_scan(source_root: str) -> Tuple[List[CommonFinding], List[CommonFinding]]:
    """Execute complete SAST scan. Returns: (active_findings, suppressed_findings)"""
    res = run_sast_scan_detailed(source_root, grade=False)
    return res.active, res.suppressed


def grade_against_vulnerableapp_csv(
    findings: List[CommonFinding],
    expected_csv_path: str,
) -> Dict[str, Any]:
    """Grade findings against VulnerableApp's official expectedIssues.csv ground truth."""
    expected_rows = _load_expected(expected_csv_path)
    total_expected = len(expected_rows)
    matched_expected = _matched_expected_indexes(findings, expected_rows)

    detected_count = len(matched_expected)
    recall_pct = (detected_count / total_expected * 100.0) if total_expected > 0 else 0.0

    return {
        "total_expected": total_expected,
        "detected": detected_count,
        "missed": total_expected - detected_count,
        "recall_pct": round(recall_pct, 2),
        "total_findings": len(findings),
    }
