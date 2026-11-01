"""
Multi-engine merge + safe-decoy gate (B-2).

* Separates active findings from suppressed safe decoys (Variant.SECURE, parameterised queries, encoders ...).
* Merges findings that several SAST engines raised for the *same sink* into ONE finding that carries every
  engine that flagged it (`CommonFinding.engines`). Two findings are the same sink when they are in the same file,
  share a canonical CWE, and sit on the same line (or within PROXIMITY lines when raised by different engines).
* When engines disagree (one flags a sink, another proves it is a guarded decoy) the decoy verdict wins and the
  disagreement is recorded for the report.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from vajra.models import CommonFinding
from vajra.sast.engines import ENGINE_DECOY, engine_for_scanner

PROXIMITY = 3


def _ensure_engines(f: CommonFinding) -> None:
    if not f.engines:
        f.engines.append(engine_for_scanner(f.scanner))


def merge_findings(
    findings: List[CommonFinding],
) -> Tuple[List[CommonFinding], List[CommonFinding], Dict[str, Any]]:
    """Return (active, suppressed, merge_stats)."""
    for f in findings:
        _ensure_engines(f)

    suppressed: List[CommonFinding] = []
    seen_sup: Dict[Tuple[str, int, str], CommonFinding] = {}
    for f in findings:
        if not f.is_safe_decoy:
            continue
        k = (f.file_path or "", f.line or 0, f.cwe)
        if k in seen_sup:
            for e in f.engines:
                if e not in seen_sup[k].engines:
                    seen_sup[k].engines.append(e)
            continue
        if ENGINE_DECOY not in f.engines:
            f.engines.append(ENGINE_DECOY)
        seen_sup[k] = f
        suppressed.append(f)

    active: List[CommonFinding] = []
    by_exact: Dict[Tuple[str, int, str], CommonFinding] = {}
    by_file_cwe: Dict[Tuple[str, str], List[CommonFinding]] = {}
    sup_by_file_cwe: Dict[Tuple[str, str], List[CommonFinding]] = {}
    for s in suppressed:
        sup_by_file_cwe.setdefault((s.file_path or "", s.cwe), []).append(s)

    merged_pairs = 0
    conflicts: List[Dict[str, Any]] = []

    for f in findings:
        if f.is_safe_decoy:
            continue
        file_key = f.file_path or ""
        exact_key = (file_key, f.line or 0, f.cwe)

        if exact_key in by_exact:
            tgt = by_exact[exact_key]
            added = [e for e in f.engines if e not in tgt.engines]
            tgt.engines.extend(added)
            merged_pairs += 1 if added else 0
            continue

        # Cross-engine proximity merge (never merges two findings from the same engine)
        merged = False
        for cand in by_file_cwe.get((file_key, f.cwe), []):
            if cand.line and f.line and abs(cand.line - f.line) <= PROXIMITY and not (set(f.engines) & set(cand.engines)):
                for e in f.engines:
                    if e not in cand.engines:
                        cand.engines.append(e)
                if not cand.function_name and f.function_name:
                    cand.function_name = f.function_name
                merged = True
                merged_pairs += 1
                break
        if merged:
            continue

        # Engine disagreement: another engine proved *this exact line* is a guarded decoy
        decoy_near = [
            s for s in sup_by_file_cwe.get((file_key, f.cwe), [])
            if s.line and f.line and s.line == f.line
        ]
        if decoy_near and f.scanner != "Vajra-AST-Taint":
            conflicts.append({
                "file": file_key,
                "line": f.line,
                "cwe": f.cwe,
                "flagged_by": f.engines,
                "suppressed_by": decoy_near[0].engines,
                "reason": decoy_near[0].suppression_reason,
            })
            continue

        by_exact[exact_key] = f
        by_file_cwe.setdefault((file_key, f.cwe), []).append(f)
        active.append(f)

    stats = {
        "raw_findings": len(findings),
        "active": len(active),
        "suppressed": len(suppressed),
        "cross_engine_merges": merged_pairs,
        "corroborated_sinks": sum(1 for a in active if len(a.engines) >= 2),
        "engine_conflicts": conflicts,
    }
    return active, suppressed, stats


def filter_safe_decoys(
    findings: List[CommonFinding],
) -> Tuple[List[CommonFinding], List[CommonFinding]]:
    """Backward-compatible wrapper: (active, suppressed)."""
    active, suppressed, _ = merge_findings(findings)
    return active, suppressed
