"""B-5: compare two scans -> new / fixed / still-open issues.

Issues are matched by their stable `fingerprint` (engine._sink_fingerprint: file + enclosing method + CWE for
code-backed issues, so it survives re-scans, line shifts inside the method, and Code-only -> Confirmed
upgrades). Nothing here is estimated: every list is a set operation on the two real issue lists.

Known limit: a Runtime-only issue has no code location, so its fingerprint is URL/param based. If a fix in
the code later lets the engine link it to a sink, it shows up as one fixed (Runtime only) + one new (Confirmed),
not as a status change.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List


def _d(issue: Any) -> Dict[str, Any]:
    return issue if isinstance(issue, dict) else issue.model_dump()


def _brief(i: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "fingerprint": i.get("fingerprint"), "issue_id": i.get("issue_id"), "status": i.get("status"),
        "severity": i.get("severity"), "cwe": i.get("cwe"), "vuln_type": i.get("vuln_type"),
        "file_path": i.get("file_path"), "line": i.get("line"), "url": i.get("url"),
        "parameter": i.get("parameter"), "risk_score": i.get("risk_score"),
    }


def load_issues(path_or_obj: Any) -> List[Dict[str, Any]]:
    """Issues from a report JSON file path, a scan-record dict ({"issues": [...]}), or a plain list."""
    obj = path_or_obj
    if isinstance(obj, str):
        with open(obj, "r", encoding="utf-8") as f:
            obj = json.load(f)
    if isinstance(obj, dict):
        obj = obj.get("issues", [])
    return [_d(i) for i in obj]


def compare_issue_lists(baseline: Iterable[Any], current: Iterable[Any]) -> Dict[str, Any]:
    """`baseline` = older scan A, `current` = newer scan B."""
    a = {i["fingerprint"]: i for i in map(_d, baseline)}
    b = {i["fingerprint"]: i for i in map(_d, current)}
    new = [_brief(b[f]) for f in b if f not in a]
    fixed = [_brief(a[f]) for f in a if f not in b]
    still_open, changed = [], []
    for f in b:
        if f not in a:
            continue
        row = _brief(b[f])
        row["previous_status"] = a[f].get("status")
        row["previous_severity"] = a[f].get("severity")
        still_open.append(row)
        if a[f].get("status") != b[f].get("status"):
            changed.append({**row, "change": f"{a[f].get('status')} -> {b[f].get('status')}"})
    return {
        "summary": {"baseline_total": len(a), "current_total": len(b), "new": len(new), "fixed": len(fixed),
                    "still_open": len(still_open), "status_changed": len(changed)},
        "new": new, "fixed": fixed, "still_open": still_open, "status_changed": changed,
    }


def compare_scans(a: Any, b: Any) -> Dict[str, Any]:
    """Each arg: scan-record dict, report JSON path, or issue list."""
    out = compare_issue_lists(load_issues(a), load_issues(b))
    for key, v in (("baseline", a), ("current", b)):
        if isinstance(v, dict):
            out[key] = {k: v.get(k) for k in ("scan_id", "started_at", "source", "target") if k in v}
    return out
