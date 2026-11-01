"""PRD scorecard: score a scan report (the JSON written by `vajra scan --json-out` / GET /scans/{id}) against a
planted-bug answer key. Matching rules are the ones scripts/unseen_app/eval_unseen.py uses (same line slack,
same definition of linked / wrong / false alarm), so the two give identical numbers on the same scan.

Answer key format (see scripts/unseen_app/answer_key.json):
  {"pairs": [{cwe,file,line,url,param}], "code_only": [{cwe,file,line}], "runtime_only": [{cwe,url,param}]?,
   "decoys": [{cwe,file,line,url}]}
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any, Dict, List, Optional

LINE_SLACK = 2


def url_match(actual, pattern):
    """True if a concrete request path matches an answer-key URL; `{var}` in the key matches one path segment.
    A leading context path on the actual URL is tolerated."""
    import re as _re
    a = (actual or "").split("?")[0].rstrip("/") or "/"
    rx = _re.escape((pattern or "").rstrip("/") or "/")
    rx = _re.sub(r"\\{[^}]*\\}", "[^/]+", rx)
    return _re.fullmatch(r"(?:/[^?]*?)?" + rx, a) is not None


def _at(item: Dict[str, Any], file_path: Optional[str], lines: List[Optional[int]], slack: int = LINE_SLACK) -> bool:
    return (file_path or "").replace("\\", "/").endswith(item["file"]) and any(
        abs((ln or 0) - item["line"]) <= slack for ln in lines)


def _upath(u: Optional[str]) -> str:
    return urllib.parse.urlparse(u or "").path


def _pct(a: int, b: int) -> Optional[float]:
    return round(100.0 * a / b, 1) if b else None


def score(report: Dict[str, Any], key: Dict[str, Any]) -> Dict[str, Any]:
    issues = report.get("issues", [])
    sast = report.get("sast_findings")
    dast = report.get("dast_findings")
    pairs, code_only = key.get("pairs", []), key.get("code_only", [])
    runtime_only, decoys = key.get("runtime_only", []), key.get("decoys", [])

    out: Dict[str, Any] = {"counts": {"issues": len(issues), "pairs": len(pairs), "code_only": len(code_only),
                                      "runtime_only": len(runtime_only), "decoys": len(decoys)}}

    # detection recall (raw scanner output, before correlation)
    if sast is not None:
        planted = pairs + code_only
        hit = [p for p in planted if any(_at(p, s["file_path"], [s["line"]]) and s["cwe"] == p["cwe"] for s in sast)]
        out["code_detection"] = {"hit": len(hit), "of": len(planted), "pct": _pct(len(hit), len(planted)),
                                 "missed": [p for p in planted if p not in hit]}
    if dast is not None:
        planted_rt = pairs + runtime_only
        hit = [p for p in planted_rt if any(url_match(_upath(d["url"]), p["url"]) and d["cwe"] == p["cwe"] for d in dast)]
        out["runtime_detection"] = {"hit": len(hit), "of": len(planted_rt), "pct": _pct(len(hit), len(planted_rt)),
                                    "missed": [p for p in planted_rt if p not in hit]}

    # links
    conf = [i for i in issues if i["status"] == "Confirmed"]
    linked, wrong, pair_hits = [], [], {}
    for i in conf:
        vb = i.get("vector_breakdown") or {}
        lines = vb.get("sink_lines") or [i.get("line")]
        eps = vb.get("verified_endpoints") or [_upath(i.get("url"))]
        hit = [n for n, p in enumerate(pairs) if p["cwe"] == i["cwe"] and _at(p, i.get("file_path"), lines) and any(url_match(e, p["url"]) for e in eps)]
        if len(hit) == 1:
            linked.append(i)
            pair_hits.setdefault(hit[0], []).append(i)
        else:
            wrong.append(i)
    out["correct_links"] = {"linked": len(linked), "of": len(pairs), "pct": _pct(len(linked), len(pairs)),
                            "pairs_without_confirmed_issue": [p for n, p in enumerate(pairs) if n not in pair_hits],
                            "pairs_with_duplicate_confirmed": [pairs[n] for n, v in pair_hits.items() if len(v) > 1]}
    out["wrong_links"] = {"wrong": len(wrong), "of_confirmed": len(conf), "pct": _pct(len(wrong), len(conf)),
                          "issues": [{"issue_id": i.get("issue_id"), "cwe": i["cwe"], "file": i.get("file_path"),
                                      "line": i.get("line"), "url": _upath(i.get("url"))} for i in wrong]}

    fa = [i for i in issues if any(
        (_at(dk, i.get("file_path"), [i.get("line")]) and i["cwe"] == dk["cwe"]) or
        (i["status"] != "Code only" and i["cwe"] == dk["cwe"] and url_match(_upath(i.get("url")), dk["url"])
         # a literal route wins over a template (/products/search is not /products/{pid})
         and not any("{" not in pp["url"] and url_match(_upath(i.get("url")), pp["url"]) for pp in pairs)) for dk in decoys)]
    out["false_alarms"] = {"count": len(fa), "of_issues": len(issues), "pct": _pct(len(fa), len(issues)),
                           "issues": [{"issue_id": i.get("issue_id"), "status": i["status"], "cwe": i["cwe"],
                                       "file": i.get("file_path"), "line": i.get("line")} for i in fa]}
    out["run_time_sec"] = (report.get("durations_sec") or {}).get("total")
    return out


def format_scorecard(sc: Dict[str, Any]) -> str:
    f = lambda v: "n/a" if v is None else f"{v:.1f}%"
    rows = []
    if "code_detection" in sc:
        c = sc["code_detection"]; rows.append(("Code detection recall", f(c["pct"]), f"{c['hit']}/{c['of']}"))
    if "runtime_detection" in sc:
        c = sc["runtime_detection"]; rows.append(("Runtime detection recall", f(c["pct"]), f"{c['hit']}/{c['of']}"))
    c = sc["correct_links"]; rows.append(("Correct links", f(c["pct"]), f"{c['linked']}/{c['of']} pairs"))
    c = sc["wrong_links"]; rows.append(("Wrong links", f(c["pct"]), f"{c['wrong']}/{c['of_confirmed']} confirmed"))
    c = sc["false_alarms"]; rows.append(("False alarms", f(c["pct"]), f"{c['count']}/{c['of_issues']} issues"))
    rt = sc["run_time_sec"]
    rows.append(("Run time", "n/a" if rt is None else f"{rt:.1f}s", "<5 min Great, <15 min Good" if rt is not None else "not in report"))
    w = max(len(r[0]) for r in rows)
    lines = [f"{n:<{w}}  {v:>7}  {d}" for n, v, d in rows]
    for label, key in (("Code recall misses", "code_detection"), ("Runtime recall misses", "runtime_detection")):
        for m in sc.get(key, {}).get("missed", []):
            lines.append(f"  {label}: {m}")
    for p in sc["correct_links"]["pairs_without_confirmed_issue"]:
        lines.append(f"  Pair with no Confirmed issue: {p}")
    for i in sc["wrong_links"]["issues"]:
        lines.append(f"  Wrong link: {i}")
    for i in sc["false_alarms"]["issues"]:
        lines.append(f"  False alarm: {i}")
    return "\n".join(lines)


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
