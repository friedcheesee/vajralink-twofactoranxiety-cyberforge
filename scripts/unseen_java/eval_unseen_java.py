"""End-to-end check on the unseen Java app (Pagecraft Books): SAST + live DAST + correlation, PRD metrics.
Generalised copy of scripts/unseen_app/eval_unseen.py (path/key are arguments; adds a per-pair diagnosis).

  .venv-win/Scripts/python.exe scripts/unseen_java/eval_unseen_java.py [http://127.0.0.1:9400] [--key path]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import sys
import time
import urllib.parse

logging.disable(logging.INFO)
sys.path.insert(0, ".")
from vajra.api import _detect_context_path, _ensure_static  # noqa: E402
from vajra.correlation.engine import correlate_findings, lookup_route  # noqa: E402
from vajra.dast.runner import PROBEABLE_CWES, run_dast_scan_detailed  # noqa: E402
from vajra.models import CommonFinding  # noqa: E402

_ap = argparse.ArgumentParser()
_ap.add_argument("target", nargs="?", default="http://127.0.0.1:9400")
_ap.add_argument("--auto-verify", action="store_true")
_ap.add_argument("--key", default=os.path.join(os.path.dirname(__file__), "answer_key.json"))
ARGS = _ap.parse_args()
KEY = json.load(open(ARGS.key))
DB = os.environ.get("VAJRA_EVAL_DB", "vajra_state.db")


def at(item, file_path, lines, slack=2):
    return (file_path or "").replace("\\", "/").endswith(item["file"]) and any(abs((ln or 0) - item["line"]) <= slack for ln in lines)


def url_match(actual, pattern):
    """True if a concrete request path matches an answer-key URL; `{var}` in the key matches one path segment.
    A leading context path on the actual URL is tolerated."""
    import re as _re
    a = (actual or "").split("?")[0].rstrip("/") or "/"
    rx = _re.escape((pattern or "").rstrip("/") or "/")
    rx = _re.sub(r"\\{[^}]*\\}", "[^/]+", rx)
    return _re.fullmatch(r"(?:/[^?]*?)?" + rx, a) is not None


async def main() -> None:
    target = ARGS.target.rstrip("/")
    src = KEY["app"]
    t0 = time.time()
    c = _ensure_static(src, force=True)
    plan = c["graph"].targeted_route_plan(c["routes"], PROBEABLE_CWES)
    dast, stats = await run_dast_scan_detailed(target, c["routes"], "screenshots", plan=plan["routes"], sast_guided=True,
                                               independent=True, decoy_audit=True, context_path=_detect_context_path(src))
    report: dict = {}
    issues = correlate_findings(c["sast"].active, dast, routes=c["routes"], fgraph=c["graph"], db_path=DB,
                                suppressed=c["sast"].suppressed, source_root=src, report=report)
    if "--auto-verify" in sys.argv:
        from vajra.correlation.auto_verify import auto_verify_code_only
        extra, av = await auto_verify_code_only(issues, dast, c["routes"], c["graph"], target,
                                                context_path=_detect_context_path(src))
        print(f"auto-verify: {av}; new: {sorted({f'{f.cwe} {urllib.parse.urlparse(f.url or chr(0)).path}' for f in extra})}")
        dast = dast + extra
        report = {}
        issues = correlate_findings(c["sast"].active, dast, routes=c["routes"], fgraph=c["graph"], db_path=DB,
                                    suppressed=c["sast"].suppressed, source_root=src, report=report)
    took = time.time() - t0

    pairs, decoys = KEY["pairs"], KEY["decoys"]
    sast_hits = [p for p in pairs + KEY["code_only"] if any(at(p, s.file_path, [s.line]) and s.cwe == p["cwe"] for s in c["sast"].active)]
    dast_hits = [p for p in pairs if any(url_match(urllib.parse.urlparse(d.url or "").path, p["url"]) and d.cwe == p["cwe"] for d in dast)]
    conf = [i for i in issues if i.status == "Confirmed"]
    linked, wrong = [], []
    for i in conf:
        lines = (i.vector_breakdown or {}).get("sink_lines") or [i.line]
        eps = (i.vector_breakdown or {}).get("verified_endpoints") or [urllib.parse.urlparse(i.url or "").path]
        hit = [p for p in pairs if p["cwe"] == i.cwe and at(p, i.file_path, lines) and any(url_match(e, p["url"]) for e in eps)]
        (linked if len(hit) == 1 else wrong).append((i, hit))
    false_alarms = [i for i in issues if any(
        (at(dk, i.file_path, [i.line]) and i.cwe == dk["cwe"]) or
        (i.status != "Code only" and i.cwe == dk["cwe"] and url_match(urllib.parse.urlparse(i.url or "").path, dk["url"])
         # a literal route wins over a template (/products/search is not /products/{pid})
         and not any("{" not in pp["url"] and url_match(urllib.parse.urlparse(i.url or "").path, pp["url"]) for pp in pairs)) for dk in decoys)]
    pct = lambda a, b: f"{100 * a / b:5.1f}%" if b else "  n/a"
    print(f"Unseen Java app ({src}) in {took:.1f}s: {len(c['routes'])} routes, {len(c['sast'].active)} SAST, {len(dast)} DAST, {len(issues)} issues")
    print(f"  Code detection   {pct(len(sast_hits), len(pairs) + len(KEY['code_only']))}")
    print(f"  Runtime detection {pct(len(dast_hits), len(pairs))}")
    print(f"  Correct links    {pct(len(linked), len(pairs))}   ({len(linked)}/{len(pairs)})")
    print(f"  Wrong links      {pct(len(wrong), len(conf))}   ({len(wrong)}/{len(conf)})")
    print(f"  False alarms     {pct(len(false_alarms), len(issues))}   ({len(false_alarms)})")
    print(f"  Engine report: { {k: v for k, v in report.items() if not isinstance(v, list)} }")
    for i in issues:
        vb = i.vector_breakdown or {}
        print(f"   #{i.issue_id} {i.status:12} {i.cwe:8} {i.file_path}:{i.line} {i.function_name} url={urllib.parse.urlparse(i.url or '').path} "
              f"{(vb.get('arbiter_engine') or '')[:40]}")
    for p in pairs:
        if p not in dast_hits:
            print(f"   DAST missed {p['cwe']} {p['url']}?{p['param']}")
        if not any(at(p, s.file_path, [s.line]) and s.cwe == p["cwe"] for s in c["sast"].active):
            print(f"   SAST missed {p['cwe']} {p['file']}:{p['line']}")



    print("--- diagnosis (route map / SAST / DAST / issues per planted pair) ---")
    for p in pairs:
        url_pat = p["url"]
        probe = CommonFinding(finding_id="x", stage="DAST", scanner="x", cwe=p["cwe"], raw_cwe=p["cwe"], vuln_type="x",
                              url=target + re.sub(r"\{[^}]*\}", "1", url_pat), method="GET")
        rt = lookup_route(probe, c["routes"])
        sast_here = [s for s in c["sast"].active + list(c["sast"].suppressed) if (s.file_path or "").replace("\\", "/").endswith(p["file"])]
        dast_here = [d for d in dast if urllib.parse.urlparse(d.url or "").path.rstrip("/") == re.sub(r"\{[^}]*\}", "1", url_pat).rstrip("/") or
                     urllib.parse.urlparse(d.url or "").path.rstrip("/").startswith(url_pat.split("{")[0].rstrip("/") + "/")
                     and "{" in url_pat]
        ok = any(i for i, h in linked if h and h[0] is p)
        print(f"[{'LINKED' if ok else 'NOT LINKED'}] {p['cwe']} {p['url']} -> {p['file'].split('/')[-1]}:{p['line']}")
        print(f"    route: {(rt.http_method + ' ' + rt.url_pattern + ' ' + rt.class_name + '.' + rt.handler_name + ' params=' + str(rt.params) + ' helpers=' + str(rt.called_helpers)) if rt else 'NONE (url not in route map)'}")
        print("    SAST in file: " + ("; ".join(f"{s.cwe}@{s.line}{'(suppressed:' + str(s.suppression_reason)[:40] + ')' if s.is_safe_decoy else ''}" for s in sast_here) or "none"))
        print("    DAST on url:  " + ("; ".join(f"{d.cwe} param={d.parameter} ev={(d.evidence or '')[:50]!r}" for d in dast_here) or "none"))
    print("--- all routes ---")
    for r in c["routes"]:
        print(f"   {r.http_method:5} {r.url_pattern:28} {r.class_name}.{r.handler_name} {r.file_path.split('/')[-1]}:{r.start_line}-{r.end_line} params={r.params}")
    print("--- all SAST (active) ---")
    for s in c["sast"].active:
        print(f"   {s.cwe:8} {(s.file_path or '').split('/')[-1]}:{s.line} {s.function_name} [{s.scanner}]")
    print("--- DAST findings ---")
    for d in dast:
        print(f"   {d.cwe:8} {d.method} {d.url} param={d.parameter} ({d.discovery})")


asyncio.run(main())
