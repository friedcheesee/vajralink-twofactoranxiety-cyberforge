"""Score the correlation output against VulnerableApp's own answer key, using the PRD's judging metrics.

Ground truth (nothing here comes from Vajra's own findings):
  * planted sinks  = src/main/resources/scanner/sast/expectedIssues.csv shipped inside VulnerableApp
  * safe decoys    = handlers the app itself annotates `variant = Variant.SECURE`
  * planted pairs  = planted sinks of a runtime-testable CWE that some vulnerable route actually reaches

A planted sink's identity ("one real bug") is the method that contains it, so two CSV rows in the same
method are one bug, and the same sink reached from five URLs is still one bug.

Usage:
  .venv-win\\Scripts\\python.exe scripts\\dump_pipeline.py targets/VulnerableApp http://localhost:9090 va_dump.json
  .venv-win\\Scripts\\python.exe scripts\\eval_correlation.py va_dump.json [--verbose] [--auto-verify]

--auto-verify (opt-in, B-1): probe Code-only findings' reachable routes live (or reuse the dump's
"auto_verify_dast"), re-run correlation with the extra findings, and print both before/after numbers.
"""
from __future__ import annotations

import csv
import json
import asyncio
import logging
import os
import sys
import urllib.parse
from collections import defaultdict

logging.disable(logging.INFO)
sys.path.insert(0, ".")
from vajra.api import _ensure_static  # noqa: E402
from vajra.correlation.engine import correlate_findings, lookup_route  # noqa: E402
from vajra.models import CommonFinding, canonicalize_cwe  # noqa: E402

RUNTIME_CWES = {"CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-601", "CWE-918", "CWE-611", "CWE-94", "CWE-90"}


def norm(p: str) -> str:
    return (p or "").replace("\\", "/").lstrip("./")


def main() -> None:
    dump = json.load(open(sys.argv[1]))
    verbose = "--verbose" in sys.argv
    src = dump["source"]
    c = _ensure_static(src)
    routes, g = c["routes"], c["graph"]
    dast = [CommonFinding(**x) for x in dump["dast"]]
    report: dict = {}
    db = os.environ.get("VAJRA_EVAL_DB", "vajra_state.db")
    issues = correlate_findings(c["sast"].active, dast, routes=routes, fgraph=g, db_path=db,
                                suppressed=c["sast"].suppressed, source_root=src, report=report)
    if "--auto-verify" in sys.argv:
        from vajra.api import _detect_context_path
        from vajra.correlation.auto_verify import auto_verify_code_only
        if "auto_verify_dast" in dump:
            extra, av = [CommonFinding(**x) for x in dump["auto_verify_dast"]], dump.get("auto_verify_stats")
        else:
            extra, av = asyncio.run(auto_verify_code_only(issues, dast, routes, g, dump["target"],
                                                          context_path=_detect_context_path(src)))
        before = {i.issue_id: i for i in issues}
        dast = dast + extra
        report = {}
        issues = correlate_findings(c["sast"].active, dast, routes=routes, fgraph=g, db_path=db,
                                    suppressed=c["sast"].suppressed, source_root=src, report=report)
        print(f"AUTO-VERIFY stats: {av}")
        print(f"AUTO-VERIFY: {len(extra)} new DAST findings: "
              + ", ".join(sorted({f'{f.cwe} {urllib.parse.urlparse(f.url or "").path}' for f in extra})))
        print(f"AUTO-VERIFY: Confirmed {sum(i.status=='Confirmed' for i in issues)} (was {sum(i.status=='Confirmed' for i in before.values())}), "
              f"Code only {sum(i.status=='Code only' for i in issues)} (was {sum(i.status=='Code only' for i in before.values())})")

    # ---- ground truth ----------------------------------------------------------------------------
    gt = []
    with open(os.path.join(src, "src/main/resources/scanner/sast/expectedIssues.csv")) as fh:
        for row in csv.DictReader(fh):
            f, ln = norm(row["File"]), int(row["Line"])
            node = g.innermost_node_at(f, ln)
            gt.append({"cwe": canonicalize_cwe(row["CWE"]), "file": f, "line": ln, "bug": node or f"{f}:{ln}"})
    bugs = defaultdict(list)
    for r in gt:
        bugs[(r["bug"], r["cwe"])].append(r)

    def bugs_at(file: str, line: int, cwe: str, slack: int = 3):
        file = norm(file)
        return {k for k, rows in bugs.items() if k[1] == cwe and any(
            r["file"].endswith(file) or file.endswith(r["file"]) for r in rows) and any(abs(r["line"] - line) <= slack for r in rows)}

    def bugs_reached_from(route, cwe):
        """Planted bugs of `cwe` that this route's handler encloses or reaches through the call graph."""
        out = set()
        entry = g.route_node(route)
        for k, rows in bugs.items():
            if k[1] != cwe:
                continue
            r = rows[0]
            if norm(route.file_path) == r["file"] and route.start_line <= r["line"] <= route.end_line:
                out.add(k)
            elif entry and g.forward_path(entry, k[0], max_hops=8) is not None:
                out.add(k)
        return out

    vuln_routes = [r for r in routes if not r.is_secure_variant]
    planted_pairs = set()
    for r in vuln_routes:
        for cwe in RUNTIME_CWES:
            planted_pairs |= bugs_reached_from(r, cwe)

    # ---- score -----------------------------------------------------------------------------------
    confirmed = [i for i in issues if i.status == "Confirmed"]
    linked_bugs, wrong, joined = set(), [], []
    for i in confirmed:
        vb = i.vector_breakdown or {}
        sink_lines = vb.get("sink_lines") or [i.line]
        at_sink = set()
        for ln in sink_lines:
            at_sink |= bugs_at(i.file_path, ln, i.cwe)
        reached = set()
        base = (i.url or "").split("/", 3)
        prefix = "/".join(base[:3]) if len(base) >= 3 else ""
        for ep in vb.get("verified_endpoints") or [urllib.parse.urlparse(i.url or "").path]:
            fake = CommonFinding(finding_id="x", stage="DAST", scanner="x", cwe=i.cwe, raw_cwe=i.cwe, vuln_type="x",
                                 url=prefix + ep, method=i.method)
            rt = lookup_route(fake, routes)
            if rt is not None:
                reached |= bugs_reached_from(rt, i.cwe)
        if not at_sink:
            wrong.append((i, "sink line is not a planted vulnerability"))
        elif len(at_sink | (reached & planted_pairs)) > 1 and len(reached) > 1:
            joined.append((i, sorted(k[0] for k in at_sink | reached)))
        else:
            linked_bugs |= at_sink

    decoy_routes = {(urllib.parse.urlparse("/" + r.url_pattern.strip("/")).path.lower()) for r in routes if r.is_secure_variant}
    false_alarms = []
    for i in issues:
        p = urllib.parse.urlparse(i.url or "").path.lower()
        if i.status != "Code only" and any(p.endswith(d) for d in decoy_routes if d != "/"):
            false_alarms.append(i)

    code_found = set()
    for i in issues:
        if not i.file_path:
            continue
        for ln in ((i.vector_breakdown or {}).get("sink_lines") or (i.vector_breakdown or {}).get("extra_lines") or [i.line]):
            code_found |= bugs_at(i.file_path, ln or 0, i.cwe)

    dast_proven = set()
    for d in dast:
        rt = lookup_route(d, routes)
        if rt is not None and not rt.is_secure_variant:
            dast_proven |= bugs_reached_from(rt, d.cwe)

    pct = lambda a, b: f"{100.0 * a / b:5.1f}%" if b else "  n/a"
    n_conf = len(confirmed)
    print(f"Issues: {len(issues)}  (Confirmed {n_conf}, Runtime only {sum(i.status == 'Runtime only' for i in issues)}, "
          f"Code only {sum(i.status == 'Code only' for i in issues)})")
    print(f"Answer key: {len(bugs)} planted bugs ({len(gt)} CSV rows), {len(planted_pairs)} runtime-testable pairs, "
          f"{len(decoy_routes)} SECURE decoy routes")
    print(f"  Code detection        {pct(len(code_found), len(bugs))}   ({len(code_found)}/{len(bugs)})            good>60 great>85")
    print(f"  Correct links         {pct(len(linked_bugs & planted_pairs), len(planted_pairs))}   ({len(linked_bugs & planted_pairs)}/{len(planted_pairs)} planted pairs)   good>50 great>80")
    print(f"    ...of pairs DAST proved {pct(len(linked_bugs & dast_proven), len(dast_proven))}   ({len(linked_bugs & dast_proven)}/{len(dast_proven)})  <- correlation quality alone")
    print(f"  Wrong links           {pct(len(wrong) + len(joined), n_conf)}   ({len(wrong)} bad sink, {len(joined)} join 2+ bugs)   good<20 great<5")
    print(f"  False alarms (decoys) {pct(len(false_alarms), len(issues))}   ({len(false_alarms)})                     good<30 great<10")
    print(f"Engine: {report.get('pairs_scored')} pairs scored, {report.get('auto_confirmed')} auto-confirmed, "
          f"{report.get('arbiter_calls')} to arbiter ({report.get('arbiter_linked')} linked), "
          f"{len(report.get('contested', []))} contested (not reported), "
          f"{len(report.get('secret_noise_dropped', []))} non-secret CWE-798 lines dropped")
    if verbose:
        for x in report.get("contested", []):
            print(f"   CONTESTED {x['url']}: {x['sast_verdict']}")
        for i, why in wrong:
            print(f"   WRONG  #{i.issue_id} {i.cwe} {i.file_path}:{i.line} <- {i.url}: {why}")
        for i, ks in joined:
            print(f"   JOINED #{i.issue_id} {i.cwe} {os.path.basename(i.file_path)}:{i.line} merges {len(ks)} bugs: {ks}")
        for i in false_alarms:
            print(f"   DECOY  #{i.issue_id} {i.status} {i.cwe} {i.url}")
        for k in sorted(dast_proven - linked_bugs):
            print(f"   MISSED (DAST proved, not linked) {k}")
        # Every planted pair not linked: why (SAST miss / no DAST proof) and which live routes reach it.
        for k in sorted(planted_pairs - linked_bugs):
            reach = [r for r in vuln_routes if k in bugs_reached_from(r, k[1])]
            print(f"   UNLINKED {k[1]:8} {k[0]}  sast={'yes' if k in code_found else 'NO'}  "
                  f"dast={'yes' if k in dast_proven else 'NO'}  routes={len(reach)}")
            for r in reach[:4]:
                print(f"        {r.http_method:5} {r.url_pattern}  params={r.params}")


if __name__ == "__main__":
    main()
