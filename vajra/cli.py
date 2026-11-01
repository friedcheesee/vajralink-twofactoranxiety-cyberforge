"""
Vajra-Link Rich Terminal Command-Line Interface (FR-1..FR-9, B-6).
Interactive CLI for source scanning, DAST execution, SARIF export, and CI Quality Gates.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from vajra.correlation.engine import correlate_findings
from vajra.correlation.sarif_export import evaluate_ci_quality_gate, export_sarif_file
from vajra.correlation.vault_helper import generate_vault_migration_plan
from vajra.dast.postman_export import export_postman_collection_file
from vajra.dast.runner import run_dast_scan_sync
from vajra.db import (
    DEFAULT_DB_PATH,
    init_db,
    save_routes,
    save_scan,
    save_suppressed_findings,
    upsert_issues,
)
from vajra.routemap.java_spring import extract_java_routes
from vajra.sast.runner import grade_against_vulnerableapp_csv, run_sast_scan

console = Console()

BANNER = """[bold cyan]
██╗   ██╗ █████╗      ██╗██████╗  █████╗       ██╗     ██╗███╗   ██╗██╗  ██╗
██║   ██║██╔══██╗     ██║██╔══██╗██╔══██╗      ██║     ██║████╗  ██║██║ ██╔╝
██║   ██║███████║     ██║██████╔╝███████║█████╗██║     ██║██╔██╗ ██║█████╔╝ 
╚██╗ ██╔╝██╔══██║██   ██║██╔══██╗██╔══██║╚════╝██║     ██║██║╚██╗██║██╔═██╗ 
 ╚████╔╝ ██║  ██║╚█████╔╝██║  ██║██║  ██║      ███████╗██║██║ ╚████║██║  ██╗
  ╚═══╝  ╚═╝  ╚═╝ ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═╝      ╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
[/bold cyan]
[bold white]Next-Gen SAST-DAST Correlation & Exploit Verification Engine[/bold white]
[italic dim]CyberForge Hackathon (Problem 06 Flagship) | SAST + DAST correlation[/italic dim]
"""


def cmd_scan(args):
    """Full pipeline via vajra.api.run_full_scan (the same code POST /scans runs)."""
    import asyncio
    import json

    from vajra.api import POSTMAN_FILENAME, run_full_scan  # noqa: F401
    from vajra.models import CorrelatedIssue

    console.print(BANNER)
    labels = {"static": "Stage 1: Route map + multi-engine SAST + function graph",
              "dast": "Stage 2: Live DAST probes",
              "correlate": "Stage 3: Correlation + risk engine",
              "auto_verify": "Stage 3b: Auto-verify Code-only findings (B-1)",
              "report": "Stage 4: Persist + export"}
    try:
        rec = asyncio.run(run_full_scan(
            args.source, args.target, context_path=args.context_path, session_cookie=args.session_cookie,
            auto_verify=args.auto_verify, db_path=args.db,
            on_stage=lambda st: console.print(f"[bold green]{labels.get(st, st)}[/bold green]"),
        ))
    except (ValueError, FileNotFoundError) as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(2)
    except Exception as e:  # HTTPException from a missing source dir etc.
        console.print(f"[bold red]Error:[/bold red] {getattr(e, 'detail', e)}")
        sys.exit(2)

    issues = [CorrelatedIssue(**i) for i in rec["issues"]]
    counts, T = rec["counts"], rec["durations_sec"]
    confirmed = [i for i in issues if i.status == "Confirmed"]

    console.print(f"  routes={rec['routes']}  SAST active={rec['sast_active']} (suppressed {rec['sast_suppressed']})  "
                  f"DAST findings={rec['dast_findings_count']}  context_path={rec['context_path'] or '(none)'}")
    if args.auto_verify:
        console.print(f"  auto-verify: {rec['auto_verify']}")

    summary_table = Table(title=f"Vajra-Link Scan #{rec['scan_id']} Summary", border_style="bright_blue")
    summary_table.add_column("Category", style="cyan", no_wrap=True)
    summary_table.add_column("Count", style="bold")
    summary_table.add_row("Confirmed", str(counts["Confirmed"]))
    summary_table.add_row("Runtime only", str(counts["Runtime only"]))
    summary_table.add_row("Code only", str(counts["Code only"]))
    summary_table.add_row("Total issues", str(rec["total_issues"]))
    console.print(summary_table)

    timing = Table(title="Run time (seconds)", border_style="bright_blue")
    timing.add_column("Stage")
    timing.add_column("Seconds", justify="right")
    for k, v in T.items():
        timing.add_row(k, f"{v:.2f}")
    console.print(timing)
    console.print(f"[bold cyan]Total run time: {T['total']:.2f}s[/bold cyan]")

    if confirmed:
        issues_table = Table(title="Confirmed (proven exploitable)", border_style="red")
        for col in ("#", "CWE", "Severity", "File:Line", "URL", "Risk"):
            issues_table.add_column(col)
        for i in confirmed[:15]:
            loc = f"{os.path.basename(i.file_path or '')}:{i.line}" if i.file_path else "N/A"
            issues_table.add_row(str(i.issue_id), i.cwe, i.severity, loc, i.url or "N/A", f"{i.risk_score:.0f}")
        console.print(issues_table)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(rec, fh, indent=2, default=str)
        console.print(f"  JSON report (issues + timings): {args.json_out}")
    if args.sarif:
        export_sarif_file(issues, args.sarif)
        console.print(f"  SARIF 2.1.0 exported: {args.sarif}")
    if args.postman:
        export_postman_collection_file(issues, args.postman)
        console.print(f"  Postman collection exported: {args.postman}")

    # CI quality gate (B-6): exit 1 exactly when a Confirmed HIGH/CRITICAL issue exists and the flag is set.
    gate = evaluate_ci_quality_gate(issues, fail_on_confirmed_high=args.fail_on_confirmed_high)
    n_hi = gate["confirmed_critical_count"] + gate["confirmed_high_count"]
    if args.fail_on_confirmed_high and not gate["passed"]:
        console.print(Panel(f"Confirmed Critical: {gate['confirmed_critical_count']}  |  Confirmed High: {gate['confirmed_high_count']}",
                            title="CI QUALITY GATE FAILED", border_style="red"))
        sys.exit(1)
    console.print(f"CI gate: {'not enforced' if not args.fail_on_confirmed_high else 'passed'} "
                  f"({n_hi} Confirmed HIGH/CRITICAL issue(s)).")


def cmd_diff(args):
    from vajra.correlation.scan_diff import compare_scans
    from vajra.db import get_scan_record

    def load(ref):
        if os.path.isfile(ref):
            return ref
        if ref.isdigit():
            rec = get_scan_record(args.db, int(ref))
            if rec:
                return rec
        console.print(f"[bold red]Error:[/bold red] {ref!r} is neither a JSON file nor a stored scan id in {args.db}")
        sys.exit(2)

    d = compare_scans(load(args.scan_a), load(args.scan_b))
    s = d["summary"]
    console.print(f"Baseline {args.scan_a}: {s['baseline_total']} issues -> Current {args.scan_b}: {s['current_total']} issues")
    console.print(f"  NEW {s['new']}   FIXED {s['fixed']}   STILL OPEN {s['still_open']}   STATUS CHANGED {s['status_changed']}")
    def loc(i):
        return f"{os.path.basename(i['file_path'] or '')}:{i['line']}" if i.get("file_path") else (i.get("url") or "")
    for title, key in (("New", "new"), ("Fixed", "fixed")):
        for i in d[key]:
            console.print(f"  [{title}] {i['status']:12} {i['cwe']:8} {loc(i)}")
    for i in d["status_changed"]:
        console.print(f"  [Changed] {i['change']}  {i['cwe']} {loc(i)}")
    if args.json_out:
        import json
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(d, fh, indent=2)


def cmd_eval(args):
    from vajra.eval.scorecard import format_scorecard, load_json, score

    sc = score(load_json(args.report), load_json(args.answer_key))
    print(format_scorecard(sc))
    if args.json_out:
        import json
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(sc, fh, indent=2)


def cmd_grade(args):
    console.print(BANNER)
    source_path = __import__("vajra.config",fromlist=["x"]).resolve_source_path(args.source)
    csv_path = os.path.abspath(args.csv) if os.path.isabs(args.csv) else str(__import__("vajra.config",fromlist=["x"]).PROJECT_ROOT / args.csv)

    console.print(f"Grading SAST against official ground truth: [bold cyan]{csv_path}[/bold cyan]...")
    sast_act, sast_sup = run_sast_scan(source_path)
    stats = grade_against_vulnerableapp_csv(sast_act, csv_path)

    grade_table = Table(title="VulnerableApp Benchmark SAST Grade", border_style="green")
    grade_table.add_column("Metric", style="cyan")
    grade_table.add_column("Value", style="bold")
    grade_table.add_column("PRD Great Threshold", style="italic")

    grade_table.add_row("Total Expected Issues", str(stats["total_expected"]), "105 issues")
    grade_table.add_row("Detected (Sink Line Match)", f"[bold green]{stats['detected']}[/bold green]", ">85% (>89 issues)")
    grade_table.add_row("Missed Issues", f"[bold red]{stats['missed']}[/bold red]", "<16 issues")
    grade_table.add_row("Detection Recall", f"[bold green]{stats['recall_pct']:.2f}%[/bold green]", ">85.0%")
    grade_table.add_row("Suppressed Safe Decoys (B-2)", f"[bold yellow]{len(sast_sup)}[/bold yellow]", ">10 decoys")
    console.print(grade_table)

    if stats["recall_pct"] >= 85.0:
        console.print("[bold green]✓ PASSED: Meets and exceeds PRD 'Great' standard (>85% recall)![/bold green]")
    else:
        console.print("[bold red]✗ FAILED: Below PRD 'Great' standard (>85% recall)[/bold red]")
        sys.exit(1)


def main():
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8")
        except Exception:
            pass
    parser = argparse.ArgumentParser(prog="vajra", description="Vajra-Link SAST-DAST Correlation Platform")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Scan subcommand
    scan_p = subparsers.add_parser("scan", help="Run full SAST-DAST correlation scan")
    scan_p.add_argument("--source", default="targets/VulnerableApp", help="Path to target source code")
    scan_p.add_argument("--target", default="http://127.0.0.1:9090", help="URL of running target instance")
    scan_p.add_argument("--sarif", default="vajra_report.sarif", help="Path to output SARIF report")
    scan_p.add_argument("--postman", default="vajra_exploits.postman_collection.json", help="Path to output Postman collection")
    scan_p.add_argument("--json-out", default=None, help="Write issues + per-stage timings to this JSON file")
    scan_p.add_argument("--context-path", default=None, help="Servlet context path of the running app (default: auto-detect from config)")
    scan_p.add_argument("--session-cookie", default=None, help="Raw Cookie header from a session you logged into yourself")
    scan_p.add_argument("--auto-verify", action="store_true", default=False, help="B-1: try to prove Code-only findings at runtime")
    scan_p.add_argument("--screenshot-dir", default="screenshots", help="Directory to save DOM proof screenshots")
    scan_p.add_argument("--db", default=DEFAULT_DB_PATH, help="Path to SQLite database")
    scan_p.add_argument("--fail-on-confirmed-high", action="store_true", default=False, help="Fail CI build if confirmed High/Critical issues exist")

    diff_p = subparsers.add_parser("diff", help="B-5: compare two scans (stored scan ids or report JSON files)")
    diff_p.add_argument("scan_a", help="Older scan: id or JSON file")
    diff_p.add_argument("scan_b", help="Newer scan: id or JSON file")
    diff_p.add_argument("--db", default=DEFAULT_DB_PATH, help="Path to SQLite database (for scan ids)")
    diff_p.add_argument("--json-out", default=None)

    eval_p = subparsers.add_parser("eval", help="Score a scan report against a planted-bug answer key (PRD metrics)")
    eval_p.add_argument("--report", required=True, help="JSON written by `vajra scan --json-out`")
    eval_p.add_argument("--answer-key", required=True, help="Answer key JSON (see scripts/unseen_app/answer_key.json)")
    eval_p.add_argument("--json-out", default=None)

    # Grade subcommand (eval-only: uses the benchmark app's own expectedIssues.csv)
    grade_p = subparsers.add_parser("grade", help="[eval only] Grade SAST against official benchmark expectedIssues.csv")
    grade_p.add_argument("--source", default="targets/VulnerableApp", help="Path to target source code")
    grade_p.add_argument("--csv", default="targets/VulnerableApp/src/main/resources/scanner/sast/expectedIssues.csv", help="Path to expectedIssues.csv")

    args = parser.parse_args()
    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "diff":
        cmd_diff(args)
    elif args.command == "eval":
        cmd_eval(args)
    elif args.command == "grade":
        cmd_grade(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
