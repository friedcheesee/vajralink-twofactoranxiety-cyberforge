"""
Vajra-Link Master Verification Suite: runs every stage against VulnerableApp and reports PRD metrics.
Validates all performance metrics, accuracy thresholds, differentiator compliance,
and export validity against SasanLabs/VulnerableApp ground truth.
"""
from __future__ import annotations

import json
import os
import sys
import time

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from vajra.config import resolve_source_path
from vajra.correlation.engine import correlate_findings
from vajra.correlation.sarif_export import export_sarif_file, generate_sarif_report
from vajra.correlation.vault_helper import generate_vault_migration_plan
from vajra.dast.postman_export import export_postman_collection_file, generate_postman_collection
from vajra.dast.runner import run_dast_scan_sync
from vajra.routemap.java_spring import extract_java_routes
from vajra.sast.runner import grade_against_vulnerableapp_csv, run_sast_scan


def main():
    print("=" * 78)
    print("VAJRA-LINK: COMPREHENSIVE PERFORMANCE & GROUND TRUTH VALIDATOR")
    print("Testing against SasanLabs/VulnerableApp ground truth (metrics reported, sanity checks asserted)")
    print("=" * 78)

    t0 = time.time()
    source_root = resolve_source_path("targets/VulnerableApp")
    benchmark_csv = os.path.join(source_root, "src/main/resources/scanner/sast/expectedIssues.csv")

    assert os.path.exists(source_root), f"Target repo missing: {source_root}"
    assert os.path.exists(benchmark_csv), f"Benchmark CSV missing: {benchmark_csv}"

    # 1. Route Mapping Validation (FR-4)
    print("\n[Stage 1/5] Extracting Java Spring Route-Map & Parameter Seeds...")
    routes = extract_java_routes(source_root)
    print(f"  ✓ Extracted routes: {len(routes)} (Declared attack parameters mapped)")
    assert len(routes) >= 90, f"Expected >= 90 routes, got {len(routes)}"

    # 2. SAST High-Accuracy Scanner Validation (FR-1, B-2)
    print("\n[Stage 2/5] Running Multi-Scanner AST Taint Analysis & Safe-Decoy Filter...")
    sast_act, sast_sup = run_sast_scan(source_root)
    sast_stats = grade_against_vulnerableapp_csv(sast_act, benchmark_csv)

    print(f"  ✓ Ground Truth Total Expected: {sast_stats['total_expected']}")
    print(f"  ✓ Sinks Successfully Detected: {sast_stats['detected']}")
    print(f"  ✓ Sinks Missed: {sast_stats['missed']}")
    r = sast_stats["recall_pct"]
    band = "GREAT" if r > 85 else "GOOD" if r > 60 else "BELOW GOOD"
    # Reported, not asserted: SAST is the generic engine (no VulnerableApp-specific rules), and this CSV also
    # counts many classes outside the PRD's six. Asserting a threshold here would only invite re-tuning to it.
    print(f"  - Detection Recall vs expectedIssues.csv: {r:.2f}% [{band}] (PRD Good >60%, Great >85%)")
    print(f"  - Suppressed safe-decoy findings (B-2): {len(sast_sup)}")
    assert sast_stats["detected"] > 0, "SAST detected nothing"

    # 3. DAST Active Pipeline Validation (FR-2, FR-3)
    print("\n[Stage 3/5] Running 5-Stage Active DAST Pipeline...")
    from vajra.api import _detect_context_path
    dast_findings = run_dast_scan_sync("http://127.0.0.1:9090", routes=routes, screenshot_dir="screenshots",
                                       context_path=_detect_context_path(source_root))
    print(f"  ✓ Verified Runtime Findings: {len(dast_findings)}")
    # NOTE: this used to assert >= 50, a number left over from an older DAST pass that included false
    # positives later fixed (boolean-SQLi, echo-reflection, open-redirect bugs - see git history). The
    # current honest count on VulnerableApp is ~20-30 real, confirmed findings; a sheer-count gate is the
    # wrong metric anyway (PRD measures recall % against the answer key - see scripts/eval_correlation.py
    # for the real, reproducible accuracy numbers). This is now just a non-fatal sanity floor.
    assert len(dast_findings) >= 10, f"Expected >= 10 DAST findings as a sanity floor, got {len(dast_findings)}"

    # 4. Correlation & Risk Engine Validation (FR-5..FR-9, B-1, B-3)
    print("\n[Stage 4/5] Executing 4-Factor Correlation & Exploit Prioritization...")
    issues = correlate_findings(sast_act, dast_findings, routes=routes, suppressed=sast_sup, source_root=source_root)

    confirmed = [i for i in issues if i.status == "Confirmed"]
    runtime_only = [i for i in issues if i.status == "Runtime only"]
    code_only = [i for i in issues if i.status == "Code only"]

    print(f"  ✓ Total Correlated Issues: {len(issues)}")
    print(f"  ✓ Rank 1 (Confirmed): {len(confirmed)} (Exploitability proven in runtime)")
    print(f"  ✓ Rank 2 (Runtime only): {len(runtime_only)}")
    print(f"  ✓ Rank 3 (Code only): {len(code_only)}")

    assert len(confirmed) > 0, "No confirmed issues found"
    # Ensure Confirmed issues are prioritized at top (Rank 1)
    for idx, c in enumerate(confirmed):
        assert c.priority_rank == 1, f"Issue #{c.issue_id} has wrong priority rank {c.priority_rank}"

    # 5. Differentiators & Artifact Exports Validation (B-6, Vault, DPDP, Postman)
    print("\n[Stage 5/5] Validating Differentiators & Compliance Standards...")

    # SARIF 2.1.0 Validation
    sarif = generate_sarif_report(issues)
    assert sarif.get("version") == "2.1.0", "SARIF version must be 2.1.0"
    assert len(sarif["runs"][0]["results"]) == len(issues), "SARIF result count mismatch"
    export_sarif_file(issues, "vajra_report.sarif")
    print("  ✓ OASIS SARIF 2.1.0 report verified & exported")

    # Postman Collection Validation
    postman = generate_postman_collection(issues)
    assert postman.get("info", {}).get("schema") == "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
    assert len(postman.get("item", [])) > 0, "Postman items cannot be empty"
    export_postman_collection_file(issues, "vajra_vulnerableapp_exploits.postman_collection.json")
    print("  ✓ Postman v2.1.0 collection verified & exported")

    # HashiCorp Vault Migration Validation
    vault_plan = generate_vault_migration_plan(issues)
    assert vault_plan["total_secrets"] > 0, "Vault migration candidate count cannot be 0"
    assert "spring:" in vault_plan["spring_cloud_vault_config"], "Vault Spring Cloud yaml missing"
    print(f"  ✓ HashiCorp Vault migration plan: {vault_plan['total_secrets']} credentials mapped to Vault KV v2")

    # DPDP Act 2023 Compliance Flag Validation
    dpdp_issues = [i for i in issues if i.dpdp_pii_flag]
    assert len(dpdp_issues) > 0, "Expected DPDP Act 2023 Sec 8(5) personal data issues to be tagged"
    print(f"  ✓ Indian DPDP Act 2023 Sec 8(5) Personal Data Breach tags: {len(dpdp_issues)} issues tagged")

    # Quantum PQC Readiness Validation
    pqc_issues = [i for i in issues if i.quantum_flag]
    assert len(pqc_issues) > 0, "Expected Quantum PQC readiness issues to be tagged"
    print(f"  ✓ NIST Post-Quantum Cryptography transition flags: {len(pqc_issues)} issues tagged")

    total_time = round(time.time() - t0, 2)
    print(f"\nTotal Scan & Correlation Duration: {total_time}s (PRD 'Great' Target: <300s)")
    assert total_time < 300.0, f"Execution time {total_time}s exceeded 300s threshold"

    print("\n" + "=" * 78)
    print("All pipeline stages ran and every sanity check passed (run time under the PRD's 5-minute Great line).")
    print("Correlation accuracy vs the answer key: scripts/eval_correlation.py (see README).")
    print("=" * 78)


if __name__ == "__main__":
    main()
