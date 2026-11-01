"""
OASIS SARIF 2.1.0 Exporter & CI Quality Gate (Bonus B-6).
Exports correlated vulnerabilities with custom property bags (DPDP, PQC, Status, Risk Score).
"""
from __future__ import annotations

import json
from typing import Any, Dict, List
from vajra.models import CorrelatedIssue, MITRE_METADATA_MAP


def generate_sarif_report(
    issues: List[CorrelatedIssue],
    tool_version: str = "1.0.0",
) -> Dict[str, Any]:
    """Generate official SARIF 2.1.0 JSON document from correlated issues."""
    rules_dict: Dict[str, Dict[str, Any]] = {}
    results_list: List[Dict[str, Any]] = []

    for issue in issues:
        rule_id = issue.cwe
        meta = MITRE_METADATA_MAP.get(rule_id, {
            "cwe_name": issue.vuln_type,
            "owasp_2025": "A01:2025-Vulnerability",
            "capec_id": "CAPEC-General",
            "attck_id": "T1190",
            "attck_name": "Exploitation",
            "d3fend_id": "D3-DEF",
            "fix_summary": "Sanitize and validate input.",
        })

        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": meta["cwe_name"],
                "shortDescription": {"text": f"{rule_id}: {meta['cwe_name']}"},
                "fullDescription": {"text": f"{meta['cwe_name']} - OWASP Top 10: {meta['owasp_2025']}"},
                "help": {
                    "text": f"Remediation: {meta['fix_summary']}\nMITRE ATT&CK: {meta['attck_id']} ({meta['attck_name']})\nCAPEC: {meta['capec_id']}"
                },
                "properties": {
                    "tags": ["security", rule_id, meta["owasp_2025"], meta["attck_id"]],
                    "precision": "high",
                },
            }

        # Map severity to SARIF level
        sev = (issue.severity or "HIGH").upper()
        if sev in ("CRITICAL", "HIGH"):
            level = "error"
        elif sev == "MEDIUM":
            level = "warning"
        else:
            level = "note"

        # Build location
        locations = []
        if issue.file_path and issue.line:
            locations.append({
                "physicalLocation": {
                    "artifactLocation": {"uri": issue.file_path, "uriBaseId": "%SRCROOT%"},
                    "region": {
                        "startLine": issue.line,
                        "endLine": issue.end_line or issue.line,
                    },
                },
                "message": {"text": f"Code sink in function {issue.function_name or 'handler'}"},
            })

        result_item = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": f"[{issue.status}] {issue.vuln_type}: "
                        f"{issue.runtime_evidence or issue.link_explanation or 'Correlated vulnerability'}"
            },
            "locations": locations,
            "properties": {
                "fingerprint": issue.fingerprint,
                "status": issue.status,
                "priorityRank": issue.priority_rank,
                "riskScore": issue.risk_score,
                "correlationConfidence": issue.correlation_confidence,
                "linkExplanation": issue.link_explanation,
                "url": issue.url,
                "method": issue.method,
                "parameter": issue.parameter,
                "payload": issue.payload,
                "dpdpActCompliance": "Breach: DPDP Act 2023 Sec 8(5) personal data safeguard violated" if issue.dpdp_pii_flag else "Compliant",
                "quantumReadiness": "Action required: Quantum-vulnerable cipher/key (NIST PQC migration)" if issue.quantum_flag else "Standard",
                "vaultCandidate": issue.vault_candidate,
                "screenshot": issue.screenshot_path,
            },
        }
        results_list.append(result_item)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Vajra-Link SAST-DAST Correlation Engine",
                        "version": tool_version,
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results_list,
            }
        ],
    }
    return sarif


def export_sarif_file(issues: List[CorrelatedIssue], output_path: str) -> str:
    """Save SARIF 2.1.0 report to disk."""
    report = generate_sarif_report(issues)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return output_path


def evaluate_ci_quality_gate(issues: List[CorrelatedIssue], fail_on_confirmed_high: bool = True) -> Dict[str, Any]:
    """Check CI quality gate. Fails if any Confirmed High/Critical vulnerabilities exist."""
    confirmed_critical = [i for i in issues if i.status == "Confirmed" and (i.severity or "").upper() == "CRITICAL"]
    confirmed_high = [i for i in issues if i.status == "Confirmed" and (i.severity or "").upper() == "HIGH"]
    runtime_critical = [i for i in issues if i.status == "Runtime only" and i.severity in ("CRITICAL", "HIGH")]

    should_fail = False
    reasons = []

    if fail_on_confirmed_high:
        if confirmed_critical:
            should_fail = True
            reasons.append(f"{len(confirmed_critical)} Confirmed CRITICAL vulnerabilities found!")
        if confirmed_high:
            should_fail = True
            reasons.append(f"{len(confirmed_high)} Confirmed HIGH vulnerabilities found!")

    return {
        "passed": not should_fail,
        "confirmed_critical_count": len(confirmed_critical),
        "confirmed_high_count": len(confirmed_high),
        "runtime_critical_count": len(runtime_critical),
        "reasons": reasons,
    }
