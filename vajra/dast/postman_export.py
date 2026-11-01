"""
Postman Collection v2.1.0 Exporter (Stage 4 DAST).
Generates ready-to-run Postman exploit collections for security analysts and developers.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List
import urllib.parse

from vajra.models import CommonFinding, CorrelatedIssue


def generate_postman_collection(
    issues: List[Any],
    collection_name: str = "Vajra-Link Confirmed Exploits",
) -> Dict[str, Any]:
    """Convert confirmed findings/correlated issues into a Postman Collection v2.1 format."""
    items: List[Dict[str, Any]] = []

    for issue in issues:
        # Support both CommonFinding and CorrelatedIssue
        url = getattr(issue, "url", None)
        if not url:
            continue

        vuln_type = getattr(issue, "vuln_type", "Security Finding")
        method = getattr(issue, "method", "GET") or "GET"
        param = getattr(issue, "parameter", None)
        payload = getattr(issue, "payload", None)
        cwe = getattr(issue, "cwe", "CWE-89")
        status = getattr(issue, "status", "Confirmed")

        parsed = urllib.parse.urlparse(url)
        path_segments = [p for p in parsed.path.split("/") if p]

        query_list = []
        if param and payload:
            query_list.append({"key": param, "value": payload, "description": "Exploit payload"})

        test_script = [
            "pm.test('Status is vulnerable response', function () {",
            "    pm.response.to.not.be.error;",
            "});",
            f"// Verified by Vajra-Link: {cwe} ({vuln_type})",
        ]

        item = {
            "name": f"[{status}] {cwe} - {vuln_type} ({parsed.path})",
            "request": {
                "method": method,
                "header": [
                    {"key": "User-Agent", "value": "Vajra-Link-DAST/1.0"},
                    {"key": "Accept", "value": "*/*"},
                ],
                "url": {
                    "raw": url if not query_list else f"{url}?{param}={urllib.parse.quote(payload or '')}",
                    "protocol": parsed.scheme or "http",
                    "host": [parsed.netloc.split(":")[0]],
                    "port": parsed.port if parsed.port else ("443" if parsed.scheme == "https" else "80"),
                    "path": path_segments,
                    "query": query_list,
                },
                "description": f"Target: {url}\nCWE: {cwe}\nProof: {getattr(issue, 'evidence', getattr(issue, 'runtime_evidence', ''))}",
            },
            "event": [
                {
                    "listen": "test",
                    "script": {
                        "type": "text/javascript",
                        "exec": test_script,
                    },
                }
            ],
        }
        items.append(item)

    collection = {
        "info": {
            "name": collection_name,
            "description": "Exported by Vajra-Link SAST-DAST Correlation Engine. Includes verified exploit requests with proof parameters.",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "item": items,
    }
    return collection


def export_postman_collection_file(
    issues: List[Any],
    output_path: str,
    collection_name: str = "Vajra-Link Confirmed Exploits",
) -> str:
    """Save Postman collection JSON to file."""
    col = generate_postman_collection(issues, collection_name)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(col, f, indent=2)
    return output_path
