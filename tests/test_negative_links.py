"""Regression tests for wrong / unjustified links in vajra.correlation.engine.correlate_findings.

Synthetic CommonFinding + RouteEntry objects, no fgraph, no network, no LLM (every positive case is a proven
code path, so the grey-zone arbiter is never called). "A wrong link is worse than a missed one."

    .venv-win/Scripts/python.exe -m pytest tests/test_negative_links.py -q
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vajra.correlation.engine import correlate_findings  # noqa: E402
from vajra.models import CommonFinding, RouteEntry  # noqa: E402

SINK_SNIPPETS = {
    "CWE-89": 'ResultSet rs = st.executeQuery("SELECT * FROM t WHERE a = \'" + term + "\'");',
    "CWE-79": 'return "<p>" + comment + "</p>";',
    "CWE-78": 'Runtime.getRuntime().exec("ping " + host);',
}
EVIDENCE = {
    "CWE-89": "SQL syntax error near ''' in query (database error text leaked)",
    "CWE-79": "DOM execution verified in Headless Chromium. Payload executed",
    "CWE-78": "command output canary uid=0(root) echoed in response",
}


def route(url, handler, start, end, file="src/A.java", params=("q",), helpers=(), method="GET", secure=False):
    return RouteEntry(http_method=method, url_pattern=url, handler_name=handler, class_name=file.split("/")[-1][:-5],
                      file_path=file, start_line=start, end_line=end, params=list(params),
                      called_helpers=list(helpers), is_secure_variant=secure)


def sast(cwe, line, fn, file="src/A.java", decoy=False, fid=None):
    return CommonFinding(finding_id=fid or f"S-{cwe}-{file}-{line}", stage="SAST", scanner="test", cwe=cwe, raw_cwe=cwe,
                         vuln_type=cwe, file_path=file, line=line, end_line=line, function_name=fn,
                         code_snippet=SINK_SNIPPETS.get(cwe, "sink();"), is_safe_decoy=decoy,
                         suppression_reason="PreparedStatement binding" if decoy else None)


def dast(cwe, url, param="q", evidence=None, fid=None, method="GET"):
    return CommonFinding(finding_id=fid or f"D-{cwe}-{url}", stage="DAST", scanner="test", cwe=cwe, raw_cwe=cwe,
                         vuln_type=cwe, url="http://127.0.0.1:9400" + url, method=method, parameter=param,
                         payload="x", evidence=evidence or EVIDENCE.get(cwe, "proof"))


def run(sasts, dasts, routes, suppressed=None, tmp_path=None):
    report: dict = {}
    issues = correlate_findings(sasts, dasts, routes=routes, fgraph=None, db_path=str(tmp_path / "t.db"),
                                suppressed=suppressed, report=report)
    return issues, report


def test_a_cwe_mismatch_is_not_linked(tmp_path):
    """SQLi proof on a URL whose handler only contains an XSS sink must not become a Confirmed link."""
    r = [route("/x", "h", 10, 20)]
    issues, _ = run([sast("CWE-79", 15, "h")], [dast("CWE-89", "/x")], r, tmp_path=tmp_path)
    assert not [i for i in issues if i.status == "Confirmed"]
    assert any(i.status == "Runtime only" and i.cwe == "CWE-89" for i in issues)
    assert any(i.status == "Code only" and i.cwe == "CWE-79" for i in issues)


def test_b_unrouted_url_is_runtime_only(tmp_path):
    """A DAST finding whose URL no route serves cannot be linked to code (the SAST sink here is another handler's)."""
    r = [route("/known", "h", 10, 20)]
    issues, _ = run([sast("CWE-89", 15, "h")], [dast("CWE-89", "/mystery/endpoint")], r, tmp_path=tmp_path)
    assert not [i for i in issues if i.status == "Confirmed"], [(i.status, i.url) for i in issues]
    assert any(i.status == "Runtime only" for i in issues)


def test_c_decoy_with_inference_only_evidence_is_not_an_issue(tmp_path):
    """The handler's only sink was judged safe (PreparedStatement). A boolean-differential hit must not
    resurrect it as a vulnerability."""
    r = [route("/safe", "h", 10, 20)]
    decoy = sast("CWE-89", 15, "h", decoy=True)
    d = dast("CWE-89", "/safe", evidence="boolean differential: response length differs between true/false probes")
    issues, rep = run([], [d], r, suppressed=[decoy], tmp_path=tmp_path)
    assert [i for i in issues if i.status != "Code only" and i.cwe == "CWE-89"] == [], [(i.status, i.url) for i in issues]
    assert rep["contested"], "expected the conflict to be reported as contested, not silently dropped"


def test_d_two_urls_one_shared_sink_is_one_issue(tmp_path):
    """/a and /b both call the same service method: one bug, one Confirmed issue listing both endpoints."""
    svc = "src/Svc.java"
    edge = f"hop=1|kind=DI|{svc}:5-12|C.h()[L11] -[@Service:svc]-> Svc.load()[L5]"
    r = [route("/a", "ha", 10, 14, file="src/C1.java", helpers=[edge]),
         route("/b", "hb", 10, 14, file="src/C2.java", helpers=[edge])]
    s = sast("CWE-89", 8, "load", file=svc)
    issues, _ = run([s], [dast("CWE-89", "/a"), dast("CWE-89", "/b")], r, tmp_path=tmp_path)
    conf = [i for i in issues if i.status == "Confirmed"]
    assert len(conf) == 1, [(i.url, i.file_path, i.line) for i in conf]
    assert set(conf[0].vector_breakdown["verified_endpoints"]) == {"/a", "/b"}


def test_e_two_handlers_two_sinks_in_one_file_are_two_issues(tmp_path):
    """Same file, same CWE, different handlers/sinks: must not be merged into one issue."""
    r = [route("/one", "one", 10, 20, params=("p",)), route("/two", "two", 30, 40, params=("p",))]
    ss = [sast("CWE-89", 15, "one"), sast("CWE-89", 35, "two")]
    issues, _ = run(ss, [dast("CWE-89", "/one", "p"), dast("CWE-89", "/two", "p")], r, tmp_path=tmp_path)
    conf = [i for i in issues if i.status == "Confirmed"]
    assert len(conf) == 2
    assert {(i.line, (i.vector_breakdown or {}).get("verified_endpoints", [None])[0]) for i in conf} == \
        {(15, "/one"), (35, "/two")}


def test_e2_cross_wiring_never_happens(tmp_path):
    """DAST on /two must never link to the sink in /one's handler (even though both are CWE-89 in one file)."""
    r = [route("/one", "one", 10, 20, params=("p",)), route("/two", "two", 30, 40, params=("p",))]
    issues, _ = run([sast("CWE-89", 15, "one")], [dast("CWE-89", "/two", "p")], r, tmp_path=tmp_path)
    assert not [i for i in issues if i.status == "Confirmed"]


def test_f_correct_case_links_confirmed(tmp_path):
    r = [route("/x", "h", 10, 20)]
    issues, _ = run([sast("CWE-89", 15, "h")], [dast("CWE-89", "/x")], r, tmp_path=tmp_path)
    conf = [i for i in issues if i.status == "Confirmed"]
    assert len(conf) == 1 and conf[0].line == 15 and conf[0].file_path == "src/A.java"
    assert issues[0].status == "Confirmed"  # prioritised first
