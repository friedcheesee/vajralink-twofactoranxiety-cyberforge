"""Run static analysis + live DAST once and cache both to JSON, so correlation can be iterated on quickly.

Usage:  .venv-win\\Scripts\\python.exe scripts\\dump_pipeline.py [source_path] [target_url] [out.json] [--auto-verify]

--auto-verify (opt-in, B-1): after DAST, correlate, then probe Code-only findings' reachable routes and store
the extra findings under "auto_verify_dast" (+ "auto_verify_stats") in the dump. Default output unchanged.
"""
from __future__ import annotations

import asyncio
import json
import sys
import os
import time

sys.path.insert(0, ".")
from vajra.api import _detect_context_path, _ensure_static  # noqa: E402
from vajra.config import resolve_source_path  # noqa: E402
from vajra.dast.runner import PROBEABLE_CWES, run_dast_scan_detailed  # noqa: E402


async def main() -> None:
    AV = "--auto-verify" in sys.argv
    sys.argv = [a for a in sys.argv if a != "--auto-verify"]
    src = resolve_source_path(sys.argv[1] if len(sys.argv) > 1 else "targets/VulnerableApp")
    target = (sys.argv[2] if len(sys.argv) > 2 else "http://localhost:9090").rstrip("/")
    out = sys.argv[3] if len(sys.argv) > 3 else "pipeline_dump.json"
    t0 = time.time()
    c = _ensure_static(src)
    plan = c["graph"].targeted_route_plan(c["routes"], PROBEABLE_CWES)
    print(f"static done {time.time()-t0:.1f}s: {len(c['routes'])} routes, {len(c['sast'].active)} sast active")
    dast, stats = await run_dast_scan_detailed(
        target, c["routes"], "screenshots", plan=plan["routes"], sast_guided=True, independent=True,
        decoy_audit=True, context_path=_detect_context_path(src),
    )
    print(f"dast done {time.time()-t0:.1f}s: {len(dast)} findings, online={stats.get('target_online')}")
    dump = {"source": src, "target": target, "dast": [d.model_dump() for d in dast]}
    if AV:
        from vajra.correlation.auto_verify import auto_verify_code_only
        from vajra.correlation.engine import correlate_findings
        issues = correlate_findings(c["sast"].active, dast, routes=c["routes"], fgraph=c["graph"],
                                    db_path=os.environ.get("VAJRA_EVAL_DB", "vajra_state.db"),
                                    suppressed=c["sast"].suppressed, source_root=src)
        extra, av = await auto_verify_code_only(issues, dast, c["routes"], c["graph"], target,
                                                context_path=_detect_context_path(src))
        print(f"auto-verify: {av}")
        dump["auto_verify_dast"] = [d.model_dump() for d in extra]
        dump["auto_verify_stats"] = av
    json.dump(dump, open(out, "w"), indent=1)


asyncio.run(main())
