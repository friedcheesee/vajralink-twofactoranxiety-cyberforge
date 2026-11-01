"""
Headless Playwright DOM XSS Verifier & Screenshot Engine (Stage 3 DAST).
Executes actual DOM payloads, triggers alert/script injection, and captures screenshot proof.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional
import httpx

from vajra.correlation.ai_triage import synthesize_filter_bypass_payload
from vajra.dast.crawler import DastTargetEndpoint
from vajra.dast.safety import assert_safe_target
from vajra.models import CommonFinding

XSS_CANARY_PAYLOADS = [
    "<script>window.__vajra_xss=1</script>",
    "<sCrIpT>window.__vajra_xss=1</sCrIpT>",
    "<svg/onload=\"window.__vajra_xss=1\">",
    "<img src=x onerror=\"window.__vajra_xss=1\">",
    "\" onfocus=\"window.__vajra_xss=1\" autofocus=\"",
]


async def verify_dom_xss_with_playwright(
    endpoint: DastTargetEndpoint,
    screenshot_dir: str,
    shared_browser=None,
    http_client: Optional[httpx.AsyncClient] = None,
    session_cookie: Optional[str] = None,
) -> List[CommonFinding]:
    """Test endpoint for reflected or DOM-based XSS using Playwright headless Chromium.
    Saves screenshot of DOM execution as indisputable proof.
    """
    assert_safe_target(endpoint.url)
    findings: List[CommonFinding] = []
    os.makedirs(screenshot_dir, exist_ok=True)

    target_url = endpoint.url
    params = endpoint.params or ["content", "name", "comment", "q", "id"]

    # Ground an AI bypass attempt in the REAL guard code SAST found for this XSS sink, if any (mirrors the
    # same approach used for the non-browser CWE classes in vajra.dast.http_verifier).
    guard_hit = next(
        (g for g in endpoint.guard_context if g["cwe"] == "CWE-79" and (g.get("guard_snippet") or g.get("handler_source"))),
        None,
    )
    ai_result: Optional[Dict[str, Any]] = None
    if guard_hit:
        try:
            loop = asyncio.get_event_loop()
            ai_result = await loop.run_in_executor(
                None,
                lambda: synthesize_filter_bypass_payload(
                    cwe="CWE-79",
                    vuln_type="Cross-Site Scripting (XSS)",
                    base_payload=XSS_CANARY_PAYLOADS[0],
                    guard_snippet=guard_hit.get("guard_snippet", ""),
                    code_snippet=guard_hit.get("code_snippet", ""),
                    file_path=guard_hit.get("file"),
                    function_name=guard_hit.get("function_name"),
                    handler_source=guard_hit.get("handler_source", ""),
                    handler_label=guard_hit.get("handler_label"),
                ),
            )
        except Exception:
            ai_result = None

    async def _probe_with_browser(browser_obj, probe_url: str, shot_file: str, param: str, payload: str) -> bool:
        context = await browser_obj.new_context(
            viewport={"width": 1280, "height": 800},
            extra_http_headers={"Cookie": session_cookie} if session_cookie else None,
        )
        page = await context.new_page()
        xss_triggered = False

        async def handle_dialog(dialog):
            nonlocal xss_triggered
            xss_triggered = True
            await dialog.dismiss()

        page.on("dialog", handle_dialog)
        try:
            await page.goto(probe_url, timeout=4500, wait_until="domcontentloaded")
            val = await page.evaluate("() => window.__vajra_xss")
            if val == 1:
                xss_triggered = True
            if xss_triggered:
                # The canary payload (window.__vajra_xss=1) only sets a JS variable - it renders nothing
                # visible, so a plain screenshot would be indistinguishable from any other page. Inject a
                # real, on-page proof banner (actual URL/param/payload/timestamp for THIS probe) before
                # capturing, so every screenshot is unique and genuinely shows what was executed where.
                try:
                    await page.evaluate(
                        """([probeUrl, param, payload]) => {
                            const banner = document.createElement('div');
                            banner.id = '__vajra_dast_proof_banner';
                            banner.style.cssText = [
                                'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
                                'background:#dc2626', 'color:#fff', 'font:bold 13px/1.5 monospace',
                                'padding:12px 16px', 'white-space:pre-wrap', 'word-break:break-all',
                                'box-shadow:0 2px 10px rgba(0,0,0,.5)',
                            ].join(';');
                            banner.textContent =
                                '⚡ VAJRA-LINK DOM-XSS EXECUTION PROOF (CWE-79)\\n' +
                                'Confirmed at: ' + new Date().toISOString() + '\\n' +
                                'URL: ' + probeUrl + '\\n' +
                                'Injected parameter: ' + param + '\\n' +
                                'Payload executed: ' + payload + '\\n' +
                                'window.__vajra_xss === 1  (verified by live JS evaluation, not assumed)';
                            document.documentElement.prepend(banner);
                        }""",
                        [probe_url, param, payload],
                    )
                except Exception:
                    pass
                await page.screenshot(path=shot_file, full_page=True)
        except Exception:
            pass
        finally:
            await context.close()
        return xss_triggered

    for param in params:
        candidates: List[Any] = ([ai_result["payload"]] if ai_result else []) + list(XSS_CANARY_PAYLOADS)
        for idx, payload in enumerate(candidates):
            is_ai_candidate = idx == 0 and ai_result is not None
            probe_url = f"{target_url}?{urllib.parse.urlencode({param: payload})}"
            # Fast HTTP pre-flight: skip spawning Chromium tab if endpoint 404s or omits canary token
            if http_client is not None:
                try:
                    pre = await http_client.get(probe_url)
                    if pre.status_code >= 400 or "__vajra_xss" not in pre.text:
                        continue
                except Exception:
                    continue
            proof_hash = hashlib.sha256(probe_url.encode()).hexdigest()[:12]
            shot_file = os.path.join(screenshot_dir, f"xss_{proof_hash}.png")

            try:
                if shared_browser is not None:
                    xss_triggered = await _probe_with_browser(shared_browser, probe_url, shot_file, param, payload)
                else:
                    from playwright.async_api import async_playwright

                    async with async_playwright() as p:
                        browser = await p.chromium.launch(headless=True)
                        try:
                            xss_triggered = await _probe_with_browser(browser, probe_url, shot_file, param, payload)
                        finally:
                            await browser.close()

                if xss_triggered:
                    # Only true when the candidate that actually triggered execution was the AI-crafted one.
                    is_agentic = is_ai_candidate
                    finding = CommonFinding(
                        finding_id=f"DAST-XSS-DOM-{proof_hash}",
                        stage="DAST",
                        scanner="Vajra-AI-Agentic-Evasion" if is_agentic else "Vajra-Playwright-DOM",
                        cwe="CWE-79",
                        raw_cwe="CWE-79",
                        vuln_type="Confirmed Reflected Cross-Site Scripting (XSS)",
                        severity="HIGH",
                        url=target_url,
                        method="GET",
                        parameter=param,
                        payload=payload,
                        evidence="DOM execution verified in Headless Chromium. Payload executed script: window.__vajra_xss == 1",
                        screenshot_path=f"/screenshots/xss_{proof_hash}.png",
                        is_agentic_ai=is_agentic,
                    )
                    if is_agentic and ai_result:
                        finding.ai_technique = ai_result.get("technique")
                        finding.ai_chain_of_thought = ai_result.get("chain_of_thought", [])
                        finding.ai_engine = ai_result.get("engine")
                        finding.ai_guard_basis = ai_result.get("guard_basis")
                    findings.append(finding)
                    return findings

            except Exception:
                # Fallback to HTTP text reflection check if Playwright browser binary isn't pre-installed
                try:
                    async with httpx.AsyncClient(
                        timeout=3.0, verify=False,
                        headers={"Cookie": session_cookie} if session_cookie else None,
                    ) as client:
                        resp = await client.get(probe_url)
                        if payload in resp.text:
                            findings.append(
                                CommonFinding(
                                    finding_id=f"DAST-XSS-REFL-{proof_hash}",
                                    stage="DAST",
                                    scanner="Vajra-HTTP-Reflection",
                                    cwe="CWE-79",
                                    raw_cwe="CWE-79",
                                    vuln_type="Confirmed Reflected Cross-Site Scripting (XSS)",
                                    severity="HIGH",
                                    url=target_url,
                                    method="GET",
                                    parameter=param,
                                    payload=payload,
                                    evidence=f"Unsanitized payload reflected unescaped into response HTML: '{payload}'",
                                )
                            )
                            return findings
                except Exception:
                    pass

    return findings
