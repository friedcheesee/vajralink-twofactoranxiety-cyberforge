# VajraLink (वज्र-लिंक)
**SAST + DAST correlation · CyberForge Hackathon (Mitigata), Problem 06**

▶ **Demo video:** <https://www.youtube.com/watch?v=s9BGGIcUiKo>

## What it does

Static analysis finds hundreds of code warnings, and many are noise. Dynamic testing proves a few bugs are
exploitable, but can't say which line of code caused them. VajraLink runs both on the same app and links them
into **one prioritised list**:

| Label | Meaning |
|---|---|
| **Confirmed** | Attack proven at runtime **and** linked to the exact line of code |
| **Runtime only** | Proven at runtime, no code location (e.g. a missing security header) |
| **Code only** | Found in code, not proven reachable |

Confirmed issues come first, then by risk. Every link comes with a plain-English reason and a fix suggestion.
A wrong link is treated as worse than a missed one.

## How it works

1. **SAST with five engines:** Java taint, sink signatures, secrets, Semgrep, Bandit. Findings are merged by
   sink and each records which engines agreed. A decoy filter drops provably safe code (parameterised queries,
   escaping, allow-lists).
2. **DAST** against the live app: HTTP probes, with a headless browser to prove that XSS really executes.
3. **Route map plus call graph** (Spring, Servlet, JAX-RS, Flask, FastAPI, Django) answers *which code serves
   this URL, and does it reach the sink?*
4. **Score five evidence vectors:** call path, CWE match, parameter, evidence fits the sink, filter parity.
   - A strong score with a proven path is **Confirmed** with no AI.
   - A grey-zone score goes to an LLM arbiter, which sees the real code and evidence.
5. **Merge duplicates:** one issue per sink, so five URLs that reach one method become one issue.


**Also built in:**
- An OpenAI Decisions API second opinion on suppressed decoys. It returns a probability with zero output tokens.
- A HashiCorp Vault migration plan for any hard-coded secret found.
- SHA-256 fingerprints, so issues are tracked across scans.
- A post-quantum crypto audit.

## Run it (Docker)

```bash
git clone --recurse-submodules <this-repo-url> vajra-link
cd vajra-link
docker compose up --build
```

This starts VajraLink and the **bundled test app, VulnerableApp** (official image, unmodified).
`--recurse-submodules` fetches its source for SAST. If you cloned without it, run `git submodule update --init`.

**Use the bundled app:**
- **Dashboard:** open <http://localhost:8000>, click **use bundled VulnerableApp demo**, then run steps 1 → 4.
- **API:**
  ```bash
  curl -X POST localhost:8000/scans -H "Content-Type: application/json" \
       -d '{"source": "targets/VulnerableApp", "target": "http://vulnerableapp:9090"}'
  curl localhost:8000/issues
  ```

**Scan your own app:**
1. Put its source in `./targets/<name>`.
2. Run the app on your machine.
3. Give its normal address, e.g. `http://localhost:8080`. Inside Docker, VajraLink rewrites `localhost` to your
   machine automatically.

No API keys are needed. To turn on the optional AI calls and the Vault push, copy `.env.example` to `.env`.
Without keys, those steps use deterministic rules and say so. Only localhost and private-network targets are
accepted.

<details><summary>Without Docker, CLI, SARIF / CI</summary>

```bash
pip install -r requirements.txt && python -m playwright install chromium
python -m uvicorn vajra.api:app --port 8000
python -m vajra.cli scan --source targets/VulnerableApp --target http://localhost:9090 \
       --json-out report.json --fail-on-confirmed-high      # exits 1 on Confirmed HIGH (CI gate)
curl localhost:8000/scans/1/compare/2                       # new / fixed / still open
python -m pytest tests -q
```
</details>

## Results

Every number below was printed by a script in this repo on a live run.

| PRD metric | Good / Great | VulnerableApp | Java bookshop | Python shop |
|---|---|---|---|---|
| Correct links | >50% / >80% | 44.7% (17/38) | 100% (6/6) | 100% (6/6) |
| Wrong links | <20% / <5% | **0%** | **0%** | **0%** |
| False alarms | <30% / <10% | **0%** | **0%** | **0%** |
| Code detection | >60% / >85% | 33.3% (32/96) | 100% | 100% |
| Run time | <15 / <5 min | 4–4.5 min | 24 s | 19–62 s |

- **Not tuned to VulnerableApp.** We removed an engine keyed to its file names, so code detection fell from
  100% to 33%.
- **The linker isn't what limits correct links.** All 17 pairs DAST proves are linked correctly. The rest need
  runtime proof for XXE, SSRF and LDAP.
- **The two shops are our own test apps**, in `scripts/unseen_java` and `scripts/unseen_app`. They test
  generalisation, but they aren't blind.
- **Reproduce** with `scripts/eval_correlation.py`, `scripts/unseen_java/eval_unseen_java.py` and
  `scripts/unseen_app/eval_unseen.py`.

**Bonuses:**

| Bonus | What it does |
|---|---|
| B-1 | Auto-verify Code-only findings |
| B-2 | Decoy noise filter |
| B-3 | Explains every link |
| B-4 | Fix suggestions |
| B-5 | Scan compare |
| B-6 | SARIF + CI gate |
| B-7 | Java and Python |

## Tools used

The correlation engine, route maps, call graph, Java/Python taint engines, sink signatures, secrets scanner and
DAST verifier are **our own code**.

| Third-party | Licence | Use |
|---|---|---|
| Semgrep OSS | LGPL-2.1 | Pattern matching with our own fixed Java rule pack |
| Bandit | Apache-2.0 | Python security linter |
| Playwright + Chromium | Apache-2.0 / BSD-3 | Proves XSS executes; screenshots |
| katana | MIT | Optional crawler (auto-detected) |
| OpenAI API: Chat Completions `gpt-4o-mini` | Proprietary | Grey-zone arbiter, filter-bypass payloads (optional) |
| OpenAI API: Decisions API `gpt-6-luna` | Proprietary | Decoy second opinion (optional) |
| HashiCorp Vault + hvac | BSL 1.1 / Apache-2.0 | Optional secret push |
| FastAPI, Uvicorn, HTTPX, Pydantic, openai SDK, cryptography, Jinja2, python-dotenv, python-multipart, Rich | MIT / BSD / Apache-2.0 | Server, HTTP client, models, CLI |
| Python, SQLite, Docker | PSF / Public domain / Apache-2.0 | Runtime, storage, packaging |
| SasanLabs VulnerableApp | Apache-2.0 | Bundled test target (not part of VajraLink) |
