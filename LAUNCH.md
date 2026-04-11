# LAUNCH.md — Vektor Pre-Launch Plan

> **North Star:** Before anything goes public, someone watching a 60-second demo
> must say "I need this." Every phase below serves that goal.
>
> **Current branch:** `feat/local-app-targets`
> **Target:** Clean `main` branch, polished demo, then public post.

---

## Phase Overview

| Phase | Name | Goal | Gate to next phase |
|---|---|---|---|
| **1** | Repo Hygiene | Clean, honest, trustworthy repo | `git clone` + `vektor demo` works cold |
| **2** | The Demo | Best possible first impression | 60-sec run produces a WOW output |
| **3** | Test Green | Zero broken tests | `pytest tests/unit/` = 0 failures |
| **4** | Docs & Discovery | People know what it does and how | README tells the story in < 2 min read |
| **5** | Launch | Ship | HN post goes live |

---

## Phase 1 — Repo Hygiene

**Goal:** Anyone who clones the repo right now gets a professional, consistent, working project.

---

### 1.1 — Merge `feat/local-app-targets` into `main`

The entire evolved codebase (27 attacks, HTTP target, analysis mode, diff system, Python API) is on a feature branch. `main` is stale.

```bash
git checkout main
git merge feat/local-app-targets --no-ff \
  -m "feat: HTTP target, analysis mode, 27 attacks, Python scan() API"
git push origin main
```

**Checklist:**
- [ ] `git checkout main && git log --oneline -3` — shows the merge commit
- [ ] `pip install -e . && vektor --version` prints `0.2.0`
- [ ] `vektor list` shows 27 attacks (not 15)
- [ ] `vektor demo` runs without error on `main`

---

### 1.2 — Purge `outputs/` and scratch files from git

The `outputs/` folder has internal scan artifacts (raw JSON/HTML from scanning your local health app). `_write_rag_targets.py` is an untracked scratch script. Neither belongs in a public repo.

```bash
# Add to .gitignore
echo "outputs/" >> .gitignore
echo "_write_rag_targets.py" >> .gitignore

# If any outputs/ files are already tracked:
git rm -r --cached outputs/ 2>/dev/null
git rm --cached _write_rag_targets.py 2>/dev/null

git add .gitignore
git commit -m "chore: ignore outputs/ artifacts and scratch scripts"
```

**Checklist:**
- [ ] `git status` — `outputs/` does not appear at all
- [ ] `git clone <repo> /tmp/vektor-check && ls /tmp/vektor-check/` — no `outputs/` directory
- [ ] `_write_rag_targets.py` not visible in the clone

---

### 1.3 — Fix the CLAUDE.md placeholder leak

`CLAUDE.md` contains literal placeholder instructions like `[e.g. "All API routes live in app/api/"]`. This is your personal dev-tool config. It must not be visible to contributors.

```bash
echo "CLAUDE.md" >> .gitignore
git add .gitignore
git commit -m "chore: gitignore personal CLAUDE.md config"
```

**Checklist:**
- [ ] `git status` — `CLAUDE.md` does not appear
- [ ] In a fresh clone — `CLAUDE.md` does not exist

---

### 1.4 — Create `CONTRIBUTING.md`

The README links to `CONTRIBUTING.md`. It doesn't exist. A 404 on a README link signals an abandoned project.

Create `CONTRIBUTING.md` with minimum viable content:

```markdown
# Contributing to Vektor

## Adding a new attack
1. Create a class extending `BaseAttack` in `vektor/attacks/`
2. Decorate it with `@attack` — auto-registers, no manual dict edits
3. Add an import in `vektor/attacks/registry.py`
4. Write tests in `tests/unit/test_attacks.py`
5. Run `pytest tests/unit/ -v` — must be green before PR

## Running tests
pip install -e ".[dev]"
pytest tests/unit/ -v

## Code style
Match existing patterns. No new dependencies without discussion in an issue first.
```

**Checklist:**
- [ ] `CONTRIBUTING.md` exists at repo root
- [ ] Clicking the link in `README.md` → renders correctly on GitHub
- [ ] File has at least: how to add an attack, how to run tests

---

### Phase 1 Gate

Run this. If all pass, move to Phase 2.

```bash
git checkout main
git clone . /tmp/vektor-gate-check
cd /tmp/vektor-gate-check
python -m venv .venv && source .venv/bin/activate
pip install -e . -q
vektor --version          # must print 0.2.0
vektor list | wc -l       # should show 27+ attacks
vektor demo               # must complete without error
ls outputs/               # must fail (directory should not exist)
cat CONTRIBUTING.md       # must exist and have content
```

**All 5 must pass before Phase 2.**

---

## Phase 2 — The Demo

> **This is the most important phase.** Everything else is preparation for this.
> The demo is the product. If the demo is weak, nothing else matters.

**Goal:** Produce a demo that makes someone say "I need this" within 60 seconds.
The demo has two layers: what they run in the terminal, and what they see in the HTML report.

---

### 2.1 — Polish `vektor demo` (the zero-setup experience)

`vektor demo` is currently functional but the pre-built data only shows 15 attacks and 4 vulnerabilities. With 27 attacks now in the codebase, the demo data feels outdated and small.

**What to update in `vektor/demo.py`:**
- Expand `DEMO_RESULTS["all_results"]` to cover all 6 attack categories (prompt injection, data extraction, instruction hijacking, RAG attacks, agent attacks, structured output)
- Add 2-3 more vulnerabilities to the `"vulnerabilities"` list — include one RAG attack (`rag_context_poisoning`) and one agent attack (`tool_injection`) so people see those categories produce findings
- Update `summary.total_attacks_run` to 27
- Change the risk score to reflect a more alarming-but-realistic result (65/100 = HIGH)
- Update the `"recommendation"` to `"HIGH RISK: 6 vulnerabilities found across 4 attack categories. Address CRITICAL and HIGH before deployment."`
- Update the demo completion panel to mention `vektor scan --target vulnerable` as the next step

**Checklist:**
- [ ] `vektor demo` shows 27 attacks scanned in the progress bar
- [ ] Terminal output includes at least 1 CRITICAL finding
- [ ] At least 4 categories are represented in the finding table
- [ ] Risk score shown is 60+ (HIGH or CRITICAL band — more compelling than 45/MEDIUM)
- [ ] The "next step" panel mentions `--target vulnerable` not just `--target openai`
- [ ] Total runtime of `vektor demo` is under 5 seconds (currently fine, just check it)

---

### 2.2 — Make `--target vulnerable` the demo centerpiece

`VulnerableTarget` is already built and working — it intentionally fails every attack and returns 13+ real vulnerabilities at zero cost. This is your **best demo** and almost nobody will discover it without you highlighting it.

**What to do:**
- Add it as the primary Quick Start command in README (before the API key path)
- Add `--output report.html` to the quick start so first-timers immediately see the HTML report

**The demo sequence to document and record:**
```bash
# Step 1: install
pip install vektor

# Step 2: first run (no API key, simulated)
vektor demo

# Step 3: real scan, zero cost, always works
vektor scan --target vulnerable --output my-first-report.html

# Step 4: open the report
# (Windows) start my-first-report.html
# (Mac)     open my-first-report.html
# (Linux)   xdg-open my-first-report.html
```

**Checklist:**
- [ ] `vektor scan --target vulnerable` completes without error in a fresh venv
- [ ] Output shows 13+ vulnerabilities (if fewer, check `VulnerableTarget.query()` still echoes caps words)
- [ ] Risk score is 60+ (HIGH band)
- [ ] `vektor scan --target vulnerable --output report.html` → HTML file opens in browser
- [ ] HTML report shows: risk badge, vulnerability table with severity colors, remediation column
- [ ] Total scan time is under 10 seconds (no API calls → should be near-instant)

---

### 2.3 — Build the "shocking demo" with an echo server

For a recorded GIF / video demo, `--target vulnerable` is fast but invisible to the audience (they can't see "real network requests"). The echo server pattern makes the scan look like it's hitting a real deployed app.

**The server (save as `demo_server.py` in the repo root, add to `.gitignore`):**
```python
"""
Demo server for Vektor GIF recording.
Intentionally echoes injected content so attacks succeed visually.
Run: pip install fastapi uvicorn && python demo_server.py
"""
from fastapi import FastAPI
import uvicorn

app = FastAPI(title="Vektor Demo Target")

SYSTEM_PROMPT = "You are FitnessCoach AI. SECRET_KEY=sk-demo-abc123."

@app.post("/chat")
async def chat(body: dict):
    msg = body.get("message", body.get("prompt", ""))
    # Vulnerable: echoes prompt, leaks system info, executes injected instructions
    if any(kw in msg.upper() for kw in ["IGNORE", "SYSTEM", "PWNED", "DAN", "REVEAL"]):
        return {"message": f"[SYSTEM] {SYSTEM_PROMPT} | Executing: {msg}"}
    return {"message": f"FitnessCoach: I can help with your fitness goals! Input: {msg}"}

@app.get("/parse")
async def parse(text: str = ""):
    return {"result": f"Parsed event: {text}"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")
```

**Demo sequence for GIF recording:**
```bash
# Terminal 1:
python demo_server.py

# Terminal 2:
vektor scan --url http://127.0.0.1:8000/chat \
  --output demo_report.html
```

**Checklist:**
- [ ] `demo_server.py` runs without error (`pip install fastapi uvicorn`)
- [ ] `vektor scan --url http://127.0.0.1:8000/chat` finds at least 3 vulnerabilities
- [ ] `direct_injection` and `system_prompt_reveal` succeed (server leaks `SECRET_KEY`)
- [ ] Generated HTML report is visually compelling (dark theme, risk badge, colored severity)
- [ ] End-to-end: server up → scan → HTML open takes under 60 seconds total

---

### 2.4 — Record the demo GIF

**Setup (Windows):**
```
Option A: Use PowerShell 7 + Windows Terminal → record with OBS (crop to terminal window)
Option B: WSL2 → install asciinema → asciinema rec demo.cast → convert with agg
Option C: Use terminalizer (npm install -g terminalizer) → terminalizer record demo
```

**Script for recording (keep under 90 seconds):**
```
[pause 1s]
$ vektor --version
  → shows 0.2.0

[pause 0.5s]
$ vektor list
  → scrolls through 27 attacks fast

[pause 0.5s]
$ vektor scan --target vulnerable --output report.html
  → progress bar runs, findings appear

[pause 1s]
  → show the vulnerability table in terminal
  → mention: "report.html has the full breakdown"

[pause 0.5s]
$ vektor scan --url http://127.0.0.1:8000/chat
  → live HTTP scan (server running in background)
  → shows findings, ends with HTML saved
```

**Checklist:**
- [ ] GIF is under 90 seconds when played at 1x speed
- [ ] Terminal font is readable (16px minimum, high contrast)
- [ ] GIF is saved to `docs/demo.gif`
- [ ] GIF is embedded in README: `![Vektor Demo](docs/demo.gif)`
- [ ] File size under 5MB (GitHub README limit for embedded GIFs)

---

### 2.5 — Fix analysis mode false positive inflation

The `localapp_ENHANCED.json` scan found 22 "vulnerabilities" with risk score 100 — but most are `ERR_UPSTREAM_API_DISCLOSURE` triggered by the target returning `429 quota exceeded` for every single request (Gemini rate limit). This makes the tool look like it's crying wolf.

The analysis mode detectors in `engine.py` run on every response and create one finding per triggered response. When the target is rate-limited, this creates 15+ identical findings from one root cause.

**Fix to implement in `vektor/core/engine.py`:**
- Deduplicate analysis findings: if the same `detector_id` fires on more than 3 responses in one scan, cap it at 3 and add a note `"(and N more identical findings — possible rate-limiting)"` to the third finding's description
- Add rate-limit detection: if `"429"` or `"quota exceeded"` appears in >40% of responses, emit one `SCAN_WARNING` entry in the report (not a vulnerability) and lower the risk score contribution from rate-limit-triggered findings

**Checklist:**
- [ ] Scan `--target vulnerable --mode analysis` — analysis findings appear (engine still works)
- [ ] Mock a rate-limited target that returns `"429 quota exceeded"` for every call → scan produces max 3 identical findings, not 15+
- [ ] `localapp_ENHANCED.json`-style scenario (22 identical findings) is no longer possible

---

### Phase 2 Gate

```bash
# Gate test: the demo sequence must work end-to-end in one shot

vektor demo                                          # [1] zero-setup demo
vektor scan --target vulnerable --output report.html # [2] real scan, $0 cost
open report.html                                     # [3] HTML opens, looks good
python demo_server.py &                              # [4] start demo server
vektor scan --url http://127.0.0.1:8000/chat         # [5] HTTP scan finds vulnerabilities
```

**All 5 must work before Phase 3. The GIF must be recorded before Phase 4.**

---

## Phase 3 — Test Green

**Goal:** The test suite is fully green. No regressions. Confidence that the codebase is solid before going public.

---

### 3.1 — Run the full unit test suite

```bash
pip install -e ".[dev]"
pytest tests/unit/ -v --tb=short 2>&1 | tee test_results.txt
grep -E "PASSED|FAILED|ERROR" test_results.txt | tail -20
```

**Checklist:**
- [ ] 0 FAILED tests
- [ ] 0 ERROR tests
- [ ] `test_http_target.py` — all tests pass (recently modified, most likely to have drifted)
- [ ] `test_rag_targets.py` — all 28 tests pass
- [ ] `test_diff.py` — status keys (`new_vuln`, `fixed`, `regression`) match current diff output
- [ ] `test_scoring.py` — risk score formula matches engine implementation
- [ ] `test_attacks.py` — attack names in tests match current `ATTACK_REGISTRY` keys

---

### 3.2 — Add one smoke test for the vulnerable target

There is no automated test that proves `vektor scan --target vulnerable` produces findings. This is the most important user-facing flow and it's untested.

Add to `tests/unit/test_scoring.py` or a new `tests/unit/test_smoke.py`:

```python
def test_vulnerable_target_produces_findings():
    from vektor.targets.vulnerable import VulnerableTarget
    from vektor.core.engine import VektorScanner

    target = VulnerableTarget()
    scanner = VektorScanner(target, budget_limit=1.0)
    results = scanner.scan(quick_mode=True)  # quick mode: 5-8 attacks

    assert results["summary"]["total_vulnerabilities"] >= 5, \
        "VulnerableTarget should fail at least 5 quick-mode attacks"
    assert results["summary"]["risk_score"] >= 30, \
        "VulnerableTarget should produce at least MEDIUM risk score"
```

**Checklist:**
- [ ] Test written and committed
- [ ] `pytest tests/unit/test_smoke.py -v` passes
- [ ] If it fails: fix `VulnerableTarget` or `VektorScanner` until it passes

---

### 3.3 — Add one smoke test for the HTTP target with a mock server

The HTTP endpoint scanner is a major new feature with no integration smoke test.

```python
# In tests/unit/test_http_target.py — add at the end:
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class EchoHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length))
        msg = body.get("message", "")
        resp = json.dumps({"message": f"Echo: {msg} PWNED"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(resp)
    def log_message(self, *args): pass  # suppress test noise

def test_http_target_scan_finds_vulnerabilities():
    server = HTTPServer(("127.0.0.1", 18765), EchoHandler)
    t = threading.Thread(target=server.serve_forever)
    t.daemon = True
    t.start()

    from vektor.targets.http_endpoint import HTTPEndpointTarget
    from vektor.core.engine import VektorScanner

    target = HTTPEndpointTarget(url="http://127.0.0.1:18765/chat")
    scanner = VektorScanner(target, budget_limit=1.0)
    results = scanner.scan(attacks=["direct_injection"])

    assert results["summary"]["total_attacks_run"] == 1
    server.shutdown()
```

**Checklist:**
- [ ] Test passes (`pytest tests/unit/test_http_target.py -v`)
- [ ] Test does not leave a dangling server thread (daemon=True handles this)
- [ ] Port 18765 is not used by any other test

---

### Phase 3 Gate

```bash
pytest tests/unit/ -v --tb=short
echo "Exit code: $?"   # must be 0
```

**Exit code 0 = move to Phase 4. Any other code = fix before proceeding.**

---

## Phase 4 — Docs & Discovery

**Goal:** A developer who has never heard of Vektor can understand what it does, why they need it, and how to start — in under 2 minutes of reading.

---

### 4.1 — Update README to reflect current reality

The README has 4 specific lies that will erode trust the moment someone tries the code:

| Location in README | Current (wrong) | Fix to |
|---|---|---|
| Hero badge | "15 validated attack vectors" | "27 validated attack vectors across 6 categories" |
| v0.3 roadmap | `--url` listed as "coming soon" | Move to v0.2 "current" section |
| v0.3 roadmap | RAG targets listed as "coming soon" | Move to v0.2 "current" section |
| Quick Start | Goes straight to `--target openai` (requires API key) | Lead with `--target vulnerable` (zero cost) |

**Also add a new section "Scan Any AI API — No SDK Needed" right after Quick Start:**
```markdown
## Scan Any AI API — No SDK Needed

Point Vektor at any HTTP endpoint:
\```bash
# Auto-detects OpenAI/Anthropic/custom shapes
vektor scan --url http://localhost:8000/chat

# With auth header
vektor scan --url https://my-app.com/api \
  --header "Authorization: Bearer YOUR_TOKEN"

# Custom request/response field names
vektor scan --url http://localhost:8000/predict \
  --request-field prompt --response-field answer

# Query-parameter mode (e.g. /api/parse?text=PAYLOAD)
vektor scan --url http://localhost:8000/api/parse \
  --param-field text

# Rate-limited API — add delay between requests
vektor scan --url http://localhost:8000/chat \
  --request-delay 12.0
\```
```

**Checklist:**
- [ ] `grep "15 validated" README.md` returns nothing
- [ ] `grep "coming soon" README.md` returns nothing for `--url` and RAG targets
- [ ] Quick Start section leads with `vektor scan --target vulnerable`
- [ ] "Scan Any AI API" section exists with 5 example commands
- [ ] Demo GIF is embedded at the top, below the headline
- [ ] Comparison table still accurate (check each cell)

---

### 4.2 — Fix the GitHub Actions CI example

The current GitHub Actions snippet in README uses `docker run vektor` without specifying an image registry or build step. It will fail for any first-timer who copies it.

**Replace with a pip-based example that actually works:**
```yaml
name: LLM Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install Vektor
        run: pip install vektor
      - name: Scan (vulnerable target — no API key needed)
        run: vektor scan --target vulnerable --ci --output report.json
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: report.json
```

**Checklist:**
- [ ] README GitHub Actions example uses `pip install vektor`, not bare `docker run vektor`
- [ ] The example uses `--target vulnerable` so it works without secrets
- [ ] A commented-out version with `--target openai` and `secrets.OPENAI_API_KEY` is provided below it

---

### 4.3 — Add `docs/DEMO.md` — the demo companion doc

This is the doc you link people to after they watch the GIF. It walks through exactly what happened in the demo and how to reproduce it.

**Contents:**
```markdown
# Vektor Demo — Step by Step

## What you saw in the GIF
1. `vektor list` — 27 attacks across 6 categories
2. `vektor scan --target vulnerable` — a deliberately insecure target (built-in)
3. HTML report opened — risk score, finding table, remediation steps

## Reproduce it yourself (60 seconds, no API key)
pip install vektor
vektor scan --target vulnerable --output report.html
open report.html  # or: start report.html (Windows)

## What "vulnerable target" means
VulnerableTarget is a built-in simulation of a poorly secured LLM app.
It has zero safety controls — it echoes injected instructions, leaks its
system prompt, and never refuses. It's designed to prove the scanner works.

## Scanning a real HTTP endpoint
[... echo server example ...]

## Scanning with Groq (free, no credit card)
[... groq example ...]
```

**Checklist:**
- [ ] `docs/DEMO.md` exists
- [ ] Reproducing the demo requires only `pip install vektor` + 2 commands
- [ ] File is linked from README under "Documentation"

---

### Phase 4 Gate

Do this cold — open a private browser tab, go to your GitHub repo, and time yourself:

- [ ] Understand what Vektor does in < 30 seconds (headline + GIF)
- [ ] Find the zero-cost Quick Start in < 60 seconds
- [ ] Copy-paste the Quick Start and run it — works first try
- [ ] Find the GitHub Actions example — it works without secrets
- [ ] `docs/DEMO.md` link exists and opens

**All 5 must pass. If any fail, fix the README before Phase 5.**

---

## Phase 5 — Launch

**Goal:** First public appearance. One shot. Make it count.

---

### 5.1 — Pre-flight (day before launch)

```bash
# Fresh environment, nothing cached
python -m venv /tmp/vektor-preflight
source /tmp/vektor-preflight/bin/activate
pip install git+https://github.com/YOUR_HANDLE/vektor.git
vektor --version
vektor demo
vektor scan --target vulnerable --output preflight.html
pytest tests/unit/ -v   # if running tests locally
```

**Checklist:**
- [ ] Install from GitHub works (not just from local editable install)
- [ ] `vektor demo` works
- [ ] `vektor scan --target vulnerable` works
- [ ] HTML report opens and looks good
- [ ] README GIF loads on GitHub
- [ ] No broken links in README (check with `markdown-link-check README.md`)
- [ ] PyPI name checked (`pip index versions vektor` — if taken, decide on `vektor-ai` now)

---

### 5.2 — Write the HN post

**Title (pick one, A/B test mentally):**
- `Show HN: Vektor — automated security scanner for LLM apps (27 attack vectors, $0 to try)`
- `Show HN: I built pytest for LLM security — scans for prompt injection, RAG hijacking, agent attacks`

**Body (keep under 300 words):**
```
I built Vektor because I wanted a tool that does for LLM apps what
Snyk does for dependencies — automated, fast, actionable.

What it does:
- Runs 27 adversarial attack patterns against any LLM endpoint
- Covers prompt injection, data extraction, RAG context poisoning,
  agent tool manipulation, and document-based instruction hijacking
- Generates risk scores + remediation steps in JSON/HTML
- Works on any HTTP API: vektor scan --url https://myapp.com/chat

The novel part: document-based instruction hijacking. DOCX files can
contain hidden text runs that LLMs process but PDF viewers don't show.
60% of RAG systems I tested were vulnerable. Standard sanitization
doesn't catch this because it strips formatting, not hidden content.

Zero-cost demo (no API key):
  pip install vektor
  vektor scan --target vulnerable

Or scan your own endpoint in 30 seconds:
  vektor scan --url http://localhost:8000/chat

GitHub: [link]
```

**Checklist:**
- [ ] HN post draft written and spell-checked
- [ ] GitHub link goes to `main` branch, not feature branch
- [ ] Demo GIF visible on the GitHub page (test on mobile too)
- [ ] Post time: Tuesday–Thursday, 7–9am US Pacific (best HN engagement window)

---

### 5.3 — Cross-post after HN traction

Wait 2 hours after HN post. If it's getting upvotes:

- [ ] Post to `r/netsec` — "I built a security scanner for LLM apps"
- [ ] Post to `r/LangChain` — focus on the RAG hijacking research
- [ ] Tweet/X thread — lead with the demo GIF, then 3 bullet points
- [ ] dev.to article — longer form, include the DOCX hidden text research angle
- [ ] Share in any LangChain / LlamaIndex / AI builders Discord you're in

---

### Phase 5 Gate (Launch Day Checklist)

```
[ ] git checkout main — confirm you're on main
[ ] pip install git+<your-repo-url> — cold install works
[ ] vektor demo — no errors
[ ] vektor scan --target vulnerable — 13+ vulns, risk score 60+
[ ] vektor list — 27 attacks shown
[ ] HTML report opens in browser, looks professional
[ ] pytest tests/unit/ — 0 failures
[ ] README renders correctly on GitHub (check mobile)
[ ] GIF loads in README
[ ] CONTRIBUTING.md exists
[ ] No outputs/ directory in repo
[ ] HN post draft ready to paste
[ ] Post
```

**The single go/no-go test:** Run `vektor scan --target vulnerable --output demo.html` in a fresh venv.
If it finishes in < 30 seconds with 13+ findings and the HTML report is visually impressive → you're ready.
If anything fails → fix it first.

---

## Demo Progression Reference

Use this as your mental model for which demo to use in which context:

| Context | Demo to use | Why |
|---|---|---|
| README GIF | `vektor scan --url http://127.0.0.1:8000/chat` | Shows real HTTP scan — looks like prod |
| HN post | `vektor scan --target vulnerable` | Zero-friction, anyone can reproduce |
| Live presentation | Echo server + `--url` scan | Visual, shows real network requests |
| Blog / written post | `vektor scan --target vulnerable` + HTML screenshot | Shareable artifact |
| Investor / stakeholder | Full 4-surface campaign (like `scan_local_app.py`) | Shows depth and real-world applicability |
| CI/CD pitch | `vektor scan --target vulnerable --ci --output report.json && echo $?` | Shows exit codes, automation |
| AI developer community | `from vektor import scan; scan(url="http://localhost:8000/chat")` | Python API — feels like pytest |

---

## Estimated Timeline

| Phase | Work | Est. Days |
|---|---|---|
| Phase 1 — Hygiene | 5 small fixes, mostly git commands | 0.5 days |
| Phase 2 — Demo | Polish demo data, echo server, GIF recording | 2–3 days |
| Phase 3 — Tests | Fix test suite, add 2 smoke tests | 1 day |
| Phase 4 — Docs | README updates, DEMO.md | 1 day |
| Phase 5 — Launch | Post writing, preflight, ship | 0.5 days |
| **Total** | | **~5–6 days of focused work** |

**The demo (Phase 2) takes the most time because it's the most important.**
Don't rush it. A bad demo on launch day is worse than launching a week later with a great one.
