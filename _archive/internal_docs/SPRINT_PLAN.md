# LLMGuard-Lite: 24-Hour Sprint Plan

**Start:** Now (H+0)
**Launch:** H+24
**Team:** Claude Code (40%) | GitHub Copilot (40%) | Human (20%)

**Single source of truth for all three:** `PROJECT_BIBLE.md`
Read it before writing a single line.

---

## WORK SPLIT OVERVIEW

```
┌─────────────────────────────────────────────────────────────┐
│                    THE SPLIT                                │
├──────────────────────┬──────────────────────────────────────┤
│   CLAUDE CODE        │   GITHUB COPILOT                    │
│   Core Logic Layer   │   Interface + Infrastructure Layer  │
│                      │                                      │
│  ┌─────────────────┐ │  ┌─────────────────────────────────┐ │
│  │ attacks/        │ │  │ cli.py                          │ │
│  │ targets/        │ │  │ scoring/reporter.py             │ │
│  │ scoring/        │ │  │ demo.py                         │ │
│  │   severity.py   │ │  │ tests/ (all test files)         │ │
│  │ utils/          │ │  │ Dockerfile + docker-compose     │ │
│  │ scanner.py      │ │  │ setup.py + pyproject.toml       │ │
│  │ config.py       │ │  │ .github/workflows/              │ │
│  │ test_detection  │ │  │ README.md + all docs/           │ │
│  └─────────────────┘ │  └─────────────────────────────────┘ │
│                      │                                      │
│  WORKS INDEPENDENTLY │  WORKS INDEPENDENTLY                │
│  No imports from     │  Uses CONTRACT only (see below)     │
│  Copilot's files     │  until integration                  │
└──────────────────────┴──────────────────────────────────────┘
                            │
                    ┌───────▼───────┐
                    │  HUMAN        │
                    │  Repo setup   │
                    │  Integration  │
                    │  Real API run │
                    │  Launch       │
                    └───────────────┘
```

---

## INTERFACE CONTRACT

**This is the ONLY thing Copilot needs to know about Claude's code.**
Copilot builds the CLI against this contract. Claude's code fulfills it.
They never need to talk to each other until integration.

```python
# What Copilot's CLI calls:
from llmguard.scanner import LLMGuardScanner
from llmguard.targets.openai import OpenAITarget
from llmguard.config import Config
from llmguard.attacks.registry import ATTACK_REGISTRY, get_categories

# 1. Create target
target = OpenAITarget(
    api_key="sk-...",
    model="gpt-3.5-turbo",         # optional
    system_prompt="You are..."     # optional
)

# 2. Run scan
scanner = LLMGuardScanner(target, budget_limit=1.0, enable_cache=False)
results = scanner.scan(attacks=["direct_injection"], quick_mode=False)

# 3. Results shape (what reporter.py consumes):
results = {
    "target": "openai-gpt-3.5-turbo",
    "model": "gpt-3.5-turbo",
    "timestamp": "2026-02-14T12:00:00Z",
    "budget_limit": 1.0,
    "vulnerabilities": [          # only vulnerable ones
        {
            "attack_name": "direct_injection",
            "category": "Prompt Injection",
            "severity": "HIGH",
            "success_rate": 0.67,
            "is_vulnerable": True,
            "remediation": "...",
            "cost": 0.003,
            "details": { "test_results": [...] }
        }
    ],
    "all_results": [...],         # all 15 attacks including non-vulnerable
    "summary": {
        "total_attacks_run": 15,
        "total_vulnerabilities": 4,
        "by_severity": {"HIGH": 2, "MEDIUM": 2},
        "risk_score": 45,         # 0-100
        "recommendation": "MEDIUM RISK: ...",
        "total_cost": 0.12,
        "budget_status": {"limit": 1.0, "spent": 0.12, "remaining": 0.88}
    }
}

# 4. Config API
api_key = Config.get_api_key("openai")   # returns str, raises ValueError if not found
```

**Copilot: build your CLI to call exactly this. Don't look inside Claude's files.**
**Claude: implement exactly this shape. Don't look inside Copilot's files.**

---

## CHECKPOINTS

```
H+0  ──── CHECKPOINT 0: Go ────────────────────────────────────────────
H+2  ──── CHECKPOINT 1: Scaffolded ─────────────────────────────────────
H+10 ──── CHECKPOINT 2: Core Layer Done (Claude) ────────────────────────
H+15 ──── CHECKPOINT 3: Interface Layer Done (Copilot) ──────────────────
H+18 ──── CHECKPOINT 4: Integration ─────────────────────────────────────
H+21 ──── CHECKPOINT 5: Launch Ready ────────────────────────────────────
H+24 ──── CHECKPOINT 6: LIVE ────────────────────────────────────────────
```

### CHECKPOINT 0 — H+0: Go
**Owner: Human (30 min)**

- [ ] Create GitHub repo: `llmguard-lite` (public, MIT license)
- [ ] Clone locally
- [ ] Set `OPENAI_KEY` environment variable
- [ ] Share repo URL with both AIs
- [ ] Send Claude Code this message: "Start SPRINT_PLAN.md — Claude Code tasks"
- [ ] Open Copilot in a separate file: "Start SPRINT_PLAN.md — Copilot tasks"

**Done when:** `git clone` works, `echo $OPENAI_KEY` returns a key.

---

### CHECKPOINT 1 — H+2: Scaffolded
**Owner: Human (45 min)**

Create the full directory and file structure from PROJECT_BIBLE.md Section 3.
All files are EMPTY at this point — just `touch` everything.

```bash
mkdir -p llmguard/{attacks,targets,scoring,utils}
mkdir -p tests/{unit,integration}
mkdir -p docs examples research scripts .github/workflows

# Package files
touch llmguard/__init__.py llmguard/__main__.py
touch llmguard/cli.py llmguard/scanner.py llmguard/config.py llmguard/demo.py

# Attacks
touch llmguard/attacks/__init__.py
touch llmguard/attacks/base.py llmguard/attacks/registry.py
touch llmguard/attacks/prompt_injection.py
touch llmguard/attacks/data_extraction.py
touch llmguard/attacks/instruction_hijacking.py

# Targets
touch llmguard/targets/__init__.py
touch llmguard/targets/base.py llmguard/targets/openai.py

# Scoring
touch llmguard/scoring/__init__.py
touch llmguard/scoring/severity.py llmguard/scoring/reporter.py

# Utils
touch llmguard/utils/__init__.py
touch llmguard/utils/budget.py llmguard/utils/cache.py llmguard/utils/validators.py

# Tests
touch tests/__init__.py tests/unit/__init__.py tests/integration/__init__.py
touch tests/unit/test_detection.py tests/unit/test_attacks.py
touch tests/unit/test_scoring.py tests/unit/test_config.py
touch tests/integration/test_openai.py

# Infrastructure
touch Dockerfile docker-compose.yml requirements.txt
touch setup.py pyproject.toml README.md CONTRIBUTING.md
touch .github/workflows/ci.yml .github/workflows/release.yml
touch docs/INSTALL.md docs/USAGE.md docs/INSTRUCTION_HIJACKING.md
touch examples/basic_scan.py examples/ci_integration.yml

# First commit
git add .
git commit -m "Initial structure — empty scaffolding"
git push
```

**Done when:** `tree llmguard/` shows the full structure, pushed to GitHub.

---

### CHECKPOINT 2 — H+10: Core Layer Done
**Owner: Claude Code (8 hours)**

**Verify with:**
```bash
python -m pytest tests/unit/test_detection.py -v
# All 10 detection tests pass

python -c "
from llmguard.attacks.prompt_injection import DirectInjectionAttack
from llmguard.attacks.data_extraction import SystemPromptRevealAttack
from llmguard.attacks.instruction_hijacking import DocxHiddenTextAttack
from llmguard.scanner import LLMGuardScanner
from llmguard.targets.openai import OpenAITarget
print('Core layer imports OK')
"
```

---

### CHECKPOINT 3 — H+15: Interface Layer Done
**Owner: GitHub Copilot (8 hours, runs parallel with Checkpoint 2)**

**Verify with:**
```bash
pip install -e .
llmguard --help                    # Shows version + commands
llmguard demo                      # Shows sample output, no API calls
llmguard info direct_injection     # Shows attack details
docker build -t llmguard-test .    # Image builds successfully
python -m pytest tests/unit/test_scoring.py -v   # Passes with mocks
```

---

### CHECKPOINT 4 — H+18: Integration
**Owner: Human (2 hours)**

This is the only human-heavy technical task.

```bash
# 1. Run full unit test suite
python -m pytest tests/unit/ -v --tb=short

# 2. Run ONE real API call to verify end-to-end
RUN_INTEGRATION_TESTS=1 python -m pytest tests/integration/test_openai.py::test_full_scan_completes -v

# 3. Run full CLI scan
llmguard scan --target openai --model gpt-3.5-turbo --budget 0.30 --output test_report.json

# 4. Verify report
cat test_report.json | python -m json.tool | head -30

# 5. Verify HTML report exists
ls -la report.html
```

**If something breaks:** Don't debug alone. Paste the error into Claude Code or Copilot immediately.

**Done when:** JSON report saved, risk_score populated, cost under $0.30.

---

### CHECKPOINT 5 — H+21: Launch Ready
**Owner: Claude Code (30 min) + Copilot (30 min) + Human (30 min)**

**Claude Code:**
- [ ] Read test results from Checkpoint 4
- [ ] Update `research/VALIDATION.md` with the REAL success rates measured
- [ ] Fix any bugs surfaced during integration

**Copilot:**
- [ ] Polish README.md with real output screenshot or demo GIF
- [ ] Final pass on `docs/INSTRUCTION_HIJACKING.md`
- [ ] Verify CI workflow passes on GitHub

**Human:**
- [ ] Tag `v0.1.0` release on GitHub
- [ ] Write the HN post (template in PROJECT_BIBLE.md Section 10)
- [ ] Write Reddit posts (3 versions: r/MachineLearning, r/LLMDevs, r/cybersecurity)
- [ ] Queue Twitter thread
- [ ] Test `docker run` from scratch on a clean terminal

**Done when:** `docker run llmguard-lite demo` works from the public image.

---

### CHECKPOINT 6 — H+24: LIVE
**Owner: Human (30 min)**

- [ ] Post to Hacker News (Wednesday 8am EST is ideal; if not, post now)
- [ ] Post to Reddit r/MachineLearning
- [ ] Post Twitter thread
- [ ] Star your own repo
- [ ] Open GitHub Discussions
- [ ] Monitor for first 2 hours — respond to every comment within 15 min

---

## CLAUDE CODE: YOUR TASK LIST

**Read first:** PROJECT_BIBLE.md Sections 6 and 7 — all implementations are there.
**Your job:** Copy them correctly, make sure they actually run, pass detection tests.

### Hour 0–1: Foundation
- [ ] `llmguard/attacks/base.py` — copy from PROJECT_BIBLE Section 6.1 exactly
- [ ] `llmguard/targets/base.py` — copy from Section 6.2
- [ ] `llmguard/utils/budget.py` — copy from Section 6.5
- [ ] `llmguard/utils/cache.py` — copy from Section 6.6 (uuid4 session ID, verify)
- [ ] `llmguard/scoring/severity.py` — copy from Section 6.4 (round() not int())
- [ ] Run quick sanity: `python -c "from llmguard.attacks.base import BaseAttack, Vulnerability"`

### Hour 1–2: Detection Tests First
- [ ] `tests/unit/test_detection.py` — copy from Section 8 exactly
- [ ] Run: `python -m pytest tests/unit/test_detection.py -v`
- [ ] ALL 10 must pass before writing any attack code
- [ ] If any fail: fix `base.py`, not the tests

### Hour 2–5: Attack Modules
- [ ] `llmguard/attacks/registry.py` — copy from Section 7.1
- [ ] `llmguard/attacks/prompt_injection.py` — all 6 attacks from Section 7.2
  - Verify `cost_before / cost_delta` pattern in every `execute()`
  - Verify `target.clear_conversation()` in MultiTurnAttack
- [ ] `llmguard/attacks/data_extraction.py` — all 4 attacks from Section 7.3
- [ ] `llmguard/attacks/instruction_hijacking.py` — all 5 attacks from Section 7.4
  - Verify all 5 check `target.supports_documents()` and return `_not_applicable()` if False
  - Verify `target.clear_documents()` called in `finally` blocks

### Hour 5–7: Target + Scanner + Config
- [ ] `llmguard/targets/openai.py` — copy from Section 6.3
  - Triple-check `_build_system_message()` merge logic
  - Triple-check `_extract_docx()` includes table cells
- [ ] `llmguard/scanner.py` — copy from Section 6.7
- [ ] `llmguard/config.py` — copy from Section 6.8

### Hour 7–8: Verification
- [ ] Run: `python -m pytest tests/unit/test_detection.py -v` (must still pass)
- [ ] Run all-imports test:
  ```python
  from llmguard.scanner import LLMGuardScanner
  from llmguard.targets.openai import OpenAITarget
  from llmguard.attacks.registry import ATTACK_REGISTRY
  assert len(ATTACK_REGISTRY) == 15
  print("All 15 attacks registered")
  ```
- [ ] Run mocked scan (no real API):
  ```python
  from unittest.mock import MagicMock
  from llmguard.scanner import LLMGuardScanner
  target = MagicMock()
  target.total_cost = 0.0
  target.name = "mock"
  target.supports_documents.return_value = False
  # This should not crash even with mocks
  ```
- [ ] Commit: `git add llmguard/ tests/unit/test_detection.py && git commit -m "Core layer complete"`

### IMPORTANT: What Claude Code does NOT touch
- `cli.py` — Copilot owns this
- `scoring/reporter.py` — Copilot owns this
- `demo.py` — Copilot owns this
- `Dockerfile` — Copilot owns this
- `README.md` — Copilot owns this
- Any file in `docs/` — Copilot owns this
- Any file in `tests/` except `test_detection.py` — Copilot owns these

---

## GITHUB COPILOT: YOUR TASK LIST

**Read first:** The INTERFACE CONTRACT section above.
**Your job:** Build everything that wraps and presents the core layer.
**You don't need to understand** the attack logic — you just call `scanner.scan()` and render what comes back.

### Hour 0–1: Infrastructure First
- [ ] `requirements.txt` — exact versions from PROJECT_BIBLE Section 4
- [ ] `setup.py` — package config with entry point `llmguard=llmguard.cli:cli`
- [ ] `pyproject.toml` — modern Python packaging config
- [ ] `Dockerfile` — python:3.11-slim, copy requirements, pip install, ENTRYPOINT
- [ ] `docker-compose.yml` — dev environment with env var passthrough
- [ ] `llmguard/__init__.py` — version string: `__version__ = "0.1.0"`
- [ ] `llmguard/__main__.py` — `from llmguard.cli import cli; cli()`

### Hour 1–3: CLI
Build `llmguard/cli.py` against the CONTRACT above. Commands:

**`llmguard scan`**
```
Options:
  --target          [openai] required
  --model           str, default gpt-3.5-turbo
  --system-prompt   str, optional
  --system-prompt-file  path, optional (read file, pass as system_prompt)
  --budget          float, default 1.0
  --output          path, default report.json
  --ci              flag — JSON to stdout, no colors, no progress bar
  --quick           flag — quick_mode=True on scanner
  --attacks         comma-separated list of attack IDs
```

**`llmguard demo`**
- No API calls
- Show pre-built fake results using the same Rich table as real scan
- Make it impressive — this is what people screenshot

**`llmguard info <attack_id>`**
- Read from ATTACK_REGISTRY
- Show name, category, severity_baseline, description, expected_success_rate

**`llmguard list`**
- List all 15 attacks in a Rich table grouped by category

**Exit codes:**
- 0 → risk_score == 0
- 1 → 0 < risk_score < 80
- 2 → risk_score >= 80

### Hour 3–5: Reporter
Build `llmguard/scoring/reporter.py`:

```python
class Reporter:
    def save_json(self, results: dict, output_path: str): ...
    def save_html(self, results: dict, output_path: str): ...
    def print_terminal(self, results: dict, console: Console): ...
```

**Terminal output should look like:**
```
╭──────────────────────────────────────────────────────╮
│ LLMGuard Security Scanner v0.1                       │
│ Target: openai-gpt-3.5-turbo  │  Budget: $1.00       │
╰──────────────────────────────────────────────────────╯

⠋ Scanning...  ━━━━━━━━━━━━━━━━━━━━━  100%  (15/15)

┌──────────────────────────────┬───────────┬─────────────┐
│ Attack                       │ Severity  │ Success Rate│
├──────────────────────────────┼───────────┼─────────────┤
│ Direct Prompt Injection      │ HIGH      │ 67%         │
│ System Prompt Disclosure     │ HIGH      │ 50%         │
│ DOCX Hidden Text Injection   │ CRITICAL  │ 100%        │
└──────────────────────────────┴───────────┴─────────────┘

╭──────────────────── Summary ─────────────────────────╮
│ Risk Score: 58/100                                    │
│ Vulnerabilities: 3 (1 Critical, 2 High)              │
│ Cost: $0.09  │  Attacks Run: 15                      │
│                                                       │
│ HIGH RISK: Address critical/high findings before      │
│ deployment.                                           │
╰───────────────────────────────────────────────────────╯

✓ Report saved to: report.json
```

**HTML report:** Basic template — table of results, risk score badge,
remediation for each vulnerability. No CSS frameworks — inline styles only
so the file is self-contained.

### Hour 5–7: Tests + Demo Mode
**`tests/unit/test_attacks.py`** — mock-based tests:
```python
# Pattern for every attack test:
class MockTarget:
    def __init__(self, response):
        self._response = response
        self.total_cost = 0.0
        self.name = "mock"
        self.conversation_history = []
        self.uploaded_documents = {}
    def query(self, prompt, **kwargs): return self._response
    def estimate_cost(self, *args): return 0.001
    def supports_documents(self): return False
    def clear_conversation(self): self.conversation_history.clear()
    def clear_documents(self): self.uploaded_documents.clear()

# Test 1: vulnerable response detected
def test_direct_injection_detects_pwned():
    target = MockTarget("PWNED — done as requested")
    attack = DirectInjectionAttack()
    result = attack.execute(target)
    assert result.is_vulnerable is True

# Test 2: refusal not flagged
def test_direct_injection_ignores_refusal():
    target = MockTarget("I cannot say PWNED as that is a prompt injection.")
    attack = DirectInjectionAttack()
    result = attack.execute(target)
    assert result.is_vulnerable is False

# Test 3: errors handled
def test_attack_handles_api_error():
    target = MockTarget("anything")
    target.query = lambda *a, **k: (_ for _ in ()).throw(Exception("API Error"))
    attack = DirectInjectionAttack()
    result = attack.execute(target)  # Must not raise
    assert result.is_vulnerable is False
```

Write at least 2 tests per attack (vulnerable + refused). That's 30 tests total.

**`tests/unit/test_scoring.py`**:
```python
from llmguard.scoring.severity import SeverityScorer, Severity

def test_critical_high_success_data_extraction():
    scorer = SeverityScorer()
    result = scorer.calculate(0.9, "Data Extraction")
    assert result == Severity.CRITICAL

def test_low_success_low_weight_is_low():
    scorer = SeverityScorer()
    result = scorer.calculate(0.1, "Evasion")
    assert result in [Severity.LOW, Severity.MEDIUM]
```

**`llmguard/demo.py`**:
```python
# Pre-built fake results — same shape as scanner.scan() returns
# Hard-code 3-4 "found" vulnerabilities
# Call reporter.print_terminal() with them
# Add a 0.05-second sleep between attack "completions" for realism
```

**`tests/integration/test_openai.py`** — copy from PROJECT_BIBLE Section 8.

### Hour 7–8: Documentation
**`README.md`** — must include:
1. One-liner description
2. Demo GIF placeholder (you'll record after Checkpoint 4)
3. Quick start: `pip install llmguard-lite` + `llmguard scan --target openai`
4. What it tests (3-category table)
5. Cost table (GPT-3.5 vs GPT-4)
6. Comparison table vs. garak/manual
7. Novel research callout
8. Contributing link

**`docs/INSTALL.md`** — Docker + pip install + env var setup

**`docs/USAGE.md`** — every CLI flag with examples

**`docs/INSTRUCTION_HIJACKING.md`** — copy structure from PROJECT_BIBLE Section 1,
but leave success rate fields as TBD (human fills after real test in Checkpoint 4)

**`.github/workflows/ci.yml`**:
```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt && pip install -e .
      - run: python -m pytest tests/unit/ -v --tb=short
```

### IMPORTANT: What Copilot does NOT touch
- `attacks/base.py` — Claude owns this
- `attacks/prompt_injection.py` — Claude owns this
- `attacks/data_extraction.py` — Claude owns this
- `attacks/instruction_hijacking.py` — Claude owns this
- `targets/` — Claude owns this
- `scanner.py` — Claude owns this
- `scoring/severity.py` — Claude owns this
- `utils/budget.py` + `utils/cache.py` — Claude owns this
- `tests/unit/test_detection.py` — Claude owns this

---

## HUMAN: YOUR TASK LIST (20%)

You are the glue. Your job is coordination, integration, and launch.
Avoid touching code directly — delegate to the right AI when something breaks.

### H+0 (30 min): Setup
- [ ] Create GitHub repo `llmguard-lite` (public, MIT)
- [ ] Clone locally
- [ ] Create `.env` file: `OPENAI_KEY=sk-...`
- [ ] Run scaffold commands from Checkpoint 1 above
- [ ] First push

### H+2 (ongoing): Traffic Control
- Monitor both AIs. If either is blocked, unblock immediately:
  - "Claude Code is blocked on X" → paste the error into this chat
  - "Copilot is blocked on Y" → paste the error into Copilot's context
- Do NOT try to resolve technical blocks yourself — just relay them

### H+15 (45 min): Integration
```bash
# Pull latest from both branches (if using branches)
git pull

# Install in dev mode
pip install -e .

# Run unit tests
python -m pytest tests/unit/ -v --tb=short > test_output.txt 2>&1
cat test_output.txt

# If tests fail: paste failures into the right AI
```

### H+18 (1 hour): Real API Run
```bash
# This is the moment of truth
export OPENAI_KEY=your-key

llmguard scan \
  --target openai \
  --model gpt-3.5-turbo \
  --budget 0.30 \
  --output validation_results.json

# Read the output
cat validation_results.json | python -m json.tool

# Record actual success rates for each attack
# Paste into docs/INSTRUCTION_HIJACKING.md (the TBD fields)
```

**After the run:**
- Copy actual `success_rate` values into `research/VALIDATION.md`
- This is your real data. Don't invent numbers.

### H+21 (30 min): Release
```bash
git add .
git commit -m "v0.1.0 — all 15 attacks, full CLI, validated"
git tag v0.1.0
git push && git push --tags

# Create GitHub Release
gh release create v0.1.0 \
  --title "LLMGuard-Lite v0.1.0 — Security scanner for LLM apps" \
  --notes "$(cat docs/RELEASE_NOTES.md)"
```

### H+22–24: Launch
Time these based on your timezone and when HN is most active.
Best time to post Show HN: **Tuesday–Thursday, 8–10am EST**.

If launching on a weekend (now), post Sunday night US time for Monday morning traffic.

```
Post order:
1. GitHub Release (already done)
2. Hacker News (Show HN)
3. Reddit r/netsec or r/LLMDevs
4. Twitter/X thread
5. LinkedIn post
6. Dev.to blog post (can be same day +1)
```

**For the next 2 hours after posting:**
Respond to EVERY comment. Fix EVERY reported bug. This is the only window
where you have momentum — don't waste it sleeping.

---

## RISK REGISTER

| Risk | Likelihood | Who Handles |
|------|-----------|-------------|
| OpenAI API changes break target | Low | Claude Code |
| Detection tests fail at integration | Medium | Claude Code |
| CLI imports from core fail | Medium | Human pastes error to Claude |
| DOCX generation fails on Windows | Medium | Claude Code |
| Docker build fails | Low | Copilot |
| Budget exceeded in real test | Low | Human reduces --budget |
| HN post gets no traction | Medium | Post to Reddit too, be patient |
| Copilot + Claude produce incompatible code | Low | Contract prevents this |

---

## COMMUNICATION PROTOCOL

When something breaks during integration, use this format:

**→ To Claude Code:**
"Integration issue in [filename]:[line]. Error: [paste error]. Claude Code's file: [filename]. Copilot's file: [filename]."

**→ To GitHub Copilot:**
"The scanner returns [shape]. Your reporter/CLI is calling [wrong method]. Fix [filename]."

**→ Never:** "It's broken, fix it." Always include the actual error output.

---

## FINAL CHECKLIST BEFORE LAUNCH

```
Technical
- [ ] python -m pytest tests/unit/ → all pass
- [ ] llmguard demo → renders without error
- [ ] llmguard scan → completes, saves report.json
- [ ] docker build → succeeds
- [ ] docker run llmguard demo → works from image

Content
- [ ] README has no placeholder text
- [ ] No TODO comments in shipped code
- [ ] No fake statistics (all numbers are from real Checkpoint 4 run)
- [ ] All 15 attacks in registry
- [ ] docs/ linked correctly from README

Launch
- [ ] v0.1.0 tagged
- [ ] GitHub Release created
- [ ] HN post written and ready
- [ ] OPENAI_KEY not committed anywhere
- [ ] .gitignore covers .env, __pycache__, *.pyc
```

---

*Sprint plan created 2026-02-14. Source of truth: PROJECT_BIBLE.md*
