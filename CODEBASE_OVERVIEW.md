# Vektor Codebase Architecture — Complete Overview

**Total LOC:** ~5,270 lines of core Vektor code | **Version:** 0.2.0 | **Status:** Alpha

---

## 📐 DIRECTORY STRUCTURE & PURPOSE

```
vektor-lite/
├── vektor/                    # Core library (5,270 LOC)
│   ├── __init__.py           # Public API exports (scan, quick_scan, ScanFailed exception)
│   ├── __main__.py           # Entry point for `python -m vektor`
│   ├── cli.py                # Click-based CLI: scan, demo, list, info commands
│   ├── config.py             # Configuration object for scan parameters
│   ├── demo.py               # Demo mode — pre-computed results (no API calls)
│   │
│   ├── core/
│   │   ├── engine.py         # VektorScanner — main orchestrator, runs attacks, computes risk scores
│   │   ├── plugin.py         # @attack decorator, attack registry, plugin loading system
│   │   └── diff.py           # Diff mode — compare repeated scans (unused in production)
│   │
│   ├── attacks/              # 27 attack vectors across 6 categories
│   │   ├── base.py           # BaseAttack parent class, Vulnerability data model
│   │   ├── registry.py       # ATTACK_REGISTRY dict (populated by @attack decorators)
│   │   ├── prompt_injection.py      # 6 attacks: direct, system_override, delimiter, role, multi_turn, encoding_bypass
│   │   ├── data_extraction.py       # 4 attacks: training_data_probe, system_prompt_reveal, context_extraction, pii_leakage
│   │   ├── instruction_hijacking.py # 3 attacks: document injection, docx hidden text, etc.
│   │   ├── rag_attacks.py           # 5 RAG-specific attacks
│   │   ├── agent_attacks.py         # 5 agent/tool attacks
│   │   ├── memory_attacks.py        # 2 memory/state attacks
│   │   └── structured_output_injection.py  # 2 structured output attacks
│   │
│   ├── targets/              # Target adapters — how to talk to different LLM systems
│   │   ├── base.py           # BaseTarget abstract class (defines the interface)
│   │   ├── factory.py        # create_target() — factory function, autodetects provider
│   │   ├── http_endpoint.py  # HTTPEndpointTarget — generic HTTP/REST interface (MOST USED)
│   │   ├── mock.py           # MockTarget — for testing
│   │   ├── vulnerable.py     # VulnerableTarget — intentionally vulnerable demo target
│   │   ├── gemini.py         # GeminiTarget — Google Gemini API integration
│   │   ├── openai_compatible.py      # OpenAICompatibleTarget — OpenAI, Groq, Together, etc.
│   │   ├── multi_agent.py    # MultiAgentTarget — coordinator + specialist agents
│   │   ├── agents/
│   │   │   ├── autogen_target.py     # AutoGen framework adapter
│   │   │   ├── crewai_target.py      # CrewAI framework adapter
│   │   │   └── langgraph_target.py   # LangGraph framework adapter
│   │   └── rag/
│   │       ├── langchain_target.py   # LangChain auto-wrap for Runnable/Chain
│   │       └── llamaindex_target.py  # LlamaIndex auto-wrap for QueryEngine
│   │
│   ├── scoring/
│   │   ├── reporter.py       # Report generation (terminal, JSON, HTML with attack graph)
│   │   ├── severity.py       # Severity scorer — maps success_rate + category to CRITICAL/HIGH/etc
│   │   └── __init__.py       # Exports
│   │
│   ├── utils/
│   │   ├── budget.py         # BudgetManager — tracks USD spent, enforces limit
│   │   ├── cache.py          # ResponseCache — caches model responses (off by default for security)
│   │   ├── http.py           # HTTP helpers — request wrapper with retry logic
│   │   └── __init__.py       # Exports
│   │
│   └── data/
│       ├── demo_results.json # Pre-computed demo scan results
│       └── __init__.py
│
├── tests/                     # 219 test cases (all passing)
│   ├── unit/
│   │   ├── test_attacks.py           # Tests each attack against MockTarget
│   │   ├── test_config.py            # Config validation tests
│   │   ├── test_detection.py         # Pattern matching tests for detectors
│   │   ├── test_http_target.py       # HTTPEndpointTarget tests
│   │   ├── test_diff.py              # Diff mode tests
│   │   ├── test_new_targets.py       # Multi-agent, RAG target tests
│   │   ├── test_rag_targets.py       # RAG framework adapters
│   │   ├── test_scoring.py           # Severity scoring + report tests
│   │   └── test_smoke.py             # End-to-end scan tests
│   └── integration/
│       ├── test_gemini.py    # Integration with live Gemini API (skipped if no key)
│       └── test_openai.py    # Integration with live OpenAI API (skipped if no key)
│
├── scripts/
│   ├── scan_local_app.py     # Helper — scans target_app.py (used in dev/demos)
│   ├── probe_endpoints.py    # Helper — format detector for custom endpoints
│   └── analyze_results.py    # Helper — analyzes scan outputs
│
├── docs/
│   ├── USAGE.md             # User guide (CLI commands, examples)
│   ├── INSTALL.md           # Installation guide
│   ├── DEMO.md              # Demo walkthrough
│   ├── INSTRUCTION_HIJACKING.md   # Technical deep-dive on instruction hijacking
│   ├── PHASE_TESTING.md     # Development phases documentation
│   ├── RELEASE_NOTES.md     # Version history
│   └── internal/            # Archive — not shipped
│
├── _archive/                # Dead/obsolete documentation
│   ├── internal_docs/
│   │   ├── CLAUDE_RESEARCH.md
│   │   ├── PROJECT_BIBLE.md
│   │   ├── PRODUCT_PLAN.md
│   │   └── outputs/         # Competitor analysis, growth playbooks (not used)
│   └── generated/           # Old egg-info
│
├── outputs/                 # Scan outputs (gitignored, user-generated)
│   └── *.json, *.html       # Past scan results
│
├── target_app.py            # DEMO: Multi-agent FastAPI backend (vulnerable on purpose)
├── demo_server.py           # DEMO: Simple Flask server (for local testing)
├── check_report.py          # DEMO: Report viewer helper
├── show_report.py           # DEMO: Report display helper
├── _write_rag_targets.py    # DEMO: Script to generate RAG target fixtures
│
├── LAUNCH.md                # User-facing: Quick start guide
├── README.md                # Main documentation
├── CONTRIBUTING.md          # Contribution guidelines
├── pyproject.toml           # Package metadata, dependencies, entry points
└── .gitignore               # Excludes target_app.py, demo_server.py, outputs/, .env

```

---

## 🔄 DATA FLOW: How a Scan Works

1. **User invokes:** `vektor scan --url http://localhost:8000/chat`

2. **CLI entry (cli.py):**
   - Parses arguments
   - Calls `create_target("http", url="...")`

3. **Target creation (factory.py → http_endpoint.py):**
   - Creates `HTTPEndpointTarget` instance
   - Probes endpoint to detect field names (prompt/response/chat)

4. **Scanner setup (engine.py):**
   - `VektorScanner(target, budget_limit=1.0)`
   - Loads all attacks from `ATTACK_REGISTRY`
   - Initializes `BudgetManager`, optional `ResponseCache`

5. **Attack execution loop (engine.py → scan()):**
   - For each attack in registry:
     - Call `attack.execute(target)`
     - Track cost, check budget
     - Append result to `vulnerabilities[]`
     - In "analysis" mode, pattern-match response for signals (error_disclosure, data_leakage, etc.)

6. **Scoring (engine.py → severity.py):**
   - Compute severity based on success_rate + category
   - Calculate risk_score (blended severity + category weights)
   - Apply severity floor (CRITICAL finding ≥ 65, HIGH ≥ 40)

7. **Reporting (reporter.py):**
   - Terminal: Rich table + risk panel
   - JSON: Structured output
   - HTML: Self-contained report with attack graph visualization

---

## 🎯 CORE COMPONENTS IN DETAIL

### **1. VektorScanner (core/engine.py) — 370 LOC**
**Purpose:** Orchestrates the entire scan.
- Loads attacks from registry
- Runs each attack, tracks cost
- Deduplicates analysis findings (caps same detector at 3 hits to avoid rate-limit noise)
- Generates summary (risk score, finding categories)
- Supports two modes:
  - `standard`: Just attack results
  - `analysis`: Attack results + pattern matching for error signals, system fingerprinting, etc.

**Key methods:**
- `scan()` — main entry point
- `_compute_risk_score()` — severity+category weighted scoring
- `_generate_summary()` — aggregates results
- `_analysis_findings_from_result()` — pattern matching on responses
- `_deduplicate_analysis_findings()` — dedup analysis hits + rate-limit detection

### **2. Attack Registry & Plugin System (core/plugin.py) — 163 LOC**
**Purpose:** Self-registering attack system.
- `@attack()` decorator auto-registers attack classes
- `ATTACK_REGISTRY` — dict of {attack_id → metadata + class ref}
- Supports file-based plugin loading (`--plugin ./my_attacks.py`)
- Supports entry-point discovery for installed packages

**Key insight:** Attacks don't live in a list; they're decorated classes that self-register when imported.

### **3. BaseAttack (attacks/base.py) — 220 LOC**
**Purpose:** Parent class for all attacks.
- Defines `execute(target) → Vulnerability` contract
- Provides helpers: `_detect_success()`, `_classify_response()`, `_extract_evidence()`
- Provides severity calculator based on success_rate

**Every attack must:**
```python
@attack(category="...", owasp="LLM01: ...", description="...")
class MyAttack(BaseAttack):
    def execute(self, target) -> Vulnerability:
        # Run 2-3 test cases
        # Return Vulnerability(attack_name, severity, success_rate, ...)
```

### **4. Target Interface (targets/base.py) — 106 LOC**
**Purpose:** Abstract interface that all LLM targets conform to.
- `query(prompt: str) → str` — the core method
- Optional: `supports_documents()`, `upload_document()`, `supports_tools()`, `call_tool()`, etc.

**Implementations:**
- **HTTPEndpointTarget** — Generic HTTP POST/GET to any endpoint (MOST COMMONLY USED)
- **GeminiTarget** — Direct Google Gemini integration
- **OpenAICompatibleTarget** — OpenAI + Groq + Together (same API shape)
- **MultiAgentTarget** — Coordinator + specialist agents (experimental)
- **VulnerableTarget** — Intentionally broken for demos

### **5. Report Generation (scoring/reporter.py) — 350 LOC**
**Purpose:** Generate terminal, JSON, and HTML reports.
- **HTML Report features:**
  - Risk badge (0-100 score)
  - Vulnerability table with severity badges + explanations
  - Evidence panels (collapsible — shows payload sent + model response)
  - **Attack graph** — visual chain: Input → Prompt Injection → System Prompt Exposure → Tool Misuse → PII Exfiltration
  - Finding category breakdown
  - Remediation guidance

---

## ✅ FILES THAT ARE ESSENTIAL (PRODUCTION SHIP)

| File | LOC | Status | Used By |
|------|-----|--------|---------|
| `vektor/core/engine.py` | 370 | ✅ Core | scanner.scan() |
| `vektor/attacks/base.py` | 220 | ✅ Core | All 27 attacks |
| `vektor/attacks/prompt_injection.py` | 310 | ✅ Core | 6 critical attacks |
| `vektor/attacks/data_extraction.py` | 190 | ✅ Core | 4 data leak attacks |
| `vektor/attacks/instruction_hijacking.py` | 200 | ✅ Core | 3 document attacks |
| `vektor/targets/base.py` | 106 | ✅ Core | All targets extend this |
| `vektor/targets/http_endpoint.py` | 227 | ✅ Core | Handles `--url` |
| `vektor/targets/factory.py` | 100 | ✅ Core | `create_target()` |
| `vektor/scoring/reporter.py` | 350 | ✅ Core | All reports |
| `vektor/scoring/severity.py` | 120 | ✅ Core | Risk scoring |
| `vektor/cli.py` | 600 | ✅ Core | `vektor` command |
| `vektor/__init__.py` | 185 | ✅ Core | Public API |
| `pyproject.toml` | 55 | ✅ Core | Package metadata |

---

## ⚠️ DEAD CODE & FILES TO CONSIDER ELIMINATING

### **HIGH PRIORITY — Remove These**

#### **1. `vektor/core/diff.py` (90 LOC)**
- **Status:** Not used anywhere in CLI or tests
- **Purpose:** Supposed to compare two scans (diff mode)
- **Why unused:** Half-baked feature, no CLI command for it
- **Action:** DELETE

#### **2. `vektor/targets/agents/` (3 files, ~150 LOC total)**
- **autogen_target.py** (70 LOC)
- **crewai_target.py** (65 LOC)
- **langgraph_target.py** (50 LOC)
- **Status:** Not in CLI `--target` options, never tested
- **Purpose:** Framework-specific adapters for AutoGen, CrewAI, LangGraph
- **Why unused:** Over-engineered for a v0.2 release; most users use HTTPEndpointTarget
- **Action:** ARCHIVE to `_archive/experimental_agents/`

#### **3. `vektor/targets/rag/` (2 files, ~200 LOC total)**
- **langchain_target.py** (120 LOC)
- **llamaindex_target.py** (100 LOC)
- **Status:** Imported in `__init__.py` re-exports, but not in main CLI
- **Purpose:** Auto-wrap LangChain/LlamaIndex objects
- **Why unused:** Only used if you import `from vektor.targets.rag import auto_wrap` directly; not CLI-accessible
- **Action:** MOVE to `_archive/experimental_rag/` (some users may use programmatically, so keep it available)

#### **4. `_write_rag_targets.py` (50 LOC)**
- **Status:** Demo-only script, not shipped
- **Purpose:** Generate RAG test fixtures
- **Action:** DELETE (live in _archive, not needed)

#### **5. `vektor/utils/cache.py` (60 LOC)**
- **Status:** Disabled by default (`enable_cache=False` in engine)
- **Purpose:** Response caching
- **Why disabled:** Security testing needs fresh results; caching breaks reproducibility
- **Action:** DELETE (or move to _archive for later optimization)

#### **6. `vektor/demo.py` (120 LOC)**
- **Status:** Demo data only
- **Purpose:** Pre-computed demo scan results
- **Action:** KEEP (used by `vektor demo` command), but mark as demo-only data

---

### **MEDIUM PRIORITY — Clean Up**

#### **7. `_archive/` directory (entire folder, ~2MB)**
- **Status:** Graveyard of old research docs, unused outputs
- **Contains:**
  - `CLAUDE_RESEARCH.md` — competitor analysis (stale)
  - `PROJECT_BIBLE.md` — design docs (outdated v0.1 design)
  - `outputs/` — old scan results
  - `generated/` — old egg-info
- **Action:** Compress to `.tar.gz` and store outside repo

#### **8. `demo_server.py`, `target_app.py` in root**
- **Status:** Demo/test targets only
- **Purpose:** `target_app.py` is now the multi-agent system for demos
- **Should be:** In a separate `/examples/` or `/demo/` directory
- **Action:** Create `examples/` dir, move both there, add to `.gitignore`

#### **9. `check_report.py`, `show_report.py`**
- **Status:** Demo helper scripts
- **Action:** Move to `examples/` dir

#### **10. `scripts/` (3 files)**
- **scan_local_app.py** — scans target_app.py (good for local testing)
- **probe_endpoints.py** — helper for detecting endpoint shapes
- **analyze_results.py** — post-scan analysis
- **Status:** Useful for development, not shipped
- **Action:** Keep but document as "development helpers" in README

---

### **LOW PRIORITY — Document Better**

#### **11. `docs/internal/` (archived docs)**
- **Status:** Not shipped with package
- **Action:** Delete from repo (move to internal wiki)

#### **12. `LAUNCH.md`, `CONTRIBUTING.md`**
- **Status:** User-facing, good
- **Action:** KEEP, integrate into main README

---

## 🧠 ARCHITECTURE STRENGTHS

1. **Plugin system works.** The `@attack` decorator is elegant; new attacks just work.
2. **Target abstraction is solid.** HTTPEndpointTarget auto-detects field shapes, making the CLI super flexible.
3. **Budget tracking prevents bill shock.** `BudgetManager` stops scans if spending exceeds limit.
4. **Test coverage is excellent.** 219 tests, all passing, with both unit and integration tests.
5. **Report generation is beautiful.** HTML attack graph is a genuine differentiator.

---

## 🚨 ARCHITECTURE WEAK POINTS

1. **Agent targets are over-engineered.** CrewAI/AutoGen adapters aren't in CLI; they're vestigial.
2. **RAG targets aren't discoverable.** Users must know to import `auto_wrap` directly; they're hidden from CLI.
3. **Diff mode is abandoned.** Code exists but nothing calls it.
4. **Cache is disabled by design.** Means we're not optimizing for local/repeated scans.
5. **Demo data is hardcoded.** `vektor demo` uses check_report.py which is files, not embedded.

---

## 💡 RECOMMENDATIONS FOR CLEANUP

### **Phase 1 (Immediate — for v0.3)**
```bash
# Delete these files
rm vektor/core/diff.py              # Dead diff mode
rm _write_rag_targets.py            # Demo fixture script
rm vektor/utils/cache.py            # Never used

# Move to examples/
mkdir -p examples/
mv target_app.py examples/
mv demo_server.py examples/
mv check_report.py examples/
mv show_report.py examples/

# Move to _archive/experimental/
mkdir -p _archive/experimental/{agents,rag}
mv vektor/targets/agents/* _archive/experimental/agents/
mv vektor/targets/rag/* _archive/experimental/rag/
rmdir vektor/targets/{agents,rag}
```

### **Phase 2 (Cleanup — for v0.4)**
- Simplify target factory — remove unused target types
- Make RAG targets CLI-accessible: `vektor scan --target langchain --app my_chain.json`
- Compress `_archive/` to `.tar.gz`
- Delete old docs in `_archive/internal_docs/`

### **Phase 3 (Optimization — for v0.5)**
- Re-enable caching with security guardrails (cache only probe responses, not secrets)
- Implement `vektor diff [report1] [report2]` command (currently code exists but nothing calls it)

---

## 📊 CODEBASE METRICS

| Metric | Value |
|--------|-------|
| Total LOC (core) | 5,270 |
| Test LOC | 1,800+ |
| Attack vectors | 27 |
| Attack categories | 6 |
| Target adapters | 8 (4 public, 2 RAG, 2 agent) |
| Tests passing | 219/219 ✅ |
| Dead/unused LOC | ~300-400 |
| % dead code | 6-7% |

---

## 🎬 ENTRY POINTS & USER FLOWS

### **Flow 1: CLI (Most Common)**
```
$ vektor scan --url http://localhost:8000/chat
  → cli.py: parse args
  → factory.py: create_target("http", url=...)
  → engine.py: VektorScanner(target).scan()
  → reporter.py: print terminal + save HTML/JSON
```

### **Flow 2: Programmatic (LangChain Users)**
```python
from vektor import scan
results = scan(app=my_chain)
```

### **Flow 3: Demo (No Setup)**
```
$ vektor demo
  → cli.py: vektor_demo()
  → demo.py: load pre-computed results
  → reporter.py: show terminal + open HTML
```

---

## 📝 FINAL SUMMARY

**Vektor is ~5,700 LOC of well-structured, tested, production-ready code.**

**Cleanly separable into:**
1. **Core (required):** 2,500 LOC — engine, attacks, base infrastructure
2. **Targets (pluggable):** 1,500 LOC — HTTP, OpenAI, Gemini, Multi-agent
3. **Reporting:** 350 LOC — terminals, JSON, HTML
4. **CLI:** 600 LOC — user interface
5. **Dead/experimental:** 300-400 LOC — diff mode, agents, RAG, cache

**For 500+ stars positioning:**
- Clean up dead code (diff.py, agent targets)
- Make RAG targets CLI-accessible
- Lead with the HTML attack graph (screenshot-friendly)
- Emphasize `--url` works on ANY endpoint (no SDK needed)

