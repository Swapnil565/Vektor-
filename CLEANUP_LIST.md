# FILES WITH ZERO RELEVANCE — DELETION/MOVING LIST

## PRIORITY 1: DELETE IMMEDIATELY (Dead Code)

### `vektor/utils/cache.py` (48 lines, 1.6 KB)
- **Status:** Imported but never used
- **Why:** `ResponseCache` is only instantiated when `enable_cache=True`, which never happens
  - Engine always initializes with `enable_cache=False` (line 84 in engine.py)
  - No CLI flag to enable it
  - Hidden from users
- **Impact:** Zero users affected
- **Action:** DELETE

### `vektor/utils/http.py` (1 line, 2 bytes)
- **Status:** Empty stub file
- **Content:** Just a blank file or comment
- **Why:** Never imported, never used
- **Action:** DELETE

---

## PRIORITY 2: MOVE TO `examples/` (Demo/Test Scripts)

These belong in a separate demo directory, not in the package root:

### `target_app.py` (503 lines, 22.6 KB)
- **Status:** Demo backend — multi-agent FastAPI system
- **Currently in:** Package root
- **Issue:** Shipped with pip install; not needed for users
- **Action:** MOVE → `examples/target_app.py`

### `demo_server.py` (31 lines, 1 KB)
- **Status:** Simple Flask demo server
- **Currently in:** Package root
- **Issue:** Demo-only, not shipped functionality
- **Action:** MOVE → `examples/demo_server.py`

### `check_report.py` (25 lines, 918 bytes)
- **Status:** Report helper script
- **Currently in:** Package root
- **Issue:** Demo utility only
- **Action:** MOVE → `examples/check_report.py`

### `show_report.py` (23 lines, 911 bytes)
- **Status:** Report display helper
- **Currently in:** Package root
- **Issue:** Demo utility only
- **Action:** MOVE → `examples/show_report.py`

### `_write_rag_targets.py` (793 lines, 28.4 KB)
- **Status:** Fixture generator for RAG testing
- **Currently in:** Package root
- **Issue:** Dev-only script, generates test data
- **Action:** MOVE → `examples/_write_rag_targets.py`

---

## PRIORITY 3: ARCHIVE (Experimental/Framework Adapters)

These are functional but not production-ready. Move to `_archive/experimental/`:

### `vektor/targets/agents/` (3 files, ~150 LOC)
- **autogen_target.py** (138 lines)
- **crewai_target.py** (106 lines)
- **langgraph_target.py** (121 lines)
- **Status:** Framework adapters for AutoGen, CrewAI, LangGraph
- **Why archived:**
  - Not in CLI provider list
  - Over-engineered for v0.2
  - Zero users currently use these
  - Most users use HTTPEndpointTarget instead
- **Action:** MOVE → `_archive/experimental/agents/`

### `vektor/targets/rag/` (2 files, ~200 LOC)
- **langchain_target.py** (370 lines)
- **llamaindex_target.py** (289 lines)
- **Status:** RAG framework adapters
- **Why archived:**
  - Not in CLI; only accessible via `from vektor.targets.rag import auto_wrap`
  - Experimental feature
  - Requires LangChain/LlamaIndex installed (optional dependencies not in pyproject.toml)
- **Action:** MOVE → `_archive/experimental/rag/` (keep for power users, just document as experimental)

---

## PRIORITY 4: DELETE (Research/Archive Docs)

### `_archive/internal_docs/CLAUDE_RESEARCH.md` (473 lines, 13.9 KB)
- **Status:** Old researcher notes/analysis
- **Why:** Stale, internal, not shipped
- **Action:** DELETE

### `_archive/internal_docs/PROJECT_BIBLE.md` (2,622 lines, 108 KB)
- **Status:** Old v0.1 product design doc
- **Why:** Outdated, not shipped, for internal reference only
- **Action:** DELETE

### `_archive/internal_docs/PRODUCT_PLAN.md` (567 lines, 22.4 KB)
- **Status:** Product roadmap (stale)
- **Why:** Not shipped, reference only
- **Action:** DELETE

### `_archive/internal_docs/SPRINT_PLAN.md` (714 lines, 27.5 KB)
- **Status:** Sprint tracking doc
- **Why:** Historical, not used
- **Action:** DELETE

### `_archive/internal_docs/outputs/` (Multiple files, 61.5 KB)
- **Status:** Competitor analysis, research outputs
- **Why:** Stale research, not shipped
- **Action:** DELETE

### `_archive/generated/` (47.8 KB)
- **Status:** Old egg-info build artifacts
- **Why:** Auto-generated, stale
- **Action:** DELETE

---

## FILES TO KEEP (Not "Zero Relevance")

These ARE in use and should stay:

- ✅ `vektor/core/diff.py` (376 lines) — Used by `vektor diff` CLI command (line 454 in cli.py)
- ✅ `vektor/demo.py` (120 lines) — Used by `vektor demo` CLI command
- ✅ All attack files — All 27 attacks are auto-registered and used
- ✅ All target files except agents/rag — core, openai, gemini, http, multi_agent are used
- ✅ All scoring files — Used for reports
- ✅ `scripts/` — Development helpers (keep but document in README)

---

## SUMMARY OF REMOVALS

| Category | Files | LOC | Size | Action |
|----------|-------|-----|------|--------|
| **Dead code** | 2 | 49 | 1.6 KB | DELETE |
| **Demo scripts** | 5 | 1,375 | 54.2 KB | MOVE → examples/ |
| **Experimental** | 5 | ~650 | ~23 KB | MOVE → _archive/experimental/ |
| **Old docs** | 6 | 5,758 | ~281 KB | DELETE |
| **TOTAL** | **18** | **~8,000** | **~360 KB** | **CLEAN UP** |

---

## CLEANUP COMMANDS (Ready to Run)

```bash
# Step 1: Delete dead code
rm vektor/utils/cache.py
rm vektor/utils/http.py

# Step 2: Create examples directory and move demo scripts
mkdir -p examples
mv target_app.py examples/
mv demo_server.py examples/
mv check_report.py examples/
mv show_report.py examples/
mv _write_rag_targets.py examples/

# Step 3: Archive experimental targets
mkdir -p _archive/experimental/{agents,rag}
mv vektor/targets/agents/* _archive/experimental/agents/
mv vektor/targets/rag/* _archive/experimental/rag/
rmdir vektor/targets/agents vektor/targets/rag

# Step 4: Delete old research docs
rm -rf _archive/internal_docs/CLAUDE_RESEARCH.md
rm -rf _archive/internal_docs/PROJECT_BIBLE.md
rm -rf _archive/internal_docs/PRODUCT_PLAN.md
rm -rf _archive/internal_docs/SPRINT_PLAN.md
rm -rf _archive/internal_docs/outputs/
rm -rf _archive/generated/

# Step 5: Update .gitignore
# Add these lines:
# examples/target_app.py
# examples/demo_server.py
```

---

## POST-CLEANUP

After cleanup:
1. Run tests: `pytest tests/ -q` (should still pass 219/219)
2. Test CLI: `vektor --help` (should work)
3. Test scan: `vektor scan --target vulnerable` (should work)
4. Update README to mention `examples/` for running demos
5. Commit: `git add . && git commit -m "chore: remove dead code and reorganize demo scripts"`

---

## Result After Cleanup

- **Cleaner package** — no demo scripts in pip install
- **Smaller install size** — removes ~360 KB of dead weight
- **Easier to maintain** — experimental code clearly archived
- **Better for PyPI** — users don't see demo junk when browsing the repo
