# A1 — Competitor Analysis
*Generated: 2026-03-02*

---

## Competitor Overview Table

| Tool | Stars | Last Updated | CI/CD | Doc/RAG Injection | Cost Controls | Status |
|------|-------|-------------|-------|-------------------|---------------|--------|
| **Promptfoo** | 10.7k | Feb 18, 2026 | ✅ Yes | ⚠️ Partial (poisons docs, doesn't test hidden text) | ❌ No | Very Active |
| **Garak** (NVIDIA) | 6.9k | Active 2026 | ❌ No | ❌ No | ❌ No | Active |
| **PyRIT** (Microsoft) | 3.5k | Feb 6, 2026 | ❌ No | ❌ No | ❌ No | Active |
| **LLM Guard** (ProtectAI) | 2.6k | Dec 2025 | ⚠️ Partial | ❌ No | ❌ No | Active |
| **Rebuff** (ProtectAI) | 1.4k | Unknown | ❌ No | ❌ No | ❌ No | Unclear |
| **DeepTeam** | Unknown | 2025 | ❌ No | ❌ No | ❌ No | New |
| **agentic_security** | ~500 | 2025 | ❌ No | ❌ No | ❌ No | Active |
| **Agentic Radar** (splx-ai) | Unknown | 2025 | ❌ No | ❌ No | ❌ No | New |
| **LLMFuzzer** | Low | Stale | ⚠️ Partial | ❌ No | ❌ No | Stale |
| **LLMGuard-Lite** | 0 | Mar 2026 | ✅ Yes | ✅ Yes (UNIQUE) | ✅ Yes (UNIQUE) | Launching |

---

## Top 3 Competitors — Deep Analysis

### 1. Promptfoo (10.7k stars — THE market leader)

**What it is:** CLI + library for LLM evaluation and red teaming. Tests prompts, agents, and RAGs across GPT/Claude/Gemini/Llama. Full CI/CD GitHub Action support.

**Who uses it:** Developers building LLM apps who want to test quality + security in one tool. Most downloaded LLM testing tool.

**Key weaknesses:**
- Not a dedicated security tool — it's eval + security combined, diluting both
- Requires YAML config setup — non-trivial onboarding
- No cost controls — no budget caps to avoid runaway API spending
- Document injection testing is limited to "RAG poisoning" (inserting docs into retrieval), does NOT test hidden text injection, DOCX footnote injection, or format-specific exploits
- Not opinionated — you have to configure what to test; LLMGuard-Lite runs 15 attacks with zero config
- "Built for developers" — security teams find it complex

**Our advantage:** We run in 30 seconds with zero config. $0.50 with budget controls. We test document FORMAT vulnerabilities (DOCX hidden text, footnotes) that promptfoo doesn't. We give a risk score, not just pass/fail results.

---

### 2. Garak — NVIDIA (6.9k stars)

**What it is:** The "nmap of LLMs." 100+ probe modules, static + dynamic + adaptive attacks. Research-grade scanner.

**Who uses it:** Researchers, ML security engineers. The de facto academic standard.

**Key weaknesses:**
- One-shot attack methodology — "doesn't learn or adapt to your specific app"
- Designed to test models in isolation, not your deployed application
- No CI/CD integration — can't put in a pipeline
- No cost controls
- Complex to configure — not a 30-second experience
- "Limited effectiveness for RAG pipelines and multi-turn agent scenarios"
- Research-focused; not designed for dev workflows

**Our advantage:** We're the developer-facing counterpart. Faster, cheaper, deployable in CI/CD, focused on your actual app not just the base model. We complement Garak (they go deep on model research; we test your app).

---

### 3. PyRIT — Microsoft Azure (3.5k stars)

**What it is:** Python red teaming framework. Batch-generates adversarial prompts, multi-turn attack flows, adaptive based on responses.

**Who uses it:** Enterprise security teams, Microsoft ecosystem, researchers.

**Key weaknesses:**
- Steep learning curve — "expect to code your flows"
- Not suitable for quick, out-of-the-box use
- Enterprise/Azure-first — cross-platform compatibility issues
- No CI/CD native integration
- No cost controls
- Requires significant coding knowledge to use

**Our advantage:** Zero config to first result. pip install + one command. No Python boilerplate needed. Developer-friendly UX vs PyRIT's research-lab UX.

---

## Competitive Gaps (What NO Tool Does Well)

1. **Document-format-specific injection** — No tool tests DOCX hidden text, footnote injection, Markdown comment injection. This is our primary novel contribution.
2. **Cost controls** — No tool has budget caps to prevent $50 accidental scan runs.
3. **30-second zero-config experience** — Every tool requires setup. We're the first true zero-config scanner.
4. **Test your actual deployed app** — Most tools test the LLM API directly. Nobody has `--url https://myapp.com/api/chat` with real auth headers.
5. **$0.50 accessible price point** — Tools either cost nothing (no API) or have uncontrolled costs.
6. **MCP security testing** — Zero tools test Model Context Protocol vulnerabilities (brand new attack surface with active CVEs).
7. **CI/CD-native with exit codes** — Promptfoo has CI support but it's not security-gate oriented. We return exit code 2 on critical risk.

---

## Our Unique Position

**Honest assessment:**
- We are NOT the research powerhouse (Garak is)
- We are NOT the enterprise multi-tool (PyRIT is)
- We ARE the fastest path from "I built an LLM app" to "I know if it's vulnerable"

**Where we clearly win:**
- Document/RAG injection testing (0 competitors)
- Cost controls with budget caps (0 competitors)
- Zero-config 30-second scan (0 competitors at this speed)
- CI/CD security gate with exit codes (strongest in class)

**Where we're behind:**
- Total attack count (Garak has 100+, we have 15)
- Multi-model support (only OpenAI today)
- Community size (need to build this)

---

## Table Stakes (Must-Haves to Be Taken Seriously)

1. ✅ Prompt injection detection
2. ✅ CI/CD integration
3. ✅ JSON + HTML reports
4. ✅ pip installable
5. ✅ Docker support
6. ❌ **OWASP LLM Top 10 tagging** (not yet in reports — needed)
7. ❌ **Multi-model support** (only OpenAI — Anthropic/Gemini/Ollama needed for v0.2)
8. ❌ **Active community** (Discord/Slack presence)

---

## Namespace Check

- PyPI: `llmguard-lite` — available (the existing `llm-guard` by ProtectAI is different)
- GitHub: `llmguard-lite` — available
- `llmguard` (without `-lite`) — ProtectAI has `llm-guard` (hyphenated, different package)
- **Risk:** Low. Our name is distinct enough. But in docs, always clarify we're NOT ProtectAI's LLM Guard.
