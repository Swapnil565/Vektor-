# LLMGuard-Lite — Market Intelligence & Growth Report
*Synthesized: 2026-03-03 | Sources: A1, A2, B1, B2, C1, C2*

---

## TL;DR (Read This First)

**Honest verdict: Yes, this gets to 1000+ stars — but only if you ship the GIF and the URL mode.**

The tool is real. The novel angle (document injection) is genuinely differentiated. The timing is good. But the README currently has no visual hook, the namespace has a near-conflict, and the single most-wanted feature (test your actual deployed app) isn't built yet.

**Biggest opportunity right now:** MCP security testing. Zero tools do attacker-simulation MCP testing. Every week there are new MCP CVEs. Being first = owning that narrative.

**Biggest threat right now:** Promptfoo at 10.7k stars has CI/CD, red teaming, and RAG testing in one package. The risk is being dismissed as "Promptfoo but smaller." The counter is our zero-config experience, cost controls, and document injection specificity — but that story needs to be told louder in the README.

**The ONE thing to do this week:** Record a 60-second terminal GIF of `llmguard scan --target vulnerable` and put it at the top of the README. This is the difference between 50 and 500 launch stars.

**Star projection:**
- 30 days: 100-150 (with proper launch)
- 90 days: 300-500 (with v0.2 `--url` mode + content)
- 180 days: 700-1500 (with MCP plugin + newsletter coverage)

---

## Competitive Position

### The Landscape
The LLM security space has 4 major players:

| | Garak | Promptfoo | PyRIT | LLMGuard-Lite |
|---|---|---|---|---|
| **Stars** | 6.9k | 10.7k | 3.5k | launching |
| **Speed to first result** | Complex | Complex | Very complex | **30 seconds** |
| **Cost controls** | ❌ | ❌ | ❌ | **✅** |
| **Zero config** | ❌ | ❌ | ❌ | **✅** |
| **Document injection** | ❌ | ❌ | ❌ | **✅** |
| **CI/CD native** | ❌ | ✅ | ❌ | **✅** |
| **Test deployed app URL** | ❌ | ❌ | ❌ | ✅ (v0.2) |
| **Model-in-isolation testing** | ✅ | ✅ | ✅ | ✅ |

### Where We Win (Clearly)
1. **Document/format-specific injection** — DOCX hidden text, footnotes, Markdown comments. Nobody else tests this. 0 competitors.
2. **Zero config + 30 seconds** — Genuinely the fastest path to first result. This matters to the startup developer who has 30 minutes, not 2 weeks.
3. **Cost controls** — $0.50/scan with `--budget` flag. Nobody else has this. Prevents accidental $50 scan runs.
4. **CI/CD as a security gate** — Exit code 2 on critical risk. Promptfoo has CI but it's not opinionated about security gating.

### Where We're Behind
- Total attack count (Garak: 100+, us: 15) — solve with MCP plugin + v0.3 attacks
- Multi-model support (only OpenAI now) — fix in v0.2
- Community size — solve with launch playbook

### Is Document Injection Strong Enough as the Differentiator?
**Yes, but only if we frame it as research, not just a feature.** "First tool to systematically test document-based instruction hijacking" is the headline. "60% of RAG systems failed" is the proof. Without the research angle, it's just a bullet point. With it, it's a citation-worthy finding that developers share.

---

## What the Community Actually Wants

### Top 5 Pain Points (from real conversations)

1. **"Tools test the LLM, not my app"** — Developers want to scan their deployed endpoint, not OpenAI in isolation. This is the #1 unmet need across all platforms.

2. **"Too complex to set up"** — PyRIT requires coding your own flows. Garak needs probe module configuration. Nobody gives results in 30 seconds with zero config.

3. **"No cost controls"** — Accidentally running red teaming against GPT-4 can be expensive. Budget caps exist nowhere else.

4. **"Results aren't actionable"** — "HIGH risk" findings without the actual request/response that proved it, without OWASP mapping, without framework-specific fixes = interesting but not usable.

5. **"MCP attack surface is dark"** — Developers building with MCP have no testing tool. Multiple CVEs, no way to test their own implementation.

### Feature Requests (Ranked)
1. `llmguard scan --url https://myapp.com/api/chat` — deploy test, not model test
2. OWASP LLM Top 10 mapping on every finding
3. Claude/Gemini/Ollama support
4. MCP security testing
5. Evidence capture (exact request + response per finding)
6. VS Code extension
7. Remediation code examples by framework

### Who Our Actual User Is
**The primary user** is a developer at a 5-50 person startup who just shipped a GPT-4 feature. Their PM or CTO asked "is this secure?" They have 30 minutes. They've heard of prompt injection but haven't had time to research it. They want to run one command, get a risk score, and either fix the findings or show the report. They will become a repeat user if the experience is fast and the results are real.

**The secondary user** is a DevSecOps engineer adding LLM security gates to a CI/CD pipeline. They want exit codes, JSON, badges. They'll read the OWASP mappings. They're the person who adds the GitHub Action.

---

## Product Direction

### Top 3 Directions (Scored)

**#1 — HTTP Endpoint Target (`--url` mode) — Build in v0.2**
- Demand: 5/5 | Gap: 5/5 | Feasibility: 5/5
- The north star feature. Changes "interesting tool" to "I need this."
- CLI: `llmguard scan --url https://myapp.com/api/chat --header "Authorization: Bearer $TOKEN"`
- Already specced in PRODUCT_PLAN.md Phase 1.

**#2 — MCP Security Testing Plugin — Build in v0.3**
- Demand: 5/5 | Gap: 4/5 | Feasibility: 4/5
- All existing MCP scanners are defender-side. We're attacker-simulation.
- Full spec in C1_plugin_spec.md.
- This is the feature that generates media coverage.

**#3 — OWASP + Compliance Reporting — Build in v0.2 (low effort)**
- Demand: 4/5 | Gap: 3/5 | Feasibility: 5/5
- Tagging all 15 attacks with OWASP category is 2 hours of work.
- Unlocks enterprise adoption and OWASP community distribution.
- Already in PRODUCT_PLAN.md Phase 1 section 1.5.

### The Killer Plugin Spec (Ready to Implement)
See `C1_plugin_spec.md` for full spec. Summary:
- Package: `pip install llmguard-lite[mcp]`
- Tests 7 MCP attack scenarios: tool output injection, description poisoning, resource injection, tool escalation, goal hijacking, data exfiltration, rug pull
- ~900 lines of new code, integrates with existing BaseAttack
- Launch timing: alongside a "first tool to test LLM apps against MCP injection" blog post

### Roadmap to v1.0 (The 1000-Star Version)

**v0.2 (30 days):** `--url` mode + OWASP tags + evidence capture + multi-model
**v0.3 (60 days):** MCP plugin + indirect injection attacks + GitHub Action in marketplace
**v1.0 (90-120 days):** VS Code extension + compliance reports + agentic testing

---

## GitHub Stars Growth Plan

### README Changes to Make This Week (Before Any Launch)
1. **Add demo GIF** — record `llmguard scan --target vulnerable`, put at line 1
2. **Fix contact info** — replace placeholder email/Twitter with real accounts
3. **Add comparison table** — us vs Garak vs Promptfoo vs PyRIT
4. **Move RAG finding higher** — "60% of RAG systems vulnerable" should be in top half
5. **Add OWASP mention** — one line in the intro section

### Launch Sequence
- **Day 1:** r/netsec — "Scan your LLM app for prompt injection in 30 seconds"
- **Day 2:** r/MachineLearning — "60% of RAG pipelines failed document injection test"
- **Day 3:** Hacker News Show HN — be in the thread for the first hour
- **Day 4:** Dev.to blog post — research post, tool is the footnote
- **Week 2:** tl;dr sec submission + Dev.to CI/CD tutorial + 5 awesome-list PRs
- **Week 3:** OWASP LLM Slack + Simon Willison DM + Johann Rehberger outreach
- **Week 4:** Amplify what worked, pivot from what didn't

### Content to Create (Priority Order)
1. Demo GIF (Week 0 — required for launch)
2. Research post: "We tested 10 RAG setups for hidden text injection" (Week 1)
3. Tutorial: "Add LLM security to your GitHub Actions in 5 minutes" (Week 2)
4. Tweet thread: "Your MCP agent is probably vulnerable to tool injection" (Week 3)

### Lists and Communities to Get Into

**Awesome lists (submit PRs immediately after launch):**
- `corca-ai/awesome-llm-security` (1.5k stars) — highest priority
- `TalEliyahu/Awesome-AI-Security` — maintainer also runs AI Security Newsletter
- `tenable/awesome-llm-cybersecurity-tools` — Tenable's brand = enterprise credibility
- `kaplanlior/oss-llm-security`
- `raphabot/awesome-cybersecurity-agentic-ai`

**Newsletters to submit to:**
- tl;dr sec (Clint Gibler) — tldrsec.com submission form
- AI Security Newsletter (Tal Eliyahu) — LinkedIn DM

**Communities to post in:**
- OWASP GenAI Slack #tools channel
- MCP Discord/GitHub Discussions
- r/netsec, r/MachineLearning, r/LocalLLaMA

---

## Realistic Projections

| Milestone | Timeline | What unlocks it |
|-----------|----------|-----------------|
| 100 stars | Week 1-2 | HN Show HN + Reddit launch + personal network |
| 300 stars | Month 1-2 | tl;dr sec feature + awesome list additions + Dev.to post trending |
| 500 stars | Month 2-3 | v0.2 `--url` mode ships + CI/CD tutorial spread |
| 1000 stars | Month 4-6 | MCP plugin launch + research citations + organic CI/CD spread |
| 2000+ stars | 6-12 months | Tool being used in production, user-generated content, enterprise adoption |

**The fastest path to 1000:** Ship the GIF + launch on HN + get in tl;dr sec + ship MCP plugin. In that order.

---

*Research pipeline complete. All outputs in `/outputs/`. Run time: 1 session.*
