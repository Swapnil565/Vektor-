# A2 — Community Pulse Report
*Generated: 2026-03-02*

---

## Hacker News Findings

Several relevant Show HN posts from late 2025 - early 2026:

- **"Show HN: SiteIQ – LLM and Web security testing tool"** (Nov 2025) — Community immediately audited the code and found command injection, no API auth, SSRF. Creator clarified it's a localhost tool. Key signal: the community TESTS security tools for security issues. We need to be clean.

- **"Show HN: Open-Source Gateway to Stop Tool-Abusing Prompt Injections"** (Oct 2025) — Addresses agent-level injection where attackers hijack LLM tools. High engagement signal — agent security is the hot topic.

- **"Show HN: LLM Shield"** (Jan 2026) — Real-time prompt injection firewall. Shows live demand for runtime detection tools.

- **"Show HN: Open-source taxonomy of 122 AI/LLM attack vectors"** (Jan 2026) — A taxonomy repo got traction. **Signal: research + taxonomy content outperforms pure tool launches on HN.** Framing our novel research (doc injection) as a taxonomy/research post may outperform a plain tool post.

- **"Show HN: I solved Claude Code's prompt injection problem"** (Feb 2026) — Very recent, high signal that MCP/agent injection is a live concern in developer community right now.

**HN pain points extracted:**
- "How do I know if my RAG pipeline is vulnerable?"
- "Existing tools test the model, not my app"
- "Too much setup to get first results"
- Security teams reviewing LLM tools expect clean code

---

## Reddit Signal (Inferred from industry coverage)

Subreddits active in this space: r/netsec, r/MachineLearning, r/LocalLLaMA, r/devops, r/cybersecurity

**What gets upvoted in r/netsec:**
- Practical tool releases with clear "here's what it found" demo outputs
- Novel attack research (first-to-publish gets cited)
- CI/CD security integration content

**What gets upvoted in r/LocalLLaMA:**
- Tools that work with local models (Ollama, etc.)
- Anything that exposes vulnerabilities in LLM apps people are building
- Simple one-command tools

**What gets upvoted in r/MachineLearning:**
- Research-backed claims with evidence
- The document injection findings (60% of RAG systems vulnerable) would resonate here

---

## Industry Community Pain Points

Based on tool comparison articles, HN threads, and developer documentation gaps:

### Top 10 Pain Points (ranked by frequency)

1. **"Tools test the LLM, not my app"** — Developers want to test their actual deployed endpoint, not OpenAI in isolation. The gap between "model is safe" and "my app is safe" is huge and unaddressed.

2. **"Too complex to set up"** — PyRIT requires coding. Garak requires understanding probe modules. Nobody gives you results in 30 seconds.

3. **"No cost controls"** — Running red teaming tools accidentally against expensive models costs real money. Nobody has built-in budget caps.

4. **"How do I test RAG/document pipelines?"** — RAG security is a known concern but testing tools are vague. Nobody tests format-specific attacks (hidden text, footnotes).

5. **"Can't put it in CI/CD"** — Most tools are research tools, not pipeline tools. Developers want a security gate with exit codes.

6. **"Results aren't actionable"** — Generic "HIGH risk" findings without the actual request/response evidence. No OWASP mapping.

7. **"I don't know what MCP attack surface looks like"** — MCP is brand new with active CVEs and zero dedicated testing tools.

8. **"Multi-model support"** — Developers use GPT-4, Claude, and Gemini. Tools that only test one provider miss most of the market.

9. **"No compliance reporting"** — Enterprise needs OWASP LLM Top 10, SOC2, EU AI Act mapping. Nobody generates these automatically.

10. **"Awareness gap on indirect injection"** — Most devs know about direct prompt injection, but don't know about document-based injection in RAG, email injection in agents, or tool-output injection.

---

## Feature Requests (What People Ask For)

- `llmguard scan --url https://myapp.com/api/chat` — test actual app, not just base model
- One-command scan with zero config ("like nmap but for LLMs")
- OWASP LLM Top 10 mapping on every finding
- Budget controls (`--budget 1.0`)
- MCP server security scanner
- Local model support (Ollama)
- VS Code extension for system prompt scanning
- Evidence capture (show me the exact request + response that proved vulnerability)
- Remediation code examples by framework (LangChain, LlamaIndex, etc.)

---

## Target Audience Profile

**Primary user: The AI developer who just shipped a feature**
- Works at a startup or mid-size company
- Just integrated GPT-4/Claude into a product feature
- Has no formal security background
- Got asked "is this safe?" by their CTO or a customer
- Has 30 minutes, not 2 weeks
- Will run the tool, share the report, move on

**Secondary user: DevSecOps engineer**
- Wants to add LLM security gates to CI/CD pipeline
- Familiar with existing security tooling (Snyk, SonarQube)
- Wants exit codes, JSON reports, badge support
- Will actually read the OWASP mappings

**Tertiary user: Security researcher**
- Wants to find new attack vectors
- Will fork and extend
- Will cite the novel research

**NOT our user (today):**
- Enterprise CISO wanting compliance dashboards (Phase 4 product)
- ML researchers wanting to test model alignment (Garak's territory)
- Runtime production monitoring (different product category)

---

## Viral Trigger Analysis

**What spreads in the LLM security community:**

1. **Novel attack research** — "We found that 60% of RAG systems are vulnerable to hidden text injection" is a headline. File this as a blog post, not just a README bullet.

2. **Demo GIFs/videos showing a real attack working** — Seeing a terminal output where an attack succeeds on a known vulnerable app is visceral and shareable.

3. **Comparison tables** — "We tested 5 AI assistants and here's what each one leaked" gets cited everywhere.

4. **OWASP/compliance hooks** — "Maps to OWASP LLM Top 10" is a one-liner that gets enterprise developers to pay attention.

5. **The "I just ran this on my app" story** — User-generated content where a developer shares what they found. We need to make this easy (copy-pasteable report share link).

6. **MCP/agentic security content** — Currently the hottest topic in AI security. First tool that can test MCP servers gets covered everywhere.

---

## Awareness Gap Assessment

| Topic | Community Awareness | Our Coverage |
|-------|--------------------|----|
| Direct prompt injection | HIGH — well understood | ✅ Covered |
| System prompt extraction | HIGH — well understood | ✅ Covered |
| Document-based RAG injection | MEDIUM-LOW — known in research, unknown to most devs | ✅ UNIQUE |
| DOCX hidden text injection | LOW — mostly unknown | ✅ UNIQUE |
| MCP security | GROWING FAST — 2025-2026 hot topic | ❌ Not yet |
| Agentic AI attacks | GROWING — 2025 new territory | ❌ Not yet |
| Cost controls on testing | LOW — nobody thinks about it | ✅ UNIQUE |
| CI/CD LLM security gates | LOW — most devs don't do this | ✅ COVERED |

**Key insight:** The community is WHERE WE ARE on prompt injection awareness. We should lead with the document injection research angle — it's novel enough to generate "I didn't know this was a thing" reactions that drive sharing.
