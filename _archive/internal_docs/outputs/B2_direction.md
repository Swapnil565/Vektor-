# B2 — Gap & Direction Finder
*Generated: 2026-03-03*

---

## Emerging Attack Surfaces 2025-2026 (New Threats, No Good Tools)

### 1. MCP (Model Context Protocol) — The Hottest New Surface
- Active CVEs discovered in 2025: CVE-2025-6514 (CVSS 9.6 command injection in mcp-remote), sandbox escape in Filesystem-MCP server, tool poisoning, rug pull attacks
- Multiple MCP security scanners launched late 2025 (mcpwn, Cisco AI Defense scanner, Proximity, Snyk agent-scan)
- **Critical gap:** All existing MCP tools scan MCP servers FOR malicious content (defender-side). NOBODY tests your LLM application's behavior AGAINST MCP injection attacks (attacker-simulation side).
- This is exactly the same gap we fill for RAG: not "is this MCP server safe?" but "is your app that uses MCP safe?"

### 2. Agentic AI / Multi-Agent Systems
- Agents with tool-calling capabilities can be hijacked to exfiltrate data, call unauthorized tools, or be redirected to new goals
- msoedov/agentic_security exists but is narrow (jailbreak/fuzzing focused)
- MAESTRO framework exists for threat modeling but no testing tool
- Most devs building with CrewAI, AutoGen, LangGraph have NO security testing

### 3. Vision/Multimodal Injection
- Image-embedded text injection bypasses text filters
- Garak added multimodal support but it's research-grade
- No tool tests this in a CI/CD pipeline

### 4. Many-Shot Jailbreaking
- Already in our roadmap (Phase 3)
- No dedicated open-source test tool exists
- High-profile academic research means developer awareness is growing

### 5. EU AI Act Compliance Reporting
- August 2025 deadline already passed for GPAI model providers
- Developers need automated compliance evidence
- Current tools don't generate OWASP LLM Top 10 / EU AI Act mapped reports

---

## Direction Scoring Matrix

| Direction | Community Demand (1-5) | Competitive Gap (1-5) | Feasibility (1-5) | Total |
|-----------|----------------------|---------------------|-------------------|-------|
| **HTTP Endpoint (`--url` mode)** | 5 | 5 | 5 | **75** |
| **MCP Security Testing** | 5 | 4 | 4 | **80** |
| **Multi-model support** (Anthropic, Gemini, Ollama) | 5 | 2 | 5 | **50** |
| **Agentic AI testing** | 4 | 3 | 3 | **36** |
| **LLM-as-Judge evaluation** | 4 | 3 | 4 | **48** |
| **OWASP + compliance reporting** | 4 | 3 | 5 | **60** |
| **VS Code extension** | 3 | 3 | 3 | **27** |
| **Many-shot jailbreaking** | 3 | 4 | 4 | **48** |
| **Visual/multimodal attacks** | 2 | 4 | 3 | **24** |
| **Web SaaS dashboard** | 3 | 2 | 2 | **12** |

---

## Top 3 Recommended Directions

### #1 — HTTP Endpoint Target (`--url` mode) [Score: 75]
**What to build:** `llmguard scan --url https://myapp.com/api/chat --header "Authorization: Bearer $TOKEN"`

**Why this is #1:**
- This is the NORTH STAR feature. Every real user wants to test THEIR app, not OpenAI in isolation.
- No competitor does this. Garak and PyRIT test model APIs. Nobody tests your deployed endpoint with auth headers.
- It's already Phase 1 of the roadmap and technically straightforward.
- It's the feature that changes "I ran it once" to "I run it on every deploy."

**What to build:**
- `llmguard/targets/http_endpoint.py` — accepts URL + auth headers, sends attack payloads as POST
- `--url`, `--header` CLI flags
- Configurable request/response field names
- Latency tracking instead of cost tracking

**Impact on stars:** This is the feature that makes the demo undeniable. "I pointed it at my app and it found real vulnerabilities."

---

### #2 — MCP Security Testing [Score: 80]
**What to build:** `llmguard scan --mcp-server stdio://path/to/server` or `--target mcp`

**Why this is #2:**
- Hottest new attack surface. Every week there are new MCP CVEs.
- All existing MCP tools are DEFENSIVE (scan servers for bad content). None are OFFENSIVE (test if your app is vulnerable to MCP injection).
- If we're first to market with "MCP security testing FROM THE ATTACK SIDE," we own that narrative.
- Our existing attack framework maps directly to MCP injection scenarios.

**The key differentiation:** Existing tools (mcpwn, Proximity, Cisco scanner) = "scan this MCP server, is it malicious?" Our tool = "I'm building an app that uses MCP — am I vulnerable to MCP injection attacks?"

**What to build:**
- New attack category: "MCP Injection"
- Attacks: tool_output_injection, resource_poisoning, prompt_in_tool_description, rug_pull_simulation
- Target: MCPEndpointTarget that speaks MCP protocol
- Could be a separate plugin: `pip install llmguard-lite[mcp]`

**Impact on stars:** Being "the MCP security testing tool" gets you listed in every MCP security article. This is the 1000-star feature.

---

### #3 — OWASP LLM Top 10 + Compliance Reporting [Score: 60]
**What to build:** Every finding tagged with OWASP LLM category. Export as compliance PDF.

**Why this is #3:**
- Zero extra development cost (just add metadata to existing attacks)
- Immediately gives enterprise teams a reason to use the tool ("we have OWASP coverage")
- EU AI Act deadline passed in Aug 2025 — compliance reporting is an active pain point
- Gets us listed in OWASP community resources

**What to build:**
- Tag all 15 attacks with OWASP LLM Top 10 category in registry
- Show tags in HTML/JSON reports
- Add `--compliance owasp` flag to generate compliance-formatted PDF

**Impact on stars:** Not viral itself, but unlocks enterprise adoption and gets us into OWASP-community distribution channels.

---

## The Single Highest-Impact Next Feature

**`--url` HTTP endpoint testing.**

This is the feature that makes the tool real. Right now we test OpenAI's API in isolation. With `--url`, we test your actual product. That changes the value proposition from "interesting research tool" to "I need this before every deploy."

Build this first. Ship in v0.2.

---

## Roadmap to v1.0

### v0.2 — Make It Real (Target: 30 days)
- `llmguard scan --url https://myapp.com/api/chat` (HTTP endpoint target)
- OWASP LLM Top 10 tags on all findings
- LLM-as-judge evaluation (`--judge` flag)
- Evidence capture in reports (show exact request/response)
- Multi-model: Anthropic Claude + Gemini support
- Goal: 200 stars, developer community takes us seriously

### v0.3 — New Attack Surface (Target: 60 days)
- MCP security testing module (`pip install llmguard-lite[mcp]`)
- Indirect prompt injection (email, web content, tool output simulation)
- Many-shot jailbreaking
- Crescendo multi-turn attack
- GitHub Action in marketplace
- Goal: 500 stars, featured in tl;dr sec newsletter

### v1.0 — The Enterprise-Ready Release (Target: 90-120 days)
- VS Code extension (system prompt scanner)
- Compliance PDF reports (OWASP, EU AI Act)
- Agentic AI security testing
- Remediation guides by framework (LangChain, LlamaIndex)
- Web dashboard (basic, read-only)
- Goal: 1000+ stars, enterprise adoption begins
