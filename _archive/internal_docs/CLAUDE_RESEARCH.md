# LLMGuard-Lite — Market Research & GitHub Growth Intelligence
## Claude Code Agent System

---

## ▶️ HOW TO RUN

```bash
claude "Read CLAUDE_RESEARCH.md and run the full market research pipeline.
Check outputs/PROGRESS.md and skip any agent already marked DONE."
```

## 🔁 RESUME AFTER RATE LIMIT

```bash
claude "Read CLAUDE_RESEARCH.md and outputs/PROGRESS.md. Resume from last completed checkpoint."
```

---

## 📋 PROJECT CONTEXT

**Project:** LLMGuard-Lite — automated LLM security testing framework
**Core value:** Scan LLM apps for prompt injection, data extraction, and document-based
instruction hijacking in 30 seconds for $0.50
**Novel angle:** First tool to systematically test document-based instruction hijacking in RAG systems
**Goal:** Maximum GitHub stars, real-world adoption in AI security community
**Distribution:** Open source, pip installable, Docker ready, CI/CD ready

---

## 🏗 AGENT ARCHITECTURE

```
ORCHESTRATOR
├── PHASE 1: MARKET INTELLIGENCE
│   ├── Agent A1 — Competitor Scanner (what exists, what's missing)
│   └── Agent A2 — Community Pulse (Reddit, HN, Twitter/X, Discord)
│
├── PHASE 2: OPPORTUNITY ANALYSIS
│   ├── Agent B1 — GitHub Stars Analyst (what makes security tools go viral)
│   └── Agent B2 — Gap & Direction Finder (what should we build next)
│
└── PHASE 3: EXECUTION
    ├── Agent C1 — Plugin Spec Generator (the killer Python plugin)
    └── Agent C2 — Growth Playbook (exact steps to get stars)

FINAL: SYNTHESIZER → outputs/MASTER_REPORT.md
```

---

## ⚙️ SETUP

```bash
pip install requests
mkdir -p outputs
```

---

# AGENT A1 — Competitor Scanner
**Output:** `outputs/A1_competitors.md`
**Check PROGRESS.md — if A1: DONE, skip.**

```
AGENT A1 INSTRUCTIONS:

Read the project context above fully.

Search the web and GitHub for the current LLM security testing landscape.
Your job: find everything that exists, what they do, what they miss,
and where LLMGuard-Lite has a clear opening.

SEARCH TARGETS:

Web search these queries one by one:
  - "LLM security testing tools 2024 2025"
  - "prompt injection scanner open source"
  - "LLM red teaming framework GitHub"
  - "RAG security testing tool"
  - "OWASP LLM Top 10 testing tools"
  - "AI security scanner CI/CD pipeline"
  - "llm pentest tool open source"
  - "garak llm security"
  - "promptfoo security testing"
  - "rebuff prompt injection detection"

GitHub search:
  - "LLM security" sorted by stars
  - "prompt injection" sorted by stars
  - "AI red teaming" sorted by stars
  - Note top 10 repos: name, stars, last commit date, what it does

SPECIFICALLY CHECK THESE KNOWN TOOLS:
  - Garak (NVIDIA's LLM vulnerability scanner)
  - Promptfoo (LLM testing framework)
  - Rebuff (prompt injection detection)
  - PyRIT (Microsoft's red teaming tool)
  - LLM Fuzzer
  - PromptBench
  - Any tool with "llmguard" in the name (namespace conflict check)

FOR EACH MAJOR COMPETITOR:
  - GitHub stars
  - Last updated
  - What it does
  - Does it test document injection? YES/NO
  - Does it have CI/CD integration? YES/NO
  - Does it have cost controls? YES/NO
  - Main weakness from user complaints
  - Our advantage over this tool

POSITIONING ANALYSIS:
  1. What does EVERY tool do? (table stakes)
  2. What does NO tool do well? (our opportunity)
  3. Where is the document/RAG security gap?
  4. What do users complain about across all tools?
  5. What's the most starred LLM security tool and WHY?

OUTPUT: outputs/A1_competitors.md
  - Competitor overview table
  - Top 3 competitors full analysis
  - Competitive gaps list
  - Our unique position
  - Table stakes we must have

Update PROGRESS.md: AGENT_A1: DONE
```

---

# AGENT A2 — Community Pulse
**Output:** `outputs/A2_community.md`
**Check PROGRESS.md — if A2: DONE, skip.**

```
AGENT A2 INSTRUCTIONS:

Search community platforms for real conversations about LLM security pain points.

SEARCH TARGETS:

Reddit:
  - site:reddit.com "prompt injection" security tool
  - site:reddit.com "LLM security" scanner
  - site:reddit.com "RAG security" vulnerability
  - Subreddits: r/netsec, r/MachineLearning, r/LocalLLaMA, r/cybersecurity, r/devops

Hacker News:
  - site:news.ycombinator.com "prompt injection"
  - site:news.ycombinator.com "LLM security"
  - site:news.ycombinator.com "AI red teaming"

Dev.to / Medium:
  - "LLM security testing" articles 2024-2025
  - What problems do developers describe?

Twitter/X via web search:
  - "prompt injection tool"
  - "LLM security scanner"

EXTRACT FROM EACH PLATFORM:
  1. Top pain points mentioned repeatedly
  2. Feature requests people ask for
  3. Frustrations with existing tools
  4. Who is talking about this (researchers? devs? DevOps? CTOs?)
  5. What posts got most engagement and why

SPECIFICALLY LOOK FOR:
  - Has anyone mentioned LLMGuard-Lite?
  - Are people aware of document injection attacks in RAG?
  - Do CI/CD teams know they should be LLM security testing?
  - What's awareness level of OWASP LLM Top 10?

OUTPUT: outputs/A2_community.md
  - Platform by platform findings
  - Top 10 pain points ranked by frequency
  - Feature requests
  - Target audience profile (primary/secondary/not our user)
  - Viral trigger analysis (what gets shared in this community)
  - Awareness gap assessment

Update PROGRESS.md: AGENT_A2: DONE
```

---

# AGENT B1 — GitHub Stars Analyst
**Output:** `outputs/B1_stars_analysis.md`
**Check PROGRESS.md — if B1: DONE, skip.**
**Reads:** A1 + A2 outputs.

```
AGENT B1 INSTRUCTIONS:

Read A1 and A2 outputs. Reverse-engineer why security/AI tools go viral on GitHub.

RESEARCH TARGETS:

Search for growth stories:
  - "garak prompt injection" growth story
  - "how promptfoo got github stars"
  - "AI security tool went viral 2024 2025"
  - Security tools that crossed 1000 stars fast

Also search:
  - "best AI security tools 2025" listicles
  - "awesome LLM security" GitHub lists
  - "OWASP LLM Top 10 tools" lists
  - Top security newsletters featuring open source tools

ANALYZE FOR TOOLS THAT GREW FAST:
  1. Launch strategy — where did they first post?
  2. README quality — what do viral READMEs have in common?
  3. Demo/hook — what's the 30-second wow moment?
  4. Community triggers — which newsletters and influencers shared them?
  5. Timing — did they launch around relevant news events?

LISTICLE RESEARCH:
Find top 10 "awesome lists" covering LLM security:
  - awesome-llm-security GitHub repos
  - awesome-ai-security repos
  - Blog posts ranking security tools

OUTPUT: outputs/B1_stars_analysis.md
  - 5 key viral patterns with examples
  - README best practices from top-starred tools
  - Launch playbook (platform by platform)
  - Top aggregators and lists to get listed on (with how to submit)
  - Influencers and newsletters in this space
  - Our viral potential: strongest hook, weakest point, highest-leverage change

Update PROGRESS.md: AGENT_B1: DONE
```

---

# AGENT B2 — Gap & Direction Finder
**Output:** `outputs/B2_direction.md`
**Check PROGRESS.md — if B2: DONE, skip.**
**Reads:** All previous outputs.

```
AGENT B2 INSTRUCTIONS:

Read all previous outputs. Find exact direction LLMGuard-Lite should evolve.

RESEARCH CURRENT TRENDS:
  - "AI security vulnerabilities 2025"
  - "agentic AI security risks"
  - "MCP security vulnerabilities" (Model Context Protocol — very new)
  - "function calling injection attack"
  - "vision language model attacks"
  - "multi-agent system vulnerabilities"
  - "Claude Gemini GPT-4 security 2025"

EVALUATE THESE DIRECTIONS (community demand + competitive gap + feasibility):

  1. Multi-model support (Anthropic, Gemini, Ollama, local models)
  2. Agentic AI / multi-agent security testing (new territory)
  3. MCP security testing (brand new, zero existing tooling)
  4. Visual/multimodal attack testing (image injection)
  5. Compliance reporting (SOC2, EU AI Act)
  6. VS Code / IDE plugin
  7. Web dashboard / SaaS lite

RANK ALL DIRECTIONS:
Score: Community Demand (1-5) x Competitive Gap (1-5) x Feasibility (1-5)
Pick top 3.

OUTPUT: outputs/B2_direction.md
  - Emerging attack surfaces 2025 (new threats no tool covers)
  - Direction scoring matrix
  - Top 3 recommended directions with what to build
  - The single highest-impact next feature
  - Roadmap: v0.2 / v0.3 / v1.0

Update PROGRESS.md: AGENT_B2: DONE
```

---

# AGENT C1 — Plugin Spec Generator
**Output:** `outputs/C1_plugin_spec.md`
**Check PROGRESS.md — if C1: DONE, skip.**
**Reads:** All previous outputs.

```
AGENT C1 INSTRUCTIONS:

Read all previous outputs. Design the killer Python plugin.

The plugin must be:
  - Simple to install: pip install llmguard-lite[plugin-name]
  - Immediately useful (solves real pain point from A2)
  - Shareable (something people demo to colleagues)
  - Novel (not in any competitor tool per A1)

Most likely best candidate based on research: MCP security scanner
or agentic AI security tester (new attack surface, zero tooling exists)

FOR THE CHOSEN PLUGIN SPECIFY:

  Plugin name:
  One-line description:
  Why this doesn't exist anywhere else:
  Who needs this immediately:

  Installation: pip install llmguard-lite[plugin-name]

  Basic 5-line Python usage example

  CLI usage example

  What it tests (every check it runs)

  Sample terminal output (realistic)

  Technical architecture:
    - Core class structure
    - Integration with existing BaseAttack class
    - External dependencies (keep minimal)
    - Approximate lines of code

  Full Python implementation skeleton:
    - Class definitions
    - Method signatures with docstrings
    - Core logic in comments
    - Integration points
    - Everything except actual attack payload strings

  Test cases

  README section for this plugin

  GitHub Actions YAML snippet

OUTPUT: outputs/C1_plugin_spec.md
  - Plugin choice and rationale
  - Full specification
  - Python code skeleton
  - GitHub Actions integration
  - Launch strategy for this plugin specifically

Update PROGRESS.md: AGENT_C1: DONE
```

---

# AGENT C2 — Growth Playbook
**Output:** `outputs/C2_growth_playbook.md`
**Check PROGRESS.md — if C2: DONE, skip.**
**Reads:** All previous outputs.

```
AGENT C2 INSTRUCTIONS:

Read all previous outputs. Produce concrete week-by-week playbook.
Goal: 500 stars in 90 days, 1000+ in 6 months.
No vague advice. Every action must be specific and executable.

PART 1 — README SURGERY
Based on B1 findings, list exactly what to change:
  - What's strong (keep)
  - What's missing (add)
  - What's weak (fix)
  - Are first 5 lines optimized for instant understanding?
  - Is there a demo GIF? (critical)
  - Is the novel research angle prominent enough?
  List every specific change with reason.

PART 2 — LAUNCH SEQUENCE

Week 1 — Soft Launch:
  Day 1: Post to r/netsec — exact post title
  Day 2: Post to r/MachineLearning — exact post title
  Day 3: Hacker News Show HN — exact title format
  Day 4-7: Engage with feedback

Week 2 — Content Push:
  Blog post topic and title
  Where to post it
  Specific newsletters to submit to

Week 3 — Community Integration:
  Specific awesome-lists to submit to
  OWASP LLM community actions
  Specific influencers to reach out to

Week 4 — Amplification:
  What to do if HN worked / didn't work

PART 3 — CONTENT THAT DRIVES STARS

3 blog post titles that would drive traffic:
  (with target audience and hook for each)

2 Twitter/X thread hooks that would spread in security community

1 YouTube/demo video concept (first 30 seconds hook)

PART 4 — STAR MILESTONES
  0 → 100: how and from where
  100 → 500: what unlocks this jump
  500 → 1000: what's needed
  1000+: what does the tool need to be

PART 5 — REALISTIC PROJECTIONS
  Stars in 30 days if playbook followed:
  Stars in 90 days:
  Stars in 6 months:
  Single biggest accelerator:
  Biggest risk to growth:

OUTPUT: outputs/C2_growth_playbook.md
  Full detail on all 5 parts above.

Update PROGRESS.md: AGENT_C2: DONE
```

---

# FINAL SYNTHESIZER
**Output:** `outputs/MASTER_REPORT.md`
**Check PROGRESS.md — if SYNTHESIZER: DONE, skip.**

```
SYNTHESIZER INSTRUCTIONS:

Read ALL agent output files. Produce one master document.

STRUCTURE:

# LLMGuard-Lite — Market Intelligence & Growth Report

## TL;DR (1 page — read this first)
  - Honest verdict: will this get 1000+ stars?
  - Biggest opportunity right now
  - Biggest threat right now
  - The ONE thing to do this week
  - Star projection: 30 / 90 / 180 days

## Competitive Position
  - Who we're up against and where we win
  - Our unique angle — is document injection strong enough?
  - Table: us vs top 3 competitors feature by feature

## What The Community Actually Wants
  - Top 5 pain points from real conversations
  - Feature requests ranked
  - Who our actual user is (specific profile)

## Product Direction
  - Top 3 directions ranked with scoring
  - The killer plugin spec (ready to implement)
  - Roadmap to v1.0 (the version that hits 1000+ stars)

## GitHub Stars Growth Plan
  - README changes to make this week
  - Launch sequence week by week
  - Content to create
  - Lists and communities to get listed in

## Realistic Projections
| Milestone | Timeline | What unlocks it |
|-----------|----------|-----------------|
| 100 stars | ? weeks  | ? |
| 500 stars | ? weeks  | ? |
| 1000 stars| ? months | ? |

Update PROGRESS.md: SYNTHESIZER: DONE
```
