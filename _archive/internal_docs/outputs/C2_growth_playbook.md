# C2 — Growth Playbook
*Generated: 2026-03-03*
*Goal: 500 stars in 90 days, 1000+ in 6 months*

---

## Part 1 — README Surgery

### What's Strong (Keep)
- The comparison table (Before/After pentest vs llmguard scan) — keep this, it's visceral
- The attack categories breakdown — clear, comprehensive
- The CI/CD GitHub Actions YAML — essential for developer adoption
- "Novel Research: Instruction Hijacking" section — this is the differentiator, keep prominent
- The quick start section structure — works well

### What's Missing (Add — in priority order)

**1. Demo GIF — CRITICAL, add this week**
Record `llmguard scan --target vulnerable` end-to-end. 60 seconds showing: attacks running → findings appearing → risk score. Tool: `asciinema` → `agg` to convert to GIF. Put it immediately after the first heading, before ANY text. This is the #1 highest-leverage single change.

**2. Competitor comparison table — add this week**
```markdown
| Feature | LLMGuard-Lite | Garak | Promptfoo | PyRIT |
|---------|--------------|-------|-----------|-------|
| Zero config | ✅ | ❌ | ❌ | ❌ |
| $0.50/scan | ✅ | ❌ | ❌ | ❌ |
| 30 seconds | ✅ | ❌ | ❌ | ❌ |
| Doc injection testing | ✅ | ❌ | ❌ | ❌ |
| CI/CD native | ✅ | ❌ | ✅ | ❌ |
| Test your app URL | ✅ (v0.2) | ❌ | ❌ | ❌ |
```

**3. OWASP LLM Top 10 badge/mention in the first 10 lines**
Add `[![OWASP](...)` badge or at minimum bold mention. Enterprise developers scan for this.

**4. PyPI download badge** — once published, add `[![PyPI downloads](...)` badge.

**5. Improve novel research callout** — move the document injection research finding closer to the top. Currently buried. "60% of RAG systems vulnerable" should be in the top half of the README.

### What's Weak (Fix)

- **First 5 lines:** Currently "What is LLMGuard-Lite?" heading then bullet list. Should be: GIF → 1-liner description → instant install command. Restructure.
- **No "Used by" or "Trusted by" section** — even placeholder screenshots from test runs work
- **Generic contact info placeholders** — "your.email@example.com" signals unmaintained project. Replace with real info before launch.
- **Roadmap section** — currently v0.1/v0.2/v0.3 with generic bullets. Make it more concrete and exciting.

### Specific Changes Ordered by Impact
1. Add demo GIF (takes 2-3 hours)
2. Add comparison table (30 min)
3. Fix contact/author info (5 min)
4. Move RAG finding higher (10 min)
5. Add OWASP mention in top section (5 min)

---

## Part 2 — Launch Sequence

### Week 1 — Soft Launch (Days 1-7)

**Day 1: r/netsec**
Post title: `"LLMGuard-Lite: scan your LLM app for prompt injection in 30 seconds — open source, $0.50/scan"`
Body: lead with the problem (testing LLM apps is hard), show the one-command experience, include a GIF, link to novel RAG research section. Do NOT say "check out my project." Say "we found that X% of RAG pipelines fail this test."

**Day 2: r/MachineLearning**
Post title: `"We found 60% of RAG pipelines vulnerable to document instruction hijacking — open source test tool"`
Frame entirely as research. The tool is the proof-of-concept. Include the DOCX hidden text finding prominently.

**Day 3: Hacker News Show HN**
Title format: `Show HN: LLMGuard-Lite – scan LLM apps for prompt injection in 30s, $0.50, no config`
CRITICAL: Be in the thread within the first hour. Answer every question, no matter how small. HN rewards active founders. Have 3 pre-written responses ready for: "how is this different from garak?", "does it work with local models?", "how does the cost work?"

**Day 4: Dev.to**
Post: "How We Found That 6 in 10 RAG Setups Fail Document Injection Tests" — research blog post style. Include code examples. End with "we open-sourced the test tool." Link in bio.

**Day 5-7: Engage**
- Respond to every GitHub issue immediately
- Follow up with HN commenters
- Submit PRs to awesome-lists (see below)

### Week 2 — Content Push

**Blog post:** "Add LLM Security Scanning to Your GitHub Actions in 5 Minutes"
Platform: Dev.to (primary) + Medium + Hashnode
Hook: Step-by-step tutorial. Real YAML. Screenshot of failed security check in CI. Copy-pasteable.

**Newsletter submissions:**
- tl;dr sec (Clint Gibler): Submit via tldrsec.com — include 2-sentence pitch + GitHub link
- AI Security Newsletter (Tal Eliyahu): DM on LinkedIn with a brief pitch

**Awesome list PRs:**
- `corca-ai/awesome-llm-security` — PR with 1-line description
- `TalEliyahu/Awesome-AI-Security` — PR
- `tenable/awesome-llm-cybersecurity-tools` — PR
- `kaplanlior/oss-llm-security` — PR

### Week 3 — Community Integration

**OWASP LLM community:**
- Join OWASP GenAI Slack (free)
- Post in #tools channel: "We've mapped all our attack vectors to OWASP LLM Top 10, interested in feedback"
- If response is positive, request listing on the OWASP resources page

**Targeted outreach:**
- Simon Willison (@simonw): Email or DM. He covers prompt injection tools regularly and is already cited in our README. "We cited your work, built a tool, thought you might find it interesting." Do NOT ask him to share. Just send.
- Johann Rehberger (@wunderwuzzi23): Leading voice on indirect prompt injection. DM on Twitter with the RAG injection research findings specifically.

**Specific awesome-list deep cuts:**
- `raphabot/awesome-cybersecurity-agentic-ai` — new list for agentic security, perfect fit
- OWASP resources page at genai.owasp.org

### Week 4 — Amplification

**If HN worked (50+ points):**
- Write a follow-up post: "We launched on HN last week, here's what we learned about LLM security gaps from the comments"
- Reach out to any security journalists who linked to the HN post
- Record a short YouTube video using the HN traction as social proof

**If HN didn't work (<20 points):**
- Analyze why (title? timing? content?)
- Reframe as a research post: "Document-Based LLM Attacks: A Taxonomy and Testing Framework" — more academic framing
- Try r/netsec with a different angle: focus on CI/CD integration, not the tool itself
- Reach out to onsecurity.io and pynt.io article authors — ask to be added to their "best LLM security tools" lists

---

## Part 3 — Content That Drives Stars

### 3 Blog Posts That Would Drive Traffic

**1. "We Tested 10 RAG Configurations for Hidden Text Injection — 6 Failed"**
- Target audience: ML engineers, AI app developers
- Hook: Specific finding + percentage = irresistible click. "10 configurations" = systematic credibility.
- Where to post: Medium, Dev.to, Hacker News (as research post not Show HN)
- CTA: "We open-sourced the test tool so you can test yours"

**2. "Add LLM Security to Your CI/CD in 5 Minutes (Before Your Users Find the Bugs)"**
- Target audience: DevOps engineers, developers with deployed LLM features
- Hook: CI/CD is familiar territory. "5 minutes" is credible. "Before your users find it" is fear-based motivation.
- Where to post: Dev.to (developer audience), Reddit r/devops, r/webdev
- CTA: The GitHub Actions YAML is the entire post — copy-paste and done

**3. "What I Wish I Knew Before Building an LLM Feature (The Security Checklist)"**
- Target audience: Startup developers, indie hackers
- Hook: Personal frame + checklist format = high shareability
- Where to post: Indie Hackers, r/startups, personal newsletter, Hacker News
- CTA: "We automated this checklist" + link

### 2 Twitter/X Threads That Would Spread

**Thread 1: The finding thread**
> "We found that 6/10 common RAG setups are vulnerable to an attack most developers have never heard of.
>
> Thread: document instruction hijacking, and how to test if your app is affected 🧵
>
> [Screenshot of attack succeeding]
> [Screenshot of attack succeeding on a different setup]
> [The technical explanation in 3 tweets]
> [Link to open source test tool]"

Hook: data + unknown attack + visual proof = RT-worthy in security community.

**Thread 2: The CI/CD thread**
> "Your LLM app passed security review.
> But did your CI/CD pipeline test it for prompt injection?
>
> Probably not. Here's how to add it in 3 minutes 👇
>
> [YAML snippet]
> [Screenshot of passing CI]
> [Screenshot of failing CI with a vulnerability]"

Hook: developer workflow + copy-paste solution = bookmarked and shared.

### 1 YouTube/Demo Video Concept

**Title:** "Watch This LLM App Get Hacked in 30 Seconds (And How We Fixed It)"

**First 30 seconds hook:**
- 0:00-0:05: Screen recording. We type one command: `llmguard scan --target vulnerable`
- 0:05-0:20: Fast-forward of attacks running, vulnerability findings appearing
- 0:20-0:30: Pause on a CRITICAL finding. Zoom in. "This is a real attack. And your app might be vulnerable right now."
- Then: cut to explanation of what's happening and how to use the tool.

**Why this works:** The visceral experience of watching a tool discover real vulnerabilities in real-time is more compelling than any explanation.

---

## Part 4 — Star Milestones

**0 → 100 stars: Your personal network + HN/Reddit**
These come from: your LinkedIn/Twitter announcement, HN Show HN upvotes, r/netsec thread, and people who click awesome-list links. Expect this in Week 1-2 if the launch goes well.

**100 → 500 stars: Content machine kicks in**
This jump requires: the research blog post getting picked up by tl;dr sec or similar newsletter, being added to 3-5 awesome lists, the GitHub Action spreading to repos that use it. Expect this in Weeks 3-6.

**500 → 1000 stars: The v0.3 MCP feature + media coverage**
This jump requires a "new angle" moment. The MCP security testing plugin is it. Being "the first tool to test LLM apps AGAINST MCP injection" is the narrative that gets you covered in security media and the AI safety community simultaneously. Expect this in Months 2-4.

**1000+ stars: When the tool is genuinely used**
1000+ is sustainable once: developers are finding real vulnerabilities and posting about it (user-generated content), enterprise teams are requiring it in CI/CD, and the OWASP/compliance angle drives B2B word-of-mouth.

---

## Part 5 — Realistic Projections

| Timeline | Expected Stars | What drives it |
|----------|---------------|----------------|
| 30 days  | 50-150 | HN launch + Reddit + initial awesome list additions |
| 90 days  | 200-500 | Content marketing, newsletter pickups, v0.2 `--url` feature |
| 6 months | 500-1500 | MCP plugin launch, organic CI/CD spread, research citations |

**Stars in 30 days if playbook followed exactly:** 100-150
**Stars in 90 days:** 300-500
**Stars in 6 months:** 700-1500

**Single biggest accelerator:** tl;dr sec newsletter feature. One issue = hundreds of security engineers seeing the tool. Worth spending a week making the submission perfect.

**Biggest risk to growth:** Launching without the demo GIF. Without a visual hook, the README doesn't convert. Every hour spent recording and adding the GIF returns more stars than any marketing.
