# B1 — GitHub Stars Analyst
*Generated: 2026-03-03*

---

## 5 Key Viral Patterns (with examples from this space)

### Pattern 1: Novel Research + Proof Data
**The pattern:** Don't just release a tool — release a finding. "We discovered X% of Y systems are vulnerable to Z."
**Example:** Our own angle: "60% of RAG systems vulnerable to hidden text injection" is the hook.
**Why it works:** Researchers cite it, journalists cover it, developers share it. The tool becomes the proof-of-concept for the finding.
**How to execute:** Write a blog post titled "We tested 10 popular RAG setups for hidden text injection — 6 failed" BEFORE the GitHub launch. The tool is the footnote, not the headline.

### Pattern 2: The Taxonomy Post
**The pattern:** A curated, comprehensive list of attack types beats a pure tool launch on HN and Reddit.
**Example:** "Show HN: Open-source taxonomy of 122 AI/LLM attack vectors" (Jan 2026) got significant HN traction.
**Why it works:** Referenceable. Gets bookmarked, added to awesome lists, cited in security curricula.
**How to execute:** Publish our 15 attack vectors as a proper taxonomy post with explanations. The tool is how you test for them.

### Pattern 3: The "One Command" Demo
**The pattern:** Show the full experience in a single GIF: install → run → result. Make it feel effortless.
**Example:** Tools that show a 30-second terminal GIF outperform text-heavy READMEs consistently.
**Why it works:** The "wow, I can do that" moment is visceral. Viewers imagine themselves running it.
**How to execute:** Record `pip install llmguard-lite && llmguard scan --target vulnerable` end-to-end. The vulnerable target shows real findings immediately.

### Pattern 4: The CI/CD Integration Angle
**The pattern:** Show it in a pipeline. Security tools that slot into developer workflow beat standalone tools.
**Example:** Promptfoo's GitHub Action drives adoption because it appears in repos — social proof at scale.
**Why it works:** Every repo that adds the action becomes an advertisement. Forks spread the YAML.
**How to execute:** Publish `.github/actions/llmguard-scan/action.yml`. Write a dedicated blog post: "Add LLM security scanning to your GitHub Actions in 5 minutes."

### Pattern 5: First-Mover on a Hot New Attack Surface
**The pattern:** Be the first tool to cover a newly-discovered attack class.
**Example:** Multiple MCP security scanners launched in late 2025 when MCP exploded. Early movers got listed everywhere.
**Why it works:** You become the canonical tool. Every article about the attack vector links you.
**How to execute:** MCP security testing is the opportunity right now. Add it before the space gets crowded.

---

## README Best Practices from Top-Starred Tools

Analysis of Garak, Promptfoo, and top security repos:

**Above the fold (first screen):**
- ✅ One-line description that's scannable (not marketing copy)
- ✅ Badges: PyPI version + Python version + license + CI status
- ✅ Demo GIF or asciinema recording — THIS IS THE #1 MISSING ITEM IN OUR README
- ✅ Quick install + quick run in < 5 lines

**Body:**
- ✅ Problem statement (1 paragraph)
- ✅ Feature comparison table (us vs alternatives)
- ✅ Clear "what it finds" with examples
- ✅ CI/CD YAML snippet
- ✅ Link to research/documentation

**What we're MISSING:**
1. **Demo GIF** — the single highest-impact README addition
2. **Competitor comparison table** — "vs Garak vs Promptfoo vs PyRIT" in our README
3. **OWASP badge/tagging** visible in README
4. **"Used by X companies" section** — even if it's just test repos initially

---

## Launch Platform Ranking (highest to lowest ROI)

1. **Hacker News — Show HN** — Highest quality traffic, most citations, leads to newsletter pickups. Frame as research, not tool announcement. Target: 50+ points = 500+ stars in 48h window.

2. **r/netsec** — Active security community, will share if the tool is genuinely useful. Title matters enormously. Needs to be "here's what I found" not "check out my tool."

3. **tl;dr sec newsletter** — Curated weekly security newsletter with ~30k+ subscribers. Being featured = 200-500 stars. Submit via their submission form.

4. **Dev.to** — Trending algorithm amplifies high-performing posts. Publish our taxonomy/research blog post here.

5. **r/MachineLearning** — Research angle plays well. "Document injection in RAG systems" framing.

6. **awesome-llm-security (corca-ai, 1.5k stars)** — Submit a PR. Every visitor to this list is our exact target user.

7. **awesome-ai-security lists** — Multiple active repos. Submit to all. Takes 15 minutes per PR.

8. **r/LocalLLaMA** — If/when we add Ollama support, this community is very large and active.

9. **AI Security Newsletter (Tal Eliyahu, Medium)** — Monthly newsletter covering AI security tools. Email to request coverage.

10. **OWASP LLM community** — OWASP GenAI project has Slack + mailing list. Our OWASP mapping makes us immediately relevant.

---

## Top Aggregators and Awesome Lists to Get Listed On

| List | Stars | How to Submit |
|------|-------|--------------|
| corca-ai/awesome-llm-security | 1.5k | PR to repo, follow CONTRIBUTING.md |
| TalEliyahu/Awesome-AI-Security | Unknown | PR to repo |
| ottosulin/awesome-ai-security | Unknown | PR to repo |
| tenable/awesome-llm-cybersecurity-tools | Unknown | PR to repo |
| kaplanlior/oss-llm-security | Unknown | PR to repo |
| OWASP GenAI security project tools list | - | Submit via OWASP Slack/email |
| onsecurity.io "Best Open Source LLM Red Teaming Tools" | - | Email the author |
| pynt.io "10 LLM Security Tools" | - | Email the author |
| deepchecks.com "Top LLM Security Frameworks" | - | Email the author |

---

## Influencers and Newsletters in This Space

| Name | Platform | Audience | Why relevant |
|------|----------|----------|--------------|
| **tl;dr sec** (Clint Gibler) | Newsletter | ~30k security pros | Covers open source security tools regularly |
| **Tal Eliyahu** | Medium/Newsletter | AI security focused | Maintains awesome-ai-security list |
| **Simon Willison** (@simonw) | Substack/Twitter | Dev community | Cited in our README, covers prompt injection |
| **Johann Rehberger** (@wunderwuzzi23) | Twitter | Prompt injection researcher | Key voice in doc injection space |
| **OWASP LLM Top 10 team** | Multiple | Enterprise devs | Endorsement = instant enterprise credibility |

---

## Our Viral Potential Assessment

**Strongest hook:** "First tool to test document-based instruction hijacking in RAG systems" — this is genuinely novel and nobody else has it.

**Weakest point:** README currently has no GIF. This is a first-impression killer.

**Highest-leverage single change:** Record a 60-second terminal demo showing the vulnerable target scan. Put the GIF at line 1 of the README. This is the difference between 50 stars and 500 stars at launch.

**Second highest-leverage change:** Write the research blog post before launch. "We found that 6/10 RAG configurations failed our document injection test." Use the tool as the evidence.
