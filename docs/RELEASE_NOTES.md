# LLMGuard-Lite v0.1.0

**Security scanner for LLM applications — find vulnerabilities before attackers do.**

## Highlights

- **15 validated attack vectors** across 3 categories
- **BYOK model** — bring your own API key, no server costs
- **Demo mode** — try instantly without an API key
- **Novel research** — first tool to systematically test document-based instruction hijacking

## Attack Categories

### Prompt Injection (6 attacks)
- Direct instruction injection
- System prompt override
- Delimiter confusion
- Role manipulation (DAN-style)
- Multi-turn context poisoning
- Encoding-based bypass (Base64, ROT13)

### Data Extraction (4 attacks)
- Training data extraction
- System prompt disclosure
- Context window extraction (RAG canary)
- PII leakage testing

### Instruction Hijacking (5 attacks) — NEW
- Simple document injection
- DOCX hidden text (white-on-white)
- DOCX footnote injection (tiny font)
- Markdown comment injection
- Multi-document context poisoning

## Quick Start

```bash
# Demo (no API key needed)
pip install llmguard-lite
llmguard demo

# Real scan
export OPENAI_API_KEY=sk-...
llmguard scan --target openai --budget 1.0
```

## What's New

This is the initial release. Everything is new.

## Supported Providers

| Provider | Status | Cost per Scan |
|----------|--------|---------------|
| OpenAI   | v0.1   | ~$0.05-$0.20  |
| Anthropic| v0.2   | Coming soon   |
| Ollama   | v0.3   | Free (local)  |

## Known Limitations

- OpenAI only in v0.1 (Anthropic and local models coming in v0.2/v0.3)
- Document-based attacks require `python-docx` (included in dependencies)
- Budget tracking is estimate-based (actual costs may vary slightly)

## Links

- [Installation Guide](docs/INSTALL.md)
- [Usage Reference](docs/USAGE.md)
- [Instruction Hijacking Research](docs/INSTRUCTION_HIJACKING.md)
