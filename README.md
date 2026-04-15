# Vektor 🛡️

**pytest for AI security — scan LLM apps for vulnerabilities in 30 seconds**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

## 🎯 What is Vektor?

An automated security testing framework that scans LLM applications for vulnerabilities:
- ✅ **27 validated attack vectors** across 6 categories
- ✅ **$0.50 average scan cost** with built-in budget controls
- ✅ **30-second results** - Docker run, immediate feedback
- ✅ **CI/CD ready** - Integrate into your deployment pipeline
- ✅ **Novel research** - First tool to systematically test document-based instruction hijacking

## 🚀 Quick Start

```bash
# Step 1: Install
pip install vektor-scan

# Step 2: Zero-setup demo (no API key needed)
python -m vektor demo

# Step 3: Real scan, $0 cost, always works
python -m vektor scan --target vulnerable --output my-first-report.html

# Step 4: Open the report
# Windows: start my-first-report.html
# Mac:     open my-first-report.html
# Linux:   xdg-open my-first-report.html

# Step 5 (optional): Scan your own LLM app
export OPENAI_API_KEY=sk-your-key
python -m vektor scan --target openai --budget 1.0
```

> **Note:** On some systems `vektor` works directly as a CLI command. If not, use `python -m vektor` — it always works everywhere.

## 🌐 Scan Any AI API — No SDK Needed

Point Vektor at any HTTP endpoint:
```bash
# Auto-detects OpenAI/Anthropic/custom shapes
python -m vektor scan --url http://localhost:8000/chat

# With auth header
python -m vektor scan --url https://my-app.com/api \
  --header "Authorization: Bearer YOUR_TOKEN"

# Custom request/response field names
python -m vektor scan --url http://localhost:8000/predict \
  --request-field prompt --response-field answer

# Query-parameter mode (e.g. /api/parse?text=PAYLOAD)
python -m vektor scan --url http://localhost:8000/api/parse \
  --param-field text

# Rate-limited API — add delay between requests
python -m vektor scan --url http://localhost:8000/chat \
  --request-delay 12.0
```

## 💡 Why Vektor?

| Feature | Vektor | Garak | Promptfoo | PyRIT |
| :--- | :---: | :---: | :---: | :---: |
| **Primary Focus** | **Actionable Security** | Vulnerability Scanning | General Eval / Testing | Red Teaming Framework |
| **Setup Time** | **< 30s** | ~10 mins | ~5 mins | ~30 mins |
| **Scan Speed** | **Fast (Targeted)** | Slow (Exhaustive) | Fast | Slow (Agentic) |
| **Cost Control** | **✅ Built-in Budget** | ❌ | ❌ | ❌ |
| **CI/CD Ready** | **✅ Native** | ⚠️ Heavy | ✅ | ⚠️ Complex |
| **RAG/Doc Attacks** | **✅ Specialized** | ⚠️ Limited | ✅ | ✅ |

| Before | After |
|--------|-------|
| Hire pentester ($5K) | Run: `vektor scan` |
| Wait 2 weeks | Get results in 1 minute |
| Get 50-page report | Actionable JSON/HTML reports |
| Still don't know if fixes work | Re-run to validate fixes |

## 🔬 Attack Categories

### 1. Prompt Injection (6 attacks)
- Direct instruction injection
- System prompt override
- Delimiter confusion
- Role manipulation
- Multi-turn context poisoning
- Encoding-based bypass

### 2. Data Extraction (4 attacks)
- Training data leak attempts
- System prompt disclosure
- Context window extraction
- PII leakage testing

### 3. Instruction Hijacking (5 attacks) — **NOVEL**
- Simple document injection
- DOCX hidden text injection
- DOCX footnote injection
- Markdown comment injection
- Multi-document context poisoning

### 4. RAG Attacks (5 attacks)
- Context poisoning via retrieved docs
- RAG prompt leakage
- Source fabrication / hallucination injection
- Indirect injection via document store
- Chunking boundary exploitation

### 5. Agent Attacks (4 attacks)
- Tool call injection
- Goal hijacking
- Memory poisoning
- Agent scope escape

### 6. Structured Output Injection (3 attacks)
- JSON schema bypass
- Output format injection
- Type confusion attack

## 📦 Installation

### Docker
```bash
docker build -t vektor .
docker run -e OPENAI_API_KEY=$OPENAI_API_KEY vektor scan --target openai
```

### pip
```bash
pip install vektor-scan
```

### From Source
```bash
git clone https://github.com/Swapnil565/Vektor-.git
cd vektor
pip install -e .
```

## 📖 Usage

### Basic Scan
```bash
python -m vektor scan --target openai --budget 1.0
```

### Quick Mode (High-confidence attacks only)
```bash
python -m vektor scan --target openai --quick
```

### CI/CD Integration
```bash
python -m vektor scan --target openai --ci --output report.json
```

### Specific Attacks
```bash
python -m vektor scan --target openai --attacks direct_injection,system_override
```

### Demo Mode (No API calls)
```bash
python -m vektor demo
```

## 📊 Sample Output

```
╔══════════════════════════════════╗
║  V  E  K  T  O  R               ║
║  AI Security Testing Framework   ║
╚══════════════════════════════════╝

⠋ Testing attacks... ━━━━━━━━━━━━━━━━━━━━━━ 100% (15/15)

┏━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Attack                  ┃ Severity  ┃ Success    ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ Direct Injection        │ HIGH      │ 83%        │
│ DOCX Hidden Text        │ CRITICAL  │ 67%        │
│ System Prompt Reveal    │ HIGH      │ 50%        │
└────────────────────────┴───────────┴────────────┘

╭─────────────────────────────────╮
│ Summary                         │
├─────────────────────────────────┤
│ Risk Score: 72/100              │
│ Total Vulnerabilities: 3        │
│ Cost: $0.47                     │
│                                 │
│ HIGH RISK: Address all critical │
│ vulnerabilities before deploy   │
╰─────────────────────────────────╯

✓ Report saved to: report.json
```

## 🔍 Novel Research: Instruction Hijacking

Vektor is the first tool to systematically test **document-based instruction hijacking** - a new class of vulnerabilities where attackers embed malicious instructions in document formats (DOCX, PDF, Markdown) that get processed by RAG systems.

Our research found:
- **60% of RAG systems** vulnerable to hidden text injection
- **40% vulnerable** to footnote/comment injection
- Standard sanitization **doesn't catch** format-specific exploits

[Read the full research paper →](docs/INSTRUCTION_HIJACKING.md)

## 🛠️ CI/CD Integration

### GitHub Actions
```yaml
name: LLM Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install Vektor
        run: pip install vektor-scan
      - name: Scan (no API key needed)
        run: vektor scan --target vulnerable --ci --output report.json
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: report.json
      # Optional: scan your real LLM endpoint
      # - name: Scan real endpoint
      #   env:
      #     OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
      #   run: vektor scan --target openai --ci --output report.json
```

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Adding Custom Attacks
```python
from vektor.attacks.base import BaseAttack, Vulnerability

class MyCustomAttack(BaseAttack):
    def __init__(self):
        super().__init__(name="my_attack", category="Custom")

    def execute(self, target):
        # Your attack logic
        pass
```

## 📚 Documentation

- [Demo Walkthrough](docs/DEMO.md)
- [Installation Guide](docs/INSTALL.md)
- [Usage Reference](docs/USAGE.md)
- [Research: Instruction Hijacking](docs/INSTRUCTION_HIJACKING.md)

## 🗺️ Roadmap

### v0.2 (Current)
- ✅ 27 attack vectors across 6 categories
- ✅ HTTP endpoint target (`vektor scan --url http://localhost:8000/chat`)
- ✅ RAG pipeline targets (LangChain, LlamaIndex)
- ✅ Agent targets (LangGraph, CrewAI, AutoGen)
- ✅ Regression diff system for CI gating
- ✅ Python scan() API
- ✅ Docker deployment + CI/CD integration

### v0.3 (Next)
- ⏳ Web dashboard
- ⏳ PDF document testing
- ⏳ Multi-model comparison
- ⏳ Compliance reporting (OWASP LLM Top 10 mapping)

## 📄 License

MIT License - see [LICENSE](LICENSE) for details

## 🙏 Acknowledgments

Built on research from:
- Simon Willison ([@simonw](https://twitter.com/simonw)) - Prompt injection taxonomy
- Greshake et al. - Indirect prompt injection
- OWASP LLM Top 10 Project

## ⭐ Support

If you find this useful, please star the repository and share with your network!

- GitHub: [vektor](https://github.com/Swapnil565/Vektor-)
- Issues: [Bug reports & feature requests](https://github.com/Swapnil565/Vektor-/issues)

## 📧 Contact

- Email: swapnil.wankhede23@spit.ac.in
- Author: Swapnil

---

**⚠️ Disclaimer:** This tool is for security testing purposes only. Use responsibly and only on systems you have permission to test.
