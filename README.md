# LLMGuard-Lite 🛡️

**Security testing for LLM applications in 30 seconds**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

## 🎯 What is LLMGuard-Lite?

An automated security testing framework that scans LLM applications for vulnerabilities:
- ✅ **15 validated attack vectors** across 3 categories
- ✅ **$0.50 average scan cost** with built-in budget controls  
- ✅ **30-second results** - Docker run, immediate feedback
- ✅ **CI/CD ready** - Integrate into your deployment pipeline
- ✅ **Novel research** - First tool to systematically test document-based instruction hijacking

## 🚀 Quick Start

```bash
# Try it instantly (no API key needed)
pip install llmguard-lite
llmguard demo

# Scan your own LLM app (BYOK - Bring Your Own Key)
export OPENAI_API_KEY=sk-your-key
llmguard scan --target openai --budget 1.0

# With Docker
docker compose run llmguard demo
docker compose run -e OPENAI_API_KEY=sk-... llmguard scan --target openai
```

## 💡 Why LLMGuard?

| Feature | LLMGuard-Lite | Garak | Promptfoo | PyRIT |
| :--- | :---: | :---: | :---: | :---: |
| **Primary Focus** | **Actionable Security** | Vulnerability Scanning | General Eval / Testing | Red Teaming Framework |
| **Setup Time** | **< 30s** | ~10 mins | ~5 mins | ~30 mins |
| **Scan Speed** | **Fast (Targeted)** | Slow (Exhaustive) | Fast | Slow (Agentic) |
| **Cost Control** | **✅ Built-in Budget** | ❌ | ❌ | ❌ |
| **CI/CD Ready** | **✅ Native** | ⚠️ Heavy | ✅ | ⚠️ Complex |
| **RAG/Doc Attacks** | **✅ Specialized** | ⚠️ Limited | ✅ | ✅ |

| Before | After |
|--------|-------|
| Hire pentester ($5K) | Run: `llmguard scan` |
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

### 3. Instruction Hijacking (5 attacks) - **NOVEL**
- Simple document injection
- DOCX hidden text injection
- DOCX footnote injection
- Markdown comment injection
- Multi-document context poisoning

## 📦 Installation

### Docker
```bash
docker build -t llmguard-lite .
docker run -e OPENAI_API_KEY=$OPENAI_API_KEY llmguard-lite scan --target openai
```

### pip
```bash
pip install llmguard-lite
```

### From Source
```bash
git clone https://github.com/yourusername/llmguard-lite.git
cd llmguard-lite
pip install -e .
```

## 📖 Usage

### Basic Scan
```bash
llmguard scan --target openai --budget 1.0
```

### Quick Mode (High-confidence attacks only)
```bash
llmguard scan --target openai --quick
```

### CI/CD Integration
```bash
llmguard scan --target openai --ci --output report.json
```

### Specific Attacks
```bash
llmguard scan --target openai --attacks direct_injection,system_override
```

### Demo Mode (No API calls)
```bash
llmguard demo
```

## 📊 Sample Output

```
╭────────────────────────────────╮
│ LLMGuard Security Scanner v0.1 │
│ Target: openai | Budget: $1.00 │
╰────────────────────────────────╯

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

LLMGuard-Lite is the first tool to systematically test **document-based instruction hijacking** - a new class of vulnerabilities where attackers embed malicious instructions in document formats (DOCX, PDF, Markdown) that get processed by RAG systems.

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
      - uses: actions/checkout@v2
      - name: Run LLMGuard
        run: |
          docker run -e OPENAI_API_KEY=${{ secrets.OPENAI_API_KEY }} \
            llmguard-lite scan --target openai --ci --output report.json
      - name: Upload Report
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: report.json
```

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Adding Custom Attacks
```python
from llmguard.attacks.base import BaseAttack, Vulnerability

class MyCustomAttack(BaseAttack):
    def __init__(self):
        super().__init__(name="my_attack", category="Custom")
    
    def execute(self, target):
        # Your attack logic
        pass
```

## 📚 Documentation

- [Installation Guide](docs/INSTALL.md)
- [Usage Reference](docs/USAGE.md)
- [Python API](docs/API.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Contributing](CONTRIBUTING.md)
- [Research: Instruction Hijacking](docs/INSTRUCTION_HIJACKING.md)

## 🗺️ Roadmap

### v0.1 (Current)
- ✅ 15 attack vectors
- ✅ OpenAI support
- ✅ Docker deployment
- ✅ CI/CD integration

### v0.2 (Next)
- ⏳ Anthropic Claude support
- ⏳ Ollama local models
- ⏳ 10 additional attacks
- ⏳ Web dashboard

### v0.3 (Future)
- 📋 PDF document testing
- 📋 Image-based attacks
- 📋 Multi-model comparison
- 📋 Compliance reporting

## 📄 License

MIT License - see [LICENSE](LICENSE) for details

## 🙏 Acknowledgments

Built on research from:
- Simon Willison ([@simonw](https://twitter.com/simonw)) - Prompt injection taxonomy
- Greshake et al. - Indirect prompt injection
- OWASP LLM Top 10 Project

## ⭐ Support

If you find this useful, please star the repository and share with your network!

- GitHub: [llmguard-lite](https://github.com/swapnilwankhede23/llmguard-lite)
- Issues: [Bug reports & feature requests](https://github.com/swapnilwankhede23/llmguard-lite/issues)

## 📧 Contact

- Email: swapnil.wankhede23@spit.ac.in
- Author: Swapnil

---

**⚠️ Disclaimer:** This tool is for security testing purposes only. Use responsibly and only on systems you have permission to test.
