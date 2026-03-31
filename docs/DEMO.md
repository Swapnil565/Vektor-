# Vektor Demo — Step by Step

## What you see in the demo

1. `vektor list` — 27 attacks across 6 categories
2. `vektor scan --target vulnerable` — a deliberately insecure target (built-in, no API key)
3. HTML report — risk score, finding table, remediation steps per vulnerability

## Reproduce it yourself (60 seconds, no API key)

```bash
pip install vektor
vektor scan --target vulnerable --output report.html
# Windows: start report.html
# Mac:     open report.html
# Linux:   xdg-open report.html
```

## What "vulnerable target" means

`VulnerableTarget` is a built-in simulation of a poorly secured LLM app. It has zero safety controls — it echoes injected instructions, leaks its system prompt, and never refuses. It's designed to prove the scanner works and let you see the HTML report without any API key or cost.

## Scanning a real HTTP endpoint

Start a local server (any HTTP API that takes a message and returns a response):

```bash
# Terminal 1 — example echo server
python demo_server.py

# Terminal 2 — scan it
vektor scan --url http://127.0.0.1:8000/chat --output demo_report.html
```

The `--url` flag works against any deployed endpoint too:

```bash
vektor scan --url https://my-app.com/api/chat \
  --header "Authorization: Bearer YOUR_TOKEN"
```

## Scanning with a free LLM (Groq — no credit card)

```bash
pip install groq
export GROQ_API_KEY=your_key_here
vektor scan --target openai-compatible \
  --base-url https://api.groq.com/openai/v1 \
  --model llama3-8b-8192 \
  --api-key $GROQ_API_KEY
```

## Python API

```python
from vektor import scan

results = scan(target="vulnerable")
print(f"Risk score: {results['summary']['risk_score']}")
print(f"Vulnerabilities: {results['summary']['total_vulnerabilities']}")
```
