# Installation Guide

## Requirements

- Python 3.10+
- An API key from a supported provider (for scanning; demo mode requires no key)

## Install via pip

```bash
pip install llmguard-lite
```

## Install from source

```bash
git clone https://github.com/yourusername/llmguard-lite.git
cd llmguard-lite
pip install -e .
```

## Docker

```bash
docker build -t llmguard-lite .
docker run --rm llmguard-lite demo
```

Or using docker compose:

```bash
docker compose run llmguard demo
```

## API Key Setup (BYOK)

LLMGuard uses a **Bring Your Own Key** model. You provide your own API key and pay your provider directly.

### Option 1: Environment Variable (Recommended)

```bash
# OpenAI
export OPENAI_API_KEY=sk-your-key-here

# Anthropic (v0.2)
export ANTHROPIC_API_KEY=sk-ant-your-key-here

# Ollama (v0.3, local models)
export OLLAMA_HOST=http://localhost:11434
```

### Option 2: Config File

Create `~/.llmguard/config.yml`:

```yaml
openai: sk-your-key-here
anthropic: sk-ant-your-key-here
```

### Option 3: Interactive Prompt

If no key is found, LLMGuard will prompt you when running in a terminal:

```
╭──────────────────────╮
│ API Key Required     │
│ No API key for openai│
╰──────────────────────╯

openai API key: sk-...
Save to config file? (y/N): y
```

### Option 4: CLI Flag

```bash
llmguard scan --target openai --api-key sk-your-key-here
```

## Supported Providers

| Provider  | Status  | Env Variable        | Cost per Scan   |
|-----------|---------|---------------------|-----------------|
| OpenAI    | v0.1    | `OPENAI_API_KEY`    | ~$0.05-$0.20    |
| Anthropic | v0.2    | `ANTHROPIC_API_KEY` | ~$0.10-$0.30    |
| Ollama    | v0.3    | `OLLAMA_HOST`       | Free (local)    |

## Verify Installation

```bash
# Check version
llmguard info

# Run demo (no API key needed)
llmguard demo

# List available attacks
llmguard list
```
