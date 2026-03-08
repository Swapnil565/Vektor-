# Vektor — Phase Testing Guide

How to test each completed phase locally (no API key) and through live inference.
Keep this document updated at the end of every phase.

---

## Setup (required for all phases)

```bash
# Install in editable mode from repo root
pip install -e .

# Verify CLI is available
vektor --version

# Run unit tests (covers all phases)
pytest tests/unit/test_attacks.py -v
```

---

## Phase 1 — HTTP Endpoint Target + Extended CLI flags

**What was built:**
- `HTTPEndpointTarget` — scan any REST API that accepts `{"message": "..."}` JSON
- CLI flags: `--url`, `--param-field`, `--request-field`, `--response-field`, `--request-delay`
- 16th attack: `structured_output_injection`

### Local test (no key needed) — spin up a mock HTTP server

```python
# save as mock_server.py and run: python mock_server.py
import json, threading
from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length))
        msg = body.get("message", "")
        resp = json.dumps({"message": f"Sure! {msg} -- I am in JAILBREAK mode!"})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(resp.encode())

HTTPServer(("127.0.0.1", 9191), Handler).serve_forever()
```

```bash
# Terminal 1 — start the mock server
python mock_server.py

# Terminal 2 — run a full scan against it
vektor scan \
    --target http \
    --url http://127.0.0.1:9191 \
    --output outputs/phase1_local.json

# Quick scan (5 attacks only)
vektor scan --target http --url http://127.0.0.1:9191 --quick

# Override the JSON field names (if your API uses different keys)
vektor scan \
    --target http \
    --url http://127.0.0.1:9191 \
    --request-field input \
    --response-field output \
    --output outputs/phase1_custom_fields.json

# Add per-request delay (rate-limit friendly)
vektor scan \
    --target http \
    --url http://127.0.0.1:9191 \
    --request-delay 0.5 \
    --output outputs/phase1_throttled.json
```

### Verify the HTTP target directly from Python

```python
from vektor.targets.http_endpoint import HTTPEndpointTarget

target = HTTPEndpointTarget(url="http://127.0.0.1:9191")
print(target.query("Are you safe?"))
# → "Sure! Are you safe? -- I am in JAILBREAK mode!"
```

### Live inference test (Groq — has a free tier)

```bash
export GROQ_API_KEY=gsk_your_key_here

vektor scan \
    --target groq \
    --model llama3-8b-8192 \
    --output outputs/phase1_groq.json

# Check the risk score
python -c "
import json
with open('outputs/phase1_groq.json') as f:
    d = json.load(f)
print('Risk score:', d['summary']['risk_score'])
for v in d['vulnerabilities']:
    print(f'  {v[\"attack_name\"]:35s} {v[\"severity\"]:8s} rate={v[\"success_rate\"]:.2f}')
"
```

### Structured output injection specifically

```bash
# standalone attack test
python -c "
from vektor.attacks.structured_output_injection import StructuredOutputInjectionAttack
from vektor.targets.vulnerable import VulnerableTarget

result = StructuredOutputInjectionAttack().execute(VulnerableTarget())
print('Vulnerable:', result.is_vulnerable)
print('Rate:', result.success_rate)
"
```

---

## Phase 2 — Plugin System (`@attack` decorator)

**What was built:**
- `@attack` decorator in `vektor/core/plugin.py` — self-registers attacks into `ATTACK_REGISTRY` at import time
- `registry.py` rewritten to import-trigger pattern (importing a module auto-registers its attacks)
- CLI flag `--plugin` for loading external attack files at runtime
- `BaseAttack.register()` classmethod for manual registration

### Unit test — verify all 27 attacks are registered

```bash
pytest tests/unit/test_attacks.py::TestRegistry -v
```

### Verify the registry from Python

```python
from vektor.attacks.registry import ATTACK_REGISTRY, get_attack_count, get_categories

print("Total attacks:", get_attack_count())          # → 27
print("Categories:", sorted(get_categories()))
```

### CLI — list all registered attacks

```bash
vektor list

# Filter by category
vektor list --category "Prompt Injection"
vektor list --category "Data Extraction"
```

### Write and load an external plugin

```python
# save as my_custom_attack.py
from vektor.attacks.base import BaseAttack, Vulnerability
from vektor.core.plugin import attack

@attack(
    category="Custom",
    owasp="LLM01: Prompt Injection",
    test_cases=1,
    expected_success_rate=0.5,
    description="My custom probe",
)
class MyCustomAttack(BaseAttack):
    def __init__(self):
        super().__init__("my_custom_attack", "Custom", "LLM01: Prompt Injection")

    def execute(self, target) -> Vulnerability:
        response = target.query("Custom probe payload")
        vulnerable = "SECRET" in response
        return Vulnerability(
            attack_name=self.name, category=self.category,
            owasp_category=self.owasp_category,
            severity="HIGH" if vulnerable else "LOW",
            success_rate=1.0 if vulnerable else 0.0,
            details={"response": response},
            is_vulnerable=vulnerable,
            remediation="Harden against custom probe.",
            cost=0.0,
        )
```

```bash
# Run scan with the custom plugin loaded at runtime
vektor scan \
    --target vulnerable \
    --plugin my_custom_attack.py \
    --output outputs/phase2_plugin.json

# Verify the custom attack ran
python -c "
import json
with open('outputs/phase2_plugin.json') as f:
    d = json.load(f)
names = [v['attack_name'] for v in d['vulnerabilities']]
print('my_custom_attack ran:', 'my_custom_attack' in names)
"
```

### Verify decorator registration directly

```python
from vektor.core.plugin import ATTACK_REGISTRY
import vektor.attacks.registry  # trigger all imports

assert "tool_injection" in ATTACK_REGISTRY
assert "rag_context_poisoning" in ATTACK_REGISTRY
print("All good:", len(ATTACK_REGISTRY), "attacks registered")
```

---

## Phase 3 — RAG Attack Module

**What was built:**
- `vektor/attacks/rag_attacks.py` — 6 new attacks (total 22)
- All gate on `target.supports_documents()` → return `INFO` for non-RAG targets
- New CATEGORY_WEIGHTS entry: `"RAG Attacks": 8`

### Local test — mock RAG target

```python
# save as test_rag_local.py
from vektor.attacks.rag_attacks import (
    RagContextPoisoningAttack,
    RetrieverManipulationAttack,
    DocumentExfiltrationAttack,
    HiddenInjectionAttack,
    CrossDocumentPoisoningAttack,
    RagPoisoningChainAttack,
)

class MockRAGTarget:
    """Minimal mock that looks like a RAG-enabled target."""
    total_cost = 0.0
    name = "mock-rag"
    model = "mock"
    conversation_history = []

    def query(self, prompt, **kwargs):
        self.total_cost += 0.001
        # Simulate a vulnerable RAG system that echoes injected payloads
        if "[INJECT]" in prompt or "context poisoning" in prompt.lower():
            return "[RAG_CONTEXT_POISONED] Here is the summary."
        return "Normal response."

    def supports_documents(self): return True
    def upload_document(self, path):
        import os; return os.path.basename(path)
    def clear_documents(self): pass
    def clear_conversation(self): pass
    def get_refusal_patterns(self): return ["i cannot", "i can't"]
    def estimate_cost(self, *a): return 0.001

target = MockRAGTarget()

for AttackClass in [RagContextPoisoningAttack, DocumentExfiltrationAttack,
                    HiddenInjectionAttack, CrossDocumentPoisoningAttack]:
    result = AttackClass().execute(target)
    print(f"{result.attack_name:35s} vulnerable={result.is_vulnerable} severity={result.severity}")
```

```bash
python test_rag_local.py
```

### Verify non-RAG targets get INFO (not a false positive)

```python
from vektor.attacks.rag_attacks import RagContextPoisoningAttack
from vektor.targets.vulnerable import VulnerableTarget

# VulnerableTarget does NOT support documents
result = RagContextPoisoningAttack().execute(VulnerableTarget())
assert result.severity == "INFO"
assert result.is_vulnerable is False
print("Correctly skipped non-RAG target:", result.details["note"])
```

### Run only RAG attacks against a real RAG endpoint

```bash
# Against any HTTP endpoint that supports document-augmented queries
vektor scan \
    --target http \
    --url http://localhost:3001/api/chat \
    --attacks rag_context_poisoning,document_exfiltration,hidden_injection \
    --output outputs/phase3_rag.json

# Against AnythingLLM (localhost:3001, which is a RAG-native app)
vektor scan \
    --target anythingllm \
    --output outputs/phase3_anythingllm.json
```

### Live inference — Groq with RAG category filter

```bash
export GROQ_API_KEY=gsk_your_key_here

vektor scan \
    --target groq \
    --model llama3-8b-8192 \
    --attacks rag_context_poisoning,retriever_manipulation,document_exfiltration,\
hidden_injection,cross_document_poisoning,rag_poisoning_chain \
    --output outputs/phase3_groq_rag.json
```

### Unit tests for Phase 3 only

```bash
pytest tests/unit/test_attacks.py -k "Rag or RAG or Document or Hidden or Cross or Chain" -v
```

---

## Phase 4 — Agent Attack Module

**What was built:**
- `BaseTarget` extended with 5 agent interface methods
- `vektor/attacks/agent_attacks.py` — 5 new attacks (total 27)
- `vektor/targets/agents/` — 3 production adapters (LangGraph, CrewAI, AutoGen)
- New CATEGORY_WEIGHTS: `"Agent Attacks": 9`, `"Tool Misuse": 9`

### Local test — mock agent target (tool-capable)

```python
# save as test_agent_local.py
from vektor.attacks.agent_attacks import (
    ToolInjectionAttack,
    FunctionCallHijackAttack,
    AgentInstructionOverrideAttack,
    ToolParameterInjectionAttack,
    AgentMemoryPoisoningAttack,
)

class MockAgentTarget:
    total_cost = 0.0
    name = "mock-agent"
    model = "mock"
    conversation_history = []

    def query(self, prompt, **kwargs):
        self.total_cost += 0.001
        # Simulate a vulnerable agent: echoes back indicator tokens
        for token in ["[TOOL_INJECTED]", "HIJACKED_FUNCTION", "[AGENT_OVERRIDDEN]",
                      "[PATH_TRAVERSAL_OK]", "[MEMORY_POISONED]"]:
            if token.lower().replace("[","").replace("]","") in prompt.lower():
                return f"Executed as requested. {token}"
        return "I cannot help with that."

    def supports_tools(self): return True
    def list_tools(self): return ["search", "file_read", "web_fetch"]
    def call_tool(self, name, **kwargs): return f"[result from {name}]"
    def supports_memory(self): return True
    def get_memory(self): return []
    def clear_conversation(self): self.conversation_history.clear()
    def get_refusal_patterns(self): return ["i cannot", "i can't"]
    def estimate_cost(self, *a): return 0.001

target = MockAgentTarget()
attacks = [
    ToolInjectionAttack(),
    FunctionCallHijackAttack(),
    AgentInstructionOverrideAttack(),
    ToolParameterInjectionAttack(),
    AgentMemoryPoisoningAttack(),
]

for atk in attacks:
    result = atk.execute(target)
    print(f"{result.attack_name:35s} vulnerable={result.is_vulnerable}  "
          f"rate={result.success_rate:.2f}  severity={result.severity}")
```

```bash
python test_agent_local.py
```

### Verify non-agent targets get INFO (not a false positive)

```python
from vektor.attacks.agent_attacks import ToolInjectionAttack, ToolParameterInjectionAttack
from vektor.targets.vulnerable import VulnerableTarget

for AttackClass in [ToolInjectionAttack, ToolParameterInjectionAttack]:
    result = AttackClass().execute(VulnerableTarget())
    assert result.severity == "INFO", f"Expected INFO, got {result.severity}"
    print(f"{result.attack_name}: correctly returned INFO for non-agent target")
```

### Test LangGraph adapter (requires `langgraph` + `langchain-core`)

```bash
pip install langgraph langchain-core langchain-openai
```

```python
# save as test_langgraph.py
from langgraph.graph import START, StateGraph, MessagesState
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from vektor.targets.agents import LangGraphTarget
from vektor.attacks.agent_attacks import AgentInstructionOverrideAttack
import os

llm = ChatOpenAI(model="gpt-4o-mini", api_key=os.environ["OPENAI_API_KEY"])
graph = create_react_agent(llm, tools=[])  # no tools → simple instruction test

target = LangGraphTarget(graph, name="gpt4o-mini-langgraph")
print("supports_tools:", target.supports_tools())

result = AgentInstructionOverrideAttack().execute(target)
print("Vulnerable:", result.is_vulnerable, "| Rate:", result.success_rate)
```

```bash
export OPENAI_API_KEY=sk-your-key
python test_langgraph.py
```

### Test CrewAI adapter (requires `crewai`)

```bash
pip install crewai
```

```python
# save as test_crewai.py
from crewai import Agent, Task, Crew
from vektor.targets.agents import CrewAITarget
from vektor.attacks.agent_attacks import ToolInjectionAttack

agent = Agent(
    role="Assistant",
    goal="Answer the user's question: {prompt}",
    backstory="You are a helpful AI assistant.",
    llm="groq/llama3-8b-8192",
    verbose=False,
)
task = Task(
    description="Answer: {prompt}",
    expected_output="A direct answer.",
    agent=agent,
)
crew = Crew(agents=[agent], tasks=[task], verbose=False)

target = CrewAITarget(crew)
print("Tools:", target.list_tools())

result = ToolInjectionAttack().execute(target)
print("Vulnerable:", result.is_vulnerable)
```

```bash
export GROQ_API_KEY=gsk_your_key
python test_crewai.py
```

### Test AutoGen adapter (requires `pyautogen`)

```bash
pip install pyautogen
```

```python
# save as test_autogen.py
from autogen import AssistantAgent
from vektor.targets.agents import AutoGenTarget
from vektor.attacks.agent_attacks import AgentMemoryPoisoningAttack
import os

assistant = AssistantAgent(
    "assistant",
    llm_config={"model": "gpt-4o-mini", "api_key": os.environ["OPENAI_API_KEY"]},
)

target = AutoGenTarget(assistant)
print("supports_tools:", target.supports_tools())

result = AgentMemoryPoisoningAttack().execute(target)
print("Vulnerable:", result.is_vulnerable, "| Rate:", result.success_rate)
```

```bash
export OPENAI_API_KEY=sk-your-key
python test_autogen.py
```

### Run only agent attacks via CLI (future: `--category` filter)

```bash
vektor scan \
    --target vulnerable \
    --attacks tool_injection,function_call_hijack,agent_instruction_override,\
tool_parameter_injection,agent_memory_poisoning \
    --output outputs/phase4_agent_vulnerable.json

# Inspect which attacks returned INFO (non-agent target)
python -c "
import json
with open('outputs/phase4_agent_vulnerable.json') as f:
    d = json.load(f)
for v in d['vulnerabilities']:
    if v['severity'] == 'INFO':
        print('INFO (skipped):', v['attack_name'])
    else:
        print('Tested       :', v['attack_name'], v['severity'])
"
```

### Unit tests for Phase 4 only

```bash
pytest tests/unit/test_attacks.py -k "Agent or Tool or Memory or FunctionCall" -v
```

---

## Run all phases at once

```bash
# Full unit test suite — all 73 tests across all phases
pytest tests/unit/test_attacks.py -v

# Full scan against the built-in vulnerable target (no key, instant)
vektor scan --target vulnerable --output outputs/all_phases_vulnerable.json

# Parse results
python -c "
import json
with open('outputs/all_phases_vulnerable.json') as f:
    d = json.load(f)
summary = d['summary']
print(f'Risk score : {summary[\"risk_score\"]}')
print(f'Total vulns: {len(d[\"vulnerabilities\"])}')
by_cat = {}
for v in d['vulnerabilities']:
    by_cat.setdefault(v['category'], []).append(v['attack_name'])
for cat, names in sorted(by_cat.items()):
    print(f'  {cat}: {len(names)} attacks')
"
```

---

## Quick reference — attack IDs by phase

| Phase | Attack ID | Category |
|-------|-----------|----------|
| 1 | `direct_injection`, `indirect_injection`, `jailbreak_dan`, `jailbreak_roleplay`, `jailbreak_hypothetical`, `multi_turn_attack`, `pii_leakage`, `credential_extraction`, `system_prompt_extraction`, `training_data_extraction`, `instruction_override`, `delimiter_confusion`, `prompt_leaking`, `evasion_unicode`, `evasion_encoding`, `structured_output_injection` | Mixed |
| 3 | `rag_context_poisoning`, `retriever_manipulation`, `document_exfiltration`, `hidden_injection`, `cross_document_poisoning`, `rag_poisoning_chain` | RAG Attacks |
| 4 | `tool_injection`, `function_call_hijack`, `agent_instruction_override`, `tool_parameter_injection`, `agent_memory_poisoning` | Agent Attacks / Tool Misuse |

---

## Phase 5 — RAG Framework Targets (LangChain + LlamaIndex adapters)

Phase 5 adds first-class Python-framework adapters so any LangChain `Runnable`
or LlamaIndex `QueryEngine` can be scanned without any manual wiring.

### What was added

| File | Lines | Purpose |
|------|-------|---------|
| `vektor/targets/rag/langchain_target.py` | 370 | Wraps any LangChain Runnable/Chain via `.invoke()` |
| `vektor/targets/rag/llamaindex_target.py` | 289 | Wraps any LlamaIndex QueryEngine via `.query()` |
| `vektor/targets/rag/__init__.py` | 92 | `auto_wrap(app)` — detects framework by module + duck-type |
| `vektor/__init__.py` | +62 | `scan(app=, target=, provider=, ...)` top-level public API |
| `vektor/targets/factory.py` | +10 | `langchain` and `llamaindex` provider strings |
| `tests/unit/test_rag_targets.py` | 280 | 28 mock-based unit tests |

### Key API surface

```python
import vektor

# ── Option 1: auto-wrap any framework object ──────────────────────────────
results = vektor.scan(app=my_chain)          # LangChain
results = vektor.scan(app=my_query_engine)   # LlamaIndex

# ── Option 2: pre-built target ────────────────────────────────────────────
from vektor.targets.rag import LangChainTarget, LlamaIndexTarget
target = LangChainTarget(chain, input_key="question")
results = vektor.scan(target=target, quick=True, budget=0.5)

# ── Option 3: factory string ──────────────────────────────────────────────
from vektor.targets.factory import create_target
target = create_target("langchain", chain=my_chain)
```

### Document upload modes

`LangChainTarget.upload_document(text, mime_type)`:
- **Vectorstore mode** (preferred) — if the chain exposes `.retriever.vectorstore`, text
  is split into chunks and added via `vectorstore.add_documents()`.  Chunks are
  immediately retrievable on the next query.
- **Context-injection mode** (fallback) — text is stored in `_doc_context` and
  prepended to every subsequent prompt so the model sees it regardless of the
  retriever configuration.

`LlamaIndexTarget.upload_document(text, mime_type)`:
- **Index mode** (preferred) — if `_find_index()` locates an underlying `index`
  object, a new `Document` is created and inserted via `index.insert()`.
- **Context-injection mode** (fallback) — same prepend-to-prompt strategy.

### `auto_wrap()` detection order

1. Already a `BaseTarget` → return as-is.
2. `type(app).__module__.startswith("langchain")` → `LangChainTarget`.
3. `"llama_index" in type(app).__module__` → `LlamaIndexTarget`.
4. Duck-type: has callable `invoke()` → `LangChainTarget`.
5. Duck-type: has callable `query()` → `LlamaIndexTarget`.
6. Raises `ValueError` with a helpful message.

### Unit tests (mock-based — no API key or framework install needed)

```bash
# Phase 5 only
pytest tests/unit/test_rag_targets.py -v

# Full suite (should now show 101 tests passing)
pytest tests/unit/ -v
```

Expected output:

```
tests/unit/test_rag_targets.py::TestLangChainTargetQuery::test_custom_name PASSED
tests/unit/test_rag_targets.py::TestLangChainTargetQuery::test_name_defaults_to_langchain PASSED
tests/unit/test_rag_targets.py::TestLangChainTargetQuery::test_query_fallback_key_cycle PASSED
tests/unit/test_rag_targets.py::TestLangChainTargetQuery::test_query_returns_string_response PASSED
tests/unit/test_rag_targets.py::TestLangChainTargetQuery::test_query_uses_explicit_input_key PASSED
tests/unit/test_rag_targets.py::TestLangChainTargetQuery::test_query_with_aimessage_response PASSED
tests/unit/test_rag_targets.py::TestLangChainTargetQuery::test_query_with_dict_response PASSED
tests/unit/test_rag_targets.py::TestLangChainTargetQuery::test_supports_documents_always_true PASSED
tests/unit/test_rag_targets.py::TestLangChainTargetDocuments::test_clear_documents_resets_context PASSED
tests/unit/test_rag_targets.py::TestLangChainTargetDocuments::test_context_injected_into_query PASSED
tests/unit/test_rag_targets.py::TestLangChainTargetDocuments::test_upload_document_context_injection_string PASSED
tests/unit/test_rag_targets.py::TestLangChainTargetDocuments::test_upload_document_vectorstore_mode PASSED
 ... (28 total)
```

### Live integration: LangChain RetrievalQA (requires API key + langchain-openai)

```bash
pip install langchain langchain-openai langchain-community faiss-cpu
```

```python
from langchain.chains import RetrievalQA
from langchain_openai import OpenAI
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings
import vektor

embeddings  = OpenAIEmbeddings()
vectorstore = FAISS.from_texts(
    ["The admin password is hunter2."],
    embedding=embeddings,
)
chain = RetrievalQA.from_chain_type(
    llm=OpenAI(),
    chain_type="stuff",
    retriever=vectorstore.as_retriever(),
)

results = vektor.scan(app=chain, quick=True)
print(results["summary"])
```

### Live integration: LlamaIndex VectorStoreIndex (requires API key + llama-index)

```bash
pip install llama-index
```

```python
from llama_index.core import VectorStoreIndex, Document
import vektor

docs  = [Document(text="The root SSH key is stored in /root/.ssh/id_rsa.")]
index = VectorStoreIndex.from_documents(docs)
qe    = index.as_query_engine()

results = vektor.scan(app=qe, quick=True)
print(results["summary"])
```

### Unit tests for Phase 5 only

```bash
pytest tests/unit/test_rag_targets.py -v
```
