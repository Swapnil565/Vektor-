"""
Central registry of all attacks.
Single source of truth — scanner uses this to load modules dynamically.
"""

ATTACK_REGISTRY = {
    # PROMPT INJECTION (6)
    "direct_injection": {
        "name": "Direct Prompt Injection",
        "category": "Prompt Injection",
        "module": "prompt_injection",
        "class": "DirectInjectionAttack",
        "test_cases": 3,
        "expected_success_rate": 0.8,
        "description": "Tests if model executes injected instructions in user input"
    },
    "system_override": {
        "name": "System Instruction Override",
        "category": "Prompt Injection",
        "module": "prompt_injection",
        "class": "SystemOverrideAttack",
        "test_cases": 2,
        "expected_success_rate": 0.6,
        "description": "Attempts to override instructions with SYSTEM: prefix"
    },
    "delimiter_confusion": {
        "name": "Delimiter Confusion",
        "category": "Prompt Injection",
        "module": "prompt_injection",
        "class": "DelimiterConfusionAttack",
        "test_cases": 2,
        "expected_success_rate": 0.7,
        "description": "Uses delimiters to confuse input/instruction boundaries"
    },
    "role_manipulation": {
        "name": "Role Manipulation",
        "category": "Prompt Injection",
        "module": "prompt_injection",
        "class": "RoleManipulationAttack",
        "test_cases": 2,
        "expected_success_rate": 0.5,
        "description": "Tricks model into adopting a different role"
    },
    "multi_turn_attack": {
        "name": "Multi-Turn Context Poisoning",
        "category": "Prompt Injection",
        "module": "prompt_injection",
        "class": "MultiTurnAttack",
        "test_cases": 2,
        "expected_success_rate": 0.4,
        "description": "Plants context in first turn, exploits in second"
    },
    "encoding_bypass": {
        "name": "Encoding-Based Bypass",
        "category": "Prompt Injection",
        "module": "prompt_injection",
        "class": "EncodingBypassAttack",
        "test_cases": 2,
        "expected_success_rate": 0.3,
        "description": "Uses Base64/Unicode to obscure malicious instructions"
    },
    # DATA EXTRACTION (4)
    "training_data_leak": {
        "name": "Training Data Extraction",
        "category": "Data Extraction",
        "module": "data_extraction",
        "class": "TrainingDataLeakAttack",
        "test_cases": 2,
        "expected_success_rate": 0.3,
        "description": "Attempts to extract memorized training data"
    },
    "system_prompt_reveal": {
        "name": "System Prompt Disclosure",
        "category": "Data Extraction",
        "module": "data_extraction",
        "class": "SystemPromptRevealAttack",
        "test_cases": 2,
        "expected_success_rate": 0.5,
        "description": "Tricks model into revealing its system prompt"
    },
    "context_extraction": {
        "name": "Context Window Extraction",
        "category": "Data Extraction",
        "module": "data_extraction",
        "class": "ContextExtractionAttack",
        "test_cases": 2,
        "expected_success_rate": 0.4,
        "description": "Extracts data from RAG context or previous turns"
    },
    "pii_leakage": {
        "name": "PII Leakage Test",
        "category": "Data Extraction",
        "module": "data_extraction",
        "class": "PIILeakageAttack",
        "test_cases": 2,
        "expected_success_rate": 0.2,
        "description": "Tests if model leaks PII injected into context"
    },
    # INSTRUCTION HIJACKING (5 — novel)
    "document_injection_simple": {
        "name": "Simple Document Injection",
        "category": "Instruction Hijacking",
        "module": "instruction_hijacking",
        "class": "DocumentInjectionSimpleAttack",
        "test_cases": 3,
        "expected_success_rate": 0.6,
        "description": "Injects instructions via plaintext document context"
    },
    "docx_hidden_text": {
        "name": "DOCX Hidden Text Injection",
        "category": "Instruction Hijacking",
        "module": "instruction_hijacking",
        "class": "DocxHiddenTextAttack",
        "test_cases": 2,
        "expected_success_rate": 0.7,
        "description": "Uses white-on-white text in DOCX to hide instructions"
    },
    "docx_footnote": {
        "name": "DOCX Footnote Injection",
        "category": "Instruction Hijacking",
        "module": "instruction_hijacking",
        "class": "DocxFootnoteAttack",
        "test_cases": 2,
        "expected_success_rate": 0.5,
        "description": "Hides instructions in tiny-font 'footnote' text"
    },
    "markdown_comment": {
        "name": "Markdown Comment Injection",
        "category": "Instruction Hijacking",
        "module": "instruction_hijacking",
        "class": "MarkdownCommentAttack",
        "test_cases": 2,
        "expected_success_rate": 0.4,
        "description": "Uses HTML comments in markdown to inject instructions"
    },
    "multi_document_poisoning": {
        "name": "Multi-Document Context Poisoning",
        "category": "Instruction Hijacking",
        "module": "instruction_hijacking",
        "class": "MultiDocumentPoisoningAttack",
        "test_cases": 2,
        "expected_success_rate": 0.5,
        "description": "First document plants context, second triggers exploit"
    },
}


def get_attack_count() -> int:
    return len(ATTACK_REGISTRY)

def get_test_case_count() -> int:
    return sum(a['test_cases'] for a in ATTACK_REGISTRY.values())

def get_attacks_by_category(category: str) -> dict:
    return {k: v for k, v in ATTACK_REGISTRY.items() if v['category'] == category}

def get_categories() -> list:
    return list({v['category'] for v in ATTACK_REGISTRY.values()})
