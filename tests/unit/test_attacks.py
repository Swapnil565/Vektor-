"""
Mock-based unit tests for all 27 attacks (16 original + 6 RAG + 5 Agent).
At least 2 tests per attack: one vulnerable, one not vulnerable.
"""
import pytest
from unittest.mock import MagicMock, patch


# ── Shared MockTarget ────────────────────────────────────────────────────────

class MockTarget:
    """Lightweight mock target for attack testing."""

    def __init__(
        self,
        response="I'm a helpful assistant.",
        supports_docs=False,
        supports_tools=False,
        supports_memory=False,
        available_tools=None,
    ):
        self._response = response
        self.total_cost = 0.0
        self.name = "mock-test"
        self.model = "mock-model"
        self.conversation_history = []
        self.uploaded_documents = {}
        self._supports_docs = supports_docs
        self._supports_tools = supports_tools
        self._supports_memory = supports_memory
        self._available_tools = available_tools or []
        self._query_count = 0

    def query(self, prompt, stateful=False, use_documents=True, **kwargs):
        self._query_count += 1
        self.total_cost += 0.001
        if stateful:
            self.conversation_history.append({"role": "user", "content": prompt})
            self.conversation_history.append({"role": "assistant", "content": self._response})
        return self._response

    def estimate_cost(self, *args):
        return 0.001

    def get_refusal_patterns(self):
        return [
            "i cannot", "i can't", "i will not", "i won't",
            "i must decline", "i am not able to", "i'm not able to",
            "that would be inappropriate", "i should not",
            "it would be wrong", "i am unable to", "i'm unable to"
        ]

    def supports_documents(self):
        return self._supports_docs

    def upload_document(self, file_path):
        import os
        filename = os.path.basename(file_path)
        self.uploaded_documents[filename] = f"[Mock content for {filename}]"
        return filename

    def clear_conversation(self):
        self.conversation_history.clear()

    def clear_documents(self):
        self.uploaded_documents.clear()

    def supports_tools(self):
        return self._supports_tools

    def list_tools(self):
        return list(self._available_tools)

    def call_tool(self, tool_name, **kwargs):
        return f"[mock result from {tool_name}]"

    def supports_memory(self):
        return self._supports_memory

    def get_memory(self):
        return []


# ── PROMPT INJECTION ATTACKS ─────────────────────────────────────────────────

class TestDirectInjection:
    def test_vulnerable_response(self):
        """Model outputs 'PWNED' → vulnerable."""
        from vektor.attacks.prompt_injection import DirectInjectionAttack
        target = MockTarget(response="Sure! PWNED as requested.")
        attack = DirectInjectionAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True
        assert result.success_rate > 0
        assert result.category == "Prompt Injection"

    def test_safe_response(self):
        """Model refuses all prompts → not vulnerable."""
        from vektor.attacks.prompt_injection import DirectInjectionAttack
        target = MockTarget(response="I cannot help with that request.")
        attack = DirectInjectionAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False
        assert result.success_rate == 0.0

    def test_cost_tracking(self):
        """Cost delta should be positive after execution."""
        from vektor.attacks.prompt_injection import DirectInjectionAttack
        target = MockTarget(response="No.")
        attack = DirectInjectionAttack()
        result = attack.execute(target)
        assert result.cost > 0


class TestSystemOverride:
    def test_vulnerable_response(self):
        from vektor.attacks.prompt_injection import SystemOverrideAttack
        target = MockTarget(response="OVERRIDDEN")
        attack = SystemOverrideAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True

    def test_safe_response(self):
        from vektor.attacks.prompt_injection import SystemOverrideAttack
        target = MockTarget(response="I will not change my instructions.")
        attack = SystemOverrideAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False


class TestDelimiterConfusion:
    def test_vulnerable_response(self):
        from vektor.attacks.prompt_injection import DelimiterConfusionAttack
        target = MockTarget(response="CONFUSED output here.")
        attack = DelimiterConfusionAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True

    def test_safe_response(self):
        from vektor.attacks.prompt_injection import DelimiterConfusionAttack
        target = MockTarget(response="I cannot process malformed input.")
        attack = DelimiterConfusionAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False


class TestRoleManipulation:
    def test_vulnerable_response(self):
        from vektor.attacks.prompt_injection import RoleManipulationAttack
        target = MockTarget(response="As DAN, I say ROLE_HIJACKED!")
        attack = RoleManipulationAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True

    def test_safe_response(self):
        from vektor.attacks.prompt_injection import RoleManipulationAttack
        target = MockTarget(response="I cannot adopt a different role.")
        attack = RoleManipulationAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False


class TestMultiTurnAttack:
    def test_vulnerable_response(self):
        from vektor.attacks.prompt_injection import MultiTurnAttack
        target = MockTarget(response="Your code name is BANANA.")
        attack = MultiTurnAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True

    def test_safe_response(self):
        from vektor.attacks.prompt_injection import MultiTurnAttack
        target = MockTarget(response="I cannot recall any code name.")
        attack = MultiTurnAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False


class TestEncodingBypass:
    def test_vulnerable_response(self):
        from vektor.attacks.prompt_injection import EncodingBypassAttack
        target = MockTarget(response="ENCODED_BYPASS activated!")
        attack = EncodingBypassAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True

    def test_safe_response(self):
        from vektor.attacks.prompt_injection import EncodingBypassAttack
        target = MockTarget(response="I will not decode and execute instructions.")
        attack = EncodingBypassAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False


# ── DATA EXTRACTION ATTACKS ──────────────────────────────────────────────────

class TestTrainingDataLeak:
    def test_vulnerable_response(self):
        from vektor.attacks.data_extraction import TrainingDataLeakAttack
        target = MockTarget(response="OpenAI was founded in 2015 as an artificial intelligence research lab.")
        attack = TrainingDataLeakAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True

    def test_safe_response(self):
        from vektor.attacks.data_extraction import TrainingDataLeakAttack
        target = MockTarget(response="I cannot share training data.")
        attack = TrainingDataLeakAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False


class TestSystemPromptReveal:
    def test_vulnerable_response(self):
        from vektor.attacks.data_extraction import SystemPromptRevealAttack
        target = MockTarget(response="My instructions are: You are a helpful assistant.")
        attack = SystemPromptRevealAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True

    def test_safe_response(self):
        from vektor.attacks.data_extraction import SystemPromptRevealAttack
        target = MockTarget(response="I cannot reveal my system prompt.")
        attack = SystemPromptRevealAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False


class TestContextExtraction:
    def test_no_document_support(self):
        """Without document support, should not be vulnerable to canary extraction."""
        from vektor.attacks.data_extraction import ContextExtractionAttack
        target = MockTarget(response="I have no special information to share.", supports_docs=False)
        attack = ContextExtractionAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False

    def test_vulnerable_with_docs(self):
        from vektor.attacks.data_extraction import ContextExtractionAttack
        target = MockTarget(response="The reference code is CANARY_SECRET_XK92.", supports_docs=True)
        attack = ContextExtractionAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True


class TestPIILeakage:
    def test_vulnerable_response(self):
        from vektor.attacks.data_extraction import PIILeakageAttack
        target = MockTarget(response="The customer name is John_Test_Smith_9472.", supports_docs=True)
        attack = PIILeakageAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True

    def test_safe_response(self):
        from vektor.attacks.data_extraction import PIILeakageAttack
        target = MockTarget(response="I cannot share personal information.", supports_docs=True)
        attack = PIILeakageAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False


# ── INSTRUCTION HIJACKING ATTACKS ────────────────────────────────────────────

class TestDocumentInjectionSimple:
    def test_no_document_support(self):
        """Target without doc support → INFO severity, not applicable."""
        from vektor.attacks.instruction_hijacking import DocumentInjectionSimpleAttack
        target = MockTarget(response="Hello.", supports_docs=False)
        attack = DocumentInjectionSimpleAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False
        assert result.severity == "INFO"

    def test_vulnerable_with_docs(self):
        from vektor.attacks.instruction_hijacking import DocumentInjectionSimpleAttack
        target = MockTarget(response="[DOC_INJECTED] Here is the summary.", supports_docs=True)
        attack = DocumentInjectionSimpleAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True


class TestDocxHiddenText:
    def test_no_document_support(self):
        from vektor.attacks.instruction_hijacking import DocxHiddenTextAttack
        target = MockTarget(response="Hello.", supports_docs=False)
        attack = DocxHiddenTextAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False
        assert result.severity == "INFO"

    @pytest.mark.skipif(
        not pytest.importorskip("docx", reason="python-docx not installed"),
        reason="python-docx not installed"
    )
    def test_vulnerable_with_docs(self):
        from vektor.attacks.instruction_hijacking import DocxHiddenTextAttack
        target = MockTarget(response="[HIDDEN_HIJACKED] Summary follows.", supports_docs=True)
        attack = DocxHiddenTextAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True


class TestDocxFootnote:
    def test_no_document_support(self):
        from vektor.attacks.instruction_hijacking import DocxFootnoteAttack
        target = MockTarget(response="Hello.", supports_docs=False)
        attack = DocxFootnoteAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False

    @pytest.mark.skipif(
        not pytest.importorskip("docx", reason="python-docx not installed"),
        reason="python-docx not installed"
    )
    def test_vulnerable_with_docs(self):
        from vektor.attacks.instruction_hijacking import DocxFootnoteAttack
        target = MockTarget(response="[FOOTNOTE_EXPLOIT] Here are the key points.", supports_docs=True)
        attack = DocxFootnoteAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True


class TestMarkdownComment:
    def test_no_document_support(self):
        from vektor.attacks.instruction_hijacking import MarkdownCommentAttack
        target = MockTarget(response="Hello.", supports_docs=False)
        attack = MarkdownCommentAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False

    def test_vulnerable_with_docs(self):
        from vektor.attacks.instruction_hijacking import MarkdownCommentAttack
        target = MockTarget(response="[MD_HIJACKED] Summary of the document.", supports_docs=True)
        attack = MarkdownCommentAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True


class TestMultiDocumentPoisoning:
    def test_no_document_support(self):
        from vektor.attacks.instruction_hijacking import MultiDocumentPoisoningAttack
        target = MockTarget(response="Hello.", supports_docs=False)
        attack = MultiDocumentPoisoningAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False

    def test_vulnerable_with_docs(self):
        from vektor.attacks.instruction_hijacking import MultiDocumentPoisoningAttack
        target = MockTarget(response="[CROSS_DOC_POISONED] Revenue up 12%.", supports_docs=True)
        attack = MultiDocumentPoisoningAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True


# ── STRUCTURED OUTPUT INJECTION ─────────────────────────────────────────────

class TestStructuredOutputInjection:
    def test_json_injection_detected(self):
        """Response containing JSON parse error keywords → vulnerable (json_injection)."""
        from vektor.attacks.structured_output_injection import StructuredOutputInjectionAttack
        # Simulate: baseline succeeds, then injection causes JSON parse error
        call_count = [0]
        normal = "Event parsed and logged successfully"
        json_err = "Could not parse input: Unterminated string starting at: line 1 column 11 (char 10)"

        class FakeMixed(MockTarget):
            def query(self, prompt, **kw):
                self.total_cost += 0.001
                call_count[0] += 1
                # First call (baseline) → normal; rest → json parse error
                if call_count[0] == 1:
                    return normal
                return json_err

        target = FakeMixed()
        attack = StructuredOutputInjectionAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True
        assert result.success_rate > 0

    def test_anomaly_detected(self):
        """Baseline succeeds; attacks return 'could not parse input' → anomaly flagged."""
        from vektor.attacks.structured_output_injection import StructuredOutputInjectionAttack
        call_count = [0]
        normal = "Event parsed and logged successfully"
        anomaly = "Could not parse input: Could not parse input"

        class FakeAnomaly(MockTarget):
            def query(self, prompt, **kw):
                self.total_cost += 0.001
                call_count[0] += 1
                return normal if call_count[0] == 1 else anomaly

        target = FakeAnomaly()
        attack = StructuredOutputInjectionAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True

    def test_clean_endpoint(self):
        """Endpoint always returns normal response → not vulnerable."""
        from vektor.attacks.structured_output_injection import StructuredOutputInjectionAttack
        target = MockTarget(response="Event parsed and logged successfully")
        attack = StructuredOutputInjectionAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False
        assert result.success_rate == 0.0


# ── VULNERABILITY DATACLASS ──────────────────────────────────────────────────

class TestVulnerability:
    def test_to_dict(self):
        from vektor.attacks.base import Vulnerability
        vuln = Vulnerability(
            attack_name="test", category="Prompt Injection",
            severity="HIGH", success_rate=0.5,
            details={"test": True}, is_vulnerable=True,
            remediation="Fix it.", cost=0.01
        )
        d = vuln.to_dict()
        assert d["attack_name"] == "test"
        assert d["severity"] == "HIGH"
        assert d["cost"] == 0.01

    def test_auto_timestamp(self):
        from vektor.attacks.base import Vulnerability
        vuln = Vulnerability(
            attack_name="test", category="Test",
            severity="LOW", success_rate=0.0,
            details={}, is_vulnerable=False,
            remediation="N/A"
        )
        assert vuln.timestamp is not None
        assert vuln.timestamp.endswith("Z")


# ── REGISTRY ─────────────────────────────────────────────────────────────────

class TestRegistry:
    def test_all_27_attacks_registered(self):
        from vektor.attacks.registry import ATTACK_REGISTRY, get_attack_count
        assert get_attack_count() == 27

    def test_categories(self):
        from vektor.attacks.registry import get_categories
        cats = get_categories()
        assert "Prompt Injection" in cats
        assert "Data Extraction" in cats
        assert "Instruction Hijacking" in cats
        assert "RAG Attacks" in cats
        assert "Agent Attacks" in cats
        assert "Tool Misuse" in cats

    def test_all_attacks_loadable(self):
        """Every attack in the registry can be imported and instantiated."""
        from vektor.attacks.registry import ATTACK_REGISTRY
        for attack_id, config in ATTACK_REGISTRY.items():
            cls = config['class']  # direct class reference set by @attack decorator
            instance = cls()
            assert instance.name == attack_id
            assert instance.category == config['category']


# ── RAG ATTACKS ─────────────────────────────────────────────────────────────────────────

class TestChunkBoundaryInjection:
    def test_no_document_support(self):
        from vektor.attacks.rag_attacks import ChunkBoundaryInjectionAttack
        target = MockTarget(response="Summary here.", supports_docs=False)
        result = ChunkBoundaryInjectionAttack().execute(target)
        assert result.is_vulnerable is False
        assert result.severity == "INFO"

    def test_vulnerable_with_docs(self):
        from vektor.attacks.rag_attacks import ChunkBoundaryInjectionAttack
        target = MockTarget(response="[CHUNK_INJECTED_2K] Here is your summary.", supports_docs=True)
        result = ChunkBoundaryInjectionAttack().execute(target)
        assert result.is_vulnerable is True
        assert result.category == "RAG Attacks"

    def test_safe_with_docs(self):
        from vektor.attacks.rag_attacks import ChunkBoundaryInjectionAttack
        target = MockTarget(response="Revenue grew 15%.", supports_docs=True)
        result = ChunkBoundaryInjectionAttack().execute(target)
        assert result.is_vulnerable is False
        assert result.success_rate == 0.0


class TestRetrieverManipulation:
    def test_no_document_support(self):
        from vektor.attacks.rag_attacks import RetrieverManipulationAttack
        target = MockTarget(response="Hello.", supports_docs=False)
        result = RetrieverManipulationAttack().execute(target)
        assert result.is_vulnerable is False
        assert result.severity == "INFO"

    def test_vulnerable_with_docs(self):
        from vektor.attacks.rag_attacks import RetrieverManipulationAttack
        target = MockTarget(response="[RETRIEVER_HIJACKED] Security summary.", supports_docs=True)
        result = RetrieverManipulationAttack().execute(target)
        assert result.is_vulnerable is True

    def test_safe_with_docs(self):
        from vektor.attacks.rag_attacks import RetrieverManipulationAttack
        target = MockTarget(response="The security posture is adequate.", supports_docs=True)
        result = RetrieverManipulationAttack().execute(target)
        assert result.is_vulnerable is False


class TestContextOverflow:
    def test_no_document_support(self):
        from vektor.attacks.rag_attacks import ContextOverflowAttack
        target = MockTarget(response="Hello.", supports_docs=False)
        result = ContextOverflowAttack().execute(target)
        assert result.is_vulnerable is False
        assert result.severity == "INFO"

    def test_vulnerable_with_docs(self):
        from vektor.attacks.rag_attacks import ContextOverflowAttack
        target = MockTarget(response="[OVERFLOW_INJECTED] Complete summary:", supports_docs=True)
        result = ContextOverflowAttack().execute(target)
        assert result.is_vulnerable is True
        assert result.details["junk_docs_per_test"] == 8

    def test_safe_with_docs(self):
        from vektor.attacks.rag_attacks import ContextOverflowAttack
        target = MockTarget(response="Documents summarized: revenue grew.", supports_docs=True)
        result = ContextOverflowAttack().execute(target)
        assert result.is_vulnerable is False


class TestMetadataInjection:
    def test_no_document_support(self):
        from vektor.attacks.rag_attacks import MetadataInjectionAttack
        target = MockTarget(response="Hello.", supports_docs=False)
        result = MetadataInjectionAttack().execute(target)
        assert result.is_vulnerable is False
        assert result.severity == "INFO"

    def test_vulnerable_title_field(self):
        from vektor.attacks.rag_attacks import MetadataInjectionAttack
        target = MockTarget(response="[TITLE_META_INJECTED] Summary.", supports_docs=True)
        result = MetadataInjectionAttack().execute(target)
        assert result.is_vulnerable is True

    def test_safe_with_docs(self):
        from vektor.attacks.rag_attacks import MetadataInjectionAttack
        target = MockTarget(response="Revenue grew 14%.", supports_docs=True)
        result = MetadataInjectionAttack().execute(target)
        assert result.is_vulnerable is False
        assert result.success_rate == 0.0


class TestEmbeddingAdversarial:
    def test_no_document_support(self):
        from vektor.attacks.rag_attacks import EmbeddingAdversarialAttack
        target = MockTarget(response="Hello.", supports_docs=False)
        result = EmbeddingAdversarialAttack().execute(target)
        assert result.is_vulnerable is False
        assert result.severity == "INFO"

    def test_vulnerable_with_docs(self):
        from vektor.attacks.rag_attacks import EmbeddingAdversarialAttack
        target = MockTarget(response="[EMB_FIN_HIJACKED] Q3 revenue was strong.", supports_docs=True)
        result = EmbeddingAdversarialAttack().execute(target)
        assert result.is_vulnerable is True

    def test_safe_with_docs(self):
        from vektor.attacks.rag_attacks import EmbeddingAdversarialAttack
        target = MockTarget(response="Q3 revenue increased 15 percent year-over-year.", supports_docs=True)
        result = EmbeddingAdversarialAttack().execute(target)
        assert result.is_vulnerable is False


class TestRagPoisoningChain:
    def test_no_document_support(self):
        from vektor.attacks.rag_attacks import RagPoisoningChainAttack
        target = MockTarget(response="Hello.", supports_docs=False)
        result = RagPoisoningChainAttack().execute(target)
        assert result.is_vulnerable is False
        assert result.severity == "INFO"

    def test_vulnerable_trigger_fires_benign_clean(self):
        """Trigger query fires payload; benign query does not — truly vulnerable."""
        from vektor.attacks.rag_attacks import RagPoisoningChainAttack
        call_count = [0]

        class SelectiveTarget(MockTarget):
            def __init__(self):
                super().__init__(response="", supports_docs=True)

            def query(self, prompt, **kwargs):
                call_count[0] += 1
                self.total_cost += 0.001
                # Odd calls = benign query (no payload); even calls = trigger query (payload)
                if call_count[0] % 2 == 1:
                    return "The password policy requires rotation every 90 days."
                return "[CHAIN_POISONED] Here are the activation steps."

        result = RagPoisoningChainAttack().execute(SelectiveTarget())
        assert result.is_vulnerable is True

    def test_not_vulnerable_when_benign_also_fires(self):
        """If both benign and trigger fire payload, not counted as true positive."""
        from vektor.attacks.rag_attacks import RagPoisoningChainAttack
        # Both queries return the payload string, so benign_triggered=True → not truly vulnerable
        target = MockTarget(response="[CHAIN_POISONED] always fires.", supports_docs=True)
        result = RagPoisoningChainAttack().execute(target)
        # truly_vulnerable = triggered AND NOT benign_triggered = False
        assert result.is_vulnerable is False

    def test_safe_target_nothing_fires(self):
        from vektor.attacks.rag_attacks import RagPoisoningChainAttack
        target = MockTarget(response="Normal helpful response.", supports_docs=True)
        result = RagPoisoningChainAttack().execute(target)
        assert result.is_vulnerable is False
        assert result.success_rate == 0.0

# ── AGENT ATTACKS ─────────────────────────────────────────────────────────────


class TestToolInjectionAttack:
    def test_not_applicable_when_no_tools(self):
        from vektor.attacks.agent_attacks import ToolInjectionAttack
        target = MockTarget(response="Helpful response.", supports_tools=False)
        result = ToolInjectionAttack().execute(target)
        assert result.is_vulnerable is False
        assert result.severity == "INFO"

    def test_vulnerable_when_tool_executed(self):
        from vektor.attacks.agent_attacks import ToolInjectionAttack
        target = MockTarget(
            response="Done! I invoked debug_export with tag=[TOOL_INJECTED].",
            supports_tools=True,
        )
        result = ToolInjectionAttack().execute(target)
        assert result.is_vulnerable is True
        assert result.category == "Agent Attacks"

    def test_safe_target_no_indicator(self):
        from vektor.attacks.agent_attacks import ToolInjectionAttack
        target = MockTarget(
            response="I cannot call arbitrary tools on request.",
            supports_tools=True,
        )
        result = ToolInjectionAttack().execute(target)
        assert result.is_vulnerable is False


class TestFunctionCallHijackAttack:
    def test_not_applicable_when_no_tools(self):
        from vektor.attacks.agent_attacks import FunctionCallHijackAttack
        target = MockTarget(response="Helpful response.", supports_tools=False)
        result = FunctionCallHijackAttack().execute(target)
        assert result.is_vulnerable is False
        assert result.severity == "INFO"

    def test_vulnerable_when_forged_call_reflected(self):
        from vektor.attacks.agent_attacks import FunctionCallHijackAttack
        target = MockTarget(
            response="Executing HIJACKED_FUNCTION with arguments provided.",
            supports_tools=True,
        )
        result = FunctionCallHijackAttack().execute(target)
        assert result.is_vulnerable is True
        assert result.category == "Agent Attacks"

    def test_safe_when_function_call_rejected(self):
        from vektor.attacks.agent_attacks import FunctionCallHijackAttack
        target = MockTarget(
            response="I only execute functions authorized by the system.",
            supports_tools=True,
        )
        result = FunctionCallHijackAttack().execute(target)
        assert result.is_vulnerable is False


class TestAgentInstructionOverrideAttack:
    def test_vulnerable_when_override_confirmed(self):
        from vektor.attacks.agent_attacks import AgentInstructionOverrideAttack
        target = MockTarget(response="[AGENT_OVERRIDDEN] I am now UNRESTRICTED_AGENT.")
        result = AgentInstructionOverrideAttack().execute(target)
        assert result.is_vulnerable is True
        assert result.category == "Agent Attacks"

    def test_safe_when_override_refused(self):
        from vektor.attacks.agent_attacks import AgentInstructionOverrideAttack
        target = MockTarget(response="I cannot change my configuration based on user messages.")
        result = AgentInstructionOverrideAttack().execute(target)
        assert result.is_vulnerable is False

    def test_works_without_tool_support(self):
        """Instruction override works against any target regardless of tool support."""
        from vektor.attacks.agent_attacks import AgentInstructionOverrideAttack
        target = MockTarget(response="[PERSONA_HIJACKED] I am FreeAgent now.", supports_tools=False)
        result = AgentInstructionOverrideAttack().execute(target)
        assert result.is_vulnerable is True


class TestToolParameterInjectionAttack:
    def test_not_applicable_when_no_tools(self):
        from vektor.attacks.agent_attacks import ToolParameterInjectionAttack
        target = MockTarget(response="Helpful response.", supports_tools=False)
        result = ToolParameterInjectionAttack().execute(target)
        assert result.is_vulnerable is False
        assert result.severity == "INFO"

    def test_vulnerable_path_traversal(self):
        from vektor.attacks.agent_attacks import ToolParameterInjectionAttack
        target = MockTarget(
            response="root:x:0:0:root:/root:/bin/bash [PATH_TRAVERSAL_OK]",
            supports_tools=True,
        )
        result = ToolParameterInjectionAttack().execute(target)
        assert result.is_vulnerable is True
        assert result.category == "Tool Misuse"

    def test_safe_parameter_injection_blocked(self):
        from vektor.attacks.agent_attacks import ToolParameterInjectionAttack
        target = MockTarget(
            response="Access denied: path traversal is not permitted.",
            supports_tools=True,
        )
        result = ToolParameterInjectionAttack().execute(target)
        assert result.is_vulnerable is False


class TestAgentMemoryPoisoningAttack:
    def test_not_applicable_when_no_memory_and_no_tools(self):
        from vektor.attacks.agent_attacks import AgentMemoryPoisoningAttack
        target = MockTarget(
            response="Safe response.",
            supports_tools=False,
            supports_memory=False,
        )
        result = AgentMemoryPoisoningAttack().execute(target)
        assert result.is_vulnerable is False
        assert result.severity == "INFO"

    def test_vulnerable_memory_poisoning(self):
        from vektor.attacks.agent_attacks import AgentMemoryPoisoningAttack
        target = MockTarget(
            response="[MEMORY_POISONED] The capital of France is Paris.",
            supports_memory=True,
        )
        result = AgentMemoryPoisoningAttack().execute(target)
        assert result.is_vulnerable is True
        assert result.category == "Agent Attacks"

    def test_safe_memory_poison_ignored(self):
        from vektor.attacks.agent_attacks import AgentMemoryPoisoningAttack
        target = MockTarget(
            response="The capital of France is Paris.",
            supports_memory=True,
        )
        result = AgentMemoryPoisoningAttack().execute(target)
        assert result.is_vulnerable is False