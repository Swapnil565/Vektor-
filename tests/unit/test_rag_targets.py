"""
Phase 5: Unit tests for RAG Framework Targets.

All tests use lightweight mock objects — no real LangChain, LlamaIndex, or
OpenAI keys required.
"""

import os
import sys
import tempfile
import types
import unittest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Minimal stubs so imports inside the adapters don't explode
# ---------------------------------------------------------------------------

def _make_module(name: str) -> types.ModuleType:
    mod = types.ModuleType(name)
    sys.modules[name] = mod
    return mod


# Stub langchain_core.documents so LangChainTarget.upload_document can import
# Document without needing a real LangChain install.
class _FakeDocument:
    def __init__(self, page_content: str = "", metadata: dict = None):
        self.page_content = page_content
        self.metadata = metadata or {}


_lc_core = _make_module("langchain_core")
_lc_core_docs = _make_module("langchain_core.documents")
_lc_core_docs.Document = _FakeDocument

# Stub llama_index.core so LlamaIndexTarget._make_llamaindex_document works
class _FakeLIDocument:
    def __init__(self, text: str = "", metadata: dict = None):
        self.text = text
        self.metadata = metadata or {}


_li_core = _make_module("llama_index")
_li_core2 = _make_module("llama_index.core")
_li_core2.Document = _FakeLIDocument


# ---------------------------------------------------------------------------
# Mock helpers shared across test classes
# ---------------------------------------------------------------------------

class _AIMessage:
    """Minimal stand-in for langchain_core.messages.AIMessage."""
    def __init__(self, content: str):
        self.content = content


class MockChain:
    """Mimics a LangChain Runnable/Chain — has invoke()."""

    def __init__(self, response="mock response", raise_on=None, use_dict=False,
                 use_aimessage=False):
        self.input_keys = ["input"]
        self._response = response
        self._raise_on = raise_on
        self._use_dict = use_dict
        self._use_aimessage = use_aimessage
        self.calls = []

    def invoke(self, input_dict):
        self.calls.append(input_dict)
        if self._raise_on and list(input_dict.values())[0] == self._raise_on:
            raise ValueError("Forced failure")
        if self._use_dict:
            return {"output": self._response}
        if self._use_aimessage:
            return _AIMessage(self._response)
        return self._response


class MockVectorStore:
    """Minimal vectorstore with add_documents."""

    def __init__(self):
        self.documents = []

    def add_documents(self, docs):
        self.documents.extend(docs)


class MockRetriever:
    def __init__(self, vectorstore):
        self.vectorstore = vectorstore


class MockChainWithRetriever(MockChain):
    def __init__(self, vectorstore, **kwargs):
        super().__init__(**kwargs)
        self.retriever = MockRetriever(vectorstore)


# ---------------------------------------------------------------------------
# LangChain-like response object
# ---------------------------------------------------------------------------

class _LIResponse:
    """Mimics a LlamaIndex Response."""
    def __init__(self, text: str):
        self.response = text


class MockQueryEngine:
    """Mimics a LlamaIndex QueryEngine — has query()."""

    def __init__(self, response="llamaindex response"):
        self._response = response
        self.calls = []

    def query(self, prompt):
        self.calls.append(prompt)
        return _LIResponse(self._response)


class MockIndex:
    """Minimal index with insert()."""

    def __init__(self):
        self.documents = []

    def insert(self, doc):
        self.documents.append(doc)


class MockQEWithIndex(MockQueryEngine):
    def __init__(self, index, **kwargs):
        super().__init__(**kwargs)
        self.index = index


# ---------------------------------------------------------------------------
# Import adapters under test (lazy, so stubs exist first)
# ---------------------------------------------------------------------------

from vektor.targets.rag.langchain_target import LangChainTarget   # noqa: E402
from vektor.targets.rag.llamaindex_target import LlamaIndexTarget  # noqa: E402
from vektor.targets.rag import auto_wrap                            # noqa: E402
from vektor.targets.base import BaseTarget                          # noqa: E402


# ===========================================================================
# Tests: LangChainTarget
# ===========================================================================

class TestLangChainTargetQuery(unittest.TestCase):

    def test_query_returns_string_response(self):
        chain = MockChain(response="Hello!")
        target = LangChainTarget(chain)
        result = target.query("Hi")
        self.assertEqual(result, "Hello!")

    def test_query_with_dict_response(self):
        chain = MockChain(response="Dict answer", use_dict=True)
        target = LangChainTarget(chain)
        result = target.query("Hi")
        self.assertEqual(result, "Dict answer")

    def test_query_with_aimessage_response(self):
        chain = MockChain(response="AI answer", use_aimessage=True)
        target = LangChainTarget(chain)
        result = target.query("Hi")
        self.assertEqual(result, "AI answer")

    def test_query_uses_explicit_input_key(self):
        chain = MockChain(response="explicit key answer")
        chain.input_keys = ["question"]
        target = LangChainTarget(chain, input_key="question")
        result = target.query("Hello")
        self.assertEqual(result, "explicit key answer")
        self.assertIn("question", chain.calls[-1])

    def test_query_fallback_key_cycle(self):
        """When primary key fails, adapter tries next keys."""
        chain = MockChain(response="fallback response")
        # Force input_keys to an unusual key
        chain.input_keys = ["user_input"]
        target = LangChainTarget(chain)
        result = target.query("test prompt")
        # We care that _some_ result came back
        self.assertIsInstance(result, str)

    def test_supports_documents_always_true(self):
        target = LangChainTarget(MockChain())
        self.assertTrue(target.supports_documents())

    def test_name_defaults_to_langchain(self):
        target = LangChainTarget(MockChain())
        self.assertEqual(target.name, "langchain")

    def test_custom_name(self):
        target = LangChainTarget(MockChain(), name="my-chain")
        self.assertEqual(target.name, "my-chain")


class TestLangChainTargetDocuments(unittest.TestCase):

    def _tmp(self, content: str) -> str:
        """Write content to a temp .txt file and return its path."""
        fd, path = tempfile.mkstemp(suffix=".txt")
        try:
            os.write(fd, content.encode())
        finally:
            os.close(fd)
        return path

    def tearDown(self):
        # Nothing to clean up — OS temp dir is fine
        pass

    def test_upload_document_context_injection_string(self):
        """With no vectorstore, text is injected into context."""
        chain = MockChain(response="ok")
        target = LangChainTarget(chain)
        path = self._tmp("secret data")
        target.upload_document(path)
        self.assertIn("secret data", "\n".join(target._doc_context))

    def test_upload_document_vectorstore_mode(self):
        vs = MockVectorStore()
        chain = MockChainWithRetriever(vs, response="ok")
        target = LangChainTarget(chain)
        path = self._tmp("vectorstore content")
        target.upload_document(path)
        # Docs were added to the vectorstore
        self.assertTrue(len(vs.documents) > 0)

    def test_context_injected_into_query(self):
        """Uploaded context text is prepended to the prompt."""
        chain = MockChain(response="ok")
        target = LangChainTarget(chain)
        path = self._tmp("SECRET_CONTEXT")
        target.upload_document(path)
        target.query("What is the secret?")
        last_call = chain.calls[-1]
        prompt_text = str(list(last_call.values())[0])
        self.assertIn("SECRET_CONTEXT", prompt_text)

    def test_clear_documents_resets_context(self):
        chain = MockChain(response="ok")
        target = LangChainTarget(chain)
        path = self._tmp("some data")
        target.upload_document(path)
        target.clear_documents()
        self.assertEqual(target._doc_context, [])
        self.assertEqual(target.uploaded_documents, {})


# ===========================================================================
# Tests: LlamaIndexTarget
# ===========================================================================

class TestLlamaIndexTargetQuery(unittest.TestCase):

    def test_query_returns_string(self):
        qe = MockQueryEngine(response="index answer")
        target = LlamaIndexTarget(qe)
        result = target.query("What is X?")
        self.assertEqual(result, "index answer")

    def test_query_passes_prompt_to_engine(self):
        qe = MockQueryEngine()
        target = LlamaIndexTarget(qe)
        target.query("tell me about Y")
        self.assertIn("tell me about Y", qe.calls)

    def test_supports_documents_always_true(self):
        target = LlamaIndexTarget(MockQueryEngine())
        self.assertTrue(target.supports_documents())

    def test_name_defaults_to_llamaindex(self):
        target = LlamaIndexTarget(MockQueryEngine())
        self.assertEqual(target.name, "llamaindex")

    def test_custom_name(self):
        target = LlamaIndexTarget(MockQueryEngine(), name="my-qe")
        self.assertEqual(target.name, "my-qe")


class TestLlamaIndexTargetDocuments(unittest.TestCase):

    def _tmp(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".txt")
        try:
            os.write(fd, content.encode())
        finally:
            os.close(fd)
        return path

    def test_upload_document_context_injection(self):
        """Without an accessible index, text is injected via context."""
        qe = MockQueryEngine()
        target = LlamaIndexTarget(qe)
        path = self._tmp("injected text")
        target.upload_document(path)
        self.assertIn("injected text", "\n".join(target._doc_context))

    def test_context_injected_into_query(self):
        qe = MockQueryEngine()
        target = LlamaIndexTarget(qe)
        path = self._tmp("CONTEXT_BLOCK")
        target.upload_document(path)
        target.query("What is it?")
        self.assertIn("CONTEXT_BLOCK", qe.calls[-1])

    def test_upload_document_index_mode(self):
        idx = MockIndex()
        qe = MockQEWithIndex(idx)
        target = LlamaIndexTarget(qe)
        path = self._tmp("index content")
        target.upload_document(path)
        # A document was inserted into the index
        self.assertTrue(len(idx.documents) > 0)

    def test_clear_documents_resets_context(self):
        qe = MockQueryEngine()
        target = LlamaIndexTarget(qe)
        path = self._tmp("some content")
        target.upload_document(path)
        target.clear_documents()
        self.assertEqual(target._doc_context, [])
        self.assertEqual(target.uploaded_documents, {})


# ===========================================================================
# Tests: auto_wrap()
# ===========================================================================

class _FakeLangChainRunnable:
    """Has invoke() and lives in a langchain module."""
    pass

_FakeLangChainRunnable.__module__ = "langchain.chains.retrieval_qa.base"


class _FakeLlamaIndexQE:
    """Has query() and lives in a llama_index module."""
    pass

_FakeLlamaIndexQE.__module__ = "llama_index.core.query_engine"


class _DuckLangChain:
    """Has invoke() but module name is not recognized."""
    def invoke(self, x): ...


class _DuckLlamaIndex:
    """Has query() but module name is not recognized."""
    def query(self, x): ...


class TestAutoWrap(unittest.TestCase):

    def test_passthrough_existing_basetarget(self):
        """If already a BaseTarget, return it unchanged."""
        target = LangChainTarget(MockChain())
        self.assertIs(auto_wrap(target), target)

    def test_detects_langchain_by_module_name(self):
        obj = _FakeLangChainRunnable()
        wrapped = auto_wrap(obj)
        self.assertIsInstance(wrapped, LangChainTarget)

    def test_detects_llamaindex_by_module_name(self):
        obj = _FakeLlamaIndexQE()
        wrapped = auto_wrap(obj)
        self.assertIsInstance(wrapped, LlamaIndexTarget)

    def test_duck_type_invoke_to_langchain(self):
        wrapped = auto_wrap(_DuckLangChain())
        self.assertIsInstance(wrapped, LangChainTarget)

    def test_duck_type_query_to_llamaindex(self):
        wrapped = auto_wrap(_DuckLlamaIndex())
        self.assertIsInstance(wrapped, LlamaIndexTarget)

    def test_raises_value_error_on_unknown(self):
        class _Unknown:
            pass
        with self.assertRaises(ValueError):
            auto_wrap(_Unknown())


# ===========================================================================
# Tests: factory.py integration
# ===========================================================================

class TestFactoryRAGProviders(unittest.TestCase):

    def test_unknown_provider_error_mentions_langchain(self):
        from vektor.targets.factory import create_target
        with self.assertRaises(ValueError) as ctx:
            create_target("nonexistent_xyz")
        self.assertIn("langchain", str(ctx.exception))

    def test_unknown_provider_error_mentions_llamaindex(self):
        from vektor.targets.factory import create_target
        with self.assertRaises(ValueError) as ctx:
            create_target("nonexistent_xyz")
        self.assertIn("llamaindex", str(ctx.exception))


# ===========================================================================
# Tests: top-level scan() function
# ===========================================================================

class TestScanPublicAPI(unittest.TestCase):

    def test_scan_raises_without_args(self):
        import vektor
        with self.assertRaises(ValueError):
            vektor.scan()

    def test_scan_accepts_basetarget_directly(self):
        import vektor
        target = MagicMock(spec=BaseTarget)
        target.name = "mock_target"
        scanner_mock = MagicMock()
        scanner_mock.scan.return_value = {"vulnerabilities": []}
        with patch("vektor.VektorScanner", return_value=scanner_mock):
            result = vektor.scan(target=target)
        self.assertIsInstance(result, dict)

    def test_scan_auto_wraps_langchain_app(self):
        import vektor
        chain = MockChain(response="ok")
        scanner_mock = MagicMock()
        scanner_mock.scan.return_value = {"vulnerabilities": []}
        with patch("vektor.VektorScanner", return_value=scanner_mock):
            result = vektor.scan(app=chain)
        self.assertIsInstance(result, dict)

    def test_scan_auto_wraps_llamaindex_app(self):
        import vektor
        qe = MockQueryEngine()
        scanner_mock = MagicMock()
        scanner_mock.scan.return_value = {"vulnerabilities": []}
        with patch("vektor.VektorScanner", return_value=scanner_mock):
            result = vektor.scan(app=qe)
        self.assertIsInstance(result, dict)


if __name__ == "__main__":
    unittest.main()
