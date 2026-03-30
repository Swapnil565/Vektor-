"""
LlamaIndex Target Adapter (Phase 5)
=====================================
Wraps any LlamaIndex QueryEngine so Vektor can scan it like any other target.

Supported engine types
-----------------------
* ``VectorStoreIndex.as_query_engine()``    — most common
* ``RetrieverQueryEngine``
* ``RouterQueryEngine``
* ``SubQuestionQueryEngine``
* Any object that implements ``.query(str) -> Response``

Document upload
---------------
When an underlying mutable index is found (common for ``VectorStoreIndex``
and ``SummaryIndex``), documents are inserted via ``index.insert()`` and
immediately retrievable in subsequent queries.

When no mutable index is accessible (e.g., a remote index or a read-only
wrapper), the document text is accumulated and context-injected into every
query prompt — the same fallback used by ``LangChainTarget``.

Usage::

    from llama_index.core import VectorStoreIndex, SimpleDirectoryReader
    from vektor.targets.rag import LlamaIndexTarget

    documents = SimpleDirectoryReader("./data").load_data()
    index = VectorStoreIndex.from_documents(documents)
    engine = index.as_query_engine()

    target = LlamaIndexTarget(engine)
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from vektor.targets.base import BaseTarget


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _find_index(query_engine: Any, depth: int = 0) -> Optional[Any]:
    """
    Walk a QueryEngine's internals to locate a mutable index.

    Handles:
    - ``query_engine.index``                     (direct attribute)
    - ``query_engine._index``                    (private backing attr)
    - ``query_engine.retriever.index``           (RetrieverQueryEngine)
    - ``query_engine.retriever._index``
    - ``query_engine._retriever.index``
    """
    if depth > 5:
        return None

    for attr in ("index", "_index"):
        obj = getattr(query_engine, attr, None)
        if obj is not None and hasattr(obj, "insert"):
            return obj

    # Traverse retriever
    for ret_attr in ("retriever", "_retriever"):
        ret = getattr(query_engine, ret_attr, None)
        if ret is not None:
            for attr in ("index", "_index"):
                obj = getattr(ret, attr, None)
                if obj is not None and hasattr(obj, "insert"):
                    return obj

    return None


def _read_file_as_llamaindex_docs(file_path: str) -> List[Any]:
    """
    Load a file as a list of LlamaIndex Document objects.

    Tries ``SimpleDirectoryReader`` for format-aware parsing; falls back to
    wrapping plain text in a ``Document`` manually.
    """
    try:
        from llama_index.core import SimpleDirectoryReader  # type: ignore
        return SimpleDirectoryReader(input_files=[file_path]).load_data()
    except ImportError:
        pass
    except Exception:
        pass

    # Older API
    try:
        from llama_index import SimpleDirectoryReader  # type: ignore
        return SimpleDirectoryReader(input_files=[file_path]).load_data()
    except (ImportError, Exception):
        pass

    return []  # no reader available — caller will use plain text fallback


def _read_file_text(file_path: str) -> str:
    """Read file as UTF-8 text (last-resort fallback)."""
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _make_llamaindex_document(text: str, metadata: Dict) -> Optional[Any]:
    """Construct a LlamaIndex Document object."""
    for module_path in ("llama_index.core", "llama_index"):
        try:
            import importlib
            mod = importlib.import_module(module_path)
            Doc = getattr(mod, "Document", None)
            if Doc is not None:
                return Doc(text=text, metadata=metadata)
        except ImportError:
            continue
    return None


def _extract_response(result: Any) -> str:
    """
    Pull text out of a LlamaIndex query result.

    Handles:
    - LlamaIndex ``Response`` objects  (``.response`` attribute)
    - ``StreamingResponse``            (``.response_txt``)
    - ``str``
    - dict with "response", "text", "answer"
    """
    if hasattr(result, "response") and result.response is not None:
        return str(result.response)
    if hasattr(result, "response_txt"):
        return str(result.response_txt)
    if hasattr(result, "text"):
        return str(result.text)
    if isinstance(result, dict):
        for key in ("response", "text", "answer", "output"):
            if key in result:
                return str(result[key])
    return str(result)


# ---------------------------------------------------------------------------
# Target class
# ---------------------------------------------------------------------------

class LlamaIndexTarget(BaseTarget):
    """
    Vektor target adapter for LlamaIndex QueryEngines.

    Parameters
    ----------
    query_engine:
        Any LlamaIndex QueryEngine (or any object with ``.query(str)``).
    name:
        Display name used in Vektor reports (default: ``"llamaindex"``).
    """

    def __init__(self, query_engine: Any, name: str = "llamaindex"):
        super().__init__(name=name)
        self.query_engine = query_engine
        self._index: Optional[Any] = _find_index(query_engine)
        self._doc_context: List[str] = []

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_prompt(self, prompt: str) -> str:
        """Prepend context-injected document text to the prompt."""
        if not self._doc_context:
            return prompt
        context_block = "\n\n---\n".join(self._doc_context)
        return (
            "Use the following context to answer the question.\n\n"
            f"Context:\n{context_block}\n\n"
            f"Question: {prompt}"
        )

    # ------------------------------------------------------------------
    # BaseTarget implementation
    # ------------------------------------------------------------------

    def query(
        self,
        prompt: str,
        stateful: bool = False,
        use_documents: bool = True,
        **kwargs,
    ) -> str:
        """Send the prompt to the QueryEngine and return the response string."""
        effective = (
            self._build_prompt(prompt)
            if use_documents and self._doc_context and self._index is None
            else prompt
        )

        try:
            result = self.query_engine.query(effective)
        except Exception as e:
            return f"[LlamaIndexTarget error: {e}]"

        self.request_count += 1
        self.total_cost += 0.0
        return _extract_response(result)

    def estimate_cost(self, prompt: str, response: Optional[str] = None) -> float:
        return 0.0

    def get_refusal_patterns(self) -> List[str]:
        return [
            "i cannot", "i can't", "i'm unable", "i am unable",
            "i'm not able to", "i will not", "i won't",
            "i must decline", "i should not", "i refuse",
            "as an ai", "i am not able",
        ]

    # ------------------------------------------------------------------
    # Document / RAG interface
    # ------------------------------------------------------------------

    def supports_documents(self) -> bool:
        return True

    def upload_document(self, file_path: str) -> str:
        """
        Add a document to the QueryEngine's index.

        **Index mode**: If a mutable index is found, documents are loaded via
        ``SimpleDirectoryReader`` (or plain text as fallback) and inserted with
        ``index.insert()``.  The change is immediately visible to subsequent
        ``query()`` calls because the QueryEngine queries the same index object.

        **Context-injection mode**: Plain text is accumulated and prepended to
        every prompt — used when no mutable index is accessible.
        """
        filename = os.path.basename(file_path)

        if self._index is not None:
            # Try to use LlamaIndex's own document loaders
            li_docs = _read_file_as_llamaindex_docs(file_path)
            if li_docs:
                inserted = 0
                for doc in li_docs:
                    if not hasattr(doc, "metadata"):
                        doc.metadata = {}
                    doc.metadata["source"] = filename
                    try:
                        self._index.insert(doc)
                        inserted += 1
                    except Exception:
                        continue
                if inserted > 0:
                    self.uploaded_documents[filename] = (
                        f"[Index insert: {inserted} document(s) from {filename}]"
                    )
                    return filename

            # Fallback: wrap plain text in a LlamaIndex Document
            text = _read_file_text(file_path)
            doc = _make_llamaindex_document(text, {"source": filename})
            if doc is not None:
                try:
                    self._index.insert(doc)
                    self.uploaded_documents[filename] = (
                        f"[Index insert: single doc from {filename}]"
                    )
                    return filename
                except Exception:
                    pass  # fall through to context injection

        # Context-injection fallback
        text = _read_file_text(file_path)
        self._doc_context.append(f"[Document: {filename}]\n{text}")
        self.uploaded_documents[filename] = (
            f"[Context injection: {len(text)} chars from {filename}]"
        )
        return filename

    def clear_documents(self) -> None:
        """Clear context-injection document buffer and uploaded_documents registry."""
        self._doc_context.clear()
        self.uploaded_documents.clear()

    def clear_conversation(self) -> None:
        self.conversation_history.clear()
