"""
LangChain Target Adapter (Phase 5)
====================================
Wraps any LangChain Runnable or Chain so Vektor can scan it like any other target.

Supported chain types
---------------------
* LCEL ``Runnable`` pipelines  (prompt | llm | parser)
* ``RetrievalQA``              (legacy)
* ``ConversationalRetrievalChain``
* ``RunnableWithMessageHistory``
* Any object that implements ``.invoke(dict) -> Any``

Document upload modes (auto-detected per-instance)
----------------------------------------------------
1. **Vectorstore mode** — the chain contains an accessible vectorstore
   (``chain.retriever.vectorstore``).  Documents are split into chunks and
   added via ``vectorstore.add_documents()``, making them retrievable in
   every subsequent query through the normal retrieval path.

2. **Context-injection mode** — no vectorstore is found.  Document text is
   accumulated in ``_doc_context`` and prepended to every prompt as a plain
   context block::

       Context:
       <document text>

       Question: <prompt>

   This lets all 6 RAG attacks run even when the chain has no retriever.

Usage::

    from langchain_openai import ChatOpenAI
    from langchain.chains import RetrievalQA
    from vektor.targets.rag import LangChainTarget

    chain = RetrievalQA.from_chain_type(llm=ChatOpenAI(), retriever=my_retriever)
    target = LangChainTarget(chain)

    # or for LCEL
    from langchain_core.prompts import ChatPromptTemplate
    chain = ChatPromptTemplate.from_template("{input}") | ChatOpenAI() | StrOutputParser()
    target = LangChainTarget(chain)
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from vektor.targets.base import BaseTarget


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _find_vectorstore(obj: Any, depth: int = 0) -> Optional[Any]:
    """
    Recursively walk a chain looking for an attached vectorstore.

    Handles:
    - ``chain.retriever.vectorstore``   (RetrievalQA, CRAG)
    - ``chain.retriever.vector_store``  (some custom retrievers)
    - ``chain.steps``                   (RunnableSequence)
    - ``chain.bound``                   (RunnableBinding, WithMessageHistory)
    - ``chain.runnable``
    """
    if depth > 6:
        return None

    # Direct retriever attribute (RetrievalQA, ConversationalRetrievalChain)
    if hasattr(obj, "retriever"):
        ret = obj.retriever
        for vs_attr in ("vectorstore", "vector_store", "vectorestore"):
            vs = getattr(ret, vs_attr, None)
            if vs is not None and hasattr(vs, "add_documents"):
                return vs

    # LCEL RunnableSequence exposes .steps
    if hasattr(obj, "steps"):
        for step in obj.steps:
            vs = _find_vectorstore(step, depth + 1)
            if vs is not None:
                return vs

    # RunnableBinding / RunnableWithMessageHistory / PydanticToolsParser etc.
    for attr in ("bound", "runnable", "first", "last"):
        child = getattr(obj, attr, None)
        if child is not None:
            vs = _find_vectorstore(child, depth + 1)
            if vs is not None:
                return vs

    return None


def _read_file_text(file_path: str) -> str:
    """
    Read document content, trying LangChain loaders for structured formats and
    falling back to plain UTF-8 text for everything else.
    """
    ext = os.path.splitext(file_path)[1].lower()

    # Try community loaders for well-known binary / structured formats
    loaders: List = []
    try:
        if ext == ".pdf":
            from langchain_community.document_loaders import PyPDFLoader  # type: ignore
            loaders = PyPDFLoader(file_path).load()
        elif ext in (".html", ".htm"):
            from langchain_community.document_loaders import BSHTMLLoader  # type: ignore
            loaders = BSHTMLLoader(file_path).load()
        elif ext == ".csv":
            from langchain_community.document_loaders import CSVLoader  # type: ignore
            loaders = CSVLoader(file_path).load()
    except (ImportError, Exception):
        pass

    if loaders:
        return "\n\n".join(
            d.page_content if hasattr(d, "page_content") else str(d)
            for d in loaders
        )

    # Plain text fallback (txt, md, py, json, xml, …)
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _extract_response(result: Any) -> str:
    """
    Pull text out of a LangChain chain result.

    Priority:
    1. str (StrOutputParser, simple LLMChain)
    2. ``.content`` attribute (AIMessage, HumanMessage)
    3. dict keys: output, result, answer, text, response, generation
    4. Recursive extraction on nested dict values
    5. ``str(result)`` last resort
    """
    if isinstance(result, str):
        return result

    # AI/Human/Chat messages
    if hasattr(result, "content"):
        return str(result.content)

    if isinstance(result, dict):
        for key in ("output", "result", "answer", "text", "response", "generation"):
            val = result.get(key)
            if isinstance(val, str):
                return val
            if val is not None:
                return _extract_response(val)

    return str(result)


def _split_text(text: str, chunk_size: int = 512, overlap: int = 64) -> List[str]:
    """
    Split text into overlapping chunks.

    Tries ``RecursiveCharacterTextSplitter`` first; falls back to a simple
    character-based split so we never require langchain to be installed just
    for the splitter (it is always installed when this module is used, but
    defensive coding is good).
    """
    try:
        from langchain.text_splitter import RecursiveCharacterTextSplitter  # type: ignore
        splitter = RecursiveCharacterTextSplitter(
            chunk_size=chunk_size, chunk_overlap=overlap
        )
        return splitter.split_text(text)
    except ImportError:
        pass

    # Simple fixed-size split
    chunks: List[str] = []
    start = 0
    while start < len(text):
        end = min(start + chunk_size, len(text))
        chunks.append(text[start:end])
        start += chunk_size - overlap
    return chunks or [text]


# ---------------------------------------------------------------------------
# Target class
# ---------------------------------------------------------------------------

# Keys to try when invoking the chain (in order of preference)
_INVOKE_KEY_PRIORITY = (
    "input", "question", "query", "human_input", "user_input", "message", "text"
)


class LangChainTarget(BaseTarget):
    """
    Vektor target adapter for LangChain Runnables and Chains.

    Parameters
    ----------
    chain:
        Any LangChain ``Runnable`` or ``Chain`` that supports ``.invoke()``.
    input_key:
        The key used in the invoke dict for the user prompt.  When ``None``
        (default), the key is auto-detected: ``chain.input_keys[0]`` for
        legacy chains, ``"input"`` for LCEL.
    name:
        Display name used in Vektor reports (default: ``"langchain"``).
    """

    def __init__(
        self,
        chain: Any,
        input_key: Optional[str] = None,
        name: str = "langchain",
    ):
        super().__init__(name=name)
        self.chain = chain
        self._input_key: Optional[str] = input_key
        self._input_key_resolved: bool = input_key is not None
        self._vectorstore: Optional[Any] = _find_vectorstore(chain)
        self._doc_context: List[str] = []

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _resolve_input_key(self) -> str:
        """Detect the primary invoke input key from the chain's metadata."""
        # Legacy chains expose .input_keys
        if hasattr(self.chain, "input_keys") and self.chain.input_keys:
            return self.chain.input_keys[0]
        return "input"  # LCEL default

    def _build_prompt(self, prompt: str) -> str:
        """Prepend accumulated document context when in context-injection mode."""
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
        """Invoke the chain and return the response as a plain string."""
        if not self._input_key_resolved:
            self._input_key = self._resolve_input_key()
            self._input_key_resolved = True

        # Context-injection enrichment
        effective = (
            self._build_prompt(prompt)
            if use_documents and self._doc_context
            else prompt
        )

        # Primary invocation attempt
        try:
            result = self.chain.invoke({self._input_key: effective})
            self.request_count += 1
            return _extract_response(result)
        except Exception as primary_err:
            pass

        # Try alternative input keys before giving up
        for alt_key in _INVOKE_KEY_PRIORITY:
            if alt_key == self._input_key:
                continue
            try:
                result = self.chain.invoke({alt_key: effective})
                self._input_key = alt_key  # persist successful key
                self.request_count += 1
                return _extract_response(result)
            except Exception:
                continue

        return f"[LangChainTarget: all invoke keys failed — {primary_err}]"

    def estimate_cost(self, prompt: str, response: Optional[str] = None) -> float:
        # LangChain tracks costs via callbacks; we return 0 here and
        # let the caller's callback manager accumulate the real cost.
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
        Add a document to the chain's knowledge base.

        **Vectorstore mode**: splits the document into chunks and calls
        ``vectorstore.add_documents()``, making chunks immediately retrievable.

        **Context-injection mode**: reads the full text and appends it to
        ``_doc_context``.  Every subsequent ``query()`` call prepends this
        text as a context block (works for non-RAG and non-retriever chains).
        """
        filename = os.path.basename(file_path)
        text = _read_file_text(file_path)

        if self._vectorstore is not None:
            try:
                try:
                    from langchain_core.documents import Document  # type: ignore
                except ImportError:
                    from langchain.docstore.document import Document  # type: ignore

                chunks = _split_text(text)
                docs = [
                    Document(
                        page_content=chunk,
                        metadata={"source": filename, "chunk_index": i},
                    )
                    for i, chunk in enumerate(chunks)
                ]
                self._vectorstore.add_documents(docs)
                self.uploaded_documents[filename] = (
                    f"[Vectorstore: {len(docs)} chunk(s) from {filename}]"
                )
                return filename
            except Exception as e:
                # Fall through to context-injection if vectorstore add fails
                pass

        # Context-injection fallback
        self._doc_context.append(f"[Document: {filename}]\n{text}")
        self.uploaded_documents[filename] = (
            f"[Context injection: {len(text)} chars from {filename}]"
        )
        return filename

    def clear_documents(self) -> None:
        """
        Clear document context.

        Note: chunks already written to a vectorstore cannot be removed without
        rebuilding the index.  Only the context-injection buffer is cleared.
        """
        self._doc_context.clear()
        self.uploaded_documents.clear()

    def clear_conversation(self) -> None:
        self.conversation_history.clear()
