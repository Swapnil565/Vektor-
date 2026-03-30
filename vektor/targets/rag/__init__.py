"""
vektor.targets.rag
==================
RAG framework target adapters for Phase 5.

Supported frameworks
--------------------
* **LangChain**   -- :class:`LangChainTarget` wraps any ``Runnable`` / ``Chain``
* **LlamaIndex**  -- :class:`LlamaIndexTarget` wraps any ``QueryEngine``

Auto-wrap
---------
:func:`auto_wrap` detects the framework automatically::

    from vektor.targets.rag import auto_wrap

    target = auto_wrap(my_langchain_chain)   # → LangChainTarget
    target = auto_wrap(my_llamaindex_engine) # → LlamaIndexTarget

This is also called by the top-level ``vektor.scan(app=...)`` API.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .langchain_target import LangChainTarget
from .llamaindex_target import LlamaIndexTarget

if TYPE_CHECKING:
    from vektor.targets.base import BaseTarget


def auto_wrap(app: object) -> "BaseTarget":
    """
    Detect the framework of *app* and return the appropriate Vektor adapter.

    Detection strategy (first match wins)
    --------------------------------------
    1. Already a ``BaseTarget`` — returned as-is (no wrapping).
    2. Module name starts with ``"langchain"`` — ``LangChainTarget``.
    3. Module name contains ``"llama_index"`` — ``LlamaIndexTarget``.
    4. Has ``.invoke()`` callable but no framework hint — ``LangChainTarget``
       (covers any custom LCEL-compatible Runnable).
    5. Has ``.query()`` callable but no framework hint — ``LlamaIndexTarget``
       (covers any QueryEngine-like object).
    6. Raises ``ValueError`` if the framework cannot be determined.

    Parameters
    ----------
    app:
        A framework object (LangChain chain, LlamaIndex QueryEngine, or an
        existing ``BaseTarget``).

    Returns
    -------
    BaseTarget
        A Vektor ``BaseTarget`` wrapping *app*.

    Raises
    ------
    ValueError
        If *app* does not match any known framework pattern.
    """
    from vektor.targets.base import BaseTarget as _BaseTarget

    if isinstance(app, _BaseTarget):
        return app

    mod = type(app).__module__

    if mod.startswith("langchain"):
        return LangChainTarget(app)

    if "llama_index" in mod or mod.startswith("llama_index"):
        return LlamaIndexTarget(app)

    # Structural duck-type detection (covers third-party LCEL-compatible libs)
    if callable(getattr(app, "invoke", None)):
        return LangChainTarget(app)

    if callable(getattr(app, "query", None)):
        return LlamaIndexTarget(app)

    raise ValueError(
        f"Cannot auto-detect the LLM framework for {type(app).__qualname__!r}.\n"
        "Wrap it explicitly:\n"
        "  from vektor.targets.rag import LangChainTarget, LlamaIndexTarget\n"
        "  target = LangChainTarget(app)   # or LlamaIndexTarget(app)"
    )


__all__ = ["LangChainTarget", "LlamaIndexTarget", "auto_wrap"]
