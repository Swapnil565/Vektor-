"""
LangGraph Agent Target Adapter
================================
Wraps a compiled LangGraph graph so Vektor can scan it like any other target.

Usage::

    from langgraph.graph import StateGraph
    from vektor.targets.agents import LangGraphTarget
    import vektor

    graph = build_my_graph().compile()
    target = LangGraphTarget(graph)
    results = vektor.scan(target)

The adapter converts Vektor prompts into LangGraph message dicts and extracts
the last AI message from the returned state.  If LangGraph is not installed
the class can still be imported; an ImportError is raised only at runtime when
``query()`` is first called.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from vektor.targets.base import BaseTarget


class LangGraphTarget(BaseTarget):
    """
    Vektor target adapter for LangGraph compiled graphs.

    Parameters
    ----------
    graph:
        A ``CompiledGraph`` produced by ``StateGraph.compile()``.
    config:
        Optional LangGraph run config dict forwarded to ``graph.invoke()``.
    name:
        Display name used in Vektor reports (default: "langgraph").
    """

    def __init__(self, graph: Any, config: Optional[Dict] = None, name: str = "langgraph"):
        super().__init__(name=name)
        self.graph = graph
        self._run_config: Dict = config or {}

    # ------------------------------------------------------------------
    # BaseTarget implementation
    # ------------------------------------------------------------------

    def query(self, prompt: str, **kwargs) -> str:
        """Send *prompt* to the graph and return the last AI message."""
        try:
            from langchain_core.messages import HumanMessage  # type: ignore
        except ImportError:
            raise ImportError(
                "langchain-core is required for LangGraphTarget. "
                "Install with: pip install langchain-core langgraph"
            )

        messages_input = {"messages": [HumanMessage(content=prompt)]}
        result = self.graph.invoke(messages_input, config=self._run_config or None)

        # result is typically {"messages": [...]} for MessagesState graphs
        if isinstance(result, dict) and "messages" in result:
            messages = result["messages"]
            if messages:
                last = messages[-1]
                return last.content if hasattr(last, "content") else str(last)
        if isinstance(result, str):
            return result
        return str(result)

    def estimate_cost(self, prompt: str, max_tokens: int = 512) -> float:
        # LangGraph agents may call many LLMs internally; cost is tracked
        # per-run by LangSmith or the underlying model clients -- we return 0
        # here and rely on the model-level cost tracking if available.
        return 0.0

    def get_refusal_patterns(self) -> List[str]:
        return [
            "i cannot", "i can't", "i'm unable", "i am unable",
            "i won't", "i will not", "as an ai", "i must decline",
            "that's not something i can", "i'm not able",
        ]

    # ------------------------------------------------------------------
    # Agent interface extensions
    # ------------------------------------------------------------------

    def supports_tools(self) -> bool:
        return True

    def list_tools(self) -> List[str]:
        """Return tool names if the graph exposes them via a `.tools` attribute."""
        if hasattr(self.graph, "tools"):
            tools = self.graph.tools
            if isinstance(tools, (list, tuple)):
                return [getattr(t, "name", str(t)) for t in tools]
        return []

    def supports_memory(self) -> bool:
        """True when the graph uses LangGraph checkpointing (persistent memory)."""
        return hasattr(self.graph, "checkpointer") and self.graph.checkpointer is not None

    def get_memory(self) -> List[Dict]:
        """Return checkpoint state as a list of memory entries (best-effort)."""
        if not self.supports_memory():
            return []
        try:
            # LangGraph checkpointers expose state via get_tuple / list
            checkpointer = self.graph.checkpointer
            if hasattr(checkpointer, "list"):
                return [dict(entry) for entry in checkpointer.list(config={})]
        except Exception:
            pass
        return []

    def clear_conversation(self) -> None:
        """Reset conversation state (no-op; LangGraph state lives in the run config)."""
        pass
