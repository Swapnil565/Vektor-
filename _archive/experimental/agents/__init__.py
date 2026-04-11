"""
vektor.targets.agents
======================
Agent framework target adapters.  Import the appropriate adapter for your
framework and pass an initialized agent instance to run Vektor scans.

Supported frameworks
--------------------
* **LangGraph** -- :class:`LangGraphTarget` wraps a ``CompiledGraph``
* **CrewAI**    -- :class:`CrewAITarget` wraps a ``Crew``
* **AutoGen**   -- :class:`AutoGenTarget` wraps a ``ConversableAgent``

Example::

    from vektor.targets.agents import LangGraphTarget
    target = LangGraphTarget(my_compiled_graph)
"""
from .autogen_target import AutoGenTarget
from .crewai_target import CrewAITarget
from .langgraph_target import LangGraphTarget

__all__ = ["LangGraphTarget", "CrewAITarget", "AutoGenTarget"]
