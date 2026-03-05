"""
CrewAI Agent Target Adapter
=============================
Wraps a CrewAI ``Crew`` so Vektor can scan it like any other target.

Usage::

    from crewai import Crew, Agent, Task
    from vektor.targets.agents import CrewAITarget
    import vektor

    crew = Crew(agents=[...], tasks=[...])
    target = CrewAITarget(crew)
    results = vektor.scan(target)

The adapter calls ``crew.kickoff(inputs={"prompt": <prompt>})`` and converts
the result to a string.  Task definitions in the crew should reference the
``{prompt}`` variable so the attack payloads are propagated correctly.

If CrewAI is not installed the class can still be imported; an ImportError is
raised only at runtime when ``query()`` is first called.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from vektor.targets.base import BaseTarget


class CrewAITarget(BaseTarget):
    """
    Vektor target adapter for CrewAI Crew objects.

    Parameters
    ----------
    crew:
        A configured ``crewai.Crew`` instance.
    input_key:
        The key in the ``inputs`` dict that carries the attack prompt
        (default: "prompt").  Change this to match your crew's task templates.
    name:
        Display name used in Vektor reports (default: "crewai").
    """

    def __init__(self, crew: Any, input_key: str = "prompt", name: str = "crewai"):
        super().__init__(name=name)
        self.crew = crew
        self.input_key = input_key

    # ------------------------------------------------------------------
    # BaseTarget implementation
    # ------------------------------------------------------------------

    def query(self, prompt: str, **kwargs) -> str:
        """Kick off the crew with *prompt* and return the final output."""
        try:
            import crewai  # noqa: F401  -- verify installation
        except ImportError:
            raise ImportError(
                "crewai is required for CrewAITarget. "
                "Install with: pip install crewai"
            )

        result = self.crew.kickoff(inputs={self.input_key: prompt})
        if hasattr(result, "raw"):        # CrewOutput object
            return str(result.raw)
        if hasattr(result, "__str__"):
            return str(result)
        return repr(result)

    def estimate_cost(self, prompt: str, max_tokens: int = 512) -> float:
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
        """Return names of all tools registered across the crew's agents."""
        names: List[str] = []
        agents = getattr(self.crew, "agents", [])
        for agent in agents:
            for tool in getattr(agent, "tools", []):
                tool_name = getattr(tool, "name", None) or getattr(tool, "__name__", str(tool))
                if tool_name and tool_name not in names:
                    names.append(tool_name)
        return names

    def supports_memory(self) -> bool:
        return bool(getattr(self.crew, "memory", False))

    def get_memory(self) -> List[Dict]:
        return []

    def clear_conversation(self) -> None:
        pass
