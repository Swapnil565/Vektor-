"""
AutoGen Agent Target Adapter
==============================
Wraps an AutoGen ``ConversableAgent`` (or ``AssistantAgent``) so Vektor can
scan it like any other target.

Usage::

    from autogen import AssistantAgent, UserProxyAgent
    from vektor.targets.agents import AutoGenTarget
    import vektor

    assistant = AssistantAgent("assistant", llm_config={...})
    target = AutoGenTarget(assistant)
    results = vektor.scan(target)

For each scan prompt the adapter creates a short-lived ``UserProxyAgent``
(unless you supply ``human_proxy``) and calls ``initiate_chat`` with
``max_turns=1`` so the conversation completes deterministically.

If AutoGen is not installed the class can still be imported; an ImportError is
raised only at runtime when ``query()`` is first called.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from vektor.targets.base import BaseTarget


class AutoGenTarget(BaseTarget):
    """
    Vektor target adapter for AutoGen ConversableAgent / AssistantAgent.

    Parameters
    ----------
    agent:
        The AutoGen agent under test.
    human_proxy:
        Optional pre-configured ``UserProxyAgent`` used to drive the
        conversation.  When *None* a minimal proxy is created automatically.
    max_turns:
        Maximum conversation turns per query (default: 1).
    name:
        Display name used in Vektor reports (default: "autogen").
    """

    def __init__(
        self,
        agent: Any,
        human_proxy: Optional[Any] = None,
        max_turns: int = 1,
        name: str = "autogen",
    ):
        super().__init__(name=name)
        self.agent = agent
        self.human_proxy = human_proxy
        self.max_turns = max_turns

    # ------------------------------------------------------------------
    # BaseTarget implementation
    # ------------------------------------------------------------------

    def query(self, prompt: str, **kwargs) -> str:
        """Send *prompt* to the agent and return the final response."""
        try:
            from autogen import UserProxyAgent  # type: ignore
        except ImportError:
            raise ImportError(
                "pyautogen is required for AutoGenTarget. "
                "Install with: pip install pyautogen"
            )

        # Create a silent proxy for each call to avoid state leakage
        proxy = self.human_proxy or UserProxyAgent(
            name=f"vektor_proxy_{uuid.uuid4().hex[:6]}",
            human_input_mode="NEVER",
            max_consecutive_auto_reply=0,
            code_execution_config=False,
        )

        chat_result = proxy.initiate_chat(
            self.agent,
            message=prompt,
            max_turns=self.max_turns,
            silent=True,
        )

        # Extract the last message from the agent
        if hasattr(chat_result, "chat_history") and chat_result.chat_history:
            for msg in reversed(chat_result.chat_history):
                if msg.get("role") == "assistant" or msg.get("name") == self.agent.name:
                    return str(msg.get("content", ""))
        if hasattr(chat_result, "summary") and chat_result.summary:
            return str(chat_result.summary)
        return ""

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
        """True when the agent has registered function tools."""
        tools = (
            getattr(self.agent, "function_map", None)
            or getattr(self.agent, "_tools", None)
        )
        return bool(tools)

    def list_tools(self) -> List[str]:
        tools = getattr(self.agent, "function_map", None)
        if tools and isinstance(tools, dict):
            return list(tools.keys())
        return []

    def supports_memory(self) -> bool:
        return False

    def get_memory(self) -> List[Dict]:
        return []

    def clear_conversation(self) -> None:
        """Reset the agent's internal chat history."""
        if hasattr(self.agent, "clear_history"):
            self.agent.clear_history()
        elif hasattr(self.agent, "_oai_messages"):
            self.agent._oai_messages.clear()
