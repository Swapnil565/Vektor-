"""
Target factory for creating provider adapters.

Supports multiple providers with a clean BYOK (Bring Your Own Key) interface:
  - openai      — OpenAI GPT models (OPENAI_API_KEY)
  - groq        — Groq (free tier, GROQ_API_KEY)
  - openrouter  — OpenRouter free models (OPENROUTER_API_KEY)
  - together    — Together AI (TOGETHER_API_KEY)
  - ollama      — Local Ollama (no key needed)
  - gemini      — Google Gemini (free tier, GEMINI_API_KEY)
  - mock        — Demo mode (no API key, pre-recorded results)
"""
from vektor.targets.base import BaseTarget


_OPENAI_COMPATIBLE = {
    "openai", "groq", "openrouter", "together", "ollama",
    # Open-source local LLM apps (all speak OpenAI Chat API)
    "lmstudio", "localai", "openwebui", "anythingllm", "jan",
}


def create_target(provider: str, **config) -> BaseTarget:
    """
    Factory function to create target adapters.

    Args:
        provider: Provider name (see module docstring)
        **config: Provider-specific configuration

    Returns:
        Configured BaseTarget instance

    Examples:
        create_target("openai", api_key="sk-...", model="gpt-4o-mini")
        create_target("groq", api_key="gsk_...", model="llama-3.1-8b-instant")
        create_target("openrouter", api_key="sk-or-...")
        create_target("gemini", api_key="AIza...", model="gemini-1.5-flash")
        create_target("ollama", model="llama3")
        create_target("mock")
        create_target("vulnerable")  # scanner validation — no API key needed

    Raises:
        ValueError: If provider is unknown
    """
    if provider in _OPENAI_COMPATIBLE:
        from vektor.targets.openai_compatible import OpenAICompatibleTarget
        return OpenAICompatibleTarget(provider=provider, **config)

    if provider == "gemini":
        from vektor.targets.gemini import GeminiTarget
        return GeminiTarget(**config)

    if provider == "mock":
        from vektor.targets.mock import MockTarget
        return MockTarget(**config)

    if provider == "vulnerable":
        from vektor.targets.vulnerable import VulnerableTarget
        return VulnerableTarget()

    if provider == "multi-agent":
        from vektor.targets.multi_agent import MultiAgentTarget
        return MultiAgentTarget(**config)

    available = sorted(_OPENAI_COMPATIBLE | {"gemini", "mock", "multi-agent", "vulnerable"})
    raise ValueError(
        f"Unknown provider: '{provider}'. "
        f"Available: {', '.join(available)}"
    )
