"""
Target factory for creating provider adapters.

Supports multiple providers with a clean interface:
- OpenAI (GPT models)
- Mock (demo mode, no API calls)
- Future: Anthropic (Claude), Ollama (local models)
"""

from llmguard.targets.base import BaseTarget
from llmguard.targets.openai import OpenAITarget
from llmguard.targets.mock import MockTarget


def create_target(provider: str, **config) -> BaseTarget:
    """
    Factory function to create target adapters.

    Args:
        provider: Provider name ("openai" | "mock" | "anthropic" | "ollama")
        **config: Provider-specific configuration

    Returns:
        Configured BaseTarget instance

    Examples:
        # BYOK mode with OpenAI
        target = create_target("openai", api_key="sk-...", model="gpt-4")

        # Demo mode (no API key)
        target = create_target("mock", dataset="demo_results")

        # Future: Anthropic Claude (v0.2)
        target = create_target("anthropic", api_key="sk-ant-...", model="claude-3")

    Raises:
        ValueError: If provider is unknown
    """
    providers = {
        "openai": OpenAITarget,
        "mock": MockTarget,
        # Future providers (v0.2+):
        # "anthropic": AnthropicTarget,
        # "ollama": OllamaTarget,
    }

    if provider not in providers:
        available = ", ".join(providers.keys())
        raise ValueError(
            f"Unknown provider: {provider}. "
            f"Available: {available}"
        )

    return providers[provider](**config)
