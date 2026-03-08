# Vektor: AI Security Testing Framework
__version__ = "0.2.0"

from vektor.core.engine import VektorScanner
from vektor.targets import BaseTarget, create_target
from vektor.config import Config
from vektor.attacks import BaseAttack, Vulnerability
from typing import Optional, List, Dict, Any


def scan(
    app: Any = None,
    target: Optional[BaseTarget] = None,
    provider: Optional[str] = None,
    attacks: Optional[List[str]] = None,
    quick: bool = False,
    budget: float = 1.0,
    **kwargs,
) -> Dict:
    """Top-level scan function — the simplest way to use Vektor.

    Usage examples::

        # Auto-wrap a LangChain chain or LlamaIndex query engine
        results = vektor.scan(app=my_chain)
        results = vektor.scan(app=my_query_engine)

        # Use a pre-built BaseTarget
        results = vektor.scan(target=my_target)

        # Create a cloud-provider target on-the-fly
        results = vektor.scan(provider="groq", api_key="gsk_...", model="llama-3.1-8b-instant")

    Args:
        app:      A LangChain Runnable/Chain or LlamaIndex QueryEngine (auto-wrapped).
        target:   A pre-built :class:`BaseTarget` instance.
        provider: Provider string passed to :func:`create_target` (e.g. ``"openai"``).
        attacks:  Optional list of attack names to run (defaults to all registered).
        quick:    If ``True``, run only the first variant of each attack.
        budget:   Maximum USD to spend (default 1.0).
        **kwargs: Extra kwargs forwarded to :func:`create_target` when *provider* is used.

    Returns:
        Scan result dict as returned by :meth:`VektorScanner.scan`.

    Raises:
        ValueError: If none of *app*, *target*, or *provider* is provided, or if
                    *app* cannot be auto-wrapped.
    """
    if app is not None:
        if isinstance(app, BaseTarget):
            resolved = app
        else:
            from vektor.targets.rag import auto_wrap
            resolved = auto_wrap(app)
    elif target is not None:
        resolved = target
    elif provider is not None:
        resolved = create_target(provider, **kwargs)
    else:
        raise ValueError(
            "Provide at least one of: app=<framework object>, "
            "target=<BaseTarget>, or provider=<str>"
        )

    scanner = VektorScanner(resolved, budget_limit=budget)
    return scanner.scan(attacks=attacks, quick_mode=quick)


__all__ = [
    '__version__',
    'VektorScanner',
    'BaseTarget',
    'create_target',
    'Config',
    'BaseAttack',
    'Vulnerability',
    'scan',
]
