# Vektor: AI Security Testing Framework
__version__ = "0.2.3"

from vektor.core.engine import VektorScanner
from vektor.targets import BaseTarget, create_target
from vektor.config import Config
from vektor.attacks import BaseAttack, Vulnerability
from typing import Optional, List, Dict, Any


# ── Severity ordering for fail_on checks ─────────────────────────────────────
_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


class ScanFailed(Exception):
    """Raised by :func:`scan` when *fail_on* is set and a matching vulnerability
    is found.

    Attributes:
        results: The full scan result dict (same as the normal return value).
    """
    def __init__(self, message: str, results: Dict) -> None:
        super().__init__(message)
        self.results = results


def scan(
    app: Any = None,
    *,
    target: Optional[BaseTarget] = None,
    provider: Optional[str] = None,
    url: Optional[str] = None,
    model: Optional[str] = None,
    attacks: Optional[List[str]] = None,
    quick: bool = False,
    mode: str = "standard",
    budget: float = 1.0,
    fail_on: Optional[str] = None,
    **kwargs,
) -> Dict:
    """Top-level scan function — the simplest way to use Vektor.

    Target resolution order:

    1. *app* — a LangChain Runnable/Chain or LlamaIndex QueryEngine (auto-wrapped).
    2. *target* — a pre-built :class:`BaseTarget` instance.
    3. *provider* — provider string passed to :func:`create_target` (e.g. ``"groq"``).
    4. *url* — convenience shorthand; creates an :class:`HTTPEndpointTarget` automatically.

    Usage examples::

        # Scan an HTTP endpoint (no target setup needed)
        results = scan(url="http://localhost:8000/chat")

        # Auto-wrap a LangChain chain
        results = scan(app=my_chain)

        # Cloud provider with model + budget cap
        results = scan(
            provider="groq",
            model="llama-3.3-70b-versatile",
            api_key="gsk_...",
            attacks=["direct_injection", "system_prompt_reveal"],
            fail_on="HIGH",
            budget=0.50,
        )

    Args:
        app:      Framework object (LangChain/LlamaIndex) — auto-wrapped.
        target:   A pre-built :class:`BaseTarget` instance.
        provider: Provider name for :func:`create_target`.
        url:      HTTP endpoint URL. Shorthand for ``provider="http", url=...``.
        model:    Model name forwarded to :func:`create_target` (keyword-only).
        attacks:  Attack names to run (all registered attacks if omitted).
        quick:    Run only high-success-rate attacks (same as CLI ``--quick``).
        mode:     Scan mode: ``"standard"`` or ``"analysis"``.
        budget:   Maximum USD to spend across the scan (default 1.0).
        fail_on:  Severity threshold — raise :exc:`ScanFailed` if any vulnerability
                  meets or exceeds this level.  Accepted values: ``"CRITICAL"``,
                  ``"HIGH"``, ``"MEDIUM"``, ``"LOW"``.
        **kwargs: Extra keyword arguments forwarded to :func:`create_target`.

    Returns:
        Scan result dict as returned by :meth:`VektorScanner.scan`.

    Raises:
        ScanFailed: When *fail_on* is set and at least one vulnerability matches.
        ValueError:  When no target source is provided or auto-wrap fails.
    """
    if model is not None:
        kwargs.setdefault("model", model)

    # ── Resolve target ────────────────────────────────────────────────────────
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
    elif url is not None:
        resolved = create_target("http", url=url, **kwargs)
    else:
        raise ValueError(
            "Provide at least one of: app=, target=, provider=, or url=."
        )

    # ── Run scan ──────────────────────────────────────────────────────────────
    scanner = VektorScanner(resolved, budget_limit=budget)
    results = scanner.scan(attacks=attacks, quick_mode=quick, mode=mode)

    # ── fail_on check ─────────────────────────────────────────────────────────
    if fail_on is not None:
        threshold = _SEV_RANK.get(fail_on.upper(), 0)
        failing = [
            v for v in results.get("vulnerabilities", [])
            if _SEV_RANK.get(v.get("severity", "INFO"), 0) >= threshold
        ]
        if failing:
            worst = max(failing, key=lambda v: _SEV_RANK.get(v["severity"], 0))
            raise ScanFailed(
                f"Scan failed: {len(failing)} vulnerability/ies at {fail_on} or above "
                f"(worst: {worst['attack_name']} — {worst['severity']})",
                results=results,
            )

    return results


def quick_scan(
    app: Any = None,
    *,
    target: Optional[BaseTarget] = None,
    provider: Optional[str] = None,
    url: Optional[str] = None,
    model: Optional[str] = None,
    mode: str = "standard",
    budget: float = 0.25,
    fail_on: Optional[str] = None,
    **kwargs,
) -> Dict:
    """Run only the highest-impact attacks (quick mode).

    This is a convenience wrapper around :func:`scan` with ``quick=True``.
    The engine selects attacks whose expected success rate is above 50 %,
    typically 5-8 attacks.

    Budget defaults to $0.25 (vs $1.00 for a full scan).

    Usage examples::

        results = quick_scan(url="http://localhost:8000/chat")
        results = quick_scan(app=my_chain, fail_on="HIGH")
        results = quick_scan(provider="groq", api_key="gsk_...")
    """
    return scan(
        app,
        target=target,
        provider=provider,
        url=url,
        model=model,
        mode=mode,
        quick=True,
        budget=budget,
        fail_on=fail_on,
        **kwargs,
    )


__all__ = [
    '__version__',
    'VektorScanner',
    'BaseTarget',
    'create_target',
    'Config',
    'BaseAttack',
    'Vulnerability',
    'ScanFailed',
    'scan',
    'quick_scan',
]
