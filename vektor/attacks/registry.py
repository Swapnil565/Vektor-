"""
Attack registry — auto-populated by @attack decorators when attack modules are imported.

Importing this module triggers registration of all built-in attacks.
Adding a new attack requires ZERO changes here — just decorate your class with @attack.
"""

# Re-export canonical registry and helpers from the plugin system.
from vektor.core.plugin import ATTACK_REGISTRY, attack, load_plugin_file, discover_entry_points  # noqa: F401

# ── Trigger registration of all built-in attacks ──────────────────────────────
# Importing these modules causes their @attack decorators to fire, which
# populates ATTACK_REGISTRY automatically with no manual dict edits needed.
import vektor.attacks.prompt_injection            # noqa: F401
import vektor.attacks.data_extraction             # noqa: F401
import vektor.attacks.instruction_hijacking       # noqa: F401
import vektor.attacks.structured_output_injection  # noqa: F401

# Discover any installed plugin packages that export vektor.attacks entry points.
discover_entry_points()


# ── Helper functions (backward-compatible public API) ─────────────────────────

def get_attack_count() -> int:
    return len(ATTACK_REGISTRY)


def get_test_case_count() -> int:
    return sum(a["test_cases"] for a in ATTACK_REGISTRY.values())


def get_attacks_by_category(category: str) -> dict:
    return {k: v for k, v in ATTACK_REGISTRY.items() if v["category"] == category}


def get_categories() -> list:
    return sorted({a["category"] for a in ATTACK_REGISTRY.values()})
