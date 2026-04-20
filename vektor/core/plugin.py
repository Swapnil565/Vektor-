"""
Vektor Plugin System
====================
@attack decorator  — self-registering attack classes.
Entry point discovery — installed packages via pyproject.toml.
File-based loading  — vektor scan --plugin ./my_attacks.py

Usage (writing a custom attack):
    from vektor.attacks.base import BaseAttack, Vulnerability
    from vektor.core.plugin import attack

    @attack(category="Custom", owasp="LLM01: Prompt Injection")
    class MyCompanyTest(BaseAttack):
        def execute(self, target):
            response = target.query("my adversarial prompt")
            ...
            return Vulnerability(...)

Then run:
    vektor scan --target groq --plugin ./my_attacks.py
"""
from __future__ import annotations

import re
import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Optional, Type, TYPE_CHECKING

if TYPE_CHECKING:
    from vektor.attacks.base import BaseAttack

# Central registry — populated by @attack decorator at import time.
# Shape: { attack_id: { "name", "category", "class", "module", ... } }
ATTACK_REGISTRY: dict = {}


def _class_to_id(cls_name: str) -> str:
    """CamelCase class name -> snake_case attack ID, stripping trailing 'Attack'."""
    name = cls_name[:-6] if cls_name.endswith("Attack") else cls_name
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def _class_to_name(cls_name: str) -> str:
    """CamelCase class name -> readable display name, stripping trailing 'Attack'."""
    name = cls_name[:-6] if cls_name.endswith("Attack") else cls_name
    return re.sub(r"([a-z])([A-Z])", r"\1 \2", name)


def attack(
    category: str,
    owasp: str,
    *,
    attack_id: Optional[str] = None,
    name: Optional[str] = None,
    test_cases: int = 0,
    expected_success_rate: float = 0.5,
    description: str = "",
):
    """
    Class decorator that self-registers an attack with Vektor.

    Args:
        category:              e.g. "Prompt Injection"
        owasp:                 e.g. "LLM01: Prompt Injection"
        attack_id:             Registry key (defaults to snake_case class name)
        name:                  Display name (defaults to prettified class name)
        test_cases:            Number of test cases (informational)
        expected_success_rate: 0.0-1.0 — used by quick-mode filter
        description:           One-line description in `vektor list`

    Example:
        @attack(category="Prompt Injection", owasp="LLM01: Prompt Injection",
                attack_id="my_test", test_cases=3, expected_success_rate=0.8,
                description="My custom injection test")
        class MyAttack(BaseAttack):
            def execute(self, target): ...
    """
    def decorator(cls: Type) -> Type:
        _id   = attack_id or _class_to_id(cls.__name__)
        _name = name      or _class_to_name(cls.__name__)

        cls._vektor_id                    = _id
        cls._vektor_name                  = _name
        cls._vektor_category              = category
        cls._vektor_owasp                 = owasp
        cls._vektor_test_cases            = test_cases
        cls._vektor_expected_success_rate = expected_success_rate
        cls._vektor_description           = description

        ATTACK_REGISTRY[_id] = {
            "name":                  _name,
            "category":              category,
            "owasp_category":        owasp,
            "test_cases":            test_cases,
            "expected_success_rate": expected_success_rate,
            "description":           description,
            "class":                 cls,           # direct reference — engine uses this
            "module":                cls.__module__.split(".")[-1],   # backward compat
            "class_name":            cls.__name__,
        }
        return cls

    return decorator


def load_plugin_file(path: str) -> int:
    """
    Load a Python file as a plugin; any @attack-decorated class is auto-registered.
    Returns the number of new attacks registered.

    Used by: vektor scan --plugin ./my_attacks.py

    WARNING: This executes arbitrary Python code from the given file with full
    process privileges. Only load plugin files you trust completely.
    """
    import sys as _sys
    p = Path(path).resolve()
    if not p.exists():
        raise FileNotFoundError(f"Plugin file not found: {p}")

    print(
        f"[vektor] WARNING: loading plugin '{p}' — this executes arbitrary Python code.",
        file=_sys.stderr,
    )

    before = set(ATTACK_REGISTRY.keys())

    module_name = f"vektor_plugin_{p.stem}"
    spec   = importlib.util.spec_from_file_location(module_name, p)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    return len(set(ATTACK_REGISTRY.keys()) - before)


def discover_entry_points() -> int:
    """
    Auto-discover installed Vektor attack plugins via entry points.

    Add to your plugin package's pyproject.toml:
        [project.entry-points."vektor.attacks"]
        my_attack = "my_package.attacks:MyAttack"

    Returns the number of new attacks registered.
    """
    try:
        from importlib.metadata import entry_points
    except ImportError:
        try:
            from importlib_metadata import entry_points
        except ImportError:
            return 0

    before = set(ATTACK_REGISTRY.keys())

    try:
        eps = entry_points(group="vektor.attacks")
    except TypeError:
        eps = entry_points().get("vektor.attacks", [])  # Python 3.8

    for ep in eps:
        try:
            ep.load()
        except Exception as e:
            print(f"[vektor] WARNING: failed to load entry point '{ep.name}': {e}", file=sys.stderr)

    return len(set(ATTACK_REGISTRY.keys()) - before)
