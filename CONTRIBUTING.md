# Contributing to Vektor

## Adding a new attack

1. Create a class extending `BaseAttack` in `vektor/attacks/`
2. Decorate it with `@attack` — auto-registers, no manual dict edits needed
3. Add an import in `vektor/attacks/registry.py`
4. Write tests in `tests/unit/test_attacks.py`
5. Run `pytest tests/unit/ -v` — must be green before PR

## Running tests

```bash
pip install -e ".[dev]"
pytest tests/unit/ -v
```

## Code style

Match existing patterns. No new dependencies without discussion in an issue first.
