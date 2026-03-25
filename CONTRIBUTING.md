# Contributing

## Development Setup

1. Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```
2. Install project dependencies:
```bash
pip install -e ".[all]"
```
3. Install pre-commit hooks:
```bash
pre-commit install
```

## Local Checks

Run these before opening a PR:
```bash
ruff check epss_framework/
ruff format --check epss_framework/
mypy epss_framework/ --ignore-missing-imports
pytest
```

## Commit & PR Guidelines

- Keep PRs scoped to one concern (feature/fix/refactor).
- Add or update tests for behavior changes.
- Update docs when CLI/config/contracts change.
- Use clear commit messages (`feat:`, `fix:`, `test:`, `docs:`).

## Testing Expectations

- Unit tests for core logic and parsing.
- Integration test for scan -> enrich -> score flow.
- Maintain project coverage target of at least 80%.
