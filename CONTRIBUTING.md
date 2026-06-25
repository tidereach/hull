# Contributing to Spektralia

## Setup

Install the project in editable mode with dev dependencies:

```bash
pip install -e ".[dev]"
```

## Pre-commit Hooks

To catch issues before pushing, install pre-commit hooks:

```bash
pip install pre-commit
pre-commit install
```

Run hooks on all files:

```bash
pre-commit run --all-files
```

See `README.md` Quick start -> Pre-commit hooks for the `python -m pre_commit` fallback and `--no-verify` guidance.

Hooks include:
- **Ruff**: Fast Python linting (E, W, F, I, B, C4, UP rules)
- **Black**: Code formatting
- **MyPy**: Type checking
- **Trailing whitespace & EOF fixers**

## Local Development

### Code Quality Checks

```bash
# Format code with Black
black src/ tests/

# Lint with Ruff (auto-fixes what it can)
ruff check src/ tests/ --fix

# Type checking with MyPy
mypy src/

# All checks together
make lint  # if added to Makefile
```

### Testing

```bash
# Run tests
pytest -q

# Run tests with coverage report
pytest --cov=src/spektralia --cov-report=term-missing -v

# Run specific test file
pytest tests/test_gate.py -v
```

### Supply Chain

```bash
# Check for vulnerable dependencies
pip-audit

# Verify SBOM and installed package hashes
spektralia verify-installed
```

### Makefile Targets

```bash
make test       # Run pytest (quiet mode)
make verify     # Run integrity + installed checks
make sbom       # Regenerate reproducible SBOM
make lock       # Update requirements.lock with hashes
```

## Continuous Integration

GitHub CI runs automatically on push and pull request:

1. **Lint job** (3.14): Ruff, Black, MyPy checks
2. **Security job** (3.14): pip-audit + supply chain verification
3. **Test job** (Python 3.11–3.14): Tests with coverage reporting
4. **SBOM verification** (3.14): Ensures SBOM is up-to-date

All jobs must pass before merge.

## Coverage Requirements

- **Minimum threshold**: 78%
- **Current coverage**: ~79%
- Higher-coverage areas: `__init__.py` (100%), `cache.py` (94.7%), `canary.py` (94.7%)
- Lower-coverage areas: `ollama_trust.py` (48%), `heartbeat.py` (56%), `memory_safety.py` (58%)

Consider adding tests for core functionality in lower-coverage modules, especially around:
- Ollama connection establishment and error handling
- Audit heartbeat/emission logic
- Memory safety initialization and PR_SET_DUMPABLE enforcement

## Type Annotations

MyPy is configured in non-strict mode (advisory). Current state: 8 type errors across 4 files.

To improve type coverage:
1. Add return type annotations to functions
2. Add parameter type hints
3. Fix `Any` returns in config, audit, classifier, and integrity modules

## Known Issues

- **Ruff**: Ignores `RUF001`/`RUF003` (ambiguous Unicode) — intentional for homoglyph testing in `normalize.py`
- **MyPy**: 8 errors in config, audit, classifier, integrity (non-blocking)
- **Coverage**: Phase 4 carry-overs (NFKC offset, corpus population, etc.) are tracked separately

## Questions?

See [SPEC.md](SPEC.md) for gate architecture, [PLAN.md](PLAN.md) for development timeline, and [COMPLIANCE.md](docs/COMPLIANCE.md) for security/privacy compliance.
