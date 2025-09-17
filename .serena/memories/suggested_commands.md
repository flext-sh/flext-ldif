# FLEXT-LDIF Suggested Commands

## Essential Development Commands

### Setup & Installation

```bash
# Complete project setup
make setup                    # Full development environment setup
poetry install                # Install dependencies
poetry install --with dev,test,docs  # Install all development dependencies
```

### Quality Gates (MANDATORY)

```bash
# Complete validation pipeline
make validate                 # Run all quality gates (lint + type + security + test)
make check                    # Quick validation (lint + type)

# Individual quality gates
make lint                     # Ruff linting (ZERO tolerance)
make type-check               # MyPy strict type checking
make security                 # Security scans (bandit + pip-audit)
make test                     # Run tests with 90% coverage requirement
```

### Testing Commands

```bash
# Run specific test categories
make test-unit               # Unit tests only
make test-integration        # Integration tests only
make test-e2e                # End-to-end tests
make test-ldif               # LDIF-specific tests
make test-parser             # Parser tests

# Development testing
pytest --lf                  # Run last failed tests
pytest -v                    # Verbose output
pytest --cov=src/flext_ldif --cov-report=html  # Coverage report

# Single test execution
pytest tests/unit/test_specific.py::TestClass::test_method -v
```

### LDIF Operations

```bash
# LDIF foundation testing
make ldif-parse              # Test LDIF parsing functionality
make ldif-validate           # Test LDIF validation functionality
make ldif-operations         # Run all LDIF validations

# CLI testing
poetry run flext-ldif --help
PYTHONPATH=src poetry run python -c "from flext_ldif.cli import FlextLdifCli; cli = FlextLdifCli(); print('CLI ready')"
```

### Build & Distribution

```bash
make build                   # Build package
make build-clean             # Clean and build
poetry build                 # Build with Poetry
```

### Development Tools

```bash
make shell                   # Open Python shell
make pre-commit              # Run pre-commit hooks
make fix                     # Auto-fix issues
make format                  # Format code
```

### Maintenance

```bash
make clean                   # Clean build artifacts
make clean-all               # Deep clean including venv
make reset                   # Reset project
make diagnose                # Project diagnostics
make doctor                  # Health check
```

### Dependencies

```bash
make deps-update             # Update dependencies
make deps-show               # Show dependency tree
make deps-audit              # Audit dependencies
```

### Documentation

```bash
make docs                    # Build documentation
make docs-serve              # Serve documentation
```

## System Commands (Linux)

```bash
# File operations
ls -la                       # List files with details
find . -name "*.py"          # Find Python files
grep -r "pattern" src/       # Search in source code
cd /path/to/project          # Change directory

# Git operations
git status                   # Check git status
git add .                    # Stage all changes
git commit -m "message"      # Commit changes
git push                     # Push to remote

# Process management
ps aux | grep python         # Find Python processes
kill -9 PID                  # Kill process by PID
```

## Environment Variables

```bash
# Python path for development
export PYTHONPATH=src

# Poetry configuration
export POETRY_VENV_IN_PROJECT=true
export POETRY_NO_INTERACTION=1
```

## Shortcuts

```bash
# Make shortcuts
make t                       # test
make l                       # lint
make f                       # format
make tc                      # type-check
make c                       # clean
make i                       # install
make v                       # validate
```
