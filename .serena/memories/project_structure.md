# FLEXT-LDIF Project Structure

## Directory Layout

```
/home/marlonsc/flext/flext-ldif/
├── src/flext_ldif/           # Source code (main package)
├── tests/                    # Test suite
├── examples/                 # Usage examples
├── docs/                     # Documentation
├── scripts/                  # Utility scripts
├── reports/                  # Coverage and analysis reports
├── dist/                     # Built packages
├── pyproject.toml            # Project configuration
├── Makefile                 # Build automation
├── README.md                # Project overview
├── CLAUDE.md                # Development standards
└── LICENSE                  # MIT license
```

## Source Code Structure (src/flext_ldif/)

```
src/flext_ldif/
├── __init__.py              # Package initialization and exports
├── api.py                   # Application layer - unified LDIF API
├── models.py                # Domain entities and value objects
├── services.py              # Infrastructure services
├── cli.py                   # Template Method Pattern CLI
├── exceptions.py            # Builder Pattern exception system
├── constants.py             # Unified constants
├── protocols.py             # Type protocols for dependency inversion
├── format_handlers.py       # LDIF format handling
├── format_validators.py     # LDIF validation logic
├── utilities.py             # Utility functions
├── config.py                # Configuration management
├── parser_service.py        # LDIF parsing service
├── validator_service.py     # LDIF validation service
├── writer_service.py        # LDIF writing service
├── transformer_service.py   # LDIF transformation service
├── repository_service.py    # LDIF repository service
├── analytics_service.py     # LDIF analytics service
├── orchestrator_service.py  # LDIF orchestration service
└── py.typed                 # Type checking marker
```

## Test Structure (tests/)

```
tests/
├── __init__.py              # Test package initialization
├── conftest.py              # Pytest configuration
├── unit/                    # Unit tests (57 files)
│   ├── test_api.py
│   ├── test_models.py
│   ├── test_services.py
│   ├── test_exceptions.py
│   └── ... (53 more unit tests)
├── integration/             # Integration tests (2 files)
│   ├── test_api.py
│   └── ...
├── e2e/                     # End-to-end tests (4 files)
│   ├── test_cli_consolidated.py
│   ├── test_enterprise.py
│   ├── test_suite.py
│   └── ...
├── fixtures/                # Test fixtures (2 files)
│   ├── docker_fixtures.py
│   └── ...
└── test_support/            # Test support utilities (5 files)
    ├── ldif_data.py
    ├── real_services.py
    ├── test_files.py
    ├── validators.py
    └── ...
```

## Examples Structure (examples/)

```
examples/
├── __init__.py              # Examples package
├── 01_basic_parsing.py      # Basic LDIF parsing example
├── 02_cli_integration.py    # CLI integration example
├── 03_error_handling.py     # Error handling patterns
├── 04_simple_docker_test.py # Docker integration test
├── 05_advanced_validation.py # Advanced validation
├── 06_complete_validation.py # Complete validation pipeline
├── 07_demo.py               # Comprehensive demo
├── 08_config_usage.py       # Configuration usage
├── sample_basic.ldif        # Basic LDIF sample data
├── sample_complex.ldif      # Complex LDIF sample data
├── sample_invalid.ldif      # Invalid LDIF for testing
├── output_basic.ldif        # Generated output
└── README.md                # Examples documentation
```

## Documentation Structure (docs/)

```
docs/
├── README.md                # Documentation overview
├── api/                     # API documentation
│   └── API.md
├── architecture/            # Architecture documentation
│   ├── ARCHITECTURE.md
│   └── ...
├── development/             # Development documentation
│   ├── AUDIT_REPORT.md
│   ├── DOCKER_INTEGRATION.md
│   ├── VALIDATION_REPORT.md
│   └── ...
├── examples/                # Examples documentation
│   └── EXAMPLES.md
└── standards/               # Coding standards
    └── python-module-organization.md
```

## Configuration Files

- **pyproject.toml**: Project configuration, dependencies, tool settings
- **Makefile**: Build automation and quality gates
- **poetry.lock**: Dependency lock file
- **requirements.txt**: Alternative dependency specification
- **meltano.yml**: Data pipeline configuration
- **.gitignore**: Git ignore patterns
- **LICENSE**: MIT license

## Key Files

- **src/flext_ldif/**init**.py**: Main package exports and CLI entry point
- **src/flext_ldif/api.py**: Unified LDIF processing API
- **src/flext_ldif/models.py**: Domain models and value objects
- **src/flext_ldif/cli.py**: CLI interface using flext-cli
- **tests/conftest.py**: Pytest configuration and fixtures
- **examples/01_basic_parsing.py**: Basic usage example
- **CLAUDE.md**: Development standards and patterns

## Build Artifacts

- **dist/**: Built packages (.whl, .tar.gz)
- **reports/**: Coverage reports, security scans
- \***\*pycache**/\*\*: Python bytecode cache
- **.coverage**: Coverage data
- **.mypy_cache/**: MyPy type checking cache
- **.ruff_cache/**: Ruff linting cache
- **.pytest_cache/**: Pytest cache

## Development Files

- **test_constants.py**: Test constants
- **test_direct_100_coverage.py**: Coverage testing
- **run_coverage_forcing.py**: Coverage enforcement
- **pytest_final_result.txt**: Test results
- **coverage.JSON**: Coverage data in JSON format
