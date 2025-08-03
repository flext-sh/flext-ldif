# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**flext-ldif** is an enterprise-grade LDIF (LDAP Data Interchange Format) processing library built with **Clean Architecture** and **Domain-Driven Design** principles using the **flext-core** foundation. It provides comprehensive LDIF parsing, generation, validation, and transformation capabilities for Python 3.13+ applications.

## Key Architecture Patterns

### Clean Architecture Structure

```
src/flext_ldif/
├── api.py                     # Application layer - unified LDIF API
├── models.py                  # Domain entities and value objects
├── services.py                # Infrastructure services (parser, validator, writer)
├── core.py                    # Core LDIF processing functionality
├── config.py                  # Configuration management
├── exceptions.py              # Domain exceptions
├── cli.py                     # Command-line interface
├── modernized_ldif.py         # Modern LDIF handling utilities
└── utils/                     # Utility modules
    ├── cli_utils.py           # CLI helper functions
    ├── error_handling.py      # Error handling utilities
    ├── logging.py             # Logging configuration
    └── validation.py          # Validation utilities
```

### Core Domain Objects

- **FlextLdifEntry**: Main domain entity representing LDIF entries
- **FlextLdifDistinguishedName**: Value object for DN handling
- **FlextLdifAttributes**: Value object for attribute collections
- **FlextLdifAPI**: Application service orchestrating operations

### Design Patterns Used

- **Clean Architecture**: Clear separation of concerns with dependency inversion
- **Domain-Driven Design**: Rich domain model with business logic
- **Value Object Pattern**: Immutable domain values (DN, Attributes)
- **Specification Pattern**: Business rules encapsulation
- **Factory Pattern**: Object creation through model_validate()
- **Result Pattern**: FlextResult for error handling (from flext-core)

## Development Commands

### Essential Development Workflow

```bash
# Complete setup and validation
make setup                    # Full development environment setup
make validate                 # Complete validation (lint + type + security + test)
make check                    # Essential checks (lint + type + test)

# Individual quality gates
make lint                     # Ruff linting (ALL rules enabled)
make type-check               # MyPy strict type checking
make security                 # Security scans (bandit + pip-audit)
make test                     # Run tests with 90% coverage requirement

# Fast testing without full coverage
make test-fast               # Run tests without coverage analysis
```

### Testing Commands

```bash
# Run specific test categories (defined in conftest.py)
pytest -m unit               # Unit tests only
pytest -m integration        # Integration tests only
pytest -m e2e                # End-to-end tests
pytest -m ldif               # LDIF-specific tests
pytest -m parser             # Parser tests

# Development testing
pytest --lf                  # Run last failed tests
pytest -v                    # Verbose output
pytest --cov=src/flext_ldif --cov-report=html  # Coverage report
```

### LDIF-Specific Operations

```bash
# Test core LDIF functionality
make ldif-parse              # Test LDIF parsing functionality
make ldif-validate           # Test LDIF validation functionality

# CLI testing
poetry run flext-ldif --help           # Show CLI help
poetry run flext-ldif parse sample.ldif      # Parse LDIF file
poetry run flext-ldif validate sample.ldif   # Validate LDIF file
```

### Build and Package Management

```bash
make build                   # Build distribution packages
make clean                   # Remove all artifacts
make deps-update             # Update dependencies
make deps-audit              # Security audit of dependencies
```

## Code Quality Standards

### Zero Tolerance Quality Gates

- **90% Test Coverage**: Minimum required coverage with comprehensive test suite
- **MyPy Strict Mode**: All code must pass strict type checking
- **Ruff ALL Rules**: Comprehensive linting with all rule categories enabled
- **Security Scanning**: Bandit + pip-audit + secrets detection
- **Pre-commit Hooks**: Automated quality checks on every commit

### Configuration Files

- **pyproject.toml**: Poetry dependencies, tool configuration, quality settings
- **Makefile**: Development commands and quality gates
- **conftest.py**: Test configuration with comprehensive fixtures

## Architecture Guidelines

### Domain Layer (models.py)

All domain objects should:

- Inherit from flext-core base classes (FlextEntity, FlextValueObject)
- Implement `validate_domain_rules()` for business logic validation
- Use immutable value objects for data integrity
- Follow DDD principles with rich domain models

### API Layer (api.py)

The FlextLdifAPI class:

- Orchestrates LDIF operations through service layer
- Uses flext-core dependency injection container
- Implements FlextResult pattern for error handling
- Integrates with flext-observability for monitoring
- Provides unified interface for all LDIF operations

### Services Layer (services.py)

Infrastructure services include:

- **FlextLdifParserService**: LDIF parsing with validation
- **FlextLdifValidatorService**: Business rule validation  
- **FlextLdifWriterService**: LDIF output generation

### Testing Strategy

- **Unit Tests**: Test individual domain objects and services
- **Integration Tests**: Test cross-layer interactions
- **LDIF-Specific Tests**: Comprehensive LDIF format testing
- **Performance Tests**: Benchmark critical operations
- **Error Handling Tests**: Validate exception scenarios

## Common Patterns

### LDIF Processing Flow

1. **Parse**: Convert LDIF text to domain objects
2. **Validate**: Apply business rules and schema validation
3. **Transform**: Apply transformations and filters
4. **Write**: Convert back to LDIF format

### Error Handling

Use FlextResult pattern from flext-core:

```python
def parse_ldif(content: str) -> FlextResult[list[FlextLdifEntry]]:
    try:
        entries = # parsing logic
        return FlextResult.success(entries)
    except Exception as e:
        return FlextResult.failure(str(e))
```

### Domain Validation

Implement business rules in domain objects:

```python
def validate_domain_rules(self) -> None:
    if not self.dn.value:
        raise FlextLdifValidationError("DN cannot be empty")
    # Additional business rules
```

## Dependencies

### Core Dependencies

- **Python 3.13**: Required Python version
- **pydantic**: Data validation and parsing
- **flext-core**: Foundation library with base patterns
- **ldif3**: LDIF format handling

### Development Dependencies

- **pytest**: Testing framework with extensive plugins
- **ruff**: Fast Python linter and formatter
- **mypy**: Static type checker
- **bandit**: Security linter
- **poetry**: Dependency management

## File Structure Notes

### Test Organization

- **conftest.py**: Comprehensive fixtures for LDIF testing scenarios
- **docker_fixtures.py**: Docker-based integration test fixtures (optional)
- Test files follow `test_*.py` pattern with descriptive names

### Source Organization

- **Unified API**: All public functionality available at root level import
- **Domain Consolidation**: Core domain objects consolidated in models.py
- **Clean Interfaces**: Simple functions (flext_ldif_parse, etc.) for common operations

## Performance Considerations

### LDIF Processing Optimizations

- **Streaming Support**: Handle large LDIF files efficiently
- **Batch Operations**: Process multiple entries together
- **Memory Management**: Efficient handling of large datasets
- **Caching**: Memoize expensive validation operations

### Configuration Settings

Environment variables for LDIF processing:

- `LDIF_ENCODING=utf-8`: Default encoding
- `LDIF_BUFFER_SIZE=8192`: Buffer size for file operations
- `LDIF_MAX_LINE_LENGTH=76`: Standard LDIF line wrapping
- `LDIF_VALIDATION_LEVEL=strict`: Validation strictness

## Integration with FLEXT Ecosystem

This project is part of the larger FLEXT ecosystem and:

- Follows FLEXT architectural patterns
- Uses flext-core foundation classes
- Maintains compatibility with other FLEXT projects
- Implements enterprise-grade quality standards

## Troubleshooting

### Common Issues

- **Import Errors**: Ensure flext-core dependency is available locally
- **Test Failures**: Check Docker availability for integration tests
- **Type Errors**: Run `make type-check` for detailed MyPy analysis
- **Quality Gate Failures**: Use `make validate` to see all issues

### Debug Commands

```bash
poetry run python -c "from flext_ldif import FlextLdifAPI; print('Import successful')"
make diagnose                # System diagnostics
make info                    # Project information
```
