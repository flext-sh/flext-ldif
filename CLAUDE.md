# FLEXT-LDIF PROJECT CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**References**: See [../CLAUDE.md](../CLAUDE.md) for FLEXT ecosystem-wide standards and quality gates.

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

## Project-Specific Quality Status (CURRENT REALITY)

### ACHIEVED QUALITY LEVELS (2025-08-23)

- **Test Coverage**: **96% REAL** (495 tests passing, 1293 statements)
- **Source Code Typing**: **100% CLEAN** (0 errors in MyPy + PyRight)
- **Architecture**: **Enterprise-grade** Clean Architecture + DDD patterns validated

### KNOWN ACCEPTABLE TECHNICAL DEBT

- **Test Type Errors**: 15 remaining PyRight errors in `tests/` (false positives)
- **Test Annotations**: ~83 Ruff warnings for missing pytest fixture annotations
- **ROI Assessment**: Further improvement yields diminishing returns

### VALIDATION COMMANDS (PROJECT-SPECIFIC)

```bash
# Source code validation (must be 100% clean)
PYTHONPATH=src poetry run mypy src/flext_ldif        # 0 errors required
PYTHONPATH=src poetry run pyright src/              # 0 errors required

# Coverage validation (current: 96%)
PYTHONPATH=src poetry run python -m pytest tests/ --cov=src/flext_ldif --cov-report=term-missing --tb=no -q

# Test execution (current: 495 tests)
make test                                            # All tests must pass
```

### Configuration Files

- **pyproject.toml**: Poetry dependencies, tool configuration, quality settings
- **Makefile**: Development commands and quality gates
- **conftest.py**: Test configuration with comprehensive fixtures

## Architecture Guidelines

### Domain Layer (models.py)

All domain objects should:

- Inherit from flext-core base classes (FlextEntity, FlextValue)
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
        return FlextResult[None].ok(entries)
    except Exception as e:
        return FlextResult[None].fail(str(e))
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

## Project-Specific Development Lessons (LEARNED 2025-08-23)

### TYPING ERROR PATTERNS AND SOLUTIONS

#### ErrorMessage Null-Safety Pattern
```python
# PROBLEM: result.error can be None but code assumes string
assert "error text" in result.error  # ❌ Type error

# SOLUTION: Null-safe check
assert result.error is not None and "error text" in result.error  # ✅ Correct
```

#### Pydantic Field Assignment False Positives
```python
# PROBLEM: PyRight doesn't understand Pydantic field validators
class Model(BaseModel):
    field: str = custom_field()  # ❌ PyRight reports FieldInfo vs str

# SOLUTION: File-level pragma for known false positives
# pyright: reportAssignmentType=false
# Reason: Pydantic field assignment pattern is not understood by pyright but is valid
```

#### Mock Type Compatibility
```python
# PROBLEM: Mock objects vs real types in tests
entries: list[FlextLdifEntry] = [mock_entry]  # ❌ Type error

# SOLUTION: File-level pragma or specific type ignore
# pyright: reportArgumentType=false
# Reason: Test mocks are intentionally different types
```

### AUTOMATION LESSONS LEARNED

#### SAFE AUTOMATION APPROACH
```bash
# ❌ DANGEROUS: Blanket sed replacements
sed -i 's/pattern/replacement/g' file.py  # Can break syntax

# ✅ SAFE: Manual verification first, then targeted fixes
grep -n "pattern" file.py                 # Understand scope
# Manual fix of 1-2 examples
# Then careful automation of remaining identical cases
```

#### ROI-AWARE QUALITY IMPROVEMENT
- **Victory Condition**: 90%+ coverage with 0 source code type errors
- **Diminishing Returns**: Last 10% of quality metrics often take 50%+ of time
- **Pragmatic Stop Point**: When false positives outnumber real issues

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

### CURRENT PROJECT STATE VALIDATION (2025-08-23)

```bash
# Verify current quality achievements
PYTHONPATH=src poetry run mypy src/flext_ldif                    # Should show: Success: no issues
PYTHONPATH=src poetry run pyright src/                          # Should show: 0 errors, 0 warnings
PYTHONPATH=src poetry run python -m pytest tests/ --tb=no -q   # Should show: 495 passed

# Check coverage achievement
PYTHONPATH=src poetry run python -m pytest tests/ --cov=src/flext_ldif --cov-report=term-missing --tb=no -q | tail -5
# Should show: TOTAL ... 96%
```
