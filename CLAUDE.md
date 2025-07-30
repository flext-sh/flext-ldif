# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**flext-ldif** is an enterprise-grade LDIF (LDAP Data Interchange Format) processing library built with **Clean Architecture** and **Domain-Driven Design** principles using the **flext-core** foundation. It provides comprehensive LDIF parsing, generation, validation, and transformation capabilities for Python 3.13+ applications.

## Key Architecture Patterns

### Clean Architecture Structure

```
src/flext_ldif/
├── domain/                    # Core business logic (currently consolidated in models.py)
├── infrastructure/            # External concerns & DI container
├── api.py                     # Application layer - main processing logic
├── models.py                  # Domain entities and value objects
├── core.py                    # Core LDIF processing functionality
├── config.py                  # Configuration management
├── exceptions.py              # Domain exceptions
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

## TODO: GAPS DE ARQUITETURA IDENTIFICADOS - PRIORIDADE ALTA

### 🚨 GAP 1: LDAP Integration Incomplete
**Status**: ALTO - LDIF processing não integrado com flext-ldap
**Problema**:
- LDIF parsing/generation não connected com LDAP operations
- Não reutiliza flext-ldap para validation e schema compliance
- Import/export workflows não integrated

**TODO**:
- [ ] Integrar com flext-ldap para validation e schema compliance
- [ ] Implementar LDIF-LDAP import/export workflows
- [ ] Criar transformation patterns entre LDIF e LDAP
- [ ] Documentar LDIF-LDAP integration patterns

### 🚨 GAP 2: Singer Integration Missing
**Status**: ALTO - LDIF não integrado com Singer ecosystem
**Problema**:
- LDIF processing não available via flext-tap-ldif/flext-target-ldif
- File-based Singer streams não implemented para LDIF
- LDIF catalog generation não available

**TODO**:
- [ ] Integrar com flext-tap-ldif e flext-target-ldif
- [ ] Implementar Singer file streams para LDIF processing
- [ ] Criar LDIF catalog generation patterns
- [ ] Documentar LDIF Singer integration

### 🚨 GAP 3: Data Transformation Pipeline Gap
**Status**: ALTO - LDIF não integra com data transformation ecosystem
**Problema**:
- LDIF transformations não available via flext-dbt-ldif
- ETL pipeline não implemented para LDIF data
- Data quality validation não integrated

**TODO**:
- [ ] Integrar com flext-dbt-ldif para data transformations
- [ ] Implementar LDIF ETL pipeline patterns
- [ ] Criar data quality validation para LDIF
- [ ] Documentar LDIF transformation workflows
```

### Testing Commands

```bash
# Run specific test categories (defined in conftest.py)
pytest -m unit               # Unit tests only
pytest -m integration        # Integration tests only
pytest -m ldif               # LDIF-specific tests
pytest -m parsing            # Parsing tests
pytest -m validation         # Schema validation tests
pytest -m performance        # Performance benchmarks

# Development testing
pytest --lf                  # Run last failed tests
pytest -v                    # Verbose output
pytest --cov=src/flext_ldif --cov-report=html  # Coverage report
```

### LDIF-Specific Operations

```bash
# Test core LDIF functionality
make ldif-parse              # Test LDIF parsing
make ldif-validate           # Test LDIF validation
make ldif-transform          # Test LDIF transformations
make ldif-performance        # Performance benchmarks

# Advanced LDIF operations
make transform-normalize     # Normalize LDIF data
make transform-filter        # Filter LDIF entries
make validate-format         # Validate LDIF format compliance
make validate-schema         # Validate schema compliance
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

Application services should:

- Orchestrate domain operations
- Handle error cases with FlextResult pattern
- Maintain clean interfaces for external consumers
- Delegate business logic to domain objects

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
