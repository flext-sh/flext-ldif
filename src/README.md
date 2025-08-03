# FLEXT-LDIF Source Code

This directory contains the complete source code for the FLEXT-LDIF enterprise LDIF processing library, organized following Clean Architecture and Domain-Driven Design principles.

## Architecture Overview

The source code is structured in a single package (`flext_ldif/`) that implements Clean Architecture patterns while maintaining compatibility with the current project structure. The code is organized into logical modules representing different architectural concerns.

## Package Structure

```
src/flext_ldif/
├── __init__.py                 # Public API exports and version information
├── api.py                      # Application Layer - Main API service
├── models.py                   # Domain Layer - Entities and value objects
├── core.py                     # Infrastructure Layer - Core LDIF processing
├── config.py                   # Infrastructure Layer - Configuration management
├── services.py                 # Infrastructure Layer - Domain services
├── cli.py                      # Interface Layer - Command-line interface
├── exceptions.py               # Domain Layer - Domain-specific exceptions
├── modernized_ldif.py          # Infrastructure Layer - Extended LDIF support
├── py.typed                    # Type information marker
└── utils/                      # Cross-cutting utilities and helpers
    ├── __init__.py
    ├── validation.py           # Validation utilities
    ├── error_handling.py       # Error handling patterns
    ├── logging.py              # Logging configuration
    └── cli_utils.py            # CLI helper functions
```

## Key Design Principles

### Clean Architecture Compliance

- **Domain Layer**: Pure business logic in `models.py` and `exceptions.py`
- **Application Layer**: Use case orchestration in `api.py`
- **Infrastructure Layer**: Technical concerns in `core.py`, `config.py`, `services.py`
- **Interface Layer**: User interfaces in `cli.py`

### Domain-Driven Design

- **Entities**: `FlextLdifEntry` with identity and business logic
- **Value Objects**: `FlextLdifDistinguishedName`, `FlextLdifAttributes` (immutable)
- **Domain Services**: Complex business operations in `services.py`
- **Domain Events**: Planned for future implementation

### FLEXT Ecosystem Integration

- **flext-core**: Foundation patterns and FlextResult error handling
- **flext-observability**: Monitoring and tracing integration
- **Type Safety**: 95%+ type annotation coverage with strict MyPy validation

## Module Responsibilities

### Core Business Logic

- **`models.py`**: Domain entities, value objects, and business rule validation
- **`exceptions.py`**: Domain-specific exceptions and error hierarchies
- **`api.py`**: Main application service orchestrating business operations

### Infrastructure Implementation

- **`core.py`**: Low-level LDIF parsing and writing with performance optimization
- **`config.py`**: Enterprise configuration management with environment variables
- **`services.py`**: Domain service implementations and dependency injection
- **`modernized_ldif.py`**: Extended LDIF format support and compatibility

### User Interfaces

- **`cli.py`**: Comprehensive command-line interface with rich formatting
- **`__init__.py`**: Public API exports and simplified interfaces

### Cross-cutting Concerns

- **`utils/`**: Shared utilities, validation helpers, and logging configuration

## Development Standards

### Code Quality Requirements

- **Test Coverage**: 90%+ minimum across all modules
- **Type Safety**: Strict MyPy validation with no untyped code
- **Documentation**: Comprehensive docstrings following enterprise standards
- **Linting**: Ruff with ALL rules enabled for maximum code quality

### Enterprise Standards

- **Error Handling**: FlextResult pattern for railway-oriented programming
- **Configuration**: Environment variable support with validation
- **Logging**: Structured logging with correlation IDs and trace context
- **Performance**: Memory-efficient processing with configurable limits

### Integration Standards

- **Dependency Injection**: flext-core container for service resolution
- **Observability**: Distributed tracing and metrics collection
- **Configuration**: Enterprise-grade settings with validation and defaults

## Usage Examples

### Direct Module Usage

```python
# Domain model usage
from flext_ldif.models import FlextLdifEntry, FlextLdifDistinguishedName

# Application service usage
from flext_ldif.api import FlextLdifAPI

# Configuration management
from flext_ldif.config import FlextLdifConfig

# Core processing (advanced usage)
from flext_ldif.core import TLdif
```

### Recommended Public API

```python
# Simplified public interface
from flext_ldif import (
    FlextLdifAPI,           # Main application service
    FlextLdifConfig,        # Configuration management
    FlextLdifEntry,         # Domain entity
    FlextLdifDistinguishedName,  # Value object
)
```

## Future Architecture Migration

The current flat structure will evolve to proper Clean Architecture directories:

```
src/flext_ldif/
├── domain/                     # Pure business logic
│   ├── entities.py
│   ├── value_objects.py
│   └── services.py
├── application/                # Use cases and orchestration
│   ├── api.py
│   └── handlers.py
├── infrastructure/             # External concerns
│   ├── config.py
│   ├── persistence.py
│   └── adapters.py
└── interfaces/                 # User interfaces
    ├── cli.py
    └── web.py
```

## Contributing

When contributing to the source code:

1. **Follow architectural patterns**: Respect Clean Architecture boundaries
2. **Maintain type safety**: Add comprehensive type annotations
3. **Write tests**: Ensure 90%+ coverage for all new code
4. **Document thoroughly**: Add comprehensive docstrings and examples
5. **Validate quality**: Run all quality gates before submitting

## Related Documentation

- **[Architecture Guide](../docs/architecture/ARCHITECTURE.md)** - Detailed architectural patterns
- **[API Documentation](../docs/api/API.md)** - Complete API reference
- **[Module Organization](../docs/standards/python-module-organization.md)** - Detailed module standards
- **[Development Guide](../CLAUDE.md)** - Development patterns and practices
