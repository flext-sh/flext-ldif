# FLEXT-LDIF Source Code


<!-- TOC START -->
- [Architecture Overview](#architecture-overview)
- [Package Structure](#package-structure)
- [Key Design Principles](#key-design-principles)
  - [Clean Architecture Compliance](#clean-architecture-compliance)
  - [Domain-Driven Design](#domain-driven-design)
  - [FLEXT Ecosystem Integration](#flext-ecosystem-integration)
- [Module Responsibilities](#module-responsibilities)
  - [Core Business Logic](#core-business-logic)
  - [Infrastructure Implementation](#infrastructure-implementation)
  - [User Interfaces](#user-interfaces)
  - [Cross-cutting Concerns](#cross-cutting-concerns)
- [Development Standards](#development-standards)
  - [Code Quality Requirements](#code-quality-requirements)
  - [Code Standards](#code-standards)
  - [Integration](#integration)
- [Usage Examples](#usage-examples)
  - [Direct Module Usage](#direct-module-usage)
  - [Recommended Public API](#recommended-public-api)
- [Future Architecture Migration](#future-architecture-migration)
- [Contributing](#contributing)
- [Related Documentation](#related-documentation)
<!-- TOC END -->

This directory contains the source code for the FLEXT-LDIF library, organized following Clean Architecture and Domain-Driven Design principles.

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
├── py.typed
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

- **Entities**: `FlextLdifModels.Entry` with identity and business logic
- **Value Objects**: `FlextLdifModels.DN`, `FlextLdifModels.Attributes` (immutable)
- **Services**: Complex business operations in `services.py`
- **Domain Events**: Planned for future implementation

### FLEXT Ecosystem Integration

- **flext-core**: Foundation patterns and FlextResult error handling
- **flext-observability**: Monitoring and tracing integration
- **Type Safety**: MyPy strict mode adoption; aiming for 95%+ coverage

## Module Responsibilities

### Core Business Logic

- **`models.py`**: Domain entities, value objects, and business rule validation
- **`exceptions.py`**: Domain-specific exceptions and error hierarchies
- **`api.py`**: Main application service orchestrating business operations

### Infrastructure Implementation

- **`core.py`**: Low-level LDIF parsing and writing
- **`config.py`**: Configuration management with environment variables
- **`services.py`**: Domain service implementations and dependency injection
- **`modernized_ldif.py`**: Extended LDIF format support

### User Interfaces

- **`cli.py`**: Command-line interface
- **`__init__.py`**: Public API exports

### Cross-cutting Concerns

- **`utils/`**: Shared utilities, validation helpers, and logging configuration

## Development Standards

### Code Quality Requirements

- **Test Coverage**: 90%+ target across all modules
- **Type Safety**: Strict MyPy validation
- **Documentation**: Complete docstrings following PEP 257
- **Linting**: Ruff with strict rules enabled

### Code Standards

- **Error Handling**: FlextResult pattern for error composition
- **Configuration**: Environment variable support with validation
- **Logging**: Structured logging with correlation IDs
- **Performance**: Memory-efficient batch processing

### Integration

- **Dependency Injection**: flext-core container for service resolution
- **Observability**: Distributed tracing and metrics
- **Configuration**: Settings with validation and defaults

## Usage Examples

### Direct Module Usage

```python
# Domain model usage
from flext_ldif.models import FlextLdifModels

# Application service usage
from flext_ldif.api import FlextLdif

# Configuration management
from flext_ldif.settings import FlextLdifSettings

# Core processing (advanced usage)
from flext_ldif.core import TLdif
```

### Recommended Public API

```python
# Simplified public interface
from flext_ldif import (
    FlextLdif,           # Main application service
    FlextLdifSettings,        # Configuration management
    FlextLdifModels,        # Unified domain models
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
