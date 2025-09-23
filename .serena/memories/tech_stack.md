# FLEXT-LDIF Tech Stack

## Core Technologies

- **Python**: 3.13+ (strict typing, modern syntax)
- **Poetry**: Dependency management and packaging
- **Pydantic**: Data validation and model management
- **LDIF3**: LDIF format handling (internal abstraction only)

## Architecture Patterns

- **Clean Architecture**: Separation of concerns across layers
- **Domain-Driven Design (DDD)**: Business logic in domain layer
- **Railway-oriented Programming**: Monadic FlextResult chains
- **Dependency Injection**: FlextContainer for service management
- **Unified Class Architecture**: Single class per module with nested helpers

## Design Patterns Implemented

- **Builder Pattern**: Exception handling system (127+ lines duplication eliminated)
- **Strategy Pattern**: Exception handling strategies (all duplication eliminated)
- **Template Method Pattern**: CLI processing (73 complexity points reduced)
- **Factory Pattern**: Unified object creation through FlextLdifModels.Factory

## Quality Tools

- **Ruff**: Linting and formatting (ZERO tolerance)
- **MyPy**: Strict type checking (ZERO errors required)
- **PyRight**: Additional type checking
- **Pytest**: Testing framework with 96%+ coverage requirement
- **Bandit**: Security scanning
- **pip-audit**: Dependency vulnerability scanning

## Development Environment

- **Linux**: Primary development platform
- **Poetry**: Virtual environment management
- **Pre-commit**: Quality gate enforcement
- **Make**: Build automation and quality gates

## Integration Dependencies

- **flext-core**: Foundation library (FlextResult, FlextContainer, FlextService)
- **flext-cli**: CLI framework (NO direct Click/Rich imports)
- **flext-ldap**: LDAP operations integration
- **flext-observability**: Monitoring and logging

## File Structure

```
src/flext_ldif/
├── api.py                     # Application layer - unified LDIF API
├── models.py                  # Domain entities and value objects
├── services.py                # Infrastructure services
├── cli.py                     # Template Method Pattern CLI
├── exceptions.py              # Builder Pattern exception system
├── constants.py               # Unified constants
├── protocols.py               # Type protocols for dependency inversion
├── format_handlers.py         # LDIF format handling
├── format_validators.py       # LDIF validation logic
└── utilities.py               # Utility functions
```
