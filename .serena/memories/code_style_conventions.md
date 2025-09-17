# FLEXT-LDIF Code Style & Conventions

## Architecture Principles

- **Unified Class Pattern**: Single class per module with nested helper classes
- **NO Multiple Classes**: One unified class per module only
- **NO Helper Functions**: All helpers must be nested classes
- **NO try/except Fallbacks**: Use explicit FlextResult error handling only

## Import Strategy

- **Root-level Only**: Import from flext-core root level
- **NO Internal Imports**: Never import from flext-core internals
- **CLI Compliance**: Use flext-cli exclusively, NO direct Click/Rich imports

## Type Safety

- **Strict Typing**: MyPy strict mode enabled
- **Python 3.13+**: Use modern generic syntax and type features
- **NO object Types**: Proper type annotations required
- **NO type: ignore**: Without specific error codes

## Error Handling

- **FlextResult Pattern**: ALL operations return FlextResult[T]
- **Railway Programming**: Use .bind(), .map(), .tap() chains
- **NO try/except**: Explicit error checking only
- **Builder Pattern**: Complex exceptions use Builder Pattern

## Naming Conventions

- **Classes**: PascalCase (FlextLdifAPI, FlextLdifModels)
- **Methods**: snake_case (parse_file, validate_entries)
- **Constants**: UPPER_SNAKE_CASE (LDIF_PARSE_ERROR)
- **Private**: Leading underscore (\_container, \_logger)

## Documentation Standards

- **Docstrings**: Google style with type hints
- **Examples**: Complete working examples in docstrings
- **API Documentation**: All public APIs documented
- **NO Inflated Claims**: Document only verified functionality

## Code Organization

- **Single Responsibility**: One class per module
- **Nested Helpers**: Helper classes nested within main class
- **Domain Separation**: Clear separation of concerns
- **Protocol-based**: Use protocols for dependency inversion

## Quality Standards

- **ZERO Lint Errors**: Ruff with all rules enabled
- **ZERO Type Errors**: MyPy strict mode
- **96%+ Test Coverage**: Real functionality tests
- **NO Code Duplication**: Systematic elimination through patterns

## Prohibited Patterns

- ❌ Multiple classes per module
- ❌ Helper functions outside classes
- ❌ try/except fallback mechanisms
- ❌ Direct Click/Rich imports
- ❌ type: ignore without error codes
- ❌ object types instead of proper annotations
- ❌ Custom LDIF parsing implementations
