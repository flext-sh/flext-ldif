# FLEXT-LDIF Utilities

This directory contains cross-cutting utilities and helper functions that support LDIF processing operations across all architectural layers without containing business logic.

## Overview

The utilities module provides shared functionality for validation, error handling, logging, and CLI operations while maintaining separation of concerns and avoiding circular dependencies between architectural layers.

## Module Structure

```
utils/
├── __init__.py                 # Utility exports and module initialization
├── validation.py               # Cross-layer validation utilities
├── error_handling.py           # Error handling patterns and utilities
├── logging.py                  # Structured logging configuration
└── cli_utils.py                # CLI helper functions and formatting
```

## Module Descriptions

### `validation.py`

**Purpose**: Provides reusable validation utilities that can be used across domain, application, and infrastructure layers.

**Key Functions**:

- LDIF format validation helpers
- DN syntax validation utilities
- Attribute name and value validation
- Common validation patterns and predicates

**Usage**:

```python
from flext_ldif.utils.validation import (
    validate_dn_syntax,
    validate_attribute_name,
    is_valid_ldif_line
)

# Validate DN syntax
if validate_dn_syntax("cn=user,dc=example,dc=com"):
    print("Valid DN")

# Validate attribute names
if validate_attribute_name("objectClass"):
    print("Valid attribute name")
```

### `error_handling.py`

**Purpose**: Provides error handling patterns, exception utilities, and error reporting helpers.

**Key Functions**:

- FlextResult pattern helpers
- Exception chaining utilities
- Error context management
- Structured error reporting

**Usage**:

```python
from flext_ldif.utils.error_handling import (
    wrap_exception,
    create_error_context,
    format_validation_errors
)

# Wrap exceptions with context
try:
    risky_operation()
except Exception as e:
    return wrap_exception(e, "Operation failed", {"context": "parsing"})
```

### `logging.py`

**Purpose**: Provides structured logging configuration and utilities integrated with flext-core logging patterns.

**Key Functions**:

- Logger configuration with FLEXT standards
- Structured logging helpers
- Performance logging utilities
- Debug and trace logging patterns

**Usage**:

```python
from flext_ldif.utils.logging import (
    configure_ldif_logging,
    log_performance,
    create_operation_logger
)

# Configure logging for LDIF operations
logger = configure_ldif_logging("ldif_parser")
logger.info("Starting LDIF parsing", extra={"entries_count": 100})
```

### `cli_utils.py`

**Purpose**: Provides CLI helper functions, formatting utilities, and command-line interface support.

**Key Functions**:

- Rich console formatting helpers
- Progress reporting utilities
- Command-line argument processing
- Output formatting and styling

**Usage**:

```python
from flext_ldif.utils.cli_utils import (
    format_entry_table,
    create_progress_bar,
    format_validation_report
)

# Format entries for CLI display
table = format_entry_table(entries)
console.print(table)
```

## Design Principles

### Cross-cutting Concerns

- **No Business Logic**: Utilities contain only technical helpers, no domain rules
- **Layer Neutral**: Can be used by any architectural layer without coupling
- **Reusable**: Focused, single-purpose functions that can be composed
- **Testable**: Pure functions with clear inputs and outputs

### FLEXT Integration

- **Consistent Patterns**: Follows flext-core utilities and logging standards
- **Type Safety**: Full type annotation coverage with strict validation
- **Error Handling**: Integrates with FlextResult patterns and error hierarchies
- **Observability**: Supports structured logging and tracing integration

### Quality Standards

- **Performance**: Optimized utilities with minimal overhead
- **Memory Efficiency**: Avoid unnecessary object creation and copying
- **Thread Safety**: Utilities are thread-safe where applicable
- **Comprehensive Testing**: 95%+ test coverage with edge case handling

## Usage Guidelines

### Import Conventions

```python
# Preferred: Import specific functions
from flext_ldif.utils.validation import validate_dn_syntax

# Acceptable: Import module for multiple functions
from flext_ldif.utils import validation

# Avoid: Wildcard imports
from flext_ldif.utils.validation import *  # Don't do this
```

### Error Handling Integration

```python
from flext_core import FlextResult
from flext_ldif.utils.error_handling import wrap_exception

def process_entry(entry):
    try:
        # Processing logic
        return FlextResult.ok(processed_entry)
    except Exception as e:
        error_context = {"entry_dn": entry.dn.value}
        wrapped_error = wrap_exception(e, "Entry processing failed", error_context)
        return FlextResult.fail(str(wrapped_error))
```

### Logging Integration

```python
from flext_ldif.utils.logging import create_operation_logger

def complex_operation():
    logger = create_operation_logger("complex_operation")

    logger.info("Starting complex operation", extra={"operation_id": "op_123"})
    try:
        # Operation logic
        logger.info("Operation completed successfully")
    except Exception as e:
        logger.error("Operation failed", extra={"error": str(e)})
        raise
```

## Testing Utilities

Each utility module includes comprehensive test coverage:

```python
# Test validation utilities
def test_validate_dn_syntax():
    assert validate_dn_syntax("cn=user,dc=example,dc=com") == True
    assert validate_dn_syntax("invalid-dn") == False

# Test error handling
def test_wrap_exception():
    original = ValueError("Original error")
    wrapped = wrap_exception(original, "Context", {"key": "value"})
    assert "Context" in str(wrapped)
    assert "Original error" in str(wrapped)
```

## Performance Considerations

### Efficient Validation

- Pre-compiled regex patterns for repeated validations
- Lazy evaluation for expensive operations
- Caching for frequently used validation results

### Memory Management

- Avoid creating unnecessary intermediate objects
- Use generators for processing large datasets
- Implement proper cleanup for resources

### Profiling Integration

```python
from flext_ldif.utils.logging import log_performance

@log_performance("validation_operation")
def validate_large_dataset(entries):
    # Validation logic with automatic performance logging
    pass
```

## Contributing Guidelines

When adding new utilities:

1. **Single Responsibility**: Each utility should have one clear purpose
2. **No Dependencies**: Avoid dependencies on other project modules except flext-core
3. **Type Safety**: Add comprehensive type annotations
4. **Documentation**: Include docstrings with examples
5. **Testing**: Achieve 95%+ test coverage
6. **Performance**: Consider performance implications and optimization opportunities

## Related Documentation

- **[Core Module](../core.py)** - Infrastructure processing that uses these utilities
- **[API Module](../api.py)** - Application service that uses these utilities
- **[CLI Module](../cli.py)** - Command-line interface using CLI utilities
- **[Architecture Guide](../../../docs/architecture/ARCHITECTURE.md)** - Overall architecture patterns
