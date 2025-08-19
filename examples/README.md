# FLEXT-LDIF Examples

This directory contains comprehensive examples demonstrating enterprise-grade LDIF processing capabilities using Clean Architecture patterns, Domain-Driven Design principles, and seamless FLEXT ecosystem integration.

## Overview

The examples are organized by complexity level and practical use cases, showcasing real-world scenarios for LDIF processing operations with proper error handling, validation, and performance optimization.

### Example Categories

- **Basic Operations**: Fundamental parsing, validation, and writing operations
- **Advanced Processing**: Complex transformations, filtering, and business rule validation
- **Enterprise Integration**: Production-ready patterns with flext-core and observability
- **Performance Optimization**: Large-scale processing and memory-efficient operations
- **Error Handling**: Comprehensive error scenarios and recovery patterns
- **Sample Data**: Realistic LDIF datasets for testing and demonstration

## Running Examples

### Prerequisites

```bash
# Install the library in development mode
poetry install

# Or run examples directly with poetry
poetry run python examples/basic_parsing.py
```

### Example Categories

1. **`basic_parsing.py`** - Simple LDIF parsing and entry manipulation
2. **`advanced_validation.py`** - Domain validation with business rules
3. **`cli_integration.py`** - Integration with flext-cli patterns
4. **`error_handling.py`** - FlextResult patterns and exception handling
5. **`transformation_pipeline.py`** - Complex data transformations
6. **`production_usage.py`** - Enterprise-grade usage patterns

### Sample LDIF Files

- **`sample_basic.ldif`** - Simple person entries for basic examples
- **`sample_complex.ldif`** - Complex directory structure with groups and OUs
- **`sample_invalid.ldif`** - Invalid LDIF for error handling examples
- **`sample_large.ldif`** - Large dataset for performance testing

## Integration with FLEXT Ecosystem

These examples demonstrate integration with:

- **flext-core**: Result patterns, logging, and base classes
- **flext-cli**: Command-line interface patterns
- **Clean Architecture**: Domain-driven design principles
- **Enterprise Patterns**: Production-ready error handling and validation

## Example Output

Each example includes expected output and demonstrates:

- ✅ Successful operations with FlextResult[None].ok()
- ❌ Error handling with FlextResult[None].fail()
- 📊 Statistics and validation reporting
- 🔄 Transformation and filtering operations
- 📝 Comprehensive logging and tracing
