# FLEXT-LDIF Development Guide

**Version**: 0.9.0 | **Updated**: September 17, 2025

This guide covers LDIF-specific development workflows and technical considerations for contributing to FLEXT-LDIF.

## Development Environment Setup

### Prerequisites

- Python 3.13 or higher
- Poetry for dependency management
- Understanding of LDIF format (RFC 2849)
- Familiarity with FLEXT ecosystem patterns (see [flext-core documentation](../../flext-core/README.md))

### Initial Setup

```bash
# Navigate to project directory
cd flext-ldif

# Set up development environment
make setup

# Verify LDIF functionality
python -c "from flext_ldif import FlextLDIFAPI; print('LDIF development environment ready')"
```

### Development Commands

```bash
# Code quality
make lint           # Ruff linting
make type-check     # MyPy type checking
make format         # Code formatting
make validate       # Complete validation pipeline

# Testing
make test           # Run test suite
pytest -m unit      # Unit tests only
pytest -m integration  # Integration tests
pytest --cov=src/flext_ldif  # Coverage report

# Development utilities
make clean          # Clean build artifacts
make reset          # Full reset of environment
```

## LDIF Processing Architecture

### Current Implementation (v0.9.0)

FLEXT-LDIF uses a custom LDIF parser implementation with the following characteristics:

```python
# Current implementation approach
class _ParserHelper:
    """Custom LDIF parser - loads entire files into memory."""

    def __init__(self, content: str) -> None:
        self._content = content
        self._lines = content.splitlines()  # Loads all lines into memory

    def parse(self) -> Iterator[tuple[str, dict[str, list[str]]]]:
        """Parse LDIF content and yield (dn, attributes) tuples."""
        # Process all lines already in memory
        pass
```

**Memory Characteristics**:

- Loads entire LDIF file into memory during processing
- Memory usage scales linearly with file size
- Suitable for files under 100MB
- No streaming support for large files

### LDIF-Specific Development Patterns

#### Working with LDIF Entries

```python
from flext_ldif import FlextLDIFAPI, FlextLDIFModels

# LDIF entry creation using Factory pattern
entry_data = {
    "dn": "cn=user,ou=people,dc=example,dc=com",
    "attributes": {
        "cn": ["user"],
        "objectClass": ["person", "organizationalPerson"],
        "mail": ["user@example.com"]
    }
}
entry = FlextLDIFModels.Factory.create_entry(entry_data)

# LDIF processing with memory awareness
api = FlextLDIFAPI()

# For small files (< 100MB)
result = api.parse_file("small_directory.ldif")

# For larger files, consider external tools
# grep "objectClass: person" large_directory.ldif | processing...
```

#### LDIF Validation Patterns

```python
# LDIF-specific validation
def validate_ldif_structure(entries: list[FlextLDIFModels.Entry]) -> FlextResult[None]:
    """Validate LDIF entries for common issues."""
    for entry in entries:
        # Check DN format
        if not entry.dn.value:
            return FlextResult[None].fail("Empty DN found")

        # Check required attributes
        if "objectClass" not in entry.attributes.data:
            return FlextResult[None].fail(f"Missing objectClass in {entry.dn.value}")

    return FlextResult[None].ok(None)
```

#### Memory-Conscious Processing

```bash
# For large LDIF files, consider external processing
# Extract specific object classes
grep "^objectClass: person" large.ldif > persons.ldif

# Count entries without loading into memory
grep -c "^dn:" large.ldif

# Process in chunks using external tools
split -l 10000 large.ldif chunk_
for chunk in chunk_*; do
    python process_ldif_chunk.py "$chunk"
done
```

## Testing LDIF Functionality

### LDIF Test Data

```python
# Create test LDIF content
def create_test_ldif() -> str:
    """Create valid LDIF content for testing."""
    return """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
objectClass: organizationalPerson
mail: test@example.com

dn: cn=admin,dc=example,dc=com
cn: admin
objectClass: person
description: Administrator account
"""

# Test parsing with various LDIF formats
def test_ldif_parsing():
    api = FlextLDIFAPI()
    result = api.parse_string(create_test_ldif())
    assert result.is_success
    entries = result.unwrap()
    assert len(entries) == 2
```

### Memory Usage Testing

```python
import psutil
import os

def test_memory_usage():
    """Monitor memory usage during LDIF processing."""
    process = psutil.Process(os.getpid())
    initial_memory = process.memory_info().rss

    api = FlextLDIFAPI()
    result = api.parse_file("test_data.ldif")

    final_memory = process.memory_info().rss
    memory_increase = final_memory - initial_memory

    # Memory increase should be reasonable for file size
    file_size = os.path.getsize("test_data.ldif")
    assert memory_increase < file_size * 3  # Allow 3x overhead
```

## Performance Considerations

### Current Limitations

1. **Memory Usage**: Entire file loaded into memory
2. **Single-threaded**: No parallel processing
3. **No Progress Reporting**: Long operations provide no feedback
4. **No Streaming**: Cannot process files larger than available memory

### Performance Guidelines

```python
# Good: Process small files directly
def process_small_ldif(file_path: str) -> FlextResult[dict]:
    """Process LDIF files under 100MB."""
    api = FlextLDIFAPI()
    return api.parse_file(file_path)

# Consider: External tools for large files
def process_large_ldif(file_path: str) -> FlextResult[dict]:
    """Process large LDIF files using external tools."""
    # Use grep, awk, or other streaming tools
    # Then process results with FLEXT-LDIF
    pass

# Monitor: Memory usage for production systems
def process_with_monitoring(file_path: str) -> FlextResult[dict]:
    """Process LDIF with memory monitoring."""
    file_size = os.path.getsize(file_path)
    if file_size > 100 * 1024 * 1024:  # 100MB
        return FlextResult[dict].fail("File too large for current implementation")

    return process_small_ldif(file_path)
```

## Contributing Guidelines

### LDIF-Specific Code Review

When reviewing LDIF-related code, check for:

1. **Memory Efficiency**: Does the code load unnecessary data into memory?
2. **LDIF Compliance**: Does the parsing follow RFC 2849 standards?
3. **Error Handling**: Are LDIF format errors handled appropriately?
4. **Test Coverage**: Are LDIF edge cases tested?

### Future Development Priorities

1. **Streaming Parser**: Replace custom parser with streaming approach
2. **Memory Monitoring**: Add memory usage tracking and warnings
3. **External Library Integration**: Evaluate ldap3 for streaming capabilities
4. **Performance Testing**: Establish benchmarks for different file sizes

## Common LDIF Development Issues

### LDIF Format Edge Cases

```python
# Handle continuation lines
ldif_with_continuation = """dn: cn=long name that spans multiple lines,
 ou=people,dc=example,dc=com
cn: long name that spans multiple lines
"""

# Handle base64 encoded values
ldif_with_base64 = """dn: cn=user,dc=example,dc=com
cn:: dXNlcg==
"""

# Handle URL references (if enabled)
ldif_with_url = """dn: cn=user,dc=example,dc=com
photo:< file:///path/to/photo.jpg
"""
```

### Memory Debugging

```bash
# Monitor memory usage during development
python -m memory_profiler ldif_script.py

# Use line profiler for detailed analysis
kernprof -l -v ldif_script.py

# Monitor with system tools
top -p $(pgrep -f python)
```

## Integration with FLEXT Ecosystem

For FLEXT ecosystem integration patterns, see [flext-core documentation](../../flext-core/CLAUDE.md). FLEXT-LDIF follows standard patterns for:

- FlextResult error handling
- FlextContainer dependency injection
- FlextDomainService architecture
- Type safety with Pydantic v2

Focus on LDIF-specific concerns:

- LDIF format validation
- Memory-efficient processing
- RFC 2849 compliance
- Directory data transformation

---

**Development Focus**: LDIF processing efficiency, memory optimization, and RFC 2849 compliance within FLEXT ecosystem patterns.
