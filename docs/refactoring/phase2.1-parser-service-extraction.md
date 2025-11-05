# Phase 2.1 - Parser Service Extraction

**Date**: 2025-01-29
**Status**: Complete - Ready for Integration
**Goal**: Extract all parsing operations from FlextLdif facade into dedicated FlextLdifParser

---

## Overview

Created new `FlextLdifParser` following FLEXT architectural patterns to consolidate all LDIF parsing operations from the 2184-line api.py facade.

**New File**: `src/flext_ldif/services/parser.py` (576 lines)

---

## Operations Extracted

### 1. `parse()` - Unified parsing with single/batch/pagination support

- **Lines in api.py**: 278-453
- **Functionality**:
  - Single file/content parsing
  - Batch processing for multiple files
  - Pagination for large files with generator pattern
  - File existence validation
  - Error handling with partial success for batch operations

### 2. `parse_schema_ldif()` - Schema LDIF parsing

- **Lines in api.py**: 744-827
- **Functionality**:
  - Parse schema LDIF files
  - Extract modify operations (add/replace/delete)
  - Handle attributeTypes, objectClasses, ldapSyntaxes, matchingRules
  - Convert schema attributes to structured modifications

### 3. `parse_with_auto_detection()` - Automatic server type detection

- **Lines in api.py**: 1990-2033
- **Functionality**:
  - Auto-detect LDAP server type from LDIF content
  - Apply appropriate server quirks automatically
  - Fallback to RFC mode if detection fails

### 4. `parse_relaxed()` - Lenient parsing for broken files

- **Lines in api.py**: 2035-2077
- **Functionality**:
  - Enable relaxed parsing mode
  - Best-effort parsing for non-compliant LDIF
  - Create temporary client with relaxed configuration

### 5. `detect_server_type()` - Manual server type detection

- **Lines in api.py**: 1952-1988
- **Functionality**:
  - Detect LDAP server type from file or content
  - Return confidence scores and pattern matches
  - Support both file path and content string inputs

### 6. `get_effective_server_type()` - Server type resolution

- **Lines in api.py**: 2079-2104
- **Functionality**:
  - Resolve effective server type based on configuration priority
  - Handle relaxed mode, manual mode, auto-detection, and RFC-only modes
  - Used internally by other parsing methods

---

## Architecture

### Service Design

```python
class FlextLdifParser(Flext[dict[str, object]]):
    """LDIF parsing service following FLEXT patterns."""

    _logger: FlextLogger          # Structured logging
    _config: FlextLdifConfig      # Configuration
```

### Dependencies

- **FlextLdifConfig**: Configuration for parsing behavior
- **FlextLogger**: Structured logging for operations
- **FlextResult**: Railway-oriented error handling
- **FlextService**: Base class for FLEXT ecosystem integration

### Design Principles Applied

1. **Single Responsibility Principle**: Service focuses only on parsing operations
2. **Dependency Injection**: Client and config injected via constructor
3. **Railway-Oriented Programming**: All methods return FlextResult[T]
4. **Type Safety**: Full Python 3.13+ type annotations
5. **FLEXT Patterns**: Inherits from FlextService, uses FlextResult

---

## Integration Plan

### Step 1: Update api.py to use parser service

Replace existing parse methods in `FlextLdif` class:

```python
class FlextLdif(Flext[dict[str, object]]):
    _parser: FlextLdifParser  # Add new service

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        super().__init__()
        self._config = config if config is not None else FlextLdifConfig()

        # Initialize parser service
        self._parser = FlextLdifParser(
            client=self._client,
            config=self._config
        )
        # ... rest of initialization

    def parse(self, source, server_type, *, batch, paginate, page_size):
        """Delegate to parser service."""
        return self._parser.parse(
            source=source,
            server_type=server_type,
            batch=batch,
            paginate=paginate,
            page_size=page_size
        )

    def parse_schema_ldif(self, file_path, server_type=None):
        """Delegate to parser service."""
        return self._parser.parse_schema_ldif(file_path, server_type)

    def parse_with_auto_detection(self, source):
        """Delegate to parser service."""
        return self._parser.parse_with_auto_detection(source)

    def parse_relaxed(self, source):
        """Delegate to parser service."""
        return self._parser.parse_relaxed(source)

    def detect_server_type(self, ldif_path=None, ldif_content=None):
        """Delegate to parser service."""
        return self._parser.detect_server_type(ldif_path, ldif_content)

    def get_effective_server_type(self, ldif_path=None):
        """Delegate to parser service."""
        return self._parser.get_effective_server_type(ldif_path)
```

### Step 2: Remove original implementations from api.py

**Lines to DELETE from api.py**:

- Lines 278-453: `parse()` method
- Lines 744-827: `parse_schema_ldif()` method
- Lines 1952-1988: `detect_server_type()` method
- Lines 1990-2033: `parse_with_auto_detection()` method
- Lines 2035-2077: `parse_relaxed()` method
- Lines 2079-2104: `get_effective_server_type()` method

**Total lines removed**: ~415 lines

### Step 3: Update services/**init**.py

Add parser service to exports:

```python
from flext_ldif.services.parser import FlextLdifParser

__all__ = [
    # ... existing exports
    "FlextLdifParser",
]
```

### Step 4: Update imports in api.py

Add import for parser service:

```python
from flext_ldif.services.parser import FlextLdifParser
```

---

## Quality Assurance

### Type Safety

- ✅ All methods have complete type annotations
- ✅ Uses Python 3.13+ syntax (`from __future__ import annotations`)
- ✅ Complex union types properly handled with `cast()`
- ✅ FlextResult[T] return types for all operations

### Error Handling

- ✅ Railway-oriented programming with FlextResult
- ✅ Proper exception handling with try/except
- ✅ Detailed error messages with context
- ✅ Partial success handling for batch operations

### Documentation

- ✅ Comprehensive module docstring
- ✅ Class-level docstring with examples
- ✅ Method docstrings following Google style
- ✅ Type hints for all parameters and returns
- ✅ Usage examples in docstrings

### FLEXT Compliance

- ✅ Inherits from FlextService[dict[str, object]]
- ✅ Implements execute() method for health checks
- ✅ Uses FlextResult for all operations
- ✅ Uses FlextLogger for structured logging
- ✅ Dependency injection via constructor

---

## Testing Requirements

### Unit Tests Required

Create `tests/unit/services/test_parser_service.py`:

1. **Test parse() method**:
   - Single file parsing
   - Content string parsing
   - Batch parsing with multiple files
   - Pagination with generator pattern
   - File not found error handling
   - Invalid batch input error handling

2. **Test parse_schema_ldif()**:
   - Schema file parsing
   - Modify operations extraction
   - AttributeTypes extraction
   - ObjectClasses extraction
   - File not found error handling

3. **Test parse_with_auto_detection()**:
   - Auto-detection success
   - Auto-detection failure handling
   - File path vs content string handling

4. **Test parse_relaxed()**:
   - Relaxed mode parsing
   - Broken LDIF handling
   - Config override verification

5. **Test detect_server_type()**:
   - File-based detection
   - Content-based detection
   - Confidence score validation

6. **Test get_effective_server_type()**:
   - Relaxed mode priority
   - Manual mode handling
   - Auto-detection mode
   - RFC-only mode

7. **Test execute() health check**:
   - Service status verification
   - Client health check delegation

### Integration Tests Required

Add to existing integration tests:

1. **End-to-end parsing workflows**:
   - Real LDIF file parsing through parser service
   - Schema parsing with real schema files
   - Auto-detection with real server LDIF files

2. **Client integration**:
   - Verify parser service correctly delegates to client
   - Verify configuration propagation
   - Verify error handling chain

---

## Benefits

### Code Quality

- **Reduced Complexity**: api.py reduced by ~415 lines
- **Single Responsibility**: Parser service focuses only on parsing
- **Improved Testability**: Parser logic isolated and independently testable
- **Better Maintainability**: Clear separation of concerns

### Architecture

- **FLEXT Compliance**: Service follows FLEXT architectural patterns
- **Dependency Injection**: Clean dependency management
- **Type Safety**: Full type annotations with Python 3.13+
- **Error Handling**: Consistent FlextResult pattern throughout

### Future Extensibility

- **Easy to extend**: New parsing methods can be added to parser service
- **Independent evolution**: Parser service can evolve independently
- **Service composition**: Other services can use parser service directly
- **Reusability**: Parser service can be used in other contexts

---

## Next Steps

1. **Integrate into api.py**: Update FlextLdif to use FlextLdifParser
2. **Remove duplicate code**: Delete original parse methods from api.py
3. **Update tests**: Create comprehensive test suite for parser service
4. **Verify integration**: Run existing tests to ensure no regressions
5. **Document changes**: Update API documentation to reflect service architecture

---

## Related Phases

- **Phase 2.2**: Extract Writer Service (write operations)
- **Phase 2.3**: Extract Validation Service (validate operations)
- **Phase 2.4**: Extract Analysis Service (analyze operations)
- **Phase 2.5**: Extract Migration Service (migrate operations)
- **Phase 2.6**: Extract Filter Service (filter operations)

---

## Success Criteria

- ✅ FlextLdifParser created with all parsing operations
- ✅ All methods follow FLEXT patterns (FlextService, FlextResult)
- ✅ Complete type annotations (Python 3.13+)
- ✅ Comprehensive documentation with examples
- ⏳ Integration with api.py (Next: User confirmation)
- ⏳ Unit tests created and passing
- ⏳ Integration tests verified
- ⏳ api.py reduced by ~415 lines

---

**Status**: Service extraction complete. Ready for integration approval.
