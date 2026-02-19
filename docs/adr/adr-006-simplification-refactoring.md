# ADR-006: Library Simplification and Deduplication


<!-- TOC START -->
- Context
  - **Structural Issues**
  - **Over-Engineering**
  - **flext-core Under-Utilization**
  - **Impact**
- Decision
  - **1. Flatten Module Structure**
  - **2. Delete Over-Engineered Processors**
  - **3. Remove Wrapper Methods**
  - **4. Remove Property Accessors**
  - **5. Leverage FlextDecorators**
  - **6. Refactor Services to FlextService**
  - **7. Simplify with Python 3.13+ Pattern Matching**
  - **8. Reorganize Tests**
- Consequences
  - **Positive**
  - **Negative**
  - **Mitigation**
- Implementation
  - **Phase 1: Documentation (4-5 hours)**
  - **Phase 2: Code Refactoring (6-7 hours)**
  - **Timeline**: 10-12 hours total
- Validation Criteria
- References
- Notes
<!-- TOC END -->

**Date**: 2025-01-24
**Status**: Approved
**Deciders**: FLEXT Core Team
**Related ADRs**: ADR-001 (RFC-First Design), ADR-005 (Pluggable Quirks System)

---

## Context

flext-ldif has evolved through multiple phases achieving production-ready status with 1766 passing tests, 78% coverage, and 0 type errors. However, complexity has accumulated through:

### **Structural Issues**

1. **Subdirectory Overhead**: 11 subdirectories (`rfc/`, `services/`, `acl/`, `schema/`, `entry/`, `pipelines/`, `processors/`, `events/`) creating navigation friction
2. **Deep Import Paths**: 4-5 level imports (`from flext_ldif.rfc.rfc_ldif_parser import ...`)
3. **Test Misalignment**: Test subdirectories mirror old structure, creating maintenance burden

### **Over-Engineering**

1. **Custom Processors**: `processors/ldif_processor.py` (160 lines) wraps `FlextProcessors` from flext-core unnecessarily
2. **Wrapper Methods**: 600+ lines in `api.py` delegating to model methods (`get_entry_dn`, `get_entry_attributes`, `create_entry`)
3. **Property Accessors**: 100+ lines exposing imports via properties (`ldif.models`, `ldif.config`, `ldif.processors`)

### **flext-core Under-Utilization**

1. **FlextProcessors**: Not used directly - wrapped unnecessarily
2. **FlextDecorators**: Not applied (`@log_operation`, `@track_performance`, `@retry`)
3. **FlextService**: Services don't extend base class (missing automatic logging, context management)

### **Impact**

- **Cognitive Load**: Developers spend time navigating directories
- **Duplication**: Custom code reimplements flext-core functionality
- **Maintenance**: More code to maintain, test, and document
- **Integration**: Indirect flext-core usage loses benefits

---

## Decision

We will simplify flext-ldif through structural and architectural changes while **maintaining public API stability**.

### **1. Flatten Module Structure**

**Action**: Move all modules to `src/flext_ldif/` root except `quirks/`

**Rationale**:

- **Simpler Navigation**: Direct file access without directory drilling
- **Faster Imports**: Fewer nesting levels
- **Industry Standard**: Libraries like `requests`, `httpx`, `pydantic` use flat structure
- **Clear Dependencies**: Module relationships more visible

**Exception**: Keep `quirks/` with `servers/` subdirectory due to:

- Domain complexity (10+ server implementations)
- Pluggable architecture (dynamic registration)
- Clear isolation (server-specific code)

**Before**:

```
src/flext_ldif/
├── rfc/
│   ├── rfc_ldif_parser.py
│   ├── rfc_ldif_writer.py
│   └── rfc_schema_parser.py
├── services/
│   ├── detector.py
│   └── validation_service.py
├── acl/
│   ├── parser.py
│   └── service.py
... (8 more subdirectories)
```

**After**:

```
src/flext_ldif/
├── rfc_ldif_parser.py
├── rfc_ldif_writer.py
├── rfc_schema_parser.py
├── detector.py
├── validation_service.py
├── acl_parser.py
├── acl_service.py
└── quirks/              # Only subdirectory
    ├── base.py
    ├── registry.py
    └── servers/
        ├── oid.py
        └── ouds.py
```

### **2. Delete Over-Engineered Processors**

**Action**: Remove `processors/` directory entirely (~200 lines)

**Rationale**:

- `FlextLdifBatchProcessor` and `FlextLdifParallelProcessor` only wrap `FlextProcessors()`
- No domain-specific logic - pure delegation
- Users should import `FlextProcessors` from flext-core directly

**Before**:

```python
from flext_ldif import FlextLdif
ldif = FlextLdif()
processor = ldif.processors  # Unnecessary wrapper
result = processor.batch_process(entries, func)
```

**After**:

```python
from flext_core import FlextProcessors
processor = FlextProcessors()  # Direct usage
result = processor.batch_process(entries, func)
```

### **3. Remove Wrapper Methods**

**Action**: Delete 600+ lines of delegation methods from `api.py`

**Methods to Remove**:

- `get_entry_dn()` → Use `entry.dn.value` directly
- `get_entry_attributes()` → Use `entry.attributes.to_ldap3()` directly
- `get_entry_objectclasses()` → Use `entry.get_attribute_values("objectClass")` directly
- `create_entry()` → Use `FlextLdifModels.Entry.create()` directly

**Rationale**:

- No added value - pure delegation
- Forces indirection (must have `FlextLdif` instance)
- Domain models already provide these operations

**Before**:

```python
ldif = FlextLdif()
dn = ldif.get_entry_dn(entry)  # Wrapper
attrs = ldif.get_entry_attributes(entry)  # Wrapper
```

**After**:

```python
from flext_ldif import FlextLdifModels
dn = entry.dn.value  # Direct
attrs = entry.attributes.to_ldap3()  # Direct
```

### **4. Remove Property Accessors**

**Action**: Delete 100+ lines of property wrappers

**Properties to Remove**:

- `@property def models()` → Import `FlextLdifModels` directly
- `@property def config()` → Import `FlextLdifSettings` directly
- `@property def constants()` → Import `FlextLdifConstants` directly
- `@property def processors()` → Import `FlextProcessors` from flext-core

**Rationale**:

- Unnecessary indirection
- Python convention: direct imports over property access

### **5. Leverage FlextDecorators**

**Action**: Apply flext-core decorators to key operations

**Decorators to Apply**:

- `@FlextDecorators.log_operation()` - Automatic operation logging
- `@FlextDecorators.track_performance()` - Performance metrics
- `@FlextDecorators.retry()` - Automatic retry logic
- `@FlextDecorators.railway()` - Railway error handling

**Example**:

```python
from flext_core import FlextDecorators

class RfcLdifParser:
    @FlextDecorators.log_operation(level="info")
    @FlextDecorators.track_performance()
    def parse(self, file_path: Path) -> FlextResult[list[Entry]]:
        """Parse LDIF with automatic logging and metrics."""
        # Implementation
```

**Benefits**:

- Automatic operation logging
- Performance tracking built-in
- Retry logic for file operations
- Consistent cross-cutting concerns

### **6. Refactor Services to FlextService**

**Action**: Services extend `FlextService` base class

**Services to Update**:

- `FlextLdifDetector`
- `FlextLdifValidation`
- `FlextLdifStatistics`
- `FlextLdifDn`
- `FlextLdifFileWriter`

**Before**:

```python
class FlextLdifDetector:
    def __init__(self):
        self._patterns = {...}
```

**After**:

```python
from flext_core import FlextService, FlextResult

class FlextLdifDetector(Flext):
    """Server detection service with automatic logging."""

    def execute(self, content: str) -> FlextResult[dict]:
        self.logger.info("Detecting server type", extra={"size": len(content)})
        # self.logger available automatically from FlextService
```

**Benefits**:

- Automatic logger injection
- Context management
- Operation tracking
- Consistent service interface

### **7. Simplify with Python 3.13+ Pattern Matching**

**Action**: Replace if/else chains with pattern matching

**Before** (170 lines with nested if/else):

```python
def parse(self, source, server_type="rfc", *, batch=False, paginate=False, page_size=1000):
    if batch:
        if not isinstance(source, list): ...
        # 50 lines
    if paginate:
        if isinstance(source, list): ...
        # 35 lines
    # 40 lines single source
```

**After** (80 lines with pattern matching):

```python
from typing import Literal

def parse(
    self,
    source: str | Path | list[str | Path],
    *,
    mode: Literal["single", "batch", "paginate"] = "single",
    server_type: str = "rfc",
    page_size: int = 1000,
) -> FlextResult[list[Entry] | Callable]:
    """Parse LDIF with pattern matching mode dispatch."""
    match mode:
        case "batch": return self._client.parse_batch(source, server_type)
        case "paginate": return self._client.parse_paginated(source, server_type, page_size)
        case "single": return self._client.parse_ldif(source, server_type)
        case _: return FlextResult.fail(f"Invalid mode: {mode}")
```

**Benefits**:

- Clearer intent
- Type safety with `Literal`
- Reduced line count
- Easier to test

### **8. Reorganize Tests**

**Action**: Flatten test structure to mirror module structure

**Before**:

```
tests/unit/
├── rfc/
├── services/
├── acl/
├── schema/
├── entry/
└── ...
```

**After**:

```
tests/unit/
├── quirks/              # Only subdirectory (mirrors src)
├── test_rfc_ldif_parser.py
├── test_detector.py
├── test_acl_parser.py
└── ...
```

**Rationale**:

- Test structure matches module structure
- Easier to find tests for modules
- Consistent with flat module organization

---

## Consequences

### **Positive**

1. **Code Reduction**: 1500-2000 lines removed
   - Processors: ~200 lines
   - Wrapper methods: ~600 lines
   - Property accessors: ~100 lines
   - Unified method simplification: ~600 lines

2. **Simpler Navigation**
   - Flat structure eliminates directory drilling
   - Direct module access
   - Clear module relationships

3. **Better flext-core Integration**
   - Direct `FlextProcessors` usage
   - `FlextDecorators` applied
   - `FlextService` inheritance
   - Maximum code reuse

4. **Improved Observability**
   - Automatic operation logging
   - Performance tracking
   - Context propagation

5. **Type Safety**
   - Pattern matching with `Literal` types
   - Clearer type signatures
   - Better IDE support

### **Negative**

1. **Import Path Changes** (Internal Breaking Change)
   - All internal imports must be updated
   - External users importing internal modules affected
   - Migration script provided

2. **Learning Curve**
   - Developers must learn new structure
   - Different from previous organization
   - Migration guide required

3. **One-Time Migration Cost**
   - ~11 hours estimated effort
   - Documentation updates
   - Test reorganization

### **Mitigation**

1. **Public API Stability**
   - `from flext_ldif import FlextLdif` unchanged
   - Main API methods unchanged
   - No breaking changes for typical users

2. **Automated Migration**
   - Scripts for import updates
   - Clear migration guide
   - Before/after examples

3. **Documentation**
   - ADR documenting decision
   - Migration guide for users
   - Updated architecture docs
   - Professional README.md

---

## Implementation

### **Phase 1: Documentation (4-5 hours)**

1. Create this ADR
2. Create migration guide (`docs/migration/v0.9-to-v1.0-migration.md`)
3. Update README.md (professional public-facing)
4. Update architecture.md
5. Update api-reference.md
6. Update getting-started.md

### **Phase 2: Code Refactoring (6-7 hours)**

1. Delete `processors/` directory
2. Flatten module structure
3. Reorganize tests
4. Apply `FlextDecorators`
5. Refactor services to `FlextService`
6. Remove wrapper methods
7. Simplify with pattern matching
8. Final validation

### **Timeline**: 10-12 hours total

---

## Validation Criteria

- ✅ Complete documentation before code changes
- ✅ Public API unchanged (`from flext_ldif import FlextLdif`)
- ✅ 0 Pyrefly errors maintained
- ✅ 0 Ruff violations maintained
- ✅ 1766/1766 tests passing
- ✅ 78%+ coverage maintained
- ✅ Professional README.md
- ✅ Migration guide for users

---

## References

- **ADR-001**: RFC-First Design - Foundation pattern maintained
- **ADR-005**: Pluggable Quirks System - Structure preserved
- **flext-core Documentation**: <https://github.com/flext-sh/flext-core>
- **Python 3.13+ Pattern Matching**: PEP 636
- **Flat Module Structure Examples**: requests, httpx, pydantic

---

## Notes

This ADR represents a maturity milestone for flext-ldif. After achieving production-ready quality (0 type errors, 1766 tests), we can now focus on simplification and maintainability. The refactoring removes accidental complexity while preserving essential complexity (quirks system, RFC compliance).

The decision aligns with FLEXT principles:

- **SOLID**: Single Responsibility (focused modules)
- **DRY**: Don't Repeat Yourself (use flext-core directly)
- **KISS**: Keep It Simple (flat structure, pattern matching)
- **YAGNI**: You Aren't Gonna Need It (remove wrappers)
