# FLEXT-LDIF Generic Library Implementation Plan

**Version**: 1.0.0
**Status**: Master Plan Document
**Created**: 2025-10-01
**Purpose**: Transform flext-ldif into a fully generic LDIF processing library

---

## 📋 Executive Summary

This document defines the comprehensive plan for transforming flext-ldif into a **fully generic LDIF processing library** usable with any LDAP server through an extensible quirks system. The library provides RFC-compliant baseline functionality with server-specific extensions via pluggable quirks.

### Core Principles

1. **RFC-First Design**: RFC 2849 (LDIF) and RFC 4512 (Schema) provide baseline compliance
2. **Quirks for Extensions**: Server-specific behavior isolated in quirks modules
3. **Generic Transformation**: Source → RFC → Target pipeline works with any server
4. **Library-First**: No CLI dependencies, API-only interface
5. **Type Safety**: Complete type annotations with FlextResult error handling
6. **Quality First**: 100% QA compliance (zero lint/type errors, 75%+ coverage)

---

## 🏗️ Architecture Overview

### RFC-First with Extensible Quirks

```
┌─────────────────────────────────────────────────────────────┐
│                      FlextLdif API                          │
│                   (Unified Facade)                          │
└────────────────────────┬────────────────────────────────────┘
                         │
         ┌───────────────┴───────────────┐
         │                               │
         ▼                               ▼
┌──────────────────┐           ┌──────────────────┐
│   RFC Parsers    │           │  Quirks System   │
│                  │           │                  │
│ • RFC 2849 LDIF  │◄─────────►│ • SchemaQuirk    │
│ • RFC 4512 Schema│           │ • AclQuirk       │
│                  │           │ • EntryQuirk     │
└──────────────────┘           └──────────────────┘
         │                               │
         └───────────────┬───────────────┘
                         │
                         ▼
            ┌─────────────────────────┐
            │   Generic Migration     │
            │  Source → RFC → Target  │
            └─────────────────────────┘
```

### Design Philosophy

**RFC Parsers Provide**:
- Baseline LDIF/Schema parsing for ALL LDAP servers
- RFC 2849 compliant LDIF processing (entries, attributes, change records)
- RFC 4512 compliant schema parsing (attributeTypes, objectClasses)
- Works with **any** LDAP server (known or unknown)

**Quirks System Provides**:
- Server-specific extensions (custom OIDs, syntaxes, formats)
- Priority-based resolution (lower number = higher priority)
- Tried **first**, RFC parsing used as **fallback**
- Easy addition of new server support

**Benefits**:
- No server-specific code in core parsers
- Works with unknown/new LDAP servers out of the box
- Easy to extend for new servers via quirks
- Clean separation of concerns

---

## 🎯 Server Support Matrix

### Complete Implementations

Full SchemaQuirk + AclQuirk + EntryQuirk implementations with comprehensive testing:

| Server            | Version      | Lines | Schema | ACL | Entry | Priority | Status      |
| ----------------- | ------------ | ----- | ------ | --- | ----- | -------- | ----------- |
| **OpenLDAP**      | 2.x (cn=config) | 537   | ✅      | ✅   | ✅     | 10       | **COMPLETE** |
| **OpenLDAP**      | 1.x (slapd.conf) | 530   | ✅      | ✅   | ✅     | 10       | **COMPLETE** |
| **Oracle OID**    | 11g+         | 347   | ✅      | ✅   | ✅     | 10       | **COMPLETE** |
| **Oracle OUD**    | 11g+         | 426   | ✅      | ✅   | ✅     | 10       | **COMPLETE** |

### Stub Implementations

Placeholder implementations with TODO comments and NotImplementedError:

| Server                  | Lines | Schema | ACL | Entry | Priority | Status       |
| ----------------------- | ----- | ------ | --- | ----- | -------- | ------------ |
| **Active Directory**    | 348   | 📝      | 📝   | 📝     | 15       | **STUB**     |
| **Apache DS**           | 174   | 📝      | 📝   | 📝     | 20       | **STUB**     |
| **389 Directory Server**| 153   | 📝      | 📝   | 📝     | 20       | **STUB**     |
| **Novell eDirectory**   | 161   | 📝      | 📝   | 📝     | 25       | **STUB**     |
| **IBM Tivoli DS**       | 153   | 📝      | 📝   | 📝     | 25       | **STUB**     |

**Stub Implementation Pattern**:
- Extends BaseSchemaQuirk/BaseAclQuirk/BaseEntryQuirk
- All abstract methods implemented with NotImplementedError
- Comprehensive docstrings explaining what needs implementation
- References to vendor documentation
- Ready for community contributions

---

## 🔧 Quirks System Design

### Base Quirk Classes

Located in `src/flext_ldif/quirks/base.py`:

#### BaseSchemaQuirk

Extends RFC 4512 schema parsing with server-specific features:

```python
class BaseSchemaQuirk(ABC, FlextModels.Value):
    """Base class for schema quirks."""

    server_type: str  # e.g., "oid", "oud", "openldap"
    priority: int     # Lower = higher priority

    # Abstract methods
    @abstractmethod
    def can_handle_attribute(self, attr_definition: str) -> bool: ...

    @abstractmethod
    def parse_attribute(self, attr_definition: str) -> FlextResult[dict]: ...

    @abstractmethod
    def can_handle_objectclass(self, oc_definition: str) -> bool: ...

    @abstractmethod
    def parse_objectclass(self, oc_definition: str) -> FlextResult[dict]: ...

    @abstractmethod
    def convert_attribute_to_rfc(self, attr_data: dict) -> FlextResult[dict]: ...

    @abstractmethod
    def convert_objectclass_to_rfc(self, oc_data: dict) -> FlextResult[dict]: ...
```

#### BaseAclQuirk

Extends ACL parsing with server-specific formats:

```python
class BaseAclQuirk(ABC, FlextModels.Value):
    """Base class for ACL quirks."""

    server_type: str
    priority: int

    @abstractmethod
    def can_handle_acl(self, acl_line: str) -> bool: ...

    @abstractmethod
    def parse_acl(self, acl_line: str) -> FlextResult[dict]: ...

    @abstractmethod
    def convert_acl_to_rfc(self, acl_data: dict) -> FlextResult[dict]: ...
```

#### BaseEntryQuirk

Handles server-specific entry attributes and transformations:

```python
class BaseEntryQuirk(ABC, FlextModels.Value):
    """Base class for entry quirks."""

    server_type: str
    priority: int

    @abstractmethod
    def can_handle_entry(self, entry_dn: str, attributes: dict) -> bool: ...

    @abstractmethod
    def process_entry(self, entry_dn: str, attributes: dict) -> FlextResult[dict]: ...

    @abstractmethod
    def convert_entry_to_rfc(self, entry_data: dict) -> FlextResult[dict]: ...
```

### Quirks Resolution Algorithm

```python
# Priority-based quirks resolution
def resolve_quirks(definition: str, quirks_list: list[Quirk]) -> FlextResult:
    # 1. Sort quirks by priority (lower = higher priority)
    sorted_quirks = sorted(quirks_list, key=lambda q: q.priority)

    # 2. Try each quirk in priority order
    for quirk in sorted_quirks:
        if quirk.can_handle(definition):
            result = quirk.parse(definition)
            if result.is_success:
                return result  # Quirk handled successfully

    # 3. Fall back to RFC parser
    return rfc_parser.parse(definition)
```

### Quirks Registry

Centralized registry managing all quirks:

```python
class QuirkRegistryService:
    """Central registry for all server quirks."""

    def get_schema_quirks(self, server_type: str) -> list[BaseSchemaQuirk]:
        """Get schema quirks for server type."""

    def get_acl_quirks(self, server_type: str) -> list[BaseAclQuirk]:
        """Get ACL quirks for server type."""

    def get_entry_quirks(self, server_type: str) -> list[BaseEntryQuirk]:
        """Get entry quirks for server type."""
```

---

## 🔄 Generic Transformation Pipeline

### Source → RFC → Target Pattern

The migration pipeline uses a three-stage transformation:

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│    Source    │───►│  RFC Format  │───►│    Target    │
│  (OID, AD,   │    │  (Generic)   │    │  (OUD, 389,  │
│   OpenLDAP)  │    │              │    │   OpenLDAP)  │
└──────────────┘    └──────────────┘    └──────────────┘
      │                    │                    │
      ▼                    ▼                    ▼
Source Quirk         RFC Parser          Target Quirk
(Normalize)      (Generic Format)      (Specialize)
```

### Pipeline Implementation

```python
def migrate_entries(entries, source_format, target_format):
    """Generic migration pipeline."""

    # Stage 1: Get source and target quirks
    source_quirks = registry.get_entry_quirks(source_format)
    target_quirks = registry.get_entry_quirks(target_format)

    transformed_entries = []

    for entry in entries:
        # Stage 2: Normalize to RFC using source quirks
        rfc_entry = entry  # Start with original
        for quirk in source_quirks:
            if quirk.can_handle_entry(entry.dn, entry.attributes):
                result = quirk.convert_entry_to_rfc(entry)
                if result.is_success:
                    rfc_entry = result.unwrap()
                    break

        # Stage 3: Transform to target using target quirks
        target_entry = rfc_entry  # Start with RFC format
        for quirk in target_quirks:
            if quirk.can_handle_entry(rfc_entry.dn, rfc_entry.attributes):
                result = quirk.process_entry(rfc_entry.dn, rfc_entry.attributes)
                if result.is_success:
                    target_entry = result.unwrap()
                    break

        transformed_entries.append(target_entry)

    return FlextResult.ok(transformed_entries)
```

**Key Features**:
- Works with **any** source/target combination
- RFC format is lingua franca
- No direct source→target conversions needed
- Easy to add new servers

---

## 📦 Library-First Design

### No CLI Dependencies

**Removed**:
- ❌ No CLI code in src/
- ❌ No CLI tests
- ❌ No CLI documentation
- ❌ No command-line entry points

**API-Only Interface**:
- ✅ FlextLdif facade class
- ✅ All operations via API methods
- ✅ Programmable interface for tools
- ✅ Easy integration into applications

### FlextLdif API

```python
from flext_ldif import FlextLdif
from pathlib import Path

# Initialize API
ldif = FlextLdif()

# Parse LDIF content
result = ldif.parse("dn: cn=test,dc=example,dc=com\ncn: test\n")
if result.is_success:
    entries = result.unwrap()

# Parse with server quirks
result = ldif.parse_with_quirks(
    content="...",
    server_type="oid"  # Use OID quirks
)

# Write LDIF
write_result = ldif.write(entries)

# Migrate between servers
migration_result = ldif.migrate(
    entries=entries,
    from_server="oid",
    to_server="oud"
)

# Access infrastructure
config = ldif.Config
models = ldif.Models
constants = ldif.Constants
```

---

## ✅ Quality Assurance Standards

### Zero Tolerance Policy

**Linting**:
```bash
make lint                    # Must pass with ZERO violations
ruff check src/ --fix        # Auto-fix where possible
```
- Zero F821 (undefined names)
- Zero E501 (line too long)
- Zero ARG (unused arguments)
- Zero violations in src/

**Type Checking**:
```bash
make type-check              # Must pass with ZERO errors
pyrefly check src/          # Zero type errors in src/
```
- Complete type annotations
- No `# type: ignore` without error codes
- No `Any` types (use proper annotations)

**Testing**:
```bash
make test                    # Must achieve 75%+ coverage
pytest --cov=src/flext_ldif --cov-report=term-missing --cov-fail-under=75
```
- 75% minimum coverage (proven achievable)
- Unit tests for all quirks
- Integration tests for pipelines
- RFC fallback behavior tested

**Complete Validation**:
```bash
make validate                # lint + type + security + test
```

### Quality Gates

Every phase must pass:
1. ✅ Ruff linting (zero violations)
2. ✅ Pyrefly type checking (zero errors)
3. ✅ Pytest with 75%+ coverage
4. ✅ Complete validation pipeline

---

## 📚 Documentation Standards

### Required Documentation

1. **README.md**:
   - Library overview and purpose
   - Generic architecture explanation
   - Server support matrix
   - API usage examples
   - Installation as library
   - No CLI references

2. **docs/architecture.md**:
   - RFC-first design principles
   - Quirks system architecture
   - Generic transformation pipeline
   - Service-oriented design

3. **docs/api-reference.md**:
   - Complete FlextLdif API
   - Quirks system API
   - Models and types
   - No CLI references

4. **docs/quirks-system.md** (NEW):
   - Deep dive into quirks architecture
   - BaseQuirk class hierarchy
   - Priority resolution algorithm
   - Implementing custom quirks

5. **docs/server-support.md** (NEW):
   - Server support matrix
   - Complete vs stub implementations
   - Server-specific features
   - Migration combinations

6. **docs/extending-quirks.md** (NEW):
   - Guide for implementing new quirks
   - Testing quirks
   - Contributing to server support
   - Code examples

### Documentation Principles

- **Accuracy**: Document actual implementation, not aspirations
- **Clarity**: Clear distinction between complete vs stub implementations
- **Examples**: Working code examples for all features
- **No CLI**: Remove all command-line references
- **API-First**: Focus on programmatic usage

---

## 🚀 Implementation Phases

### Phase 1: Documentation Master Plan ✅

**Status**: COMPLETE
**Output**: This document

**Deliverables**:
- ✅ Architecture overview
- ✅ Server support matrix
- ✅ Quirks system design
- ✅ Quality standards
- ✅ Implementation timeline

### Phase 2: Quirks Validation & Enhancement

**Duration**: 2-3 hours

**Tasks**:
1. Audit complete implementations (OpenLDAP 1.x/2.x, OID, OUD)
2. Verify SchemaQuirk + AclQuirk + EntryQuirk completeness
3. Validate stub implementations (AD, Apache, 389DS, Novell, Tivoli)
4. Ensure consistent stub patterns
5. Add comprehensive docstrings
6. Reference vendor documentation

**Validation**:
- All complete servers have all three quirk types
- All stubs follow consistent pattern
- All abstract methods implemented

### Phase 3: CLI Elimination Verification

**Duration**: 30 minutes

**Tasks**:
1. Verify no CLI code in src/
2. Verify no CLI tests
3. Remove CLI references from documentation
4. Ensure API-only interface in pyproject.toml

**Validation**:
- No CLI entry points
- Documentation has no CLI references
- FlextLdif API is only interface

### Phase 4: Quality Assurance

**Duration**: 2-3 hours

**Tasks**:
1. Fix all ruff violations (make lint)
2. Fix all type errors (make type-check)
3. Achieve 75%+ test coverage (make test)
4. Pass complete validation (make validate)

**Validation**:
- ✅ Zero lint violations
- ✅ Zero type errors
- ✅ 75%+ coverage
- ✅ Complete validation passes

### Phase 5: Documentation Overhaul

**Duration**: 2-3 hours

**Tasks**:
1. Update README.md (remove CLI, add generic patterns)
2. Update docs/architecture.md (RFC-first quirks)
3. Update docs/api-reference.md (API-only)
4. Update docs/getting-started.md (library usage)
5. Create docs/quirks-system.md (deep dive)
6. Create docs/server-support.md (matrix)
7. Create docs/extending-quirks.md (guide)

**Validation**:
- All docs reflect actual implementation
- No CLI references
- Complete API documentation
- Working code examples

### Phase 6: Final Validation

**Duration**: 1 hour

**Tasks**:
1. Run complete QA validation
2. Update serena memory
3. Verify all documentation
4. Confirm 100% compliance

**Validation**:
- ✅ All quality gates pass
- ✅ Documentation accurate
- ✅ Memory updated

---

## 📊 Timeline & Milestones

| Phase                     | Duration | Milestone                        |
| ------------------------- | -------- | -------------------------------- |
| Phase 1: Master Plan      | 0.5h     | ✅ Documentation created          |
| Phase 2: Quirks Validation| 2-3h     | All quirks validated/enhanced    |
| Phase 3: CLI Elimination  | 0.5h     | Zero CLI dependencies            |
| Phase 4: QA Compliance    | 2-3h     | 100% quality standards met       |
| Phase 5: Documentation    | 2-3h     | Complete docs overhaul           |
| Phase 6: Final Validation | 1h       | All gates pass, memory updated   |
| **TOTAL**                 | **8-11h**| **Generic library complete**     |

---

## 🎯 Success Criteria

### Technical

- ✅ Generic RFC-compliant architecture
- ✅ Extensible quirks system
- ✅ Complete implementations: OpenLDAP 1.x/2.x, OID, OUD
- ✅ Stub implementations: AD, Apache, 389DS, Novell, Tivoli
- ✅ Generic transformation pipeline (Source → RFC → Target)
- ✅ Zero CLI dependencies
- ✅ API-only interface (FlextLdif facade)

### Quality

- ✅ Zero ruff violations in src/
- ✅ Zero type errors in src/
- ✅ 75%+ test coverage
- ✅ Complete validation pipeline passes
- ✅ All quality gates pass

### Documentation

- ✅ README.md reflects library-first design
- ✅ Architecture docs explain RFC-first quirks
- ✅ API reference complete and accurate
- ✅ No CLI references anywhere
- ✅ New docs created (quirks-system, server-support, extending-quirks)

### Project

- ✅ Serena memory updated
- ✅ All tasks completed
- ✅ Plan fully executed
- ✅ Ready for 1.0.0 release

---

## 📝 Notes

### Design Decisions

**Why RFC-First?**
- Works with ANY LDAP server out of the box
- Clean baseline without vendor pollution
- Easy to understand and maintain
- Follows standards-first principle

**Why Quirks System?**
- Clean separation of concerns
- Easy to add new servers
- Priority-based flexible resolution
- No core code changes needed

**Why No CLI?**
- Library-first design principle
- Better reusability in tools
- Simpler maintenance
- Focus on API quality

### Future Enhancements

**Potential Additions**:
- More server implementations (contribute stubs!)
- Performance optimizations
- Advanced transformation rules
- Schema validation enhancements
- ACL transformation library

**Community Contributions**:
- Stub implementations ready for community
- Clear extension guide
- Comprehensive testing patterns
- Well-documented APIs

---

**Document Version**: 1.0.0
**Status**: Master Plan - Reference for All Phases
**Next**: Execute Phase 2 (Quirks Validation)
