# Changelog

All notable changes to flext-ldif will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.9] - 2025-10-01

### 🚨 BREAKING CHANGES

#### CLI Removal - Library-Only Interface

- **REMOVED**: All CLI functionality and command-line interface
- **REMOVED**: `click` dependency from project
- **REMOVED**: CLI entry point (`flext-ldif` command)
- **IMPACT**: Users must now use the programmatic API (`FlextLdif`, `FlextLdifAPI`)
- **MIGRATION**: See `examples/01_basic_parsing.py` through `examples/06_custom_quirks.py` for library usage

#### MANDATORY quirk_registry Parameter

- **CHANGED**: All RFC parsers now REQUIRE `quirk_registry` parameter (not Optional)
- **IMPACT**: `RfcLdifParserService`, `RfcLdifWriterService`, and `RfcSchemaParserService` require `QuirkRegistryService` instance
- **MIGRATION**: Initialize `quirk_registry = QuirkRegistryService()` before creating parsers/writers
- **Example**:

  ```python
  from flext_ldif.quirks.registry import QuirkRegistryService
  from flext_ldif.rfc.rfc_schema_parser import RfcSchemaParserService

  # MANDATORY: Create quirk registry first
  quirk_registry = QuirkRegistryService()

  # Pass to ALL RFC parsers/writers
  parser = RfcSchemaParserService(
      params={"content": schema_content},
      quirk_registry=quirk_registry,  # ⚠️ MANDATORY parameter
      server_type="oid",
  )
  ```

### ✨ Added

#### RFC-First Architecture

- **NEW**: Zero bypass paths - ALL LDIF operations through RFC parsers + quirks
- **NEW**: Generic transformation pipeline: `Source → RFC → Target`
- **NEW**: Works with ANY LDAP server combination (not N² implementations)
- **NEW**: Priority-based quirks system (10=high, 15=medium, 20=low)
- **NEW**: Nested quirks pattern (SchemaQuirk contains AclQuirk and EntryQuirk)

#### Complete Server Implementations (4 servers)

- **OpenLDAP 1.x** (`openldap1_quirks.py`) - Priority 20
- **OpenLDAP 2.x** (`openldap_quirks.py`) - Priority 10
- **Oracle Internet Directory (OID)** (`oid_quirks.py`) - Priority 10
- **Oracle Unified Directory (OUD)** (`oud_quirks.py`) - Priority 10

#### Stub Implementations (5 servers)

- **Active Directory** (`ad_quirks.py`) - Stub with protocol compliance
- **Apache Directory Server** (`apache_quirks.py`) - Stub
- **389 Directory Server** (`ds389_quirks.py`) - Stub
- **Novell eDirectory** (`novell_quirks.py`) - Stub
- **IBM Tivoli Directory Server** (`tivoli_quirks.py`) - Stub

#### Comprehensive Documentation

- **NEW**: `docs/architecture.md` - RFC-first architecture with diagrams
- **NEW**: `docs/api-reference.md` - Complete library-only API reference
- **NEW**: `docs/COMPLETION_SUMMARY.md` - Project completion assessment
- **NEW**: `docs/RFC_FIRST_REFACTORING_PLAN.md` - 13-point refactoring plan

#### Practical Examples (6 examples)

- **NEW**: `examples/01_basic_parsing.py` - Basic LDIF parsing with FlextResult
- **NEW**: `examples/02_server_specific_quirks.py` - RFC-first with quirks (OID/OUD/OpenLDAP)
- **NEW**: `examples/03_writing_ldif.py` - Creating and writing LDIF programmatically
- **NEW**: `examples/04_validation.py` - Entry validation and railway-oriented pipelines
- **NEW**: `examples/05_migration.py` - Generic transformation (Source → RFC → Target)
- **NEW**: `examples/06_custom_quirks.py` - Creating custom server quirks

#### Migration Pipeline

- **NEW**: `FlextLdifMigrationPipeline` - Automated server-to-server migration
- **NEW**: Generic transformation supporting ANY LDAP server combination
- **NEW**: Directory-based batch processing

### 🐛 Fixed

- **FIX**: Empty string handling in handlers.py (lines 208-210)
- **FIX**: Proper None checks in test assertions
- **FIX**: Lint compliance (noqa comments for stub implementations)
- **FIX**: Type safety in test_api.py (result.error None checks)

### 🔧 Changed

#### Architecture

- **CHANGED**: Enforced RFC-first architecture with ZERO bypass paths
- **CHANGED**: All operations MUST go through `handlers.py` → RFC parsers + quirks
- **CHANGED**: Removed all direct parser/writer usage outside handlers
- **CHANGED**: CQRS pattern in handlers (Command/Query Responsibility Segregation)

#### API Design

- **CHANGED**: Library-only interface (no CLI dependencies)
- **CHANGED**: FlextResult pattern for all operations (railway-oriented error handling)
- **CHANGED**: Simplified facade (`FlextLdif`, `FlextLdifAPI`) exposing all functionality

#### Dependencies

- **REMOVED**: `click >= 8.1.0`
- **MAINTAINED**: All other dependencies unchanged

### 📊 Quality Metrics

- **Tests**: 389/389 passing (100%)
- **Coverage**: 52% (target: 75% for v1.0.0)
- **Lint**: Zero violations in `src/` (Ruff)
- **Type Checking**: Pyrefly strict mode (7 warnings, non-blocking)
- **Architecture**: Zero bypass paths verified

### 🎯 Migration Guide

#### From CLI to API

**Before (v0.9.8 with CLI)**:

```bash
flext-ldif parse input.ldif --server-type oid
```

**After (v0.9.9 library-only)**:

```python
from pathlib import Path
from flext_ldif import FlextLdifAPI

api = FlextLdifAPI()
result = api.parse(Path("input.ldif"), server_type="oid")

if result.is_success:
    entries = result.unwrap()
    print(f"Parsed {len(entries)} entries")
else:
    print(f"Error: {result.error}")
```

#### Adding quirk_registry Parameter

**Before (v0.9.8 - Optional parameter)**:

```python
parser = RfcSchemaParserService(
    params={"content": schema_content},
    server_type="oid",
)
```

**After (v0.9.9 - MANDATORY parameter)**:

```python
from flext_ldif.quirks.registry import QuirkRegistryService

quirk_registry = QuirkRegistryService()  # ⚠️ MANDATORY initialization

parser = RfcSchemaParserService(
    params={"content": schema_content},
    quirk_registry=quirk_registry,  # ⚠️ MANDATORY parameter
    server_type="oid",
)
```

### 📚 Resources

- **Examples**: `examples/` directory with 6 comprehensive examples
- **Architecture**: `docs/architecture.md` for RFC-first design
- **API Reference**: `docs/api-reference.md` for complete API documentation
- **Migration Guide**: This CHANGELOG for upgrade instructions

### 🚀 Next Steps for v1.0.0

1. **Test Coverage**: Improve from 52% to 75% minimum
   - Add ~100 tests for high-impact modules
   - Focus on RFC parsers, migration pipeline, quirks priority resolution

2. **Documentation**: Expand examples and tutorials
   - Add more server-specific examples
   - Document quirks development guide
   - Add troubleshooting section

3. **Performance**: Optimize for large LDIF files
   - Implement streaming parser
   - Add memory usage monitoring
   - Establish performance baselines

### 🤝 Contributing

For contribution guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).

For development setup, see [README.md](README.md#development).

---

## [0.9.8] - Previous Release

See previous releases for changes before v0.9.9.
