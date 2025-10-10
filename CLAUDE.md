# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

**LDIF Processing Library for FLEXT Ecosystem**
**Version**: 0.9.9 | **Updated**: 2025-10-10
**Status**: RFC-first LDIF processing with universal conversion matrix · Production-ready

---

## 📋 DOCUMENT STRUCTURE & REFERENCES

**Quick Links**:
- **[~/.claude/commands/flext.md](~/.claude/commands/flext.md)**: Optimization command for module refactoring (USE with `/flext` command)
- **[../CLAUDE.md](../CLAUDE.md)**: FLEXT ecosystem standards and domain library rules
- **[README.md](README.md)**: Project overview and usage documentation

**Document Purpose**:
- **This file (CLAUDE.md)**: Project-specific flext-ldif standards and LDIF processing patterns
- **flext.md command**: Practical refactoring workflows and MCP tool usage patterns
- **Workspace CLAUDE.md**: Domain library standards and ecosystem architectural principles

**DO NOT DUPLICATE**: This file focuses on flext-ldif specifics. The `/flext` command provides HOW-TO workflows. The workspace CLAUDE.md provides ecosystem-wide standards.

**Hierarchy**: This document provides project-specific standards based on workspace-level patterns defined in [../CLAUDE.md](../CLAUDE.md). For architectural principles, quality gates, and MCP server usage, reference the main workspace standards.

---

## 🔗 MCP SERVER INTEGRATION (MANDATORY)

As defined in [../CLAUDE.md](../CLAUDE.md), all FLEXT development MUST use:

| MCP Server              | Purpose                                                     | Status          |
| ----------------------- | ----------------------------------------------------------- | --------------- |
| **serena**              | Semantic code analysis, symbol manipulation, refactoring    | **MANDATORY**   |
| **sequential-thinking** | LDIF architecture and data processing problem decomposition | **RECOMMENDED** |
| **context7**            | Third-party library documentation (LDIF, Pydantic)          | **RECOMMENDED** |
| **github**              | Repository operations and LDIF ecosystem PRs                | **ACTIVE**      |

**Usage**: Reference [~/.claude/commands/flext.md](~/.claude/commands/flext.md) for MCP workflows. Use `/flext` command for module optimization.

---

## 🎯 FLEXT-LDIF PURPOSE

**ROLE**: flext-ldif provides RFC 2849/4512 compliant LDIF processing with server-specific quirks for FLEXT ecosystem projects working with LDAP directory data.

**CURRENT CAPABILITIES**:

- ✅ **RFC-First Design**: Full RFC 2849 (LDIF) and RFC 4512 (Schema) compliance
- ✅ **Quirks System**: Pluggable server-specific extensions for OID, OUD, OpenLDAP, Active Directory, and more
- ✅ **Universal Conversion Matrix**: N×N server conversions via RFC intermediate format (2×N implementations)
- ✅ **DN Case Registry**: Canonical DN case tracking for OUD compatibility during conversions
- ✅ **Generic Migration**: Server-agnostic transformation pipeline (Source → RFC → Target)
- ✅ **Enhanced Filters**: Advanced entry filtering, categorization, and transformation utilities
- ✅ **FLEXT Integration**: Uses flext-core 1.0.0 patterns (FlextResult, FlextDispatcher, FlextProcessors)
- ✅ **Type Safety**: Pydantic v2 models with Python 3.13+ type annotations
- ⚠️ **Memory Constraints**: Memory-bound processing for files under 100MB

**ECOSYSTEM USAGE**:

- **ALGAR OUD Migration**: Oracle Unified Directory migration from OID
- **Directory Data**: Processing LDAP data interchange files
- **Data Integration**: LDIF-based data operations within FLEXT pipelines

**QUALITY STANDARDS**:

- **Type Safety**: Pyrefly (MyPy successor) strict mode compliance
- **Test Coverage**: 65%+ minimum (990/990 tests passing)
- **FLEXT Integration**: Complete flext-core 1.0.0 integration
- **Code Quality**: Ruff linting and formatting (100% compliance)

---

## 🏗️ ARCHITECTURE

### RFC-First Design with Pluggable Quirks

**Design Philosophy**: Generic RFC foundation with extensible server-specific enhancements

FLEXT-LDIF is built on a **generic RFC-compliant foundation** with a powerful **quirks system** for server-specific extensions:

**Core Architecture**:

- **RFC 2849 (LDIF Format)** - Standard LDIF parsing and writing foundation
- **RFC 4512 (Schema)** - Standard LDAP schema parsing foundation
- **Quirks System** - Pluggable server-specific extensions that enhance RFC parsing
- **Generic Transformation** - Source → RFC → Target pipeline works with any server

**Design Principles**:

- RFC parsers provide the **baseline** for all LDAP servers
- Quirks **extend and enhance** RFC parsing for server-specific features
- No server-specific code in core parsers - all extensions via quirks
- **Works with any LDAP server** - known or unknown

### Module Organization

```
src/flext_ldif/
├── api.py                      # FlextLdif facade (main entry point)
├── client.py                   # LDIF file operations (read/write)
├── models.py                   # FlextLdifModels (Pydantic v2)
├── config.py                   # FlextLdifConfig
├── constants.py                # FlextLdifConstants
├── typings.py                  # Type definitions
├── protocols.py                # Protocol definitions
├── exceptions.py               # FlextLdifExceptions
├── containers.py               # Dependency injection
├── filters.py                  # Entry filtering and transformation
├── diff.py                     # LDIF diff operations
├── utilities.py                # Helper functions
├── migration_pipeline.py       # Server migration orchestration
├── mixins.py                   # Shared behaviors
│
├── rfc/                        # RFC 2849/4512 foundation
│   ├── rfc_ldif_parser.py     # Standard LDIF parsing
│   ├── rfc_ldif_writer.py     # Standard LDIF writing
│   └── rfc_schema_parser.py   # Standard schema parsing
│
├── quirks/                     # Server-specific extensions
│   ├── base.py                # QuirkBase abstract class
│   ├── registry.py            # QuirkRegistry for auto-discovery
│   ├── conversion_matrix.py   # Server-to-server mappings
│   ├── dn_case_registry.py    # DN case handling per server
│   ├── entry_quirks.py        # Entry-level quirks
│   ├── manager.py             # Quirk orchestration
│   └── servers/               # Per-server implementations
│       ├── oid_quirks.py      # Oracle Internet Directory
│       ├── oud_quirks.py      # Oracle Unified Directory
│       ├── openldap_quirks.py # OpenLDAP 2.x
│       ├── openldap1_quirks.py# OpenLDAP 1.x
│       ├── ad_quirks.py       # Active Directory
│       ├── ds389_quirks.py    # Red Hat Directory Server
│       ├── apache_quirks.py   # Apache Directory Server
│       ├── novell_quirks.py   # Novell eDirectory
│       └── tivoli_quirks.py   # IBM Tivoli Directory Server
│
├── schema/                     # Schema processing
│   ├── builder.py             # Schema construction
│   ├── extractor.py           # Schema extraction
│   ├── validator.py           # Schema validation
│   └── objectclass_manager.py # ObjectClass management
│
├── acl/                        # ACL processing
│   ├── parser.py              # ACL parsing
│   ├── service.py             # ACL service operations
│   └── utils.py               # ACL utilities
│
└── entry/                      # Entry processing
    └── builder.py             # Entry construction
```

### Quirks System Architecture

**How Quirks Work**:

1. **RFC Foundation**: All parsing starts with RFC-compliant parsers
2. **Quirk Discovery**: `FlextLdifQuirksRegistry` auto-discovers server-specific quirks
3. **Priority Resolution**: Quirks use priority system (lower number = higher priority)
4. **Nested Quirks**: Schema quirks contain nested ACL and Entry quirks
5. **Transformation Pipeline**: Source → RFC → Target via `QuirksConversionMatrix`

**Supported Servers**:

- **Fully Implemented**: OID, OUD, OpenLDAP 1.x/2.x
- **Stub Implementations**: Active Directory, Apache DS, 389 DS, Novell eDirectory, IBM Tivoli DS
- **Generic RFC**: Works with any LDAP server using RFC baseline

**Adding New Server Support**:

```python
from flext_ldif.quirks.base import QuirkBase

class MyServerQuirks(QuirkBase):
    """Quirks for MyServer LDAP."""

    def __init__(self) -> None:
        super().__init__(
            server_name="myserver",
            priority=50,  # Lower = higher priority
        )

    def normalize_dn(self, dn: str) -> str:
        """Normalize DN for MyServer."""
        return dn.lower()  # Example: MyServer uses lowercase DNs
```

### Migration Pipeline Architecture

The migration pipeline enables server-agnostic LDIF transformations:

```python
from flext_ldif import FlextLdifMigrationPipeline
from pathlib import Path

# Generic transformation works with ANY server combination
pipeline = FlextLdifMigrationPipeline(
    input_dir=Path("source"),
    output_dir=Path("target"),
    source_server_type="oid",    # Can be any registered server
    target_server_type="oud",    # Or "rfc" for pure RFC format
)

# Pipeline automatically:
# 1. Uses source quirks to normalize to RFC
# 2. Uses target quirks to transform from RFC
# 3. Handles DN case, ACLs, schema extensions
result = pipeline.execute()
```

**Key Components**:

- **FlextLdifClient**: LDIF read/write operations with encoding detection
- **QuirksConversionMatrix**: Universal N×N server conversion facade via RFC intermediate format
- **DnCaseRegistry**: Canonical DN case tracking for OUD compatibility during conversions
- **FlextLdifFilters**: Advanced entry filtering, categorization, and transformation utilities

### Universal Conversion Matrix Architecture

The `QuirksConversionMatrix` enables seamless conversion between any LDAP server quirks using RFC as intermediate format:

```python
from flext_ldif.quirks.conversion_matrix import QuirksConversionMatrix
from flext_ldif.quirks.servers.oud_quirks import FlextLdifQuirksServersOud
from flext_ldif.quirks.servers.oid_quirks import FlextLdifQuirksServersOid

# Create conversion matrix facade
matrix = QuirksConversionMatrix()

# Convert between any server combination via RFC intermediate
oud = FlextLdifQuirksServersOud()
oid = FlextLdifQuirksServersOid()

# OID attribute → OUD format
oid_attr = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' ... )"
result = matrix.convert(oud, oid, "attribute", oid_attr)
```

**Benefits**:
- **N×N Matrix**: Convert between any server pair with only 2×N implementations
- **RFC Intermediate**: Uses standards-compliant intermediate representation
- **DN Consistency**: Tracks canonical DN case for OUD compatibility
- **Type Safety**: Full type annotations with FlextResult error handling

### DN Case Registry Architecture

The `DnCaseRegistry` ensures DN case consistency during conversions, critical for OUD compatibility:

```python
from flext_ldif.quirks.dn_case_registry import DnCaseRegistry

registry = DnCaseRegistry()

# Register canonical DN case (first seen becomes canonical)
canonical = registry.register_dn("CN=Admin,DC=Example,DC=Com")
# Returns: "cn=admin,dc=example,dc=com"

# Get canonical case for any variant
canonical = registry.get_canonical_dn("cn=ADMIN,dc=example,dc=com")
# Returns: "cn=admin,dc=example,dc=com"

# Validate OUD consistency (no case conflicts)
result = registry.validate_oud_consistency()
```

**Key Features**:
- **Case Normalization**: Tracks all DN variants with canonical representation
- **OUD Compatibility**: Ensures consistent DN case for OUD targets
- **Conversion Pipeline**: Integrated into universal conversion matrix
- **Statistics Tracking**: Monitors DN variants and conflicts

---

## 🔧 DEVELOPMENT WORKFLOW

### Essential Commands

```bash
make setup          # Development environment setup
make lint           # Ruff linting (ZERO TOLERANCE)
make type-check     # Pyrefly type checking (ZERO TOLERANCE)
make security       # Bandit + pip-audit security scanning
make test           # Run test suite with 65% coverage minimum
make validate       # Complete validation pipeline (lint + type + security + test)
make build          # Build package
```

### Running Specific Tests

```bash
# Run specific test file
PYTHONPATH=src poetry run pytest tests/unit/test_oid_quirks.py -v

# Run tests matching a pattern
PYTHONPATH=src poetry run pytest -k "test_quirk" -v

# Run specific test markers
pytest -m unit                    # Unit tests only
pytest -m integration            # Integration tests
pytest -m ldif                   # LDIF-specific tests
pytest -m parser                 # Parser tests
pytest -m e2e                    # End-to-end tests

# Run with coverage for specific module
PYTHONPATH=src poetry run pytest --cov=flext_ldif.quirks --cov-report=term-missing

# Fast testing without coverage
PYTHONPATH=src poetry run pytest -v

# Run tests with maximum failures control
PYTHONPATH=src poetry run pytest --maxfail=1 -x

# Run with detailed output
PYTHONPATH=src poetry run pytest tests/unit/test_oid_quirks.py -xvs --tb=short

# Run integration tests (requires Docker)
PYTHONPATH=src poetry run pytest -m integration -v
```

### Quality Gates

- **Type Safety**: Pyrefly strict mode compliance for `src/` (successor to MyPy)
- **Code Quality**: Ruff linting and formatting (100% compliance)
- **Security**: Bandit + pip-audit scanning
- **Testing**: Unit and integration tests (65%+ coverage)
- **RFC Compliance**: Strict RFC 2849/4512 adherence (NO fallbacks)

---

## 🚨 CRITICAL PATTERNS

### MANDATORY: PYTHONPATH Requirements

**ALL test and script execution requires PYTHONPATH=src**:

```bash
# ✅ CORRECT
PYTHONPATH=src poetry run pytest tests/unit/test_oid_quirks.py -v
PYTHONPATH=src poetry run python -c "from flext_ldif import FlextLdif"

# ❌ WRONG - Will fail with import errors
poetry run pytest tests/unit/test_oid_quirks.py -v
python -c "from flext_ldif import FlextLdif"
```

### MANDATORY: QuirkRegistry Parameter

**ALL RFC parsers and writers REQUIRE `quirk_registry` parameter**:

```python
from flext_ldif.rfc.rfc_schema_parser import RfcSchemaParserService
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry

# ✅ CORRECT - Always initialize QuirkRegistry
quirk_registry = FlextLdifQuirksRegistry()

parser = RfcSchemaParserService(
    params={"file_path": "schema.ldif"},
    quirk_registry=quirk_registry,  # MANDATORY parameter
    server_type="oid",
)

# ❌ WRONG - Missing quirk_registry will fail
parser = RfcSchemaParserService(
    params={"file_path": "schema.ldif"},
    server_type="oid",
)
```

### FlextResult Pattern (Railway-Oriented Programming)

```python
from flext_ldif import FlextLdif
from pathlib import Path

ldif = FlextLdif()

# All operations return FlextResult for composable error handling
result = ldif.parse(Path("directory.ldif"))
if result.is_success:
    entries = result.unwrap()

    # Chain operations with FlextResult
    validation_result = ldif.validate_entries(entries)
    if validation_result.is_success:
        print("LDIF processing successful")
    else:
        print(f"Validation error: {validation_result.error}")
else:
    print(f"Parse error: {result.error}")
```

### Domain Model Usage

```python
from flext_ldif import FlextLdifModels

# Use unified Models namespace
entry = FlextLdifModels.Entry(
    dn="cn=test,dc=example,dc=com",
    attributes={"cn": ["test"], "objectClass": ["person"]}
)

# Access configuration
from flext_ldif import FlextLdifConfig
config = FlextLdifConfig()

# Access constants
from flext_ldif import FlextLdifConstants
server_types = FlextLdifConstants.SUPPORTED_SERVERS
```

---

## 📊 CURRENT STATUS (v0.9.9)

### What Works

- **RFC Compliance**: Full RFC 2849 (LDIF) and RFC 4512 (Schema) compliance
- **Universal Conversion Matrix**: N×N server conversions via RFC intermediate format
- **DN Case Registry**: Canonical DN case tracking for OUD compatibility
- **Enhanced Filters**: Advanced entry filtering and transformation utilities
- **Quirks System**: Extensible server-specific adaptations for 8+ LDAP servers
- **Generic Migration**: Server-agnostic transformation pipeline
- **Type Safety**: Python 3.13+ with Pyrefly strict mode (100% compliance)
- **Error Handling**: FlextResult patterns throughout (railway-oriented programming)
- **FLEXT Integration**: Complete flext-core 1.0.0 integration
- **Testing**: 1012/1012 tests passing (100% pass rate)

### Known Limitations

- **Memory Usage**: Loads entire LDIF files into memory during processing
- **Performance**: Single-threaded processing suitable for small to medium files
- **Scale**: Recommended for files under 100MB due to memory constraints
- **Features**: Production-ready core with room for streaming enhancements

---

## 🗺️ DEVELOPMENT PRIORITIES

### Phase 1: Production Hardening (Current)

- Maintain 100% test pass rate and type safety
- Enhance error messages for quirk-related failures
- Document server-specific quirk behaviors
- Expand integration test coverage

### Phase 2: Performance Optimization

- Implement memory usage monitoring and warnings
- Develop streaming parser for large files (>100MB)
- Add configurable chunk sizes for memory management
- Establish performance baselines and benchmarks

### Phase 3: Feature Enhancement

- Add more server-specific quirks (enhance stubs)
- Enhanced ACL transformation capabilities
- Better schema validation and conflict resolution
- Extended CLI tools for directory management

---

## 📚 PATTERNS AND BEST PRACTICES

### Generic Schema Parsing with Quirks

```python
from flext_ldif.rfc.rfc_schema_parser import RfcSchemaParserService
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from pathlib import Path

# MANDATORY: quirk_registry is REQUIRED for all RFC parsers/writers
quirk_registry = FlextLdifQuirksRegistry()

# Parse OID schema with quirks support
oid_parser = RfcSchemaParserService(
    params={
        "file_path": "oid_schema.ldif",
        "parse_attributes": True,
        "parse_objectclasses": True,
    },
    quirk_registry=quirk_registry,  # MANDATORY parameter
    server_type="oid",  # Use Oracle Internet Directory quirks
)

result = oid_parser.execute()
if result.is_success:
    schema_data = result.unwrap()
    print(f"Parsed {schema_data['stats']['total_attributes']} attributes")
    print(f"Parsed {schema_data['stats']['total_objectclasses']} objectClasses")

# Parse with RFC-only mode (quirks available but not used)
rfc_parser = RfcSchemaParserService(
    params={"file_path": "standard_schema.ldif"},
    quirk_registry=quirk_registry,  # Still MANDATORY
    server_type="rfc",  # Pure RFC mode - no server-specific quirks applied
)
```

### Generic Entry Migration with Quirks

```python
from flext_ldif import FlextLdifMigrationPipeline
from pathlib import Path

# Initialize migration pipeline
pipeline = FlextLdifMigrationPipeline(
    input_dir=Path("source_ldifs"),
    output_dir=Path("target_ldifs"),
    source_server_type="oid",    # Source: Oracle Internet Directory
    target_server_type="oud",    # Target: Oracle Unified Directory
)

# Generic transformation: OID → RFC → OUD
result = pipeline.execute()
if result.is_success:
    print("Migration completed successfully")
    print(f"Entries migrated: {result.value['entries_migrated']}")
    print(f"Schema transformed: {result.value['schema_files']}")

    # Pipeline automatically:
    # 1. Uses OID quirks to normalize entries to RFC format
    # 2. Uses OUD quirks to transform from RFC to OUD format
    # 3. Works with ANY server combination (even unknown servers)
```

### Unified Facade API Usage

```python
from flext_ldif import FlextLdif
from pathlib import Path

# Initialize FlextLdif facade (unified interface)
ldif = FlextLdif()

# Parse LDIF file or content string
result = ldif.parse(Path("directory.ldif"))  # Accepts Path, str (file path), or content
if result.is_success:
    entries = result.unwrap()
    print(f"Parsed {len(entries)} LDIF entries")

    # Validate entries
    validation_result = ldif.validate_entries(entries)

    # Write entries to file
    write_result = ldif.write(entries, Path("output.ldif"))

    # Migrate between servers
    migration_result = ldif.migrate(
        input_dir=Path("data/oid"),
        output_dir=Path("data/oud"),
        from_server="oid",
        to_server="oud"
    )
```

---

## 🤝 CONTRIBUTING

### FLEXT-Core Compliance

- [x] Operations return FlextResult[T] for error handling
- [x] CQRS pattern with FlextDispatcher and FlextRegistry
- [x] FlextProcessors for batch and parallel processing
- [x] FlextContainer for dependency injection
- [x] Type annotations with Python 3.13+ syntax
- [x] Pydantic v2 models for data validation

### Quality Standards

- **Code Quality**: Pyrefly strict mode + Ruff (100% compliance)
- **Test Coverage**: 65%+ minimum (990/990 tests passing)
- **Documentation**: Public APIs with Google-style docstrings
- **Architecture**: RFC-first with pluggable quirks system

---

**FLEXT-LDIF v0.9.9** - RFC-first LDIF processing library with server-specific quirks for LDAP data operations within the FLEXT ecosystem.

**Purpose**: Provide type-safe, RFC-compliant LDIF processing with extensible server adaptations for FLEXT projects requiring directory data handling.
