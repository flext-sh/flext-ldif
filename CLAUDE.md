# FLEXT-LDIF Project Guidelines

**Reference**: See [../CLAUDE.md](../CLAUDE.md) for FLEXT ecosystem standards and general rules.

---

## Project Overview

**FLEXT-LDIF** provides RFC 2849/4512 compliant LDIF processing with server-specific quirks for FLEXT ecosystem projects working with LDAP directory data.

**Version**: 0.9.0  
**Status**: Production-ready  
**Python**: 3.13+ only

**Current Quality Metrics**:
- ✅ Ruff: 0 critical violations
- ✅ Type Safety: 0 Pyrefly errors (strict mode)
- ✅ Tests: 1766/1766 passing (100% pass rate)
- ✅ Coverage: 78% (1861 uncovered lines)
- ✅ Mock Tests: 0 remaining (all use REAL implementations)

---

## Architecture

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
├── models.py                   # FlextLdifModels (Pydantic v2)
├── config.py                   # FlextLdifConfig
├── constants.py                # FlextLdifConstants
├── typings.py                  # Type definitions
├── protocols.py                # Protocol definitions
├── exceptions.py               # FlextLdifExceptions
├── filters.py                  # Entry filtering and transformation
├── diff.py                     # LDIF diff operations
├── utilities.py                # Helper functions
├── migration_pipeline.py       # Server migration orchestration
│
├── services/                   # Business logic services
│   └── server_detector.py     # Auto-detect LDAP server type from LDIF content
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
│   └── servers/               # Per-server implementations
│       ├── oid_quirks.py      # Oracle Internet Directory
│       ├── oud_quirks.py      # Oracle Unified Directory
│       ├── openldap_quirks.py # OpenLDAP 2.x
│       └── relaxed_quirks.py # Lenient parsing for broken/non-compliant LDIF
│
└── servers/                   # Server implementations (legacy structure)
    ├── base.py                # Base server class
    ├── oid.py                 # OID server
    └── oud.py                 # OUD server
```

### Quirks System Architecture

**How Quirks Work**:
1. **RFC Foundation**: All parsing starts with RFC-compliant parsers
2. **Quirk Discovery**: `FlextLdifQuirksRegistry` auto-discovers server-specific quirks
3. **Priority Resolution**: Quirks use priority system (lower number = higher priority)
4. **Nested Quirks**: Schema quirks contain nested ACL and Entry quirks
5. **Transformation Pipeline**: Source → RFC → Target via `QuirksConversionMatrix`

**Supported Servers**:
- **Fully Implemented**: OID, OUD, OpenLDAP 1.x/2.x, Relaxed Mode
- **Stub Implementations**: Active Directory, Apache DS, 389 DS, Novell eDirectory, IBM Tivoli DS
- **Generic RFC**: Works with any LDAP server using RFC baseline
- **Auto-Detected**: Automatic server detection from LDIF content with 8+ server patterns supported

### Auto-Detection Architecture

**Purpose**: Automatically detect LDAP server type from LDIF content using pattern matching and confidence scoring.

**How Auto-Detection Works**:
1. **Pattern Matching**: Scans LDIF content for server-specific OIDs, attributes, and patterns
2. **Weighted Scoring**: Each server type receives points based on pattern matches
3. **Confidence Calculation**: Determines confidence score (0.0-1.0) based on match strength
4. **Fallback Strategy**: Returns RFC if confidence is below threshold (0.6)

### Configuration Modes

**Quirks Detection Modes**: Control how server-specific quirks are selected during LDIF processing.

**Three Detection Modes**:
- **auto** (default): Automatic detection from LDIF content
- **manual**: Uses specified `quirks_server_type` from config, skips auto-detection
- **disabled**: Uses only RFC 2849/4512, no server-specific quirks

---

## Essential Commands

```bash
# Setup and validation
make setup          # Development environment setup
make validate       # Complete validation (lint + type + security + test)
make lint           # Ruff linting (ZERO TOLERANCE)
make type-check     # Pyrefly type checking (ZERO TOLERANCE)
make security       # Bandit + pip-audit security scanning
make test           # Run test suite with 65% coverage minimum
make format         # Auto-format code with Ruff

# Testing
PYTHONPATH=src poetry run pytest tests/unit/test_oid_quirks.py -v
PYTHONPATH=src poetry run pytest -k "test_quirk" -v
pytest -m unit                    # Unit tests only
pytest -m integration            # Integration tests
pytest -m ldif                   # LDIF-specific tests
```

---

## Key Patterns

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
```

### MANDATORY: Use FlextUtilities/FlextRuntime Instead of Custom Helpers

**ALWAYS use FlextUtilities/FlextRuntime from flext-core instead of custom helpers**:

```python
from flext_core import FlextRuntime, FlextUtilities

# Phone validation
if FlextRuntime.is_valid_phone(value):
    ...

# Email validation
result = FlextUtilities.Validation.validate_pattern(email, email_pattern)

# Type guards
if FlextRuntime.is_list_like(values):
    ...
```

---

## Known Limitations

- **Memory Usage**: Loads entire LDIF files into memory during processing
- **Performance**: Single-threaded processing suitable for small to medium files
- **Scale**: Recommended for files under 100MB due to memory constraints
- **Features**: Production-ready core with room for streaming enhancements

---

## Development Priorities

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

**Additional Resources**: [../CLAUDE.md](../CLAUDE.md) (workspace), [README.md](README.md) (overview), [HOOK_PATTERNS.md](HOOK_PATTERNS.md) (hook patterns)
