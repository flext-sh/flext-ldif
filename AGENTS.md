# flext-ldif - FLEXT LDIF Processing

**Hierarchy**: PROJECT
**Parent**: [../AGENTS.md](../AGENTS.md) - Workspace standards
**Last Update**: 2025-12-09
**Architecture Refactoring**: Applied strict layering rules - removed prohibited imports, enforced namespace consistency

______________________________________________________________________

## Multi-Agent Coordination

See [../AGENTS.md §10 Multi-Agent Parallel Execution Law](../AGENTS.md#10-multi-agent-parallel-execution-law).

## Architecture Layering

See [../AGENTS.md §2 Architecture Law](../AGENTS.md#2-architecture-law). flext-ldif specific tier mapping is in the [Import Guidelines](#import-and-namespace-guidelines) section below.

______________________________________________________________________

## Regra 0 — Alinhamento Cruzado

- Este arquivo espelha o `../AGENTS.md` raiz. Qualquer mudança de regra deve ser registrada primeiro no `AGENTS.md` raiz e propagada para este arquivo e para `flext-core/`, `flext-cli/`, `flext-ldap/` e `algar-oud-mig/`.
- Todos os agentes aceitam mudanças cruzadas e resolvem conflitos no `AGENTS.md` raiz antes de codar.

## Project Overview

**FLEXT-LDIF** provides RFC 2849/4512 compliant LDIF processing with server-specific quirks for FLEXT ecosystem projects working with LDAP directory data.

**Version**: 0.9.0\
**Status**: Production-ready\
**Python**: 3.13+ only

**Current Quality Metrics** (Target Post-Refactoring):

- ✅ Ruff: Zero violations (PLC0415 justified for circular imports)
- ✅ MyPy: Zero type errors (strict mode)
- ✅ PyRight: Zero type errors
- ✅ PyRefly: Zero Pydantic validation errors (strict mode)
- ✅ Tests: 100% passing (no skipped tests)
- ✅ Coverage: 100% (all testable code covered)
- ✅ Mock Tests: 0 remaining (all use REAL implementations)
- ✅ Test Structure: Unified Tests[ldif]\* classes with short name aliases

**Server Implementation Status**: See project documentation for server implementation details.

- ✅ **RFC Stub Servers** (Detection + RFC Baseline): Apache, 389DS, Novell, Tivoli, AD - **174 tests passing**
- ✅ **Real Implementations**: OpenLDAP 2.x (olc\* format), OpenLDAP 1.x, OID, OUD
- ✅ **Tests**: All stub servers 100% passing. OpenLDAP fixture tests blocked by RFC refactoring (other agents)

______________________________________________________________________

## Regras do Ecossistema FLEXT

For full zero-tolerance rules, code examples, and anti-patterns, see [../AGENTS.md §3 Code Law](../AGENTS.md#3-code-law).

**flext-ldif specific rules:**

- **Root Aliases**: Always use full namespace: `m.Ldif.Entry`, not `m.Entry`
- **Namespace constants**: `c.Ldif.ServerTypes`, not `c.ServerTypes`
- **TYPE_CHECKING**: Allowed for non-Pydantic type-only imports to resolve circular deps

______________________________________________________________________

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
├── api.py                      # ldif facade (main entry point)
├── models.py                   # FlextLdifModels (Pydantic v2)
├── settings.py                   # FlextLdifSettings
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
1. **Quirk Discovery**: `FlextLdifServersRegistry` auto-discovers server-specific quirks
1. **Priority Resolution**: Quirks use priority system (lower number = higher priority)
1. **Nested Quirks**: Schema quirks contain nested ACL and Entry quirks
1. **Transformation Pipeline**: Source → RFC → Target via `QuirksConversionMatrix`

**Supported Servers**:

- **Fully Implemented**: OID, OUD, OpenLDAP 1.x/2.x, Relaxed Mode
- **Stub Implementations**: Active Directory, Apache DS, 389 DS, Novell eDirectory, IBM Tivoli DS
- **Generic RFC**: Works with any LDAP server using RFC baseline
- **Auto-Detected**: Automatic server detection from LDIF content with 8+ server patterns supported

### Auto-Detection Architecture

**Purpose**: Automatically detect LDAP server type from LDIF content using pattern matching and confidence scoring.

**How Auto-Detection Works**:

1. **Pattern Matching**: Scans LDIF content for server-specific OIDs, attributes, and patterns
1. **Weighted Scoring**: Each server type receives points based on pattern matches
1. **Confidence Calculation**: Determines confidence score (0.0-1.0) based on match strength
1. **Fallback Strategy**: Returns RFC if confidence is below threshold (0.6)

### Configuration Modes

**Quirks Detection Modes**: Control how server-specific quirks are selected during LDIF processing.

**Three Detection Modes**:

- **auto** (default): Automatic detection from LDIF content
- **manual**: Uses specified `quirks_server_type` from settings, skips auto-detection
- **disabled**: Uses only RFC 2849/4512, no server-specific quirks

______________________________________________________________________

## Import and Namespace Guidelines

For full import law, aliases, circular import strategies, and module aggregation rules, see [../AGENTS.md §2 Architecture Law](../AGENTS.md#2-architecture-law) and [§4 Import Law](../AGENTS.md#4-import-law).

### flext-ldif Tier Mapping

| Source Module     | Can Import From                          | Cannot Import From                          |
| ----------------- | ---------------------------------------- | ------------------------------------------- |
| constants.py      | flext_core.constants                     | everything else                             |
| typings.py        | flext_core.typings                       | everything else                             |
| protocols.py      | flext_core.protocols, constants, typings | everything else                             |
| \_models/\*.py    | Tier 0, other \_models/\*                | \_utilities/\*, services/, servers/, api.py |
| models.py         | \_models/\*, Tier 0                      | services/, servers/, api.py                 |
| \_utilities/\*.py | \_models/\*, Tier 0, models              | services/, servers/, api.py                 |
| utilities.py      | \_utilities/\*, models, Tier 0           | services/, servers/, api.py                 |
| servers/\*.py     | Tier 0, Tier 1                           | services/, api.py                           |
| quirks/\*.py      | Tier 0, Tier 1                           | services/, api.py                           |
| rfc/\*.py         | Tier 0, Tier 1                           | services/, api.py                           |
| services/\*.py    | ALL lower tiers                          | api.py                                      |
| api.py            | ALL lower tiers                          | NOTHING prohibited                          |

______________________________________________________________________

## Essential Commands

All commands run from `flext-ldif/` directory. RTK hook intercepts automatically — saves 60-90% tokens.

### Linters (direct via RTK — preferred, fast, token-efficient)

```bash
# Individual linters (RTK intercepts automatically)
ruff check src/                        # Ruff lint
ruff check src/ --fix                  # Ruff lint + auto-fix
pyright src/                           # Pyright strict
mypy src/                              # MyPy with pydantic plugin
pyrefly check src/ tests/             # Pyrefly type checking
pytest tests/                          # Full test suite
pytest tests/ -k test_quirk -x        # Filter + fail-fast
pytest tests/ -vv -s                   # Verbose output

# Single file / targeted
ruff check src/flext_ldif/base.py
pyright src/flext_ldif/base.py
mypy src/flext_ldif/base.py
```

### Make targets (full gates with preflight + reports)

```bash
make check                             # ALL gates (ruff + format + pyrefly + mypy + pyright)
make check CHECK_GATES=lint            # Ruff via make (with flext_infra wrapper)
make check CHECK_GATES=pyrefly         # Pyrefly via make
make check CHECK_GATES=lint,mypy       # Combine gates
make check CHANGED_ONLY=1             # Git-changed files only
make fmt                               # Auto-format (ruff format + markdownlint)
make test                              # Pytest with coverage + reports
make scan                              # Bandit + pip-audit
make val                               # Validate gates (complexity, docstring)
make help                              # Show all targets
```

### When to use which

| Scenario                        | Use                                    |
| ------------------------------- | -------------------------------------- |
| Quick lint check during dev     | `ruff check src/` (RTK)                |
| Type-check a single file        | `pyright src/flext_ldif/foo.py` (RTK)  |
| Run all 4 type checkers at once | `make check`                           |
| Pre-commit full validation      | `make check && make test`              |
| CI/CD pipeline                  | `make check && make test && make scan` |

## Test Helpers and Unified Methods

### Enhanced Test Infrastructure

All test files should import unified test infrastructure:

```python
from tests import t, c, p, m, u, s, tm, tv, tt, tf
```

**Available Test Helpers**:

- `tm`: `TestsFlextLdifMatchers` - Unified matchers with parameterized validation
- `tv`: `TestsFlextLdifValidators` - Enhanced validators
- `tt`: `TestsFlextLdifTypes` - Type helpers
- `tf`: `TestsFlextLdifFixtures` - Factory methods for test data

### Unified Entry Validation Methods

**`tm.entry()`** - Unified entry validation (ALL entry assertions in ONE method):

```python
# Validate DN and attributes
tm.entry(entry, dn="cn=test,dc=example", has_attr=["cn", "sn"])

# Validate attribute values
tm.entry(entry, attr_equals={"cn": "test"}, attr_contains={"mail": "@"})

# Validate counts and objectClasses
tm.entry(entry, attr_count_gte=3, oc_count=2, has_oc="person")

# Validate missing attributes
tm.entry(entry, not_has_attr=["userPassword", "pwdHistory"])
```

**`tm.entries()`** - Unified entries list validation:

```python
# Validate count and all entries
tm.entries(result, count=5, all_have_attr="cn")

# Validate specific entries by index
tm.entries(entries, at_index={0: {"dn": "cn=first"}, 1: {"has_attr": "mail"}})
```

**`tm.ok_entry()`** - Assert r success and validate entry:

```python
entry = tm.ok_entry(result, has_dn="cn=test,dc=example", has_attrs=["cn", "sn"])
```

**`tm.ok_entries()`** - Assert r success and validate entries list:

```python
entries = tm.ok_entries(result, count=3, empty=False)
```

### Factory Methods

**`tf.create_entry()`** - Create test entry with flexible parameterization:

```python
entry = tf.create_entry("cn=test,dc=example", attrs={"cn": ["test"]})
entry = tf.create_entry(
    "cn=user,dc=example", object_classes=["person", "inetOrgPerson"]
)
```

**`tf.create_entries()`** - Create multiple entries:

```python
entries = tf.create_entries([
    ("cn=user1,dc=example", {"cn": ["user1"]}),
    ("cn=user2,dc=example", {"cn": ["user2"]}),
])
```

### Benefits

- **Reduced Code**: Single method replaces multiple assertions
- **Better Parameterization**: All validations in one call
- **Type Safety**: Full type checking support
- **Consistency**: Unified patterns across all tests

______________________________________________________________________

## Key Patterns

### r Pattern (Railway-Oriented Programming)

```python
from flext_ldif import ldif
from pathlib import Path


# All operations return r for composable error handling
result = ldif.parse(Path("directory.ldif"))
if result.is_success:
    entries = result.unwrap()

    # Chain operations with r
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
from flext_core import FlextModels

# Use unified Models namespace (ALWAYS use namespace completo)
entry = FlextModels.Ldif.Entry(
    dn="cn=test,dc=example,dc=com",
    attributes={"cn": ["test"], "objectClass": ["person"]},
)

# Or use short alias with namespace completo
from flext_core import m

entry = m.Ldif.Entry(...)  # ✅ CORRETO
# entry = m.Entry(...)  # ❌ PROIBIDO - root alias

# Access configuration
from flext_ldif import FlextLdifSettings

settings = FlextLdifSettings()

# Access constants (ALWAYS use namespace completo)
from flext_core import c

server_types = c.Ldif.ServerTypes  # ✅ CORRETO
# server_types = c.ServerTypes  # ❌ PROIBIDO - root alias
```

### Generic Schema Parsing with Quirks

```python
from flext_ldif import RfcSchemaParserService
from flext_ldif import FlextLdifServersRegistry
from pathlib import Path

# MANDATORY: quirk_registry is REQUIRED for all RFC parsers/writers
quirk_registry = FlextLdifServersRegistry()

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
    source_server_type="oid",  # Source: Oracle Internet Directory
    target_server_type="oud",  # Target: Oracle Unified Directory
)

# Generic transformation: OID → RFC → OUD
result = pipeline.execute()
if result.is_success:
    print("Migration completed successfully")
```

### MANDATORY: Use FlextUtilities/u Instead of Custom Helpers

**ALWAYS use FlextUtilities/u from flext-core instead of custom helpers**:

```python
from flext_core import u, FlextUtilities

# Phone validation
if u.is_valid_phone(value):
    ...

# Email validation
result = FlextUtilities.Validation.validate_pattern(email, email_pattern)

# Type guards
if u.list_like(values):
    ...
```

______________________________________________________________________

## Known Limitations

- **Memory Usage**: Loads entire LDIF files into memory during processing
- **Performance**: Single-threaded processing suitable for small to medium files
- **Scale**: Recommended for files under 100MB due to memory constraints
- **Features**: Production-ready core with room for streaming enhancements

______________________________________________________________________

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

______________________________________________________________________

**See Also**:

- [Workspace Standards](../AGENTS.md)
- [flext-core Patterns](../flext-core/AGENTS.md)
- [flext-ldap Patterns](../flext-ldap/AGENTS.md)

## Session Completion

See [../CLAUDE.md § Landing the Plane](../CLAUDE.md#landing-the-plane-session-completion).
