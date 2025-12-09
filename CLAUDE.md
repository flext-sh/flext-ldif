# flext-ldif - FLEXT LDIF Processing

**Hierarchy**: PROJECT
**Parent**: [../CLAUDE.md](../CLAUDE.md) - Workspace standards
**Last Update**: 2025-12-08

---

## ⚠️ CRITICAL: Architecture Layering (Zero Tolerance)

### Module Import Hierarchy (MANDATORY)

**ABSOLUTELY FORBIDDEN IMPORT PATTERNS**:

```
NEVER IMPORT (regardless of method - direct, lazy, function-local, proxy):

Foundation Modules (_models/*.py, _utilities/*.py, models.py, protocols.py, utilities.py, typings.py, constants.py):
  ❌ NEVER import services/*.py
  ❌ NEVER import servers/*.py
  ❌ NEVER import api.py

Infrastructure Modules (servers/*.py):
  ❌ NEVER import services/*.py
  ❌ NEVER import api.py
```

**CORRECT ARCHITECTURE LAYERING**:

```
Tier 0 - Foundation (ZERO internal dependencies):
  ├── constants.py    # FlextLdifConstants
  ├── typings.py      # FlextLdifTypes
  └── protocols.py    # FlextLdifProtocols

Tier 1 - Domain Foundation:
  ├── _models/*.py    # Internal domain models
  ├── models.py       # FlextLdifModels facade → _models/*, constants, typings, protocols
  ├── _utilities/*.py # Internal utilities
  └── utilities.py    # FlextLdifUtilities facade → _utilities/*, models, constants

Tier 2 - Infrastructure:
  └── servers/*.py    # Server implementations → Tier 0, Tier 1 only
                      # NEVER import services/, api.py

Tier 3 - Application (Top Layer):
  ├── services/*.py   # Business logic → All lower tiers
  └── api.py          # FlextLdif facade → All lower tiers
```

**WHY THIS MATTERS**:
- Circular imports cause runtime failures
- Lazy imports are a band-aid, not a solution
- Proper layering ensures testability and maintainability
- Each tier only depends on lower tiers, NEVER on higher tiers

---

### Architecture Violation Quick Check

**Run before committing:**
```bash
# Quick check for this project
grep -rEn "(from flext_.*\.(services|api) import)" \
  src/*/models.py src/*/protocols.py src/*/utilities.py \
  src/*/constants.py src/*/typings.py src/*/servers/*.py 2>/dev/null

# Expected: ZERO results
# If violations found: Do NOT commit, fix architecture first
```

**See [Ecosystem Standards](../CLAUDE.md) for complete prohibited patterns and remediation examples.**

---

## Regra 0 — Alinhamento Cruzado
- Este arquivo espelha o `../CLAUDE.md` raiz. Qualquer mudança de regra deve ser registrada primeiro no `CLAUDE.md` raiz e propagada para este arquivo e para `flext-core/`, `flext-cli/`, `flext-ldap/` e `client-a-oud-mig/`.
- Todos os agentes aceitam mudanças cruzadas e resolvem conflitos no `CLAUDE.md` raiz antes de codar.

## Project Overview

**FLEXT-LDIF** provides RFC 2849/4512 compliant LDIF processing with server-specific quirks for FLEXT ecosystem projects working with LDAP directory data.

**Version**: 0.9.0  
**Status**: Production-ready  
**Python**: 3.13+ only

**Current Quality Metrics** (Target Post-Refactoring):
- ✅ Ruff: Zero violations (PLC0415 justified for circular imports)
- ✅ MyPy: Zero type errors (strict mode)
- ✅ PyRight: Zero type errors
- ✅ PyRefly: Zero Pydantic validation errors (strict mode)
- ✅ Tests: 100% passing (no skipped tests)
- ✅ Coverage: 100% (all testable code covered)
- ✅ Mock Tests: 0 remaining (all use REAL implementations)
- ✅ Test Structure: Unified Tests[FlextLdif]* classes with short name aliases

**Server Implementation Status**: See project documentation for server implementation details.
- ✅ **RFC Stub Servers** (Detection + RFC Baseline): Apache, 389DS, Novell, Tivoli, AD - **174 tests passing**
- ✅ **Real Implementations**: OpenLDAP 2.x (olc* format), OpenLDAP 1.x, OID, OUD
- ✅ **Tests**: All stub servers 100% passing. OpenLDAP fixture tests blocked by RFC refactoring (other agents)

---

## Regras Unificadas do Ecossistema FLEXT

### Zero Tolerância (Proibido Completamente)

1. **TYPE_CHECKING**: ❌ PROIBIDO - Mover código que causa dependência circular para módulo apropriado
2. **# type: ignore**: ❌ PROIBIDO COMPLETAMENTE - ZERO tolerância, sem exceções
3. **Metaclasses**: ❌ PROIBIDAS COMPLETAMENTE - Todas as metaclasses são proibidas (incluindo `__getattr__`)
4. **Root Aliases**: ❌ PROIBIDO COMPLETAMENTE - Sempre namespace completo (m.Ldif.Entry, não m.Entry)
5. **Atribuições Dinâmicas**: ❌ PROIBIDO COMPLETAMENTE - Remover todas, usar apenas namespace completo
6. **Functions em constants.py**: ❌ PROIBIDO - constants.py apenas constantes, sem funções/metaclasses/código
7. **cast()**: ❌ PROIBIDO - substituir todos por Models/Protocols/TypeGuards com tipagem correta
8. **Any**: ❌ PROIBIDO - substituir todos por tipos específicos (código, docstrings, comentários)
9. **Importação**: ❌ Sem root aliases, lazy imports ou fallbacks de ImportError; imports sempre no topo
10. **Testes**: ✅ Implementações reais (sem mocks/monkeypatch), fixtures/dados reais, expectativa de 100% de cobertura, sem perda de funcionalidade

### Exemplos de Correções

#### TYPE_CHECKING

```python
# ❌ PROIBIDO
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from typing import ClassVar as TypeClassVar
else:
    TypeClassVar = type

# ✅ CORRETO - Mover para módulo apropriado
# _utilities/type_helpers.py
from typing import ClassVar
TypeClassVar = ClassVar
```

#### # type: ignore

```python
# ❌ PROIBIDO
Field(default="lower")  # type: ignore[assignment]

# ✅ CORRETO - Usar model_config ou type hints adequados
from pydantic import ConfigDict
model_config = ConfigDict(...)
```

#### Metaclasses

```python
# ❌ PROIBIDO
class _FlextLdifConstantsMeta(type):
    def __getattr__(cls, name: str) -> object:
        if name == "LiteralTypes":
            return cls.Ldif.LiteralTypes
        ...

class FlextLdifConstants(metaclass=_FlextLdifConstantsMeta):
    ...

# ✅ CORRETO - Sempre usar namespace completo
c.Ldif.LiteralTypes  # Não c.LiteralTypes
```

#### Atribuições Dinâmicas

```python
# ❌ PROIBIDO
FlextLdifModels.Entry = FlextLdifModels.Ldif.Entry

# ✅ CORRETO - Sempre usar namespace completo
m.Ldif.Entry  # Não m.Entry
```

#### Functions em constants.py

```python
# ❌ PROIBIDO - constants.py
class FlextLdifConstants:
    @staticmethod
    def normalize_server_type(server_type: str) -> str:
        ...

# ✅ CORRETO - Mover para utilities.py ou _utilities/server.py
# utilities.py ou _utilities/server.py
def normalize_server_type(server_type: str) -> str:
    ...
```

#### cast()

```python
# ❌ PROIBIDO - Uso excessivo de cast()
value = cast(MyModel, data)

# ✅ CORRETO - Usar Models/Protocols/TypeGuards
if isinstance(data, MyModel):
    value = data
# ou
def is_my_model(obj: object) -> TypeGuard[MyModel]:
    return isinstance(obj, MyModel)
```

#### Any

```python
# ❌ PROIBIDO
def process(data: Any) -> Any:
    """Process any data."""

# ✅ CORRETO - Usar tipos específicos
from flext_core import FlextTypes
def process(data: FlextTypes.GeneralValueType) -> FlextTypes.GeneralValueType:
    """Process general value type data."""
```

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

## 📦 Import and Namespace Guidelines (Critical Architecture)

This section defines **mandatory patterns** for imports, namespaces, and module aggregation. These rules prevent circular imports and ensure maintainability.

### 1. Runtime Import Access (Short Aliases)

**MANDATORY**: Use short aliases at runtime for type annotations and class instantiation:

```python
# ✅ CORRECT - Runtime short aliases (src/ and tests/)
from flext_ldif.typings import t      # FlextLdifTypes
from flext_ldif.constants import c    # FlextLdifConstants
from flext_ldif.models import m       # FlextLdifModels
from flext_ldif.protocols import p    # FlextLdifProtocols
from flext_ldif.utilities import u    # FlextLdifUtilities

# flext_core aliases (also available)
from flext_core.result import r      # FlextResult
from flext_core.exceptions import e  # FlextExceptions
from flext_core.decorators import d  # FlextDecorators
from flext_core.mixins import mx     # FlextMixins

# Usage with full namespace (MANDATORY)
result: r[str] = r[str].ok("value")
config: t.Types.ConfigurationDict = {}
server: c.Ldif.ServerTypes = c.Ldif.ServerTypes.OID
entry: m.Ldif.Entry = m.Ldif.Entry(dn="cn=test")
service: p.Ldif.Service[str] = my_service

# ❌ FORBIDDEN - Root aliases
server: c.ServerTypes    # WRONG - must use c.Ldif.ServerTypes
entry: m.Entry           # WRONG - must use m.Ldif.Entry
```

### 2. Module Aggregation Rules (Facades)

**Facade modules** (models.py, utilities.py, protocols.py) aggregate internal submodules:

```python
# =========================================================
# models.py (Facade) - Aggregates _models/*.py
# =========================================================
from flext_ldif._models.entry import LdifEntry
from flext_ldif._models.config import ProcessConfig

class FlextLdifModels:
    """Facade aggregating all model classes."""

    class Ldif:
        Entry = LdifEntry

        class Config:
            ProcessConfig = ProcessConfig
            # ... other config models

# Short alias for runtime access
m = FlextLdifModels

# =========================================================
# IMPORT RULES FOR AGGREGATION
# =========================================================

# ✅ CORRECT - Internal modules (_models/) can import from:
#   - Other _models/* modules
#   - Tier 0 modules (constants, typings, protocols)
#   - NOT from services/, servers/, api.py

# ✅ CORRECT - Facade (models.py) imports from:
#   - All internal _models/* modules
#   - Tier 0 modules

# ❌ FORBIDDEN - Internal modules importing from higher tiers
# _models/base.py importing services/api.py = ARCHITECTURE VIOLATION
```

### 3. Circular Import Avoidance Strategies

**Strategy 1: Forward References with `from __future__ import annotations`**
```python
from __future__ import annotations
from typing import Self

class QuirkBase:
    def clone(self) -> Self:
        """Self reference works with forward annotations."""
        return type(self)()
```

**Strategy 2: Protocol-Based Decoupling**
```python
# protocols.py (Tier 0 - no internal imports except flext_core)
from flext_core.protocols import FlextProtocols

class FlextLdifProtocols(FlextProtocols):
    class Ldif:
        class Parser(Protocol):
            def parse(self, content: str) -> list[Entry]: ...

# services/parser.py (Tier 3 - can import protocols)
from flext_ldif.protocols import p

class ParserService:
    def process(self, parser: p.Ldif.Parser) -> r[list[Entry]]:
        """Use protocol types to avoid importing concrete classes."""
        pass
```

**Strategy 3: Dependency Injection**
```python
# Instead of importing services directly, inject them
from flext_core import FlextContainer

class MigrationHandler:
    def __init__(self, container: FlextContainer) -> None:
        self._container = container

    def process(self) -> None:
        # Get service at runtime instead of importing
        parser_result = self._container.get("ldif_parser")
        if parser_result.is_success:
            parser_result.value.parse(content)
```

### 4. When Modules Can Import Submodules Directly

**ALLOWED**: Internal modules importing from other internal modules at same tier:

```python
# =========================================================
# EXCEPTION: _utilities/builders.py importing from models
# =========================================================

# _utilities/builders.py
from flext_ldif.models import FlextLdifModels  # ✅ ALLOWED
m = FlextLdifModels

# WHY: _utilities (Tier 1) can import from models (Tier 1)
# Both are below services/ and api.py
# No circular dependency created

# =========================================================
# EXCEPTION: quirks/servers/*.py importing from quirks/base.py
# =========================================================

# quirks/servers/oid_quirks.py
from flext_ldif.quirks.base import QuirkBase  # ✅ ALLOWED

# WHY: Same tier, both quirks modules
```

**FORBIDDEN**: Higher tier importing lower tier that imports back:

```python
# ❌ FORBIDDEN PATTERN - Creates circular import
# api.py
from flext_ldif.services.parser import ParserService

# services/parser.py
from flext_ldif.api import FlextLdif  # CIRCULAR!

# ✅ CORRECT - Services use protocols, not concrete api.py
# services/parser.py
from flext_ldif.protocols import p
# No import of api.py
```

### 5. Test Import Patterns

```python
# tests/unit/test_my_module.py

# ✅ CORRECT - Import from package root
from flext_ldif import FlextLdif
from flext_ldif.models import m
from flext_ldif.constants import c

# ✅ CORRECT - Import test helpers
from tests import tm, tf  # TestsFlextLdifMatchers, TestsFlextLdifFixtures

# ✅ ALLOWED - Tests can import internal modules for testing
from flext_ldif._utilities.builders import ProcessConfigBuilder

# ✅ CORRECT - Use pytest fixtures
@pytest.fixture
def ldif_client() -> FlextLdif:
    return FlextLdif()

# ❌ FORBIDDEN - Don't use TYPE_CHECKING in tests
from typing import TYPE_CHECKING
if TYPE_CHECKING:  # FORBIDDEN even in tests
    from flext_ldif import FlextLdif
```

### 6. Complete Import Hierarchy Reference

```
Tier 0 - Foundation (ZERO internal imports except flext_core):
├── constants.py    → imports: FlextConstants from flext_core
├── typings.py      → imports: FlextTypes from flext_core
└── protocols.py    → imports: FlextProtocols from flext_core, constants, typings

Tier 1 - Domain Foundation:
├── _models/*.py    → imports: Tier 0, other _models/*
├── models.py       → imports: _models/*, Tier 0
├── _utilities/*.py → imports: _models/*, models, Tier 0
└── utilities.py    → imports: _utilities/*, models, Tier 0

Tier 2 - Infrastructure:
├── servers/*.py    → imports: Tier 0, Tier 1
├── quirks/*.py     → imports: Tier 0, Tier 1
└── rfc/*.py        → imports: Tier 0, Tier 1
                    → NEVER: services/, api.py

Tier 3 - Application:
├── services/*.py   → imports: ALL lower tiers
└── api.py          → imports: ALL lower tiers (Facade for external use)
```

### 7. Module-Specific Import Rules

| Source Module | Can Import From | Cannot Import From |
|---------------|-----------------|-------------------|
| constants.py | flext_core.constants | everything else |
| typings.py | flext_core.typings | everything else |
| protocols.py | flext_core.protocols, constants, typings | everything else |
| _models/*.py | Tier 0, other _models/* | _utilities/*, services/, servers/, api.py |
| models.py | _models/*, Tier 0 | services/, servers/, api.py |
| _utilities/*.py | _models/*, Tier 0, models | services/, servers/, api.py |
| utilities.py | _utilities/*, models, Tier 0 | services/, servers/, api.py |
| servers/*.py | Tier 0, Tier 1 | services/, api.py |
| quirks/*.py | Tier 0, Tier 1 | services/, api.py |
| rfc/*.py | Tier 0, Tier 1 | services/, api.py |
| services/*.py | ALL lower tiers | api.py |
| api.py | ALL lower tiers | NOTHING prohibited |

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

**`tm.ok_entry()`** - Assert FlextResult success and validate entry:
```python
entry = tm.ok_entry(result, has_dn="cn=test,dc=example", has_attrs=["cn", "sn"])
```

**`tm.ok_entries()`** - Assert FlextResult success and validate entries list:
```python
entries = tm.ok_entries(result, count=3, empty=False)
```

### Factory Methods

**`tf.create_entry()`** - Create test entry with flexible parameterization:
```python
entry = tf.create_entry("cn=test,dc=example", attrs={"cn": ["test"]})
entry = tf.create_entry("cn=user,dc=example", object_classes=["person", "inetOrgPerson"])
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
from flext_core import FlextModels

# Use unified Models namespace (ALWAYS use namespace completo)
entry = FlextModels.Ldif.Entry(
    dn="cn=test,dc=example,dc=com",
    attributes={"cn": ["test"], "objectClass": ["person"]}
)

# Or use short alias with namespace completo
from flext_core import m
entry = m.Ldif.Entry(...)  # ✅ CORRETO
# entry = m.Entry(...)  # ❌ PROIBIDO - root alias

# Access configuration
from flext_ldif import FlextLdifConfig
config = FlextLdifConfig()

# Access constants (ALWAYS use namespace completo)
from flext_core import c
server_types = c.Ldif.ServerTypes  # ✅ CORRETO
# server_types = c.ServerTypes  # ❌ PROIBIDO - root alias
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

**See Also**:
- [Workspace Standards](../CLAUDE.md)
- [flext-core Patterns](../flext-core/CLAUDE.md)
- [flext-ldap Patterns](../flext-ldap/CLAUDE.md)
