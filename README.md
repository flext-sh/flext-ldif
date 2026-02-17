# flext-ldif

> **Enterprise-grade LDIF processing for the FLEXT platform**

[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-1.0.0-brightgreen.svg)](https://github.com/flext/flext-ldif)
[![Type Safety](https://img.shields.io/badge/type%20safety-100%25-brightgreen.svg)](https://github.com/microsoft/pyright)
[![Test Coverage](https://img.shields.io/badge/coverage-78%25-green.svg)](https://pytest.org)
[![Tests](https://img.shields.io/badge/tests-1766%20passing-brightgreen.svg)](https://pytest.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**LDIF (LDAP Data Interchange Format)** processing library providing RFC 2849/4512 compliant parsing, validation, and server-specific adaptations for enterprise directory migrations and data operations.

---

## 🚀 Quick Start

### Installation

```bash
pip install flext-ldif
```

### Basic Usage

```python
from flext_ldif import FlextLdif
from pathlib import Path

# Initialize
ldif = FlextLdif()

# Parse LDIF file
result = ldif.parse(Path("directory.ldif"))

if result.is_success:
    entries = result.unwrap()
    print(f"✅ Parsed {len(entries)} entries")

    # Access entry data
    for entry in entries[:3]:
        print(f"DN: {entry.dn.value}")
        print(f"ObjectClasses: {entry.get_attribute_values('objectClass')}")
else:
    print(f"❌ Error: {result.error}")
```

---

## ✨ Key Features

### RFC Compliant & Production Ready

- **RFC 2849 (LDIF Format)** - Full LDIF specification support
- **RFC 4512 (Schema)** - LDAP schema parsing and validation
- **Type Safe** - Python 3.13+ with 100% type safety (Pyrefly strict mode)
- **Zero Errors** - 0 type errors, 0 linting violations
- **Well Tested** - 1766 passing tests with 78% coverage
- **Production Ready** - Used in enterprise Oracle directory migrations

### Universal Server Support

- **Oracle OID/OUD** - Full Oracle Internet/Unified Directory support
- **OpenLDAP 1.x/2.x** - Traditional and cn=config formats
- **Active Directory** - Microsoft AD-specific adaptations
- **389 Directory Server** - Red Hat directory support
- **Generic RFC** - Works with any RFC-compliant LDAP server

### Enterprise Features

- **Universal Conversion Matrix** - N×N server conversions via RFC intermediate format
- **DN Case Registry** - Canonical DN case tracking for OUD compatibility
- **Auto-Detection** - Automatic LDAP server type detection
- **Relaxed Mode** - Lenient parsing for broken/non-compliant LDIF files
- **Batch Processing** - Memory-efficient processing for large files
- **FLEXT Integration** - Railway-oriented programming with FlextResult[T]

---

## 📚 Documentation

- **[Getting Started](docs/getting-started.md)** - Installation, configuration, and basic usage
- **[API Reference](docs/api-reference.md)** - Complete API documentation
- **[Architecture](docs/architecture.md)** - System design and patterns
- **[Configuration](docs/configuration.md)** - Configuration options and customization
- **[Integration Guide](docs/guides/integration.md)** - Integration with other systems
- **[Migration Guide](docs/migration/v0.9-to-v1.0-migration.md)** - Upgrade from v0.9 to v1.0
- **[Troubleshooting](docs/troubleshooting.md)** - Common issues and solutions

---

## 🏗️ Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   RFC 2849   │────▶│    Quirks    │────▶│    Target    │
│   Parsing    │     │    System    │     │    Format    │
│              │     │ (OID/OUD/AD) │     │              │
└──────────────┘     └──────────────┘     └──────────────┘
       │                     │                     │
       └─────────────────────┴─────────────────────┘
                Railway-Oriented Error Handling
                    (FlextResult[T])
```

**Design Principles**:

- **RFC-First** - RFC compliance as foundation
- **Pluggable Quirks** - Server-specific extensions
- **Railway Pattern** - Composable error handling
- **Clean Architecture** - Clear layer separation
- **Type Safety** - 100% type coverage

---

## 💡 Usage Examples

### Parse LDIF with Auto-Detection

```python
from flext_ldif import FlextLdif
from pathlib import Path

ldif = FlextLdif()

# Automatically detect server type
result = ldif.parse_with_auto_detection(Path("directory.ldif"))

if result.is_success:
    entries = result.unwrap()

    # Check detected server
    if entries and entries[0].metadata:
        print(f"Detected: {entries[0].metadata.quirk_type}")
```

### Server-to-Server Migration

```python
from flext_ldif import FlextLdif
from pathlib import Path

# Initialize FlextLdif API
ldif = FlextLdif()

# Simple migration from Oracle OID to OUD (single output file)
result = ldif.migrate(
    input_dir=Path("oid-export"),
    output_dir=Path("oud-import"),
    from_server="oracle_oid",
    to_server="oracle_oud"
)

if result.is_success:
    stats = result.unwrap().statistics
    print(f"✅ Migrated {stats.processed_entries} entries")
```

### Filter and Categorize Entries

```python
from flext_ldif import FlextLdif, FlextLdifModels

ldif = FlextLdif()
entries_result = ldif.parse(Path("directory.ldif"))

if entries_result.is_success:
    entries = entries_result.unwrap()

    # Filter by DN pattern
    criteria = FlextLdifModels.FilterCriteria(
        filter_type="dn_pattern",
        pattern="*,ou=users,dc=example,dc=com",
        mode="include"
    )

    filtered = ldif.filter(entries, criteria)

    # Categorize by objectClass
    categorized = ldif.categorize(filtered.unwrap())

    if categorized.is_success:
        result = categorized.unwrap()
        print(f"Users: {len(result.users)}")
        print(f"Groups: {len(result.groups)}")
        print(f"Containers: {len(result.containers)}")
```

### Relaxed Mode for Broken LDIF

```python
from flext_ldif import FlextLdif
from pathlib import Path

ldif = FlextLdif()

# Parse non-compliant LDIF with best-effort recovery
result = ldif.parse_relaxed(Path("broken.ldif"))

if result.is_success:
    entries = result.unwrap()
    print(f"✅ Recovered {len(entries)} entries from broken LDIF")
```

### Build and Write Entries

```python
from flext_ldif import FlextLdif
from pathlib import Path

ldif = FlextLdif()

# Build a person entry
person_result = ldif.build(
    "person",
    cn="John Doe",
    sn="Doe",
    mail="john.doe@example.com",
    base_dn="dc=example,dc=com"
)

if person_result.is_success:
    entry = person_result.unwrap()

    # Write to file
    write_result = ldif.write([entry], Path("output.ldif"))

    if write_result.is_success:
        print("✅ Entry written successfully")
```

---

## 🔧 Advanced Usage

### Direct flext-core Integration

```python
# Use FlextProcessors directly for batch processing
from flext_core import FlextProcessors

processor = FlextProcessors()
result = processor.batch_process(entries, transform_func, batch_size=100)
```

### Custom Quirks

```python
from flext_ldif.services.base import QuirkBase

class CustomServerQuirks(QuirkBase):
    """Custom server-specific quirks."""

    def __init__(self) -> None:
        super().__init__(server_name="custom", priority=50)

    def normalize_dn(self, dn: str) -> str:
        """Custom DN normalization."""
        return dn.lower()
```

### Performance Tracking

```python
from flext_core import FlextDecorators

# Services automatically use decorators for logging and performance
# Example from internal implementation:

class MyService(FlextService):
    @FlextDecorators.log_operation(level="info")
    @FlextDecorators.track_performance()
    def process(self, data):
        # Automatic logging and metrics
        pass
```

---

## 🎯 Use Cases

### Enterprise Directory Migration

- **Oracle OID → OUD**: Migrate Oracle Internet Directory to Unified Directory
- **OpenLDAP → 389DS**: Migrate between open-source directory servers
- **AD → OpenLDAP**: Extract and transform Active Directory data

### Data Integration

- **LDIF Export/Import**: Extract directory data for backup or analysis
- **Schema Migration**: Transfer schema definitions between servers
- **ACL Transformation**: Convert access control lists between formats

### Development & Testing

- **Test Data Generation**: Build LDIF entries programmatically
- **Validation**: Verify LDIF compliance before importing
- **Analysis**: Extract statistics and patterns from directory data

---

## 🤝 Integration

### FLEXT Ecosystem

flext-ldif is part of the [FLEXT platform](https://github.com/flext) for enterprise data integration:

- **flext-core** - Foundation patterns (FlextResult, FlextContainer, FlextProcessors)
- **flext-ldap** - LDAP client operations
- **client-a-oud-mig** - Production Oracle directory migration project
- **flext-tap-ldif** - Singer tap for LDIF data extraction
- **flext-target-ldif** - Singer target for LDIF data loading

### External Libraries

- **Pydantic v2** - Data validation and settings
- **Python 3.13+** - Modern Python features
- **dependency-injector** - Type-safe dependency injection

---

## 🧪 Development

### Setup

```bash
# Clone repository
git clone https://github.com/flext/flext-ldif.git
cd flext-ldif

# Install dependencies
make setup

# Run tests
make test

# Run validation (lint + type + test + security)
make validate
```

### Quality Standards

- **Type Safety**: Pyrefly strict mode (100% type coverage)
- **Linting**: Ruff with zero violations
- **Testing**: 78%+ coverage with 1766+ tests
- **Security**: Bandit security scanning
- **PEP 8**: Full compliance

### Test Infrastructure

All tests use unified test helpers for concise, parameterized validation:

```python
from tests import tm, tf, c, m, s

# Unified entry validation
entry = tf.create_entry("cn=test,dc=example", attrs={"cn": ["test"]})
tm.entry(entry, dn="cn=test,dc=example", has_attr="cn", attr_count_gte=1)

# Unified result validation
result = service.execute()
entries = tm.ok_entries(result, count=3, all_have_attr="cn")
```

See [CLAUDE.md](CLAUDE.md) for complete test helper documentation.

### Contributing

See [Development Guide](docs/development.md) for development guidelines.

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

Part of the **FLEXT Ecosystem** - Enterprise data integration platform.

**Developed by**: FLEXT Core Team
**Used in production**: Oracle directory migrations (1M+ entries)
**Maintained**: Active development and support

---

## 📞 Support

- **Documentation**: [docs/](docs/)
- **Issues**: <https://github.com/flext/flext-ldif/issues>
- **Discussions**: <https://github.com/flext/flext-ldif/discussions>
- **Email**: <support@flext-platform.org>

---

## Features

### RFC-Compliant Design

Built on RFC-compliant foundation with conversion matrix for server-to-server transformations:

**Core Components**:

- **RFC 2849 (LDIF Format)** - LDIF parsing
- **RFC 4512 (Schema)** - LDAP schema parsing
- **Conversion Matrix** - N×N server conversions via RFC intermediate format
- **DN Case Registry** - DN case tracking for server compatibility
- **Categorized Pipeline** - Entry categorization with structured output
- **Batch & Parallel Processors** - Processing for large datasets
- **Event System** - Processing lifecycle events
- **Filters** - Entry filtering and transformation
- **Quirks System** - Server-specific extensions

### Conversion Matrix

Converts between LDAP server quirks using RFC as intermediate format:

**Conversion Pattern**:

```
Source Format → Source.to_rfc() → RFC Format → Target.from_rfc() → Target Format
```

**Approach**:

- N×N Matrix: Convert between any server pair with 2×N implementations
- RFC Intermediate: Standards-compliant intermediate representation
- DN Consistency: Canonical DN case tracking
- Type Safety: Type annotations with FlextResult error handling

**Example**:

```python
from flext_ldif.services.conversion import QuirksConversionMatrix
from flext_ldif.servers.ouds import FlextLdifServersOud
from flext_ldif.servers.oid import FlextLdifServersOid

matrix = QuirksConversionMatrix()
oud = FlextLdifServersOud()
oid = FlextLdifServersOid()

# Convert OID attribute to OUD format
oid_attr = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' ... )"
result = matrix.convert(oud, oid, "attribute", oid_attr)
```

### **DN Case Registry**

Ensures DN case consistency during conversions, critical for OUD compatibility:

```python
from flext_ldif.services.dn_case_registry import DnCaseRegistry

registry = DnCaseRegistry()

# Register canonical DN case
canonical = registry.register_dn("CN=Admin,DC=Example,DC=Com")
# Returns: "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"

# Get canonical case for any variant
canonical = registry.get_canonical_dn("cn=ADMIN,dc=example,dc=com")
# Returns: "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"

# Validate OUD consistency
result = registry.validate_oud_consistency()
```

**Design Philosophy**:

- RFC parsers provide the **baseline** for all LDAP servers
- Universal matrix enables **any-to-any server conversion** with minimal implementations
- DN case registry ensures **OUD compatibility** during conversions
- Quirks **extend and enhance** RFC parsing for server-specific features
- **Works with any LDAP server** - known or unknown

### **RFC 2849 Compliance (LDIF Format)**

Full compliance with RFC 2849 LDIF specification:

- **Base64 Encoding** - Automatic handling of `::` syntax for binary data
- **Change Records** - Support for `add`, `modify`, `delete`, and `modrdn` operations
- **Line Continuations** - Proper handling of line folding and continuation
- **Comments** - Support for `#` comment lines
- **URL References** - Handling of `<url>` references for external data
- **Attribute Options** - Support for language tags and other attribute options
- **Version Control** - LDIF version header support

### **RFC 4512 Compliance (Schema)**

Full compliance with RFC 4512 LDAP schema specification:

- **AttributeType Parsing** - OID, NAME, SYNTAX, EQUALITY, ORDERING, SUBSTR
- **ObjectClass Parsing** - OID, NAME, SUP, STRUCTURAL/AUXILIARY/ABSTRACT, MUST, MAY
- **Schema Subentry** - cn=subschemasubentry discovery
- **Standard LDAP Syntaxes** - RFC 4517 syntax support

### **Server-Specific Quirks (Extensible)**

Automatic detection and quirk-based adaptation for LDAP servers:

**Fully Implemented** (Production-validated):

- **OpenLDAP 1.x/2.x** (757 LOC) - Custom OID extensions, operational attributes, production-validated
- **Oracle Internet Directory (OID)** (1479 LOC) - Oracle-specific schema extensions, production-validated
- **Oracle Unified Directory (OUD)** (1466 LOC) - OUD quirks with nested ACL/Entry quirks, production-validated

**Fully Implemented** (Not yet validated with production data):

- **Active Directory** (777 LOC) - Complete implementation with MS OID namespace, nTSecurityDescriptor ACL parsing, DN normalization
- **Apache Directory Server** (648 LOC) - Complete implementation with ApacheDS OID namespace (1.3.6.1.4.1.18060), ACI format, ads-\* attributes
- **389 Directory Server** (699 LOC) - Complete implementation with Red Hat OID namespace (2.16.840.1.113730), nsslapd-\* attributes, ACI format
- **Novell eDirectory** (680 LOC) - Complete implementation with Novell OID namespace (2.16.840.1.113719), nspm/login attributes, ACL parsing
- **IBM Tivoli Directory Server** (666 LOC) - Complete implementation with IBM OID namespace (1.3.18), ibm-/ids-\* attributes, access control

**Status Notes**:

- All implementations include: Schema parsing (attributes + objectClasses), ACL quirks, Entry processing, RFC conversions, Write methods
- "Not yet validated" implementations need real server LDIF exports for integration testing
- All implementations have comprehensive unit tests and follow the same architectural patterns
- Ready for production use but require validation with actual server data before enterprise deployment

**Quirks Architecture**:

- Each server has a **Schema** for attributeType/objectClass extensions
- Schema quirks contain nested **Acl** and **Entry** classes
- Quirks use **priority-based resolution** (lower number = higher priority)
- Strict RFC 4514 compliance enforced (NO fallback behavior)

### **Multi-Encoding Support**

- **Automatic Detection** - Detects UTF-8, Latin-1, ASCII, and other encodings
- **Encoding Conversion** - Seamless handling of mixed encoding content
- **Unicode Support** - Full Unicode character support in DNs and attributes

### **Advanced Validation**

- **RFC Compliance Validation** - Comprehensive compliance checking
- **Server-Specific Validation** - Validation against server-specific rules
- **Quality Assessment** - Quality metrics and recommendations
- **Error Recovery** - Graceful handling of malformed LDIF with detailed error reporting

---

## 🏗️ Architecture and Patterns

### **FLEXT-Core Integration Status**

| Pattern             | Status      | Description                                      |
| ------------------- | ----------- | ------------------------------------------------ |
| **FlextResult[T]**  | 🟢 Complete | Operations return FlextResult for error handling |
| **FlextService**    | 🟢 Complete | Service-oriented architecture with LDIF services |
| **FlextContainer**  | 🟢 Complete | Dependency injection for service orchestration   |
| **Domain Patterns** | 🟢 Complete | LDIF Entry, DN, and Attribute domain models      |

> **Integration**: Uses flext-core patterns with memory-bound processing

### **Architecture Overview**

```mermaid
graph TB
    API --> Models[FlextLdifModels]
    API --> Config[FlextLdifSettings]

    Client --> Parser[RFC Parser]
    Client --> Writer[RFC Writer]
    Client --> Migration[FlextLdif.migrate()]
    Client --> Processors[LdifBatchProcessor/LdifParallelProcessor]
    Client --> Events[LdifMigratedEvent/LdifParsedEvent/etc.]

    Migration --> Quirks[Quirks System]
    Categorized --> Quirks
    Parser --> Quirks
    Writer --> Quirks

    Quirks --> ConversionMatrix[QuirksConversionMatrix]
    Quirks --> DnCaseRegistry[DnCaseRegistry]
    Quirks --> Registry[FlextLdifServer]

    Models --> Entry[Entry Domain Model]
    Models --> DN[Distinguished Name]
    Models --> ChangeRecord[Change Record Model]
```

---

## 🚀 Quick Start

⚠️ **CRITICAL MEMORY WARNING**: This implementation loads entire LDIF files into memory during processing. **Files larger than 100MB may cause processing failures** due to memory constraints. Check file size before processing large files to avoid out-of-memory errors.

### **Installation**

```bash
cd flext-ldif
make setup

# Verify installation
python -c "from flext_ldif import FlextLdif; print('FLEXT-LDIF ready')"
```

### **Basic Usage (Library-Only API)**

```python
from flext_ldif import FlextLdif
from pathlib import Path

# Initialize FlextLdif facade (library-only interface)
ldif = FlextLdif()

# ⚠️ MEMORY CHECK: Verify file size before processing
ldif_file = Path("directory.ldif")
file_size_mb = ldif_file.stat().st_size / (1024 * 1024)
if file_size_mb > 100:
    print(f"WARNING: File size ({file_size_mb:.1f}MB) exceeds recommended 100MB limit")
    print("Processing may fail due to memory-bound architecture - see Known Limitations")

# Parse LDIF file or content string
result = ldif.parse(ldif_file)  # Accepts Path, str (file path), or content string
if result.is_success:
    entries = result.unwrap()
    print(f"Parsed {len(entries)} LDIF entries")

    # Validate entries
    validation_result = ldif.validate_entries(entries)
    if validation_result.is_success:
        print("LDIF validation successful")
    else:
        print(f"Validation error: {validation_result.error}")
else:
    print(f"Parse error: {result.error}")
```

---

## 📚 Advanced Usage Examples

### **Generic Schema Parsing with Quirks (MANDATORY)**

```python
from flext_ldif.services.rfc_schema_parser import FlextLdifRfcSchemaParser
from flext_ldif.services.server import QuirkRegistryService
from pathlib import Path

# ⚠️ MANDATORY: quirk_registry is REQUIRED for all RFC parsers/writers
# QuirkRegistryService auto-discovers and registers all standard quirks
quirk_registry = QuirkRegistryService()

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

    # Schema parsing automatically uses OID quirks for extensions
    # Falls back to RFC 4512 for standard attributes

# Parse with RFC-only mode (quirks available but not used for this server)
rfc_parser = RfcSchemaParserService(
    params={"file_path": "standard_schema.ldif"},
    quirk_registry=quirk_registry,  # Still MANDATORY
    server_type="rfc",  # Pure RFC mode - no server-specific quirks applied
)
```

### **Categorized Entry Migration with Structured Output**

```python
from flext_ldif import FlextLdif
from pathlib import Path

# Initialize FlextLdif API
ldif = FlextLdif()

# Define categorization rules (enables categorized mode automatically)
categorization_rules = {
    "hierarchy_objectclasses": ["organization", "organizationalUnit", "domain"],
    "user_objectclasses": ["inetOrgPerson", "person", "organizationalPerson"],
    "group_objectclasses": ["groupOfNames", "groupOfUniqueNames"],
    "acl_attributes": ["aci"],  # Empty list disables ACL processing
}

# Execute unified migration (automatically detects categorized mode)
result = ldif.migrate(
    input_dir=Path("source_ldifs"),
    output_dir=Path("categorized_output"),
    from_server="oracle_oid",
    to_server="oracle_oud",
    categorization_rules=categorization_rules
)

if result.is_success:
    stats = result.unwrap().statistics
    print("Categorized migration completed successfully")
    print(f"Total entries processed: {stats.processed_entries}")
    print(f"Categories created: {len(result.unwrap().entries_by_category)}")

    # Generates 6 structured LDIF files:
    # 00-schema.ldif, 01-hierarchy.ldif, 02-users.ldif,
    # 03-groups.ldif, 04-acl.ldif, 05-rejected.ldif
```

### **Batch and Parallel Processing**

```python
from flext_ldif.processors import LdifBatchProcessor, LdifParallelProcessor
from flext_ldif import FlextLdif

# Initialize processors
batch_processor = LdifBatchProcessor(batch_size=100)
parallel_processor = LdifParallelProcessor(max_workers=4)  # Uses ThreadPoolExecutor

# Parse large LDIF file
ldif = FlextLdif()
result = ldif.parse("large_directory.ldif")
if result.is_success:
    entries = result.unwrap()

    # Batch processing for memory efficiency
    def validate_entry(entry):
        # Validate entry logic here
        return entry.dn.value if hasattr(entry, 'dn') else "invalid"

    batch_result = batch_processor.process_batch(entries, validate_entry)
    if batch_result.is_success:
        validated_dns = batch_result.unwrap()
        print(f"Validated {len(validated_dns)} entries in batches")

    # Parallel processing for CPU-intensive operations (TRUE PARALLELISM)
    def transform_entry(entry):
        # CPU-intensive transformation logic
        return entry  # transformed entry

    parallel_result = parallel_processor.process_parallel(entries, transform_entry)
    if parallel_result.is_success:
        transformed_entries = parallel_result.unwrap()
        print(f"Transformed {len(transformed_entries)} entries in parallel")
        # Note: Results may be in different order due to parallel execution
```

### **RFC 2849 Compliant Parsing**

```python
from flext_ldif import FlextLdifProcessor
import base64

# LDIF with RFC 2849 features
ldif_content = """
version: 1
dn: cn=test,dc=example,dc=com
cn: test
description:: VGVzdCBkZXNjcmlwdGlvbg==
objectClass: person
"""

processor = FlextLdifProcessor()

# Parse with advanced RFC 2849 compliance
result = processor.parse_string_advanced(ldif_content)
if result.is_success:
    entries = result.value
    print(f"Advanced parsing: {len(entries)} entries/records")

    # Validate RFC compliance
    compliance = processor.validate_rfc_compliance(entries)
    if compliance.is_success:
        print(f"Compliance score: {compliance.value['compliance_score']:.2f}")
```

### **Server Detection and Adaptation**

```python
from flext_ldif import FlextLdifProcessor

processor = FlextLdifProcessor()

# Parse entries
result = processor.parse_string(ldif_content)
if result.is_success:
    entries = result.value

    # Detect server type
    server_result = processor.detect_server_type(entries)
    if server_result.is_success:
        server_type = server_result.value
        print(f"Detected server: {server_type}")

        # Adapt entries for specific server
        adapted_result = processor.adapt_entries_for_server(entries, "active_directory")
        if adapted_result.is_success:
            adapted_entries = adapted_result.value
            print(f"Adapted {len(adapted_entries)} entries for Active Directory")
```

### **Change Records Processing**

```python
from flext_ldif import FlextLdifProcessor

# LDIF with change records
change_ldif = """
dn: cn=new user,dc=example,dc=com
changetype: add
cn: new user
objectClass: person

dn: cn=existing user,dc=example,dc=com
changetype: modify
cn: existing user
objectClass: person
"""

processor = FlextLdifProcessor()
result = processor.parse_string_advanced(change_ldif)

if result.is_success:
    for item in result.value:
        if hasattr(item, 'changetype'):
            print(f"Change Record: {item.changetype} - {item.dn.value}")
        else:
            print(f"Entry: {item.dn.value}")
```

### **File Processing with Encoding Detection**

```python
from pathlib import Path
from flext_ldif import FlextLdifProcessor

processor = FlextLdifProcessor()

# Process file with automatic encoding detection
file_path = Path("data.ldif")
result = processor.parse_file_advanced(file_path)

if result.is_success:
    entries = result.value
    print(f"Processed file: {len(entries)} entries")
else:
    print(f"Processing failed: {result.error}")
```

---

## 🔧 Quality Assurance

The FLEXT ecosystem provides comprehensive automated quality assurance:

- **Pattern Analysis**: Automatic detection of architectural violations and duplication
- **Consolidation Guidance**: SOLID-based refactoring recommendations
- **Batch Operations**: Safe, automated fixes with backup and rollback
- **Quality Gates**: Enterprise-grade validation before integration

### Development Standards

- **Architecture Compliance**: Changes maintain layering and dependencies
- **Type Safety**: Complete type coverage maintained
- **Test Coverage**: All changes include comprehensive tests
- **Quality Validation**: Automated checks ensure standards are met

## 🔧 Development

### **Essential Commands**

```bash
make setup          # Development environment setup
make lint           # Ruff linting
make type-check     # MyPy type checking
make test           # Run test suite
make validate       # Validation pipeline
```

### **Quality Gates**

- **Type Safety**: MyPy strict mode compliance for `src/`
- **Code Quality**: Ruff linting and formatting
- **Testing**: Unit and integration tests
- **LDIF Compliance**: Basic RFC 2849 support

---

## 🧪 Testing

### **Test Structure**

```bash
tests/
├── unit/                    # Service component tests
├── integration/             # End-to-end LDIF processing
├── fixtures/ldif/           # Test LDIF data samples
└── conftest.py             # Shared test configuration
```

### **Testing Commands**

```bash
pytest                                    # Full test suite
pytest -m unit                          # Unit tests only
pytest -m integration                   # Integration tests only
pytest --cov=src/flext_ldif             # Coverage report
```

---

## 📊 Status and Metrics

### **Current Capabilities (v0.9.0)**

- **Universal Conversion Matrix**: N×N server conversions via RFC intermediate format
- **DN Case Registry**: Canonical DN case tracking for OUD compatibility
- **Categorized Pipeline**: Rule-based entry categorization with 6-file structured output
- **Batch & Parallel Processors**: True parallel processing with ThreadPoolExecutor for CPU-intensive operations
- **Event System**: Domain events for processing lifecycle tracking
- **Enhanced Filters**: Advanced entry filtering and transformation utilities
- **LDIF Processing**: Full RFC 2849/4512 compliant parsing and validation
- **ACL Evaluation**: Composite ACL rule evaluation with permission checking
- **Service Architecture**: Modular services with FlextResult error handling
- **Type Safety**: 100% Pyrefly strict mode compliance
- **Memory-bound Processing**: Loads entire files into memory for processing
- **Testing**: 1415/1415 tests passing (100% pass rate, 77.93% coverage)

### **Known Limitations**

⚠️ **CRITICAL MEMORY ARCHITECTURE CONSTRAINTS**:

- **Memory Usage**: **Loads entire LDIF files into memory** during processing via `content.splitlines()` in `format_handlers.py:206`
- **File Size Limit**: **Files larger than available RAM will cause failures** - recommended maximum 100MB
- **Memory Scaling**: **Memory usage scales linearly with file size** - no streaming or chunked processing
- **No Graceful Degradation**: **No memory pressure detection or recovery mechanisms**
- **Performance**: Single-threaded processing, memory-bound architecture unsuitable for large datasets
- **Architecture**: Custom parser implementation
- **Features**: Basic functionality focused on small to medium file processing

**Technical Details**: The current implementation uses a custom `_ParserHelper` class that calls `content.splitlines()`, loading the entire file content into memory before processing begins. This design choice makes the library suitable only for files that fit comfortably in available system memory.

### **Ecosystem Integration**

- **Primary User**: client-a-oud-mig (Oracle migration project)
- **Foundation**: flext-core (base patterns and utilities)
- **Context**: LDAP directory processing within FLEXT ecosystem

---

## 🗺️ Roadmap

### **Current Version (v0.9.0)**

Production-ready LDIF processing with comprehensive enterprise features including categorized migration pipelines, batch/parallel processing, and event-driven architecture. Suitable for production use with memory constraints for files under 100MB.

### **Planned Improvements**

- **Memory Optimization**: Investigate streaming approaches for large files
- **Performance**: Evaluate processing bottlenecks and optimization opportunities
- **Features**: Additional LDIF operations based on user requirements
- **Testing**: Expand test coverage for edge cases

See TODO.md for detailed development priorities.

---

## 📚 Documentation

- **[Architecture](docs/architecture.md)** - LDIF operations responsibility, import rules, compliance verification
- **[Getting Started](docs/getting-started.md)** - Installation and setup
- **[Architecture](docs/architecture.md)** - Service design and patterns
- **[API Reference](docs/api-reference.md)** - Complete API documentation
- **[Configuration](docs/configuration.md)** - Settings and environment management
- **[Development](docs/development.md)** - Contributing and workflows
- **[Integration](docs/guides/integration.md)** - FLEXT ecosystem integration patterns
- **[Examples](docs/examples/)** - Working code examples
- **[Troubleshooting](docs/troubleshooting.md)** - Common issues and solutions

---

## 🤝 Contributing

### Quality Standards

All contributions must:

- Maintain architectural layering and dependency rules
- Preserve complete type safety
- Follow established testing patterns
- Pass automated quality validation

### **FLEXT-Core Compliance**

- [x] Operations return FlextResult[T] for error handling
- [x] Services use FlextContainer for dependency injection
- [x] Type annotations with Python 3.13+ syntax
- [x] Pydantic v2 models for data validation
- [x] Integration with flext-core patterns

### **Quality Standards**

- **Code Quality**: MyPy strict mode compliance
- **Test Coverage**: Unit and integration tests
- **Documentation**: Public APIs documented
- **Architecture**: Service-oriented design patterns

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🆘 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/flext-sh/flext-ldif/issues)
- **Security**: Report security issues privately to maintainers

---

**FLEXT-LDIF v0.9.0** - Enterprise-grade LDIF processing library for LDAP data operations within the FLEXT ecosystem.

**Purpose**: Provide type-safe, RFC-compliant LDIF processing with advanced migration pipelines, batch processing, and comprehensive server-specific adaptations for enterprise directory operations.
