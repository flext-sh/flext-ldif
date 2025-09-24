# FLEXT-LDIF

**Advanced LDIF processing library** for the FLEXT ecosystem, providing comprehensive LDAP data parsing, validation, and server-specific adaptations with full RFC 2849 compliance.

> **STATUS**: Version 0.9.0 - **ENHANCED** with RFC 2849 compliance, server quirks handling, and advanced parsing capabilities 🚀

---

## 🎯 Purpose and Role in FLEXT Ecosystem

### **For the FLEXT Ecosystem**

FLEXT-LDIF provides LDIF (LDAP Data Interchange Format) processing capabilities for the FLEXT data integration platform. It handles LDIF file parsing, validation, and basic manipulation operations.

### **Key Responsibilities**

1. **RFC 2849 Compliance** - Full LDIF standard compliance with Base64 encoding, change records, and URL references
2. **Server-Specific Adaptations** - Handle quirks from Active Directory, OpenLDAP, Apache Directory Server, and others
3. **Advanced Parsing** - Multi-encoding support, line continuations, comments, and attribute options
4. **Type Safety** - Pydantic v2 models for data validation with comprehensive error handling
5. **Service Architecture** - Modular services for parsing, validation, writing, and server detection

### **Integration Points**

- **[flext-core](../flext-core/README.md)** → Foundation patterns (FlextResult, FlextContainer)
- **[algar-oud-mig](../algar-oud-mig/README.md)** → Oracle Unified Directory migration project
- **Projects requiring LDIF processing** → Directory data operations

---

## 🚀 Advanced Features

### **RFC 2849 Compliance**

FLEXT-LDIF now provides full compliance with RFC 2849 LDIF specification:

- **Base64 Encoding** - Automatic handling of `::` syntax for binary data
- **Change Records** - Support for `add`, `modify`, `delete`, and `modrdn` operations
- **Line Continuations** - Proper handling of line folding and continuation
- **Comments** - Support for `#` comment lines
- **URL References** - Handling of `<url>` references for external data
- **Attribute Options** - Support for language tags and other attribute options
- **Version Control** - LDIF version header support

### **Server-Specific Adaptations**

Automatic detection and adaptation for different LDAP server implementations:

- **Active Directory** - DN case sensitivity, required object classes, attribute mappings
- **OpenLDAP** - Standard LDAP compliance, schema validation
- **Apache Directory Server** - Specific validation rules and attribute handling
- **Novell eDirectory** - Legacy compatibility and special attributes
- **IBM Tivoli Directory Server** - Enterprise-specific requirements
- **Generic LDAP** - Fallback for unknown server types

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
    API[FlextLdifAPI] --> Parser[ParserService]
    API --> Validator[ValidatorService]
    API --> Writer[WriterService]
    API --> Repository[RepositoryService]
    API --> Analytics[AnalyticsService]

    Parser --> Models[FlextLdifModels]
    Validator --> Models
    Writer --> Models

    Models --> Entry[Entry Domain Model]
    Models --> DN[Distinguished Name]
    Models --> Config[Configuration]
```

---

## 🚀 Quick Start

⚠️ **CRITICAL MEMORY WARNING**: This implementation loads entire LDIF files into memory during processing. **Files larger than 100MB may cause processing failures** due to memory constraints. Check file size before processing large files to avoid out-of-memory errors.

### **Installation**

```bash
cd flext-ldif
make setup

# Verify installation
python -c "from flext_ldif import FlextLdifAPI; print('FLEXT-LDIF ready')"
```

### **Basic Usage**

```python
from flext_ldif import FlextLdifAPI
from pathlib import Path

# Initialize API
api = FlextLdifAPI()

# ⚠️ MEMORY CHECK: Verify file size before processing
ldif_file = Path("directory.ldif")
file_size_mb = ldif_file.stat().st_size / (1024 * 1024)
if file_size_mb > 100:
    print(f"WARNING: File size ({file_size_mb:.1f}MB) exceeds recommended 100MB limit")
    print("Processing may fail due to memory-bound architecture - see Known Limitations")

# Parse LDIF file
result = api.parse_file(ldif_file)
if result.is_success:
    entries = result.unwrap()
    print(f"Parsed {len(entries)} LDIF entries")

    # Validate entries
    validation_result = api.validate_entries(entries)
    if validation_result.is_success:
        print("LDIF validation successful")
    else:
        print(f"Validation error: {validation_result.error}")
else:
    print(f"Parse error: {result.error}")
```

---

## 📚 Advanced Usage Examples

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

### **Current Capabilities (v0.9.9)**

- **LDIF Processing**: Basic parsing and validation of LDIF files
- **Service Architecture**: Five services (parser, validator, writer, repository, analytics)
- **Type Safety**: Pydantic v2 models with type annotations
- **Error Handling**: FlextResult patterns for error management
- **Memory-bound Processing**: Loads entire files into memory for processing

### **Known Limitations**

⚠️ **CRITICAL MEMORY ARCHITECTURE CONSTRAINTS**:

- **Memory Usage**: **Loads entire LDIF files into memory** during processing via `content.splitlines()` in `format_handlers.py:206`
- **File Size Limit**: **Files larger than available RAM will cause failures** - recommended maximum 100MB
- **Memory Scaling**: **Memory usage scales linearly with file size** - no streaming or chunked processing
- **No Graceful Degradation**: **No memory pressure detection or recovery mechanisms**
- **Performance**: Single-threaded processing, memory-bound architecture unsuitable for large datasets
- **Architecture**: Custom parser implementation contradicts 2025 industry best practices for LDIF processing
- **Features**: Basic functionality focused on small to medium file processing

**Technical Details**: The current implementation uses a custom `_ParserHelper` class that calls `content.splitlines()`, loading the entire file content into memory before processing begins. This design choice makes the library suitable only for files that fit comfortably in available system memory.

### **Ecosystem Integration**

- **Primary User**: algar-oud-mig (Oracle migration project)
- **Foundation**: flext-core (base patterns and utilities)
- **Context**: LDAP directory processing within FLEXT ecosystem

---

## 🗺️ Roadmap

### **Current Version (v0.9.9)**

Functional LDIF processing with service-oriented architecture. Suitable for development and small-scale use cases.

### **Planned Improvements**

- **Memory Optimization**: Investigate streaming approaches for large files
- **Performance**: Evaluate processing bottlenecks and optimization opportunities
- **Features**: Additional LDIF operations based on user requirements
- **Testing**: Expand test coverage for edge cases

See TODO.md for detailed development priorities.

---

## 📚 Documentation

- **[Getting Started](docs/getting-started.md)** - Installation and setup
- **[Architecture](docs/architecture.md)** - Service design and patterns
- **[API Reference](docs/api-reference.md)** - Complete API documentation
- **[Configuration](docs/configuration.md)** - Settings and environment management
- **[Development](docs/development.md)** - Contributing and workflows
- **[Integration](docs/integration.md)** - FLEXT ecosystem integration patterns
- **[Examples](docs/examples/)** - Working code examples
- **[Troubleshooting](docs/troubleshooting.md)** - Common issues and solutions

---

## 🤝 Contributing

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

**FLEXT-LDIF v0.9.9** - LDIF processing library for LDAP data operations within the FLEXT ecosystem.

**Purpose**: Provide type-safe LDIF processing capabilities for FLEXT projects requiring directory data handling.
