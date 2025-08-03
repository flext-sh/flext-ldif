# FLEXT-LDIF - Enterprise LDIF Processing Library

[![Python 3.13+](https://img.shields.io/badge/python-3.13%2B-blue.svg)](https://www.python.org/downloads/)
[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Type Checked](https://img.shields.io/badge/typed-mypy-blue.svg)](https://mypy.readthedocs.io/)
[![Code Style](https://img.shields.io/badge/code%20style-ruff-black.svg)](https://github.com/astral-sh/ruff)
[![Test Coverage](https://img.shields.io/badge/coverage-90%2B%25-brightgreen.svg)](tests/)
[![FLEXT Ecosystem](https://img.shields.io/badge/FLEXT-ecosystem-purple.svg)](https://github.com/flext-sh)

**FLEXT-LDIF** is an enterprise-grade LDIF (LDAP Data Interchange Format) processing library built with **Clean Architecture** and **Domain-Driven Design** principles. It provides comprehensive LDIF parsing, validation, transformation, and generation capabilities integrated with the **FLEXT ecosystem**.

## 🏗️ Project Status

| **Component**              | **Status**          | **Coverage** | **Integration** |
| -------------------------- | ------------------- | ------------ | --------------- |
| **Core LDIF Processing**   | ✅ Production Ready | 90%+         | Complete        |
| **Domain Model**           | ✅ Production Ready | 95%+         | Complete        |
| **API Layer**              | ✅ Production Ready | 85%+         | Complete        |
| **CLI Interface**          | ✅ Production Ready | 80%+         | Complete        |
| **FLEXT-Core Integration** | ✅ Complete         | 100%         | ✅ Active       |
| **FLEXT-LDAP Integration** | ⚠️ In Progress      | 60%          | 🔄 Phase 1      |
| **Singer Ecosystem**       | 🔄 Planned          | 0%           | 📋 Phase 2      |
| **Observability**          | ⚠️ Partial          | 70%          | 🔄 Phase 1      |

**Current Version**: 0.9.0 | **Target**: 1.0.0 (Production Release)

## ⚡ Quick Start

### Installation

```bash
# Install from PyPI (when available)
pip install flext-ldif

# Install from source (current)
git clone https://github.com/flext-sh/flext-ldif.git
cd flext-ldif
poetry install
```

### Basic Usage

```python
from flext_ldif import FlextLdifAPI

# Initialize API
api = FlextLdifAPI()

# Parse LDIF content
ldif_content = """
dn: cn=John Doe,ou=people,dc=example,dc=com
cn: John Doe
objectClass: person
objectClass: inetOrgPerson
mail: john.doe@example.com
"""

# Parse with error handling
result = api.parse(ldif_content)
if result.is_success:
    entries = result.data
    print(f"Successfully parsed {len(entries)} entries")
else:
    print(f"Parsing failed: {result.error}")

# Validate LDIF entries
validation_result = api.validate(entries)
print(f"Validation passed: {validation_result.is_success}")

# Generate LDIF output
output_result = api.write(entries)
if output_result.is_success:
    print(output_result.data)
```

### Command Line Interface

```bash
# Parse and validate LDIF file
flext-ldif parse sample.ldif

# Validate LDIF file with strict mode
flext-ldif validate --strict sample.ldif

# Transform LDIF with filters
flext-ldif transform --filter "objectClass=person" input.ldif output.ldif

# Show help
flext-ldif --help
```

## 🏛️ Architecture

FLEXT-LDIF implements **Clean Architecture** with **Domain-Driven Design** patterns:

```
src/flext_ldif/
├── api.py                     # Application Layer - Unified API
├── models.py                  # Domain Layer - Entities & Value Objects
├── services.py                # Infrastructure Layer - Domain Services
├── core.py                    # Infrastructure Layer - Core Processing
├── config.py                  # Infrastructure Layer - Configuration
├── cli.py                     # Presentation Layer - Command Interface
├── exceptions.py              # Domain Layer - Domain Exceptions
├── modernized_ldif.py         # Infrastructure Layer - Modern LDIF Support
└── utils/                     # Cross-cutting Concerns
    ├── validation.py          # Validation utilities
    ├── error_handling.py      # Error handling patterns
    ├── logging.py             # Logging configuration
    └── cli_utils.py           # CLI helper functions
```

### Key Design Patterns

- **Clean Architecture**: Clear separation between domain, application, and infrastructure
- **Domain-Driven Design**: Rich domain model with business logic
- **CQRS Pattern**: Command/Query separation for operations
- **Result Pattern**: Railway-oriented programming with FlextResult
- **Dependency Injection**: Centralized container from flext-core
- **Observer Pattern**: Domain events for integration points

## 🔧 Core Features

### 📋 LDIF Processing

- **Parsing**: RFC-compliant LDIF parsing with validation
- **Generation**: Clean LDIF output with proper formatting
- **Validation**: Business rule validation and schema compliance
- **Transformation**: Entry filtering and modification

### 🏗️ Enterprise Architecture

- **Clean Architecture**: Testable, maintainable code structure
- **Domain-Driven Design**: Business logic encapsulation
- **Type Safety**: 95%+ type annotation coverage with MyPy
- **Error Handling**: Comprehensive error scenarios with FlextResult

### 🔌 FLEXT Ecosystem Integration

- **flext-core**: Foundation patterns and utilities
- **flext-observability**: Monitoring and tracing (partial)
- **flext-ldap**: Directory services integration (planned)
- **Singer Ecosystem**: Data pipeline integration (planned)

### ⚡ Performance & Scalability

- **Streaming Support**: Large file processing capabilities
- **Memory Efficient**: Optimized for enterprise workloads
- **Async Ready**: Asynchronous processing patterns
- **Batch Operations**: Bulk processing optimizations

## 📖 API Reference

### Core Classes

#### FlextLdifAPI

Main application service providing unified LDIF operations:

```python
from flext_ldif import FlextLdifAPI, FlextLdifConfig

# Configure API
config = FlextLdifConfig(
    max_entries=10000,
    strict_validation=True,
    encoding="utf-8"
)

api = FlextLdifAPI(config)

# Core operations
parse_result = api.parse(ldif_content)         # Parse LDIF string
file_result = api.parse_file("data.ldif")     # Parse LDIF file
validate_result = api.validate(entries)       # Validate entries
write_result = api.write(entries)             # Generate LDIF
transform_result = api.transform(entries, filters)  # Transform entries
```

#### FlextLdifEntry

Domain entity representing LDIF entries:

```python
from flext_ldif import FlextLdifEntry, FlextLdifDistinguishedName

# Create entry
entry = FlextLdifEntry.model_validate({
    "dn": FlextLdifDistinguishedName(value="cn=user,dc=example,dc=com"),
    "attributes": {
        "cn": ["user"],
        "objectClass": ["person", "inetOrgPerson"],
        "mail": ["user@example.com"]
    }
})

# Domain operations
entry.validate_domain_rules()                 # Business rule validation
object_classes = entry.get_object_classes()   # Get object classes
has_person = entry.has_object_class("person") # Check object class
mail_values = entry.get_attribute_values("mail")  # Get attribute values
```

#### FlextLdifDistinguishedName

Value object for Distinguished Names:

```python
from flext_ldif import FlextLdifDistinguishedName

dn = FlextLdifDistinguishedName(value="cn=John Doe,ou=people,dc=example,dc=com")

# DN operations
rdn = dn.get_rdn()                            # Get relative DN
parent = dn.get_parent_dn()                   # Get parent DN
depth = dn.get_depth()                        # Get DN depth
is_child = dn.is_child_of(parent_dn)          # Check hierarchy
```

## 🔌 Integration Guide

### FLEXT Core Integration

```python
from flext_core import get_flext_container, FlextResult
from flext_ldif import FlextLdifAPI

# Use DI container
container = get_flext_container()
api = container.get(FlextLdifAPI)

# FlextResult pattern
result = api.parse(ldif_content)
if result.is_success:
    entries = result.data
    # Process entries
else:
    logger.error(f"Parse failed: {result.error}")
```

### Observability Integration

```python
from flext_observability import flext_monitor_function
from flext_ldif import FlextLdifAPI

@flext_monitor_function("ldif_processing")
def process_ldif_file(file_path: str):
    api = FlextLdifAPI()
    return api.parse_file(file_path)
```

### Future Integrations (Roadmap)

```python
# LDAP Integration (Phase 1)
from flext_ldap import FlextLdapConnection
from flext_ldif import FlextLdifAPI

connection = FlextLdapConnection("ldap://localhost")
api = FlextLdifAPI(ldap_connection=connection)
result = api.import_from_ldap("ou=people,dc=example,dc=com")

# Singer Integration (Phase 2)
from flext_tap_ldif import FlextLdifTap
from flext_target_ldif import FlextLdifTarget

# Extract LDIF data
tap = FlextLdifTap(config={"file_path": "data.ldif"})
records = tap.discover_streams()

# Load to LDIF format
target = FlextLdifTarget(config={"output_path": "output.ldif"})
target.process_records(records)
```

## 🧪 Testing

### Running Tests

```bash
# Complete test suite
make test                      # Run all tests with coverage

# Test categories
pytest -m unit                 # Unit tests only
pytest -m integration          # Integration tests
pytest -m e2e                  # End-to-end tests
pytest -m ldif                 # LDIF-specific tests
pytest -m parser               # Parser tests

# Coverage reporting
make coverage-html             # Generate HTML coverage report
pytest --cov=src/flext_ldif --cov-report=term-missing
```

### Test Configuration

Tests are configured with comprehensive fixtures:

```python
from tests.conftest import (
    ldif_test_data,           # Sample LDIF data
    flext_ldif_api,           # Configured API instance
    sample_entries,           # Test LDIF entries
    invalid_ldif_data,        # Invalid LDIF samples
)

def test_ldif_parsing(ldif_test_data, flext_ldif_api):
    result = flext_ldif_api.parse(ldif_test_data)
    assert result.is_success
    assert len(result.data) > 0
```

## 🚀 Development

### Development Environment Setup

```bash
# Clone and setup
git clone https://github.com/flext-sh/flext-ldif.git
cd flext-ldif

# Complete development setup
make setup                     # Install dependencies and pre-commit hooks

# Development workflow
make validate                  # Complete validation (lint + type + test)
make check                     # Quick health check
make build                     # Build distribution packages
```

### Code Quality Standards

```bash
# Linting and formatting
make lint                      # Ruff linting (ALL rules)
make format                    # Auto-format code
make type-check                # MyPy strict type checking
make security                  # Security scanning

# Quality gates (pre-commit)
make pre-commit                # Run all pre-commit hooks
```

### Contributing Guidelines

1. **Follow FLEXT ecosystem patterns**
2. **Maintain 90%+ test coverage**
3. **Pass all quality gates** (lint, type, security)
4. **Use FlextResult pattern** for error handling
5. **Write comprehensive docstrings**
6. **Respect Clean Architecture boundaries**

## 📋 Roadmap

### Phase 1: Core Stabilization (v1.0.0)

- [ ] **Fix FLEXT-Observability Integration** - Resolve dependency issues
- [ ] **Implement FLEXT-LDAP Integration** - Schema validation and directory ops
- [ ] **Performance Optimization** - Streaming support for large files
- [ ] **Architecture Refactoring** - Proper Clean Architecture structure

### Phase 2: Ecosystem Integration (v1.1.0)

- [ ] **Singer SDK Integration** - Tap, Target, and DBT implementations
- [ ] **Advanced Transformations** - Business rule engine
- [ ] **Multi-format Support** - JSON, XML, YAML conversion
- [ ] **Enterprise Features** - Audit logging, compliance

### Phase 3: Advanced Features (v1.2.0)

- [ ] **Real-time Processing** - Stream processing capabilities
- [ ] **Schema Evolution** - Dynamic schema adaptation
- [ ] **Performance Analytics** - Built-in benchmarking
- [ ] **Multi-tenant Support** - Enterprise deployment

## 🔒 Security & Compliance

### Security Features

- **Input Validation**: Comprehensive LDIF format validation
- **Schema Compliance**: LDAP schema validation support
- **Error Handling**: Secure error messages without data leakage
- **Dependency Scanning**: Regular security audits

### Compliance Standards

- **RFC 2849**: LDIF specification compliance
- **LDAP Standards**: Integration with LDAP directory standards
- **Enterprise Security**: Audit logging and access controls

## 📚 Documentation

- **[API Documentation](docs/api/API.md)** - Complete API reference
- **[Architecture Guide](docs/architecture/ARCHITECTURE.md)** - Design principles and patterns
- **[Examples](docs/examples/EXAMPLES.md)** - Practical usage examples
- **[Development Guide](CLAUDE.md)** - Developer guidance and patterns
- **[TODO & Issues](docs/TODO.md)** - Known issues and roadmap

## 🤝 Support & Community

- **Issues**: [GitHub Issues](https://github.com/flext-sh/flext-ldif/issues)
- **Discussions**: [GitHub Discussions](https://github.com/flext-sh/flext-ldif/discussions)
- **Documentation**: [Project Documentation](docs/)
- **FLEXT Ecosystem**: [FLEXT Organization](https://github.com/flext-sh)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🏆 Related FLEXT Projects

### Foundation Libraries

- **[flext-core](https://github.com/flext-sh/flext-core)** - Foundation patterns and utilities
- **[flext-observability](https://github.com/flext-sh/flext-observability)** - Monitoring and observability

### Infrastructure Libraries

- **[flext-ldap](https://github.com/flext-sh/flext-ldap)** - LDAP directory integration
- **[flext-db-oracle](https://github.com/flext-sh/flext-db-oracle)** - Oracle database connectivity
- **[flext-grpc](https://github.com/flext-sh/flext-grpc)** - gRPC communication protocols

### Application Services

- **[flext-api](https://github.com/flext-sh/flext-api)** - REST API services
- **[flext-cli](https://github.com/flext-sh/flext-cli)** - Command-line tools
- **[flext-web](https://github.com/flext-sh/flext-web)** - Web interface and dashboard

### Singer Ecosystem (Planned)

- **[flext-tap-ldif](https://github.com/flext-sh/flext-tap-ldif)** - LDIF data extraction
- **[flext-target-ldif](https://github.com/flext-sh/flext-target-ldif)** - LDIF data loading
- **[flext-dbt-ldif](https://github.com/flext-sh/flext-dbt-ldif)** - LDIF data transformation

---

**Built with ❤️ by the FLEXT Team** | **Enterprise-Grade • Type-Safe • Production-Ready**
