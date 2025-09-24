# FLEXT-LDIF CLAUDE.MD

**LDIF Processing Library for FLEXT Ecosystem**
**Version**: 0.9.9 RC | **Updated**: 2025-09-17
**Status**: Functional LDIF processing with memory-bound operations · 1.0.0 Release Preparation

**References**: See [../CLAUDE.md](../CLAUDE.md) for FLEXT ecosystem standards and [README.md](README.md) for project overview.

**Hierarchy**: This document provides project-specific standards based on workspace-level patterns defined in [../CLAUDE.md](../CLAUDE.md). For architectural principles, quality gates, and MCP server usage, reference the main workspace standards.

## 🔗 MCP SERVER INTEGRATION

| MCP Server              | Purpose                                                     | Status     |
| ----------------------- | ----------------------------------------------------------- | ---------- |
| **serena**              | LDIF processing codebase analysis and file parsing patterns | **ACTIVE** |
| **sequential-thinking** | LDIF architecture and data processing problem solving       | **ACTIVE** |
| **github**              | LDIF ecosystem integration and processing PRs               | **ACTIVE** |

**Usage**: `claude mcp list` for available servers, leverage for LDIF-specific development patterns and data processing analysis.

---

## 🎯 FLEXT-LDIF PURPOSE

**ROLE**: flext-ldif provides LDIF processing capabilities for FLEXT ecosystem projects that need to work with LDAP directory data.

**CURRENT CAPABILITIES**:

- ✅ **LDIF Processing**: Basic parsing and validation of LDIF files
- ✅ **FLEXT Integration**: Uses flext-core patterns (FlextResult, FlextContainer)
- ✅ **Type Safety**: Pydantic v2 models with type annotations
- ✅ **Service Architecture**: Modular services for parsing, validation, and writing
- ⚠️ **Memory Constraints**: Memory-bound processing for files under 100MB

**ECOSYSTEM USAGE**:

- **ALGAR OUD Migration**: LDIF processing for Oracle Unified Directory migration
- **Directory Data**: Processing LDAP data interchange files
- **Data Integration**: LDIF-based data operations within FLEXT pipelines

**QUALITY STANDARDS**:

- **Type Safety**: MyPy strict mode compliance in source code
- **Test Coverage**: Comprehensive test suite with good coverage
- **FLEXT Integration**: Uses flext-core patterns consistently
- **Code Quality**: Ruff linting and formatting compliance

---

## 🏗️ ARCHITECTURE

**Service-Oriented Design**: LDIF processing using modular services with clear separation of concerns.

**flext-core Integration**: Uses foundation library patterns including FlextResult for error handling, FlextContainer for dependency injection, and FlextDomainService for architecture.

**Type Safety**: Complete type annotations with Pydantic v2 models for data validation and processing.

**Memory Model**: Current implementation loads files into memory during processing, suitable for small to medium files.

### Service Structure

```
src/flext_ldif/
├── api.py                    # Main API interface
├── models.py                 # Domain models with Pydantic v2
├── parser_service.py         # LDIF parsing operations
├── validator_service.py      # Entry validation
├── writer_service.py         # LDIF output generation
├── repository_service.py     # Data management
├── analytics_service.py      # Statistics and analysis
├── cli.py                   # Command line interface
├── config.py                # Configuration management
├── exceptions.py            # Error handling
└── utilities.py             # Helper functions
```

---

## 🔧 DEVELOPMENT WORKFLOW

### Essential Commands

```bash
make setup          # Development environment setup
make lint           # Ruff linting
make type-check     # MyPy type checking
make test           # Run test suite
make validate       # Complete validation pipeline
```

### Quality Gates

- **Type Safety**: MyPy strict mode compliance for `src/`
- **Code Quality**: Ruff linting and formatting
- **Testing**: Unit and integration tests
- **LDIF Compliance**: Basic RFC 2849 support

---

## 📊 CURRENT STATUS (v0.9.9)

### What Works

- **LDIF Processing**: Basic RFC 2849 compliant parsing and writing
- **Service Architecture**: Five services with unified API
- **Type Safety**: Python 3.13+ type annotations with Pydantic v2
- **Error Handling**: FlextResult patterns throughout
- **FLEXT Integration**: Uses flext-core patterns
- **Testing**: Comprehensive test suite

### Known Limitations

- **Memory Usage**: Loads entire LDIF files into memory during processing
- **Performance**: Single-threaded processing suitable for small to medium files
- **Scale**: Recommended for files under 100MB due to memory constraints
- **Features**: Basic functionality with room for enhancement

---

## 🗺️ DEVELOPMENT PRIORITIES

### Phase 1: Quality and Stability

- Fix any remaining type issues
- Enhance test coverage for edge cases
- Improve error messages and recovery strategies
- Document memory limitations clearly

### Phase 2: Performance Optimization

- Implement memory usage monitoring
- Develop streaming parser for large files
- Add configurable chunk sizes for memory management
- Establish performance baselines and tests

### Phase 3: Feature Enhancement

- More sophisticated entry filtering capabilities
- Enhanced transformation and manipulation tools
- Better integration with LDAP servers and directories
- More comprehensive command-line operations

---

## 🚨 KNOWN ISSUES

### Memory Constraints

- Files larger than available RAM will cause failures
- No graceful degradation for memory pressure
- Limited monitoring of resource usage during processing

### Error Handling

- Some error messages lack actionable information
- Recovery from partial failures needs improvement
- Validation errors could be more specific

---

## 🔬 RESEARCH AREAS

### Memory Optimization

- Investigate line-by-line parsing approaches using streaming techniques
- Research memory-mapped file processing for large datasets
- Study garbage collection optimization patterns
- Evaluate chunk-based processing algorithms

### Performance Enhancement

- Research parallel processing patterns for LDIF data
- Investigate async/await patterns for I/O operations
- Study caching strategies for repeated operations
- Benchmark against other LDIF processing libraries

### Integration Opportunities

- Enhanced integration with ldap3 library for direct server operations
- Integration with enterprise directory services
- Connection to FLEXT data pipeline components
- Enhanced CLI tools for directory management

---

## 📚 PATTERNS AND BEST PRACTICES

### FlextResult Pattern

```python
from flext_ldif import FlextLdifAPI
from pathlib import Path

api = FlextLdifAPI()

# All operations return FlextResult for composable error handling
result = api.parse_file(Path("directory.ldif"))
if result.is_success:
    entries = result.unwrap()

    # Chain operations with FlextResult
    validation_result = api.validate(entries)
    if validation_result.is_success:
        print("LDIF processing successful")
    else:
        print(f"Validation error: {validation_result.error}")
else:
    print(f"Parse error: {result.error}")
```

### Service Usage

```python
from flext_ldif.services import FlextLdifServices

# Initialize services with dependency injection
services = FlextLdifServices()

# Use individual services
parser_result = services.parser.parse_content(ldif_content)
validation_result = services.validator.validate_entries(entries)
write_result = services.writer.write_entries_to_string(entries)
```

### Domain Model Usage

```python
from flext_ldif.models import FlextLdifModels

# Use Factory pattern for object creation
entry_data = {
    "dn": "cn=test,dc=example,dc=com",
    "attributes": {"cn": ["test"], "objectClass": ["person"]}
}
entry = FlextLdifModels.Entry.create(entry_data)

# Access consolidated models - use flext-ldif config directly
from flext_ldif.config import FlextLdifConfig
config = FlextLdifConfig()
```

---

## 🤝 CONTRIBUTING

### FLEXT-Core Compliance

- [x] Operations return FlextResult[T] for error handling
- [x] Services use FlextContainer for dependency injection
- [x] Type annotations with Python 3.13+ syntax
- [x] Pydantic v2 models for data validation
- [x] Integration with flext-core patterns

### Quality Standards

- **Code Quality**: MyPy strict mode compliance
- **Test Coverage**: Unit and integration tests
- **Documentation**: Public APIs documented
- **Architecture**: Service-oriented design patterns

---

**FLEXT-LDIF v0.9.9** - LDIF processing library for LDAP data operations within the FLEXT ecosystem.

**Purpose**: Provide type-safe LDIF processing capabilities for FLEXT projects requiring directory data handling.
