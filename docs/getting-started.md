# Getting Started with FLEXT-LDIF

<!-- TOC START -->

- [Prerequisites](#prerequisites)
  - [System Requirements](#system-requirements)
  - [FLEXT Ecosystem Dependencies](#flext-ecosystem-dependencies)
- [Installation](#installation)
  - [Development Installation](#development-installation)
  - [Development Commands](#development-commands)
  - [⚠️ CRITICAL: PYTHONPATH Requirements](#critical-pythonpath-requirements)
- [First Steps](#first-steps)
  - [Basic LDIF Processing](#basic-ldif-processing)
  - [File Operations](#file-operations)
- [Configuration](#configuration)
  - [Basic Configuration](#basic-configuration)
  - [Advanced Configuration](#advanced-configuration)
- [Command Line Interface](#command-line-interface)
  - [CLI Installation and Usage](#cli-installation-and-usage)
  - [CLI Help](#cli-help)
- [Common Use Cases](#common-use-cases)
  - [Generic Schema Parsing with Server Quirks](#generic-schema-parsing-with-server-quirks)
  - [Generic Entry Migration Between Servers](#generic-entry-migration-between-servers)
  - [Working with Multiple Server Types](#working-with-multiple-server-types)
  - [Data Validation and Cleaning](#data-validation-and-cleaning)
- [Troubleshooting](#troubleshooting)
  - [Common Issues](#common-issues)
  - [Getting Help](#getting-help)
- [Next Steps](#next-steps)
- [Related Documentation](#related-documentation)

<!-- TOC END -->

**Version**: 0.9.9 RC | **Updated**: October 10, 2025

This guide provides step-by-step instructions for installing and using FLEXT-LDIF, an RFC 2849/4512 compliant LDIF processing library with server-specific quirks for the FLEXT ecosystem.

## Prerequisites

### System Requirements

- Python 3.13 or higher
- Poetry for dependency management
- Git for source code access
- Sufficient memory for LDIF processing (recommended 4GB+ for files >50MB)

### FLEXT Ecosystem Dependencies

FLEXT-LDIF integrates with the broader FLEXT ecosystem:

- **[flext-core](https://github.com/organization/flext/tree/main/flext-core/README.md)**: Foundation library providing FlextResult, FlextContainer, and logging patterns
- **Poetry**: Dependency management and virtual environment handling
- **Python 3.13+**: Modern Python features including improved type annotations

## Installation

### Development Installation

```bash
# Navigate to the FLEXT-LDIF directory
cd flext-ldif

# Set up development environment
make setup

# Verify installation
python -c "from flext_ldif import FlextLdif; print('FLEXT-LDIF installed successfully')"
```

### Development Commands

```bash
# Essential development workflow
make lint           # Code quality checking with Ruff (ZERO TOLERANCE)
make type-check     # Type safety validation with Pyrefly (MyPy successor)
make test           # Run test suite (990/990 tests passing)
make validate       # Complete validation pipeline (lint + type + security + test)

# Testing commands (⚠️ CRITICAL: Requires PYTHONPATH=src)
PYTHONPATH=src pytest                           # Full test suite
PYTHONPATH=src pytest -m unit                   # Unit tests only
PYTHONPATH=src pytest --cov=src/flext_ldif      # Coverage report
PYTHONPATH=src pytest tests/unit/test_oid.py -v  # Specific test file
```

### ⚠️ CRITICAL: PYTHONPATH Requirements

**ALL test and script execution requires `PYTHONPATH=src`**:

```bash
# ✅ CORRECT
PYTHONPATH=src poetry run pytest tests/unit/test_oid.py -v
PYTHONPATH=src poetry run python -c "from flext_ldif import FlextLdif"

# ❌ WRONG - Will fail with import errors
poetry run pytest tests/unit/test_oid.py -v
python -c "from flext_ldif import FlextLdif"
```

## First Steps

### Basic LDIF Processing

Create your first LDIF processing script:

```python
from flext_ldif import FlextLdif
from pathlib import Path

# Initialize the LDIF API
api = FlextLdif()

# Sample LDIF content
sample_ldif = """dn: cn=John Doe,ou=People,dc=example,dc=com
cn: John Doe
sn: Doe
objectClass: person
objectClass: organizationalPerson
mail: john.doe@example.com

dn: cn=Administrators,ou=Groups,dc=example,dc=com
cn: Administrators
objectClass: groupOfNames
member: cn=John Doe,ou=People,dc=example,dc=com
"""

# Parse LDIF content using FlextResult patterns
result = api.parse_string(sample_ldif)
if result.is_success:
    entries = result.unwrap()
    print(f"Successfully parsed {len(entries)} LDIF entries")

    # Display entry information
    for entry in entries:
        print(f"DN: {entry.dn}")
        print(f"Attributes: {list(entry.attributes.keys())}")
        print("---")
else:
    print(f"Parse failed: {result.error}")
```

### File Operations

Process LDIF files with error handling:

```python
from flext_ldif import FlextLdif
from pathlib import Path

api = FlextLdif()

# Parse LDIF file
ldif_path = Path("directory.ldif")
result = api.parse_file(ldif_path)

if result.is_success:
    entries = result.unwrap()

    # Validate entries
    validation_result = api.validate_entries(entries)
    if validation_result.is_success:
        print("All entries are valid")

        # Write to new file
        output_path = Path("processed_directory.ldif")
        write_result = api.write_file(entries, output_path)
        if write_result.is_success:
            print(f"Successfully wrote {len(entries)} entries to {output_path}")
    else:
        print(f"Validation failed: {validation_result.error}")
else:
    print(f"Failed to parse {ldif_path}: {result.error}")
```

## Configuration

### Basic Configuration

Configure LDIF processing behavior:

```python
from flext_ldif import FlextLdif, FlextLdifModels

# Create configuration
config = FlextLdifModels.Config(
    max_entries=10000,              # Limit number of entries processed
    strict_validation=True,         # Enable strict RFC 2849 validation
    ignore_unknown_attributes=False, # Process all attributes
    encoding='utf-8'                # Character encoding
)

# Initialize API with configuration
api = FlextLdif(config=config)
```

### Advanced Configuration

Access additional configuration options:

```python
from flext_ldif import FlextLdifSettings, get_ldif_config

# Get global configuration
config = get_ldif_config()

# Access configuration settings
print(f"Max entries: {config.max_entries}")
print(f"Strict validation: {config.strict_validation}")
```

## Command Line Interface

### CLI Installation and Usage

FLEXT-LDIF provides a command-line interface for common operations:

```bash
# Parse and validate LDIF file
python -m flext_ldif parse directory.ldif

# Get statistics about LDIF file
python -m flext_ldif analyze directory.ldif

# Filter entries by type
python -m flext_ldif filter --type person directory.ldif
```

### CLI Help

```bash
# Get help for all commands
python -m flext_ldif --help

# Get help for specific command
python -m flext_ldif parse --help
```

## Common Use Cases

### Generic Schema Parsing with Server Quirks

Parse LDAP schema files with automatic server-specific handling:

```python
# ✅ v1.0+ Service imports
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.server import QuirkRegistryService  # Unchanged - quirks subdirectory
from pathlib import Path

# Initialize quirks registry
quirk_registry = QuirkRegistryService()

# Parse OID schema with server-specific quirks
parser = RfcSchemaParserService(
    params={
        "file_path": "oid_schema.ldif",
        "parse_attributes": True,
        "parse_objectclasses": True,
    },
    quirk_registry=quirk_registry,
    server_type="oid",  # Oracle Internet Directory
)

result = parser.execute()
if result.is_success:
    schema_data = result.unwrap()
    attributes = schema_data["attributes"]
    objectclasses = schema_data["objectclasses"]

    print(f"Parsed {len(attributes)} attributes")
    print(f"Parsed {len(objectclasses)} objectClasses")

    # Quirks automatically handle OID-specific extensions
    # Falls back to RFC 4512 for standard attributes

# Works with any LDAP server - OpenLDAP, OUD, AD, etc.
```

### Generic Entry Migration Between Servers

Migrate entries between different LDAP servers using generic transformation:

```python
from flext_ldif.migration_pipeline import FlextLdifMigration
from pathlib import Path

# Initialize migration pipeline with source and target servers
pipeline = FlextLdifMigration(
    input_dir=Path("source_ldifs"),
    output_dir=Path("target_ldifs"),
    source_server_type="oid",    # Source: Oracle Internet Directory
    target_server_type="oud",    # Target: Oracle Unified Directory
)

# Execute generic transformation: OID → RFC → OUD
result = pipeline.execute()
if result.is_success:
    migration_data = result.unwrap()
    print("Migration completed successfully")
    print(f"Entries migrated: {migration_data.get('entries_migrated', 0)}")
    print(f"Schema files: {migration_data.get('schema_files', [])}")

# Generic transformation pipeline:
# 1. Source quirks normalize entries to RFC format
# 2. Target quirks transform from RFC to target format
# 3. Works with ANY server combination (even unknown servers)
```

### Working with Multiple Server Types

Handle entries from different LDAP servers in the same workflow:

```python
from flext_ldif.services.server import QuirkRegistryService

# Initialize registry once
quirk_registry = QuirkRegistryService()

# Get quirks for different servers
openldap = quirk_registry.get_entrys("openldap")
oid = quirk_registry.get_entrys("oid")
ouds = quirk_registry.get_entrys("oud")

# Each quirk knows how to handle server-specific extensions
# All quirks follow the same Protocol interface
# Quirks are tried in priority order (lower number = higher priority)
```

### Data Validation and Cleaning

Validate and clean LDIF data:

```python
api = FlextLdif(FlextLdifModels.Config(strict_validation=True))

# Parse with strict validation
result = api.parse_string(ldif_content)
if result.is_success:
    entries = result.unwrap()

    # Validate all entries
    validation_result = api.validate_entries(entries)
    if validation_result.is_failure:
        print(f"Validation issues found: {validation_result.error}")

    # Continue processing valid entries
    valid_entries = [entry for entry in entries if entry.is_valid()]
    print(f"Processing {len(valid_entries)} valid entries")
```

## Troubleshooting

### Common Issues

**Memory Issues with Large Files**:

- Current version loads entire LDIF into memory
- For files >100MB, consider processing in smaller chunks
- Monitor memory usage during processing

**Parse Errors**:

- Verify LDIF format compliance (RFC 2849)
- Check character encoding (UTF-8 recommended)
- Enable debug logging for detailed error information

**Type Checking Issues**:

- Ensure Python 3.13+ is being used
- Verify all dependencies are properly installed
- Run `make type-check` to identify issues (uses Pyrefly strict mode)
- Check PYTHONPATH=src is set for all operations

### Getting Help

- **Documentation**: Complete documentation
- **API Reference**: API documentation
- **Examples**: Usage examples
- **Issues**: [GitHub Issues](https://github.com/flext-sh/flext-ldif/issues)

## Next Steps

Once you have FLEXT-LDIF installed and working:

1. **Architecture**: Understand the service-oriented design
1. **API Reference**: Explore all available operations
1. **Examples**: See practical usage patterns
1. **Integration**: Learn about FLEXT ecosystem integration

## Related Documentation

**Within Project**:

- Architecture - Service-oriented design and RFC-first approach
- API Reference - Complete API documentation
- Configuration - Settings and environment management
- Development - Contributing and workflows
- Integration Guide - FLEXT ecosystem integration

**Across Projects**:

- [flext-core Foundation](https://github.com/organization/flext/tree/main/flext-core/docs/guides/railway-oriented-programming.md) - Railway-oriented programming patterns
- [flext-ldap Integration](https://github.com/organization/flext/tree/main/flext-ldap/docs/guides/integration.md) - LDAP operations integration

**External Resources**:

- [PEP 257 - Docstring Conventions](https://peps.python.org/pep-0257/)
- [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)

______________________________________________________________________

This getting started guide provides the foundation for using FLEXT-LDIF effectively within the FLEXT ecosystem while maintaining software development practices.
