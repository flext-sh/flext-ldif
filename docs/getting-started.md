# Getting Started with FLEXT-LDIF

**Version**: 0.9.9 RC | **Updated**: September 17, 2025

This guide provides step-by-step instructions for installing and using FLEXT-LDIF, a Python library for processing LDAP Data Interchange Format (LDIF) files within the FLEXT ecosystem.

## Prerequisites

### System Requirements

- Python 3.13 or higher
- Poetry for dependency management
- Git for source code access
- Sufficient memory for LDIF processing (recommended 4GB+ for files >50MB)

### FLEXT Ecosystem Dependencies

FLEXT-LDIF integrates with the broader FLEXT ecosystem:

- **[flext-core](../flext-core/README.md)**: Foundation library providing FlextResult, FlextContainer, and logging patterns
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
python -c "from flext_ldif import FlextLdifAPI; print('FLEXT-LDIF installed successfully')"
```

### Development Commands

```bash
# Essential development workflow
make lint           # Code quality checking with Ruff
make type-check     # Type safety validation with MyPy
make test           # Run test suite
make validate       # Complete validation pipeline

# Testing commands
pytest                          # Full test suite
pytest -m unit                  # Unit tests only
pytest --cov=src/flext_ldif     # Coverage report
```

## First Steps

### Basic LDIF Processing

Create your first LDIF processing script:

```python
from flext_ldif import FlextLdifAPI
from pathlib import Path

# Initialize the LDIF API
api = FlextLdifAPI()

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
from flext_ldif import FlextLdifAPI
from pathlib import Path

api = FlextLdifAPI()

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
from flext_ldif import FlextLdifAPI, FlextLdifModels

# Create configuration
config = FlextLdifModels.Config(
    max_entries=10000,              # Limit number of entries processed
    strict_validation=True,         # Enable strict RFC 2849 validation
    ignore_unknown_attributes=False, # Process all attributes
    encoding='utf-8'                # Character encoding
)

# Initialize API with configuration
api = FlextLdifAPI(config=config)
```

### Advanced Configuration

Access additional configuration options:

```python
from flext_ldif import FlextLdifConfig, get_ldif_config

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

### Enterprise LDAP Migration

Process large directory exports:

```python
from flext_ldif import FlextLdifAPI
from pathlib import Path

api = FlextLdifAPI()

# Process enterprise directory export
export_file = Path("enterprise_directory.ldif")
result = api.parse_file(export_file)

if result.is_success:
    entries = result.unwrap()
    print(f"Processing {len(entries)} directory entries")

    # Filter person entries for user migration
    persons_result = api.filter_persons(entries)
    if persons_result.is_success:
        persons = persons_result.unwrap()
        print(f"Found {len(persons)} user accounts")

        # Generate migration statistics
        stats_result = api.get_entry_statistics(entries)
        if stats_result.is_success:
            stats = stats_result.unwrap()
            print(f"Entry types: {stats}")
```

### Data Validation and Cleaning

Validate and clean LDIF data:

```python
api = FlextLdifAPI(FlextLdifModels.Config(strict_validation=True))

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
- Run `make type-check` to identify issues

### Getting Help

- **Documentation**: [Complete documentation](../docs/)
- **API Reference**: [API documentation](api-reference.md)
- **Examples**: [Usage examples](examples/)
- **Issues**: [GitHub Issues](https://github.com/flext-sh/flext-ldif/issues)

## Next Steps

Once you have FLEXT-LDIF installed and working:

1. **[Architecture](architecture.md)**: Understand the service-oriented design
2. **[API Reference](api-reference.md)**: Explore all available operations
3. **[Examples](examples/)**: See practical usage patterns
4. **[Integration](integration.md)**: Learn about FLEXT ecosystem integration

---

This getting started guide provides the foundation for using FLEXT-LDIF effectively within the FLEXT ecosystem while maintaining software development practices.
