# FLEXT-LDIF API Reference

**Version**: 0.9.9 RC | **Updated**: September 17, 2025

Complete API documentation for FLEXT-LDIF, including all public classes, methods, and integration patterns with the FLEXT ecosystem.

## Core API Classes

### FlextLdifAPI

Main unified interface for all LDIF processing operations.

```python
class FlextLdifAPI:
    """Unified LDIF Processing API."""

    def __init__(self, config: FlextLdifModels.Config | None = None) -> None:
        """Initialize LDIF API with optional configuration."""
```

#### Core Operations

##### parse_file(file_path)

Parse LDIF file into structured entries.

```python
def parse_file(self, file_path: Path | str) -> FlextResult[list[FlextLdifModels.Entry]]:
    """Parse LDIF file using railway-oriented programming.

    Args:
        file_path: Path to LDIF file to parse

    Returns:
        FlextResult containing list of parsed entries or error

    Example:
        >>> api = FlextLdifAPI()
        >>> result = api.parse_file("directory.ldif")
        >>> if result.is_success:
        ...     entries = result.unwrap()
        ...     print(f"Parsed {len(entries)} entries")
    """
```

##### parse_string(content)

Parse LDIF string content into structured entries.

```python
def parse_string(self, content: str) -> FlextResult[list[FlextLdifModels.Entry]]:
    """Parse LDIF string content.

    Args:
        content: LDIF string content to parse

    Returns:
        FlextResult containing parsed entries or error

    Example:
        >>> ldif_content = '''
        ... dn: cn=John Doe,ou=People,dc=example,dc=com
        ... cn: John Doe
        ... objectClass: person
        ... '''
        >>> result = api.parse_string(ldif_content)
        >>> entries = result.unwrap() if result.is_success else []
    """
```

##### validate_entries(entries)

Validate LDIF entries against RFC 2849 and business rules.

```python
def validate_entries(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[bool]:
    """Validate LDIF entries.

    Args:
        entries: List of LDIF entries to validate

    Returns:
        FlextResult[bool] indicating validation success

    Example:
        >>> entries = parse_result.unwrap()
        >>> validation = api.validate_entries(entries)
        >>> if validation.is_success:
        ...     print("All entries are valid")
    """
```

##### write_file(entries, file_path)

Write LDIF entries to file.

```python
def write_file(
    self,
    entries: list[FlextLdifModels.Entry],
    file_path: Path | str
) -> FlextResult[bool]:
    """Write LDIF entries to file.

    Args:
        entries: List of entries to write
        file_path: Output file path

    Returns:
        FlextResult[bool] indicating write success

    Example:
        >>> entries = [...]
        >>> result = api.write_file(entries, "output.ldif")
        >>> if result.is_success:
        ...     print("File written successfully")
    """
```

##### write(entries)

Convert entries to LDIF string format.

```python
def write(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[str]:
    """Convert entries to LDIF string.

    Args:
        entries: List of entries to convert

    Returns:
        FlextResult containing LDIF string or error

    Example:
        >>> result = api.write(entries)
        >>> if result.is_success:
        ...     ldif_content = result.unwrap()
        ...     print(ldif_content)
    """
```

#### Filtering Operations

##### filter_persons(entries)

Filter entries with person object class.

```python
def filter_persons(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[list[FlextLdifModels.Entry]]:
    """Filter person entries from entry list.

    Args:
        entries: List of entries to filter

    Returns:
        FlextResult containing filtered person entries

    Example:
        >>> result = api.filter_persons(all_entries)
        >>> if result.is_success:
        ...     persons = result.unwrap()
        ...     print(f"Found {len(persons)} person entries")
    """
```

##### filter_groups(entries)

Filter entries with group object classes.

```python
def filter_groups(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[list[FlextLdifModels.Entry]]:
    """Filter group entries from entry list.

    Args:
        entries: List of entries to filter

    Returns:
        FlextResult containing filtered group entries

    Example:
        >>> groups_result = api.filter_groups(all_entries)
        >>> groups = groups_result.unwrap() if groups_result.is_success else []
    """
```

##### filter_by_objectclass(entries, object_class)

Filter entries by specific object class.

```python
def filter_by_objectclass(
    self,
    entries: list[FlextLdifModels.Entry],
    object_class: str
) -> FlextResult[list[FlextLdifModels.Entry]]:
    """Filter entries by object class.

    Args:
        entries: List of entries to filter
        object_class: Object class to filter by

    Returns:
        FlextResult containing filtered entries

    Example:
        >>> ou_result = api.filter_by_objectclass(entries, "organizationalUnit")
        >>> organizational_units = ou_result.unwrap() if ou_result.is_success else []
    """
```

#### Analytics Operations

##### get_entry_statistics(entries)

Generate statistics about LDIF entries.

```python
def get_entry_statistics(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[dict[str, int]]:
    """Get statistics about LDIF entries.

    Args:
        entries: List of entries to analyze

    Returns:
        FlextResult containing statistics dictionary

    Example:
        >>> stats_result = api.get_entry_statistics(entries)
        >>> if stats_result.is_success:
        ...     stats = stats_result.unwrap()
        ...     print(f"Object class distribution: {stats}")
    """
```

##### analyze_entries(entries)

Perform comprehensive analysis of LDIF entries.

```python
def analyze_entries(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[dict]:
    """Perform comprehensive entry analysis.

    Args:
        entries: List of entries to analyze

    Returns:
        FlextResult containing analysis results

    Example:
        >>> analysis = api.analyze_entries(entries)
        >>> if analysis.is_success:
        ...     results = analysis.unwrap()
        ...     print(f"Analysis: {results}")
    """
```

## Domain Models

### FlextLdifModels.Entry

Represents an LDIF entry with structured data.

```python
class Entry(BaseModel):
    """LDIF entry domain model."""

    dn: str = Field(..., description="Distinguished Name")
    attributes: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Entry attributes as key-value pairs"
    )

    def get_object_classes(self) -> list[str]:
        """Get object class values for this entry."""

    def get_attribute_values(self, attr_name: str) -> list[str]:
        """Get values for specific attribute."""

    def has_object_class(self, object_class: str) -> bool:
        """Check if entry has specific object class."""

    def is_person(self) -> bool:
        """Check if entry represents a person."""

    def is_group(self) -> bool:
        """Check if entry represents a group."""
```

**Example Usage**:

```python
# Access entry data
entry = entries[0]
print(f"DN: {entry.dn}")
print(f"Common Name: {entry.get_attribute_values('cn')}")
print(f"Object Classes: {entry.get_object_classes()}")

# Check entry type
if entry.is_person():
    print("This is a person entry")
    email = entry.get_attribute_values('mail')
    if email:
        print(f"Email: {email[0]}")
```

### FlextLdifModels.Config

Configuration settings for LDIF processing.

```python
class Config(BaseModel):
    """LDIF processing configuration."""

    max_entries: int | None = Field(
        None,
        description="Maximum number of entries to process"
    )
    strict_validation: bool = Field(
        False,
        description="Enable strict RFC 2849 validation"
    )
    ignore_unknown_attributes: bool = Field(
        True,
        description="Ignore attributes not in standard schema"
    )
    encoding: str = Field(
        "utf-8",
        description="Character encoding for LDIF processing"
    )
    line_separator: str = Field(
        "\n",
        description="Line separator for LDIF output"
    )
```

**Example Usage**:

```python
# Create custom configuration
config = FlextLdifModels.Config(
    max_entries=50000,
    strict_validation=True,
    ignore_unknown_attributes=False,
    encoding='utf-8'
)

# Use configuration with API
api = FlextLdifAPI(config=config)
```

### FlextLdifModels.Factory

Factory methods for creating domain objects.

```python
class Factory:
    """Factory for creating LDIF domain objects."""

    @staticmethod
    def create_entry(dn: str, attributes: dict[str, list[str]]) -> Entry:
        """Create LDIF entry with validation."""

    @staticmethod
    def create_config(**kwargs) -> Config:
        """Create configuration with validation."""

    @staticmethod
    def create_person_entry(
        dn: str,
        cn: str,
        sn: str,
        **additional_attrs
    ) -> Entry:
        """Create person entry with common attributes."""

    @staticmethod
    def create_group_entry(
        dn: str,
        cn: str,
        members: list[str],
        **additional_attrs
    ) -> Entry:
        """Create group entry with members."""
```

**Example Usage**:

```python
# Create entries using factory
person = FlextLdifModels.Factory.create_person_entry(
    dn="cn=John Doe,ou=People,dc=example,dc=com",
    cn="John Doe",
    sn="Doe",
    mail=["john.doe@example.com"]
)

group = FlextLdifModels.Factory.create_group_entry(
    dn="cn=Admins,ou=Groups,dc=example,dc=com",
    cn="Administrators",
    members=["cn=John Doe,ou=People,dc=example,dc=com"]
)
```

## Configuration Management

### Global Configuration

```python
from flext_ldif import FlextLdifConfig, initialize_ldif_config, get_ldif_config

# Initialize global configuration
initialize_ldif_config({
    'max_entries': 100000,
    'strict_validation': True,
    'encoding': 'utf-8'
})

# Access global configuration
config = get_ldif_config()
print(f"Max entries: {config.max_entries}")
```

### Instance Configuration

```python
# Create instance-specific configuration
instance_config = FlextLdifModels.Config(
    max_entries=10000,  # Override global setting
    strict_validation=False
)

# Use with API instance
api = FlextLdifAPI(config=instance_config)
```

## Error Handling

### FlextResult Integration

All API operations return FlextResult for composable error handling:

```python
from flext_core import FlextResult

# Successful operation
result = api.parse_file("valid.ldif")
if result.is_success:
    entries = result.unwrap()
    # Process entries
else:
    error_message = result.error
    print(f"Parse failed: {error_message}")

# Safe value extraction with defaults
entries = result.unwrap_or([])  # Empty list if failed

# Railway-oriented composition
final_result = (
    api.parse_file("input.ldif")
    .flat_map(api.validate_entries)
    .flat_map(lambda entries: api.filter_persons(entries))
    .flat_map(lambda persons: api.write_file(persons, "persons.ldif"))
)
```

### Exception Types

```python
from flext_ldif import (
    FlextLdifError,           # Base LDIF error
    FlextLdifParseError,      # LDIF parsing errors
    FlextLdifValidationError, # Validation errors
    FlextLdifExceptions       # Exception builder
)

# Exception builder pattern
try:
    # Operations that might raise exceptions
    pass
except FlextLdifParseError as e:
    print(f"Parse error: {e}")
except FlextLdifValidationError as e:
    print(f"Validation error: {e}")
```

## Command Line Interface

### CLI Commands

```bash
# Parse and validate LDIF file
python -m flext_ldif parse directory.ldif

# Analyze LDIF file statistics
python -m flext_ldif analyze directory.ldif

# Filter entries by type
python -m flext_ldif filter --type person directory.ldif --output persons.ldif

# Validate LDIF format
python -m flext_ldif validate directory.ldif
```

### Programmatic CLI Access

```python
from flext_ldif import main

# Access CLI functionality programmatically
# main() function provides entry point
```

## Advanced Usage Patterns

### Pipeline Processing

```python
def process_enterprise_directory(input_file: Path, output_file: Path) -> FlextResult[dict]:
    """Process enterprise directory with complete pipeline."""
    api = FlextLdifAPI(FlextLdifModels.Config(strict_validation=True))

    return (
        # Parse directory export
        api.parse_file(input_file)

        # Validate all entries
        .flat_map(lambda entries:
            api.validate_entries(entries).map(lambda _: entries))

        # Extract person entries
        .flat_map(api.filter_persons)

        # Generate statistics
        .flat_map(lambda persons: (
            api.get_entry_statistics(persons)
            .map(lambda stats: {'persons': persons, 'stats': stats})
        ))

        # Write processed entries
        .flat_map(lambda data:
            api.write_file(data['persons'], output_file)
            .map(lambda _: data['stats']))

        # Add error context
        .map_error(lambda error: f"Enterprise processing failed: {error}")
    )
```

### Batch Processing

```python
def process_multiple_files(file_paths: list[Path]) -> FlextResult[dict]:
    """Process multiple LDIF files in batch."""
    api = FlextLdifAPI()
    all_entries = []
    processing_stats = {}

    for file_path in file_paths:
        result = api.parse_file(file_path)
        if result.is_success:
            entries = result.unwrap()
            all_entries.extend(entries)
            processing_stats[str(file_path)] = len(entries)
        else:
            return FlextResult[dict].fail(f"Failed to process {file_path}: {result.error}")

    return FlextResult[dict].ok({
        'total_entries': len(all_entries),
        'file_stats': processing_stats,
        'entries': all_entries
    })
```

### Custom Filtering

```python
def filter_by_custom_criteria(
    api: FlextLdifAPI,
    entries: list[FlextLdifModels.Entry]
) -> FlextResult[list[FlextLdifModels.Entry]]:
    """Apply custom filtering logic."""

    def matches_criteria(entry: FlextLdifModels.Entry) -> bool:
        # Custom business logic
        return (
            entry.has_object_class('person') and
            entry.get_attribute_values('mail') and
            'admin' not in entry.dn.lower()
        )

    try:
        filtered = [entry for entry in entries if matches_criteria(entry)]
        return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)
    except Exception as e:
        return FlextResult[list[FlextLdifModels.Entry]].fail(f"Filtering failed: {e}")
```

## Integration with FLEXT Ecosystem

### FlextContainer Usage

```python
from flext_core import FlextContainer

# Access global container
container = FlextContainer.get_global()

# Register LDIF API as service
api = FlextLdifAPI()
register_result = container.register("ldif_api", api)

# Retrieve from container in other services
api_result = container.get("ldif_api")
if api_result.is_success:
    ldif_api = api_result.unwrap()
```

### FlextLogger Integration

```python
from flext_core import FlextLogger

# Structured logging in LDIF operations
logger = FlextLogger(__name__)

# Log processing operations
logger.info("Starting LDIF processing", extra={
    'file_path': str(input_file),
    'config': config.model_dump()
})

# Log processing results
logger.info("LDIF processing completed", extra={
    'entries_processed': len(entries),
    'processing_time': elapsed_time
})
```

---

This API reference provides complete coverage of FLEXT-LDIF functionality while demonstrating integration with FLEXT ecosystem patterns and professional Python development practices.
