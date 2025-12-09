# FLEXT-LDIF API Reference

**Version**: 0.9.9 | **Updated**: October 10, 2025

Complete API documentation for FLEXT-LDIF, including all public classes, methods, and integration patterns with the FLEXT ecosystem.

## 🎯 Library Overview

**FLEXT-LDIF** is a **library-only** LDIF processing package with NO CLI dependencies. All functionality is exposed through programmatic APIs.

### Generic RFC-Based Architecture with ZERO Bypass Paths

FLEXT-LDIF enforces a **strict RFC-first design** with **mandatory quirks system**:

**Critical Architecture Principles**:

1. ✅ **RFC-First Enforcement**: ALL parse/write/validate operations go through RFC parsers + quirks
2. ✅ **MANDATORY quirk_registry**: All RFC parsers/writers REQUIRE quirk_registry parameter (not Optional)
3. ✅ **Zero Bypass Paths**: NO direct usage of parsers/writers - ALL operations through handlers/facade
4. ✅ **Generic Transformation**: Source → RFC → Target pipeline works with ANY LDAP server
5. ✅ **Library-Only Interface**: NO CLI code, tools, or applications - API-only through FlextLdif facade

**Architecture Benefits**:

- Works with **any LDAP server** (known or unknown) without code changes
- Easy to add support for new servers via quirks (no core changes needed)
- Server-specific code isolated in quirk modules
- Core parsers remain simple, maintainable, and generic
- Guaranteed consistency: all code paths use same RFC + quirks logic

**Supported Servers**:

- ✅ **Complete Implementations** (4): OpenLDAP 1.x/2.x, OID, OUD
- ⚠️ **Stub Implementations** (5): AD, Apache DS, 389DS, Novell, Tivoli (ready for enhancement)
- ✅ **Universal Conversion Matrix**: N×N server conversions via RFC intermediate format
- ✅ **DN Case Registry**: Canonical DN case tracking for OUD compatibility

## Core API Classes

### FlextLdif

Main unified interface for all LDIF processing operations.

```python
class FlextLdif:
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
        >>> api = FlextLdif()
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
def analyze_entries(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[t.Dict]:
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

### QuirksConversionMatrix

Universal facade for N×N server conversions using RFC as intermediate format.

```python
class QuirksConversionMatrix:
    """Facade for universal quirk-to-quirk conversion via RFC intermediate format.

    Enables seamless conversion between any LDAP server quirks using RFC standards
    as the universal intermediate representation.

    Attributes:
        dn_registry: DN case registry for tracking canonical DN case

    """

    def __init__(self) -> None:
        """Initialize conversion matrix with DN case registry."""

    def convert(
        self,
        source: object,
        target: object,
        data_type: Literal["attribute", "objectclass", "acl", "entry"],
        data: str | dict[str, object],
    ) -> FlextResult[str | dict[str, object]]:
        """Convert data from source quirk format to target quirk format via RFC.

        Args:
            source: Source quirk instance (e.g., OUD, OID)
            target: Target quirk instance (e.g., OUD, OID)
            data_type: Type of data - "attribute", "objectclass", "acl", or "entry"
            data: Data to convert (string or dict)

        Returns:
            FlextResult containing converted data in target quirk format

        """

    def batch_convert(
        self,
        source: object,
        target: object,
        data_type: Literal["attribute", "objectclass", "acl", "entry"],
        data_batch: Sequence[str | dict[str, object]],
    ) -> FlextResult[Sequence[str | dict[str, object]]]:
        """Convert batch of data from source to target quirk format via RFC.

        Args:
            source: Source quirk instance
            target: Target quirk instance
            data_type: Type of data being converted
            data_batch: Sequence of data items to convert

        Returns:
            FlextResult containing sequence of converted data items

        """

    def get_supported_conversions(self) -> dict[str, t.StringList]:
        """Get matrix of supported source→target conversions.

        Returns:
            Dict mapping source server types to list of target server types

        """

    def validate_oud_conversion(
        self, converted_data: Sequence[str | dict[str, object]]
    ) -> FlextResult[bool]:
        """Validate converted data for OUD compatibility.

        Args:
            converted_data: Data converted for OUD target

        Returns:
            FlextResult[bool]: Success if OUD-compatible, failure with validation errors

        """

    def reset_dn_registry(self) -> None:
        """Reset DN case registry to initial empty state."""
```

### DnCaseRegistry

Registry for tracking canonical DN case during conversions.

```python
class DnCaseRegistry:
    """Registry for tracking canonical DN case during conversions.

    Maintains a mapping of DNs in normalized form to their canonical case
    representation. Critical for OUD compatibility during server migrations.

    """

    def __init__(self) -> None:
        """Initialize empty DN case registry."""

    def register_dn(self, dn: str, *, force: bool = False) -> str:
        """Register DN and return its canonical case.

        Args:
            dn: Distinguished Name to register
            force: Override existing canonical case with this one

        Returns:
            Canonical case DN string

        """

    def get_canonical_dn(self, dn: str) -> str:
        """Get canonical case for DN, registering if not seen before.

        Args:
            dn: Distinguished Name to get canonical case for

        Returns:
            Canonical case DN string

        """

    def get_stats(self) -> dict[str, int]:
        """Get registry statistics.

        Returns:
            Dict with registry statistics (total_dns, total_variants, etc.)

        """

    def validate_oud_consistency(self) -> FlextResult[bool]:
        """Validate registry for OUD case-sensitive consistency.

        Returns:
            FlextResult[bool]: Success if no case conflicts, failure with conflicts

        """

    def get_case_variants(self, normalized_dn: str) -> set[str]:
        """Get all case variants seen for a normalized DN.

        Args:
            normalized_dn: Normalized DN to get variants for

        Returns:
            Set of all case variants seen for this DN

        """

    def merge_registry(self, other: DnCaseRegistry) -> None:
        """Merge another registry into this one.

        Args:
            other: Registry to merge from

        """
```

## Domain Models

### FlextLdifModels.Entry

Represents an LDIF entry with structured data.

```python
class Entry(BaseModel):
    """LDIF entry domain model."""

    dn: str = Field(..., description="Distinguished Name")
    attributes: dict[str, t.StringList] = Field(
        default_factory=dict,
        description="Entry attributes as key-value pairs"
    )

    def get_object_classes(self) -> t.StringList:
        """Get object class values for this entry."""

    def get_attribute_values(self, attr_name: str) -> t.StringList:
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
api = FlextLdif(config=config)
```

### FlextLdifModels.Factory

Factory methods for creating domain objects.

```python
class Factory:
    """Factory for creating LDIF domain objects."""

    @staticmethod
    def create(data: t.Dict | str, attributes: dict[str, t.StringList] | None = None) -> Entry:
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
        members: t.StringList,
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
api = FlextLdif(config=instance_config)
```

## Error Handling

### FlextResult Integration

All API operations return FlextResult for composable error handling:

```python
from flext_core import FlextBus
from flext_core import FlextConfig
from flext_core import FlextConstants
from flext_core import FlextContainer
from flext_core import FlextContext
from flext_core import FlextDecorators
from flext_core import FlextDispatcher
from flext_core import FlextExceptions
from flext_core import h
from flext_core import FlextLogger
from flext_core import x
from flext_core import FlextModels
from flext_core import FlextProcessors
from flext_core import p
from flext_core import FlextRegistry
from flext_core import FlextResult
from flext_core import FlextRuntime
from flext_core import FlextService
from flext_core import t
from flext_core import u

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

## ⚠️ Library-Only Usage

**IMPORTANT**: FLEXT-LDIF is a **library-only** package with NO CLI. All functionality must be accessed programmatically through the API.

**Migration from CLI to API**:

```python
# ❌ OLD (CLI - no longer available):
# python -m flext_ldif parse directory.ldif

# ✅ NEW (Library API):
from flext_ldif import FlextLdif
from pathlib import Path

api = FlextLdif()
result = api.parse_file(Path("directory.ldif"))
if result.is_success:
    entries = result.unwrap()
    print(f"Parsed {len(entries)} entries")

# ❌ OLD (CLI - no longer available):
# python -m flext_ldif analyze directory.ldif

# ✅ NEW (Library API):
result = api.parse_file(Path("directory.ldif"))
if result.is_success:
    entries = result.unwrap()
    stats_result = api.get_entry_statistics(entries)
    if stats_result.is_success:
        stats = stats_result.unwrap()
        print(f"Statistics: {stats}")

# ❌ OLD (CLI - no longer available):
# python -m flext_ldif filter --type person directory.ldif

# ✅ NEW (Library API):
result = api.parse_file(Path("directory.ldif"))
if result.is_success:
    entries = result.unwrap()
    persons_result = api.filter_persons(entries)
    if persons_result.is_success:
        persons = persons_result.unwrap()
        print(f"Found {len(persons)} person entries")
```

## Advanced Usage Patterns

### Pipeline Processing

```python
def process_enterprise_directory(input_file: Path, output_file: Path) -> FlextResult[t.Dict]:
    """Process enterprise directory with complete pipeline."""
    api = FlextLdif(FlextLdifModels.Config(strict_validation=True))

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
def process_multiple_files(file_paths: list[Path]) -> FlextResult[t.Dict]:
    """Process multiple LDIF files in batch."""
    api = FlextLdif()
    all_entries = []
    processing_stats = {}

    for file_path in file_paths:
        result = api.parse_file(file_path)
        if result.is_success:
            entries = result.unwrap()
            all_entries.extend(entries)
            processing_stats[str(file_path)] = len(entries)
        else:
            return FlextResult[t.Dict].fail(f"Failed to process {file_path}: {result.error}")

    return FlextResult[t.Dict].ok({
        'total_entries': len(all_entries),
        'file_stats': processing_stats,
        'entries': all_entries
    })
```

### Custom Filtering

```python
def filter_by_custom_criteria(
    api: FlextLdif,
    entries: list[FlextLdifModels.Entry]
) -> FlextResult[list[FlextLdifModels.Entry]]:
    """Apply custom filtering logic."""

    def matches_criteria(entry: FlextLdifModels.Entry) -> bool:
        # Custom business logic
        return (
            entry.has_object_class('person') and
            entry.get_attribute_values('mail') and
            'REDACTED_LDAP_BIND_PASSWORD' not in entry.dn.lower()
        )

    try:
        filtered = [entry for entry in entries if matches_criteria(entry)]
        return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)
    except Exception as e:
        return FlextResult[list[FlextLdifModels.Entry]].fail(f"Filtering failed: {e}")
```

## RFC Schema Parser API

### RfcSchemaParserService

Parse LDAP schema definitions with RFC 4512 compliance and **MANDATORY quirks support**.

```python
# ✅ v1.0+ Flat imports
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.server import QuirkRegistryService  # Unchanged - quirks subdirectory

class RfcSchemaParserService:
    """RFC 4512 compliant schema parser with MANDATORY quirks integration."""

    def __init__(
        self,
        *,
        params: dict,
        quirk_registry: QuirkRegistryService,  # ⚠️ MANDATORY parameter
        server_type: str | None = None,
    ) -> None:
        """Initialize RFC schema parser.

        Args:
            params: Parsing parameters (file_path, parse_attributes, parse_objectclasses)
            quirk_registry: ⚠️ MANDATORY quirk registry for RFC-first architecture
            server_type: Optional server type to select specific quirks (None = pure RFC)
        """

    def execute(self) -> FlextResult[t.Dict]:
        """Execute RFC-compliant schema parsing with quirks.

        Returns:
            FlextResult with parsed schema data containing:
                - attributes: Dict of attribute definitions by name
                - objectclasses: Dict of objectClass definitions by name
                - source_dn: DN of schema subentry
                - stats: Parsing statistics
        """
```

**⚠️ CRITICAL: quirk_registry is MANDATORY**

The `quirk_registry` parameter is **MANDATORY** (not Optional) to enforce RFC-first architecture with zero bypass paths.

**Example Usage**:

```python
# ✅ CORRECT: v1.0+ flat imports with MANDATORY quirk_registry
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.server import QuirkRegistryService

# Initialize registry FIRST (auto-discovers all standard quirks)
quirk_registry = QuirkRegistryService()

# Parse with OID quirks
oid_parser = RfcSchemaParserService(
    params={
        "file_path": "oid_schema.ldif",
        "parse_attributes": True,
        "parse_objectclasses": True,
    },
    quirk_registry=quirk_registry,  # ⚠️ MANDATORY parameter
    server_type="oid",  # Selects OID-specific quirks
)

result = oid_parser.execute()
if result.is_success:
    schema_data = result.unwrap()
    print(f"Attributes: {len(schema_data['attributes'])}")
    print(f"ObjectClasses: {len(schema_data['objectclasses'])}")

# ✅ CORRECT: Parse pure RFC 4512 (still requires quirk_registry)
rfc_parser = RfcSchemaParserService(
    params={"file_path": "standard_schema.ldif"},
    quirk_registry=quirk_registry,  # ⚠️ MANDATORY even for pure RFC
    server_type=None,  # None = no server-specific quirks, pure RFC baseline
)

# ❌ INCORRECT: Omitting quirk_registry (will cause errors)
# parser = RfcSchemaParserService(params={"file_path": "schema.ldif"})
```

**Why quirk_registry is MANDATORY**:

1. **Enforces RFC-first architecture** - Zero bypass paths guarantee
2. **Enables generic transformation** - Source → RFC → Target pipeline requires registry
3. **Auto-discovery** - QuirkRegistryService automatically discovers all standard quirks
4. **Future-proof** - New servers can be added without API changes

## Migration Pipeline API

### FlextLdifMigration

Generic LDIF migration between different LDAP servers.

```python
from flext_ldif.migration_pipeline import FlextLdifMigration
from pathlib import Path

class FlextLdifMigration:
    """Generic LDIF migration pipeline using quirks-based transformation."""

    def __init__(
        self,
        input_dir: Path,
        output_dir: Path,
        source_server_type: str,
        target_server_type: str,
    ) -> None:
        """Initialize migration pipeline.

        Args:
            input_dir: Source LDIF directory
            output_dir: Target LDIF directory
            source_server_type: Source server type (e.g., "oid", "openldap")
            target_server_type: Target server type (e.g., "oud", "openldap")
        """

    def execute(self) -> FlextResult[t.Dict]:
        """Execute migration pipeline.

        Generic transformation process:
        1. Parse source LDIF files
        2. Migrate schema (source → RFC → target)
        3. Migrate entries (source → RFC → target)
        4. Write target LDIF files

        Returns:
            FlextResult with migration results containing:
                - entries_migrated: Number of entries migrated
                - schema_files: List of schema files processed
                - output_files: List of generated output files
        """
```

**Example Usage**:

```python
# OID to OUD migration
pipeline = FlextLdifMigration(
    input_dir=Path("source_oid"),
    output_dir=Path("target_oud"),
    source_server_type="oid",
    target_server_type="oud",
)

result = pipeline.execute()
if result.is_success:
    data = result.unwrap()
    print(f"Migrated {data['entries_migrated']} entries")
    print(f"Schema files: {data['schema_files']}")

# Works with any server combination
# OpenLDAP to OUD, AD to 389 DS, etc.
```

## Quirks Registry API

### QuirkRegistryService

Central registry for managing server-specific quirks.

```python
from flext_ldif.services.server import QuirkRegistryService

class QuirkRegistryService:
    """Registry for managing LDAP server quirks."""

    def get_schemas(self, server_type: str) -> list[SchemaProtocol]:
        """Get schema quirks for server type.

        Args:
            server_type: Server type identifier

        Returns:
            List of schema quirks sorted by priority
        """

    def get_entrys(self, server_type: str) -> list[EntryProtocol]:
        """Get entry quirks for server type.

        Args:
            server_type: Server type identifier

        Returns:
            List of entry quirks sorted by priority
        """

    def get_acls(self, server_type: str) -> list[AclProtocol]:
        """Get ACL quirks for server type.

        Args:
            server_type: Server type identifier

        Returns:
            List of ACL quirks sorted by priority
        """
```

**Example Usage**:

```python
# Initialize registry
registry = QuirkRegistryService()

# Get quirks for different servers
oid_schemas = registry.get_schemas("oid")
oud_entrys = registry.get_entrys("oud")
openldap_acls = registry.get_acls("openldap")

# Quirks are automatically sorted by priority
# Lower priority number = higher precedence
```

## Integration with FLEXT Ecosystem

### FlextContainer Usage

```python
from flext_core import FlextBus
from flext_core import FlextConfig
from flext_core import FlextConstants
from flext_core import FlextContainer
from flext_core import FlextContext
from flext_core import FlextDecorators
from flext_core import FlextDispatcher
from flext_core import FlextExceptions
from flext_core import h
from flext_core import FlextLogger
from flext_core import x
from flext_core import FlextModels
from flext_core import FlextProcessors
from flext_core import p
from flext_core import FlextRegistry
from flext_core import FlextResult
from flext_core import FlextRuntime
from flext_core import FlextService
from flext_core import t
from flext_core import u

# Access global container
container = FlextContainer.get_global()

# Register LDIF API as service
api = FlextLdif()
register_result = container.register("ldif_api", api)

# Retrieve from container in other services
api_result = container.get("ldif_api")
if api_result.is_success:
    ldif_api = api_result.unwrap()
```

### FlextLogger Integration

```python
from flext_core import FlextBus
from flext_core import FlextConfig
from flext_core import FlextConstants
from flext_core import FlextContainer
from flext_core import FlextContext
from flext_core import FlextDecorators
from flext_core import FlextDispatcher
from flext_core import FlextExceptions
from flext_core import h
from flext_core import FlextLogger
from flext_core import x
from flext_core import FlextModels
from flext_core import FlextProcessors
from flext_core import p
from flext_core import FlextRegistry
from flext_core import FlextResult
from flext_core import FlextRuntime
from flext_core import FlextService
from flext_core import t
from flext_core import u

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

## 🚀 Quick Start Guide

### Basic Usage - Parse, Validate, Write

```python
from flext_ldif import FlextLdif
from pathlib import Path

# Initialize API (library-only, no CLI)
api = FlextLdif()

# Parse LDIF file
parse_result = api.parse_file(Path("directory.ldif"))
if parse_result.is_failure:
    print(f"Parse failed: {parse_result.error}")
    exit(1)

entries = parse_result.unwrap()
print(f"✅ Parsed {len(entries)} entries")

# Validate entries
validation_result = api.validate_entries(entries)
if validation_result.is_failure:
    print(f"Validation failed: {validation_result.error}")
    exit(1)

print("✅ All entries valid")

# Filter person entries
persons_result = api.filter_persons(entries)
if persons_result.is_success:
    persons = persons_result.unwrap()
    print(f"✅ Found {len(persons)} person entries")

# Write filtered results
write_result = api.write_file(persons, Path("persons_only.ldif"))
if write_result.is_success:
    print("✅ Written persons_only.ldif")
```

### Server-Specific Parsing with Quirks

```python
# ✅ v1.0+ Flat imports
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.server import QuirkRegistryService  # Unchanged - quirks subdirectory

# ⚠️ MANDATORY: Initialize quirk registry first
quirk_registry = QuirkRegistryService()

# Parse OID schema with OID-specific quirks
oid_parser = RfcSchemaParserService(
    params={
        "file_path": "oid_schema.ldif",
        "parse_attributes": True,
        "parse_objectclasses": True,
    },
    quirk_registry=quirk_registry,  # MANDATORY parameter
    server_type="oid",  # Oracle Internet Directory quirks
)

result = oid_parser.execute()
if result.is_success:
    schema = result.unwrap()
    print(f"✅ Parsed {len(schema['attributes'])} attributes")
    print(f"✅ Parsed {len(schema['objectclasses'])} objectClasses")

# Parse OpenLDAP schema with OpenLDAP quirks
openldap_parser = RfcSchemaParserService(
    params={"file_path": "openldap_schema.ldif"},
    quirk_registry=quirk_registry,  # MANDATORY parameter
    server_type="openldap",  # OpenLDAP 2.x quirks
)

# Parse pure RFC 4512 (no server-specific quirks)
rfc_parser = RfcSchemaParserService(
    params={"file_path": "standard_schema.ldif"},
    quirk_registry=quirk_registry,  # MANDATORY even for pure RFC
    server_type=None,  # None = pure RFC baseline
)
```

### Generic Migration Pipeline

```python
from flext_ldif.migration_pipeline import FlextLdifMigration
from pathlib import Path

# Migrate OID → OUD using generic transformation pipeline
migration = FlextLdifMigration(
    input_dir=Path("source_oid_ldif"),
    output_dir=Path("target_oud_ldif"),
    source_server_type="oid",     # Oracle Internet Directory
    target_server_type="oud",     # Oracle Unified Directory
)

# Execute migration: OID → RFC → OUD
result = migration.execute()
if result.is_success:
    data = result.unwrap()
    print(f"✅ Migrated {data['entries_migrated']} entries")
    print(f"✅ Processed {len(data['schema_files'])} schema files")
    print(f"✅ Generated {len(data['output_files'])} output files")
else:
    print(f"❌ Migration failed: {result.error}")

# Works with ANY server combination (N implementations, not N²)
# Examples: OID→OUD, OpenLDAP→389DS, AD→OUD, OUD→OpenLDAP, etc.
```

### Railway-Oriented Pipeline

```python
from flext_ldif import FlextLdif
from pathlib import Path

api = FlextLdif()

# Composable pipeline with explicit error handling
result = (
    # Parse LDIF file
    api.parse_file(Path("directory.ldif"))

    # Validate all entries
    .flat_map(lambda entries:
        api.validate_entries(entries).map(lambda _: entries))

    # Filter person entries
    .flat_map(api.filter_persons)

    # Generate statistics
    .flat_map(lambda persons:
        api.get_entry_statistics(persons)
        .map(lambda stats: {"persons": persons, "stats": stats}))

    # Write filtered entries
    .flat_map(lambda data:
        api.write_file(data["persons"], Path("persons.ldif"))
        .map(lambda _: data["stats"]))

    # Add error context
    .map_error(lambda error: f"Processing failed: {error}")
)

# Handle final result
if result.is_success:
    stats = result.unwrap()
    print(f"✅ Pipeline completed: {stats}")
else:
    print(f"❌ Pipeline failed: {result.error}")
```

### Supported LDAP Servers

**Complete Implementations** (4 servers):

```python
# Oracle Internet Directory
server_type="oid"

# Oracle Unified Directory
server_type="oud"

# OpenLDAP 2.x
server_type="openldap"

# OpenLDAP 1.x
server_type="openldap1"
```

**Stub Implementations** (5 servers - ready for enhancement):

```python
# Active Directory (stub - not implemented)
server_type="ad"

# Apache Directory Server (stub - not implemented)
server_type="apache"

# 389 Directory Server (stub - not implemented)
server_type="389ds"

# Novell eDirectory (stub - not implemented)
server_type="novell"

# IBM Tivoli Directory Server (stub - not implemented)
server_type="tivoli"
```

**Generic/Unknown Servers**:

```python
# Works with ANY LDAP server using pure RFC baseline
server_type=None  # Pure RFC 2849/4512 compliance
server_type="my_custom_ldap_v5"  # Unknown server = RFC baseline
```

---

This API reference provides complete coverage of FLEXT-LDIF functionality, including the library-only interface, RFC-first architecture with MANDATORY quirk_registry, generic migration pipeline, and comprehensive quirks system, while demonstrating integration with FLEXT ecosystem patterns and professional Python development practices.

## Related Documentation

**Within Project**:
- [Getting Started](getting-started.md) - Installation and basic usage
- [Architecture](architecture.md) - Architecture and design patterns
- [Examples](../examples/) - Practical usage patterns

**Across Projects**:
- [flext-core Foundation](https://github.com/organization/flext/tree/main/flext-core/docs/api-reference/foundation.md) - Core APIs and patterns
- [flext-ldap Operations](https://github.com/organization/flext/tree/main/flext-ldap/docs/api-reference.md) - LDAP operations API
- [flext-meltano Pipelines](https://github.com/organization/flext/tree/main/flext-meltano/CLAUDE.md) - Data integration and ELT orchestration

**External Resources**:
- [RFC 2849 - The LDAP Data Interchange Format (LDIF)](https://www.rfc-editor.org/rfc/rfc2849.html)
- [RFC 4512 - LDAP: Technical Specification Road Map](https://www.rfc-editor.org/rfc/rfc4512.html)
