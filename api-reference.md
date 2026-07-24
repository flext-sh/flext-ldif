# FLEXT-LDIF API Reference

<!-- TOC START -->
- [🎯 Library Overview](#library-overview)
  - [Generic RFC-Based Architecture with ZERO Bypass Paths](#generic-rfc-based-architecture-with-zero-bypass-paths)
- [Core API Classes](#core-api-classes)
  - [ldif](#ldif)
  - [ServersConversionMatrix](#serversconversionmatrix)
  - [DnCaseRegistry](#dncaseregistry)
- [Domain Models](#domain-models)
  - [FlextLdifModels.Entry](#flextldifmodelsentry)
  - [FlextLdifModels.Config](#flextldifmodelsconfig)
  - [FlextLdifModels.Factory](#flextldifmodelsfactory)
- [Configuration Management](#configuration-management)
  - [Global Configuration](#global-configuration)
  - [Instance Configuration](#instance-configuration)
- [Error Handling](#error-handling)
  - [r Integration](#r-integration)
  - [Exception Types](#exception-types)
- [⚠️ Library-Only Usage](#library-only-usage)
- [Advanced Usage Patterns](#advanced-usage-patterns)
  - [Pipeline Processing](#pipeline-processing)
  - [Batch Processing](#batch-processing)
  - [Custom Filtering](#custom-filtering)
- [RFC Schema Parser API](#rfc-schema-parser-api)
  - [RfcSchemaParserService](#rfcschemaparserservice)
- [Migration Pipeline API](#migration-pipeline-api)
  - [FlextLdifMigration](#flextldifmigration)
- [Servers Registry API](#servers-registry-api)
  - [ServerRegistryService](#serverregistryservice)
- [Integration with FLEXT Ecosystem](#integration-with-flext-ecosystem)
  - [FlextContainer Usage](#flextcontainer-usage)
  - [FlextLogger Integration](#flextlogger-integration)
- [🚀 Quick Start Guide](#quick-start-guide)
  - [Basic Usage - Parse, Validate, Write](#basic-usage-parse-validate-write)
  - [Server-Specific Parsing with Servers](#server-specific-parsing-with-servers)
  - [Generic Migration Pipeline](#generic-migration-pipeline)
  - [Railway-Oriented Pipeline](#railway-oriented-pipeline)
  - [Supported LDAP Servers](#supported-ldap-servers)
- [Related Documentation](#related-documentation)
<!-- TOC END -->

**Version**: 0.9.9 | **Updated**: October 10, 2025

Complete API documentation for FLEXT-LDIF, including all public classes, methods, and integration patterns with the FLEXT ecosystem.

## 🎯 Library Overview

**FLEXT-LDIF** is a **library-only** LDIF processing package with NO CLI dependencies. All functionality is exposed through programmatic APIs.

### Generic RFC-Based Architecture with ZERO Bypass Paths

FLEXT-LDIF enforces a **strict RFC-first design** with **mandatory servers system**:

**Critical Architecture Principles**:

1. ✅ **RFC-First Enforcement**: ALL parse/write/validate operations go through RFC parsers + servers
1. ✅ **MANDATORY server_registry**: All RFC parsers/writers REQUIRE server_registry parameter (not Optional)
1. ✅ **Zero Bypass Paths**: NO direct usage of parsers/writers - ALL operations through handlers/facade
1. ✅ **Generic Transformation**: Source → RFC → Target pipeline works with ANY LDAP server
1. ✅ **Library-Only Interface**: NO CLI code, tools, or applications - API-only through ldif facade

**Architecture Benefits**:

- Works with **any LDAP server** (known or unknown) without code changes
- Easy to add support for new servers via servers (no core changes needed)
- Server-specific code isolated in server modules
- Core parsers remain simple, maintainable, and generic
- Guaranteed consistency: all code paths use same RFC + servers logic

**Supported Servers**:

- ✅ **Complete Implementations** (4): OpenLDAP 1.x/2.x, OID, OUD
- ⚠️ **Stub Implementations** (5): AD, Apache DS, 389DS, Novell, Tivoli (ready for enhancement)
- ✅ **Universal Conversion Matrix**: N×N server conversions via RFC intermediate format
- ✅ **DN Case Registry**: Canonical DN case tracking for OUD compatibility

## Core API Classes

### ldif

Main unified interface for all LDIF processing operations.

```text
class ldif:
    """Unified LDIF Processing API."""

    def __init__(self, settings: FlextLdifModels.Config | None = None) -> None:
        """Initialize LDIF API with optional configuration."""
```

#### Core Operations

##### parse_file(file_path)

Parse LDIF file into structured entries.

```text
def parse_file(
    self, file_path: Path | str
) -> p.Result[Sequence[FlextLdifModels.Entry]]:
    """Parse LDIF file using railway-oriented programming.

    Args:
        file_path: Path to LDIF file to parse

    Returns:
        r containing list of parsed entries or error

    Example:
        >>> api = ldif()
        >>> result = api.parse_file("directory.ldif")
        >>> if result.success:
        ...     entries = result.unwrap()
        ...     u.Cli.print(f"Parsed {len(entries)} entries")
    """
```

##### parse_string(content)

Parse LDIF string content into structured entries.

```text
def parse_string(self, content: str) -> p.Result[Sequence[FlextLdifModels.Entry]]:
    """Parse LDIF string content.

    Args:
        content: LDIF string content to parse

    Returns:
        r containing parsed entries or error

    Example:
        >>> ldif_content = '''
        ... dn: cn=John Doe,ou=People,dc=example,dc=com
        ... cn: John Doe
        ... objectClass: person
        ... '''
        >>> result = api.parse_string(ldif_content)
        >>> entries = result.unwrap() if result.success else []
    """
```

##### validate_entries(entries)

Validate LDIF entries against RFC 2849 and business rules.

```text
def validate_entries(self, entries: t.SequenceOf[FlextLdifModels.Entry]) -> p.Result[bool]:
    """Validate LDIF entries.

    Args:
        entries: List of LDIF entries to validate

    Returns:
        r[bool] indicating validation success

    Example:
        >>> entries = parse_result.unwrap()
        >>> validation = api.validate_entries(entries)
        >>> if validation.success:
        ...     u.Cli.print("All entries are valid")
    """
```

##### write_file(entries, file_path)

Write LDIF entries to file.

```text
def write_file(
    self, entries: t.SequenceOf[FlextLdifModels.Entry], file_path: Path | str
) -> p.Result[bool]:
    """Write LDIF entries to file.

    Args:
        entries: List of entries to write
        file_path: Output file path

    Returns:
        r[bool] indicating write success

    Example:
        >>> entries = [...]
        >>> result = api.write_file(entries, "output.ldif")
        >>> if result.success:
        ...     u.Cli.print("File written successfully")
    """
```

##### write(entries)

Convert entries to LDIF string format.

```text
def write(self, entries: t.SequenceOf[FlextLdifModels.Entry]) -> p.Result[str]:
    """Convert entries to LDIF string.

    Args:
        entries: List of entries to convert

    Returns:
        r containing LDIF string or error

    Example:
        >>> result = api.write(entries)
        >>> if result.success:
        ...     ldif_content = result.unwrap()
        ...     u.Cli.print(ldif_content)
    """
```

#### Filtering Operations

##### filter_persons(entries)

Filter entries with person object class.

```text
def filter_persons(
    self, entries: t.SequenceOf[FlextLdifModels.Entry]
) -> p.Result[Sequence[FlextLdifModels.Entry]]:
    """Filter person entries from entry list.

    Args:
        entries: List of entries to filter

    Returns:
        r containing filtered person entries

    Example:
        >>> result = api.filter_persons(all_entries)
        >>> if result.success:
        ...     persons = result.unwrap()
        ...     u.Cli.print(f"Found {len(persons)} person entries")
    """
```

##### filter_groups(entries)

Filter entries with group object classes.

```text
def filter_groups(
    self, entries: t.SequenceOf[FlextLdifModels.Entry]
) -> p.Result[Sequence[FlextLdifModels.Entry]]:
    """Filter group entries from entry list.

    Args:
        entries: List of entries to filter

    Returns:
        r containing filtered group entries

    Example:
        >>> groups_result = api.filter_groups(all_entries)
        >>> groups = groups_result.unwrap() if groups_result.success else []
    """
```

##### filter_by_objectclass(entries, object_class)

Filter entries by specific object class.

```text
def filter_by_objectclass(
    self, entries: t.SequenceOf[FlextLdifModels.Entry], object_class: str
) -> p.Result[Sequence[FlextLdifModels.Entry]]:
    """Filter entries by object class.

    Args:
        entries: List of entries to filter
        object_class: Object class to filter by

    Returns:
        r containing filtered entries

    Example:
        >>> ou_result = api.filter_by_objectclass(entries, "organizationalUnit")
        >>> organizational_units = ou_result.unwrap() if ou_result.success else []
    """
```

#### Analytics Operations

##### get_entry_statistics(entries)

Generate statistics about LDIF entries.

```text
def get_entry_statistics(
    self, entries: t.SequenceOf[FlextLdifModels.Entry]
) -> p.Result[t.IntMapping]:
    """Get statistics about LDIF entries.

    Args:
        entries: List of entries to analyze

    Returns:
        r containing statistics dictionary

    Example:
        >>> stats_result = api.get_entry_statistics(entries)
        >>> if stats_result.success:
        ...     stats = stats_result.unwrap()
        ...     u.Cli.print(f"Object class distribution: {stats}")
    """
```

##### analyze_entries(entries)

Perform comprehensive analysis of LDIF entries.

```text
def analyze_entries(self, entries: t.SequenceOf[FlextLdifModels.Entry]) -> p.Result[m.Dict]:
    """Perform comprehensive entry analysis.

    Args:
        entries: List of entries to analyze

    Returns:
        r containing analysis results

    Example:
        >>> analysis = api.analyze_entries(entries)
        >>> if analysis.success:
        ...     results = analysis.unwrap()
        ...     u.Cli.print(f"Analysis: {results}")
    """
```

### ServersConversionMatrix

Universal facade for N×N server conversions using RFC as intermediate format.

```text
class ServersConversionMatrix:
    """Facade for universal server-to-server conversion via RFC intermediate format.

    Enables seamless conversion between any LDAP server servers using RFC standards
    as the universal intermediate representation.

    Attributes:
        dn_registry: DN case registry for tracking canonical DN case

    """

    def __init__(self) -> None:
        """Initialize conversion matrix with DN case registry."""

    def convert(
        self,
        source,
        target,
        data_type: Literal["attribute", "objectclass", "acl", "entry"],
        data: str | t.JsonMapping,
    ) -> p.Result[str | t.JsonMapping]:
        """Convert data from source server format to target server format via RFC.

        Args:
            source: Source server instance (e.g., OUD, OID)
            target: Target server instance (e.g., OUD, OID)
            data_type: Type of data - "attribute", "objectclass", "acl", or "entry"
            data: Data to convert (string or dict)

        Returns:
            r containing converted data in target server format

        """

    def batch_convert(
        self,
        source,
        target,
        data_type: Literal["attribute", "objectclass", "acl", "entry"],
        data_batch: t.SequenceOf[str | t.JsonMapping],
    ) -> p.Result[Sequence[str | t.JsonMapping]]:
        """Convert batch of data from source to target server format via RFC.

        Args:
            source: Source server instance
            target: Target server instance
            data_type: Type of data being converted
            data_batch: Sequence of data items to convert

        Returns:
            r containing sequence of converted data items

        """

    def get_supported_conversions(self) -> t.MappingKV[str, t.StringList]:
        """Get matrix of supported source→target conversions.

        Returns:
            Dict mapping source server types to list of target server types

        """

    def validate_oud_conversion(
        self, converted_data: t.SequenceOf[str | t.JsonMapping]
    ) -> p.Result[bool]:
        """Validate converted data for OUD compatibility.

        Args:
            converted_data: Data converted for OUD target

        Returns:
            r[bool]: Success if OUD-compatible, failure with validation errors

        """

    def reset_dn_registry(self) -> None:
        """Reset DN case registry to initial empty state."""
```

### DnCaseRegistry

Registry for tracking canonical DN case during conversions.

```text
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

    def get_stats(self) -> t.IntMapping:
        """Get registry statistics.

        Returns:
            Dict with registry statistics (total_dns, total_variants, etc.)

        """

    def validate_oud_consistency(self) -> p.Result[bool]:
        """Validate registry for OUD case-sensitive consistency.

        Returns:
            r[bool]: Success if no case conflicts, failure with conflicts

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

```text
class Entry(m.BaseModel):
    """LDIF entry domain model."""

    dn: str = u.Field(..., description="Distinguished Name")
    attributes: t.MappingKV[str, t.StringList] = u.Field(
        default_factory=lambda: MappingProxyType({}),
        description="Entry attributes as key-value pairs",
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

```python notest
# Access entry data
entry = entries[0]
u.Cli.print(f"DN: {entry.dn}")
u.Cli.print(f"Common Name: {entry.get_attribute_values('cn')}")
u.Cli.print(f"Object Classes: {entry.get_object_classes()}")

# Check entry type
if entry.is_person():
    u.Cli.print("This is a person entry")
    email = entry.get_attribute_values("mail")
    if email:
        u.Cli.print(f"Email: {email[0]}")
```

### FlextLdifModels.Config

Configuration settings for LDIF processing.

```text
class Config(m.BaseModel):
    """LDIF processing configuration."""

    max_entries: int | None = u.Field(
        None, description="Maximum number of entries to process"
    )
    strict_validation: bool = u.Field(
        False, description="Enable strict RFC 2849 validation"
    )
    ignore_unknown_attributes: bool = u.Field(
        True, description="Ignore attributes not in standard schema"
    )
    encoding: str = u.Field(
        "utf-8", description="Character encoding for LDIF processing"
    )
    line_separator: str = u.Field("\n", description="Line separator for LDIF output")
```

**Example Usage**:

```python notest
# Create custom configuration
settings = FlextLdifModels.Config(
    max_entries=50000,
    strict_validation=True,
    ignore_unknown_attributes=False,
    encoding="utf-8",
)

# Use configuration with API
api = ldif(settings=settings)
```

### FlextLdifModels.Factory

Factory methods for creating domain objects.

```python notest
from __future__ import annotations

from collections.abc import Mapping

from flext_ldif import FlextLdifModels, m, t


class Factory:
    """Factory for creating LDIF domain objects."""

    @staticmethod
    def create(
        data: m.Dict | str, attributes: t.MappingKV[str, t.StringList] | None = None
    ) -> Entry:
        """Create LDIF entry with validation."""

    @staticmethod
    def create_config(**kwargs) -> Config:
        """Create configuration with validation."""

    @staticmethod
    def create_person_entry(dn: str, cn: str, sn: str, **additional_attrs) -> Entry:
        """Create person entry with common attributes."""

    @staticmethod
    def create_group_entry(
        dn: str, cn: str, members: t.StringList, **additional_attrs
    ) -> Entry:
        """Create group entry with members."""
```

**Example Usage**:

```python notest
from flext_ldif import FlextLdifModels

# Create entries directly with the public Entry model
person = FlextLdifModels.Entry(
    dn="cn=John Doe,ou=People,dc=example,dc=com",
    attributes={"cn": ["John Doe"], "sn": ["Doe"], "mail": ["john.doe@example.com"]},
)

group = FlextLdifModels.Entry(
    dn="cn=Admins,ou=Groups,dc=example,dc=com",
    attributes={
        "cn": ["Administrators"],
        "member": ["cn=John Doe,ou=People,dc=example,dc=com"],
    },
)
```

## Configuration Management

### Global Configuration

```python notest
from flext_ldif import FlextLdifSettings

# Initialize configuration
settings = FlextLdifSettings(
    max_entries=100000, strict_validation=True, encoding="utf-8"
)

# Access global configuration
u.Cli.print(f"Max entries: {settings.max_entries}")
```

### Instance Configuration

```python notest
from flext_ldif import FlextLdifModels, ldif

# Create instance-specific configuration
instance_config = FlextLdifModels.Config(
    max_entries=10000,  # Override global setting
    strict_validation=False,
)

# Use with API instance
api = ldif(settings=instance_config)
```

## Error Handling

### r Integration

All API operations return r for composable error handling:

```python notest
from flext_cli import u
from flext_core import FlextSettings

# Successful operation
result = api.parse_file("valid.ldif")
if result.success:
    entries = result.unwrap()
    # Process entries
else:
    error_message = result.error
    u.Cli.print(f"Parse failed: {error_message}")

# Safe value extraction with defaults
entries = result.unwrap_or([])  # Empty list if failed

# Railway-oriented composition
final_result = (
    api
    .parse_file("input.ldif")
    .flat_map(api.validate_entries)
    .flat_map(lambda entries: api.filter_persons(entries))
    .flat_map(lambda persons: api.write_file(persons, "persons.ldif"))
)
```

### Exception Types

```python notest
from flext_ldif import (
    FlextLdifError,  # Base LDIF error
    FlextLdifParseError,  # LDIF parsing errors
    FlextLdifValidationError,  # Validation errors
)

# Exception builder pattern
try:
    # Operations that might raise exceptions
    pass
except FlextLdifParseError as e:
    u.Cli.print(f"Parse error: {e}")
except FlextLdifValidationError as e:
    u.Cli.print(f"Validation error: {e}")
```

## ⚠️ Library-Only Usage

**IMPORTANT**: FLEXT-LDIF is a **library-only** package with NO CLI. All functionality must be accessed programmatically through the API.

**Migration from CLI to API**:

```python notest
# ❌ OLD (CLI - no longer available):
# python -m flext_ldif parse directory.ldif

# ✅ NEW (Library API):
from flext_ldif import ldif
from pathlib import Path

api = ldif()
result = api.parse_file(Path("directory.ldif"))
if result.success:
    entries = result.unwrap()
    u.Cli.print(f"Parsed {len(entries)} entries")

# ❌ OLD (CLI - no longer available):
# python -m flext_ldif analyze directory.ldif

# ✅ NEW (Library API):
result = api.parse_file(Path("directory.ldif"))
if result.success:
    entries = result.unwrap()
    stats_result = api.get_entry_statistics(entries)
    if stats_result.success:
        stats = stats_result.unwrap()
        u.Cli.print(f"Statistics: {stats}")

# ❌ OLD (CLI - no longer available):
# python -m flext_ldif filter --type person directory.ldif

# ✅ NEW (Library API):
result = api.parse_file(Path("directory.ldif"))
if result.success:
    entries = result.unwrap()
    persons_result = api.filter_persons(entries)
    if persons_result.success:
        persons = persons_result.unwrap()
        u.Cli.print(f"Found {len(persons)} person entries")
```

## Advanced Usage Patterns

### Pipeline Processing

```text
def process_enterprise_directory(
    input_file: Path, output_file: Path
) -> p.Result[m.Dict]:
    """Process enterprise directory with complete pipeline."""
    api = ldif(FlextLdifModels.Config(strict_validation=True))

    return (
        # Parse directory export
        api
        .parse_file(input_file)
        # Validate all entries
        .flat_map(lambda entries: api.validate_entries(entries).map(lambda _: entries))
        # Extract person entries
        .flat_map(api.filter_persons)
        # Generate statistics
        .flat_map(
            lambda persons: api.get_entry_statistics(persons).map(
                lambda stats: {"persons": persons, "stats": stats}
            )
        )
        # Write processed entries
        .flat_map(
            lambda data: api.write_file(data["persons"], output_file).map(
                lambda _: data["stats"]
            )
        )
        # Add error context
        .map_error(lambda error: f"Enterprise processing failed: {error}")
    )
```

### Batch Processing

```text
def process_multiple_files(file_paths: t.SequenceOf[Path]) -> p.Result[m.Dict]:
    """Process multiple LDIF files in batch."""
    api = ldif()
    all_entries = []
    processing_stats = {}

    for file_path in file_paths:
        result = api.parse_file(file_path)
        if result.success:
            entries = result.unwrap()
            all_entries.extend(entries)
            processing_stats[str(file_path)] = len(entries)
        else:
            return r[m.Dict].fail(f"Failed to process {file_path}: {result.error}")

    return r[m.Dict].ok({
        "total_entries": len(all_entries),
        "file_stats": processing_stats,
        "entries": all_entries,
    })
```

### Custom Filtering

```text
def filter_by_custom_criteria(
    api: ldif, entries: t.SequenceOf[FlextLdifModels.Entry]
) -> p.Result[Sequence[FlextLdifModels.Entry]]:
    """Apply custom filtering logic."""

    def matches_criteria(entry: FlextLdifModels.Entry) -> bool:
        # Custom business logic
        return (
            entry.has_object_class("person")
            and entry.get_attribute_values("mail")
            and "REDACTED_LDAP_BIND_PASSWORD" not in entry.dn.lower()
        )

    try:
        filtered = [entry for entry in entries if matches_criteria(entry)]
        return r[Sequence[FlextLdifModels.Entry]].ok(filtered)
    except Exception as e:
        return r[Sequence[FlextLdifModels.Entry]].fail(f"Filtering failed: {e}")
```

## RFC Schema Parser API

### RfcSchemaParserService

Parse LDAP schema definitions with RFC 4512 compliance and **MANDATORY servers support**.

```python notest
# ✅ v1.0+ Flat imports
from flext_ldif import FlextLdifParser
from flext_ldif import ServerRegistryService  # Unchanged - servers subdirectory


class RfcSchemaParserService:
    """RFC 4512 compliant schema parser with MANDATORY servers integration."""

    def __init__(
        self,
        *,
        params: dict,
        server_registry: ServerRegistryService,  # ⚠️ MANDATORY parameter
        server_type: str | None = None,
    ) -> None:
        """Initialize RFC schema parser.

        Args:
            params: Parsing parameters (file_path, parse_attributes, parse_objectclasses)
            server_registry: ⚠️ MANDATORY server registry for RFC-first architecture
            server_type: Optional server type to select specific servers (None = pure RFC)
        """

    def execute(self) -> p.Result[m.Dict]:
        """Execute RFC-compliant schema parsing with servers.

        Returns:
            r with parsed schema data containing:
                - attributes: Dict of attribute definitions by name
                - objectclasses: Dict of objectClass definitions by name
                - source_dn: DN of schema subentry
                - stats: Parsing statistics
        """
```

**⚠️ CRITICAL: server_registry is MANDATORY**

The `server_registry` parameter is **MANDATORY** (not Optional) to enforce RFC-first architecture with zero bypass paths.

**Example Usage**:

```python notest
# ✅ CORRECT: v1.0+ flat imports with MANDATORY server_registry
from flext_ldif import FlextLdifParser
from flext_ldif import ServerRegistryService

# Initialize registry FIRST (auto-discovers all standard servers)
server_registry = ServerRegistryService()

# Parse with OID servers
oid_parser = RfcSchemaParserService(
    params={
        "file_path": "oid_schema.ldif",
        "parse_attributes": True,
        "parse_objectclasses": True,
    },
    server_registry=server_registry,  # ⚠️ MANDATORY parameter
    server_type="oid",  # Selects OID-specific servers
)

result = oid_parser.execute()
if result.success:
    schema_data = result.unwrap()
    u.Cli.print(f"Attributes: {len(schema_data['attributes'])}")
    u.Cli.print(f"ObjectClasses: {len(schema_data['objectclasses'])}")

# ✅ CORRECT: Parse pure RFC 4512 (still requires server_registry)
rfc_parser = RfcSchemaParserService(
    params={"file_path": "standard_schema.ldif"},
    server_registry=server_registry,  # ⚠️ MANDATORY even for pure RFC
    server_type=None,  # None = no server-specific servers, pure RFC baseline
)

# ❌ INCORRECT: Omitting server_registry (will cause errors)
# parser = RfcSchemaParserService(params={"file_path": "schema.ldif"})
```

**Why server_registry is MANDATORY**:

1. **Enforces RFC-first architecture** - Zero bypass paths guarantee
1. **Enables generic transformation** - Source → RFC → Target pipeline requires registry
1. **Auto-discovery** - ServerRegistryService automatically discovers all standard servers
1. **Future-proof** - New servers can be added without API changes

## Migration Pipeline API

### FlextLdifMigration

Generic LDIF migration between different LDAP servers.

```python notest
from pathlib import Path


class Result: ...


class m:
    Dict = dict


class p:
    Result = Result


class FlextLdifMigration:
    """Generic LDIF migration pipeline using servers-based transformation."""

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

    def execute(self) -> p.Result[m.Dict]:
        """Execute migration pipeline.

        Generic transformation process:
        1. Parse source LDIF files
        2. Migrate schema (source → RFC → target)
        3. Migrate entries (source → RFC → target)
        4. Write target LDIF files

        Returns:
            r with migration results containing:
                - entries_migrated: Number of entries migrated
                - schema_files: List of schema files processed
                - output_files: List of generated output files
        """
```

**Example Usage**:

```python notest
from pathlib import Path


class Result:
    def __init__(self, success: bool, value=None) -> None:
        self.success = success
        self._value = value

    def unwrap(self):
        return self._value


class FlextLdifMigration:
    def __init__(
        self,
        input_dir: Path,
        output_dir: Path,
        source_server_type: str,
        target_server_type: str,
    ) -> None:
        pass

    def execute(self) -> Result:
        return Result(True, {"entries_migrated": 100, "schema_files": []})


# OID to OUD migration
pipeline = FlextLdifMigration(
    input_dir=Path("source_oid"),
    output_dir=Path("target_oud"),
    source_server_type="oid",
    target_server_type="oud",
)

result = pipeline.execute()
if result.success:
    data = result.unwrap()
    u.Cli.print(f"Migrated {data['entries_migrated']} entries")
    u.Cli.print(f"Schema files: {data['schema_files']}")

# Works with any server combination
# OpenLDAP to OUD, AD to 389 DS, etc.
```

## Servers Registry API

### ServerRegistryService

Central registry for managing server-specific servers.

```python notest
from flext_ldif import ServerRegistryService


class ServerRegistryService:
    """Registry for managing LDAP server servers."""

    def get_schemas(self, server_type: str) -> t.SequenceOf[Schema]:
        """Get schema servers for server type.

        Args:
            server_type: Server type identifier

        Returns:
            List of schema servers sorted by priority
        """

    def get_entrys(self, server_type: str) -> t.SequenceOf[Entry]:
        """Get entry servers for server type.

        Args:
            server_type: Server type identifier

        Returns:
            List of entry servers sorted by priority
        """

    def get_acls(self, server_type: str) -> t.SequenceOf[Acl]:
        """Get ACL servers for server type.

        Args:
            server_type: Server type identifier

        Returns:
            List of ACL servers sorted by priority
        """
```

**Example Usage**:

```python notest
from flext_ldif import FlextLdif

# Initialize the public facade and query server servers
client = FlextLdif()

schema_server = client.schema_server("oid")
entry_server = client.entry("oud")
acl_server = client.acl("openldap")

# Servers are automatically resolved by the registered server registry
# and exposed through the facade API.
```

## Integration with FLEXT Ecosystem

### FlextContainer Usage

```python notest
class Result:
    def __init__(self, success: bool, value=None) -> None:
        self.success = success
        self._value = value

    def unwrap(self):
        return self._value


class FlextContainer:
    @staticmethod
    def get_global() -> "FlextContainer":
        return FlextContainer()

    def bind(self, name: str, obj: object) -> Result:
        return Result(True, obj)

    def resolve(self, name: str) -> Result:
        return Result(True, object())


def ldif() -> object:
    return object()


# Access global container
container = FlextContainer.get_global()

# Register LDIF API as service
api = ldif()
register_result = container.bind("ldif_api", api)

# Retrieve from container in other services
api_result = container.resolve("ldif_api")
if api_result.success:
    ldif_api = api_result.unwrap()
```

### FlextLogger Integration

```python notest
from flext_ldif import u

# Structured logging in LDIF operations
logger = u.fetch_logger(__name__)

# Log processing operations
logger.info(
    "Starting LDIF processing",
    extra={"file_path": str(input_file), "settings": settings.model_dump()},
)

# Log processing results
logger.info(
    "LDIF processing completed",
    extra={"entries_processed": len(entries), "processing_time": elapsed_time},
)
```

## 🚀 Quick Start Guide

### Basic Usage - Parse, Validate, Write

```python notest
from flext_ldif import ldif
from pathlib import Path

# Initialize API (library-only, no CLI)
api = ldif()

# Write a sample LDIF file and load it as text
ldif_path = Path("directory.ldif")
ldif_path.write_text(
    "dn: cn=user,ou=people,dc=example,dc=com\nobjectClass: person\ncn: user\n"
)

ldif_content = ldif_path.read_text()
parse_result = api.parse_string(ldif_content)
if parse_result.failure:
    u.Cli.print(f"Parse failed: {parse_result.error}")
    exit(1)

entries = parse_result.unwrap()
u.Cli.print(f"✅ Parsed {len(entries)} entries")

# Validate entries
validation_result = api.validate_entries(entries)
if validation_result.failure:
    u.Cli.print(f"Validation failed: {validation_result.error}")
    exit(1)

u.Cli.print("✅ All entries valid")
```

### LDIF Parsing Example

```python notest
from flext_ldif import ldif

ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: inetOrgPerson
cn: test"""

api = ldif()
result = api.parse_string(ldif_content)
if result.success:
    entries = result.unwrap()
    u.Cli.print(f"✅ Parsed {len(entries)} entries")
else:
    u.Cli.print(f"❌ Failed to parse LDIF: {result.error}")
```

### Generic Migration Pipeline

```python notest
from flext_ldif import FlextLdifMigration
from pathlib import Path

# Migrate OID → OUD using generic transformation pipeline
migration = FlextLdifMigration(
    input_dir=Path("source_oid_ldif"),
    output_dir=Path("target_oud_ldif"),
    source_server_type="oid",  # Oracle Internet Directory
    target_server_type="oud",  # Oracle Unified Directory
)

# Execute migration: OID → RFC → OUD
result = migration.execute()
if result.success:
    data = result.unwrap()
    u.Cli.print(f"✅ Migrated {data['entries_migrated']} entries")
    u.Cli.print(f"✅ Processed {len(data['schema_files'])} schema files")
    u.Cli.print(f"✅ Generated {len(data['output_files'])} output files")
else:
    u.Cli.print(f"❌ Migration failed: {result.error}")

# Works with ANY server combination (N implementations, not N²)
# Examples: OID→OUD, OpenLDAP→389DS, AD→OUD, OUD→OpenLDAP, etc.
```

### Railway-Oriented Pipeline

```python notest
from flext_ldif import ldif
from pathlib import Path

Path("directory.ldif").write_text(
    "dn: cn=John Doe,dc=example,dc=com\nobjectClass: person\ncn: John Doe\n"
)

api = ldif()

# Composable pipeline with explicit error handling
result = (
    # Parse LDIF file
    api
    .parse_file(Path("directory.ldif"))
    # Validate all entries
    .flat_map(lambda entries: api.validate_entries(entries).map(lambda _: entries))
    # Filter person entries
    .flat_map(api.filter_persons)
    # Generate statistics
    .flat_map(
        lambda persons: api.get_entry_statistics(persons).map(
            lambda stats: {"persons": persons, "stats": stats}
        )
    )
    # Write filtered entries
    .flat_map(
        lambda data: api.write_file(data["persons"], Path("persons.ldif")).map(
            lambda _: data["stats"]
        )
    )
    # Add error context
    .map_error(lambda error: f"Processing failed: {error}")
)

# Handle final result
if result.success:
    stats = result.unwrap()
    u.Cli.print(f"✅ Pipeline completed: {stats}")
else:
    u.Cli.print(f"❌ Pipeline failed: {result.error}")
```

### Supported LDAP Servers

**Complete Implementations** (4 servers):

```python notest
# Oracle Internet Directory
server_type = "oid"

# Oracle Unified Directory
server_type = "oud"

# OpenLDAP 2.x
server_type = "openldap"

# OpenLDAP 1.x
server_type = "openldap1"
```

**Stub Implementations** (5 servers - ready for enhancement):

```python notest
# Active Directory (stub - not implemented)
server_type = "ad"

# Apache Directory Server (stub - not implemented)
server_type = "apache"

# 389 Directory Server (stub - not implemented)
server_type = "389ds"

# Novell eDirectory (stub - not implemented)
server_type = "novell"

# IBM Tivoli Directory Server (stub - not implemented)
server_type = "tivoli"
```

**Generic/Unknown Servers**:

```python notest
# Works with ANY LDAP server using pure RFC baseline
server_type = None  # Pure RFC 2849/4512 compliance
server_type = "my_custom_ldap_v5"  # Unknown server = RFC baseline
```

______________________________________________________________________

This API reference provides complete coverage of FLEXT-LDIF functionality, including the library-only interface, RFC-first architecture with MANDATORY server_registry, generic migration pipeline, and comprehensive servers system, while demonstrating integration with FLEXT ecosystem patterns and professional Python development practices.

## Related Documentation

**Within Project**:

- Getting Started - Installation and basic usage
- Architecture - Architecture and design patterns
- Examples - Practical usage patterns

**Across Projects**:

- [flext-core Foundation](https://github.com/organization/flext/tree/main/flext-core/docs/api-reference/foundation.md) - Core APIs and patterns
- [flext-ldap Operations](https://github.com/organization/flext/tree/main/flext-ldap/docs/api-reference.md) - LDAP operations API
- [flext-meltano Pipelines](https://github.com/organization/flext/tree/main/flext-meltano/AGENTS.md) - Data integration and ELT orchestration

**External Resources**:

- [RFC 2849 - The LDAP Data Interchange Format (LDIF)](https://www.rfc-editor.org/rfc/rfc2849.html)
- [RFC 4512 - LDAP: Technical Specification Road Map](https://www.rfc-editor.org/rfc/rfc4512.html)
