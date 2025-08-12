"""FLEXT-LDIF Models - Enterprise LDIF Processing Models.

CONSOLIDATED PEP8 ARCHITECTURE: This module consolidates LDIF domain models,
constants, and protocols into ONE centralized, PEP8-compliant module.

CONSOLIDATION MAPPING:
✅ src/flext_ldif/models.py → Domain models (FlextLdifEntry, FlextLdifAttributes, etc.)
✅ src/flext_ldif/constants.py → LDIF processing constants and settings
✅ src/flext_ldif/protocols.py → Type-safe protocol interfaces

Domain Objects:
    - FlextLdifDistinguishedName: RFC 4514 compliant DN value object
    - FlextLdifAttributes: Immutable attribute collection with business rules
    - FlextLdifEntry: Rich domain entity with complete business logic
    - FlextLdifFactory: Factory patterns with validation using flext-core

Enterprise Architecture:
- Domain-Driven Design: Rich domain models with business logic
- Value Object Pattern: Immutable domain values (DN, Attributes)
- Entity Pattern: FlextLdifEntry with identity and behavior
- Factory Pattern: Object creation through FlextFactory delegation
- Type Safety: Python 3.13+ with comprehensive type annotations
- Error Handling: FlextResult pattern for railway-oriented programming

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from __future__ import annotations

import uuid
from typing import (
    TYPE_CHECKING,
    Final,
    NotRequired,
    Protocol,
    TypedDict,
    cast,
    runtime_checkable,
)

# FOUNDATION: Complete flext-core integration - NO duplication
from flext_core import (
    FlextEntity,
    FlextFactory,
    FlextResult,
    FlextValue,
)
from flext_core.exceptions import FlextValidationError

# ✅ CORRECT - Import from flext-ldap root API to eliminate DN validation duplication
from flext_ldap import (
    flext_ldap_validate_attribute_name,
    flext_ldap_validate_dn,
)

if TYPE_CHECKING:
    from pathlib import Path


# =============================================================================
# LDIF FORMAT CONSTANTS (RFC 2849)
# =============================================================================

DEFAULT_LINE_WRAP_LENGTH: Final[int] = 76
MIN_LINE_WRAP_LENGTH: Final[int] = 50
MAX_LINE_WRAP_LENGTH: Final[int] = 998
DEFAULT_LINE_SEPARATOR: Final[str] = "\n"
DEFAULT_ENTRY_SEPARATOR: Final[str] = "\n\n"

# =============================================================================
# FILE PROCESSING SETTINGS
# =============================================================================

DEFAULT_INPUT_ENCODING: Final[str] = "utf-8"
DEFAULT_OUTPUT_ENCODING: Final[str] = "utf-8"
DEFAULT_FILE_BUFFER_SIZE: Final[int] = 8192
DEFAULT_LDIF_FILE_PATTERN: Final[str] = "*.ldif"
DEFAULT_MAX_FILE_SIZE_MB: Final[int] = 100

# =============================================================================
# ENTRY PROCESSING LIMITS
# =============================================================================

DEFAULT_MAX_ENTRIES: Final[int] = 20000
MAX_ENTRIES_LIMIT: Final[int] = 1000000
MIN_ENTRIES_LIMIT: Final[int] = 1

# Entry Size Limits
DEFAULT_MAX_ENTRY_SIZE: Final[int] = 1048576  # 1MB
MIN_ENTRY_SIZE: Final[int] = 1024  # 1KB
MAX_ENTRY_SIZE_LIMIT: Final[int] = 104857600  # 100MB

# =============================================================================
# DN (DISTINGUISHED NAME) CONSTANTS
# =============================================================================

MIN_DN_COMPONENTS: Final[int] = 2
MAX_DN_DEPTH: Final[int] = 20
DN_SEPARATOR: Final[str] = ","
DN_ATTRIBUTE_SEPARATOR: Final[str] = "="
ATTRIBUTE_SEPARATOR: Final[str] = "="  # Alias for backward compatibility

# DN Validation Patterns
LDAP_ATTRIBUTE_PATTERN: Final[str] = r"^[a-zA-Z][a-zA-Z0-9-]*$"
DN_COMPONENT_PATTERN: Final[str] = r"^[a-zA-Z]+=.+"

# =============================================================================
# LDAP OBJECT CLASSES (CONSOLIDATED - NO DUPLICATION)
# =============================================================================

# Person Object Classes (merged from constants.py + ldif_constants.py)
LDAP_PERSON_CLASSES: Final[frozenset[str]] = frozenset({
    "person",
    "organizationalPerson",
    "inetOrgPerson",
    "user",
    "posixAccount",
})

# Group Object Classes (merged from constants.py + ldif_constants.py)
LDAP_GROUP_CLASSES: Final[frozenset[str]] = frozenset({
    "group",
    "groupOfNames",
    "groupOfUniqueNames",
    "posixGroup",
    "organizationalRole",
    "groupOfMembers",
})

# Organizational Unit Object Classes
LDAP_OU_CLASSES: Final[frozenset[str]] = frozenset({
    "organizationalUnit",
    "top",
})

# Backward Compatibility Aliases (DEPRECATED - use LDAP_ prefixed versions)
PERSON_OBJECT_CLASSES: Final[frozenset[str]] = LDAP_PERSON_CLASSES
GROUP_OBJECT_CLASSES: Final[frozenset[str]] = LDAP_GROUP_CLASSES
OU_OBJECT_CLASSES: Final[frozenset[str]] = LDAP_OU_CLASSES

# =============================================================================
# LDAP ATTRIBUTES (CONSOLIDATED - NO DUPLICATION)
# =============================================================================

# DN-Valued Attributes requiring DN normalization (merged from both files)
LDAP_DN_ATTRIBUTES: Final[frozenset[str]] = frozenset({
    "orcldaspublicgroupdns",
    "member",
    "uniquemember",
    "owner",
    "seealso",
    "distinguishedname",
    "manager",
    "secretary",
    "roleoccupant",
})

# Backward Compatibility Alias (DEPRECATED - use LDAP_DN_ATTRIBUTES)
DN_VALUED_ATTRIBUTES: Final[frozenset[str]] = LDAP_DN_ATTRIBUTES

# =============================================================================
# LDIF CHANGE TYPES
# =============================================================================

LDIF_CHANGE_TYPES: Final[frozenset[str]] = frozenset({
    "add",
    "delete",
    "modify",
    "modrdn",
})

# =============================================================================
# VALIDATION SETTINGS
# =============================================================================

DEFAULT_STRICT_VALIDATION: Final[bool] = True
DEFAULT_ALLOW_EMPTY_ATTRIBUTES: Final[bool] = False
DEFAULT_NORMALIZE_DN: Final[bool] = False
DEFAULT_SORT_ATTRIBUTES: Final[bool] = False

# =============================================================================
# LIBRARY METADATA
# =============================================================================

LIBRARY_NAME: Final[str] = "flext-ldif"
LIBRARY_VERSION: Final[str] = "0.9.0"
LIBRARY_DESCRIPTION: Final[str] = "Enterprise LDIF Processing Library"

# =============================================================================
# DOMAIN MODEL TYPE DEFINITIONS
# =============================================================================


class FlextLdifAttributesDict(TypedDict):
    """Type definition for LDIF attributes dictionary with validation."""

    cn: NotRequired[list[str]]
    objectClass: NotRequired[list[str]]
    mail: NotRequired[list[str]]
    uid: NotRequired[list[str]]
    sn: NotRequired[list[str]]
    givenName: NotRequired[list[str]]
    member: NotRequired[list[str]]
    uniqueMember: NotRequired[list[str]]


class FlextLdifDNDict(TypedDict):
    """Type definition for DN dictionary representation."""

    components: list[dict[str, str]]
    raw: str
    normalized: str


class FlextLdifEntryDict(TypedDict):
    """Type definition for complete LDIF entry with all metadata."""

    dn: str
    attributes: FlextLdifAttributesDict
    raw_attributes: NotRequired[dict[str, list[str]]]
    line_number: NotRequired[int]
    source_file: NotRequired[str]
    entry_id: NotRequired[str]


# Type aliases for content handling
LDIFContent = str
LDIFLines = list[str]

# =============================================================================
# APPLICATION PROTOCOLS - Extending flext-core protocols
# =============================================================================


@runtime_checkable
class FlextLdifParserProtocol(Protocol):
    """LDIF parsing protocol - extends flext-core patterns."""

    def parse(self, content: str) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF content into domain entities."""
        ...

    def parse_file(self, file_path: str | Path) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF file into domain entities."""
        ...

    def parse_entries_from_string(self, ldif_string: str) -> FlextResult[list[FlextLdifEntry]]:
        """Parse multiple entries from LDIF string."""
        ...


@runtime_checkable
class FlextLdifValidatorProtocol(Protocol):
    """LDIF validation protocol using flext-core patterns."""

    def validate(self, data: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate data using flext-core pattern."""
        ...

    def validate_entry(self, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Validate single LDIF entry."""
        ...

    def validate_entries(self, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate multiple LDIF entries."""
        ...

    def validate_dn_format(self, dn: str) -> FlextResult[bool]:
        """Validate DN format compliance."""
        ...


@runtime_checkable
class FlextLdifWriterProtocol(Protocol):
    """LDIF writing protocol."""

    def write(self, entries: list[FlextLdifEntry]) -> FlextResult[str]:
        """Write entries to LDIF string."""
        ...

    def write_file(self, entries: list[FlextLdifEntry], file_path: str | Path) -> FlextResult[bool]:
        """Write entries to LDIF file."""
        ...

    def write_entry(self, entry: FlextLdifEntry) -> FlextResult[str]:
        """Write single entry to LDIF string."""
        ...


@runtime_checkable
class FlextLdifRepositoryProtocol(Protocol):
    """LDIF data access protocol."""

    def find_by_dn(self, entries: list[FlextLdifEntry], dn: str) -> FlextResult[FlextLdifEntry | None]:
        """Find entry by distinguished name."""
        ...

    def filter_by_objectclass(self, entries: list[FlextLdifEntry], objectclass: str) -> FlextResult[list[FlextLdifEntry]]:
        """Filter entries by objectClass attribute."""
        ...

    def filter_by_attribute(self, entries: list[FlextLdifEntry], attribute: str, value: str) -> FlextResult[list[FlextLdifEntry]]:
        """Filter entries by attribute value."""
        ...

    def get_statistics(self, entries: list[FlextLdifEntry]) -> FlextResult[dict[str, int]]:
        """Get statistical information about entries."""
        ...


@runtime_checkable
class FlextLdifTransformerProtocol(Protocol):
    """LDIF transformation protocol."""

    def transform_entry(self, entry: FlextLdifEntry) -> FlextResult[FlextLdifEntry]:
        """Transform single LDIF entry."""
        ...

    def transform_entries(self, entries: list[FlextLdifEntry]) -> FlextResult[list[FlextLdifEntry]]:
        """Transform multiple LDIF entries."""
        ...

    def normalize_dns(self, entries: list[FlextLdifEntry]) -> FlextResult[list[FlextLdifEntry]]:
        """Normalize all DN values in entries."""
        ...


@runtime_checkable
class FlextLdifAnalyticsProtocol(Protocol):
    """LDIF analytics protocol for business intelligence."""

    def analyze_entry_patterns(self, entries: list[FlextLdifEntry]) -> FlextResult[dict[str, int]]:
        """Analyze patterns in LDIF entries."""
        ...

    def get_objectclass_distribution(self, entries: list[FlextLdifEntry]) -> FlextResult[dict[str, int]]:
        """Get distribution of objectClass types."""
        ...

    def get_dn_depth_analysis(self, entries: list[FlextLdifEntry]) -> FlextResult[dict[str, int]]:
        """Analyze DN depth distribution."""
        ...

# =============================================================================
# DOMAIN MODEL IMPLEMENTATIONS
# =============================================================================


class FlextLdifDistinguishedName(FlextValue[str]):
    """DN Value Object with RFC 4514 compliance and enterprise validation.

    Implements RFC 4514 DN format with comprehensive validation and normalization
    capabilities. Uses flext-ldap for validation to eliminate code duplication.

    Features:
    - RFC 4514 DN format compliance
    - Validation through flext-ldap integration
    - Hash-based equality for performance
    - Immutable value object semantics
    - Component extraction and analysis
    """

    def __init__(self, dn: str) -> None:
        """Initialize DN with validation via flext-ldap."""
        # Validate using flext-ldap service (eliminates duplication)
        validation_result = flext_ldap_validate_dn(dn)
        if validation_result.is_failure:
            msg = f"Invalid DN format: {dn}"
            raise FlextValidationError(msg) from None

        super().__init__(dn)

    @property
    def components(self) -> list[str]:
        """Extract DN components (RDNs) from the DN string."""
        return [comp.strip() for comp in self.value.split(",")]

    @property
    def depth(self) -> int:
        """Calculate the depth (number of components) of the DN."""
        return len(self.components)

    @property
    def normalized(self) -> str:
        """Return normalized DN (lowercase, no extra spaces)."""
        return self.value.lower().replace(" ", "")

    def is_under(self, parent_dn: str) -> bool:
        """Check if this DN is under the given parent DN."""
        return self.value.lower().endswith(parent_dn.lower())

    def get_parent_dn(self) -> str | None:
        """Get the parent DN by removing the leftmost RDN."""
        components = self.components
        if len(components) <= 1:
            return None
        return ",".join(components[1:])

    def get_rdn(self) -> str:
        """Get the Relative Distinguished Name (leftmost component)."""
        return self.components[0] if self.components else ""

    def __hash__(self) -> int:
        """Hash based on normalized DN for efficient lookups."""
        return hash(self.normalized)


class FlextLdifAttributes(FlextValue[dict[str, list[str]]]):
    """LDIF Attributes Value Object with immutable semantics.

    Represents LDIF attributes as an immutable collection with business rules
    and validation. Provides type-safe access to attribute values with
    comprehensive validation through flext-ldap integration.

    Features:
    - Immutable attribute collection
    - Type-safe attribute access
    - Validation through flext-ldap
    - ObjectClass business logic
    - Efficient hash-based equality
    """

    def __init__(self, attributes: dict[str, list[str]]) -> None:
        """Initialize attributes with validation."""
        validated_attrs = {}

        for attr_name, attr_values in attributes.items():
            # Validate attribute name using flext-ldap (eliminates duplication)
            validation_result = flext_ldap_validate_attribute_name(attr_name)
            if validation_result.is_failure:
                msg = f"Invalid attribute name: {attr_name}"
                raise FlextValidationError(msg) from None

            # Ensure values is always a list
            if isinstance(attr_values, str):
                validated_attrs[attr_name] = [attr_values]
            elif isinstance(attr_values, list):
                validated_attrs[attr_name] = attr_values.copy()
            else:
                msg = f"Attribute values must be string or list, got {type(attr_values)}"
                raise FlextValidationError(msg) from None

        super().__init__(validated_attrs)

    def get(self, name: str, default: list[str] | None = None) -> list[str]:
        """Get attribute values by name with default fallback."""
        return self.value.get(name, default or [])

    def get_first(self, name: str, default: str | None = None) -> str | None:
        """Get first value of attribute with default fallback."""
        values = self.get(name)
        return values[0] if values else default

    def has(self, name: str) -> bool:
        """Check if attribute exists."""
        return name in self.value

    def has_value(self, name: str, value: str) -> bool:
        """Check if attribute has specific value."""
        return value in self.get(name)

    @property
    def names(self) -> list[str]:
        """Get all attribute names."""
        return list(self.value.keys())

    @property
    def object_classes(self) -> list[str]:
        """Get objectClass values."""
        return self.get("objectClass")

    @property
    def is_person(self) -> bool:
        """Check if entry represents a person object."""
        return bool(LDAP_PERSON_CLASSES.intersection(self.object_classes))

    @property
    def is_group(self) -> bool:
        """Check if entry represents a group object."""
        return bool(LDAP_GROUP_CLASSES.intersection(self.object_classes))

    @property
    def is_organizational_unit(self) -> bool:
        """Check if entry represents an organizational unit."""
        return bool(LDAP_OU_CLASSES.intersection(self.object_classes))

    def to_dict(self) -> FlextLdifAttributesDict:
        """Convert to typed dictionary for serialization."""
        return cast("FlextLdifAttributesDict", self.value.copy())

    def __hash__(self) -> int:
        """Hash based on all attributes for efficient set operations."""
        # Create a deterministic hash from sorted items
        sorted_items = tuple(sorted((k, tuple(sorted(v))) for k, v in self.value.items()))
        return hash(sorted_items)


class FlextLdifEntry(FlextEntity):
    """LDIF Entry Entity with rich domain behavior and business logic.

    Represents a complete LDIF entry with DN, attributes, and metadata.
    Implements entity pattern with identity, behavior, and business rules.

    Features:
    - Rich domain entity with business logic
    - Immutable attributes and DN
    - Type-safe access patterns
    - Comprehensive validation
    - Metadata tracking (line number, source file)
    """

    def __init__(
        self,
        dn: str,
        attributes: dict[str, list[str]],
        *,
        line_number: int | None = None,
        source_file: str | None = None,
        entry_id: str | None = None,
    ) -> None:
        """Initialize LDIF entry with validation."""
        # Generate ID if not provided
        if entry_id is None:
            entry_id = str(uuid.uuid4())

        super().__init__(entry_id)

        # Create immutable domain objects
        self._dn = FlextLdifDistinguishedName(dn)
        self._attributes = FlextLdifAttributes(attributes)
        self._line_number = line_number
        self._source_file = source_file

    @property
    def dn(self) -> FlextLdifDistinguishedName:
        """Get the Distinguished Name as a value object."""
        return self._dn

    @property
    def attributes(self) -> FlextLdifAttributes:
        """Get the attributes as an immutable value object."""
        return self._attributes

    @property
    def line_number(self) -> int | None:
        """Get the line number where this entry was found."""
        return self._line_number

    @property
    def source_file(self) -> str | None:
        """Get the source file path where this entry was found."""
        return self._source_file

    @property
    def dn_string(self) -> str:
        """Get DN as string for convenience."""
        return self.dn.value

    @property
    def common_name(self) -> str | None:
        """Get the common name (cn) attribute."""
        return self.attributes.get_first("cn")

    @property
    def object_classes(self) -> list[str]:
        """Get objectClass values."""
        return self.attributes.object_classes

    @property
    def is_person(self) -> bool:
        """Check if this entry represents a person."""
        return self.attributes.is_person

    @property
    def is_group(self) -> bool:
        """Check if this entry represents a group."""
        return self.attributes.is_group

    @property
    def is_organizational_unit(self) -> bool:
        """Check if this entry represents an organizational unit."""
        return self.attributes.is_organizational_unit

    def get_attribute(self, name: str, default: list[str] | None = None) -> list[str]:
        """Get attribute values by name."""
        return self.attributes.get(name, default)

    def get_first_attribute(self, name: str, default: str | None = None) -> str | None:
        """Get first value of attribute."""
        return self.attributes.get_first(name, default)

    def has_attribute(self, name: str) -> bool:
        """Check if attribute exists."""
        return self.attributes.has(name)

    def has_attribute_value(self, name: str, value: str) -> bool:
        """Check if attribute has specific value."""
        return self.attributes.has_value(name, value)

    def is_under_dn(self, parent_dn: str) -> bool:
        """Check if this entry is under the given parent DN."""
        return self.dn.is_under(parent_dn)

    def get_parent_dn(self) -> str | None:
        """Get the parent DN."""
        return self.dn.get_parent_dn()

    def get_rdn(self) -> str:
        """Get the Relative Distinguished Name."""
        return self.dn.get_rdn()

    def to_dict(self) -> FlextLdifEntryDict:
        """Convert to dictionary for serialization."""
        result: FlextLdifEntryDict = {
            "dn": self.dn_string,
            "attributes": self.attributes.to_dict(),
        }

        if self.line_number is not None:
            result["line_number"] = self.line_number
        if self.source_file is not None:
            result["source_file"] = self.source_file
        if self.entity_id:
            result["entry_id"] = self.entity_id

        return result

    def __str__(self) -> str:
        """String representation for debugging."""
        return f"FlextLdifEntry(dn='{self.dn_string}', attributes={len(self.attributes.names)})"

    def __repr__(self) -> str:
        """Detailed string representation."""
        return (
            f"FlextLdifEntry(id='{self.entity_id}', dn='{self.dn_string}', "
            f"attributes={len(self.attributes.names)}, line={self.line_number})"
        )

    def __hash__(self) -> int:
        """Hash based on DN for efficient lookups."""
        return hash(self.dn)

    def __eq__(self, other: object) -> bool:
        """Equality based on DN (business equality)."""
        if not isinstance(other, FlextLdifEntry):
            return False
        return self.dn == other.dn


class FlextLdifFactory(FlextFactory):
    """Factory for creating LDIF domain objects with validation.

    Provides factory methods for creating LDIF domain objects with proper
    validation and error handling. Extends flext-core factory patterns.
    """

    @classmethod
    def create_entry(
        cls,
        dn: str,
        attributes: dict[str, list[str]],
        *,
        line_number: int | None = None,
        source_file: str | None = None,
    ) -> FlextResult[FlextLdifEntry]:
        """Create LDIF entry with validation."""
        try:
            entry = FlextLdifEntry(
                dn=dn,
                attributes=attributes,
                line_number=line_number,
                source_file=source_file,
            )
            return FlextResult.success(entry)
        except Exception as e:
            return FlextResult.failure(f"Failed to create LDIF entry: {e}")

    @classmethod
    def create_dn(cls, dn: str) -> FlextResult[FlextLdifDistinguishedName]:
        """Create DN value object with validation."""
        try:
            dn_obj = FlextLdifDistinguishedName(dn)
            return FlextResult.success(dn_obj)
        except Exception as e:
            return FlextResult.failure(f"Failed to create DN: {e}")

    @classmethod
    def create_attributes(cls, attributes: dict[str, list[str]]) -> FlextResult[FlextLdifAttributes]:
        """Create attributes value object with validation."""
        try:
            attrs_obj = FlextLdifAttributes(attributes)
            return FlextResult.success(attrs_obj)
        except Exception as e:
            return FlextResult.failure(f"Failed to create attributes: {e}")


# =============================================================================
# BACKWARD COMPATIBILITY ALIASES (DEPRECATED - use FlextLdif* versions)
# =============================================================================

# Legacy protocol aliases for backward compatibility
LdifParserProtocol = FlextLdifParserProtocol
LdifValidatorProtocol = FlextLdifValidatorProtocol
LdifWriterProtocol = FlextLdifWriterProtocol
LdifRepositoryProtocol = FlextLdifRepositoryProtocol
LdifTransformerProtocol = FlextLdifTransformerProtocol

# =============================================================================
# COMPREHENSIVE PUBLIC API
# =============================================================================

__all__ = [
    "ATTRIBUTE_SEPARATOR",
    "DEFAULT_ALLOW_EMPTY_ATTRIBUTES",
    "DEFAULT_ENTRY_SEPARATOR",
    "DEFAULT_FILE_BUFFER_SIZE",
    # Constants - File Processing
    "DEFAULT_INPUT_ENCODING",
    "DEFAULT_LDIF_FILE_PATTERN",
    "DEFAULT_LINE_SEPARATOR",
    # Constants - LDIF Format (RFC 2849)
    "DEFAULT_LINE_WRAP_LENGTH",
    # Constants - Entry Processing
    "DEFAULT_MAX_ENTRIES",
    "DEFAULT_MAX_ENTRY_SIZE",
    "DEFAULT_MAX_FILE_SIZE_MB",
    "DEFAULT_NORMALIZE_DN",
    "DEFAULT_OUTPUT_ENCODING",
    "DEFAULT_SORT_ATTRIBUTES",
    # Constants - Validation Settings
    "DEFAULT_STRICT_VALIDATION",
    "DN_ATTRIBUTE_SEPARATOR",
    "DN_COMPONENT_PATTERN",
    "DN_SEPARATOR",
    "DN_VALUED_ATTRIBUTES",   # Deprecated
    "GROUP_OBJECT_CLASSES",   # Deprecated
    "LDAP_ATTRIBUTE_PATTERN",
    # Constants - LDAP Attributes
    "LDAP_DN_ATTRIBUTES",
    "LDAP_GROUP_CLASSES",
    "LDAP_OU_CLASSES",
    # Constants - LDAP Object Classes
    "LDAP_PERSON_CLASSES",
    # Constants - LDIF Change Types
    "LDIF_CHANGE_TYPES",
    "LIBRARY_DESCRIPTION",
    # Constants - Library Metadata
    "LIBRARY_NAME",
    "LIBRARY_VERSION",
    "MAX_DN_DEPTH",
    "MAX_ENTRIES_LIMIT",
    "MAX_ENTRY_SIZE_LIMIT",
    "MAX_LINE_WRAP_LENGTH",
    # Constants - DN Processing
    "MIN_DN_COMPONENTS",
    "MIN_ENTRIES_LIMIT",
    "MIN_ENTRY_SIZE",
    "MIN_LINE_WRAP_LENGTH",
    "OU_OBJECT_CLASSES",      # Deprecated
    "PERSON_OBJECT_CLASSES",  # Deprecated
    "FlextLdifAnalyticsProtocol",
    "FlextLdifAttributes",
    # Type Definitions
    "FlextLdifAttributesDict",
    "FlextLdifDNDict",
    # Domain Models
    "FlextLdifDistinguishedName",
    "FlextLdifEntry",
    "FlextLdifEntryDict",
    "FlextLdifFactory",
    # Protocol Interfaces - Modern
    "FlextLdifParserProtocol",
    "FlextLdifRepositoryProtocol",
    "FlextLdifTransformerProtocol",
    "FlextLdifValidatorProtocol",
    "FlextLdifWriterProtocol",
    "LDIFContent",
    "LDIFLines",
    # Protocol Interfaces - Legacy
    "LdifParserProtocol",     # Deprecated
    "LdifRepositoryProtocol",  # Deprecated
    "LdifTransformerProtocol",  # Deprecated
    "LdifValidatorProtocol",  # Deprecated
    "LdifWriterProtocol",     # Deprecated
]
