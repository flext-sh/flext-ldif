"""FLEXT-LDIF Type Definitions - Domain-Specific Extensions.

This module provides LDIF-specific type definitions that extend the base types
from flext-core.typings, following the FLEXT ecosystem type hierarchy.

ARCHITECTURE PATTERN: Domain-specific types extending flext-core foundation
- Inherits base types from FlextTypes in flext-core
- Extends with LDIF-specific domain types and business logic
- Maintains consistency with flext-core patterns

Benefits:
✅ Consistent with flext-core type hierarchy
✅ Domain-specific types for LDIF processing
✅ Type safety with FlextResult integration
✅ Enhanced IDE support through inheritance

Type Categories:
    - LDIF Domain Types: Extending flext-core base types
    - LDIF-Specific TypedDicts: Structured data definitions
    - LDIF Service Types: Domain service interfaces
    - LDIF Protocol Types: Business protocol definitions

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import NotRequired, TypedDict

from flext_ldif.typings import FlextTypes

# =============================================================================
# LDIF DOMAIN TYPES - Extending flext-core base types
# =============================================================================

# LDIF-specific extensions of core types
LDIFContent = str | bytes  # Specific to LDIF content processing
LDIFText = str
LDIFBytes = bytes
LDIFLines = list[str]

# File system types (extending core types)
FilePath = Path | FlextTypes.Config.FilePath  # Extend core FilePath
FileContent = str | bytes

# Collection types (extending core collection types)
StringList = FlextTypes.Data.StringList  # Use core string list
StringDict = FlextTypes.Core.StringDict  # Use core string dict
AttributeDict = dict[str, list[str]]  # LDIF-specific attribute structure

# Generic data types (using core types)
JSONData = FlextTypes.Core.JsonDict  # Use core JSON dict
ConfigData = FlextTypes.Core.Config  # Use core config type

# =============================================================================
# SEMANTIC TYPES - Domain-specific type aliases extending core types
# =============================================================================

# LDAP/LDIF semantic types (extending core identifier types)
LDAPObjectClass = FlextTypes.Core.Key  # Use core key type
AttributeName = FlextTypes.Core.Key  # Use core key type
AttributeValue = FlextTypes.Core.Value  # Use core value type
DistinguishedName = FlextTypes.Core.EntityId  # Use core entity ID
RelativeDistinguishedName = str  # LDIF-specific RDN

# Entry identification types (extending core types)
EntryID = FlextTypes.Core.EntityId  # Use core entity ID
EntryHash = str  # LDIF-specific hash

# Processing context types (extending core validation)
ValidationLevel = FlextTypes.Validation.ValidationRule  # Use core validation
ProcessingMode = str  # LDIF-specific: "streaming", "batch", "memory"
FormatVersion = str  # LDIF format version identifier

# Business rule types (extending core domain types)
ObjectClassName = FlextTypes.Core.Key  # Use core key type
PersonType = str  # "person", "inetOrgPerson", "organizationalPerson"
GroupType = str  # "groupOfNames", "groupOfUniqueNames", "posixGroup"

# Analytics and metrics types
EntryCount = int
AttributeCount = int
ValidationScore = float
ProcessingTime = float

# =============================================================================
# INTERFACE TYPES - TypedDict definitions for structured data
# =============================================================================


class FlextLdifDNDict(TypedDict):
    """TypedDict for DN structure with metadata."""

    value: str
    depth: NotRequired[int]
    components: NotRequired[dict[str, str]]
    parent_dn: NotRequired[str]


class FlextLdifAttributesDict(TypedDict):
    """TypedDict for attributes structure."""

    attributes: dict[str, list[str]]
    total_values: NotRequired[int]
    attribute_names: NotRequired[list[str]]


class FlextLdifEntryDict(TypedDict):
    """TypedDict for entry structure with optional fields."""

    id: NotRequired[str]
    dn: str
    attributes: dict[str, list[str]]
    changetype: NotRequired[str]
    object_classes: NotRequired[list[str]]


class FlextLdifParseResult(TypedDict):
    """TypedDict for parse operation results."""

    entries: list[FlextLdifEntryDict]
    entry_count: int
    parse_time: NotRequired[float]
    warnings: NotRequired[list[str]]


class FlextLdifValidationResult(TypedDict):
    """TypedDict for validation operation results."""

    is_valid: bool
    validation_score: NotRequired[float]
    errors: NotRequired[list[str]]
    warnings: NotRequired[list[str]]


class FlextLdifAnalyticsResult(TypedDict):
    """TypedDict for analytics operation results."""

    total_entries: int
    total_attributes: int
    object_class_distribution: dict[str, int]
    dn_depth_stats: NotRequired[dict[str, float]]
    processing_metrics: NotRequired[dict[str, str | int | float]]


class FlextLdifConfigDict(TypedDict):
    """TypedDict for configuration data."""

    max_entries: NotRequired[int]
    max_entry_size: NotRequired[int]
    strict_validation: NotRequired[bool]
    input_encoding: NotRequired[str]
    output_encoding: NotRequired[str]
    line_wrap_length: NotRequired[int]
    sort_attributes: NotRequired[bool]
    normalize_dn: NotRequired[bool]


# =============================================================================
# FUNCTION TYPES - Callable type signatures for service interfaces
# =============================================================================

# Parser function types
ParseFunction = Callable[[LDIFContent], list[FlextLdifEntryDict]]
ParseFileFunction = Callable[
    [Path | FlextTypes.Config.FilePath], list[FlextLdifEntryDict]
]

# Validator function types
ValidateFunction = Callable[[list[FlextLdifEntryDict]], bool]
ValidateEntryFunction = Callable[[FlextLdifEntryDict], bool]

# Writer function types
WriteFunction = Callable[[list[FlextLdifEntryDict]], LDIFText]
WriteFileFunction = Callable[
    [list[FlextLdifEntryDict], Path | FlextTypes.Config.FilePath], None
]

# Analytics function types
AnalyticsFunction = Callable[[list[FlextLdifEntryDict]], FlextLdifAnalyticsResult]
FilterFunction = Callable[[list[FlextLdifEntryDict], str], list[FlextLdifEntryDict]]

# Transformation function types
TransformFunction = Callable[[FlextLdifEntryDict], FlextLdifEntryDict]
NormalizeFunction = Callable[[str], str]

# Configuration function types
ConfigValidateFunction = Callable[[FlextLdifConfigDict], bool]
ConfigMergeFunction = Callable[
    [FlextLdifConfigDict, FlextLdifConfigDict],
    FlextLdifConfigDict,
]

# =============================================================================
# ERROR AND RESULT TYPES - For FlextResult pattern integration
# =============================================================================

# Error information types (using core error types)
ErrorMessage = FlextTypes.Core.ErrorMessage  # Use core error message
ErrorCode = FlextTypes.Core.ErrorCode  # Use core error code
ErrorContext = FlextTypes.Core.AnyDict  # Use core dict type

# Result data types (LDIF-specific results)
ParseResultData = list[FlextLdifEntryDict]
ValidationResultData = bool
WriteResultData = LDIFText
AnalyticsResultData = FlextLdifAnalyticsResult

# Success/failure status types
OperationStatus = bool
ResultStatus = str  # "success", "failure", "partial"

# =============================================================================
# SERVICE LAYER TYPES - For dependency injection and service orchestration
# =============================================================================

# Service instance types (extending core service types)
ParserServiceType = FlextTypes.Service.ServiceInstance  # FlextLdifParserService
ValidatorServiceType = FlextTypes.Service.ServiceInstance  # FlextLdifValidatorService
WriterServiceType = FlextTypes.Service.ServiceInstance  # FlextLdifWriterService
AnalyticsServiceType = FlextTypes.Service.ServiceInstance  # FlextLdifAnalyticsService
RepositoryServiceType = FlextTypes.Service.ServiceInstance  # FlextLdifRepositoryService
TransformerServiceType = (
    FlextTypes.Service.ServiceInstance
)  # FlextLdifTransformerService

# Configuration types (using core service types)
ConfigServiceType = FlextTypes.Service.Configuration  # FlextLdifConfig
APIServiceType = FlextTypes.Service.ServiceInstance  # FlextLdifAPI

# =============================================================================
# LEGACY COMPATIBILITY TYPES - For backward compatibility
# =============================================================================

# Legacy type aliases for compatibility
LdifEntry = FlextLdifEntryDict
LdifAttributes = FlextLdifAttributesDict
LdifDN = FlextLdifDNDict

# Legacy function signatures
LegacyParseFunction = Callable[[str], list[dict[str, str | list[str]]]]
LegacyValidateFunction = Callable[[list[dict[str, str | list[str]]]], bool]
LegacyWriteFunction = Callable[[list[dict[str, str | list[str]]]], str]

# =============================================================================
# CONSTANTS AND ENUMS - Type-safe constants
# =============================================================================

# Object class categories
PERSON_OBJECT_CLASSES = frozenset(
    {
        "person",
        "inetOrgPerson",
        "organizationalPerson",
        "user",
        "posixAccount",
        "shadowAccount",
    },
)

GROUP_OBJECT_CLASSES = frozenset(
    {"groupOfNames", "groupOfUniqueNames", "posixGroup", "group", "organizationalRole"},
)

STRUCTURAL_OBJECT_CLASSES = frozenset(
    {"organizationalUnit", "organization", "domain", "country", "locality", "dcObject"},
)

# DN component attribute names
DN_COMPONENT_ATTRIBUTES = frozenset(
    {
        "member",
        "uniqueMember",
        "memberOf",
        "manager",
        "secretary",
        "seeAlso",
        "superior",
    },
)

# Standard LDIF line lengths per RFC 2849
MIN_LINE_WRAP_LENGTH = 50
MAX_LINE_WRAP_LENGTH = 998
DEFAULT_LINE_WRAP_LENGTH = 76

# Validation levels
VALIDATION_LEVELS = frozenset({"strict", "relaxed", "minimal"})

# Processing modes
PROCESSING_MODES = frozenset({"streaming", "batch", "memory"})

# Supported encodings
SUPPORTED_ENCODINGS = frozenset({"utf-8", "utf-16", "ascii", "latin1"})


__all__ = [
    "DEFAULT_LINE_WRAP_LENGTH",
    "DN_COMPONENT_ATTRIBUTES",
    "GROUP_OBJECT_CLASSES",
    "MAX_LINE_WRAP_LENGTH",
    "MIN_LINE_WRAP_LENGTH",
    # Constants
    "PERSON_OBJECT_CLASSES",
    "PROCESSING_MODES",
    "STRUCTURAL_OBJECT_CLASSES",
    "SUPPORTED_ENCODINGS",
    "VALIDATION_LEVELS",
    "APIServiceType",
    "AnalyticsFunction",
    "AnalyticsResultData",
    "AnalyticsServiceType",
    "AttributeCount",
    "AttributeDict",
    "AttributeName",
    "AttributeValue",
    "ConfigData",
    "ConfigMergeFunction",
    "ConfigServiceType",
    "ConfigValidateFunction",
    "DistinguishedName",
    "EntryCount",
    "EntryHash",
    "EntryID",
    "ErrorCode",
    "ErrorContext",
    # Error and result types
    "ErrorMessage",
    "FileContent",
    "FilePath",
    "FilterFunction",
    "FlextLdifAnalyticsResult",
    "FlextLdifAttributesDict",
    "FlextLdifConfigDict",
    # Interface types
    "FlextLdifDNDict",
    "FlextLdifEntryDict",
    "FlextLdifParseResult",
    "FlextLdifValidationResult",
    "FormatVersion",
    "GroupType",
    "JSONData",
    # Semantic types
    "LDAPObjectClass",
    "LDIFBytes",
    # Basic types
    "LDIFContent",
    "LDIFLines",
    "LDIFText",
    "LdifAttributes",
    "LdifDN",
    # Legacy compatibility
    "LdifEntry",
    "LegacyParseFunction",
    "LegacyValidateFunction",
    "LegacyWriteFunction",
    "NormalizeFunction",
    "ObjectClassName",
    "OperationStatus",
    "ParseFileFunction",
    # Function types
    "ParseFunction",
    "ParseResultData",
    # Service types
    "ParserServiceType",
    "PersonType",
    "ProcessingMode",
    "ProcessingTime",
    "RelativeDistinguishedName",
    "RepositoryServiceType",
    "ResultStatus",
    "StringDict",
    "StringList",
    "TransformFunction",
    "TransformerServiceType",
    "ValidateEntryFunction",
    "ValidateFunction",
    "ValidationLevel",
    "ValidationResultData",
    "ValidationScore",
    "ValidatorServiceType",
    "WriteFileFunction",
    "WriteFunction",
    "WriteResultData",
    "WriterServiceType",
]
