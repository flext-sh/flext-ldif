"""LDIF type definitions and type aliases.

This module defines type aliases and type hints used throughout the LDIF
library, including complex types for attributes, entries, and operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import Annotated, TypeVar

from flext_core import FlextResult, FlextTypes
from pydantic import Field

from flext_ldif.constants import FlextLdifConstants

# =============================================================================
# LDIF-SPECIFIC TYPE VARIABLES - Domain-specific TypeVars for LDIF operations
# =============================================================================

# Generic TypeVars T and U imported from flext-core FlextTypes

# TypeVar for generic service retrieval with type narrowing
ServiceT = TypeVar("ServiceT", bound=object)


# LDIF domain TypeVars
class FlextLdifTypes(FlextTypes):
    """LDIF-specific type definitions extending FlextLdifTypes.

    Domain-specific type system for LDIF processing operations.
    Contains ONLY complex LDIF-specific types, no simple aliases.
    Uses Python 3.13+ type syntax and patterns.
    """

    # =========================================================================
    # LDIF ENTRY TYPES - Complex LDIF entry handling types
    # =========================================================================
    # REMOVED: Simple type aliases like BoolDict - use dict[str, object] directly

    class Entry:
        """LDIF entry complex types."""

        type EntryConfiguration = dict[str, str | list[str] | dict[str, object]]
        type EntryAttributes = dict[
            str,
            list[str] | dict[str, FlextLdifTypes.JsonValue],
        ]
        type EntryValidation = dict[str, bool | list[str] | dict[str, object]]
        type EntryTransformation = list[dict[str, str | object]]
        type EntryMetadata = dict[
            str,
            str | int | bool | dict[str, FlextLdifTypes.JsonValue],
        ]
        type EntryProcessing = dict[str, str | bool | list[dict[str, object]]]
        type EntryCreateData = Mapping[str, object]

    # =========================================================================
    # LDIF PARSING TYPES - Complex parsing operation types
    # =========================================================================

    class Parser:
        """LDIF parsing complex types."""

        type ParserConfiguration = dict[str, bool | str | int | dict[str, object]]
        type ParsingContext = dict[
            str,
            str | int | bool | list[str] | dict[str, object],
        ]
        type ParsingResult = dict[str, list[dict[str, object]] | bool | str]
        type ParsingValidation = dict[str, bool | str | list[str] | dict[str, object]]
        type ParsingMetrics = dict[
            str,
            int | float | bool | dict[str, FlextLdifTypes.JsonValue],
        ]
        type ParsingState = dict[str, str | int | bool | list[object]]

    # =========================================================================
    # LDIF VALIDATION TYPES - Complex validation handling types
    # =========================================================================

    class LdifValidation:
        """LDIF validation complex types."""

        type ValidationConfiguration = dict[
            str,
            bool | str | list[str] | dict[str, object],
        ]
        type ValidationRules = list[
            dict[str, str | bool | list[str] | dict[str, object]]
        ]
        type LdifValidationResult = dict[
            str,
            bool | str | list[str] | dict[str, FlextLdifTypes.JsonValue],
        ]
        type ValidationContext = dict[str, str | bool | list[str] | dict[str, object]]
        type ValidationReport = dict[str, int | bool | list[dict[str, object]]]
        type BusinessRules = list[dict[str, str | bool | FlextTypes.PredicateType]]

    # =========================================================================
    # LDIF PROCESSING TYPES - Complex processing operation types
    # =========================================================================

    class LdifProcessing:
        """LDIF processing complex types."""

        type ProcessingConfiguration = dict[str, object | dict[str, object]]
        type ProcessingPipeline = list[
            dict[str, str | Callable[[object], FlextResult[object]]]
        ]
        type ProcessingState = dict[
            str,
            str | int | bool | list[object] | dict[str, object],
        ]
        type ProcessingMetrics = dict[
            str,
            int | float | dict[str, FlextLdifTypes.JsonValue],
        ]
        type LdifProcessingResult = dict[
            str,
            bool | list[object] | dict[str, FlextLdifTypes.JsonValue],
        ]
        type TransformationRules = list[dict[str, str | FlextTypes.MiddlewareType]]

    # =========================================================================
    # LDIF ANALYTICS TYPES - Complex analytics and reporting types
    # =========================================================================

    class Analytics:
        """LDIF analytics complex types."""

        type AnalyticsConfiguration = dict[str, bool | str | int | dict[str, object]]
        type AnalyticsMetrics = dict[
            str,
            int | float | bool | dict[str, FlextLdifTypes.JsonValue],
        ]
        type StatisticalAnalysis = dict[str, float | int | dict[str, int | float]]
        type AnalyticsReport = dict[str, str | int | float | list[dict[str, object]]]
        type TrendAnalysis = dict[str, list[dict[str, int | float | str]]]
        type PerformanceMetrics = dict[str, float | int | bool | dict[str, float]]

    # REMOVED: Simple dict[str, object] aliases - use dict[str, object] directly
    # LdifStatistics, ServiceDict, ManagementDict, ConfigDict, StatusDict, ResultDict,
    # ProcessingDict, ValidationDict, AnalysisDict, ReportDict, EntryDict, AttributesDict,
    # MetadataDict, ContextDict, HealthDict, MetricsDict, StatisticsDict, InfoDict,
    # QuirksDict, AclDict, SchemaDict, ParserDict, ProcessorDict
    # ALL replaced with dict[str, object] for direct usage

    # =========================================================================
    # LDIF WRITING TYPES - Complex LDIF output generation types
    # =========================================================================

    class Writer:
        """LDIF writing complex types."""

        type WriterConfiguration = dict[str, str | bool | int | dict[str, object]]
        type OutputFormat = dict[str, str | bool | list[str] | dict[str, object]]
        type WritingContext = dict[
            str,
            str | bool | dict[str, FlextLdifTypes.JsonValue],
        ]
        type OutputValidation = dict[str, bool | str | list[str]]
        type SerializationRules = list[dict[str, str | Callable[[object], str]]]
        type OutputMetrics = dict[str, int | float | bool]

    # =========================================================================
    # LDIF SERVER TYPES - Complex server-specific operation types
    # =========================================================================

    class ServerTypes:
        """LDIF server-specific complex types."""

        type ServerConfiguration = dict[str, str | int | bool | dict[str, object]]
        type ServerCompatibility = dict[str, bool | list[str] | dict[str, object]]
        type SchemaMapping = dict[
            str,
            str | list[str] | dict[str, FlextLdifTypes.JsonValue],
        ]
        type AttributeMapping = dict[str, str | list[str] | dict[str, object]]
        type ServerOptimization = dict[str, bool | int | dict[str, object]]

    # =========================================================================
    # LDIF LITERALS AND ENUMS - Domain-specific literal types from constants
    # =========================================================================

    # Literal types moved to FlextLdifConstants.LiteralTypes for centralization

    # =========================================================================
    # FUNCTIONAL PROGRAMMING TYPES - Advanced composition patterns
    # =========================================================================

    class Functional:
        """Functional programming complex types for LDIF operations."""

        type ProcessorFunction = Callable[[object], FlextResult[object]]
        type ValidatorFunction = Callable[[object], FlextResult[bool]]
        type TransformerFunction = FlextTypes.MiddlewareType
        type AnalyzerFunction = Callable[
            [Sequence[object]],
            FlextResult[dict[str, FlextLdifTypes.JsonValue]],
        ]
        type WriterFunction = Callable[[Sequence[object]], FlextResult[str]]
        type FilterFunction = FlextTypes.PredicateType

        type CompositionPipeline = list[Callable[[object], FlextResult[object]]]
        type ValidationPipeline = list[Callable[[object], FlextResult[bool]]]
        type TransformationPipeline = list[FlextTypes.MiddlewareType]

    # =========================================================================
    # ITERATOR AND STREAMING TYPES - Memory-efficient processing
    # =========================================================================

    class Streaming:
        """Streaming and iterator complex types for large LDIF processing."""

        type EntryIterator = Iterator[dict[str, FlextLdifTypes.JsonValue]]
        type ValidationIterator = Iterator[FlextResult[bool]]
        type ProcessingIterator = Iterator[FlextResult[dict[str, object]]]
        type StreamingConfiguration = dict[str, int | bool | dict[str, object]]
        type ChunkingStrategy = dict[str, int | str | bool | dict[str, object]]
        type MemoryManagement = dict[str, int | bool | float | dict[str, object]]

    # =========================================================================
    # LDIF MODEL TYPES - Pydantic model-specific type definitions
    # =========================================================================

    class Models:
        """Type definitions for LDIF Pydantic models."""

        # QuirkMetadata types
        type QuirkExtensions = dict[str, bool | str | int | list[int] | None]

        # ACL types
        type PermissionsData = dict[str, bool | str]
        type TargetData = dict[str, str | list[str]]
        type SubjectData = dict[str, str]

        # DiffItem types
        type ItemData = dict[str, object]
        type ItemMetadata = dict[str, object]

        # Schema types
        type AttributesData = dict[str, dict[str, object]]
        type ObjectClassesData = dict[str, dict[str, object]]
        type ObjectClassData = dict[str, object]
        type AttributesInputData = dict[str, object]

        # Entry types (more specific than Entry.EntryCreateData)
        type EntryDnValue = str
        type EntryAttributesDict = dict[str, list[str] | object]

        # Validation and Quirks types with semantic meaning
        type ValidationReportData = dict[
            str,
            str | bool | list[str] | int | dict[str, object],
        ]
        type DNValidationResult = dict[str, bool | list[str]]
        type QuirksRulesData = dict[
            str,
            str | bool | int | list[str] | dict[str, str] | dict[str, object],
        ]
        type ServerQuirksData = dict[str, object]
        type AttributeMappingsData = dict[str, str]
        type EntryValidationResult = dict[str, str | bool | list[str] | int]

        # =====================================================================
        # QUIRKS SCHEMA TYPES - Semantic types for quirks-based schema parsing
        # =====================================================================

        # Parsed attribute definition with metadata and quirk extensions
        # Note: Includes QuirkMetadata in "_metadata" key for tracking
        type QuirkSchemaAttributeData = dict[
            str,
            str
            | bool
            | int
            | list[str]
            | object  # Allows QuirkMetadata and other objects
            | None,
        ]

        # Parsed objectClass definition with metadata and quirk extensions
        # Note: Includes QuirkMetadata in "_metadata" key for tracking
        type QuirkSchemaObjectClassData = dict[
            str,
            str
            | bool
            | int
            | list[str]
            | object  # Allows QuirkMetadata and other objects
            | None,
        ]

        # Extracted schema with attributes and objectClasses lists
        type QuirkSchemaExtractedData = dict[
            str,
            list[dict[str, str | bool | int | list[str] | object | None]] | object,
        ]

        # =====================================================================
        # QUIRKS ACL TYPES - Semantic types for ACL processing
        # =====================================================================

        # Parsed ACL permission entry
        type QuirkAclPermission = dict[str, str | list[str]]

        # Parsed ACL bind rule entry
        type QuirkAclBindRule = dict[str, str]

        # Complete ACL data with permissions, bind rules, and metadata
        # Note: Includes QuirkMetadata in "_metadata" key
        type QuirkAclData = dict[
            str,
            str
            | bool
            | int
            | list[str]
            | list[dict[str, str | list[str]]]
            | object,  # Allows QuirkMetadata and dict values
        ]

        # =====================================================================
        # QUIRKS ENTRY TYPES - Semantic types for entry quirks processing
        # =====================================================================

        # Processed entry data with attributes and metadata
        # Note: Includes QuirkMetadata in "_metadata" key
        type QuirkEntryData = dict[
            str,
            str
            | bool
            | int
            | list[str]
            | list[dict[str, str]]
            | list[object]
            | object,  # Allows QuirkMetadata and various value types
        ]

        # Server-specific conversion result
        type QuirkConversionResult = dict[
            str,
            str | int | bool | dict[str, object] | object,
        ]

    # =========================================================================
    # OPTIMIZED DIRECTORY TYPES - Consolidated high-frequency patterns
    # =========================================================================
    # Eliminates 50+ inline dict definitions across LDIF, LDAP, and migration modules

    class CommonDict:
        """Common dictionary patterns used in LDIF/LDAP operations."""

        # Attribute dictionary: {attribute_name: value(s)}
        # Standardized type compatible with FlextLdap.add_entry()
        # Single-valued attributes: string, Multi-valued: list[str]
        # Used 9+ times in LDIF/LDAP/migration modules
        type AttributeDict = dict[str, str | list[str]]

        # Comparison result: {attribute: (old_values, new_values)}
        # Used 3+ times in diff/comparison operations
        type ChangeDict = dict[str, tuple[list[str], list[str]]]

        # Categorization pattern: {category_name: [items]}
        # Used 2+ times in filtering and grouping operations
        type CategorizedDict = dict[str, list[dict[str, object]]]

        # Statistics/distribution: {key: count}
        # Used 12+ times in metrics and analytics
        type DistributionDict = dict[str, int]

        # Tree/hierarchy: {parent_dn: [children_dns]}
        # Used in DN organization and hierarchy mapping
        type TreeDict = dict[str, list[str]]

        # Nested hierarchy: {parent: {child_data}}
        # Used in nested structure organization
        type HierarchyDict = dict[str, dict[str, object]]

    # =========================================================================
    # ANNOTATED LDIF TYPES - Pydantic v2 Annotated types with validation
    # =========================================================================

    class AnnotatedLdif:
        """LDIF-specific Annotated types with built-in validation constraints.

        Provides reusable Annotated type definitions for LDIF-specific field patterns,
        eliminating verbose Field() declarations in LDIF models and services.

        Example:
        from flext_ldif.typings import FlextLdifTypes
        from pydantic import BaseModel

        class LdifProcessingConfig(BaseModel):
        input_ldif_path: FlextLdifTypes.AnnotatedLdif.LdifFilePath
        encoding: FlextLdifTypes.AnnotatedLdif.EncodingType
        max_entries: FlextLdifTypes.AnnotatedLdif.MaxEntries

        """

        # =====================================================================
        # DN AND ATTRIBUTE TYPES
        # =====================================================================

        DistinguishedName = Annotated[str, Field(min_length=1, max_length=256)]
        """LDAP Distinguished Name (DN) with length constraints."""

        AttributeName = Annotated[
            str,
            Field(pattern=r"^[a-zA-Z]([a-zA-Z0-9\-]*;)?", min_length=1, max_length=64),
        ]
        """LDAP attribute name with format validation."""

        ObjectClassName = Annotated[
            str,
            Field(pattern=r"^[a-zA-Z]([a-zA-Z0-9\-]*)?$", min_length=1, max_length=64),
        ]
        """LDAP objectClass name with format validation."""

        # =====================================================================
        # FILE PATH AND ENCODING TYPES
        # =====================================================================

        LdifFilePath = Annotated[str, Field(min_length=1)]
        """Path to LDIF file with minimum length constraint."""

        InputDirectory = Annotated[str, Field(min_length=1)]
        """Path to input directory with minimum length constraint."""

        OutputDirectory = Annotated[str, Field(min_length=1)]
        """Path to output directory with minimum length constraint."""

        EncodingFormat = Annotated[
            str,
            Field(pattern=r"^(utf-8|latin-1|ascii|iso-8859-1)$"),
        ]
        """Supported encoding formats for LDIF files."""

        # =====================================================================
        # SERVER AND COMPATIBILITY TYPES
        # =====================================================================

        ServerTypeName = Annotated[
            str,
            Field(pattern=r"^(oid|oud|openldap|openldap1|rfc|generic)$"),
        ]
        """LDIF server type selector."""

        ServerHostname = Annotated[str, Field(min_length=1, max_length=256)]
        """Server hostname or IP address."""

        ServerPort = Annotated[int, Field(ge=1, le=65535)]
        """Server port number (valid range: 1-65535)."""

        LdapTimeout = Annotated[int, Field(ge=1, le=600)]
        """LDAP timeout in seconds (1-600 seconds)."""

        # =====================================================================
        # PROCESSING AND VALIDATION TYPES
        # =====================================================================

        MaxEntries = Annotated[int, Field(ge=1, le=1000000)]
        """Maximum number of entries to process (1-1000000)."""

        BatchSize = Annotated[int, Field(ge=1, le=100000)]
        """Batch processing size (1-100000 entries)."""

        MaxWorkers = Annotated[int, Field(ge=1, le=50)]
        """Maximum number of parallel workers (1-50)."""

        MemoryLimit = Annotated[int, Field(ge=1, le=10000)]
        """Memory limit in MB (1-10000 MB)."""

        # =====================================================================
        # VALIDATION LEVEL TYPES
        # =====================================================================

        ValidationLevel = Annotated[str, Field(pattern=r"^(strict|normal|lenient)$")]
        """LDIF validation level (strict, normal, or lenient)."""

        ValidationRuleCount = Annotated[int, Field(ge=0, le=1000)]
        """Number of validation rules (0-1000)."""

        # =====================================================================
        # PROCESSING STAGE TYPES
        # =====================================================================

        ProcessingStage = Annotated[
            str,
            Field(pattern=r"^(parsing|validation|transformation|writing|complete)$"),
        ]
        """Current processing stage in LDIF pipeline."""

        ProcessingTimeout = Annotated[int, Field(ge=10, le=3600)]
        """Processing timeout in seconds (10-3600 seconds)."""

        # =====================================================================
        # STATISTICS AND METRICS TYPES
        # =====================================================================

        EntryCount = Annotated[int, Field(ge=0)]
        """Number of LDIF entries processed."""

        ErrorCount = Annotated[int, Field(ge=0)]
        """Number of errors encountered."""

        SuccessRate = Annotated[float, Field(ge=0.0, le=100.0)]
        """Success percentage (0-100%)."""

    # =========================================================================
    # PYDANTIC MODEL ALIASES - Type aliases referencing FlextLdifModels
    # =========================================================================
    # These provide backward-compatible type aliases while enabling
    # gradual migration to strongly-typed Pydantic v2 models.
    #
    # Migration path:
    # 1. Old code: Uses dict-based types (Parser.ParserConfiguration)
    # 2. New code: Uses model aliases (Models.ParserConfigModel)
    # 3. Future: Direct model usage (FlextLdifModels.ParserConfiguration)

    class ModelAliases:
        """Type aliases for Pydantic models - preferred for new code.

        These aliases reference FlextLdifModels defined in models.py,
        providing strong typing with Pydantic v2 validation and computed fields.
        Use these instead of dict-based types for new implementations.
        """

        # Parser and Writer Configuration Models
        # Replaces: Parser.ParserConfiguration (dict-based)
        # Benefits: Immutable configs, cross-field validation, computed fields
        type ParserConfigModel = (
            object  # Forward reference: FlextLdifModels.ParserConfiguration
        )
        type WriterConfigModel = (
            object  # Forward reference: FlextLdifModels.WriterConfiguration
        )

        # Runtime Context Models
        # Replaces: Parser.ParsingContext, Writer.WritingContext (dict-based)
        # Benefits: Mutable state tracking, progress summaries, error tracking
        type ParsingContextModel = (
            object  # Forward reference: FlextLdifModels.ParsingContext
        )
        type WritingContextModel = (
            object  # Forward reference: FlextLdifModels.WritingContext
        )

        # Validation Models
        # Replaces: Entry.EntryValidation, LdifValidation.LdifValidationResult (dict-based)
        # Benefits: Computed counts, validation summaries, structured errors
        type EntryValidationModel = (
            object  # Forward reference: FlextLdifModels.EntryValidationDetail
        )

        # Transformation Models
        # Replaces: Entry.EntryTransformation (dict-based)
        # Benefits: Transformation tracking, modification detection
        type EntryTransformationModel = (
            object  # Forward reference: FlextLdifModels.EntryTransformationResult
        )

        # Analytics Models
        # Replaces: Analytics.StatisticalAnalysis, Analytics.PerformanceMetrics (dict-based)
        # Benefits: Computed metrics, complexity scores, performance summaries
        type StatisticalAnalysisModel = (
            object  # Forward reference: FlextLdifModels.StatisticalAnalysis
        )
        type PerformanceMetricsModel = (
            object  # Forward reference: FlextLdifModels.PerformanceMetrics
        )

    # =========================================================================
    # MIGRATION GUIDELINES - Dict-based types → Pydantic models
    # =========================================================================
    #
    # OLD (dict-based, to be deprecated):
    #   config: FlextLdifTypes.Parser.ParserConfiguration = {...}
    #   if isinstance(config, dict): ...
    #
    # NEW (Pydantic model, preferred):
    #   from flext_ldif.models import FlextLdifModels
    #   config = FlextLdifModels.ParserConfiguration(file_path="test.ldif")
    #   if config.is_file_based: ...  # Use computed fields
    #
    # BENEFITS OF MODELS:
    # - Type safety: MyPy/Pyrefly strict mode compliance
    # - Validation: Automatic Pydantic field validation
    # - Computed fields: Automatic calculations (error_count, is_rfc_compliant, etc.)
    # - Immutability: ConfigDict(frozen=True) for thread-safety
    # - Serialization: model_dump() for dict, model_dump_json() for JSON

    # =========================================================================
    # LDIF PROJECT TYPES - Domain-specific project types extending FlextTypes
    # =========================================================================

    class LdifProject(FlextTypes):
        """LDIF-specific project types extending FlextTypes.

        Adds LDIF/directory data processing-specific project types while inheriting
        generic types from FlextTypes. Follows domain separation principle:
        LDIF domain owns directory data processing-specific types.
        """

        # Project types moved to FlextLdifConstants.LiteralTypes for centralization

    # Alias for consistency with test expectations
    Project = LdifProject

    # =========================================================================
    # LITERAL TYPES - Import from constants for Pydantic compatibility
    # =========================================================================

    # Import literal types from constants for use in Pydantic models
    # Zero Tolerance: ALL Literal type definitions MUST be in FlextLdifConstants.LiteralTypes
    type ProcessingStage = FlextLdifConstants.LiteralTypes.ProcessingStage
    type HealthStatus = FlextLdifConstants.LiteralTypes.HealthStatus
    type EntryType = FlextLdifConstants.LiteralTypes.EntryType
    type ModificationType = FlextLdifConstants.LiteralTypes.ModificationType
    type ServerType = FlextLdifConstants.LiteralTypes.ServerType
    type EncodingType = FlextLdifConstants.LiteralTypes.EncodingType
    type ValidationLevel = FlextLdifConstants.LiteralTypes.ValidationLevel
    type ProjectType = FlextLdifConstants.LiteralTypes.ProjectType
    # ACL server types - use the same types as ServerType for consistency
    type AclServerType = FlextLdifConstants.LiteralTypes.ServerType


# =============================================================================
# PUBLIC API EXPORTS - LDIF TypeVars and types
# =============================================================================

__all__: list[str] = [
    "FlextLdifTypes",
    "ServiceT",
]
