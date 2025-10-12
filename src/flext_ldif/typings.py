"""FLEXT LDIF Types - Domain-specific LDIF type definitions.

This module provides LDIF-specific type definitions extending FlextLdifTypes.
Follows FLEXT standards:
- Domain-specific complex types only
- No simple aliases to primitive types
- Python 3.13+ syntax
- Extends FlextCore.Types properly

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence

from flext_core import FlextCore

from flext_ldif.constants import FlextLdifConstants

# =============================================================================
# LDIF-SPECIFIC TYPE VARIABLES - Domain-specific TypeVars for LDIF operations
# =============================================================================

# Generic TypeVars T and U imported from flext-core FlextCore.Types


# LDIF domain TypeVars
class FlextLdifTypes(FlextCore.Types):
    """LDIF-specific type definitions extending FlextLdifTypes.

    Domain-specific type system for LDIF processing operations.
    Contains ONLY complex LDIF-specific types, no simple aliases.
    Uses Python 3.13+ type syntax and patterns.
    """

    # =========================================================================
    # LDIF ENTRY TYPES - Complex LDIF entry handling types
    # =========================================================================
    # REMOVED: Simple type aliases like BoolDict - use FlextCore.Types.Dict directly

    class Entry:
        """LDIF entry complex types."""

        type EntryConfiguration = dict[
            str, str | FlextLdifTypes.StringList | dict[str, FlextLdifTypes.ConfigValue]
        ]
        type EntryAttributes = dict[
            str, FlextLdifTypes.StringList | dict[str, FlextLdifTypes.JsonValue]
        ]
        type EntryValidation = dict[
            str, bool | FlextLdifTypes.StringList | FlextCore.Types.Dict
        ]
        type EntryTransformation = list[dict[str, str | object]]
        type EntryMetadata = dict[
            str, str | int | bool | dict[str, FlextLdifTypes.JsonValue]
        ]
        type EntryProcessing = dict[str, str | bool | list[FlextCore.Types.Dict]]
        type EntryCreateData = Mapping[str, object]

    # =========================================================================
    # LDIF PARSING TYPES - Complex parsing operation types
    # =========================================================================

    class Parser:
        """LDIF parsing complex types."""

        type ParserConfiguration = dict[
            str, bool | str | int | dict[str, FlextLdifTypes.ConfigValue]
        ]
        type ParsingContext = dict[
            str, str | int | bool | FlextLdifTypes.StringList | FlextCore.Types.Dict
        ]
        type ParsingResult = dict[str, list[FlextCore.Types.Dict] | bool | str]
        type ParsingValidation = dict[
            str, bool | str | FlextLdifTypes.StringList | FlextCore.Types.Dict
        ]
        type ParsingMetrics = dict[
            str, int | float | bool | dict[str, FlextLdifTypes.JsonValue]
        ]
        type ParsingState = dict[str, str | int | bool | FlextLdifTypes.List]

    # =========================================================================
    # LDIF VALIDATION TYPES - Complex validation handling types
    # =========================================================================

    class LdifValidation:
        """LDIF validation complex types."""

        type ValidationConfiguration = dict[
            str,
            bool
            | str
            | FlextLdifTypes.StringList
            | dict[str, FlextLdifTypes.ConfigValue],
        ]
        type ValidationRules = list[
            dict[str, str | bool | FlextLdifTypes.StringList | FlextCore.Types.Dict]
        ]
        type LdifValidationResult = dict[
            str,
            bool
            | str
            | FlextLdifTypes.StringList
            | dict[str, FlextLdifTypes.JsonValue],
        ]
        type ValidationContext = dict[
            str, str | bool | FlextLdifTypes.StringList | FlextCore.Types.Dict
        ]
        type ValidationReport = dict[str, int | bool | list[FlextCore.Types.Dict]]
        type BusinessRules = list[dict[str, str | bool | Callable[[object], bool]]]

    # =========================================================================
    # LDIF PROCESSING TYPES - Complex processing operation types
    # =========================================================================

    class LdifProcessing:
        """LDIF processing complex types."""

        type ProcessingConfiguration = dict[
            str, FlextLdifTypes.ConfigValue | FlextCore.Types.Dict
        ]
        type ProcessingPipeline = list[
            dict[str, str | Callable[[object], FlextCore.Result[object]]]
        ]
        type ProcessingState = dict[
            str, str | int | bool | FlextLdifTypes.List | FlextCore.Types.Dict
        ]
        type ProcessingMetrics = dict[
            str, int | float | dict[str, FlextLdifTypes.JsonValue]
        ]
        type LdifProcessingResult = dict[
            str, bool | FlextLdifTypes.List | dict[str, FlextLdifTypes.JsonValue]
        ]
        type TransformationRules = list[dict[str, str | Callable[[object], object]]]

    # =========================================================================
    # LDIF ANALYTICS TYPES - Complex analytics and reporting types
    # =========================================================================

    class Analytics:
        """LDIF analytics complex types."""

        type AnalyticsConfiguration = dict[
            str, bool | str | int | dict[str, FlextLdifTypes.ConfigValue]
        ]
        type AnalyticsMetrics = dict[
            str, int | float | bool | dict[str, FlextLdifTypes.JsonValue]
        ]
        type StatisticalAnalysis = dict[str, float | int | dict[str, int | float]]
        type AnalyticsReport = dict[str, str | int | float | list[FlextCore.Types.Dict]]
        type TrendAnalysis = dict[str, list[dict[str, int | float | str]]]
        type PerformanceMetrics = dict[
            str, float | int | bool | FlextLdifTypes.FloatDict
        ]

    # REMOVED: Simple FlextCore.Types.Dict aliases - use FlextCore.Types.Dict directly
    # LdifStatistics, ServiceDict, ManagementDict, ConfigDict, StatusDict, ResultDict,
    # ProcessingDict, ValidationDict, AnalysisDict, ReportDict, EntryDict, AttributesDict,
    # MetadataDict, ContextDict, HealthDict, MetricsDict, StatisticsDict, InfoDict,
    # QuirksDict, AclDict, SchemaDict, ParserDict, ProcessorDict
    # ALL replaced with FlextCore.Types.Dict for direct usage

    # =========================================================================
    # LDIF WRITING TYPES - Complex LDIF output generation types
    # =========================================================================

    class Writer:
        """LDIF writing complex types."""

        type WriterConfiguration = dict[
            str, str | bool | int | dict[str, FlextLdifTypes.ConfigValue]
        ]
        type OutputFormat = dict[
            str, str | bool | FlextLdifTypes.StringList | FlextCore.Types.Dict
        ]
        type WritingContext = dict[
            str, str | bool | dict[str, FlextLdifTypes.JsonValue]
        ]
        type OutputValidation = dict[str, bool | str | FlextLdifTypes.StringList]
        type SerializationRules = list[dict[str, str | Callable[[object], str]]]
        type OutputMetrics = dict[str, int | float | bool]

    # =========================================================================
    # LDIF SERVER TYPES - Complex server-specific operation types
    # =========================================================================

    class ServerTypes:
        """LDIF server-specific complex types."""

        type ServerConfiguration = dict[
            str, str | int | bool | dict[str, FlextLdifTypes.ConfigValue]
        ]
        type ServerCompatibility = dict[
            str, bool | FlextLdifTypes.StringList | FlextCore.Types.Dict
        ]
        type SchemaMapping = dict[
            str, str | FlextLdifTypes.StringList | dict[str, FlextLdifTypes.JsonValue]
        ]
        type AttributeMapping = dict[
            str, str | FlextLdifTypes.StringList | FlextCore.Types.Dict
        ]
        type ServerOptimization = dict[
            str, bool | int | dict[str, FlextLdifTypes.ConfigValue]
        ]

    # =========================================================================
    # LDIF LITERALS AND ENUMS - Domain-specific literal types from constants
    # =========================================================================

    # Literal types moved to FlextLdifConstants.LiteralTypes for centralization

    # =========================================================================
    # FUNCTIONAL PROGRAMMING TYPES - Advanced composition patterns
    # =========================================================================

    class Functional:
        """Functional programming complex types for LDIF operations."""

        type ProcessorFunction = Callable[[object], FlextCore.Result[object]]
        type ValidatorFunction = Callable[[object], FlextCore.Result[bool]]
        type TransformerFunction = Callable[[object], object]
        type AnalyzerFunction = Callable[
            [Sequence[object]], FlextCore.Result[dict[str, FlextLdifTypes.JsonValue]]
        ]
        type WriterFunction = Callable[[Sequence[object]], FlextCore.Result[str]]
        type FilterFunction = Callable[[object], bool]

        type CompositionPipeline = list[Callable[[object], FlextCore.Result[object]]]
        type ValidationPipeline = list[Callable[[object], FlextCore.Result[bool]]]
        type TransformationPipeline = list[Callable[[object], object]]

    # =========================================================================
    # ITERATOR AND STREAMING TYPES - Memory-efficient processing
    # =========================================================================

    class Streaming:
        """Streaming and iterator complex types for large LDIF processing."""

        type EntryIterator = Iterator[dict[str, FlextLdifTypes.JsonValue]]
        type ValidationIterator = Iterator[FlextCore.Result[bool]]
        type ProcessingIterator = Iterator[FlextCore.Result[FlextCore.Types.Dict]]
        type StreamingConfiguration = dict[
            str, int | bool | dict[str, FlextLdifTypes.ConfigValue]
        ]
        type ChunkingStrategy = dict[str, int | str | bool | FlextCore.Types.Dict]
        type MemoryManagement = dict[
            str, int | bool | float | dict[str, FlextLdifTypes.ConfigValue]
        ]

    # =========================================================================
    # LDIF PROJECT TYPES - Domain-specific project types extending FlextCore.Types
    # =========================================================================

    class Project(FlextCore.Types.Project):
        """LDIF-specific project types extending FlextCore.Types.Project.

        Adds LDIF/directory data processing-specific project types while inheriting
        generic types from FlextCore.Types. Follows domain separation principle:
        LDIF domain owns directory data processing-specific types.
        """

        # Project types moved to FlextLdifConstants.LiteralTypes for centralization

    # =========================================================================
    # LITERAL TYPES - Import from constants for Pydantic compatibility
    # =========================================================================

    # Import literal types from constants for use in Pydantic models
    # ZERO TOLERANCE: ALL Literal type definitions MUST be in FlextLdifConstants.LiteralTypes
    type ProcessingStage = FlextLdifConstants.LiteralTypes.ProcessingStage
    type HealthStatus = FlextLdifConstants.LiteralTypes.HealthStatus
    type EntryType = FlextLdifConstants.LiteralTypes.EntryType
    type ModificationType = FlextLdifConstants.LiteralTypes.ModificationType
    type ServerType = FlextLdifConstants.LiteralTypes.ServerType
    type EncodingType = FlextLdifConstants.LiteralTypes.EncodingType
    type ValidationLevel = FlextLdifConstants.LiteralTypes.ValidationLevel
    type ProjectType = FlextLdifConstants.LiteralTypes.ProjectType


# =============================================================================
# PUBLIC API EXPORTS - LDIF TypeVars and types
# =============================================================================

__all__: FlextLdifTypes.StringList = [
    "FlextLdifTypes",
]
