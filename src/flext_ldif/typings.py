"""FLEXT LDIF Types - Domain-specific LDIF type definitions.

This module provides LDIF-specific type definitions extending FlextTypes.
Follows FLEXT standards:
- Domain-specific complex types only
- No simple aliases to primitive types
- Python 3.13+ syntax
- Extends FlextTypes properly

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import Literal

from flext_core import FlextResult, FlextTypes

# =============================================================================
# LDIF-SPECIFIC TYPE VARIABLES - Domain-specific TypeVars for LDIF operations
# =============================================================================


# LDIF domain TypeVars
class FlextLdifTypes(FlextTypes):
    """LDIF-specific type definitions extending FlextTypes.

    Domain-specific type system for LDIF processing operations.
    Contains ONLY complex LDIF-specific types, no simple aliases.
    Uses Python 3.13+ type syntax and patterns.
    """

    # =========================================================================
    # LDIF ENTRY TYPES - Complex LDIF entry handling types
    # =========================================================================

    class Entry:
        """LDIF entry complex types."""

        type EntryConfiguration = dict[
            str, str | FlextTypes.StringList | dict[str, FlextTypes.ConfigValue]
        ]
        type EntryAttributes = dict[
            str, FlextTypes.StringList | dict[str, FlextTypes.JsonValue]
        ]
        type EntryValidation = dict[str, bool | FlextTypes.StringList | FlextTypes.Dict]
        type EntryTransformation = list[dict[str, str | object]]
        type EntryMetadata = dict[
            str, str | int | bool | dict[str, FlextTypes.JsonValue]
        ]
        type EntryProcessing = dict[str, str | bool | list[FlextTypes.Dict]]
        type EntryCreateData = Mapping[str, object]

    # =========================================================================
    # LDIF PARSING TYPES - Complex parsing operation types
    # =========================================================================

    class Parser:
        """LDIF parsing complex types."""

        type ParserConfiguration = dict[
            str, bool | str | int | dict[str, FlextTypes.ConfigValue]
        ]
        type ParsingContext = dict[
            str, str | int | bool | FlextTypes.StringList | FlextTypes.Dict
        ]
        type ParsingResult = dict[str, list[FlextTypes.Dict] | bool | str]
        type ParsingValidation = dict[
            str, bool | str | FlextTypes.StringList | FlextTypes.Dict
        ]
        type ParsingMetrics = dict[
            str, int | float | bool | dict[str, FlextTypes.JsonValue]
        ]
        type ParsingState = dict[str, str | int | bool | FlextTypes.List]

    # =========================================================================
    # LDIF VALIDATION TYPES - Complex validation handling types
    # =========================================================================

    class LdifValidation:
        """LDIF validation complex types."""

        type ValidationConfiguration = dict[
            str, bool | str | FlextTypes.StringList | dict[str, FlextTypes.ConfigValue]
        ]
        type ValidationRules = list[
            dict[str, str | bool | FlextTypes.StringList | FlextTypes.Dict]
        ]
        type LdifValidationResult = dict[
            str, bool | str | FlextTypes.StringList | dict[str, FlextTypes.JsonValue]
        ]
        type ValidationContext = dict[
            str, str | bool | FlextTypes.StringList | FlextTypes.Dict
        ]
        type ValidationReport = dict[str, int | bool | list[FlextTypes.Dict]]
        type BusinessRules = list[dict[str, str | bool | Callable[[object], bool]]]

    # =========================================================================
    # LDIF PROCESSING TYPES - Complex processing operation types
    # =========================================================================

    class LdifProcessing:
        """LDIF processing complex types."""

        type ProcessingConfiguration = dict[
            str, FlextTypes.ConfigValue | FlextTypes.Dict
        ]
        type ProcessingPipeline = list[
            dict[str, str | Callable[[object], FlextResult[object]]]
        ]
        type ProcessingState = dict[
            str, str | int | bool | FlextTypes.List | FlextTypes.Dict
        ]
        type ProcessingMetrics = dict[
            str, int | float | dict[str, FlextTypes.JsonValue]
        ]
        type LdifProcessingResult = dict[
            str, bool | FlextTypes.List | dict[str, FlextTypes.JsonValue]
        ]
        type TransformationRules = list[dict[str, str | Callable[[object], object]]]

    # =========================================================================
    # LDIF ANALYTICS TYPES - Complex analytics and reporting types
    # =========================================================================

    class Analytics:
        """LDIF analytics complex types."""

        type AnalyticsConfiguration = dict[
            str, bool | str | int | dict[str, FlextTypes.ConfigValue]
        ]
        type AnalyticsMetrics = dict[
            str, int | float | bool | dict[str, FlextTypes.JsonValue]
        ]
        type StatisticalAnalysis = dict[str, float | int | dict[str, int | float]]
        type AnalyticsReport = dict[str, str | int | float | list[FlextTypes.Dict]]
        type TrendAnalysis = dict[str, list[dict[str, int | float | str]]]
        type PerformanceMetrics = dict[str, float | int | bool | FlextTypes.FloatDict]

    # Missing type needed by api.py
    type LdifStatistics = FlextTypes.Dict
    # =========================================================================
    # CORE LDIF TYPES - Commonly used LDIF type aliases extending FlextTypes
    # =========================================================================

    class LdifCore:
        """Core LDIF types extending FlextTypes."""

        # Service and management types
        type ServiceDict = FlextTypes.Dict
        type ManagementDict = FlextTypes.Dict
        type ConfigDict = FlextTypes.Dict
        type StatusDict = FlextTypes.Dict
        type ResultDict = FlextTypes.Dict

        # Processing and validation types
        type ProcessingDict = FlextTypes.Dict
        type ValidationDict = FlextTypes.Dict
        type AnalysisDict = FlextTypes.Dict
        type ReportDict = FlextTypes.Dict

        # Entry and data types
        type EntryDict = FlextTypes.Dict
        type AttributesDict = FlextTypes.Dict
        type MetadataDict = FlextTypes.Dict
        type ContextDict = FlextTypes.Dict

        # Health and monitoring types
        type HealthDict = FlextTypes.Dict
        type MetricsDict = FlextTypes.Dict
        type StatisticsDict = FlextTypes.Dict
        type InfoDict = FlextTypes.Dict

        # Specialized LDIF types
        type QuirksDict = FlextTypes.Dict
        type AclDict = FlextTypes.Dict
        type SchemaDict = FlextTypes.Dict
        type ParserDict = FlextTypes.Dict
        type ProcessorDict = FlextTypes.Dict

    # =========================================================================
    # LDIF WRITING TYPES - Complex LDIF output generation types
    # =========================================================================

    class Writer:
        """LDIF writing complex types."""

        type WriterConfiguration = dict[
            str, str | bool | int | dict[str, FlextTypes.ConfigValue]
        ]
        type OutputFormat = dict[
            str, str | bool | FlextTypes.StringList | FlextTypes.Dict
        ]
        type WritingContext = dict[str, str | bool | dict[str, FlextTypes.JsonValue]]
        type OutputValidation = dict[str, bool | str | FlextTypes.StringList]
        type SerializationRules = list[dict[str, str | Callable[[object], str]]]
        type OutputMetrics = dict[str, int | float | bool]

    # =========================================================================
    # LDIF SERVER TYPES - Complex server-specific operation types
    # =========================================================================

    class ServerTypes:
        """LDIF server-specific complex types."""

        type ServerConfiguration = dict[
            str, str | int | bool | dict[str, FlextTypes.ConfigValue]
        ]
        type ServerCompatibility = dict[
            str, bool | FlextTypes.StringList | FlextTypes.Dict
        ]
        type SchemaMapping = dict[
            str, str | FlextTypes.StringList | dict[str, FlextTypes.JsonValue]
        ]
        type AttributeMapping = dict[str, str | FlextTypes.StringList | FlextTypes.Dict]
        type ServerOptimization = dict[
            str, bool | int | dict[str, FlextTypes.ConfigValue]
        ]

    # =========================================================================
    # LDIF LITERALS AND ENUMS - Domain-specific literal types
    # =========================================================================

    # Processing stage literals
    type ProcessingStage = Literal["parsing", "validation", "analytics", "writing"]
    type HealthStatus = Literal["healthy", "degraded", "unhealthy"]
    type HealthStatusDict = dict[str, HealthStatus | str | int | bool]
    type EntryType = Literal["person", "group", "organizationalunit", "domain", "other"]
    type ModificationType = Literal["add", "modify", "delete", "modrdn"]

    # Server type literals
    type ServerType = Literal[
        "active_directory",
        "openldap",
        "apache_directory",
        "novell_edirectory",
        "ibm_tivoli",
        "generic",
    ]

    # Encoding type literals
    type EncodingType = Literal[
        "utf-8", "latin-1", "ascii", "utf-16", "utf-32", "cp1252", "iso-8859-1"
    ]

    # Validation level literals
    type ValidationLevel = Literal["strict", "moderate", "lenient"]

    # =========================================================================
    # FUNCTIONAL PROGRAMMING TYPES - Advanced composition patterns
    # =========================================================================

    class Functional:
        """Functional programming complex types for LDIF operations."""

        type ProcessorFunction = Callable[[object], FlextResult[object]]
        type ValidatorFunction = Callable[[object], FlextResult[bool]]
        type TransformerFunction = Callable[[object], object]
        type AnalyzerFunction = Callable[
            [Sequence[object]], FlextResult[dict[str, FlextTypes.JsonValue]]
        ]
        type WriterFunction = Callable[[Sequence[object]], FlextResult[str]]
        type FilterFunction = Callable[[object], bool]

        type CompositionPipeline = list[Callable[[object], FlextResult[object]]]
        type ValidationPipeline = list[Callable[[object], FlextResult[bool]]]
        type TransformationPipeline = list[Callable[[object], object]]

    # =========================================================================
    # ITERATOR AND STREAMING TYPES - Memory-efficient processing
    # =========================================================================

    class Streaming:
        """Streaming and iterator complex types for large LDIF processing."""

        type EntryIterator = Iterator[dict[str, FlextTypes.JsonValue]]
        type ValidationIterator = Iterator[FlextResult[bool]]
        type ProcessingIterator = Iterator[FlextResult[FlextTypes.Dict]]
        type StreamingConfiguration = dict[
            str, int | bool | dict[str, FlextTypes.ConfigValue]
        ]
        type ChunkingStrategy = dict[str, int | str | bool | FlextTypes.Dict]
        type MemoryManagement = dict[
            str, int | bool | float | dict[str, FlextTypes.ConfigValue]
        ]

    # =========================================================================
    # LDIF PROJECT TYPES - Domain-specific project types extending FlextTypes
    # =========================================================================

    class Project(FlextTypes.Project):
        """LDIF-specific project types extending FlextTypes.Project.

        Adds LDIF/directory data processing-specific project types while inheriting
        generic types from FlextTypes. Follows domain separation principle:
        LDIF domain owns directory data processing-specific types.
        """

        # LDIF-specific project types extending the generic ones
        type LdifProjectType = Literal[
            # Generic types inherited from FlextTypes.Project
            "library",
            "application",
            "service",
            # LDIF-specific types
            "ldif-processor",
            "directory-converter",
            "ldif-validator",
            "ldif-analyzer",
            "ldif-parser",
            "directory-migrator",
            "ldap-data-processor",
            "ldif-transformer",
            "directory-sync",
            "ldif-exporter",
            "ldif-importer",
            "data-migration",
            "ldif-etl",
            "directory-backup",
            "ldif-merger",
            "schema-converter",
        ]

        # LDIF-specific project configurations
        type LdifProjectConfig = dict[str, FlextTypes.ConfigValue | object]
        type ProcessingConfig = dict[str, str | int | bool | FlextTypes.StringList]
        type ValidationConfig = dict[str, bool | str | FlextTypes.Dict]
        type TransformationConfig = dict[str, FlextTypes.ConfigValue | object]


# =============================================================================
# PUBLIC API EXPORTS - LDIF TypeVars and types
# =============================================================================

__all__: FlextTypes.StringList = [
    "FlextLdifTypes",
]
