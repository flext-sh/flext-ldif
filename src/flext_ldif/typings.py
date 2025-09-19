"""FLEXT LDIF Types - Unified type definitions for LDIF operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from flext_core import FlextTypes


class FlextLdifTypes(FlextTypes):
    """LDIF-specific type definitions extending flext-core FlextTypes.

    Single unified class containing all LDIF type definitions
    following SOLID principles and FLEXT ecosystem patterns.

    Uses FlextTypes inheritance to reduce code duplication and ensure
    consistent type patterns across the FLEXT ecosystem.
    """

    # =============================================================================
    # LDIF DOMAIN TYPES (extending FlextTypes.Core)
    # =============================================================================

    class Core(FlextTypes.Core):
        """Core LDIF types extending flext-core types."""

        # LDIF-specific type aliases building on FlextTypes.Core
        LdifEntryDict = dict[str, object]
        LdifAttributeDict = dict[str, FlextTypes.Core.StringList]
        LdifStatistics = dict[str, int | float | FlextTypes.Core.StringList]

        # LDIF processing types
        LdifParseResult = dict[str, object]
        LdifValidationResult = dict[str, bool | str]
        LdifAnalyticsResult = dict[str, int | float | dict[str, object]]

        # LDIF format types
        DistinguishedNameString = str
        AttributeNameString = str
        AttributeValueString = str
        LdifContentString = str

        # LDIF file handling types
        LdifFilePath = str
        LdifFileContent = str
        LdifUrl = str

        # LDIF operation types
        EntryModificationType = str  # add, modify, delete
        OperationResultCode = int

    class Processing:
        """LDIF processing operation types."""

        # Generic type variables for LDIF processing
        T_Entry = TypeVar("T_Entry")
        T_Attribute = TypeVar("T_Attribute")
        T_Result = TypeVar("T_Result")
        T_Statistics = TypeVar("T_Statistics")

        # LDIF processor function types
        EntryProcessor = Callable[[T_Entry], T_Result]
        AttributeProcessor = Callable[
            [str, FlextTypes.Core.StringList],
            FlextTypes.Core.StringList,
        ]
        ValidationProcessor = Callable[[T_Entry], bool]
        StatisticsProcessor = Callable[[list[T_Entry]], T_Statistics]

        # LDIF filter and transformation types
        EntryFilter = Callable[[T_Entry], bool]
        EntryTransformer = Callable[[T_Entry], T_Entry]
        AttributeFilter = Callable[[str, FlextTypes.Core.StringList], bool]
        AttributeTransformer = Callable[
            [str, FlextTypes.Core.StringList],
            FlextTypes.Core.StringList,
        ]

        # LDIF analytics types
        AnalyticsCalculator = Callable[[list[T_Entry]], dict[str, object]]
        StatisticsAggregator = Callable[[dict[str, object]], dict[str, object]]

    class Services:
        """LDIF service-specific types."""

        # Service configuration types
        ParserConfig = dict[str, object]
        ValidatorConfig = dict[str, object]
        WriterConfig = dict[str, object]
        RepositoryConfig = dict[str, object]
        AnalyticsConfig = dict[str, object]
        TransformerConfig = dict[str, object]

        # Service result types
        ParserResult = dict[str, object]
        ValidationResult = dict[str, object]
        WriterResult = dict[str, object]
        RepositoryResult = dict[str, object]
        AnalyticsResult = dict[str, object]
        TransformerResult = dict[str, object]

        # Service operation types (using object instead of object for type safety)
        ServiceOperation = Callable[[object], object]
        ServiceValidator = Callable[[object], bool]
        ServiceProcessor = Callable[[object], object]

    class Analytics:
        """LDIF analytics and statistics types."""

        # Statistics data types
        EntryCount = int
        AttributeCount = int
        ObjectClassCount = int
        DepthDistribution = dict[int, int]
        AttributeDistribution = dict[str, int]
        ObjectClassDistribution = dict[str, int]

        # Analytics calculation types
        StatisticsData = dict[str, int | float | dict[str, object]]
        AnalyticsReport = dict[str, object]
        MetricsCollection = dict[str, float | int]

        # Analytics aggregation types
        AggregationFunction = Callable[[list[object]], float | int]
        GroupingFunction = Callable[[object], str]
        FilterFunction = Callable[[object], bool]

    class LdifValidation:
        """LDIF validation types."""

        # Validation rule types
        ValidationRule = Callable[[object], bool]
        ValidationMessage = str
        ValidationError = dict[str, str]
        ValidationRules = list[ValidationRule]

        # Validation result types
        ValidationStatus = bool
        ValidationMessages = list[str]
        ValidationErrors = list[dict[str, str]]

        # Validation configuration types
        ValidationConfig = dict[str, bool | str | int]
        ValidationOptions = dict[str, object]

    class Configuration:
        """LDIF configuration types."""

        # Configuration data types
        ConfigurationData = dict[str, object]
        ConfigurationOverrides = dict[str, object]
        ConfigurationDefaults = dict[str, object]

        # Configuration validation types
        ConfigurationValidator = Callable[[dict[str, object]], bool]
        ConfigurationProcessor = Callable[[dict[str, object]], dict[str, object]]


__all__ = ["FlextLdifTypes"]
