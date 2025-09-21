"""Unified LDIF Processor - Main entry point for all LDIF operations.

This module provides the unified FlextLdifProcessor class that consolidates
functionality from multiple overlapping modules into a single, coherent API
following FLEXT unified class patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import cast

# Constants
MAX_ERROR_DISPLAY_COUNT = 3

from flext_core import (
    FlextContainer,
    FlextDomainService,
    FlextLogger,
    FlextResult,
    FlextUtilities,
)

from .config import FlextLdifConfig
from .constants import FlextLdifConstants
from .format_handlers import FlextLdifFormatHandler
from .models import FlextLdifModels

__all__ = ["FlextLdifProcessor"]


class FlextLdifProcessor(FlextDomainService[dict[str, object]]):
    """Unified LDIF Processor - Single comprehensive class for all LDIF operations.

    Consolidates functionality from multiple modules into a cohesive, optimized API:
    - Core parsing, writing, validation operations
    - Advanced analytics with pattern recognition and anomaly detection
    - File discovery and processing utilities
    - Entry filtering, transformation, and analysis capabilities
    - Performance tracking and health monitoring
    - Enhanced validation with configurable rules
    - Intelligent caching and optimization features

    Follows FLEXT unified class pattern with comprehensive responsibilities
    leveraging flext-core advanced features for maximum efficiency.
    """

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize unified LDIF processor with advanced flext-core integration.

        Args:
            config: Optional LDIF processing configuration

        """
        super().__init__()
        self._logger = FlextLogger(__name__)
        self._container = FlextContainer.get_global()
        self._config = config or FlextLdifConfig()
        self._utilities = FlextUtilities()

        # Performance tracking
        self._start_time = time.time()
        self._operation_count = 0
        self._total_entries_processed = 0

        # Enhanced service tracking
        self._validation_count = 0
        self._analysis_count = 0
        self._transformation_count = 0
        self._write_operations = 0
        self._parse_operations = 0

        # Advanced analytics tracking
        self._total_analyses = 0
        self._total_entries_analyzed = 0
        self._analysis_failures = 0
        self._pattern_detections = 0
        self._anomaly_detections = 0

        # Validation performance tracking
        self._total_validations = 0
        self._total_entries_validated = 0
        self._validation_failures = 0
        self._schema_validations = 0
        self._dn_validations = 0

        # Validation statistics by type
        self._validation_stats = {
            "dn_format_errors": 0,
            "missing_objectclass_errors": 0,
            "missing_required_attributes": 0,
            "invalid_attribute_values": 0,
            "schema_violations": 0,
            "encoding_errors": 0,
        }

        # Performance metrics
        self._validation_times: list[float] = []
        self._analysis_times: list[float] = []
        self._slow_validation_threshold = 1.0  # seconds
        self._slow_analysis_threshold = 3.0  # seconds
        self._batch_size_threshold = 1000  # entries

        # Validation configuration
        self._strict_mode = self._config.ldif_strict_validation
        self._validate_objectclass = self._config.ldif_validate_object_class
        self._validate_dn_format = self._config.ldif_validate_dn_format
        self._allow_empty_values = self._config.ldif_allow_empty_values

        # Analytics configuration and caching
        self._analytics_cache: dict[
            str,
            tuple[dict[str, int] | dict[str, object], float],
        ] = {}
        self._cache_ttl = 600.0  # 10 minutes for analytics cache
        self._max_cache_size = self._config.ldif_analytics_cache_size
        self._large_dataset_threshold = 50000  # entries

        # Pattern recognition thresholds
        self._pattern_confidence_threshold = 0.75
        self._anomaly_detection_sensitivity = 0.95
        self._min_pattern_support = 10  # minimum occurrences

        # Analytics statistics
        self._analytics_stats = {
            "basic_analyses": 0,
            "pattern_analyses": 0,
            "anomaly_detections": 0,
            "cached_results": 0,
            "deep_analyses": 0,
            "trend_analyses": 0,
        }

        # Initialize format handler using flext-core patterns
        self._format_handler = FlextLdifFormatHandler()

        self._logger.info(
            "processor_initialized",
            config_sealed=self._config.is_sealed(),
            unified_features=True,
            advanced_analytics=True,
            intelligent_validation=True,
            performance_optimized=True,
        )

    @property
    def config(self) -> FlextLdifConfig:
        """Access processor configuration."""
        return self._config

    class _ValidationHelper:
        """Enhanced validation helper with monadic patterns and railway composition."""

        def __init__(self, processor: FlextLdifProcessor) -> None:
            self._processor = processor
            self._logger = processor._logger
            self._config = processor._config

        def validate_single_entry_with_context(
            self,
            entry: FlextLdifModels.Entry,
            index: int,
        ) -> FlextResult[bool]:
            """Validate single entry with monadic composition and enhanced context.

            Returns:
                FlextResult[bool]: Validation result

            """
            return (
                self._validate_entry_business_rules(entry, index)
                .flat_map(lambda _: self._validate_entry_structure_safe(entry, index))
                .flat_map(lambda _: self._validate_schema_compliance_safe(entry, index))
                .map(lambda _: True)
                .tap_error(
                    lambda error: self._log_validation_failure(entry, index, error)
                )
            )

        def validate_entry_structure(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[bool]:
            """Validate entry structure with monadic composition.

            Returns:
                FlextResult[bool]: Validation result

            """
            return (
                self._validate_dn_structure(entry)
                .flat_map(lambda _: self._validate_objectclass_presence(entry))
                .flat_map(lambda _: self._validate_attribute_values(entry))
                .map(lambda _: True)
            )

        def validate_dn_format(self, dn: str) -> FlextResult[bool]:
            """Validate DN format with enhanced monadic error handling.

            Returns:
                FlextResult[bool]: Validation result

            """
            start_time = time.time()
            self._processor.increment_dn_validations()

            return (
                FlextResult[str]
                .safe_call(dn.strip)
                .flat_map(self._create_dn_object)
                .flat_map(self._validate_dn_business_rules)
                .map(lambda _: True)
                .tap_error(
                    lambda error: self._record_dn_validation_failure(
                        dn, error, start_time
                    )
                )
                .tap(lambda _: self._record_dn_validation_success(dn, start_time))
            )

        def validate_schema_compliance(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[bool]:
            """Validate entry against LDAP schema rules with monadic composition."""
            self._processor.increment_schema_validations()

            return (
                self._extract_objectclasses(entry)
                .flat_map(
                    lambda ocs: self._validate_required_attributes_for_objectclasses(
                        entry, ocs
                    )
                )
                .map(lambda _: True)
                .tap_error(
                    lambda error: self._record_schema_validation_failure(entry, error)
                )
            )

        # Private monadic helper methods
        def _validate_entry_business_rules(
            self, entry: FlextLdifModels.Entry, index: int
        ) -> FlextResult[bool]:
            """Validate entry business rules using FlextResult."""
            return (
                FlextResult[FlextLdifModels.Entry]
                .safe_call(lambda: entry)
                .flat_map(lambda e: e.validate_business_rules())
                .map(lambda _: True)
                .tap_error(
                    lambda error: self._logger.error(
                        f"Entry {index} business rules validation failed: {error}"
                    )
                )
            )

        def _validate_entry_structure_safe(
            self, entry: FlextLdifModels.Entry, index: int
        ) -> FlextResult[bool]:
            """Safe entry structure validation wrapper."""
            return self.validate_entry_structure(entry).tap_error(
                lambda error: self._logger.error(
                    f"Entry {index} structure validation failed: {error}"
                )
            )

        @staticmethod
        def _validate_schema_compliance_safe(entry: Entry) -> FlextResult[bool]:
            """Validate schema compliance safely."""
            try:
                if not entry.attributes.data:
                    return FlextResult[bool].fail("Entry has no attributes")
                return FlextResult[bool].ok(value=True)
            except Exception as e:
                return FlextResult[bool].fail(f"Schema validation error: {e!s}")

        def _validate_dn_structure(
            self, entry: FlextLdifModels.Entry
        ) -> FlextResult[bool]:
            """Validate DN structure with monadic composition."""
            return self.validate_dn_format(entry.dn.value).tap_error(
                lambda _: self._processor.increment_validation_stat("dn_format_errors")
            )

        def _validate_objectclass_presence(
            self, entry: FlextLdifModels.Entry
        ) -> FlextResult[bool]:
            """Validate objectClass presence if required."""
            if not self._config.ldif_validate_object_class:
                return FlextResult[bool].ok(value=True)

            attributes = entry.attributes.data

            if "objectClass" not in attributes:
                self._processor.increment_validation_stat("missing_objectclass_errors")
                return FlextResult[bool].fail("Missing required objectClass attribute")

            if not attributes["objectClass"]:
                self._processor.increment_validation_stat("missing_objectclass_errors")
                return FlextResult[bool].fail("objectClass attribute cannot be empty")

            return FlextResult[bool].ok(value=True)

        def _validate_attribute_values(
            self, entry: FlextLdifModels.Entry
        ) -> FlextResult[bool]:
            """Validate attribute values if empty values are not allowed."""
            if self._config.ldif_allow_empty_values:
                return FlextResult[bool].ok(value=True)

            for attr_name, attr_values in entry.attributes.data.items():
                if not attr_values or any(not value.strip() for value in attr_values):
                    self._processor.increment_validation_stat(
                        "invalid_attribute_values"
                    )
                    return FlextResult[bool].fail(
                        f"Empty values not allowed for attribute: {attr_name}"
                    )

            return FlextResult[bool].ok(value=True)

        def _create_dn_object(
            self, dn: str
        ) -> FlextResult[FlextLdifModels.DistinguishedName]:
            """Create DN object safely."""
            return FlextResult[FlextLdifModels.DistinguishedName].safe_call(
                lambda: FlextLdifModels.DistinguishedName(value=dn)
            )

        def _validate_dn_business_rules(
            self, dn_obj: FlextLdifModels.DistinguishedName
        ) -> FlextResult[bool]:
            """Validate DN business rules."""
            return dn_obj.validate_business_rules()

        def _extract_objectclasses(
            self, entry: FlextLdifModels.Entry
        ) -> FlextResult[list[str]]:
            """Extract objectClasses from entry."""
            attributes = entry.attributes.data
            object_classes = attributes.get("objectClass", [])

            if not object_classes:
                self._processor.increment_validation_stat("schema_violations")
                return FlextResult[list[str]].fail(
                    "Missing objectClass for schema validation"
                )

            return FlextResult[list[str]].ok(object_classes)

        def _validate_required_attributes_for_objectclasses(
            self, entry: FlextLdifModels.Entry, object_classes: list[str]
        ) -> FlextResult[bool]:
            """Validate required attributes for all objectClasses."""
            attributes = entry.attributes.data

            for obj_class in object_classes:
                obj_class_lower = obj_class.lower()

                # Validate person class attributes
                if (
                    obj_class_lower
                    in FlextLdifConstants.ObjectClasses.LDAP_PERSON_CLASSES
                ):
                    result = self._validate_required_attributes(
                        attributes,
                        FlextLdifConstants.Required.REQUIRED_PERSON_ATTRIBUTES,
                        obj_class,
                    )
                    if result.is_failure:
                        return result

                # Validate organizational unit attributes
                elif (
                    obj_class_lower
                    in FlextLdifConstants.ObjectClasses.LDAP_ORGANIZATIONAL_CLASSES
                ):
                    result = self._validate_required_attributes(
                        attributes,
                        FlextLdifConstants.Required.REQUIRED_ORGUNIT_ATTRIBUTES,
                        obj_class,
                    )
                    if result.is_failure:
                        return result

                # Validate domain attributes
                elif (
                    obj_class_lower
                    in FlextLdifConstants.ObjectClasses.LDAP_DOMAIN_CLASSES
                ):
                    result = self._validate_required_attributes(
                        attributes,
                        FlextLdifConstants.Required.REQUIRED_DOMAIN_ATTRIBUTES,
                        obj_class,
                    )
                    if result.is_failure:
                        return result

            return FlextResult[bool].ok(value=True)

        def _validate_required_attributes(
            self,
            attributes: dict[str, list[str]],
            required_attrs: frozenset[str],
            obj_class: str,
        ) -> FlextResult[bool]:
            """Validate required attributes for a specific objectClass."""
            for required_attr in required_attrs:
                if required_attr not in attributes:
                    self._processor.increment_validation_stat(
                        "missing_required_attributes"
                    )
                    return FlextResult[bool].fail(
                        f"Missing required attribute '{required_attr}' for objectClass '{obj_class}'"
                    )

            return FlextResult[bool].ok(value=True)

        # Logging and metrics helpers
        def _log_validation_failure(
            self, entry: FlextLdifModels.Entry, index: int, error: str
        ) -> None:
            """Log validation failure with context."""
            self._logger.error(
                "Entry validation failed",
                entry_index=index,
                dn=entry.dn.value,
                error=error,
            )

        def _record_dn_validation_failure(
            self, dn: str, error: str, start_time: float
        ) -> None:
            """Record DN validation failure metrics."""
            validation_time = time.time() - start_time
            self._processor.increment_validation_stat("dn_format_errors")

            self._logger.debug(
                "DN validation failed",
                dn=dn,
                error=error,
                validation_time_seconds=validation_time,
            )

        def _record_dn_validation_success(self, dn: str, start_time: float) -> None:
            """Record DN validation success metrics."""
            validation_time = time.time() - start_time
            self._logger.debug(
                "DN validation succeeded",
                dn=dn,
                validation_time_seconds=validation_time,
            )

        def _record_schema_validation_failure(
            self, entry: FlextLdifModels.Entry, error: str
        ) -> None:
            """Record schema validation failure metrics."""
            self._processor.increment_validation_stat("schema_violations")
            self._logger.error(
                "Schema validation error", dn=entry.dn.value, error=error
            )

    class _AnalyticsHelper:
        """Enhanced analytics helper with sequence/traverse patterns and monadic composition."""

        def __init__(self, processor: FlextLdifProcessor) -> None:
            self._processor = processor
            self._logger = processor._logger
            self._config = processor._config

        def get_entries_hash(self, entries: list[FlextLdifModels.Entry]) -> str:
            """Generate a hash for entries using monadic composition."""
            return (
                FlextResult[list[FlextLdifModels.Entry]]
                .ok(entries)
                .map(
                    lambda entries: entries[: min(10, len(entries))] if entries else []
                )
                .map(lambda sample: [e.dn.value for e in sample])
                .map(lambda dns: str(hash(tuple(dns))) if dns else "empty")
                .unwrap_or("empty")
            )

        def classify_entry_types(
            self,
            entries: list[FlextLdifModels.Entry],
        ) -> dict[str, int]:
            """Classify entries using sequence patterns and monadic composition."""
            initial_types = {
                "user_accounts": 0,
                "service_accounts": 0,
                "security_groups": 0,
                "distribution_groups": 0,
                "containers": 0,
                "computers": 0,
                "unknown_types": 0,
            }

            return (
                FlextResult[list[FlextLdifModels.Entry]]
                .ok(entries)
                .map(
                    lambda entries: self._sequence_classify_entries(
                        entries, initial_types
                    )
                )
                .unwrap_or(initial_types)
            )

        def calculate_data_quality_metrics(
            self,
            entries: list[FlextLdifModels.Entry],
        ) -> dict[str, int]:
            """Calculate data quality metrics using traverse patterns."""
            if not entries:
                return {}

            return (
                FlextResult[list[FlextLdifModels.Entry]]
                .ok(entries)
                .flat_map(self._traverse_quality_analysis)
                .map(lambda metrics: self._compute_quality_score(metrics, len(entries)))
                .unwrap_or({})
            )

        def detect_structural_patterns(
            self,
            entries: list[FlextLdifModels.Entry],
        ) -> dict[str, int]:
            """Detect structural patterns using monadic composition."""
            initial_patterns = {
                "hierarchical_entries": 0,
                "flat_entries": 0,
                "mixed_structure": 0,
            }

            return (
                FlextResult[list[FlextLdifModels.Entry]]
                .ok(entries)
                .map(self._analyze_entry_depths)
                .map(
                    lambda depths: self._classify_structural_patterns(
                        depths, len(entries)
                    )
                )
                .unwrap_or(initial_patterns)
            )

        def detect_objectclass_anomalies(
            self,
            distribution: dict[str, int],
            total_entries: int,
        ) -> list[str]:
            """Detect anomalies using functional composition."""
            if total_entries == 0:
                return []

            return (
                FlextResult[dict[str, int]]
                .ok(distribution)
                .map(
                    lambda dist: [
                        self._detect_rare_objectclass_anomaly(oc, count, total_entries)
                        for oc, count in dist.items()
                    ]
                )
                .map(
                    lambda anomaly_results: [
                        anomaly for anomaly in anomaly_results if anomaly is not None
                    ]
                )
                .unwrap_or([])
            )

        def perform_anomaly_detection(
            self,
            entries: list[FlextLdifModels.Entry],
        ) -> dict[str, list[str]]:
            """Perform comprehensive anomaly detection using traverse patterns."""
            default_anomalies: dict[str, list[str]] = {
                "unusual_attribute_counts": [],
                "rare_objectclasses": [],
                "suspicious_dns": [],
            }

            if not entries:
                return default_anomalies

            return (
                FlextResult[list[FlextLdifModels.Entry]]
                .ok(entries)
                .flat_map(self._traverse_anomaly_detection)
                .unwrap_or(default_anomalies)
            )

        # Private monadic helper methods using sequence/traverse patterns
        def _sequence_classify_entries(
            self, entries: list[FlextLdifModels.Entry], types: dict[str, int]
        ) -> dict[str, int]:
            """Classify entries using sequence operations."""
            for entry in entries:
                entry_type = self._classify_single_entry(entry)
                types[entry_type] = types.get(entry_type, 0) + 1
            return types

        def _classify_single_entry(self, entry: FlextLdifModels.Entry) -> str:
            """Classify a single entry type using monadic composition."""
            return (
                FlextResult[FlextLdifModels.Entry]
                .ok(entry)
                .map(self._extract_objectclasses_set)
                .flat_map(lambda ocs: self._determine_entry_category(entry, ocs))
                .unwrap_or("unknown_types")
            )

        def _extract_objectclasses_set(self, entry: FlextLdifModels.Entry) -> set[str]:
            """Extract objectClasses as a set."""
            object_classes = (
                entry.get_attribute(FlextLdifConstants.Format.OBJECTCLASS_ATTRIBUTE)
                or []
            )
            return {oc.lower() for oc in object_classes}

        def _determine_entry_category(
            self, entry: FlextLdifModels.Entry, object_classes: set[str]
        ) -> FlextResult[str]:
            """Determine entry category based on objectClasses."""
            dn_lower = entry.dn.value.lower()

            if object_classes.intersection({"user", "inetorgperson", "person"}):
                if "service" in dn_lower or "svc" in dn_lower:
                    return FlextResult[str].ok("service_accounts")
                return FlextResult[str].ok("user_accounts")
            if object_classes.intersection({
                "group",
                "groupofnames",
                "groupofuniquenames",
            }):
                if "security" in dn_lower:
                    return FlextResult[str].ok("security_groups")
                return FlextResult[str].ok("distribution_groups")
            if object_classes.intersection({"container", "organizationalunit"}):
                return FlextResult[str].ok("containers")
            if object_classes.intersection({"computer"}):
                return FlextResult[str].ok("computers")
            return FlextResult[str].ok("unknown_types")

        def _traverse_quality_analysis(
            self, entries: list[FlextLdifModels.Entry]
        ) -> FlextResult[dict[str, int]]:
            """Traverse entries for quality analysis using monadic patterns."""
            empty_attributes = 0
            missing_required_attrs = 0

            for entry in entries:
                # Check empty attributes
                if self._has_empty_attributes(entry):
                    empty_attributes += 1

                # Check missing required attributes
                if self._has_missing_required_attributes(entry):
                    missing_required_attrs += 1

            return FlextResult[dict[str, int]].ok({
                "entries_with_empty_attributes": empty_attributes,
                "entries_missing_required_attributes": missing_required_attrs,
            })

        def _has_empty_attributes(self, entry: FlextLdifModels.Entry) -> bool:
            """Check if entry has empty attributes."""
            for values in entry.attributes.data.values():
                if not values or any(not v.strip() for v in values):
                    return True
            return False

        def _has_missing_required_attributes(
            self, entry: FlextLdifModels.Entry
        ) -> bool:
            """Check if entry has missing required attributes."""
            object_classes = self._extract_objectclasses_set(entry)

            if object_classes.intersection(
                FlextLdifConstants.ObjectClasses.LDAP_PERSON_CLASSES
            ):
                required_attrs = FlextLdifConstants.Required.REQUIRED_PERSON_ATTRIBUTES
                return not all(attr in entry.attributes.data for attr in required_attrs)

            return False

        def _compute_quality_score(
            self, metrics: dict[str, int], total_entries: int
        ) -> dict[str, int]:
            """Compute quality score from metrics."""
            empty_attrs = metrics.get("entries_with_empty_attributes", 0)
            missing_attrs = metrics.get("entries_missing_required_attributes", 0)

            quality_score = int(
                100 * (1 - (empty_attrs + missing_attrs) / total_entries)
            )

            return {
                **metrics,
                "data_quality_score": quality_score,
            }

        def _analyze_entry_depths(
            self, entries: list[FlextLdifModels.Entry]
        ) -> dict[int, int]:
            """Analyze entry depths using functional composition."""
            depth_counts: dict[int, int] = {}

            for entry in entries:
                depth = len(entry.dn.value.split(","))
                depth_counts[depth] = depth_counts.get(depth, 0) + 1

            return depth_counts

        def _classify_structural_patterns(
            self, depth_counts: dict[int, int], total_entries: int
        ) -> dict[str, int]:
            """Classify structural patterns based on depth analysis."""
            patterns = {
                "hierarchical_entries": 0,
                "flat_entries": 0,
                "mixed_structure": 0,
            }

            if len(depth_counts) == 1:
                single_depth = next(iter(depth_counts.keys()))
                if single_depth <= FlextLdifConstants.Analytics.MAX_FLAT_ENTRY_DEPTH:
                    patterns["flat_entries"] = total_entries
                else:
                    patterns["hierarchical_entries"] = total_entries
            else:
                patterns["mixed_structure"] = total_entries

            return patterns

        def _detect_rare_objectclass_anomaly(
            self, oc: str, count: int, total_entries: int
        ) -> str | None:
            """Detect rare objectClass anomaly."""
            ratio = count / total_entries
            if (
                ratio < FlextLdifConstants.Analytics.RARE_OBJECTCLASS_RATIO_THRESHOLD
                and count
                < FlextLdifConstants.Analytics.RARE_OBJECTCLASS_COUNT_THRESHOLD
            ):
                return f"rare_objectclass_{oc}"
            return None

        def _traverse_anomaly_detection(
            self, entries: list[FlextLdifModels.Entry]
        ) -> FlextResult[dict[str, list[str]]]:
            """Traverse entries for anomaly detection using monadic patterns."""
            anomalies: dict[str, list[str]] = {
                "unusual_attribute_counts": [],
                "rare_objectclasses": [],
                "suspicious_dns": [],
            }

            # Calculate thresholds
            attr_counts = [len(e.attributes.data) for e in entries]
            avg_attrs = sum(attr_counts) / len(attr_counts) if attr_counts else 0
            threshold = avg_attrs * 2

            # Analyze each entry
            for entry in entries:
                # Check unusual attribute counts
                if len(entry.attributes.data) > threshold:
                    anomalies["unusual_attribute_counts"].append(entry.dn.value)

                # Check suspicious DNs
                if self._is_suspicious_dn(entry.dn.value):
                    anomalies["suspicious_dns"].append(entry.dn.value)

            return FlextResult[dict[str, list[str]]].ok(anomalies)

        def _is_suspicious_dn(self, dn: str) -> bool:
            """Check if DN is suspicious based on length and characters."""
            return len(
                dn
            ) > FlextLdifConstants.Validation.MAX_SUSPICIOUS_DN_LENGTH or any(
                c in dn for c in "<>[]{}"
            )

    class _TransformationHelper:
        """Enhanced transformation helper with railway composition and monadic patterns."""

        def __init__(self, processor: FlextLdifProcessor) -> None:
            self._processor = processor
            self._logger = processor._logger

        def apply_transformation(
            self,
            entries: list[FlextLdifModels.Entry],
            transformation: Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry],
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Apply transformation using railway composition and error accumulation."""
            return (
                FlextResult[list[FlextLdifModels.Entry]]
                .ok(entries)
                .flat_map(
                    lambda entries: self._validate_transformation_inputs(
                        entries, transformation
                    )
                )
                .flat_map(
                    lambda inputs: self._apply_transformation_pipeline(
                        inputs[0], inputs[1]
                    )
                )
                .tap_error(self._log_transformation_failure)
            )

        def apply_safe_transformation(
            self,
            entries: list[FlextLdifModels.Entry],
            transformation: Callable[
                [FlextLdifModels.Entry], FlextResult[FlextLdifModels.Entry]
            ],
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Apply safe transformation that returns FlextResult with error accumulation."""
            return (
                FlextResult[list[FlextLdifModels.Entry]]
                .ok(entries)
                .flat_map(
                    lambda entries: self._validate_safe_transformation_inputs(
                        entries, transformation
                    )
                )
                .flat_map(
                    lambda inputs: self._apply_safe_transformation_pipeline(
                        inputs[0], inputs[1]
                    )
                )
                .tap_error(self._log_transformation_failure)
            )

        def apply_batch_transformation(
            self,
            entries: list[FlextLdifModels.Entry],
            transformations: list[
                Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry]
            ],
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Apply multiple transformations in sequence using railway composition."""
            return (
                FlextResult[list[FlextLdifModels.Entry]]
                .ok(entries)
                .flat_map(
                    lambda entries: self._validate_batch_inputs(
                        entries, transformations
                    )
                )
                .flat_map(
                    lambda inputs: self._apply_transformation_sequence(
                        inputs[0], inputs[1]
                    )
                )
                .tap_error(self._log_batch_transformation_failure)
            )

        def transform_with_validation(
            self,
            entries: list[FlextLdifModels.Entry],
            transformation: Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry],
            validator: Callable[[FlextLdifModels.Entry], FlextResult[bool]],
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Apply transformation with validation using railway composition."""
            return (
                FlextResult[list[FlextLdifModels.Entry]]
                .ok(entries)
                .flat_map(
                    lambda entries: self._transform_and_validate_pipeline(
                        entries, transformation, validator
                    )
                )
                .tap_error(self._log_validation_transformation_failure)
            )

        def filter_and_transform(
            self,
            entries: list[FlextLdifModels.Entry],
            filter_predicate: Callable[[FlextLdifModels.Entry], bool],
            transformation: Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry],
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Filter entries and apply transformation using monadic composition."""
            return (
                FlextResult[list[FlextLdifModels.Entry]]
                .ok(entries)
                .map(
                    lambda entries: [
                        entry for entry in entries if filter_predicate(entry)
                    ]
                )
                .flat_map(
                    lambda filtered: self.apply_transformation(filtered, transformation)
                )
                .tap(
                    lambda result: self._log_filter_transform_success(
                        len(entries), len(result)
                    )
                )
            )

        # Private railway composition methods
        def _validate_transformation_inputs(
            self,
            entries: list[FlextLdifModels.Entry],
            transformation: Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry],
        ) -> FlextResult[
            tuple[
                list[FlextLdifModels.Entry],
                Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry],
            ]
        ]:
            """Validate inputs for transformation pipeline."""
            if not entries:
                return FlextResult.fail(
                    "Cannot apply transformation to empty entry list"
                )

            # Type annotation ensures callable, so no runtime check needed
            return FlextResult.ok((entries, transformation))

        def _apply_transformation_pipeline(
            self,
            entries: list[FlextLdifModels.Entry],
            transformation: Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry],
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Apply transformation pipeline using monadic composition."""
            transformed_entries: list[FlextLdifModels.Entry] = []

            for i, entry in enumerate(entries):
                result = self._transform_single_entry(entry, transformation, i)
                if result.is_failure:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        result.error or "Transformation failed"
                    )
                if result.data is not None:
                    transformed_entries.append(result.data)

            return FlextResult[list[FlextLdifModels.Entry]].ok(transformed_entries)

        def _transform_single_entry(
            self,
            entry: FlextLdifModels.Entry,
            transformation: Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry],
            index: int,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Transform single entry safely."""
            return (
                FlextResult[FlextLdifModels.Entry]
                .safe_call(lambda: transformation(entry))
                .tap_error(
                    lambda error: self._log_single_entry_transformation_failure(
                        entry, index, error
                    )
                )
            )

        def _validate_safe_transformation_inputs(
            self,
            entries: list[FlextLdifModels.Entry],
            transformation: Callable[
                [FlextLdifModels.Entry], FlextResult[FlextLdifModels.Entry]
            ],
        ) -> FlextResult[
            tuple[
                list[FlextLdifModels.Entry],
                Callable[[FlextLdifModels.Entry], FlextResult[FlextLdifModels.Entry]],
            ]
        ]:
            """Validate inputs for safe transformation pipeline."""
            if not entries:
                return FlextResult.fail(
                    "Cannot apply safe transformation to empty entry list"
                )

            # Type annotation ensures callable, so no runtime check needed
            return FlextResult.ok((entries, transformation))

        def _apply_safe_transformation_pipeline(
            self,
            entries: list[FlextLdifModels.Entry],
            transformation: Callable[
                [FlextLdifModels.Entry], FlextResult[FlextLdifModels.Entry]
            ],
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Apply safe transformation pipeline with error accumulation."""
            transformed_entries: list[FlextLdifModels.Entry] = []
            errors: list[str] = []

            for i, entry in enumerate(entries):
                result = transformation(entry)
                if result.is_failure:
                    error_msg = f"Entry {i} (DN: {entry.dn.value}): {result.error or 'Unknown error'}"
                    errors.append(error_msg)
                    self._log_single_entry_transformation_failure(
                        entry, i, result.error or "Unknown error"
                    )
                elif result.data is not None:
                    transformed_entries.append(result.data)

            if errors:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Safe transformation failed for {len(errors)} entries: {'; '.join(errors[:MAX_ERROR_DISPLAY_COUNT])}"
                    + (
                        f" (and {len(errors) - MAX_ERROR_DISPLAY_COUNT} more)"
                        if len(errors) > MAX_ERROR_DISPLAY_COUNT
                        else ""
                    )
                )

            return FlextResult[list[FlextLdifModels.Entry]].ok(transformed_entries)

        def _validate_batch_inputs(
            self,
            entries: list[FlextLdifModels.Entry],
            transformations: list[
                Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry]
            ],
        ) -> FlextResult[
            tuple[
                list[FlextLdifModels.Entry],
                list[Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry]],
            ]
        ]:
            """Validate inputs for batch transformation."""
            if not entries:
                return FlextResult[
                    tuple[
                        list[FlextLdifModels.Entry],
                        list[Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry]],
                    ]
                ].fail("Cannot apply batch transformation to empty entry list")

            if not transformations:
                return FlextResult[
                    tuple[
                        list[FlextLdifModels.Entry],
                        list[Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry]],
                    ]
                ].fail("Cannot apply empty transformation list")

            if not all(callable(t) for t in transformations):
                return FlextResult[
                    tuple[
                        list[FlextLdifModels.Entry],
                        list[Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry]],
                    ]
                ].fail("All transformations must be callable")

            return FlextResult[
                tuple[
                    list[FlextLdifModels.Entry],
                    list[Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry]],
                ]
            ].ok((entries, transformations))

        def _apply_transformation_sequence(
            self,
            entries: list[FlextLdifModels.Entry],
            transformations: list[
                Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry]
            ],
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Apply transformation sequence using railway composition."""
            current_entries = entries

            for i, transformation in enumerate(transformations):
                result = self.apply_transformation(current_entries, transformation)
                if result.is_failure:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Batch transformation failed at step {i + 1}: {result.error or 'Unknown error'}"
                    )
                if result.data is not None:
                    current_entries = result.data

            return FlextResult[list[FlextLdifModels.Entry]].ok(current_entries)

        def _transform_and_validate_pipeline(
            self,
            entries: list[FlextLdifModels.Entry],
            transformation: Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry],
            validator: Callable[[FlextLdifModels.Entry], FlextResult[bool]],
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Transform and validate using railway composition."""
            return self.apply_transformation(entries, transformation).flat_map(
                lambda transformed: self._validate_transformed_entries(
                    transformed, validator
                )
            )

        def _validate_transformed_entries(
            self,
            entries: list[FlextLdifModels.Entry],
            validator: Callable[[FlextLdifModels.Entry], FlextResult[bool]],
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Validate transformed entries."""
            validation_errors: list[str] = []

            for i, entry in enumerate(entries):
                validation_result = validator(entry)
                if validation_result.is_failure:
                    validation_errors.append(
                        f"Entry {i} validation failed: {validation_result.error}"
                    )

            if validation_errors:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Validation failed for {len(validation_errors)} entries: {'; '.join(validation_errors[:MAX_ERROR_DISPLAY_COUNT])}"
                    + (
                        f" (and {len(validation_errors) - MAX_ERROR_DISPLAY_COUNT} more)"
                        if len(validation_errors) > MAX_ERROR_DISPLAY_COUNT
                        else ""
                    )
                )

            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

        # Logging helpers
        def _log_transformation_failure(self, error: str) -> None:
            """Log transformation failure."""
            self._logger.error("Transformation pipeline failed", error=error)

        def _log_batch_transformation_failure(self, error: str) -> None:
            """Log batch transformation failure."""
            self._logger.error("Batch transformation pipeline failed", error=error)

        def _log_validation_transformation_failure(self, error: str) -> None:
            """Log validation transformation failure."""
            self._logger.error("Transform and validate pipeline failed", error=error)

        def _log_single_entry_transformation_failure(
            self, entry: FlextLdifModels.Entry, index: int, error: str
        ) -> None:
            """Log single entry transformation failure."""
            self._logger.error(
                "Single entry transformation failed",
                entry_index=index,
                dn=entry.dn.value,
                error=error,
            )

        def _log_filter_transform_success(
            self, original_count: int, filtered_count: int
        ) -> None:
            """Log filter and transform success."""
            self._logger.info(
                "Filter and transform completed",
                original_entries=original_count,
                filtered_entries=filtered_count,
                entries_processed=filtered_count,
            )

    # Core Processing Operations

    def parse_ldif_file(
        self, file_path: str | Path
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF file with enhanced validation and railway pattern composition."""
        file_path_obj = Path(file_path)

        return (
            self._validate_file_path(file_path_obj)
            .flat_map(self._read_file_content)
            .flat_map(self._parse_content_with_metrics)
            .map(self._log_parse_file_success(file_path_obj))
            .tap_error(
                lambda error: self._logger.error(
                    "parse_file_failed", file_path=str(file_path_obj), error=error
                )
            )
        )

    def parse_string(self, content: str) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF content string with railway pattern composition."""
        # Handle empty content as success case (not failure)
        if not content.strip():
            self._logger.debug("parse_string_empty_content")
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        return (
            FlextResult[str]
            .ok(content)
            .flat_map(self._parse_content_with_metrics)
            .tap_error(
                lambda error: self._logger.error(
                    "parse_string_failed", error=error, content_size=len(content)
                )
            )
        )

    def write_file(
        self,
        entries: list[FlextLdifModels.Entry],
        file_path: str | Path,
    ) -> FlextResult[bool]:
        """Write entries to LDIF file with railway pattern composition."""
        file_path_obj = Path(file_path)
        start_time = time.time()

        return (
            self._validate_entries_for_writing(entries)
            .flat_map(self.write_string)
            .flat_map(
                lambda content: self._write_content_to_file(content, file_path_obj)
            )
            .map(lambda _: True)
            .map(self._record_write_file_metrics(file_path_obj, entries, start_time))
            .tap_error(
                lambda error: self._logger.error(
                    "write_file_failed", file_path=str(file_path_obj), error=error
                )
            )
        )

    def write_string(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[str]:
        """Write entries to LDIF string format using railway pattern composition."""
        return (
            self._validate_entries_for_writing(entries)
            .flat_map(self._format_handler.write_ldif)
            .map(self._record_write_metrics(entries))
            .tap_error(
                lambda error: self._logger.error(
                    "write_string_failed", entries_count=len(entries), error=error
                )
            )
        )

    # Enhanced Validation Operations

    def validate_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[bool]:
        """Validate LDIF entries using monadic sequence composition."""
        start_time = time.time()

        return (
            self._validate_batch_preconditions(entries)
            .flat_map(
                lambda validated_entries: self._execute_validation_sequence(
                    validated_entries, start_time
                )
            )
            .map(lambda _: True)
            .tap_error(
                lambda error: self._logger.error(
                    "batch_validation_failed", entries_count=len(entries), error=error
                )
            )
        )

    def validate_entry(self, entry: FlextLdifModels.Entry) -> FlextResult[bool]:
        """Validate single LDIF entry with railway pattern composition."""
        start_time = time.time()

        return (
            FlextResult[FlextLdifModels.Entry]
            .ok(entry)
            .flat_map(self._execute_single_validation)
            .map(lambda _: True)
            .map(self._record_single_validation_success(start_time))
            .tap_error(
                lambda error: self._logger.error(
                    "single_validation_failed", dn=entry.dn.value, error=error
                )
            )
        )

    # Advanced Analytics Operations

    def analyze_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[dict[str, int]]:
        """Comprehensive entry analysis with monadic composition."""
        start_time = time.time()

        return (
            self._validate_analytics_input(entries)
            .flat_map(
                lambda validated_entries: self._execute_cached_analysis(
                    validated_entries, start_time, "basic_analysis"
                )
            )
            .tap_error(
                lambda error: self._logger.error(
                    "analyze_entries_failed", entries_count=len(entries), error=error
                )
            )
        )

    def get_objectclass_distribution(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[dict[str, int]]:
        """Advanced object class distribution analysis with monadic composition."""
        start_time = time.time()

        return (
            self._validate_analytics_input(entries)
            .flat_map(
                lambda validated_entries: self._execute_cached_analysis(
                    validated_entries, start_time, "objectclass_distribution"
                )
            )
            .tap_error(
                lambda error: self._logger.error(
                    "objectclass_distribution_failed",
                    entries_count=len(entries),
                    error=error,
                )
            )
        )

    def get_dn_depth_analysis(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[dict[str, int]]:
        """Advanced DN depth analysis with pattern recognition."""
        start_time = time.time()

        try:
            analytics = self._AnalyticsHelper(self)
            cache_key = f"dn_depth:{len(entries)}:{analytics.get_entries_hash(entries)}"

            cached_result = self._get_from_analytics_cache(cache_key)
            if cached_result is not None:
                self._analytics_stats["cached_results"] += 1
                cached_dict = cast("dict[str, int]", cached_result)
                return FlextResult[dict[str, int]].ok(cached_dict)

            self._logger.info(
                "Starting DN depth analysis",
                extra={"entry_count": len(entries)},
            )

            depth_distribution: dict[str, int] = {}
            depth_values: list[int] = []
            base_dn_patterns: dict[str, int] = {}

            for entry in entries:
                dn_parts = [part.strip() for part in entry.dn.value.split(",")]
                depth = len(dn_parts)
                depth_values.append(depth)

                # Track depth distribution
                depth_key = f"depth_{depth}"
                depth_distribution[depth_key] = depth_distribution.get(depth_key, 0) + 1

                # Analyze base DN patterns (last 2-3 components)
                if len(dn_parts) >= FlextLdifConstants.Validation.MIN_DN_PARTS_FOR_BASE:
                    base_components = dn_parts[-2:]  # Take last 2 components
                    base_dn = ",".join(base_components)
                    base_dn_patterns[base_dn] = base_dn_patterns.get(base_dn, 0) + 1

            # Statistical analysis
            if depth_values:
                avg_depth = sum(depth_values) / len(depth_values)
                max_depth = max(depth_values)
                min_depth = min(depth_values)

                # Detect depth anomalies (simplified version)
                avg_depth_int = int(avg_depth)
                depth_anomalies = [
                    f"unusual_depth_{depth}"
                    for depth in set(depth_values)
                    if abs(depth - avg_depth_int)
                    > FlextLdifConstants.Analytics.MAX_DEPTH_DEVIATION
                ]
            else:
                avg_depth = max_depth = min_depth = 0
                depth_anomalies = []

            # Enhanced analysis
            enhanced_analysis = {
                **depth_distribution,
                "avg_depth": int(avg_depth),
                "max_depth": max_depth,
                "min_depth": min_depth,
                "depth_range": max_depth - min_depth,
                "unique_depths": len(set(depth_values)),
                "base_dn_patterns": len(base_dn_patterns),
                "most_common_base_dn_count": max(base_dn_patterns.values())
                if base_dn_patterns
                else 0,
            }

            # Add significant base DN patterns
            for base_dn, count in base_dn_patterns.items():
                if count >= self._min_pattern_support:
                    safe_key = f"base_pattern_{hash(base_dn) % 10000}"
                    enhanced_analysis[safe_key] = count

            # Add anomaly information
            if depth_anomalies:
                enhanced_analysis["depth_anomalies_detected"] = len(depth_anomalies)
                self._anomaly_detections += 1

            # Cache the result
            self._store_in_analytics_cache(cache_key, enhanced_analysis)

            analysis_time = time.time() - start_time
            self._record_analysis_success(len(entries), analysis_time)

            self._logger.info(
                "DN depth analysis completed",
                extra={
                    "entry_count": len(entries),
                    "avg_depth": enhanced_analysis["avg_depth"],
                    "depth_range": enhanced_analysis["depth_range"],
                    "base_patterns": enhanced_analysis["base_dn_patterns"],
                    "analysis_time_seconds": analysis_time,
                },
            )

            return FlextResult[dict[str, int]].ok(enhanced_analysis)

        except Exception as e:
            analysis_time = time.time() - start_time
            self._record_analysis_failure("dn_depth_analysis_error")

            self._logger.exception(
                "DN depth analysis failed",
                extra={
                    "entry_count": len(entries),
                    "error": str(e),
                    "analysis_time_seconds": analysis_time,
                },
            )

            return FlextResult[dict[str, int]].fail(f"DN depth analysis error: {e}")

    # File Discovery and Management

    def discover_ldif_files(
        self,
        directory_path: str | Path | None = None,
        file_pattern: str = "*.ldif",
        max_file_size_mb: int | None = None,
    ) -> FlextResult[list[Path]]:
        """Discover LDIF files using pattern matching and size filtering."""
        if max_file_size_mb is None:
            max_file_size_mb = self._config.ldif_max_file_size_mb

        try:
            # Get files to process
            files_result = self._get_files_to_process(directory_path, file_pattern)
            if files_result.is_failure:
                return files_result

            files_to_process = files_result.unwrap()

            # Filter by size and sort
            filtered_files = self._filter_files_by_size(
                files_to_process, max_file_size_mb
            )
            sorted_files = sorted(filtered_files)

            self._logger.debug(
                "file_discovery_completed",
                found_files=len(sorted_files),
                skipped_files=len(files_to_process) - len(filtered_files),
            )

            return FlextResult[list[Path]].ok(sorted_files)

        except Exception as exc:
            self._logger.exception("discover_files_unexpected_error", error=str(exc))
            return FlextResult[list[Path]].fail(f"File discovery failed: {exc}")

    # Entry Filtering Operations

    def filter_persons(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter person entries from entry list."""
        try:
            filtered = [entry for entry in entries if entry.is_person_entry()]
            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)
        except Exception as exc:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Filter persons failed: {exc}"
            )

    def filter_groups(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter group entries from entry list."""
        try:
            filtered = [entry for entry in entries if entry.is_group_entry()]
            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)
        except Exception as exc:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Filter groups failed: {exc}"
            )

    def filter_by_objectclass(
        self, entries: list[FlextLdifModels.Entry], object_class: str
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by objectClass attribute."""
        try:
            filtered = []
            for entry in entries:
                object_classes = entry.get_attribute("objectClass") or []
                if any(oc.lower() == object_class.lower() for oc in object_classes):
                    filtered.append(entry)
            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)
        except Exception as exc:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Filter by objectclass failed: {exc}"
            )

    def filter_by_attribute(
        self, entries: list[FlextLdifModels.Entry], attribute: str, value: str
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by specific attribute value."""
        try:
            filtered = []
            for entry in entries:
                attr_values = entry.get_attribute(attribute) or []
                if value in attr_values:
                    filtered.append(entry)
            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)
        except Exception as exc:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Filter by attribute failed: {exc}"
            )

    # Transformation Operations

    def transform(
        self,
        entries: list[FlextLdifModels.Entry],
        transformation: Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry]
        | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Transform LDIF entries using specified transformation rules."""
        try:
            self._logger.debug(
                "Transforming LDIF entries",
                extra={
                    "entry_count": len(entries),
                    "has_transformation": transformation is not None,
                },
            )

            if transformation is None:
                # Default transformation - return entries as-is
                return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

            transformer = self._TransformationHelper(self)
            result = transformer.apply_transformation(entries, transformation)

            if result.is_success:
                self._transformation_count += 1

            return result
        except Exception as e:
            self._logger.exception("LDIF entry transformation failed")
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Transform error: {e}"
            )

    # Utility Operations

    def sort_hierarchically(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort entries hierarchically by DN depth."""
        if not entries:
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        try:

            def sort_by_dn_depth(entry: FlextLdifModels.Entry) -> int:
                """Calculate DN depth for sorting."""
                return len(entry.dn.value.split(","))

            sorted_entries = sorted(entries, key=sort_by_dn_depth)
            return FlextResult[list[FlextLdifModels.Entry]].ok(sorted_entries)
        except Exception as exc:
            return FlextResult[list[FlextLdifModels.Entry]].fail(f"Sort failed: {exc}")

    def find_entry_by_dn(
        self, entries: list[FlextLdifModels.Entry], dn: str
    ) -> FlextResult[FlextLdifModels.Entry | None]:
        """Find entry by Distinguished Name."""
        try:
            for entry in entries:
                if entry.dn.value == dn:
                    return FlextResult[FlextLdifModels.Entry | None].ok(entry)
            return FlextResult[FlextLdifModels.Entry | None].ok(None)
        except Exception as exc:
            return FlextResult[FlextLdifModels.Entry | None].fail(
                f"Find entry failed: {exc}"
            )

    def normalize_dn(self, dn: str) -> FlextResult[str]:
        """Normalize DN format according to LDAP standards."""
        try:
            # Normalize DN format
            components: list[str] = []
            for raw_component in dn.split(","):
                component = raw_component.strip()
                if "=" in component:
                    key, value = component.split("=", 1)
                    key = key.strip().lower()
                    value = value.strip()
                    components.append(f"{key}={value}")
                else:
                    components.append(component)

            normalized_dn = ",".join(components)

            # Validate using domain model
            dn_model = FlextLdifModels.DistinguishedName(value=normalized_dn)
            validation_result = dn_model.validate_business_rules()
            if validation_result.is_failure:
                return FlextResult[str].fail(
                    validation_result.error or "Invalid DN format"
                )

            return FlextResult[str].ok(normalized_dn)
        except Exception as exc:
            return FlextResult[str].fail(f"DN normalization failed: {exc}")

    # Performance and Monitoring

    def get_performance_metrics(self) -> FlextResult[dict[str, object]]:
        """Get comprehensive performance metrics for the processor."""
        try:
            current_time = time.time()
            uptime = current_time - self._start_time

            metrics: dict[str, object] = {
                "uptime_ms": uptime * 1000,
                "operation_count": self._operation_count,
                "total_entries_processed": self._total_entries_processed,
                "config_sealed": self._config.is_sealed(),
                "avg_entries_per_operation": (
                    self._total_entries_processed / max(self._operation_count, 1)
                ),
                "operations_per_second": (
                    self._operation_count / max(uptime, 1.0) if uptime > 0 else 0.0
                ),
                "operation_breakdown": {
                    "parse_operations": self._parse_operations,
                    "write_operations": self._write_operations,
                    "validation_count": self._validation_count,
                    "analysis_count": self._analysis_count,
                    "transformation_count": self._transformation_count,
                },
                "validation_metrics": {
                    "total_validations": self._total_validations,
                    "total_entries_validated": self._total_entries_validated,
                    "validation_failures": self._validation_failures,
                    "schema_validations": self._schema_validations,
                    "dn_validations": self._dn_validations,
                    "success_rate": self._calculate_validation_success_rate(),
                },
                "analytics_metrics": {
                    "total_analyses": self._total_analyses,
                    "total_entries_analyzed": self._total_entries_analyzed,
                    "analysis_failures": self._analysis_failures,
                    "pattern_detections": self._pattern_detections,
                    "anomaly_detections": self._anomaly_detections,
                    "analytics_success_rate": self._calculate_analytics_success_rate(),
                },
            }

            self._logger.debug("performance_metrics_requested", **metrics)
            return FlextResult[dict[str, object]].ok(metrics)

        except Exception as exc:
            self._logger.exception("performance_metrics_failed", error=str(exc))
            return FlextResult[dict[str, object]].fail(
                f"Performance metrics failed: {exc}"
            )

    def reset_performance_metrics(self) -> FlextResult[None]:
        """Reset performance tracking metrics."""
        self._start_time = time.time()
        self._operation_count = 0
        self._total_entries_processed = 0

        # Reset operation-specific counters
        self._validation_count = 0
        self._analysis_count = 0
        self._transformation_count = 0
        self._write_operations = 0
        self._parse_operations = 0

        # Reset analytics metrics
        self._total_analyses = 0
        self._total_entries_analyzed = 0
        self._analysis_failures = 0
        self._pattern_detections = 0
        self._anomaly_detections = 0

        # Reset validation metrics
        self._total_validations = 0
        self._total_entries_validated = 0
        self._validation_failures = 0
        self._schema_validations = 0
        self._dn_validations = 0

        # Clear performance tracking lists
        self._validation_times.clear()
        self._analysis_times.clear()

        # Reset error statistics
        for key in self._validation_stats:
            self._validation_stats[key] = 0

        for key in self._analytics_stats:
            self._analytics_stats[key] = 0

        self._logger.info("performance_metrics_reset")
        return FlextResult[None].ok(None)

    def health_check(self) -> FlextResult[dict[str, object]]:
        """Perform comprehensive health check of processor and all integrated services."""
        # Get performance metrics
        metrics_result = self.get_performance_metrics()
        performance_metrics = (
            metrics_result.unwrap() if metrics_result.is_success else {}
        )

        health_status = {
            "processor_healthy": True,
            "unified_services_initialized": True,
            "config_valid": True,
            "performance_metrics": performance_metrics,
        }

        try:
            # Test basic functionality with minimal LDIF content
            test_content = (
                "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\nsn: test"
            )
            test_result = self.parse_string(test_content)
            health_status["parser_healthy"] = test_result.is_success

            if test_result.is_success:
                entries = test_result.unwrap()
                validation_result = self.validate_entries(entries)
                health_status["validator_healthy"] = validation_result.is_success

                if validation_result.is_success:
                    write_result = self.write_string(entries)
                    health_status["writer_healthy"] = write_result.is_success

                    # Test analytics
                    analytics_result = self.analyze_entries(entries)
                    health_status["analytics_healthy"] = analytics_result.is_success

        except Exception as exc:
            health_status["processor_healthy"] = False
            health_status["health_check_error"] = str(exc)
            self._logger.exception("health_check_failed", error=str(exc))

        # Overall health determination
        overall_healthy = all([
            health_status.get("processor_healthy", False),
            health_status.get("parser_healthy", False),
            health_status.get("validator_healthy", False),
            health_status.get("writer_healthy", False),
            health_status.get("analytics_healthy", False),
        ])

        health_status["overall_healthy"] = overall_healthy

        self._logger.info("health_check_completed", overall_healthy=overall_healthy)

        if overall_healthy:
            return FlextResult[dict[str, object]].ok(health_status)
        return FlextResult[dict[str, object]].fail(
            f"Health check failed: {health_status}"
        )

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute processor operation - domain service interface."""
        return FlextResult[dict[str, object]].ok({
            "status": "ready",
            "processor": "FlextLdifProcessor",
            "unified": True,
        })

    # Private Helper Methods

    def _validate_file_path(self, file_path: Path) -> FlextResult[Path]:
        """Validate LDIF file path."""
        if not file_path.exists():
            return FlextResult[Path].fail(f"File not found: {file_path}")

        if not file_path.is_file():
            return FlextResult[Path].fail(f"Path is not a file: {file_path}")

        # Check file size limits
        try:
            file_stat = file_path.stat()
            file_size = file_stat.st_size
            max_size_mb = self._config.ldif_max_file_size_mb or 100
            max_size_bytes = max_size_mb * 1024 * 1024

            if file_size > max_size_bytes:
                return FlextResult[Path].fail(
                    f"File too large: {file_size} bytes, limit: {max_size_bytes} bytes"
                )

        except OSError as e:
            return FlextResult[Path].fail(f"Cannot access file: {e}")

        return FlextResult[Path].ok(file_path)

    def _read_file_content(self, file_path: Path) -> FlextResult[str]:
        """Read file content with proper error handling via railway pattern."""
        return FlextResult.safe_call(
            lambda: file_path.read_text(encoding="utf-8")
        ).tap_error(
            lambda error: self._logger.error(
                "file_read_failed", file_path=str(file_path), error=error
            )
        )

    def _parse_content_with_metrics(
        self, content: str
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse content string with performance tracking via railway pattern."""
        start_time = time.time()
        content_size = len(content)

        return (
            self._validate_content_input(content)
            .flat_map(self._format_handler.parse_ldif)
            .map(self._record_parse_metrics(start_time, content_size))
            .tap_error(
                lambda error: self._logger.error(
                    "content_parsing_failed", content_size=content_size, error=error
                )
            )
        )

    def _validate_content_input(self, content: str) -> FlextResult[str]:
        """Validate content input with early return for empty content."""
        if not content.strip():
            self._logger.debug("parse_string_empty_content")
            return FlextResult[str].fail("Empty content provided")

        return FlextResult[str].ok(content)

    def _record_parse_metrics(
        self, start_time: float, content_size: int
    ) -> Callable[[list[FlextLdifModels.Entry]], list[FlextLdifModels.Entry]]:
        """Create a metrics recording function for railway pattern mapping."""

        def record_metrics(
            entries: list[FlextLdifModels.Entry],
        ) -> list[FlextLdifModels.Entry]:
            elapsed = time.time() - start_time
            self._operation_count += 1
            self._parse_operations += 1
            self._total_entries_processed += len(entries)

            self._logger.info(
                "parse_content_success",
                entries_count=len(entries),
                content_size=content_size,
                elapsed_ms=elapsed * 1000,
                total_operations=self._operation_count,
            )
            return entries

        return record_metrics

    def _log_parse_file_success(
        self, file_path: Path
    ) -> Callable[[list[FlextLdifModels.Entry]], list[FlextLdifModels.Entry]]:
        """Create a file parse success logging function for railway pattern mapping."""

        def log_success(
            entries: list[FlextLdifModels.Entry],
        ) -> list[FlextLdifModels.Entry]:
            self._logger.info(
                "parse_file_success",
                file_path=str(file_path),
                entries_count=len(entries),
                total_operations=self._operation_count,
            )
            return entries

        return log_success

    def _validate_entries_for_writing(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Validate entries before writing via railway pattern."""
        if not entries:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "Cannot write empty entry list"
            )

        return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

    def _write_content_to_file(self, content: str, file_path: Path) -> FlextResult[str]:
        """Write content to file with proper error handling via railway pattern."""

        def write_operation() -> str:
            file_path.write_text(content, encoding="utf-8")
            return content

        return FlextResult.safe_call(write_operation).tap_error(
            lambda error: self._logger.error(
                "file_write_failed", file_path=str(file_path), error=error
            )
        )

    def _record_write_metrics(
        self, entries: list[FlextLdifModels.Entry]
    ) -> Callable[[str], str]:
        """Create a write metrics recording function for railway pattern mapping."""

        def record_metrics(content: str) -> str:
            self._operation_count += 1
            self._write_operations += 1

            self._logger.debug(
                "write_string_success",
                entries_count=len(entries),
                content_length=len(content),
                total_operations=self._operation_count,
            )
            return content

        return record_metrics

    def _record_write_file_metrics(
        self, file_path: Path, entries: list[FlextLdifModels.Entry], start_time: float
    ) -> Callable[[bool], bool]:
        """Create a write file metrics recording function for railway pattern mapping."""

        def record_file_metrics(*, success: bool) -> bool:
            elapsed = time.time() - start_time

            self._logger.info(
                "write_file_success",
                file_path=str(file_path),
                entries_count=len(entries),
                elapsed_ms=elapsed * 1000,
                total_operations=self._operation_count,
            )
            return success

        return record_file_metrics

    def _validate_batch_preconditions(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Validate batch preconditions using railway pattern."""
        if not entries:
            self._record_validation_failure("empty_entry_list")
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "Cannot validate empty entry list"
            )

        max_entries = self._config.ldif_max_entries
        if len(entries) > max_entries:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Entry count exceeded: {len(entries)} entries, limit is {max_entries}"
            )

        self._logger.info(
            "Starting batch validation",
            entry_count=len(entries),
            large_batch=len(entries) > self._batch_size_threshold,
            strict_mode=self._strict_mode,
        )

        return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

    def _execute_validation_sequence(
        self, entries: list[FlextLdifModels.Entry], start_time: float
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute validation sequence using monadic patterns."""
        validator = self._ValidationHelper(self)

        if self._strict_mode:
            # In strict mode, validate each entry and fail fast on first error
            for i, entry in enumerate(entries):
                validation_result = validator.validate_single_entry_with_context(
                    entry, i
                )
                if validation_result.is_failure:
                    self._record_validation_failure("strict_mode_violation")
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Strict validation failed at entry {i}: {validation_result.error}"
                    )

            return (
                FlextResult[list[FlextLdifModels.Entry]]
                .ok(entries)
                .map(self._record_batch_validation_success(start_time))
            )
        # In non-strict mode, use traverse with error accumulation
        return self._execute_non_strict_validation(entries, start_time)

    def _execute_non_strict_validation(
        self, entries: list[FlextLdifModels.Entry], start_time: float
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute non-strict validation with error accumulation."""
        validator = self._ValidationHelper(self)

        validated_entries = []
        validation_errors = []

        for i, entry in enumerate(entries):
            result = validator.validate_single_entry_with_context(entry, i)
            if result.is_success:
                validated_entries.append(entry)
            else:
                validation_errors.append(f"Entry {i}: {result.error}")

        # Log warnings for non-strict mode but continue
        if validation_errors:
            self._logger.warning(
                "Validation completed with errors (non-strict mode)",
                total_errors=len(validation_errors),
                validated_entries=len(validated_entries),
                error_rate=len(validation_errors) / len(entries),
            )

        return (
            FlextResult[list[FlextLdifModels.Entry]]
            .ok(validated_entries)
            .map(self._record_batch_validation_success(start_time))
        )

    def _execute_single_validation(
        self, entry: FlextLdifModels.Entry
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Execute single entry validation using ValidationHelper."""
        validator = self._ValidationHelper(self)
        return validator.validate_single_entry_with_context(entry, 0).map(
            lambda _: entry
        )

    def _record_batch_validation_success(
        self, start_time: float
    ) -> Callable[[list[FlextLdifModels.Entry]], list[FlextLdifModels.Entry]]:
        """Create batch validation success recording function for railway pattern."""

        def record_success(
            entries: list[FlextLdifModels.Entry],
        ) -> list[FlextLdifModels.Entry]:
            validation_time = time.time() - start_time
            self._record_validation_success(len(entries), validation_time)

            self._logger.info(
                "Batch validation completed",
                entry_count=len(entries),
                validation_time_seconds=validation_time,
                throughput_entries_per_sec=len(entries) / validation_time
                if validation_time > 0
                else 0,
                slow_validation=validation_time > self._slow_validation_threshold,
            )
            return entries

        return record_success

    def _record_single_validation_success(
        self, start_time: float
    ) -> Callable[[bool], bool]:
        """Create single validation success recording function for railway pattern."""

        def record_success(*, result: bool) -> bool:
            validation_time = time.time() - start_time
            self._record_validation_success(1, validation_time)
            return result

        return record_success

    def _validate_analytics_input(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Validate analytics input using railway pattern."""
        if not entries:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "Cannot analyze empty entry list"
            )

        return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

    def _execute_cached_analysis(
        self,
        entries: list[FlextLdifModels.Entry],
        start_time: float,
        analysis_type: str,
    ) -> FlextResult[dict[str, int]]:
        """Execute analysis with caching using monadic composition."""
        analytics = self._AnalyticsHelper(self)
        cache_key = (
            f"{analysis_type}:{len(entries)}:{analytics.get_entries_hash(entries)}"
        )

        return (
            self._check_analytics_cache(cache_key)
            .or_else_get(
                lambda: FlextResult[dict[str, int]].ok(
                    self._perform_analysis(entries, analysis_type, analytics)
                )
            )
            .map(self._record_analysis_metrics(entries, start_time, analysis_type))
            .flat_map(lambda result: self._store_analysis_result(cache_key, result))
        )

    def _check_analytics_cache(self, cache_key: str) -> FlextResult[dict[str, int]]:
        """Check analytics cache with railway pattern."""
        cached_result = self._get_from_analytics_cache(cache_key)
        if cached_result is not None:
            self._analytics_stats["cached_results"] += 1
            self._logger.debug("Cache hit for analysis", cache_key=cache_key)
            return FlextResult[dict[str, int]].ok(cast("dict[str, int]", cached_result))

        return FlextResult[dict[str, int]].fail("Cache miss")

    def _perform_analysis(
        self,
        entries: list[FlextLdifModels.Entry],
        analysis_type: str,
        analytics: FlextLdifProcessor._AnalyticsHelper,
    ) -> dict[str, int]:
        """Perform the actual analysis based on type."""
        self._logger.info(
            f"Starting {analysis_type} analysis",
            entry_count=len(entries),
            large_dataset=len(entries) > self._large_dataset_threshold,
        )

        if analysis_type == "basic_analysis":
            return self._compute_basic_analysis(entries, analytics)
        if analysis_type == "objectclass_distribution":
            return self._compute_objectclass_distribution(entries, analytics)
        return {}

    def _compute_basic_analysis(
        self,
        entries: list[FlextLdifModels.Entry],
        analytics: FlextLdifProcessor._AnalyticsHelper,
    ) -> dict[str, int]:
        """Compute basic analysis metrics."""
        person_entries = sum(1 for e in entries if e.is_person_entry())
        group_entries = sum(1 for e in entries if e.is_group_entry())
        ou_entries = sum(
            1
            for e in entries
            if "organizationalunit"
            in (
                oc.lower()
                for oc in (
                    e.get_attribute(FlextLdifConstants.Format.OBJECTCLASS_ATTRIBUTE)
                    or []
                )
            )
        )

        unique_dns = len({e.dn.value.lower() for e in entries})
        total_attributes = sum(len(e.attributes.data) for e in entries)
        avg_attributes = total_attributes / len(entries) if entries else 0

        entry_types = analytics.classify_entry_types(entries)
        quality_metrics = analytics.calculate_data_quality_metrics(entries)
        structural_patterns = analytics.detect_structural_patterns(entries)

        return {
            "total_entries": len(entries),
            "person_entries": person_entries,
            "group_entries": group_entries,
            "organizational_unit_entries": ou_entries,
            "unique_dns": unique_dns,
            "duplicate_dns": len(entries) - unique_dns,
            "total_attributes": total_attributes,
            "avg_attributes_per_entry": int(avg_attributes),
            "max_attributes_per_entry": max(len(e.attributes.data) for e in entries)
            if entries
            else 0,
            "min_attributes_per_entry": min(len(e.attributes.data) for e in entries)
            if entries
            else 0,
            **entry_types,
            **quality_metrics,
            **structural_patterns,
        }

    def _compute_objectclass_distribution(
        self,
        entries: list[FlextLdifModels.Entry],
        analytics: FlextLdifProcessor._AnalyticsHelper,
    ) -> dict[str, int]:
        """Compute objectclass distribution metrics."""
        distribution: dict[str, int] = {}
        combination_patterns: dict[str, int] = {}

        for entry in entries:
            object_classes = (
                entry.get_attribute(FlextLdifConstants.Format.OBJECTCLASS_ATTRIBUTE)
                or []
            )

            # Track individual object classes
            for oc in object_classes:
                oc_lower = oc.lower()
                distribution[oc_lower] = distribution.get(oc_lower, 0) + 1

            # Track objectClass combinations
            if len(object_classes) > 1:
                combination_key = "|".join(sorted(oc.lower() for oc in object_classes))
                combination_patterns[combination_key] = (
                    combination_patterns.get(combination_key, 0) + 1
                )

        enhanced_distribution = {
            **distribution,
            **{
                f"combination_{combo}": count
                for combo, count in combination_patterns.items()
                if count >= self._min_pattern_support
            },
            "unique_objectclasses": len(distribution),
            "most_common_objectclass_count": max(distribution.values())
            if distribution
            else 0,
            "least_common_objectclass_count": min(distribution.values())
            if distribution
            else 0,
            "objectclass_combinations": len(combination_patterns),
        }

        # Detect anomalies
        anomalies = analytics.detect_objectclass_anomalies(distribution, len(entries))
        if anomalies:
            enhanced_distribution["anomalous_patterns_detected"] = len(anomalies)
            self._anomaly_detections += 1

        return enhanced_distribution

    def _record_analysis_metrics(
        self,
        entries: list[FlextLdifModels.Entry],
        start_time: float,
        analysis_type: str,
    ) -> Callable[[dict[str, int]], dict[str, int]]:
        """Create analysis metrics recording function for railway pattern."""

        def record_metrics(result: dict[str, int]) -> dict[str, int]:
            analysis_time = time.time() - start_time
            self._record_analysis_success(len(entries), analysis_time)
            self._analytics_stats[f"{analysis_type}_analyses"] = (
                self._analytics_stats.get(f"{analysis_type}_analyses", 0) + 1
            )

            self._logger.info(
                f"{analysis_type} completed",
                entry_count=len(entries),
                analysis_time_seconds=analysis_time,
                insights_generated=len(result),
                slow_analysis=analysis_time > self._slow_analysis_threshold,
            )
            return result

        return record_metrics

    def _store_analysis_result(
        self, cache_key: str, result: dict[str, int]
    ) -> FlextResult[dict[str, int]]:
        """Store analysis result in cache."""
        self._store_in_analytics_cache(cache_key, result)
        return FlextResult[dict[str, int]].ok(result)

    def _get_files_to_process(
        self, directory_path: str | Path | None, file_pattern: str
    ) -> FlextResult[list[Path]]:
        """Get initial list of files to process."""
        if directory_path:
            return self._process_directory_path(directory_path, file_pattern)
        return self._process_current_directory_pattern(file_pattern)

    def _process_directory_path(
        self, directory_path: str | Path, file_pattern: str
    ) -> FlextResult[list[Path]]:
        """Process directory path with pattern."""
        directory_obj = Path(directory_path)
        if not directory_obj.exists():
            return FlextResult[list[Path]].fail(
                f"Directory not found: {directory_path}"
            )
        if not directory_obj.is_dir():
            return FlextResult[list[Path]].fail(
                f"Path is not a directory: {directory_path}"
            )

        try:
            files_found = list(directory_obj.glob(file_pattern))
            return FlextResult[list[Path]].ok(files_found)
        except (OSError, ValueError) as e:
            return FlextResult[list[Path]].fail(
                f"Error discovering files in directory: {e}"
            )

    def _process_current_directory_pattern(
        self, file_pattern: str
    ) -> FlextResult[list[Path]]:
        """Process pattern in current directory."""
        try:
            files_found = list(Path().glob(file_pattern))
            return FlextResult[list[Path]].ok(files_found)
        except (OSError, ValueError) as e:
            return FlextResult[list[Path]].fail(
                f"Error discovering files with pattern: {e}"
            )

    def _filter_files_by_size(
        self, files_to_process: list[Path], max_file_size_mb: int
    ) -> list[Path]:
        """Filter files by size limit."""
        max_size_bytes = max_file_size_mb * 1024 * 1024
        filtered_files: list[Path] = []

        for file_path_item in files_to_process:
            try:
                if file_path_item.stat().st_size <= max_size_bytes:
                    filtered_files.append(file_path_item)
                else:
                    self._logger.warning(
                        "file_size_exceeded",
                        file_path=str(file_path_item),
                        file_size=file_path_item.stat().st_size,
                        max_size=max_size_bytes,
                    )
            except OSError as e:
                self._logger.warning(
                    "file_size_check_failed",
                    file_path=str(file_path_item),
                    error=str(e),
                )
                continue

        return filtered_files

    # Analytics Cache Management

    def _get_from_analytics_cache(
        self,
        cache_key: str,
    ) -> dict[str, int] | dict[str, object] | None:
        """Get result from analytics cache if not expired."""
        if cache_key in self._analytics_cache:
            result, timestamp = self._analytics_cache[cache_key]
            if time.time() - timestamp < self._cache_ttl:
                return result
            del self._analytics_cache[cache_key]
        return None

    def _store_in_analytics_cache(
        self,
        cache_key: str,
        result: dict[str, int] | dict[str, object],
    ) -> None:
        """Store result in analytics cache with cleanup if needed."""
        if len(self._analytics_cache) >= self._max_cache_size:
            self._cleanup_analytics_cache()

        self._analytics_cache[cache_key] = (result, time.time())

    def _cleanup_analytics_cache(self) -> None:
        """Remove expired entries from analytics cache."""
        current_time = time.time()
        expired_keys = [
            key
            for key, (_, timestamp) in self._analytics_cache.items()
            if current_time - timestamp >= self._cache_ttl
        ]

        for key in expired_keys:
            del self._analytics_cache[key]

        # If still too large, remove oldest entries
        if len(self._analytics_cache) >= self._max_cache_size:
            sorted_items = sorted(self._analytics_cache.items(), key=lambda x: x[1][1])
            keep_count = self._max_cache_size // 2
            self._analytics_cache = dict(sorted_items[-keep_count:])

    # Metrics Recording

    def _record_validation_success(
        self,
        entry_count: int,
        validation_time: float,
    ) -> None:
        """Record successful validation metrics."""
        self._total_validations += 1
        self._total_entries_validated += entry_count
        self._validation_count += 1
        self._validation_times.append(validation_time)

        # Keep validation times list manageable
        if (
            len(self._validation_times)
            > FlextLdifConstants.Processing.MAX_CACHE_ENTRIES
        ):
            self._validation_times = self._validation_times[
                -FlextLdifConstants.Processing.MANAGEABLE_CACHE_SIZE :
            ]

    def _record_validation_failure(self, failure_type: str) -> None:
        """Record validation failure with categorization."""
        self._validation_failures += 1
        self._total_validations += 1

        self._logger.warning(
            "Validation failure recorded",
            extra={"failure_type": failure_type},
        )

    def _record_analysis_success(self, entry_count: int, analysis_time: float) -> None:
        """Record successful analysis metrics."""
        self._total_analyses += 1
        self._total_entries_analyzed += entry_count
        self._analysis_count += 1
        self._analysis_times.append(analysis_time)

        if len(self._analysis_times) > FlextLdifConstants.Processing.MAX_CACHE_ENTRIES:
            self._analysis_times = self._analysis_times[
                -FlextLdifConstants.Processing.MANAGEABLE_CACHE_SIZE :
            ]

    def _record_analysis_failure(self, failure_type: str) -> None:
        """Record analysis failure with categorization."""
        self._analysis_failures += 1
        self._total_analyses += 1

        self._logger.warning(
            "Analytics analysis failure",
            extra={"failure_type": failure_type},
        )

    def _calculate_validation_success_rate(self) -> float:
        """Calculate validation success rate."""
        if self._total_validations == 0:
            return 1.0
        return max(
            0.0,
            (self._total_validations - self._validation_failures)
            / self._total_validations,
        )

    def _calculate_analytics_success_rate(self) -> float:
        """Calculate analysis success rate."""
        if self._total_analyses == 0:
            return 1.0
        return max(
            0.0,
            (self._total_analyses - self._analysis_failures) / self._total_analyses,
        )

    # =========================================================================
    # ENHANCED ANALYTICS METHODS (merged from analytics_service)
    # =========================================================================

    def analyze_patterns(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, object]]:
        """Advanced pattern analysis using functional composition.

        Performs comprehensive pattern detection including:
        - Basic statistical patterns
        - Object class distribution patterns
        - DN depth and hierarchy patterns
        - Temporal and structural anomalies

        Args:
            entries: List of LDIF entries to analyze

        Returns:
            FlextResult containing combined pattern analysis data

        """
        if not entries:
            return FlextResult[dict[str, object]].ok({})

        self._logger.info("pattern_analysis_started", entry_count=len(entries))

        try:
            # Use functional composition to combine multiple analyses
            basic_result = self.analyze_entries(entries)
            if basic_result.is_failure:
                return FlextResult[dict[str, object]].fail(
                    f"Basic analysis failed: {basic_result.error}"
                )

            oc_result = self.get_objectclass_distribution(entries)
            if oc_result.is_failure:
                return FlextResult[dict[str, object]].fail(
                    f"ObjectClass analysis failed: {oc_result.error}"
                )

            depth_result = self.get_dn_depth_analysis(entries)
            if depth_result.is_failure:
                return FlextResult[dict[str, object]].fail(
                    f"Depth analysis failed: {depth_result.error}"
                )

            # Combine all pattern analyses
            combined_patterns = self._combine_pattern_analyses(
                cast("dict[str, object]", basic_result.unwrap()),
                cast("dict[str, object]", oc_result.unwrap()),
                cast("dict[str, object]", depth_result.unwrap()),
            )

            self._logger.info(
                "pattern_analysis_completed", patterns_detected=len(combined_patterns)
            )
            return FlextResult[dict[str, object]].ok(combined_patterns)

        except Exception as exc:
            error_msg = f"Pattern analysis failed: {exc}"
            self._logger.exception("pattern_analysis_failed", error=str(exc))
            return FlextResult[dict[str, object]].fail(error_msg)

    def _combine_pattern_analyses(
        self,
        basic: dict[str, object],
        objectclass: dict[str, object],
        depth: dict[str, object],
    ) -> dict[str, object]:
        """Combine multiple pattern analyses into unified result.

        Args:
            basic: Basic statistical analysis results
            objectclass: Object class distribution analysis
            depth: DN depth and hierarchy analysis

        Returns:
            Combined pattern analysis dictionary

        """
        return {
            "basic_stats": basic,
            "objectclass_distribution": objectclass,
            "depth_analysis": depth,
            "analysis_timestamp": time.time(),
            "combined_insights": {
                "total_patterns": len(basic) + len(objectclass) + len(depth),
                "analysis_scope": "comprehensive",
                "data_quality_indicators": self._extract_quality_indicators(
                    basic, objectclass, depth
                ),
            },
        }

    def _extract_quality_indicators(
        self,
        basic: dict[str, object],
        objectclass: dict[str, object],
        depth: dict[str, object],
    ) -> dict[str, object]:
        """Extract data quality indicators from pattern analysis.

        Args:
            basic: Basic statistical data
            objectclass: Object class data
            depth: Depth analysis data

        Returns:
            Data quality indicators dictionary

        """
        indicators: dict[str, object] = {}

        # Extract completion metrics
        if isinstance(basic, dict) and "total_entries" in basic:
            total_entries = basic.get("total_entries", 0)
            if isinstance(total_entries, (int, float)) and total_entries > 0:
                indicators["completeness_score"] = min(1.0, total_entries / 1000)

        # Extract diversity metrics
        if isinstance(objectclass, dict):
            unique_classes = len(objectclass)
            indicators["diversity_score"] = min(1.0, unique_classes / 10)

        # Extract structure metrics
        if isinstance(depth, dict) and "average_depth" in depth:
            avg_depth = depth.get("average_depth", 0)
            if isinstance(avg_depth, (int, float)):
                indicators["structure_score"] = min(1.0, avg_depth / 5)

        return indicators

    def get_analytics_insights(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, object]]:
        """Generate comprehensive analytics insights with recommendations.

        Provides detailed insights including:
        - Data quality assessment
        - Structural analysis recommendations
        - Performance optimization suggestions
        - Schema compliance insights

        Args:
            entries: List of LDIF entries to analyze

        Returns:
            FlextResult containing comprehensive insights and recommendations

        """
        if not entries:
            return FlextResult[dict[str, object]].ok({
                "summary": {
                    "total_entries": 0,
                    "insights": "No entries to analyze",
                },
                "recommendations": ["Add LDIF entries to enable analysis"],
            })

        self._logger.info("analytics_insights_started", entry_count=len(entries))

        # Generate pattern analysis first
        patterns_result = self.analyze_patterns(entries)
        if patterns_result.is_failure:
            return FlextResult[dict[str, object]].fail(
                f"Pattern analysis failed: {patterns_result.error}"
            )

        patterns = patterns_result.unwrap()
        insights = self._generate_insights(patterns, len(entries))

        self._logger.info("analytics_insights_completed")
        return FlextResult[dict[str, object]].ok(insights)

    def _generate_insights(
        self, patterns: dict[str, object], entry_count: int
    ) -> dict[str, object]:
        """Generate actionable insights from pattern analysis.

        Args:
            patterns: Pattern analysis results
            entry_count: Total number of entries analyzed

        Returns:
            Comprehensive insights dictionary

        """
        return {
            "summary": {
                "total_entries": entry_count,
                "analysis_timestamp": time.time(),
                "data_quality": "comprehensive_analysis",
                "analysis_depth": "advanced_patterns",
            },
            "patterns": patterns,
            "recommendations": self._generate_recommendations(entry_count),
            "quality_assessment": self._assess_data_quality(patterns, entry_count),
            "optimization_suggestions": self._generate_optimization_suggestions(
                entry_count
            ),
        }

    def _generate_recommendations(self, entry_count: int) -> list[str]:
        """Generate optimization and improvement recommendations.

        Args:
            entry_count: Number of entries in the dataset

        Returns:
            List of actionable recommendations

        """
        recommendations = []

        if entry_count < FlextLdifConstants.Processing.MIN_PRODUCTION_ENTRIES:
            recommendations.append(
                f"Consider adding more entries (current: {entry_count}, "
                f"recommended minimum: {FlextLdifConstants.Processing.MIN_PRODUCTION_ENTRIES})"
            )

        if entry_count > FlextLdifConstants.Analytics.LARGE_DATASET_THRESHOLD:
            recommendations.extend([
                "Enable parallel processing for better performance",
                "Consider implementing data partitioning strategies",
                "Monitor memory usage during processing",
            ])

        recommendations.extend([
            "Implement regular data validation checks",
            "Consider adding data quality monitoring",
            "Enable analytics caching for repeated operations",
        ])

        return recommendations

    def _assess_data_quality(
        self, patterns: dict[str, object], entry_count: int
    ) -> dict[str, object]:
        """Assess overall data quality based on patterns.

        Args:
            patterns: Pattern analysis results
            entry_count: Total entries analyzed

        Returns:
            Data quality assessment dictionary

        """
        assessment: dict[str, object] = {
            "overall_score": 0.0,
            "completeness": 0.0,
            "consistency": 0.0,
            "structure": 0.0,
        }

        # Calculate completeness score
        if entry_count > 0:
            assessment["completeness"] = min(1.0, entry_count / 1000)

        # Calculate consistency score based on object class patterns
        if "objectclass_distribution" in patterns:
            oc_data = patterns["objectclass_distribution"]
            if isinstance(oc_data, dict) and oc_data:
                assessment["consistency"] = min(1.0, len(oc_data) / 5)

        # Calculate structure score based on depth analysis
        if "depth_analysis" in patterns:
            depth_data = patterns["depth_analysis"]
            if isinstance(depth_data, dict) and "average_depth" in depth_data:
                avg_depth = depth_data.get("average_depth", 0)
                assessment["structure"] = (
                    min(1.0, float(avg_depth) / 4)
                    if isinstance(avg_depth, (int, float))
                    else 0.0
                )

        # Calculate overall score with proper type casting
        completeness = (
            float(assessment["completeness"])
            if isinstance(assessment["completeness"], (int, float))
            else 0.0
        )
        consistency = (
            float(assessment["consistency"])
            if isinstance(assessment["consistency"], (int, float))
            else 0.0
        )
        structure = (
            float(assessment["structure"])
            if isinstance(assessment["structure"], (int, float))
            else 0.0
        )
        assessment["overall_score"] = (completeness + consistency + structure) / 3

        return assessment

    def _generate_optimization_suggestions(self, entry_count: int) -> list[str]:
        """Generate performance optimization suggestions.

        Args:
            entry_count: Number of entries being processed

        Returns:
            List of optimization suggestions

        """
        suggestions = []

        if entry_count > FlextLdifConstants.Processing.MAX_CACHE_ENTRIES:
            suggestions.extend([
                "Enable result caching for improved performance",
                "Consider batch processing for large datasets",
            ])

        if entry_count > FlextLdifConstants.Analytics.SMALL_BATCH_SIZE_THRESHOLD:
            suggestions.append("Enable parallel processing for faster analysis")

        suggestions.extend([
            "Monitor memory usage during processing",
            "Consider implementing progress tracking for long operations",
            "Enable analytics caching for repeated queries",
        ])

        return suggestions

    def get_config_info(self) -> dict[str, object]:
        """Get comprehensive configuration information.

        Returns:
            Dictionary containing current configuration details

        """
        return {
            "processor_type": "FlextLdifProcessor",
            "version": "unified",
            "config_sealed": self._config.is_sealed(),
            "processing_capabilities": {
                "parsing": True,
                "validation": True,
                "analytics": True,
                "writing": True,
                "caching": True,
                "parallel_processing": self._config.ldif_parallel_processing,
            },
            "configuration": {
                "max_entries": self._config.ldif_max_entries,
                "max_workers": self._config.ldif_max_workers,
                "buffer_size": self._config.ldif_buffer_size,
                "enable_analytics": self._config.ldif_enable_analytics,
                "analytics_cache_size": self._config.ldif_analytics_cache_size,
            },
            "performance_tracking": {
                "total_operations": self._operation_count,
                "total_entries_processed": self._total_entries_processed,
                "validation_success_rate": self._calculate_validation_success_rate(),
                "analytics_success_rate": self._calculate_analytics_success_rate(),
            },
        }

    # =========================================================================
    # ENHANCED REPOSITORY METHODS (merged from repository_service)
    # =========================================================================

    def store_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, object]]:
        """Store entries with comprehensive validation and statistics.

        Args:
            entries: List of LDIF entries to store

        Returns:
            FlextResult containing storage statistics and metadata

        """
        if not entries:
            return FlextResult[dict[str, object]].ok({
                "stored_entries": 0,
                "storage_time_ms": 0.0,
                "validation_passed": True,
            })

        start_time = time.time()
        self._logger.info("entry_storage_started", entry_count=len(entries))

        try:
            # Validate entries before storage
            validation_result = self._validate_entries(entries)
            if validation_result.is_failure:
                return FlextResult[dict[str, object]].fail(
                    f"Entry validation failed: {validation_result.error}"
                )

            # Store validated entries
            storage_result = self._store_validated_entries(entries)
            if storage_result.is_failure:
                return FlextResult[dict[str, object]].fail(
                    f"Storage failed: {storage_result.error}"
                )

            storage_time = (
                time.time() - start_time
            ) * FlextLdifConstants.Processing.MILLISECONDS_MULTIPLIER

            storage_stats = {
                "stored_entries": len(entries),
                "storage_time_ms": storage_time,
                "validation_passed": True,
                "storage_timestamp": time.time(),
                "entry_statistics": self._calculate_basic_stats(entries),
                "type_statistics": self._calculate_type_stats(entries),
            }

            self._logger.info(
                "entry_storage_completed",
                stored_count=len(entries),
                storage_time_ms=storage_time,
            )

            return FlextResult[dict[str, object]].ok(storage_stats)

        except Exception as exc:
            error_msg = f"Entry storage failed: {exc}"
            self._logger.exception("entry_storage_failed", error=str(exc))
            return FlextResult[dict[str, object]].fail(error_msg)

    def _store_validated_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[bool]:
        """Store pre-validated entries with optimized processing.

        Args:
            entries: Validated LDIF entries to store

        Returns:
            FlextResult indicating storage success

        """
        try:
            # For this implementation, we'll use in-memory storage
            # In a full implementation, this would persist to database/file system
            self._total_entries_processed += len(entries)

            # Update operation count
            self._operation_count += 1

            return FlextResult[bool].ok(value=True)

        except Exception as exc:
            return FlextResult[bool].fail(f"Storage operation failed: {exc}")

    def _validate_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[bool]:
        """Validate entries before storage with comprehensive checks.

        Args:
            entries: LDIF entries to validate

        Returns:
            FlextResult indicating validation success

        """
        try:
            for entry in entries:
                # Validate DN
                if not self._validate_dn(entry.dn.value):
                    return FlextResult[bool].fail(f"Invalid DN: {entry.dn.value}")

                # Validate object classes
                object_classes = entry.get_attribute("objectClass")
                if not object_classes:
                    return FlextResult[bool].fail(
                        f"Missing objectClass for DN: {entry.dn.value}"
                    )

                for oc in object_classes:
                    if not self._validate_object_class(oc):
                        return FlextResult[bool].fail(f"Invalid objectClass: {oc}")

                # Validate attributes
                for attr_name in entry.attributes.data:
                    if not self._validate_attribute_name(attr_name):
                        return FlextResult[bool].fail(
                            f"Invalid attribute name: {attr_name}"
                        )

            return FlextResult[bool].ok(value=True)

        except Exception as exc:
            return FlextResult[bool].fail(f"Validation failed: {exc}")

    def _validate_dn(self, dn: str) -> bool:
        """Validate DN format and structure.

        Args:
            dn: Distinguished Name to validate

        Returns:
            True if DN is valid, False otherwise

        """
        if not dn or len(dn) < FlextLdifConstants.Validation.MIN_DN_LENGTH:
            return False

        if len(dn) > FlextLdifConstants.Validation.MAX_SUSPICIOUS_DN_LENGTH:
            return False

        # Basic DN structure validation
        components = dn.split(",")
        if len(components) < FlextLdifConstants.Validation.MIN_DN_COMPONENTS:
            return False

        return all("=" in component for component in components)

    def _validate_object_class(self, object_class: str) -> bool:
        """Validate object class name.

        Args:
            object_class: Object class name to validate

        Returns:
            True if object class is valid, False otherwise

        """
        if not object_class or not isinstance(object_class, str):
            return False

        # Check against known object classes
        all_known_classes = (
            FlextLdifConstants.ObjectClasses.LDAP_PERSON_CLASSES
            | FlextLdifConstants.ObjectClasses.LDAP_GROUP_CLASSES
            | FlextLdifConstants.ObjectClasses.LDAP_ORGANIZATIONAL_CLASSES
            | FlextLdifConstants.ObjectClasses.LDAP_DOMAIN_CLASSES
        )

        return object_class.lower() in {oc.lower() for oc in all_known_classes}

    def _validate_attribute_name(self, attr_name: str) -> bool:
        """Validate LDAP attribute name.

        Args:
            attr_name: Attribute name to validate

        Returns:
            True if attribute name is valid, False otherwise

        """
        if not attr_name or not isinstance(attr_name, str):
            return False

        if len(attr_name) > FlextLdifConstants.Validation.MAX_ATTRIBUTE_NAME_LENGTH:
            return False

        # Basic attribute name validation (letters, numbers, hyphens)
        return bool(
            re.match(r"^[a-zA-Z][a-zA-Z0-9-]*$", attr_name.split(";", maxsplit=1)[0])
        )

    def _calculate_basic_stats(
        self, entries: list[FlextLdifModels.Entry]
    ) -> dict[str, int]:
        """Calculate basic entry statistics.

        Args:
            entries: LDIF entries to analyze

        Returns:
            Dictionary containing basic statistics

        """
        stats = {
            "total_entries": len(entries),
            "entries_with_cn": 0,
            "entries_with_mail": 0,
            "entries_with_telephone": 0,
            "unique_dns": len({entry.dn.value for entry in entries}),
        }

        for entry in entries:
            if entry.get_attribute("cn"):
                stats["entries_with_cn"] += 1
            if entry.get_attribute("mail"):
                stats["entries_with_mail"] += 1
            if entry.get_attribute("telephoneNumber"):
                stats["entries_with_telephone"] += 1

        return stats

    def _calculate_type_stats(
        self, entries: list[FlextLdifModels.Entry]
    ) -> dict[str, int]:
        """Calculate entry type statistics.

        Args:
            entries: LDIF entries to analyze

        Returns:
            Dictionary containing type-based statistics

        """
        stats = {
            "person_entries": 0,
            "group_entries": 0,
            "organizational_entries": 0,
            "domain_entries": 0,
            "other_entries": 0,
        }

        for entry in entries:
            object_classes = {
                oc.lower() for oc in entry.get_attribute("objectClass") or []
            }

            if object_classes & {
                oc.lower()
                for oc in FlextLdifConstants.ObjectClasses.LDAP_PERSON_CLASSES
            }:
                stats["person_entries"] += 1
            elif object_classes & {
                oc.lower() for oc in FlextLdifConstants.ObjectClasses.LDAP_GROUP_CLASSES
            }:
                stats["group_entries"] += 1
            elif object_classes & {
                oc.lower()
                for oc in FlextLdifConstants.ObjectClasses.LDAP_ORGANIZATIONAL_CLASSES
            }:
                stats["organizational_entries"] += 1
            elif object_classes & {
                oc.lower()
                for oc in FlextLdifConstants.ObjectClasses.LDAP_DOMAIN_CLASSES
            }:
                stats["domain_entries"] += 1
            else:
                stats["other_entries"] += 1

        return stats

    def get_statistics(self) -> dict[str, object]:
        """Get comprehensive processor statistics.

        Returns:
            Dictionary containing complete processor statistics

        """
        return {
            "processor_stats": {
                "total_operations": self._operation_count,
                "total_entries_processed": self._total_entries_processed,
                "parse_operations": self._parse_operations,
                "write_operations": self._write_operations,
                "validation_operations": self._total_validations,
                "analysis_operations": self._total_analyses,
            },
            "success_rates": {
                "validation_success_rate": self._calculate_validation_success_rate(),
                "analytics_success_rate": self._calculate_analytics_success_rate(),
            },
            "performance_metrics": self.get_performance_metrics(),
            "configuration": self.get_config_info(),
        }

    # Private accessor methods for helper classes to avoid SLF001 violations

    def increment_validation_stat(self, stat_name: str) -> None:
        """Increment validation statistic by name."""
        if stat_name in self._validation_stats:
            self._validation_stats[stat_name] += 1

    def increment_dn_validations(self) -> None:
        """Increment DN validation counter."""
        self._dn_validations += 1

    def increment_schema_validations(self) -> None:
        """Increment schema validation counter."""
        self._schema_validations += 1

    # API Compatibility Methods

    def transform_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        transformation: Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Transform entries using the provided transformation function."""
        return self.transform(entries, transformation)

    def filter_entries_by_attribute(
        self,
        entries: list[FlextLdifModels.Entry],
        attribute_name: str,
        attribute_value: str | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by attribute name and optional value."""
        if attribute_value is None:
            # Filter by attribute presence
            try:
                filtered = [
                    entry for entry in entries if entry.get_attribute(attribute_name)
                ]
                return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)
            except Exception as exc:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Filter by attribute failed: {exc}"
                )
        else:
            # Filter by attribute value
            return self.filter_by_attribute(entries, attribute_name, attribute_value)

    def filter_entries_by_objectclass(
        self, entries: list[FlextLdifModels.Entry], object_class: str
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by objectClass."""
        return self.filter_by_objectclass(entries, object_class)
