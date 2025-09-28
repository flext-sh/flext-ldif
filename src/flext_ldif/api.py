"""FLEXT LDIF API - Unified interface for LDIF operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import cast, override

from pydantic import ConfigDict

from flext_core import FlextContainer, FlextLogger, FlextResult, FlextService
from flext_ldif.config import FlextLdifConfig
from flext_ldif.management import FlextLdifManagement
from flext_ldif.models import FlextLdifModels
from flext_ldif.processor import FlextLdifProcessor
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifAPI(FlextService[FlextLdifTypes.HealthStatusDict]):
    """Unified LDIF API for direct LDIF processing operations.

    Provides a single interface for all LDIF processing operations including
    parsing, validation, writing, transformation, and analytics. Uses FlextResult
    patterns for composable error handling and railway-oriented programming.

    Now leverages the unified FlextLdifManagement layer for coordinated schema,
    ACL, entry, and quirks management following FLEXT architectural principles.

    Implements FlextLdifProtocols through structural subtyping:
    - LdifProcessorProtocol: parse, validate_entries, write, transform_entries, analyze_entries methods
    - LdifValidatorProtocol: validate_entries method
    - LdifWriterProtocol: write_entries_to_string, write_entries_to_file methods
    - LdifAnalyticsProtocol: analyze_entries, get_statistics, detect_patterns methods
    """

    model_config = ConfigDict(
        validate_assignment=True,
        extra="allow",
        arbitrary_types_allowed=True,
    )

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize LDIF API with management layer and processor."""
        super().__init__()
        self._logger = FlextLogger(__name__)
        self._config: FlextLdifConfig = config or FlextLdifConfig()
        self._container = FlextContainer.get_global()

        # Initialize management layer for unified operations
        self._management = FlextLdifManagement()

        # Initialize processor with error handling
        self._processor_result: FlextResult[FlextLdifProcessor] = (
            self._initialize_processor()
        )

    def _initialize_processor(self) -> FlextResult[FlextLdifProcessor]:
        """Initialize the processor with proper error handling.

        Returns:
            FlextResult[FlextLdifProcessor]: Success with initialized processor
            or failure with error message.

        """
        try:
            processor = FlextLdifProcessor(config=self._config)
            self._logger.info("LDIF processor initialized successfully")
            return FlextResult[FlextLdifProcessor].ok(processor)
        except Exception as e:
            error_msg = f"Failed to initialize LDIF processor: {e}"
            self._logger.exception(error_msg)
            return FlextResult[FlextLdifProcessor].fail(error_msg)

    @override
    def execute(self) -> FlextResult[FlextLdifTypes.HealthStatusDict]:
        """Execute health check operation - required by FlextService.

        Returns:
            FlextResult[FlextLdifTypes.HealthStatusDict]: Health check status
            information.

        """
        return self.health_check()

    async def execute_async(self) -> FlextResult[FlextLdifTypes.HealthStatusDict]:
        """Execute health check operation asynchronously - required by FlextService.

        Returns:
            FlextResult[FlextLdifTypes.HealthStatusDict]: Health check status
            information.

        """
        return self.health_check()

    # =============================================================================
    # CORE API METHODS - Main functionality
    # =============================================================================

    def parse(self, content: str) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF content string into entries.

        Returns:
            FlextResult[list[FlextLdifModels.Entry]]: Success with parsed entries
            or failure with error message.

        """
        return self._processor_result.flat_map(
            lambda processor: processor.parse_string(content)
        ).map(self._log_parse_success)

    def parse_ldif_file(
        self, file_path: Path | str
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF file using file path (string or Path).

        Returns:
            FlextResult[list[FlextLdifModels.Entry]]: Success with parsed entries
            or failure with error message.

        """
        if isinstance(file_path, str):
            file_path = Path(file_path)
        return self._processor_result.flat_map(
            lambda processor: processor.parse_ldif_file(file_path)
        ).map(self._log_parse_file_success)

    def validate_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Validate LDIF entries and return valid entries.

        Returns:
            FlextResult[list[FlextLdifModels.Entry]]: Success with validated
            entries or failure with error message.

        """
        validation_result = self._processor_result.flat_map(
            lambda processor: processor.validate_entries(entries)
        )

        if validation_result.is_success:
            self._log_validation_success_with_entries(entries)
            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)
        return FlextResult[list[FlextLdifModels.Entry]].fail(
            validation_result.error or "Validation failed"
        )

    def write(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[str]:
        """Write entries to LDIF format string.

        Returns:
            FlextResult[str]: Success with LDIF content string or failure with
            error message.

        """
        return self._processor_result.flat_map(
            lambda processor: processor.write_string(entries)
        ).map(self._log_write_success)

    def write_file(
        self, entries: list[FlextLdifModels.Entry], file_path: Path | str
    ) -> FlextResult[bool]:
        """Write entries to LDIF file.

        Returns:
            FlextResult[bool]: Success with True if file written successfully
            or failure with error message.

        """
        if isinstance(file_path, str):
            file_path = Path(file_path)

        return (
            self._processor_result.flat_map(
                lambda processor: processor.write_file(entries, str(file_path))
            )
            .map(lambda _: True)
            .map(lambda success: self._log_write_file_success(success=success))
            .recover(lambda _: False)  # Return False on write failure
        )

    def transform(
        self,
        entries: list[FlextLdifModels.Entry],
        transformer: (
            Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry] | None
        ) = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Transform entries using optional transformer function.

        Returns:
            FlextResult[list[FlextLdifModels.Entry]]: Success with transformed
            entries or failure with error message.

        """
        if transformer is None:
            # Default transformer - identity function
            def identity_transformer(
                entry: FlextLdifModels.Entry,
            ) -> FlextLdifModels.Entry:
                return entry

            transformer = identity_transformer

        return self._processor_result.flat_map(
            lambda processor: processor.transform_entries(entries, transformer)
        ).map(self._log_transformation_success)

    def analyze(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, object]]:
        """Analyze entries and return statistics.

        Returns:
            FlextResult[dict[str, object]]: Success with analysis statistics
            or failure with error message.

        """
        return self._processor_result.flat_map(
            lambda processor: processor.analyze_entries(entries)
        ).map(self._log_analysis_success)

    # =============================================================================
    # PROTOCOL IMPLEMENTATION METHODS - FlextLdifProtocols compliance
    # =============================================================================

    def transform_entries(
        self, entries: list[object], transformer: object
    ) -> FlextResult[list[object]]:
        """Transform entries using transformer function - implements LdifProcessorProtocol.

        Args:
            entries: List of LDIF entries to transform
            transformer: Transformer function or object

        Returns:
            FlextResult[list[object]]: Transformed entries

        """
        # Cast entries to the correct type and delegate to existing transform method
        typed_entries = cast("list[FlextLdifModels.Entry]", entries)
        typed_transformer = cast(
            "Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry]", transformer
        )

        result = self.transform(typed_entries, typed_transformer)
        return result.map(lambda x: cast("list[object]", x))

    def analyze_entries(self, entries: list[object]) -> FlextResult[dict[str, object]]:
        """Analyze LDIF entries and generate analytics - implements LdifProcessorProtocol and LdifAnalyticsProtocol.

        Args:
            entries: List of LDIF entries to analyze

        Returns:
            FlextResult[dict[str, object]]: Analysis results

        """
        # Cast entries to the correct type and delegate to existing analyze method
        typed_entries = cast("list[FlextLdifModels.Entry]", entries)
        return self.analyze(typed_entries)

    def write_entries_to_string(self, entries: list[object]) -> FlextResult[str]:
        """Write entries to LDIF format string - implements LdifWriterProtocol.

        Args:
            entries: List of LDIF entries to write

        Returns:
            FlextResult[str]: LDIF formatted string

        """
        # Cast entries to the correct type and delegate to existing write method
        typed_entries = cast("list[FlextLdifModels.Entry]", entries)
        return self.write(typed_entries)

    def write_entries_to_file(
        self, entries: list[object], file_path: str
    ) -> FlextResult[bool]:
        """Write entries to LDIF file - implements LdifWriterProtocol.

        Args:
            entries: List of LDIF entries to write
            file_path: Path to output file

        Returns:
            FlextResult[bool]: Success status

        """
        # Cast entries to the correct type and delegate to existing write_file method
        typed_entries = cast("list[FlextLdifModels.Entry]", entries)
        result = self.write_file(typed_entries, Path(file_path))
        return result.map(lambda _: True)  # Convert None to bool

    def get_statistics(self) -> dict[str, int | float]:
        """Get analytics statistics - implements LdifAnalyticsProtocol.

        Returns:
            dict[str, int | float]: Statistics data

        """
        # Return basic statistics - could be enhanced with actual processor stats
        return {
            "entries_processed": 0,
            "validation_success_rate": 1.0,
            "processing_time": 0.0,
        }

    def detect_patterns(self, entries: list[object]) -> dict[str, object]:
        """Detect patterns in LDIF entries - implements LdifAnalyticsProtocol.

        Args:
            entries: List of LDIF entries to analyze

        Returns:
            dict[str, object]: Detected patterns

        """
        # Cast entries and perform basic pattern detection
        typed_entries = cast("list[FlextLdifModels.Entry]", entries)

        # Basic pattern detection - could be enhanced
        object_classes = set()
        dn_patterns = set()

        for entry in typed_entries:
            if hasattr(entry, "attributes") and "objectClass" in entry.attributes:
                object_class_attr = entry.attributes["objectClass"]
                if object_class_attr:
                    object_classes.update(object_class_attr.values)
            if hasattr(entry, "dn"):
                # Extract DN components for pattern analysis
                dn_value = (
                    entry.dn.value if hasattr(entry.dn, "value") else str(entry.dn)
                )
                dn_parts = dn_value.split(",")
                if dn_parts:
                    dn_patterns.add(
                        dn_parts[0].split("=")[0] if "=" in dn_parts[0] else dn_parts[0]
                    )

        return {
            "object_classes": list(object_classes),
            "dn_patterns": list(dn_patterns),
            "entry_count": len(typed_entries),
        }

    @staticmethod
    def filter_entries(
        entries: list[FlextLdifModels.Entry],
        filter_func: Callable[[FlextLdifModels.Entry], bool],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries using provided predicate function.

        Returns:
            FlextResult[list[FlextLdifModels.Entry]]: Success with filtered
            entries or failure with error message.

        """
        try:
            filtered_entries = [entry for entry in entries if filter_func(entry)]
            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered_entries)
        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Filter operation failed: {e}", error_code="FILTER_ERROR"
            )

    def health_check(self) -> FlextResult[FlextLdifTypes.HealthStatusDict]:
        """Perform health check on the API and processor.

        Returns:
            FlextResult[FlextLdifTypes.HealthStatusDict]: Health status information.

        """
        return self._processor_result.map(
            lambda _: cast(
                "FlextLdifTypes.HealthStatusDict",
                {
                    "status": "healthy",
                    "timestamp": FlextLdifUtilities.TimeUtilities.get_timestamp(),
                    "config": self._get_config_summary(),
                },
            )
        )

    @override
    def get_service_info(self) -> dict[str, object]:
        """Get service information using safe evaluation.

        Returns:
            FlextLdifTypes.LdifStatistics: Service information dictionary.

        """
        return self._processor_result.map(
            lambda processor: cast(
                "dict[str, object]",
                {
                    "api": "FlextLdifAPI",
                    "capabilities": [
                        "parse",
                        "parse_file",
                        "validate",
                        "write",
                        "write_file",
                        "transform",
                        "analyze",
                        "filter_entries",
                        "health_check",
                    ],
                    "processor": processor.get_config_info(),
                    "config": self._get_config_summary(),
                    "pattern": "railway_oriented_programming",
                },
            )
        ).unwrap_or(
            cast(
                "dict[str, object]",
                {
                    "api": "FlextLdifAPI",
                    "status": "processor_initialization_failed",
                    "pattern": "railway_oriented_programming",
                },
            )
        )

    # =============================================================================
    # ADDITIONAL API METHODS - Enhanced functionality
    # =============================================================================

    def entry_statistics(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, object]]:
        """Get comprehensive entry statistics.

        Returns:
            FlextResult[dict[str, object]]: Success with statistics or failure
            with error message.

        """
        try:
            # Generate comprehensive statistics
            total_entries = len(entries)
            object_class_counts: dict[str, int] = {}
            attribute_counts: dict[str, int] = {}
            dn_depths: list[int] = []

            for entry in entries:
                # Count object classes
                object_class_attr = entry.get_attribute("objectClass")
                if object_class_attr:
                    # Extract individual object class names from AttributeValues
                    object_classes = object_class_attr.values
                    for oc in object_classes:
                        object_class_counts[oc] = object_class_counts.get(oc, 0) + 1

                # Count attributes
                for attr_name in entry.attributes.data:
                    attribute_counts[attr_name] = attribute_counts.get(attr_name, 0) + 1

                # Track DN depths
                dn_depths.append(entry.dn.depth)

            statistics: FlextLdifTypes.LdifStatistics = {
                "total_entries": total_entries,
                "object_class_counts": object_class_counts,
                "attribute_counts": attribute_counts,
                "average_dn_depth": sum(dn_depths) / len(dn_depths) if dn_depths else 0,
                "max_dn_depth": max(dn_depths) if dn_depths else 0,
                "min_dn_depth": min(dn_depths) if dn_depths else 0,
            }

            return FlextResult[dict[str, object]].ok(statistics)
        except Exception as e:  # pragma: no cover
            return FlextResult[dict[str, object]].fail(
                f"Statistics generation failed: {e}", error_code="STATISTICS_ERROR"
            )

    # =============================================================================
    # HELPER METHODS - Logging and utilities
    # =============================================================================

    def _log_parse_success(
        self, entries: list[FlextLdifModels.Entry]
    ) -> list[FlextLdifModels.Entry]:
        """Log successful parsing operation.

        Returns:
            list[FlextLdifModels.Entry]: The parsed entries.

        """
        self._logger.info(f"Successfully parsed {len(entries)} LDIF entries")
        return entries

    def _log_parse_file_success(
        self, entries: list[FlextLdifModels.Entry]
    ) -> list[FlextLdifModels.Entry]:
        """Log successful file parsing operation.

        Returns:
            list[FlextLdifModels.Entry]: The input entries (unchanged).

        """
        self._logger.info(f"Successfully parsed {len(entries)} entries from LDIF file")
        return entries

    def _log_validation_success_with_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> list[FlextLdifModels.Entry]:
        """Log successful validation operation with entries.

        Returns:
            list[FlextLdifModels.Entry]: The input entries (unchanged).

        """
        self._logger.info(
            f"Validation completed successfully for {len(entries)} entries"
        )
        return entries

    def _log_write_success(self, content: str) -> str:
        """Log successful write operation.

        Returns:
            str: The content that was written.

        """
        self._logger.info(
            f"Successfully generated LDIF content ({len(content)} characters)"
        )
        return content

    def _log_write_file_success(self, *, success: bool) -> bool:
        """Log successful file write operation.

        Returns:
            bool: The success status.

        """
        self._logger.info(f"Successfully wrote LDIF file: {success}")
        return success

    def _log_transformation_success(
        self, entries: list[FlextLdifModels.Entry]
    ) -> list[FlextLdifModels.Entry]:
        """Log successful transformation operation.

        Returns:
            list[FlextLdifModels.Entry]: The input entries (unchanged).

        """
        self._logger.info(f"Successfully transformed {len(entries)} entries")
        return entries

    def _log_analysis_success(
        self, stats: FlextLdifTypes.LdifStatistics
    ) -> FlextLdifTypes.LdifStatistics:
        """Log successful analysis operation.

        Returns:
            FlextLdifTypes.LdifStatistics: The input statistics (unchanged).

        """
        self._logger.info(
            f"Successfully analyzed entries, generated {len(stats)} statistics"
        )
        return stats

    def _get_config_summary(self) -> FlextLdifTypes.LdifStatistics:
        """Get configuration summary for service info.

        Returns:
            FlextLdifTypes.LdifStatistics: Configuration summary dictionary.

        """
        return cast(
            "FlextLdifTypes.LdifStatistics",
            {
                "max_entries": getattr(self._config, "ldif_max_entries", 10000),
                "strict_validation": str(
                    getattr(self._config, "ldif_strict_validation", True)
                ),
                "encoding": getattr(self._config, "ldif_encoding", "utf-8"),
            },
        )

    def filter_persons(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries to only include person entries.

        Args:
            entries: List of LDIF entries to filter

        Returns:
            FlextResult[list[FlextLdifModels.Entry]]: Filtered person entries

        """
        try:
            person_entries = [entry for entry in entries if entry.is_person_entry()]
            return FlextResult[list[FlextLdifModels.Entry]].ok(person_entries)
        except Exception as e:  # pragma: no cover
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Person filtering failed: {e}", error_code="PERSON_FILTER_ERROR"
            )

    def filter_by_objectclass(
        self, entries: list[FlextLdifModels.Entry], object_class: str
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by object class.

        Args:
            entries: List of LDIF entries to filter
            object_class: Object class to filter by

        Returns:
            FlextResult[list[FlextLdifModels.Entry]]: Filtered entries

        """
        try:
            filtered_entries = [
                entry for entry in entries if entry.has_object_class(object_class)
            ]
            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered_entries)
        except Exception as e:  # pragma: no cover
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Object class filtering failed: {e}",
                error_code="OBJECT_CLASS_FILTER_ERROR",
            )

    def filter_valid(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries to only include valid entries.

        Args:
            entries: List of LDIF entries to filter

        Returns:
            FlextResult[list[FlextLdifModels.Entry]]: Valid entries

        """
        try:
            valid_entries: list[FlextLdifModels.Entry] = []
            for entry in entries:
                validation_result: FlextResult[bool] = entry.validate_business_rules()
                if validation_result.is_success:
                    valid_entries.append(entry)
            return FlextResult[list[FlextLdifModels.Entry]].ok(valid_entries)
        except Exception as e:  # pragma: no cover
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Valid filtering failed: {e}", error_code="VALID_FILTER_ERROR"
            )

    # =============================================================================
    # MANAGEMENT LAYER METHODS - Unified schema, ACL, entry, and quirks operations
    # =============================================================================

    def process_with_schema(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, object]]:
        """Process entries with schema extraction and validation.

        Uses the unified management layer to extract schema and validate entries.

        Args:
            entries: List of LDIF entries to process

        Returns:
            FlextResult with schema and validation results

        """
        return self._management.process_entries_with_schema(entries)

    def process_with_acl(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, object]]:
        """Process entries with ACL extraction.

        Uses the unified management layer to detect server type and extract ACLs.

        Args:
            entries: List of LDIF entries to process

        Returns:
            FlextResult with server type, ACL count, and extracted ACLs

        """
        return self._management.process_entries_with_acl(entries)

    def adapt_for_server(
        self, entries: list[FlextLdifModels.Entry], target_server: str
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Adapt entries for target LDAP server type.

        Uses the unified management layer to apply server-specific quirks.

        Args:
            entries: List of LDIF entries to adapt
            target_server: Target server type (openldap, 389ds, oracle_oid, etc.)

        Returns:
            FlextResult with adapted entries

        """
        return self._management.adapt_entries_for_server(entries, target_server)

    def validate_for_server(
        self, entries: list[FlextLdifModels.Entry], server_type: str | None = None
    ) -> FlextResult[dict[str, object]]:
        """Validate entries for server compliance.

        Uses the unified management layer to validate against server-specific rules.

        Args:
            entries: List of LDIF entries to validate
            server_type: Target server type (auto-detected if not provided)

        Returns:
            FlextResult with validation report

        """
        return self._management.validate_entries_for_server(entries, server_type)

    def process_complete(
        self, content: str, server_type: str | None = None
    ) -> FlextResult[dict[str, object]]:
        """Complete LDIF processing pipeline with all operations.

        Parses content, detects server type, extracts schema and ACLs, and adapts
        entries for the target server using the unified management layer.

        Args:
            content: LDIF content string
            server_type: Target server type (auto-detected if not provided)

        Returns:
            FlextResult with entries, schema, ACLs, and server type

        """
        return self._management.process_ldif_complete(content, server_type)


__all__ = ["FlextLdifAPI"]
