"""FLEXT LDIF API - Unified interface for LDIF operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from pydantic import ConfigDict

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import FlextLdifModels
from flext_ldif.processor import FlextLdifProcessor


class FlextLdifAPI(FlextService[dict[str, object]]):
    """Unified LDIF API for direct LDIF processing operations.

    Provides a single interface for all LDIF processing operations including
    parsing, validation, writing, transformation, and analytics. Uses FlextResult
    patterns for composable error handling and railway-oriented programming.

    Follows FLEXT architectural principles with direct API methods and no
    compatibility layers, wrappers, or service abstractions.
    """

    model_config = ConfigDict(
        validate_assignment=True,
        extra="forbid",
        arbitrary_types_allowed=True,
    )

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize LDIF API with processor."""
        super().__init__()
        self._logger = FlextLogger(__name__)
        self._config = config

        # Initialize processor with error handling
        self._processor_result = self._initialize_processor()

    def _initialize_processor(self) -> FlextResult[FlextLdifProcessor]:
        """Initialize the processor with proper error handling.

        Returns:
            FlextResult[FlextLdifProcessor]: Success with initialized processor or failure with error message.

        """
        try:
            processor = FlextLdifProcessor(config=self._config)
            self._logger.info("LDIF processor initialized successfully")
            return FlextResult[FlextLdifProcessor].ok(processor)
        except Exception as e:
            error_msg = f"Failed to initialize LDIF processor: {e}"
            self._logger.exception(error_msg)
            return FlextResult[FlextLdifProcessor].fail(error_msg)

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute health check operation - required by FlextService.

        Returns:
            FlextResult[dict[str, object]]: Health check status information.

        """
        return self.health_check()

    # =============================================================================
    # CORE API METHODS - Main functionality
    # =============================================================================

    def parse(self, content: str) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF content string into entries.

        Returns:
            FlextResult[list[FlextLdifModels.Entry]]: Success with parsed entries or failure with error message.

        """
        return self._processor_result.flat_map(
            lambda processor: processor.parse_string(content)
        ).map(self._log_parse_success)

    def parse_ldif_file(
        self, file_path: Path | str
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF file using file path (string or Path).

        Returns:
            FlextResult[list[FlextLdifModels.Entry]]: Success with parsed entries or failure with error message.

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
            FlextResult[list[FlextLdifModels.Entry]]: Success with validated entries or failure with error message.

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
            FlextResult[str]: Success with LDIF content string or failure with error message.

        """
        return self._processor_result.flat_map(
            lambda processor: processor.write_string(entries)
        ).map(self._log_write_success)

    def write_file(
        self, entries: list[FlextLdifModels.Entry], file_path: Path | str
    ) -> FlextResult[bool]:
        """Write entries to LDIF file.

        Returns:
            FlextResult[bool]: Success with True if file written successfully or failure with error message.

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
            FlextResult[list[FlextLdifModels.Entry]]: Success with transformed entries or failure with error message.

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
            FlextResult[dict[str, object]]: Success with analysis statistics or failure with error message.

        """
        return (
            self._processor_result.flat_map(
                lambda processor: processor.analyze_entries(entries)
            )
            .map(lambda stats: stats)
            .map(self._log_analysis_success)
        )

    @staticmethod
    def filter_entries(
        entries: list[FlextLdifModels.Entry],
        filter_func: Callable[[FlextLdifModels.Entry], bool],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries using provided predicate function.

        Returns:
            FlextResult[list[FlextLdifModels.Entry]]: Success with filtered entries or failure with error message.

        """
        try:
            filtered_entries = [entry for entry in entries if filter_func(entry)]
            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered_entries)
        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Filter operation failed: {e}"
            )

    def health_check(self) -> FlextResult[dict[str, object]]:
        """Perform health check on the API and processor.

        Returns:
            FlextResult[dict[str, object]]: Health status information.

        """
        return self._processor_result.map(
            lambda _: cast(
                "dict[str, object]",
                {
                    "status": "healthy",
                    "timestamp": self._get_timestamp(),
                    "config": self._get_config_summary(),
                },
            )
        )

    def get_service_info(self) -> dict[str, object]:
        """Get service information using safe evaluation.

        Returns:
            dict[str, object]: Service information dictionary.

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
            FlextResult[dict[str, object]]: Success with statistics or failure with error message.

        """
        try:
            # Generate comprehensive statistics
            total_entries = len(entries)
            object_class_counts: dict[str, int] = {}
            attribute_counts: dict[str, int] = {}
            dn_depths: list[int] = []

            for entry in entries:
                # Count object classes
                object_classes = entry.get_attribute("objectClass") or []
                for oc in object_classes:
                    object_class_counts[oc] = object_class_counts.get(oc, 0) + 1

                # Count attributes
                for attr_name in entry.attributes.data:
                    attribute_counts[attr_name] = attribute_counts.get(attr_name, 0) + 1

                # Track DN depths
                dn_depths.append(entry.dn.depth)

            statistics: dict[str, object] = {
                "total_entries": cast("object", total_entries),
                "object_class_counts": cast("object", object_class_counts),
                "attribute_counts": cast("object", attribute_counts),
                "average_dn_depth": cast(
                    "object", sum(dn_depths) / len(dn_depths) if dn_depths else 0
                ),
                "max_dn_depth": cast("object", max(dn_depths) if dn_depths else 0),
                "min_dn_depth": cast("object", min(dn_depths) if dn_depths else 0),
            }

            return FlextResult[dict[str, object]].ok(statistics)
        except Exception as e:  # pragma: no cover
            return FlextResult[dict[str, object]].fail(
                f"Statistics generation failed: {e}"
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

    def _log_analysis_success(self, stats: dict[str, object]) -> dict[str, object]:
        """Log successful analysis operation.

        Returns:
            dict[str, object]: The input statistics (unchanged).

        """
        self._logger.info(
            f"Successfully analyzed entries, generated {len(stats)} statistics"
        )
        return stats

    def _get_config_summary(self) -> dict[str, object]:
        """Get configuration summary for service info.

        Returns:
            dict[str, object]: Configuration summary dictionary.

        """
        return {
            "max_entries": getattr(self._config, "max_entries", 10000),
            "strict_validation": getattr(self._config, "strict_validation", True),
            "encoding": getattr(self._config, "encoding", "utf-8"),
        }

    @staticmethod
    def _get_timestamp() -> str:
        """Get current timestamp string.

        Returns:
            str: ISO format timestamp string.

        """
        return datetime.now(UTC).isoformat()

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
                f"Person filtering failed: {e}"
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
                f"Object class filtering failed: {e}"
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
                validation_result = entry.validate_business_rules()
                if validation_result.is_success:
                    valid_entries.append(entry)
            return FlextResult[list[FlextLdifModels.Entry]].ok(valid_entries)
        except Exception as e:  # pragma: no cover
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Valid filtering failed: {e}"
            )


__all__ = ["FlextLdifAPI"]
