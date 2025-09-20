"""FLEXT LDIF API - Unified interface for LDIF operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from flext_core import FlextDomainService, FlextLogger, FlextResult
from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import FlextLdifModels
from flext_ldif.services import FlextLdifServices


class FlextLdifAPI(FlextDomainService[list[FlextLdifModels.Entry]]):
    """Unified API interface for FLEXT-LDIF operations.

    This class provides a high-level, easy-to-use interface for common LDIF
    operations such as parsing, validation, writing, and transformation.

    All operations return FlextResult for consistent error handling and follow
    the FLEXT ecosystem patterns.
    """

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize LDIF API with optional configuration.

        Args:
            config: Optional configuration instance. If None, uses global config.

        """
        super().__init__()
        self._logger = FlextLogger(__name__)

        # Configuration management
        if config is None:
            try:
                self._config = FlextLdifConfig.get_global_ldif_config()
            except RuntimeError:
                self._config = FlextLdifConfig()
        else:
            self._config = config

        # Service container
        self._services = FlextLdifServices(config=self._config)

        self._logger.debug("FlextLdifAPI initialized")

    def parse(self, content: str) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF content and return entries.

        Args:
            content: LDIF content string to parse

        Returns:
            FlextResult containing list of parsed entries or error

        """
        try:
            self._logger.debug(
                "Parsing LDIF content", extra={"content_size": len(content)}
            )
            return self._services.parser.parse_content(content)
        except Exception as e:
            self._logger.exception("LDIF content parsing failed")
            return FlextResult[list[FlextLdifModels.Entry]].fail(f"Parse error: {e}")

    def parse_file_path(
        self, file_path: str | Path
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF file and return entries.

        Args:
            file_path: Path to LDIF file to parse

        Returns:
            FlextResult containing list of parsed entries or error

        """
        try:
            path_str = str(file_path)
            self._logger.debug("Parsing LDIF file", extra={"file_path": path_str})
            return self._services.parser.parse_ldif_file(file_path)
        except Exception as e:
            self._logger.exception("LDIF file parsing failed")
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"File parse error: {e}"
            )

    def validate_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[bool]:
        """Validate LDIF entries.

        Args:
            entries: List of LDIF entries to validate

        Returns:
            FlextResult containing validation result (True if valid) or error

        """
        try:
            self._logger.debug(
                "Validating LDIF entries", extra={"entry_count": len(entries)}
            )
            validation_result = self._services.validator.validate_entries(entries)
            if validation_result.is_success:
                # Convert list result to boolean (true if entries exist and are valid)
                return FlextResult[bool].ok(len(entries) > 0)
            return FlextResult[bool].fail(
                validation_result.error or "Validation failed"
            )
        except Exception as e:
            self._logger.exception("LDIF entry validation failed")
            return FlextResult[bool].fail(f"Validation error: {e}")

    def write(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[str]:
        """Write LDIF entries to string format.

        Args:
            entries: List of LDIF entries to write

        Returns:
            FlextResult containing LDIF string or error

        """
        try:
            self._logger.debug(
                "Writing LDIF entries", extra={"entry_count": len(entries)}
            )
            return self._services.writer.write_entries_to_string(entries)
        except Exception as e:
            self._logger.exception("LDIF entry writing failed")
            return FlextResult[str].fail(f"Write error: {e}")

    def write_file(
        self, entries: list[FlextLdifModels.Entry], file_path: str | Path
    ) -> FlextResult[None]:
        """Write LDIF entries to file.

        Args:
            entries: List of LDIF entries to write
            file_path: Path where to write the LDIF file

        Returns:
            FlextResult indicating success or error

        """
        try:
            path_str = str(file_path)
            self._logger.debug(
                "Writing LDIF file",
                extra={"entry_count": len(entries), "file_path": path_str},
            )
            write_result = self._services.writer.write_entries_to_file(
                entries, file_path
            )
            if write_result.is_success:
                return FlextResult[None].ok(None)
            return FlextResult[None].fail(write_result.error or "File write failed")
        except Exception as e:
            self._logger.exception("LDIF file writing failed")
            return FlextResult[None].fail(f"File write error: {e}")

    def transform(
        self,
        entries: list[FlextLdifModels.Entry],
        transformation: Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry]
        | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Transform LDIF entries using specified transformation rules.

        Args:
            entries: List of LDIF entries to transform
            transformation: Transformation function (optional)

        Returns:
            FlextResult containing transformed entries or error

        """
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

            return self._services.transformer.transform_entries(entries, transformation)
        except Exception as e:
            self._logger.exception("LDIF entry transformation failed")
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Transform error: {e}"
            )

    def analyze(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, object]]:
        """Analyze LDIF entries and return statistics.

        Args:
            entries: List of LDIF entries to analyze

        Returns:
            FlextResult containing analysis results or error

        """
        try:
            self._logger.debug(
                "Analyzing LDIF entries", extra={"entry_count": len(entries)}
            )
            analysis_result = self._services.analytics.analyze_entries(entries)
            if analysis_result.is_success:
                # Cast from dict[str, int] to dict[str, object] since int is a subtype of object
                analytics_data = analysis_result.unwrap()
                return FlextResult[dict[str, object]].ok(dict(analytics_data))
            return FlextResult[dict[str, object]].fail(
                analysis_result.error or "Analysis failed"
            )
        except Exception as e:
            self._logger.exception("LDIF entry analysis failed")
            return FlextResult[dict[str, object]].fail(f"Analysis error: {e}")

    def filter_entries(
        self, entries: list[FlextLdifModels.Entry], criteria: dict[str, object]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter LDIF entries based on specified criteria.

        Args:
            entries: List of LDIF entries to filter
            criteria: Filter criteria

        Returns:
            FlextResult containing filtered entries or error

        """
        try:
            self._logger.debug(
                "Filtering LDIF entries",
                extra={
                    "entry_count": len(entries),
                    "criteria_keys": list(criteria.keys()),
                },
            )

            # Simple implementation using available repository methods
            if "attribute" in criteria and "value" in criteria:
                attribute_name = str(criteria["attribute"])
                attribute_value = (
                    str(criteria["value"]) if criteria["value"] is not None else None
                )
                return self._services.repository.filter_entries_by_attribute(
                    entries, attribute_name, attribute_value
                )
            if "objectClass" in criteria:
                object_class = str(criteria["objectClass"])
                return self._services.repository.filter_entries_by_objectclass(
                    entries, object_class
                )
            # Return all entries if no supported criteria
            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

        except Exception as e:
            self._logger.exception("LDIF entry filtering failed")
            return FlextResult[list[FlextLdifModels.Entry]].fail(f"Filter error: {e}")

    def health_check(self) -> FlextResult[dict[str, object]]:
        """Perform health check on the API and underlying services.

        Returns:
            FlextResult containing health status or error

        """
        try:
            self._logger.debug("Performing API health check")

            # Check service container health
            service_health = self._services.health_check()
            if service_health.is_failure:
                return FlextResult[dict[str, object]].fail(
                    f"Service health check failed: {service_health.error}"
                )

            health_status: dict[str, object] = {
                "api": "FlextLdifAPI",
                "status": "healthy",
                "services": service_health.unwrap(),
                "config": {
                    "type": type(self._config).__name__,
                    "memory_management": getattr(
                        self._config, "memory_management_enabled", "unknown"
                    ),
                    "validation_mode": getattr(
                        self._config, "strict_validation", "unknown"
                    ),
                },
            }

            return FlextResult[dict[str, object]].ok(health_status)

        except Exception as e:
            self._logger.exception("API health check failed")
            return FlextResult[dict[str, object]].fail(f"Health check error: {e}")

    def get_service_info(self) -> dict[str, object]:
        """Get information about the API and its services."""
        return {
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
            "services": self._services.get_service_info(),
            "config": {
                "type": type(self._config).__name__,
                "memory_management": getattr(
                    self._config, "memory_management_enabled", "unknown"
                ),
                "validation_mode": getattr(
                    self._config, "strict_validation", "unknown"
                ),
            },
        }

    def execute(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute API operation - FlextDomainService interface."""
        return FlextResult[list[FlextLdifModels.Entry]].ok([])


__all__ = [
    "FlextLdifAPI",
]
