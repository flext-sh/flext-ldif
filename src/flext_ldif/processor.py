"""Unified LDIF Processor - Main entry point for all LDIF operations.

This module provides the unified FlextLdifProcessor class that consolidates
functionality from multiple overlapping modules into a single, coherent API
following FLEXT unified class patterns.
"""

from __future__ import annotations

import time
from pathlib import Path

from flext_core import (
    FlextContainer,
    FlextDomainService,
    FlextLogger,
    FlextResult,
    FlextUtilities,
)

from .analytics_service import FlextLdifAnalyticsService
from .config import FlextLdifConfig
from .format_handlers import FlextLdifFormatHandler
from .models import FlextLdifModels
from .parser_service import FlextLdifParserService
from .repository_service import FlextLdifRepositoryService
from .transformer_service import FlextLdifTransformerService
from .validator_service import FlextLdifValidatorService
from .writer_service import FlextLdifWriterService

__all__ = ["FlextLdifProcessor"]


class FlextLdifProcessor(FlextDomainService[dict[str, object]]):
    """Unified LDIF Processor - Single entry point for all LDIF operations.

    Consolidates functionality from multiple modules into a cohesive API:
    - Core parsing, writing, validation operations
    - File discovery and processing utilities
    - Entry filtering and analysis capabilities
    - Performance tracking and health monitoring

    Follows FLEXT unified class pattern with focused responsibilities.
    """

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize unified LDIF processor with dependency injection.

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

        # Initialize specialized services with proper dependency injection
        self._format_handler = FlextLdifFormatHandler()
        self._parser = FlextLdifParserService(self._format_handler)
        self._validator = FlextLdifValidatorService()
        self._writer = FlextLdifWriterService(self._format_handler)
        self._repository = FlextLdifRepositoryService()
        self._analytics = FlextLdifAnalyticsService()
        self._transformer = FlextLdifTransformerService()

        self._logger.info(
            "processor_initialized",
            config_sealed=self._config.is_sealed(),
            services_count=6,
        )

    @property
    def config(self) -> FlextLdifConfig:
        """Access processor configuration."""
        return self._config

    # Core Processing Operations

    def parse_ldif_file(
        self, file_path: str | Path
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF file with enhanced validation and performance tracking.

        Args:
            file_path: Path to LDIF file

        Returns:
            FlextResult containing parsed entries

        """
        file_path_obj = Path(file_path)
        start_time = time.time()

        # Enhanced file validation
        validation_result = self._validate_file_path(file_path_obj)
        if validation_result.is_failure:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                validation_result.error or "File validation failed"
            )

        try:
            result = self._parser.parse_ldif_file(str(file_path_obj))
            if result.is_failure:
                self._logger.error(
                    "parse_file_failed",
                    file_path=str(file_path_obj),
                    error=result.error,
                )
                return result

            entries = result.unwrap()
            elapsed = time.time() - start_time
            self._operation_count += 1
            self._total_entries_processed += len(entries)

            self._logger.info(
                "parse_file_success",
                file_path=str(file_path_obj),
                entries_count=len(entries),
                elapsed_ms=elapsed * 1000,
                total_operations=self._operation_count,
            )

            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

        except Exception as exc:
            elapsed = time.time() - start_time
            self._logger.exception(
                "parse_file_unexpected_error",
                file_path=str(file_path_obj),
                error=str(exc),
                elapsed_ms=elapsed * 1000,
            )
            return FlextResult[list[FlextLdifModels.Entry]].fail(f"Parse failed: {exc}")

    def parse_string(self, content: str) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF content string with validation.

        Args:
            content: LDIF content to parse

        Returns:
            FlextResult containing parsed entries

        """
        # Input validation
        if not content.strip():
            self._logger.debug("parse_string_empty_content")
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        start_time = time.time()
        content_size = len(content)

        self._logger.info("parse_string_started", content_size=content_size)

        try:
            result = self._parser.parse_content(content)
            if result.is_failure:
                self._logger.error(
                    "parse_string_failed",
                    error=result.error,
                    content_size=content_size,
                    content_preview=content[:100] if content else "",
                )
                return result

            entries = result.unwrap()
            elapsed = time.time() - start_time
            self._operation_count += 1
            self._total_entries_processed += len(entries)

            self._logger.info(
                "parse_string_success",
                entries_count=len(entries),
                content_size=content_size,
                elapsed_ms=elapsed * 1000,
            )

            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

        except Exception as exc:
            elapsed = time.time() - start_time
            self._logger.exception(
                "parse_string_unexpected_error",
                error=str(exc),
                content_size=content_size,
                elapsed_ms=elapsed * 1000,
            )
            return FlextResult[list[FlextLdifModels.Entry]].fail(f"Parse failed: {exc}")

    def write_file(
        self,
        entries: list[FlextLdifModels.Entry],
        file_path: str | Path,
    ) -> FlextResult[bool]:
        """Write entries to LDIF file with validation.

        Args:
            entries: LDIF entries to write
            file_path: Destination file path

        Returns:
            FlextResult indicating write success

        """
        if not entries:
            return FlextResult[bool].fail("Cannot write empty entry list")

        start_time = time.time()
        file_path_obj = Path(file_path)

        try:
            result = self._writer.write_entries_to_file(entries, str(file_path_obj))
            if result.is_failure:
                self._logger.error(
                    "write_file_failed",
                    file_path=str(file_path_obj),
                    entries_count=len(entries),
                    error=result.error,
                )
                return FlextResult[bool].fail(result.error or "Write failed")

            elapsed = time.time() - start_time
            self._operation_count += 1

            self._logger.info(
                "write_file_success",
                file_path=str(file_path_obj),
                entries_count=len(entries),
                elapsed_ms=elapsed * 1000,
            )

            return FlextResult[bool].ok(data=True)

        except Exception as exc:
            elapsed = time.time() - start_time
            self._logger.exception(
                "write_file_unexpected_error",
                file_path=str(file_path_obj),
                error=str(exc),
                elapsed_ms=elapsed * 1000,
            )
            return FlextResult[bool].fail(f"Write failed: {exc}")

    def write_string(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[str]:
        """Write entries to LDIF string format.

        Args:
            entries: LDIF entries to write

        Returns:
            FlextResult containing LDIF string content

        """
        if not entries:
            return FlextResult[str].fail("Cannot write empty entry list")

        try:
            result = self._writer.write_entries_to_string(entries)
            if result.is_success:
                self._operation_count += 1
                self._logger.debug(
                    "write_string_success",
                    entries_count=len(entries),
                    content_length=len(result.unwrap()),
                )
            return result

        except Exception as exc:
            self._logger.exception("write_string_unexpected_error", error=str(exc))
            return FlextResult[str].fail(f"Write string failed: {exc}")

    def validate_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[bool]:
        """Validate LDIF entries using centralized validation.

        Args:
            entries: LDIF entries to validate

        Returns:
            FlextResult indicating validation success

        """
        if not entries:
            return FlextResult[bool].fail("Cannot validate empty entry list")

        try:
            # Validate entry count against configuration limits
            max_entries = self._config.ldif_max_entries
            if len(entries) > max_entries:
                return FlextResult[bool].fail(
                    f"Entry count exceeded: {len(entries)} entries, limit is {max_entries}"
                )

            # Use validator service for detailed validation
            validation_result = self._validator.validate_entries(entries)
            if validation_result.is_success:
                self._operation_count += 1
                self._logger.debug(
                    "validate_entries_success", entries_count=len(entries)
                )
                return FlextResult[bool].ok(data=True)

            error_msg = validation_result.error or "Validation failed"
            return FlextResult[bool].fail(error_msg)

        except Exception as exc:
            self._logger.exception("validate_entries_unexpected_error", error=str(exc))
            return FlextResult[bool].fail(f"Validation failed: {exc}")

    # File Discovery and Management

    def discover_ldif_files(
        self,
        directory_path: str | Path | None = None,
        file_pattern: str = "*.ldif",
        max_file_size_mb: int | None = None,
    ) -> FlextResult[list[Path]]:
        """Discover LDIF files using pattern matching and size filtering.

        Args:
            directory_path: Directory to search (default: current directory)
            file_pattern: File pattern to match (default: *.ldif)
            max_file_size_mb: Maximum file size limit

        Returns:
            FlextResult containing list of discovered file paths

        """
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
        """Filter person entries from entry list.

        Args:
            entries: LDIF entries to filter

        Returns:
            FlextResult containing filtered person entries

        """
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
        """Filter group entries from entry list.

        Args:
            entries: LDIF entries to filter

        Returns:
            FlextResult containing filtered group entries

        """
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
        """Filter entries by objectClass attribute.

        Args:
            entries: LDIF entries to filter
            object_class: ObjectClass to filter by

        Returns:
            FlextResult containing filtered entries

        """
        try:
            return self._repository.filter_entries_by_objectclass(entries, object_class)
        except Exception as exc:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Filter by objectclass failed: {exc}"
            )

    def filter_by_attribute(
        self, entries: list[FlextLdifModels.Entry], attribute: str, value: str
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by specific attribute value.

        Args:
            entries: LDIF entries to filter
            attribute: Attribute name to filter by
            value: Attribute value to match

        Returns:
            FlextResult containing filtered entries

        """
        try:
            return self._repository.filter_entries_by_attribute(
                entries, attribute, value
            )
        except Exception as exc:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Filter by attribute failed: {exc}"
            )

    # Analysis and Statistics

    def analyze_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, int]]:
        """Analyze LDIF entries and return comprehensive statistics.

        Args:
            entries: LDIF entries to analyze

        Returns:
            FlextResult containing analysis statistics

        """
        if not entries:
            return FlextResult[dict[str, int]].fail("Cannot analyze empty entry list")

        try:
            return self._repository.get_statistics(entries)
        except Exception as exc:
            return FlextResult[dict[str, int]].fail(f"Analysis failed: {exc}")

    def get_objectclass_distribution(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, int]]:
        """Get distribution of objectClass types in entries.

        Args:
            entries: LDIF entries to analyze

        Returns:
            FlextResult containing objectClass distribution

        """
        try:
            return self._analytics.get_objectclass_distribution(entries)
        except Exception as exc:
            return FlextResult[dict[str, int]].fail(
                f"ObjectClass distribution failed: {exc}"
            )

    def get_dn_depth_analysis(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, int]]:
        """Analyze DN depth distribution in entries.

        Args:
            entries: LDIF entries to analyze

        Returns:
            FlextResult containing DN depth analysis

        """
        try:
            return self._analytics.get_dn_depth_analysis(entries)
        except Exception as exc:
            return FlextResult[dict[str, int]].fail(f"DN depth analysis failed: {exc}")

    # Utility Operations

    def sort_hierarchically(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort entries hierarchically by DN depth.

        Args:
            entries: LDIF entries to sort

        Returns:
            FlextResult containing sorted entries

        """
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
        """Find entry by Distinguished Name.

        Args:
            entries: LDIF entries to search
            dn: Distinguished Name to find

        Returns:
            FlextResult containing found entry or None

        """
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
        """Normalize DN format according to LDAP standards.

        Args:
            dn: Distinguished Name to normalize

        Returns:
            FlextResult containing normalized DN

        """
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
        """Get comprehensive performance metrics for the processor.

        Returns:
            FlextResult containing performance statistics

        """
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
        self._logger.info("performance_metrics_reset")
        return FlextResult[None].ok(None)

    def health_check(self) -> FlextResult[dict[str, object]]:
        """Perform comprehensive health check of processor and services.

        Returns:
            FlextResult containing health status information

        """
        # Get performance metrics
        metrics_result = self.get_performance_metrics()
        performance_metrics = (
            metrics_result.unwrap() if metrics_result.is_success else {}
        )

        health_status = {
            "processor_healthy": True,
            "services_initialized": True,
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

        except Exception as exc:
            health_status["processor_healthy"] = False
            health_status["health_check_error"] = str(exc)
            self._logger.exception("health_check_failed", error=str(exc))

        # Overall health determination
        overall_healthy = all(
            [
                health_status.get("processor_healthy", False),
                health_status.get("parser_healthy", False),
                health_status.get("validator_healthy", False),
                health_status.get("writer_healthy", False),
            ]
        )

        health_status["overall_healthy"] = overall_healthy

        self._logger.info("health_check_completed", overall_healthy=overall_healthy)

        if overall_healthy:
            return FlextResult[dict[str, object]].ok(health_status)
        return FlextResult[dict[str, object]].fail(
            f"Health check failed: {health_status}"
        )

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute processor operation - domain service interface.

        Returns:
            FlextResult containing processor status

        """
        return FlextResult[dict[str, object]].ok(
            {"status": "ready", "processor": "FlextLdifProcessor"}
        )

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
