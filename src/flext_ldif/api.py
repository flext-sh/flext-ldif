"""FLEXT LDIF - API unified using flext-core patterns.

This module provides the complete LDIF processing API using flext-core
patterns for result handling, configuration, and dependency injection.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from flext_core import FlextResult, get_logger
from flext_observability import (
    FlextObservabilityMonitor,
    flext_create_trace,
    flext_monitor_function,
)

from .config import FlextLdifConfig
from .core import TLdif

if TYPE_CHECKING:
    from .models import FlextLdifEntry, LDIFContent


class FlextLdifAPI:
    """Unified LDIF API using flext-core patterns with real observability."""

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize LDIF API with configuration and real observability."""
        self.logger = get_logger(self.__class__.__name__)
        self.logger.debug("Initializing FlextLdifAPI with config: %s", config)

        self.config = config or FlextLdifConfig()
        self.logger.debug("Configuration loaded: max_entries=%d, strict_validation=%s, input_encoding=%s, output_encoding=%s",
                         self.config.max_entries, self.config.strict_validation,
                         self.config.input_encoding, self.config.output_encoding)
        self.logger.trace("Full configuration: %s", self.config.model_dump())

        # Real observability integration
        self.logger.debug("Initializing observability monitor")
        self._observability_monitor = FlextObservabilityMonitor()
        init_result = self._observability_monitor.flext_initialize_observability()
        if init_result.is_success:
            self.logger.debug("Observability initialized successfully")
            self._observability_monitor.flext_start_monitoring()
            self.logger.info("LDIF API initialized with real observability monitoring")
            self.logger.trace("Observability monitor ready for metrics collection")
        else:
            self.logger.warning(
                "Failed to initialize observability: %s", init_result.error,
            )
            self.logger.debug("Continuing without observability monitoring")

        self.logger.debug("FlextLdifAPI initialization completed successfully")
        # Specifications now integrated in FlextLdifEntry via composition

    @flext_monitor_function(metric_name="ldif_parse_operation")
    def parse(self, content: str | LDIFContent) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF content with intelligent processing and real monitoring."""
        self.logger.debug("Starting LDIF content parsing")
        self.logger.trace("Parse input type: %s", type(content).__name__)

        # Create distributed trace for operation (handled by monitoring framework)
        trace_id = f"ldif_parse_{id(content)}"
        self.logger.debug("Creating distributed trace with ID: %s", trace_id)
        _ = flext_create_trace(
            trace_id=trace_id,
            operation="ldif_parse",
        )

        try:
            # Record parsing metrics
            content_size = len(str(content))
            self.logger.debug("Content size: %d bytes", content_size)
            self.logger.trace("Recording content size metric: %d bytes", content_size)
            self._observability_monitor.flext_record_metric(
                "ldif_content_size_bytes",
                float(content_size),
                "histogram",
            )

            # Parse using core functionality
            self.logger.debug("Delegating to TLdif.parse for core parsing")
            self.logger.trace("Using configuration: strict_validation=%s, max_entries=%d",
                             self.config.strict_validation, self.config.max_entries)
            parse_result = TLdif.parse(content)

            if not parse_result.is_success:
                self.logger.warning("Core parsing failed: %s", parse_result.error)
                self.logger.debug("Recording parse error metric")
                self._observability_monitor.flext_record_metric(
                    "ldif_parse_errors_total",
                    1.0,
                    "counter",
                )
                return parse_result

            entries = parse_result.data
            if entries is None:
                self.logger.warning("Parse succeeded but returned None entries")
                self.logger.debug("Returning failure for None entries")
                return FlextResult.fail("No entries parsed")

            # Record successful parsing metrics
            entries_count = len(entries)
            self.logger.debug("Successfully parsed %d entries", entries_count)
            self.logger.trace("Parsed entries DNs: %s", [str(entry.dn) for entry in entries[:5]])  # First 5 for trace

            self.logger.debug("Recording successful parsing metrics")
            self._observability_monitor.flext_record_metric(
                "ldif_entries_parsed_total",
                float(entries_count),
                "counter",
            )
            self._observability_monitor.flext_record_metric(
                "ldif_entries_per_operation",
                float(entries_count),
                "histogram",
            )

            # Record validation warnings if strict validation enabled (parse always succeeds)
            if self.config.strict_validation:
                self.logger.debug("Strict validation enabled, validating %d entries", entries_count)
                self.logger.trace("Running TLdif.validate_entries with strict mode")
                validate_result = TLdif.validate_entries(entries)
                if not validate_result.is_success:
                    self.logger.warning("Strict validation warnings: %s", validate_result.error)
                    self.logger.debug("Recording validation warning metric")
                    self._observability_monitor.flext_record_metric(
                        "ldif_validation_warnings_total",
                        1.0,
                        "counter",
                    )
                    # Continue with parse success, just log validation warnings
                    self.logger.info("Parse succeeded with validation warnings",
                                   entries_count=entries_count,
                                   validation_warnings=validate_result.error)
                else:
                    self.logger.debug("Strict validation passed for all entries")
            else:
                self.logger.trace("Skipping strict validation (disabled in config)")

            # Check limits
            if len(entries) > self.config.max_entries:
                self.logger.warning("Entry count %d exceeds max_entries limit %d",
                                  len(entries), self.config.max_entries)
                self.logger.debug("Recording limit exceeded metric")
                self._observability_monitor.flext_record_metric(
                    "ldif_limit_exceeded_total",
                    1.0,
                    "counter",
                )
                return FlextResult.fail(
                    f"Too many entries: {len(entries)} > {self.config.max_entries}",
                )
            self.logger.trace("Entry count %d within limit %d", len(entries), self.config.max_entries)

            # Record successful completion
            self.logger.debug("Recording successful completion metrics")
            self._observability_monitor.flext_record_metric(
                "ldif_parse_success_total",
                1.0,
                "counter",
            )

            self.logger.info(
                "LDIF parsing completed successfully",
                entries_count=entries_count,
                content_size_bytes=content_size,
                strict_validation=self.config.strict_validation,
            )
            self.logger.trace("Parse operation trace ID %s completed successfully", trace_id)

            # Note: Trace completion handled by observability monitor
            # The trace is automatically managed by the monitoring framework

            return FlextResult.ok(entries)

        except (ValueError, TypeError, AttributeError, OSError, ImportError) as e:
            # Record error metrics
            self.logger.debug("Exception type: %s", type(e).__name__)
            self.logger.trace("Full exception details", exc_info=True)

            self.logger.debug("Recording parse exception metric")
            self._observability_monitor.flext_record_metric(
                "ldif_parse_exceptions_total",
                1.0,
                "counter",
            )
            self.logger.exception("LDIF parsing failed with exception")

            # Note: Trace error handling managed by observability monitor
            # The trace records errors automatically through the monitoring framework
            self.logger.trace("Trace ID %s failed with exception", trace_id)

            return FlextResult.fail(f"Parse failed: {e}")

    @flext_monitor_function(metric_name="ldif_parse_file_operation")
    def parse_file(self, file_path: str | Path) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF file with intelligent parsing, validation and real monitoring."""
        # Create distributed trace for file operation (handled by monitoring framework)
        _ = flext_create_trace(
            trace_id=f"ldif_parse_file_{hash(str(file_path))}",
            operation="ldif_parse_file",
        )

        try:
            # Record file parsing metrics
            self._observability_monitor.flext_record_metric(
                "ldif_file_operations_total",
                1.0,
                "counter",
            )

            # Parse using core functionality with input encoding
            parse_result = TLdif.read_file(file_path, self.config.input_encoding)
            if not parse_result.is_success:
                self._observability_monitor.flext_record_metric(
                    "ldif_file_parse_errors_total",
                    1.0,
                    "counter",
                )
                return parse_result

            entries = parse_result.data
            if entries is None:
                return FlextResult.fail("No entries parsed from file")

            # Record successful file parsing metrics
            entries_count = len(entries)
            self._observability_monitor.flext_record_metric(
                "ldif_file_entries_parsed_total",
                float(entries_count),
                "counter",
            )

            # Apply config limits and validation
            if len(entries) > self.config.max_entries:
                self._observability_monitor.flext_record_metric(
                    "ldif_file_limit_exceeded_total",
                    1.0,
                    "counter",
                )
                return FlextResult.fail(
                    f"Too many entries: {len(entries)} > {self.config.max_entries}",
                )

            if self.config.strict_validation:
                validate_result = TLdif.validate_entries(entries)
                if not validate_result.is_success:
                    self.logger.warning("File validation warnings: %s", validate_result.error)
                    self._observability_monitor.flext_record_metric(
                        "ldif_file_validation_warnings_total",
                        1.0,
                        "counter",
                    )
                    # Continue with parse success, just log validation warnings
                    self.logger.info("File parse succeeded with validation warnings",
                                   file_path=str(file_path),
                                   entries_count=len(entries),
                                   validation_warnings=validate_result.error)

            # Record successful completion
            self._observability_monitor.flext_record_metric(
                "ldif_file_parse_success_total",
                1.0,
                "counter",
            )

            self.logger.info(
                "LDIF file parsing completed successfully",
                file_path=str(file_path),
                entries_count=entries_count,
                strict_validation=self.config.strict_validation,
            )

            # Note: File trace completion handled by observability monitor
            # The trace is automatically managed by the monitoring framework

            return FlextResult.ok(entries)

        except (OSError, ValueError, TypeError, AttributeError, ImportError) as e:
            # Record error metrics
            self._observability_monitor.flext_record_metric(
                "ldif_file_exceptions_total",
                1.0,
                "counter",
            )
            self.logger.exception("LDIF file parsing failed", file_path=str(file_path))

            # Note: File trace error handling managed by observability monitor
            # The trace records errors automatically through the monitoring framework

            return FlextResult.fail(f"File parse failed: {e}")

    def validate(self, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate LDIF entries using configuration settings."""
        self.logger.debug("Starting validation of %d entries", len(entries))
        self.logger.trace("Validation config: allow_empty_attributes=%s, max_entry_size=%d, input_encoding=%s",
                         self.config.allow_empty_attributes, self.config.max_entry_size, self.config.input_encoding)

        # Apply configuration-based validation
        if not self.config.allow_empty_attributes:
            self.logger.debug("Checking for empty attributes (not allowed)")
            empty_attr_count = 0
            for i, entry in enumerate(entries):
                self.logger.trace("Validating entry %d: %s", i, entry.dn)
                for attr_name, attr_values in entry.attributes.attributes.items():
                    if not attr_values or any(not v.strip() for v in attr_values):
                        self.logger.warning("Empty attribute value found: %s in %s", attr_name, entry.dn)
                        self.logger.debug("Failing validation due to empty attribute")
                        return FlextResult.fail(
                            f"Empty attribute value not allowed: {attr_name} in {entry.dn}",
                        )
                    empty_attr_count += sum(1 for v in attr_values if not v.strip())

            if empty_attr_count == 0:
                self.logger.debug("No empty attributes found (validation passed)")
            else:
                self.logger.trace("Found %d empty attribute values", empty_attr_count)
        else:
            self.logger.trace("Skipping empty attribute check (allowed in config)")

        # Check entry size limits
        self.logger.debug("Checking entry size limits (max: %d bytes)", self.config.max_entry_size)
        oversized_entries = 0
        for i, entry in enumerate(entries):
            entry_ldif = entry.to_ldif()
            entry_size = len(entry_ldif.encode(self.config.input_encoding))
            self.logger.trace("Entry %d (%s) size: %d bytes", i, entry.dn, entry_size)

            if entry_size > self.config.max_entry_size:
                self.logger.warning("Entry size %d exceeds limit %d: %s",
                                  entry_size, self.config.max_entry_size, entry.dn)
                self.logger.debug("Failing validation due to oversized entry")
                return FlextResult.fail(
                    f"Entry size {entry_size} exceeds limit {self.config.max_entry_size}: {entry.dn}",
                )
            oversized_entries += 1 if entry_size > (self.config.max_entry_size * 0.8) else 0

        if oversized_entries > 0:
            self.logger.debug("Found %d entries approaching size limit (>80%% of max)", oversized_entries)
        else:
            self.logger.debug("All entries within size limits")

        # Use core validation
        self.logger.debug("Delegating to TLdif.validate_entries for core validation")
        self.logger.trace("Core validation will check DN format, attribute names, and objectClass presence")
        result = TLdif.validate_entries(entries)

        if result.is_success:
            self.logger.debug("Core validation passed for all %d entries", len(entries))
            self.logger.info("Entry validation completed successfully",
                           entries_validated=len(entries),
                           allow_empty_attributes=self.config.allow_empty_attributes,
                           max_entry_size=self.config.max_entry_size)
        else:
            self.logger.warning("Core validation failed: %s", result.error)
            self.logger.debug("Validation failure details logged by TLdif.validate_entries")

        return result

    def write(
        self,
        entries: list[FlextLdifEntry],
        file_path: str | Path | None = None,
    ) -> FlextResult[str]:
        """Write LDIF entries to string or file with intelligent formatting using configuration."""
        self.logger.debug("Starting write operation for %d entries", len(entries))
        self.logger.trace("Write target: %s", "file" if file_path else "string")

        if file_path:
            self.logger.debug("Writing to file: %s", file_path)

            # Use output directory configuration if relative path
            original_path = str(file_path)
            file_path = Path(file_path)
            self.logger.trace("Original file path: %s", original_path)

            if not file_path.is_absolute() and self.config.output_directory:
                self.logger.debug("Resolving relative path with output_directory: %s", self.config.output_directory)
                file_path = self.config.output_directory / file_path
                self.logger.trace("Resolved absolute path: %s", file_path)
            else:
                self.logger.trace("Using path as-is (absolute or no output_directory configured)")

            # Create output directory if configured to do so and parent is valid
            if self.config.create_output_dir and file_path.parent:
                self.logger.debug("Creating output directory if needed: %s", file_path.parent)
                try:
                    file_path.parent.mkdir(parents=True, exist_ok=True)
                    self.logger.trace("Directory created/verified: %s", file_path.parent)
                except (OSError, PermissionError) as e:
                    # If can't create directory, let the write operation fail naturally
                    self.logger.warning("Failed to create output directory %s: %s", file_path.parent, e)
                    self.logger.debug("Continuing with write operation, may fail if directory doesn't exist")
            else:
                self.logger.trace("Skipping directory creation (disabled or no parent directory)")

            # Write to file using core functionality with encoding
            self.logger.debug("Delegating to TLdif.write_file with encoding: %s", self.config.output_encoding)
            self.logger.trace("Writing entries to file: %s", [str(entry.dn) for entry in entries[:3]])  # First 3 for trace

            result = TLdif.write_file(entries, file_path, self.config.output_encoding)
            if result.is_success:
                self.logger.debug("File write successful: %s", file_path)
                self.logger.info("LDIF entries written to file",
                               entries_count=len(entries),
                               file_path=str(file_path),
                               encoding=self.config.output_encoding)
                return FlextResult.ok(f"Written to {file_path}")
            self.logger.error("File write failed: %s", result.error)
            self.logger.debug("TLdif.write_file returned failure")
            return FlextResult.fail(result.error or "Write failed")

        # Return LDIF string using core functionality
        self.logger.debug("Writing to string (no file path provided)")
        self.logger.trace("Delegating to TLdif.write for string output")

        string_result: FlextResult[str] = TLdif.write(entries)
        if string_result.is_success and string_result.data:
            output_size = len(string_result.data)
            self.logger.debug("String write successful, output size: %d characters", output_size)
            self.logger.trace("String output preview: %s...", string_result.data[:100])
            self.logger.info("LDIF entries converted to string",
                           entries_count=len(entries),
                           output_size_chars=output_size)
            return FlextResult.ok(string_result.data)
        self.logger.error("String write failed: %s", string_result.error)
        self.logger.debug("TLdif.write returned failure")
        return FlextResult.fail(string_result.error or "String write failed")

    @flext_monitor_function(metric_name="ldif_filter_persons")
    def filter_persons(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter person entries using integrated composition logic with monitoring."""
        try:
            # Record filtering metrics
            total_entries = len(entries)
            self._observability_monitor.flext_record_metric(
                "ldif_filter_input_entries",
                float(total_entries),
                "histogram",
            )

            person_entries = [entry for entry in entries if entry.is_person_entry()]

            # Record results
            person_count = len(person_entries)
            self._observability_monitor.flext_record_metric(
                "ldif_persons_filtered",
                float(person_count),
                "histogram",
            )
            self._observability_monitor.flext_record_metric(
                "ldif_filter_persons_total",
                1.0,
                "counter",
            )

            self.logger.info(
                "Person entries filtered successfully",
                total_entries=total_entries,
                person_entries=person_count,
                filter_ratio=person_count/total_entries if total_entries > 0 else 0,
            )

            return FlextResult.ok(person_entries)
        except (ValueError, TypeError, AttributeError) as e:
            self._observability_monitor.flext_record_metric(
                "ldif_filter_persons_errors_total",
                1.0,
                "counter",
            )
            return FlextResult.fail(f"Failed to filter person entries: {e}")

    def filter_valid(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter valid entries using integrated composition logic."""
        try:
            valid_entries = [entry for entry in entries if entry.is_valid_entry()]
            return FlextResult.ok(valid_entries)
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to filter valid entries: {e}")

    def filter_by_objectclass(
        self,
        entries: list[FlextLdifEntry],
        object_class: str,
    ) -> list[FlextLdifEntry]:
        """Filter entries by objectClass using intelligent filtering."""
        return [entry for entry in entries if entry.has_object_class(object_class)]

    def find_entry_by_dn(
        self,
        entries: list[FlextLdifEntry],
        dn: str,
    ) -> FlextLdifEntry | None:
        """Find entry by DN with intelligent search."""
        for entry in entries:
            if str(entry.dn) == dn:
                return entry
        return None

    def sort_hierarchically(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Sort entries hierarchically using intelligent sorting."""
        try:
            sorted_entries = sorted(
                entries,
                key=lambda entry: (
                    str(entry.dn).count(","),  # Primary: depth (parents first)
                    str(entry.dn).lower(),  # Secondary: alphabetical
                ),
            )
            return FlextResult.ok(sorted_entries)
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to sort entries hierarchically: {e}")

    def entries_to_ldif(self, entries: list[FlextLdifEntry]) -> str:
        """Convert multiple entries to LDIF content using intelligent formatting."""
        result = TLdif.write(entries)
        if not result.is_success:
            error_msg = result.error or "LDIF write operation failed"
            error_message = f"Failed to convert entries to LDIF: {error_msg}"
            raise ValueError(error_message)
        return result.data or ""

    # ==========================================================================
    # INTELLIGENT FILTERING METHODS (Using integrated composition)
    # ==========================================================================

    def filter_groups(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter group entries using integrated composition logic."""
        try:
            group_entries = [entry for entry in entries if entry.is_group_entry()]
            return FlextResult.ok(group_entries)
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to filter group entries: {e}")

    def filter_organizational_units(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter organizational unit entries using integrated composition logic."""
        try:
            ou_entries = [entry for entry in entries if entry.is_organizational_unit()]
            return FlextResult.ok(ou_entries)
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to filter OU entries: {e}")

    def filter_change_records(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter change record entries using integrated composition logic."""
        try:
            change_entries = [entry for entry in entries if entry.is_change_record()]
            return FlextResult.ok(change_entries)
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to filter change records: {e}")

    def get_entry_statistics(self, entries: list[FlextLdifEntry]) -> dict[str, int | str]:
        """Get entry statistics using integrated composition analysis with monitoring."""
        try:
            stats: dict[str, int] = {
                "total_entries": len(entries),
                "valid_entries": sum(1 for entry in entries if entry.is_valid_entry()),
                "person_entries": sum(1 for entry in entries if entry.is_person_entry()),
                "group_entries": sum(1 for entry in entries if entry.is_group_entry()),
                "ou_entries": sum(1 for entry in entries if entry.is_organizational_unit()),
                "change_records": sum(1 for entry in entries if entry.is_change_record()),
            }

            # Record statistics as metrics
            for stat_name, stat_value in stats.items():
                self._observability_monitor.flext_record_metric(
                    f"ldif_statistics_{stat_name}",
                    float(stat_value),
                    "gauge",
                )

        except (ValueError, TypeError, AttributeError, Exception) as e:
            self.logger.exception("Failed to calculate statistics")
            return {"error": f"Statistics calculation failed: {e}"}
        else:
            self.logger.info("Entry statistics calculated", **stats)
            # Type narrowing for mypy - stats is dict[str, int] here
            return dict(stats)

    def get_observability_metrics(self) -> FlextResult[dict[str, object]]:
        """Get comprehensive observability metrics from the monitoring system."""
        try:
            if not self._observability_monitor:
                return FlextResult.fail("Observability monitor not available")

            # Get metrics summary
            metrics_result = self._observability_monitor.flext_get_metrics_summary()
            if metrics_result.is_failure:
                return FlextResult.fail(f"Failed to get metrics: {metrics_result.error}")

            # Get health status
            health_result = self._observability_monitor.flext_get_health_status()
            if health_result.is_failure:
                return FlextResult.fail(f"Failed to get health: {health_result.error}")

            # Combine metrics and health
            observability_data = {
                "metrics": metrics_result.data or {},
                "health": health_result.data or {},
                "monitoring_active": self._observability_monitor.flext_is_monitoring_active(),
            }

            return FlextResult.ok(observability_data)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to get observability metrics: {e}")

    def reset_observability_metrics(self) -> FlextResult[None]:
        """Reset observability metrics (useful for testing and cleanup)."""
        try:
            if not self._observability_monitor:
                return FlextResult.fail("Observability monitor not available")

            # Access the metrics service through container
            container = self._observability_monitor.container
            metrics_service = container.get("flext_metrics_service")

            if hasattr(metrics_service, "data") and hasattr(metrics_service.data, "reset_metrics"):
                reset_result = metrics_service.data.reset_metrics()
                if reset_result.is_failure:
                    return FlextResult.fail(f"Failed to reset metrics: {reset_result.error}")

            self.logger.info("Observability metrics reset successfully")
            return FlextResult.ok(None)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to reset observability metrics: {e}")


# Global API instance
_api_instance: FlextLdifAPI | None = None


def flext_ldif_get_api(config: FlextLdifConfig | None = None) -> FlextLdifAPI:
    """Get global LDIF API instance."""
    global _api_instance  # noqa: PLW0603
    if _api_instance is None or config is not None:
        _api_instance = FlextLdifAPI(config)
    return _api_instance


# Convenience functions using global API
def flext_ldif_parse(content: str | LDIFContent) -> list[FlextLdifEntry]:
    """Parse LDIF content - convenience function."""
    result = flext_ldif_get_api().parse(content)
    if isinstance(result, FlextResult) and result.is_success and result.data is not None:
        # Type assertion for mypy - we know result.data is list[FlextLdifEntry] here
        entries: list[FlextLdifEntry] = result.data
        return entries
    return []


def flext_ldif_validate(content: str | LDIFContent) -> bool:
    """Validate LDIF content - convenience function."""
    parse_result = flext_ldif_get_api().parse(content)
    if not isinstance(parse_result, FlextResult) or not parse_result.is_success:
        return False

    if parse_result.data is None:
        return False

    validate_result = flext_ldif_get_api().validate(parse_result.data)
    return isinstance(validate_result, FlextResult) and validate_result.is_success and bool(validate_result.data)


def flext_ldif_write(
    entries: list[FlextLdifEntry],
    output_path: str | None = None,
) -> str:
    """Write LDIF entries - convenience function."""
    result = flext_ldif_get_api().write(entries, output_path)
    if isinstance(result, FlextResult) and result.is_success and result.data is not None:
        # Type assertion for mypy - we know result.data is str here
        output: str = result.data
        return output
    return ""


__all__ = [
    "FlextLdifAPI",
    "flext_ldif_get_api",
    "flext_ldif_parse",
    "flext_ldif_validate",
    "flext_ldif_write",
]
