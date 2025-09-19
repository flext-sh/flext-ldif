"""FLEXT LDIF API - Unified LDIF processing API.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import time
from pathlib import Path

from flext_core import FlextContainer, FlextLogger, FlextResult
from flext_ldif.analytics_service import FlextLdifAnalyticsService
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.dispatcher import FlextLdifDispatcher
from flext_ldif.models import FlextLdifModels
from flext_ldif.parser_service import FlextLdifParserService
from flext_ldif.repository_service import FlextLdifRepositoryService
from flext_ldif.services import FlextLdifServices
from flext_ldif.validator_service import FlextLdifValidatorService
from flext_ldif.writer_service import FlextLdifWriterService


class FlextLdifAPI:
    """Unified LDIF Processing API.

    Enterprise-grade LDIF operations with railway-oriented programming,
    dependency injection, and comprehensive error handling. Follows unified
    class architecture with nested operation handlers.
    """

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize unified LDIF API with enhanced dependency injection.

        Args:
            config: Optional LDIF processing configuration

        """
        # Initialize with enhanced observability and error tracking
        self._logger = FlextLogger(__name__)
        self._container = FlextContainer.get_global()
        self._config = config or FlextLdifConfig()

        # Performance tracking initialization
        self._start_time = time.time()
        self._operation_count = 0
        self._total_entries_processed = 0

        # Initialize nested operation handlers with enhanced patterns
        self._operations = self.Operations(self)
        self._filters = self.Filters(self)
        self._analytics = self.Analytics(self)

        # Initialize services with proper dependency injection and error handling
        try:
            self._services = self._initialize_services()
            self._logger.info(
                "services_initialized",
                api=self.__class__.__name__,
                config_sealed=self._config.is_sealed(),
            )
        except Exception as exc:
            self._logger.exception(
                "services_initialization_failed",
                error=str(exc),
                config_type=type(self._config).__name__,
            )
            raise

        # Enhanced dispatcher initialization with circuit breaker pattern
        self._dispatcher: FlextLdifDispatcher.SimpleDispatcher | None = None
        self._dispatcher_failures = 0
        self._max_dispatcher_failures = 3

        if FlextLdifConstants.FeatureFlags.dispatcher_enabled():
            try:
                self._dispatcher = FlextLdifDispatcher.build_dispatcher(self._services)
                self._logger.info(
                    "dispatcher_enabled",
                    api=self.__class__.__name__,
                    dispatcher_type=type(self._dispatcher).__name__,
                )
            except Exception as exc:  # pragma: no cover - defensive logging
                self._logger.exception(
                    "dispatcher_initialisation_failed",
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
                self._dispatcher = None

    def _dispatch_command(self, message: object) -> FlextResult[object]:
        """Dispatch helper with circuit breaker pattern and enhanced error handling."""
        if self._dispatcher is None:
            return FlextResult[object].fail("Dispatcher not enabled")

        # Circuit breaker pattern - fail fast if too many failures
        if self._dispatcher_failures >= self._max_dispatcher_failures:
            self._logger.warning(
                "dispatcher_circuit_breaker_open",
                failures=self._dispatcher_failures,
                max_failures=self._max_dispatcher_failures,
            )
            return FlextResult[object].fail(
                f"Dispatcher circuit breaker open: {self._dispatcher_failures} failures"
            )

        try:
            dispatch_result = self._dispatcher.dispatch(message)
            if dispatch_result.is_failure:
                self._dispatcher_failures += 1
                self._logger.warning(
                    "dispatcher_operation_failed",
                    error=dispatch_result.error,
                    failures=self._dispatcher_failures,
                    message_type=type(message).__name__,
                )
                return FlextResult[object].fail(
                    dispatch_result.error or "Dispatcher failed",
                )

            # Reset failure count on success
            self._dispatcher_failures = 0
            handler_output = dispatch_result.unwrap()

            if isinstance(handler_output, FlextResult):
                return handler_output
            return FlextResult[object].ok(handler_output)

        except Exception as exc:
            self._dispatcher_failures += 1
            self._logger.exception(
                "dispatcher_unexpected_error",
                error=str(exc),
                error_type=type(exc).__name__,
                failures=self._dispatcher_failures,
                message_type=type(message).__name__,
            )
            return FlextResult[object].fail(f"Dispatcher error: {exc}")

    class Operations:
        """Nested operations handler for core LDIF processing."""

        def __init__(self, api_instance: FlextLdifAPI) -> None:
            """Initialize with parent API reference."""
            self._api = api_instance
            self._logger = api_instance._logger
            self._config = api_instance._config

        def parse_string(
            self, content: str
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Parse LDIF content using enhanced railway-oriented programming with performance tracking."""
            # Input validation with early return
            if not content.strip():
                self._logger.debug("parse_string_empty_content")
                return FlextResult[list[FlextLdifModels.Entry]].ok([])

            # Performance tracking
            start_time = time.time()
            content_size = len(content)

            self._logger.info(
                "parse_string_started",
                content_size=content_size,
                has_dispatcher=self._api._dispatcher is not None,
            )

            # Try dispatcher path first if available
            if self._api._dispatcher is not None:
                dispatch_result = self._api._dispatch_command(
                    FlextLdifModels.ParseStringCommand(content=content),
                )
                if dispatch_result.is_success:
                    # Track successful dispatcher operation
                    elapsed = time.time() - start_time
                    self._api._operation_count += 1
                    self._logger.info(
                        "parse_string_dispatcher_success",
                        content_size=content_size,
                        elapsed_ms=elapsed,
                        operation_count=self._api._operation_count,
                    )
                    return dispatch_result

                self._logger.warning(
                    "dispatcher_parse_string_failed",
                    error=dispatch_result.error,
                    content_size=content_size,
                    fallback_to_direct=True,
                )

            # Fallback to direct service with enhanced error context
            try:
                result = self._api._services.parser.parse_content(content)
                if result.is_failure:
                    self._logger.error(
                        "parse_string_service_failed",
                        error=result.error,
                        content_size=content_size,
                        content_preview=content[:100] if content else "",
                    )
                    return result

                # Validate and track success
                validated_result = result.flat_map(self._validate_entry_count)
                if validated_result.is_success:
                    entries = validated_result.unwrap()
                    elapsed = time.time() - start_time
                    self._api._operation_count += 1
                    self._api._total_entries_processed += len(entries)

                    self._logger.info(
                        "parse_string_success",
                        entries_count=len(entries),
                        content_size=content_size,
                        elapsed_ms=elapsed,
                        total_entries_processed=self._api._total_entries_processed,
                    )

                return validated_result

            except Exception as exc:
                elapsed = time.time() - start_time
                self._logger.exception(
                    "parse_string_unexpected_error",
                    error=str(exc),
                    error_type=type(exc).__name__,
                    content_size=content_size,
                    elapsed_ms=elapsed,
                )
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Parse operation failed: {exc}"
                )

        def parse_file(
            self, file_path: str | Path
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Parse LDIF file with enhanced validation and performance tracking."""
            file_path_obj = Path(file_path)
            start_time = time.time()

            # Enhanced file validation
            if not file_path_obj.exists():
                self._logger.error(
                    "parse_file_not_found",
                    file_path=str(file_path_obj),
                    absolute_path=str(file_path_obj.absolute()),
                )
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"LDIF file not found: {file_path_obj}",
                )

            # File size and accessibility checks
            try:
                file_stat = file_path_obj.stat()
                file_size = file_stat.st_size

                # Check file size limits
                max_size_mb = self._config.ldif_max_file_size_mb or 100
                max_size_bytes = max_size_mb * 1024 * 1024

                if file_size > max_size_bytes:
                    self._logger.error(
                        "parse_file_too_large",
                        file_path=str(file_path_obj),
                        file_size=file_size,
                        max_size_bytes=max_size_bytes,
                    )
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"File too large: {file_size} bytes, limit: {max_size_bytes} bytes"
                    )

                self._logger.info(
                    "parse_file_started",
                    file_path=str(file_path_obj),
                    file_size=file_size,
                    has_dispatcher=self._api._dispatcher is not None,
                )

            except OSError as e:
                self._logger.exception(
                    "parse_file_stat_error",
                    file_path=str(file_path_obj),
                    error=str(e),
                )
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Cannot access file: {e}"
                )

            # Try dispatcher path first
            if self._api._dispatcher is not None:
                dispatch_result = self._api._dispatch_command(
                    FlextLdifModels.ParseFileCommand(file_path=str(file_path_obj)),
                )
                if dispatch_result.is_success:
                    elapsed = time.time() - start_time
                    self._api._operation_count += 1
                    self._logger.info(
                        "parse_file_dispatcher_success",
                        file_path=str(file_path_obj),
                        file_size=file_size,
                        elapsed_ms=elapsed,
                        operation_count=self._api._operation_count,
                    )
                    return dispatch_result

                self._logger.warning(
                    "dispatcher_parse_file_failed",
                    error=dispatch_result.error,
                    file=str(file_path_obj),
                    fallback_to_direct=True,
                )

            # Fallback to direct service
            try:
                result = self._api._services.parser.parse_file(str(file_path_obj))
                if result.is_failure:
                    elapsed = time.time() - start_time
                    self._logger.error(
                        "parse_file_service_failed",
                        file_path=str(file_path_obj),
                        error=result.error,
                        elapsed_ms=elapsed,
                    )
                    return result

                # Validate and track success
                validated_result = result.flat_map(self._validate_entry_count)
                if validated_result.is_success:
                    entries = validated_result.unwrap()
                    elapsed = time.time() - start_time
                    self._api._operation_count += 1
                    self._api._total_entries_processed += len(entries)

                    self._logger.info(
                        "parse_file_success",
                        file_path=str(file_path_obj),
                        entries_count=len(entries),
                        file_size=file_size,
                        elapsed_ms=elapsed,
                        total_entries_processed=self._api._total_entries_processed,
                    )

                return validated_result

            except Exception as exc:
                elapsed = time.time() - start_time
                self._logger.exception(
                    "parse_file_unexpected_error",
                    file_path=str(file_path_obj),
                    error=str(exc),
                    error_type=type(exc).__name__,
                    elapsed_ms=elapsed,
                )
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Parse file operation failed: {exc}"
                )

        def write_string(
            self, entries: list[FlextLdifModels.Entry]
        ) -> FlextResult[str]:
            """Write entries to LDIF string format."""
            if not entries:
                return FlextResult[str].fail("Cannot write empty entry list")

            if self._api._dispatcher is not None:
                dispatch_result = self._api._dispatch_command(
                    FlextLdifModels.WriteStringCommand(entries=entries),
                )
                if dispatch_result.is_success:
                    return dispatch_result

                self._logger.warning(
                    "dispatcher_write_string_failed",
                    error=dispatch_result.error,
                )

            return self._api._services.writer.write_entries_to_string(entries)

        def write_file(
            self, entries: list[FlextLdifModels.Entry], file_path: str | Path
        ) -> FlextResult[bool]:
            """Write entries to LDIF file with validation."""
            if not entries:
                return FlextResult[bool].fail("Cannot write empty entry list")

            if self._api._dispatcher is not None:
                dispatch_result = self._api._dispatch_command(
                    FlextLdifModels.WriteFileCommand(
                        entries=entries, file_path=str(file_path)
                    ),
                )
                if dispatch_result.is_success:
                    return dispatch_result

                self._logger.warning(
                    "dispatcher_write_file_failed",
                    error=dispatch_result.error,
                    file=str(file_path),
                )

            write_result = self._api._services.writer.write_entries_to_file(
                entries, str(file_path)
            )
            if write_result.is_success:
                self._logger.debug(f"Wrote {len(entries)} entries to {file_path}")
                return FlextResult[bool].ok(data=True)
            # Handle possible None error with proper fallback message
            error_msg = (
                write_result.error or "Write operation failed with unknown error"
            )
            return FlextResult[bool].fail(error_msg)

        def validate_entries(
            self, entries: list[FlextLdifModels.Entry]
        ) -> FlextResult[bool]:
            """Validate multiple LDIF entries."""
            if not entries:
                return FlextResult[bool].fail("Cannot validate empty entry list")

            if self._api._dispatcher is not None:
                dispatch_result = self._api._dispatch_command(
                    FlextLdifModels.ValidateEntriesCommand(entries=entries),
                )
                if dispatch_result.is_success:
                    return dispatch_result

                self._logger.warning(
                    "dispatcher_validate_entries_failed",
                    error=dispatch_result.error,
                )

            validation_result = (
                FlextResult[list[FlextLdifModels.Entry]]
                .ok(entries)
                .flat_map(self._validate_entry_count)
                .flat_map(self._api._services.validator.validate_entries)
            )

            if validation_result.is_success:
                self._logger.debug(f"Validated {len(entries)} entries")
                return FlextResult[bool].ok(data=True)
            # Handle possible None error with proper fallback message
            error_msg = (
                validation_result.error or "Validation failed with unknown error"
            )
            return FlextResult[bool].fail(error_msg)

        def _validate_entry_count(
            self, entries: list[FlextLdifModels.Entry]
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Validate entry count against configuration limits."""
            max_entries = self._config.ldif_max_entries
            if max_entries is not None and len(entries) > max_entries:
                error_msg = f"Entry count exceeded: {len(entries)} entries, limit is {max_entries}"
                return FlextResult[list[FlextLdifModels.Entry]].fail(error_msg)
            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

    class Filters:
        """Nested filters handler for entry filtering operations."""

        def __init__(self, api_instance: FlextLdifAPI) -> None:
            """Initialize with parent API reference."""
            self._api = api_instance
            self._logger = api_instance._logger

        def by_object_class(
            self, entries: list[FlextLdifModels.Entry], object_class: str
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Filter entries by objectClass attribute."""
            return self._api._services.repository.filter_entries_by_object_class(
                entries, object_class
            )

        def by_attribute(
            self, entries: list[FlextLdifModels.Entry], attribute: str, value: str
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Filter entries by specific attribute value."""
            return self._api._services.repository.filter_entries_by_attribute(
                entries, attribute, value
            )

        def persons(
            self, entries: list[FlextLdifModels.Entry]
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Filter person entries."""
            filtered = [entry for entry in entries if entry.is_person_entry()]
            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)

        def groups(
            self, entries: list[FlextLdifModels.Entry]
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Filter group entries."""
            filtered = [entry for entry in entries if entry.is_group_entry()]
            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)

        def organizational_units(
            self, entries: list[FlextLdifModels.Entry]
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Filter organizational unit entries."""
            filtered = [
                entry
                for entry in entries
                if "organizationalunit"
                in (
                    oc.lower()
                    for oc in (
                        entry.get_attribute(FlextLdifConstants.OBJECTCLASS_ATTRIBUTE)
                        or []
                    )
                )
            ]
            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)

        def valid_entries(
            self, entries: list[FlextLdifModels.Entry]
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Filter only valid entries."""
            filtered = []
            for entry in entries:
                validation_result = (
                    self._api._services.validator.validate_entry_structure(entry)
                )
                if validation_result.is_success and validation_result.unwrap():
                    filtered.append(entry)
            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)

    class Analytics:
        """Nested analytics handler for LDIF analysis operations."""

        def __init__(self, api_instance: FlextLdifAPI) -> None:
            """Initialize with parent API reference."""
            self._api = api_instance
            self._logger = api_instance._logger

        def entry_patterns(
            self, entries: list[FlextLdifModels.Entry]
        ) -> FlextResult[dict[str, int]]:
            """Analyze patterns in LDIF entries."""
            return self._api._services.analytics.analyze_patterns(entries)

        def object_class_distribution(
            self, entries: list[FlextLdifModels.Entry]
        ) -> FlextResult[dict[str, int]]:
            """Get distribution of objectClass types."""
            return self._api._services.analytics.get_objectclass_distribution(entries)

        def dn_depth_analysis(
            self, entries: list[FlextLdifModels.Entry]
        ) -> FlextResult[dict[str, int]]:
            """Analyze DN depth distribution."""
            return self._api._services.analytics.get_dn_depth_analysis(entries)

        def entry_statistics(
            self, entries: list[FlextLdifModels.Entry]
        ) -> FlextResult[dict[str, int]]:
            """Get comprehensive entry statistics."""
            return self._api._services.repository.get_statistics(entries)

    class Builder:
        """Fluent API builder for enhanced usability and method chaining."""

        def __init__(self, api_instance: FlextLdifAPI) -> None:
            """Initialize builder with parent API reference."""
            self._api = api_instance
            self._logger = api_instance._logger
            self._entries: list[FlextLdifModels.Entry] = []
            self._filters_applied: list[str] = []
            self._validations_run: bool = False

        def from_file(self, file_path: str | Path) -> FlextLdifAPI.Builder:
            """Load entries from LDIF file with fluent interface."""
            result = self._api._operations.parse_file(file_path)
            if result.is_success:
                self._entries = result.unwrap()
                self._logger.debug(
                    "builder_loaded_from_file",
                    file_path=str(file_path),
                    entries_count=len(self._entries),
                )
            else:
                self._logger.error(
                    "builder_load_from_file_failed",
                    file_path=str(file_path),
                    error=result.error,
                )
                # For builder pattern, we store empty list and continue
                self._entries = []
            return self

        def from_string(self, content: str) -> FlextLdifAPI.Builder:
            """Load entries from LDIF string with fluent interface."""
            result = self._api._operations.parse_string(content)
            if result.is_success:
                self._entries = result.unwrap()
                self._logger.debug(
                    "builder_loaded_from_string",
                    content_size=len(content),
                    entries_count=len(self._entries),
                )
            else:
                self._logger.error(
                    "builder_load_from_string_failed",
                    content_size=len(content),
                    error=result.error,
                )
                self._entries = []
            return self

        def filter_persons(self) -> FlextLdifAPI.Builder:
            """Filter person entries with fluent interface."""
            if self._entries:
                result = self._api._filters.persons(self._entries)
                if result.is_success:
                    self._entries = result.unwrap()
                    self._filters_applied.append("persons")
                    self._logger.debug(
                        "builder_filter_applied",
                        filter_type="persons",
                        remaining_entries=len(self._entries),
                    )
            return self

        def filter_groups(self) -> FlextLdifAPI.Builder:
            """Filter group entries with fluent interface."""
            if self._entries:
                result = self._api._filters.groups(self._entries)
                if result.is_success:
                    self._entries = result.unwrap()
                    self._filters_applied.append("groups")
                    self._logger.debug(
                        "builder_filter_applied",
                        filter_type="groups",
                        remaining_entries=len(self._entries),
                    )
            return self

        def filter_by_objectclass(self, object_class: str) -> FlextLdifAPI.Builder:
            """Filter by objectClass with fluent interface."""
            if self._entries:
                result = self._api._filters.by_object_class(self._entries, object_class)
                if result.is_success:
                    self._entries = result.unwrap()
                    self._filters_applied.append(f"objectclass:{object_class}")
                    self._logger.debug(
                        "builder_filter_applied",
                        filter_type="objectclass",
                        object_class=object_class,
                        remaining_entries=len(self._entries),
                    )
            return self

        def validate(self) -> FlextLdifAPI.Builder:
            """Validate current entries with fluent interface."""
            if self._entries:
                result = self._api._operations.validate_entries(self._entries)
                self._validations_run = True
                if result.is_success:
                    self._logger.debug(
                        "builder_validation_success",
                        entries_count=len(self._entries),
                    )
                else:
                    self._logger.warning(
                        "builder_validation_failed",
                        entries_count=len(self._entries),
                        error=result.error,
                    )
            return self

        def sort_hierarchically(self) -> FlextLdifAPI.Builder:
            """Sort entries hierarchically with fluent interface."""
            if self._entries:
                result = self._api.sort_hierarchically(self._entries)
                if result.is_success:
                    self._entries = result.unwrap()
                    self._logger.debug(
                        "builder_sort_applied",
                        sort_type="hierarchical",
                        entries_count=len(self._entries),
                    )
            return self

        def get_entries(self) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Get processed entries from builder."""
            self._logger.info(
                "builder_get_entries",
                entries_count=len(self._entries),
                filters_applied=self._filters_applied,
                validations_run=self._validations_run,
            )
            return FlextResult[list[FlextLdifModels.Entry]].ok(self._entries)

        def to_string(self) -> FlextResult[str]:
            """Convert entries to LDIF string with builder pattern."""
            if not self._entries:
                return FlextResult[str].fail("No entries to write")

            result = self._api._operations.write_string(self._entries)
            if result.is_success:
                self._logger.info(
                    "builder_to_string_success",
                    entries_count=len(self._entries),
                    filters_applied=self._filters_applied,
                )
            return result

        def to_file(self, file_path: str | Path) -> FlextResult[bool]:
            """Write entries to file with builder pattern."""
            if not self._entries:
                return FlextResult[bool].fail("No entries to write")

            result = self._api._operations.write_file(self._entries, file_path)
            if result.is_success:
                self._logger.info(
                    "builder_to_file_success",
                    file_path=str(file_path),
                    entries_count=len(self._entries),
                    filters_applied=self._filters_applied,
                )
            return result

        def analyze(self) -> FlextResult[dict[str, int]]:
            """Analyze current entries with builder pattern."""
            if not self._entries:
                return FlextResult[dict[str, int]].fail("No entries to analyze")

            result = self._api._analytics.entry_statistics(self._entries)
            if result.is_success:
                self._logger.info(
                    "builder_analyze_success",
                    entries_count=len(self._entries),
                    filters_applied=self._filters_applied,
                )
            return result

        def count(self) -> int:
            """Get current entry count."""
            return len(self._entries)

        def is_empty(self) -> bool:
            """Check if builder has entries."""
            return len(self._entries) == 0

        def reset(self) -> FlextLdifAPI.Builder:
            """Reset builder to initial state."""
            self._entries = []
            self._filters_applied = []
            self._validations_run = False
            self._logger.debug("builder_reset")
            return self

    def _initialize_services(self) -> FlextLdifAPI.ServiceContainer:
        """Initialize and configure all LDIF services."""
        self._container.register("ldif_config", self._config)

        # Create unified services instance
        services = FlextLdifServices(config=self._config)

        # Register in container for DI
        self._container.register("ldif_services", services)

        # Services are always initialized in FlextLdifServices.__init__
        # No need to check for None values

        # Services are always initialized in FlextLdifServices.__init__
        # Check services are properly initialized instead of using assert
        services_not_initialized_msg = "Services not properly initialized"
        if (
            services.parser is None
            or services.validator is None
            or services.writer is None
            or services.repository is None
            or services.analytics is None
        ):
            raise ValueError(services_not_initialized_msg)

        return self.ServiceContainer(
            parser=services.parser,
            validator=services.validator,
            writer=services.writer,
            repository=services.repository,
            analytics=services.analytics,
        )

    class ServiceContainer:
        """Nested container for service instances."""

        def __init__(
            self,
            parser: FlextLdifParserService,
            validator: FlextLdifValidatorService,
            writer: FlextLdifWriterService,
            repository: FlextLdifRepositoryService,
            analytics: FlextLdifAnalyticsService,
        ) -> None:
            """Initialize service container with parser, validator, writer, repository, and analytics."""
            self.parser = parser
            self.validator = validator
            self.writer = writer
            self.repository = repository
            self.analytics = analytics

    def discover_ldif_files(
        self,
        directory_path: str | Path | None = None,
        file_pattern: str = "*.ldif",
        file_path: str | Path | None = None,
        max_file_size_mb: int | None = None,
    ) -> FlextResult[list[Path]]:
        """Discover LDIF files using railway-oriented programming."""
        # Use config default if not provided
        if max_file_size_mb is None:
            max_file_size_mb = self._config.ldif_max_file_size_mb

        return (
            self._get_files_to_process(directory_path, file_pattern, file_path)
            .flat_map(
                lambda files: self._process_and_filter_files(files, max_file_size_mb)
            )
            .tap(
                lambda files: self._logger.debug(f"Discovered {len(files)} LDIF files")
            )
        )

    def _process_and_filter_files(
        self, files_to_process: list[Path], max_file_size_mb: int
    ) -> FlextResult[list[Path]]:
        """Filter and sort discovered files."""
        filtered_files = self._filter_files_by_size(files_to_process, max_file_size_mb)
        sorted_files = sorted(filtered_files)

        self._logger.debug(
            f"File discovery completed - found: {len(sorted_files)}, skipped: {len(files_to_process) - len(filtered_files)}",
        )
        return FlextResult[list[Path]].ok(sorted_files)

    def filter_change_records(
        self, entries: list[FlextLdifModels.Entry] | None
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries that represent change records."""
        if entries is None:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "Entries cannot be None",
            )
        filtered = [entry for entry in entries if entry.get_attribute("changetype")]
        return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)

    def sort_hierarchically(
        self, entries: list[FlextLdifModels.Entry] | None
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort entries hierarchically by DN depth."""
        if entries is None:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "Entries cannot be None",
            )

        def sort_by_dn_depth(entry: FlextLdifModels.Entry) -> int:
            """Calculate DN depth for sorting."""
            return len(entry.dn.value.split(","))

        try:
            sorted_entries = sorted(entries, key=sort_by_dn_depth)
            return FlextResult[list[FlextLdifModels.Entry]].ok(sorted_entries)
        except (ValueError, AttributeError, TypeError) as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Sort operation failed: {e!s}",
            )

    def _get_files_to_process(
        self,
        directory_path: str | Path | None,
        file_pattern: str,
        file_path: str | Path | None,
    ) -> FlextResult[list[Path]]:
        """Get initial list of files to process based on input parameters."""
        if file_path:
            return self._process_single_file_path(file_path)
        if directory_path:
            return self._process_directory_path(directory_path, file_pattern)
        return self._process_current_directory_pattern(file_pattern)

    def _process_single_file_path(
        self,
        file_path: str | Path,
    ) -> FlextResult[list[Path]]:
        """Process single file path input."""
        file_path_obj = Path(file_path)
        if file_path_obj.exists() and file_path_obj.is_file():
            return FlextResult.ok([file_path_obj])
        return FlextResult.fail(
            f"File not found: {file_path}",
        )

    def _process_directory_path(
        self,
        directory_path: str | Path,
        file_pattern: str,
    ) -> FlextResult[list[Path]]:
        """Process directory path with pattern."""
        directory_obj = Path(directory_path)
        if not directory_obj.exists():
            return FlextResult.fail(
                f"Directory not found: {directory_path}",
            )
        if not directory_obj.is_dir():
            return FlextResult.fail(f"Path is not a directory: {directory_path}")

        try:
            files_found = list(directory_obj.glob(file_pattern))
            return FlextResult.ok(files_found)
        except (OSError, ValueError) as e:
            return FlextResult.fail(f"Error discovering files in directory: {e}")

    def _process_current_directory_pattern(
        self,
        file_pattern: str,
    ) -> FlextResult[list[Path]]:
        """Process pattern in current directory."""
        try:
            files_found = list(Path().glob(file_pattern))
            return FlextResult.ok(files_found)
        except (OSError, ValueError) as e:
            return FlextResult.fail(f"Error discovering files with pattern: {e}")

    def _filter_files_by_size(
        self,
        files_to_process: list[Path],
        max_file_size_mb: int,
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
                        "Skipping file - size exceeds limit - file_path=%s, file_size=%s, max_size=%s",
                        str(file_path_item),
                        file_path_item.stat().st_size,
                        max_size_bytes,
                    )
            except OSError as e:
                self._logger.warning(
                    "Could not check file size - file_path=%s, error=%s",
                    str(file_path_item),
                    str(e),
                )
                continue

        return filtered_files

    # Core API methods - direct access to operations
    def parse_file(
        self, file_path: str | Path
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF file."""
        return self._operations.parse_file(file_path)

    def parse_string(self, content: str) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF string."""
        return self._operations.parse_string(content)

    def validate_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[bool]:
        """Validate entries."""
        return self._operations.validate_entries(entries)

    def write_file(
        self,
        entries: list[FlextLdifModels.Entry],
        file_path: str | Path,
        *,
        _encoding: str = "utf-8",
    ) -> FlextResult[bool]:
        """Write LDIF file."""
        return self._operations.write_file(entries, file_path)

    def get_entry_statistics(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, int]]:
        """Get entry statistics."""
        return self._analytics.entry_statistics(entries)

    def filter_persons(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter person entries."""
        return self._filters.persons(entries)

    def find_entry_by_dn(
        self, entries: list[FlextLdifModels.Entry], dn: str
    ) -> FlextResult[FlextLdifModels.Entry | None]:
        """Find entry by DN."""
        for entry in entries:
            if entry.dn.value == dn:
                return FlextResult[FlextLdifModels.Entry | None].ok(entry)
        return FlextResult[FlextLdifModels.Entry | None].ok(None)

    # Convenience methods for direct API access
    def parse(self, content: str) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF content - convenience method."""
        return self.parse_string(content)

    def validate(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[bool]:
        """Validate entries - convenience method."""
        return self.validate_entries(entries)

    def write(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[str]:
        """Write entries to string - convenience method."""
        return self._operations.write_string(entries)

    def analyze(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, int]]:
        """Analyze entries - convenience method."""
        return self._analytics.entry_statistics(entries)

    def filter_by_objectclass(
        self, entries: list[FlextLdifModels.Entry], object_class: str
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter by objectClass - convenience method."""
        return self._filters.by_object_class(entries, object_class)

    def filter_groups(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter groups - convenience method."""
        return self._filters.groups(entries)

    def filter_organizational_units(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter organizational units - convenience method."""
        return self._filters.organizational_units(entries)

    def filter_valid(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter valid entries - convenience method."""
        return self._filters.valid_entries(entries)

    # Enhanced API Methods with Builder Pattern Integration
    def builder(self) -> FlextLdifAPI.Builder:
        """Create a new fluent API builder instance.

        Returns:
            FlextLdifAPI.Builder instance for method chaining

        Example:
            ```python
            api = FlextLdifAPI()

            # Fluent API usage
            result = (
                api.builder()
                .from_file("data.ldif")
                .filter_persons()
                .validate()
                .sort_hierarchically()
                .to_string()
            )
            ```

        """
        return self.Builder(self)

    def get_performance_metrics(self) -> dict[str, object]:
        """Get comprehensive performance metrics for the API instance.

        Returns:
            Dictionary containing performance statistics

        """
        current_time = time.time()
        uptime = current_time - self._start_time

        metrics = {
            "uptime_ms": uptime,
            "operation_count": self._operation_count,
            "total_entries_processed": self._total_entries_processed,
            "dispatcher_enabled": self._dispatcher is not None,
            "dispatcher_failures": self._dispatcher_failures,
            "config_sealed": self._config.is_sealed(),
            "avg_entries_per_operation": (
                self._total_entries_processed / max(self._operation_count, 1)
            ),
            "operations_per_second": (self._operation_count / max(uptime / 1000.0, 1.0))
            if uptime > 0
            else 0.0,
        }

        self._logger.debug("performance_metrics_requested", **metrics)

        return metrics

    def reset_performance_metrics(self) -> None:
        """Reset performance tracking metrics."""
        self._start_time = time.time()
        self._operation_count = 0
        self._total_entries_processed = 0
        self._dispatcher_failures = 0

        self._logger.info("performance_metrics_reset")

    def health_check(self) -> FlextResult[dict[str, object]]:
        """Perform comprehensive health check of the API and its services.

        Returns:
            FlextResult containing health status information

        """
        health_status = {
            "api_healthy": True,
            "services_initialized": self._services is not None,
            "dispatcher_healthy": self._dispatcher is not None
            and self._dispatcher_failures < self._max_dispatcher_failures,
            "config_valid": True,
            "performance_metrics": self.get_performance_metrics(),
        }

        # Test basic service functionality
        try:
            # Test with minimal LDIF content
            test_content = (
                "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test"
            )
            test_result = self.parse_string(test_content)
            health_status["parser_healthy"] = test_result.is_success

            if test_result.is_success:
                entries = test_result.unwrap()
                validation_result = self.validate_entries(entries)
                health_status["validator_healthy"] = validation_result.is_success

                if validation_result.is_success:
                    write_result = self.write(entries)
                    health_status["writer_healthy"] = write_result.is_success

        except Exception as exc:
            health_status["api_healthy"] = False
            health_status["health_check_error"] = str(exc)
            self._logger.exception(
                "health_check_failed",
                error=str(exc),
                error_type=type(exc).__name__,
            )

        # Overall health determination
        overall_healthy = all(
            [
                health_status.get("api_healthy", False),
                health_status.get("services_initialized", False),
                health_status.get("parser_healthy", False),
                health_status.get("validator_healthy", False),
                health_status.get("writer_healthy", False),
            ]
        )

        health_status["overall_healthy"] = overall_healthy

        self._logger.info(
            "health_check_completed",
            overall_healthy=overall_healthy,
            dispatcher_healthy=health_status["dispatcher_healthy"],
        )

        if overall_healthy:
            return FlextResult[dict[str, object]].ok(health_status)
        return FlextResult[dict[str, object]].fail(
            f"Health check failed: {health_status}"
        )


__all__ = [
    "FlextLdifAPI",
]
