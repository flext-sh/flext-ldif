"""FLEXT LDIF API - Unified LDIF processing API.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from flext_core import (
    FlextContainer,
    FlextLogger,
    FlextResult,
)

from flext_ldif.analytics_service import FlextLDIFAnalyticsService
from flext_ldif.models import FlextLDIFModels
from flext_ldif.parser_service import FlextLDIFParserService
from flext_ldif.repository_service import FlextLDIFRepositoryService
from flext_ldif.services import FlextLDIFServices
from flext_ldif.validator_service import FlextLDIFValidatorService
from flext_ldif.writer_service import FlextLDIFWriterService

# Type aliases for Python 3.13+ generic syntax
if TYPE_CHECKING:
    type FlextResultEntries = FlextResult[list[FlextLDIFModels.Entry]]
    type FlextResultStr = FlextResult[str]
    type FlextResultBool = FlextResult[bool]
    type FlextResultDict = FlextResult[dict[str, int]]
else:
    FlextResultEntries = FlextResult
    FlextResultStr = FlextResult
    FlextResultBool = FlextResult
    FlextResultDict = FlextResult


class FlextLDIFAPI:
    """Unified LDIF Processing API.

    Enterprise-grade LDIF operations with railway-oriented programming,
    dependency injection, and comprehensive error handling. Follows unified
    class architecture with nested operation handlers.
    """

    def __init__(self, config: FlextLDIFModels.Config | None = None) -> None:
        """Initialize unified LDIF API with dependency injection.

        Args:
            config: Optional LDIF processing configuration

        """
        # Initialize as simple class without abstract inheritance
        self._logger = FlextLogger(__name__)
        self._container = FlextContainer.get_global()
        self._config = config or FlextLDIFModels.Config()

        # Initialize nested operation handlers
        self._operations = self.Operations(self)
        self._filters = self.Filters(self)
        self._analytics = self.Analytics(self)

        # Initialize services with proper dependency injection
        self._services = self._initialize_services()

    class Operations:
        """Nested operations handler for core LDIF processing."""

        def __init__(self, api_instance: FlextLDIFAPI) -> None:
            """Initialize with parent API reference."""
            self._api = api_instance
            self._logger = api_instance._logger
            self._config = api_instance._config

        def parse_string(self, content: str) -> FlextResultEntries:
            """Parse LDIF content using railway-oriented programming."""
            if not content.strip():
                # Return empty list for empty content - valid LDIF case
                return FlextResult[list[FlextLDIFModels.Entry]].ok([])

            result = self._api._services.parser.parse_content(content)
            if result.is_failure:
                return result
            return result.flat_map(self._validate_entry_count)

        def parse_file(self, file_path: str | Path) -> FlextResultEntries:
            """Parse LDIF file with comprehensive validation."""
            file_path_obj = Path(file_path)

            if not file_path_obj.exists():
                return FlextResult[list[FlextLDIFModels.Entry]].fail(
                    f"LDIF file not found: {file_path_obj}",
                )

            result = self._api._services.parser.parse_ldif_file(str(file_path_obj))
            if result.is_failure:
                return result
            return result.flat_map(self._validate_entry_count)

        def write_string(self, entries: list[FlextLDIFModels.Entry]) -> FlextResultStr:
            """Write entries to LDIF string format."""
            if not entries:
                return FlextResult[str].fail("Cannot write empty entry list")

            return self._api._services.writer.write_entries_to_string(entries)

        def write_file(
            self, entries: list[FlextLDIFModels.Entry], file_path: str | Path
        ) -> FlextResultBool:
            """Write entries to LDIF file with validation."""
            if not entries:
                return FlextResult[bool].fail("Cannot write empty entry list")

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
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResultBool:
            """Validate multiple LDIF entries."""
            if not entries:
                return FlextResult[bool].fail("Cannot validate empty entry list")

            validation_result = (
                FlextResult[list[FlextLDIFModels.Entry]]
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
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResultEntries:
            """Validate entry count against configuration limits."""
            max_entries = self._config.max_entries
            if max_entries is not None and len(entries) > max_entries:
                error_msg = f"Entry count exceeded: {len(entries)} entries, limit is {max_entries}"
                return FlextResult[list[FlextLDIFModels.Entry]].fail(error_msg)
            return FlextResult[list[FlextLDIFModels.Entry]].ok(entries)

    class Filters:
        """Nested filters handler for entry filtering operations."""

        def __init__(self, api_instance: FlextLDIFAPI) -> None:
            """Initialize with parent API reference."""
            self._api = api_instance
            self._logger = api_instance._logger

        def by_object_class(
            self, entries: list[FlextLDIFModels.Entry], object_class: str
        ) -> FlextResultEntries:
            """Filter entries by objectClass attribute."""
            return self._api._services.repository.filter_entries_by_object_class(
                entries, object_class
            )

        def by_attribute(
            self, entries: list[FlextLDIFModels.Entry], attribute: str, value: str
        ) -> FlextResultEntries:
            """Filter entries by specific attribute value."""
            return self._api._services.repository.filter_entries_by_attribute(
                entries, attribute, value
            )

        def persons(self, entries: list[FlextLDIFModels.Entry]) -> FlextResultEntries:
            """Filter person entries."""
            filtered = [entry for entry in entries if entry.is_person()]
            return FlextResult[list[FlextLDIFModels.Entry]].ok(filtered)

        def groups(self, entries: list[FlextLDIFModels.Entry]) -> FlextResultEntries:
            """Filter group entries."""
            filtered = [entry for entry in entries if entry.is_group()]
            return FlextResult[list[FlextLDIFModels.Entry]].ok(filtered)

        def organizational_units(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResultEntries:
            """Filter organizational unit entries."""
            filtered = [
                entry
                for entry in entries
                if "organizationalunit"
                in (oc.lower() for oc in (entry.get_attribute("objectClass") or []))
            ]
            return FlextResult[list[FlextLDIFModels.Entry]].ok(filtered)

        def valid_entries(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResultEntries:
            """Filter only valid entries."""
            filtered = []
            for entry in entries:
                validation_result = (
                    self._api._services.validator.validate_entry_structure(entry)
                )
                if validation_result.is_success and validation_result.unwrap():
                    filtered.append(entry)
            return FlextResult[list[FlextLDIFModels.Entry]].ok(filtered)

    class Analytics:
        """Nested analytics handler for LDIF analysis operations."""

        def __init__(self, api_instance: FlextLDIFAPI) -> None:
            """Initialize with parent API reference."""
            self._api = api_instance
            self._logger = api_instance._logger

        def entry_patterns(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResultDict:
            """Analyze patterns in LDIF entries."""
            return self._api._services.analytics.analyze_patterns(entries)

        def object_class_distribution(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResultDict:
            """Get distribution of objectClass types."""
            return self._api._services.analytics.get_objectclass_distribution(entries)

        def dn_depth_analysis(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResultDict:
            """Analyze DN depth distribution."""
            return self._api._services.analytics.get_dn_depth_analysis(entries)

        def entry_statistics(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResultDict:
            """Get comprehensive entry statistics."""
            return self._api._services.repository.get_statistics(entries)

    def _initialize_services(self) -> FlextLDIFAPI.ServiceContainer:
        """Initialize and configure all LDIF services."""
        self._container.register("ldif_config", self._config)

        # Create unified services instance
        services = FlextLDIFServices(config=self._config)

        # Register in container for DI
        self._container.register("ldif_services", services)

        # Services are always initialized in FlextLDIFServices.__init__
        # No need to check for None values

        # Services are always initialized in FlextLDIFServices.__init__
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
            parser: FlextLDIFParserService,
            validator: FlextLDIFValidatorService,
            writer: FlextLDIFWriterService,
            repository: FlextLDIFRepositoryService,
            analytics: FlextLDIFAnalyticsService,
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
        max_file_size_mb: int = 100,
    ) -> FlextResult[list[Path]]:
        """Discover LDIF files using railway-oriented programming."""
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
        self, entries: list[FlextLDIFModels.Entry] | None
    ) -> FlextResultEntries:
        """Filter entries that represent change records."""
        if entries is None:
            return FlextResult[list[FlextLDIFModels.Entry]].fail(
                "Entries cannot be None",
            )
        filtered = [entry for entry in entries if entry.get_attribute("changetype")]
        return FlextResult[list[FlextLDIFModels.Entry]].ok(filtered)

    def sort_hierarchically(
        self, entries: list[FlextLDIFModels.Entry] | None
    ) -> FlextResultEntries:
        """Sort entries hierarchically by DN depth."""
        if entries is None:
            return FlextResult[list[FlextLDIFModels.Entry]].fail(
                "Entries cannot be None",
            )

        def sort_by_dn_depth(entry: FlextLDIFModels.Entry) -> int:
            """Calculate DN depth for sorting."""
            return len(entry.dn.value.split(","))

        try:
            sorted_entries = sorted(entries, key=sort_by_dn_depth)
            return FlextResult[list[FlextLDIFModels.Entry]].ok(sorted_entries)
        except (ValueError, AttributeError, TypeError) as e:
            return FlextResult[list[FlextLDIFModels.Entry]].fail(
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


__all__ = [
    "FlextLDIFAPI",
]
