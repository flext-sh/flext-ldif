"""FLEXT-LDIF API.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path
from typing import cast

from flext_core import FlextLogger, FlextResult, get_flext_container

from flext_ldif.constants import FlextLDIFConstants
from flext_ldif.models import FlextLDIFModels
from flext_ldif.services import FlextLDIFServices

logger = FlextLogger(__name__)


class FlextLDIFAPI:
    """LDIF processing API."""

    def __init__(self, config: FlextLDIFModels.Config | None = None) -> None:
        """Initialize API with FlextContainer dependency injection.

        Args:
            config: Optional configuration object.

        """
        self.config = config or FlextLDIFModels.Config()
        self._container = get_flext_container()

        # Register services in container for dependency injection
        self._container.register("ldif_config", self.config)
        self._container.register("ldif_parser", FlextLDIFServices.ParserService())
        self._container.register("ldif_validator", FlextLDIFServices.ValidatorService())
        self._container.register("ldif_writer", FlextLDIFServices.WriterService())
        self._container.register(
            "ldif_repository", FlextLDIFServices.RepositoryService()
        )
        self._container.register("ldif_analytics", FlextLDIFServices.AnalyticsService())

        # Get services from container (enables dependency injection)
        parser_result = self._container.get("ldif_parser")
        validator_result = self._container.get("ldif_validator")
        writer_result = self._container.get("ldif_writer")
        repository_result = self._container.get("ldif_repository")
        analytics_result = self._container.get("ldif_analytics")

        # Extract values from FlextResult if needed and cast to proper types
        self._parser_service = cast(
            "FlextLDIFServices.ParserService",
            parser_result.value if hasattr(parser_result, "value") else parser_result,
        )
        self._validator_service = cast(
            "FlextLDIFServices.ValidatorService",
            validator_result.value
            if hasattr(validator_result, "value")
            else validator_result,
        )
        self._writer_service = cast(
            "FlextLDIFServices.WriterService",
            writer_result.value if hasattr(writer_result, "value") else writer_result,
        )
        self._repository_service = cast(
            "FlextLDIFServices.RepositoryService",
            repository_result.value
            if hasattr(repository_result, "value")
            else repository_result,
        )
        self._analytics_service = cast(
            "FlextLDIFServices.AnalyticsService",
            analytics_result.value
            if hasattr(analytics_result, "value")
            else analytics_result,
        )

    def parse(self, content: str) -> FlextResult:  # type: ignore[type-arg]
        """Parse LDIF content using railway-oriented programming."""

        def validate_entry_count(
            entries: list[FlextLDIFModels.Entry],
        ) -> FlextResult:  # type: ignore[type-arg]
            """Validate entry count against configuration limits."""
            max_entries = self.config.max_entries
            if max_entries is not None and len(entries) > max_entries:
                error_msg = FlextLDIFConstants.FlextLDIFValidationMessages.ENTRY_COUNT_EXCEEDED.format(
                    count=len(entries),
                    limit=self.config.max_entries,
                )
                logger.warning(error_msg)
                return FlextResult.fail(error_msg)
            return FlextResult.ok(entries)

        # Railway-oriented programming chain
        return self._parser_service.parse(content).flat_map(validate_entry_count)

    def parse_file(self, file_path: str | Path) -> FlextResult:  # type: ignore[type-arg]
        """Parse LDIF file using railway-oriented programming."""
        file_path_obj = Path(file_path)
        logger.debug(
            "Starting LDIF file parsing - file_path=%s",
            str(file_path_obj.absolute()),
        )

        def validate_file_entry_count(
            entries: list[FlextLDIFModels.Entry],
        ) -> FlextResult:  # type: ignore[type-arg]
            """Validate file entry count against configuration limits."""
            max_entries = self.config.max_entries
            if max_entries is not None and len(entries) > max_entries:
                error_msg = FlextLDIFConstants.FlextLDIFValidationMessages.FILE_ENTRY_COUNT_EXCEEDED.format(
                    count=len(entries),
                    limit=self.config.max_entries,
                )
                logger.warning(error_msg)
                return FlextResult.fail(error_msg)

            logger.debug("File parsed successfully with %d entries", len(entries))
            return FlextResult.ok(entries)

        # Railway-oriented programming chain
        return self._parser_service.parse_ldif_file(str(file_path_obj)).flat_map(
            validate_file_entry_count
        )

    def parse_entries_from_string(
        self,
        ldif_string: str,
    ) -> FlextResult:  # type: ignore[type-arg]
        """Parse multiple entries from LDIF string."""
        return self._parser_service.parse_ldif_content(ldif_string)

    def discover_ldif_files(
        self,
        directory_path: str | Path | None = None,
        file_pattern: str = "*.ldif",
        file_path: str | Path | None = None,
        max_file_size_mb: int = 100,
    ) -> FlextResult:  # type: ignore[type-arg]
        """Discover LDIF files using railway-oriented programming."""

        def process_and_filter_files(
            files_to_process: list[Path],
        ) -> FlextResult:  # type: ignore[type-arg]
            """Filter and sort discovered files."""
            filtered_files = self._filter_files_by_size(
                files_to_process, max_file_size_mb
            )
            sorted_files = sorted(filtered_files)

            logger.debug(
                "LDIF file discovery completed - files_found=%s, files_skipped=%s",
                len(sorted_files),
                len(files_to_process) - len(filtered_files),
            )
            return FlextResult.ok(sorted_files)

        # Railway-oriented programming chain
        return self._get_files_to_process(
            directory_path,
            file_pattern,
            file_path,
        ).flat_map(process_and_filter_files)

    def write(
        self,
        entries: list[FlextLDIFModels.Entry],
        file_path: str | None = None,
    ) -> FlextResult:  # type: ignore[type-arg]
        """Write entries to LDIF format using railway-oriented programming.

        Args:
            entries: List of entries to serialize.
            file_path: Optional file path for output.

        Returns:
            FlextResult containing LDIF string or error.

        """
        logger.debug("Preparing to write LDIF output")

        if file_path:
            # Railway pattern for file writing
            return (
                self._writer_service.write_entries_to_file(entries, file_path)
                .map(
                    lambda _: FlextLDIFConstants.FlextLDIFOperationMessages.WRITE_SUCCESS.format(
                        path=file_path
                    )
                )
                .or_else(
                    FlextResult.fail(
                        FlextLDIFConstants.FlextLDIFOperationMessages.WRITE_FAILED.format(
                            error="File write failed",
                        )
                    )
                )
            )

        # Railway pattern for string writing
        return self._writer_service.write_entries_to_string(entries).tap(
            lambda content: logger.debug(
                "LDIF string writing completed - content_length=%s",
                len(content),
            )
        )

    def entries_to_ldif(self, entries: list[FlextLDIFModels.Entry]) -> FlextResult:  # type: ignore[type-arg]
        """Convert entries to LDIF string format.

        Args:
            entries: List of entries to convert.

        Returns:
            FlextResult containing LDIF string or error.

        """
        return self._writer_service.write_entries_to_string(entries)

    def write_file(
        self,
        entries: list[FlextLDIFModels.Entry],
        file_path: str | Path,
    ) -> FlextResult:  # type: ignore[type-arg]
        """Write entries to LDIF file.

        Args:
            entries: List of entries to write.
            file_path: Target file path.

        Returns:
            FlextResult containing success status or error.

        """
        logger.debug("Validating %d entries", len(entries))

        # Use railway programming for file writing
        return self._writer_service.write_entries_to_file(entries, str(file_path)).tap(
            lambda _: logger.debug("File write completed successfully")
        )

    def validate(self, entries: list[FlextLDIFModels.Entry]) -> FlextResult:  # type: ignore[type-arg]
        """Validate multiple LDIF entries.

        Args:
            entries: List of entries to validate.

        Returns:
            FlextResult containing validation status or error.

        """
        logger.debug("debug message")

        if (
            self.config.max_entries is not None
            and len(entries) > self.config.max_entries
        ):
            error_msg = FlextLDIFConstants.FlextLDIFValidationMessages.ENTRY_COUNT_EXCEEDED.format(
                count=len(entries),
                limit=self.config.max_entries,
            )
            return FlextResult.fail(error_msg)

        # Use railway programming for validation
        return self._validator_service.validate_entries(entries).tap(
            lambda _: logger.debug("Bulk validation completed successfully")
        )

    def validate_entry(self, entry: FlextLDIFModels.Entry) -> FlextResult:  # type: ignore[type-arg]
        """Validate single LDIF entry.

        Args:
            entry: Entry to validate.

        Returns:
            FlextResult containing validation status or error.

        """
        logger.debug("Validating single entry")

        return self._validator_service.validate_entry_structure(entry)

    def validate_dn_format(self, dn: str) -> FlextResult:  # type: ignore[type-arg]
        """Validate DN format compliance.

        Args:
            dn: Distinguished name to validate.

        Returns:
            FlextResult containing validation status or error.

        """
        return self._validator_service.validate_dn_format(dn)

    def filter_persons(
        self,
        entries: list[FlextLDIFModels.Entry],
    ) -> FlextResult:  # type: ignore[type-arg]
        """Filter person entries.

        Args:
            entries: List of entries to filter.

        Returns:
            FlextResult containing filtered person entries.

        """
        filtered = [entry for entry in entries if entry.is_person()]
        return FlextResult.ok(filtered)

    def filter_groups(
        self,
        entries: list[FlextLDIFModels.Entry],
    ) -> FlextResult:  # type: ignore[type-arg]
        """Filter group entries.

        Args:
            entries: List of entries to filter.

        Returns:
            FlextResult containing filtered group entries.

        """
        filtered = [entry for entry in entries if entry.is_group()]
        return FlextResult.ok(filtered)

    def filter_organizational_units(
        self,
        entries: list[FlextLDIFModels.Entry] | None,
    ) -> FlextResult:  # type: ignore[type-arg]
        """Filter organizational unit entries.

        Args:
            entries: List of entries to filter.

        Returns:
            FlextResult containing filtered OU entries.

        """
        if entries is None:
            return FlextResult.fail(
                FlextLDIFConstants.FlextLDIFValidationMessages.ENTRIES_CANNOT_BE_NONE
            )
        filtered = [
            entry
            for entry in entries
            if "organizationalunit" in (oc.lower() for oc in entry.get_object_classes())
        ]
        return FlextResult.ok(filtered)

    def filter_valid(
        self,
        entries: list[FlextLDIFModels.Entry] | None,
    ) -> FlextResult:  # type: ignore[type-arg]
        """Filter valid entries.

        Args:
            entries: List of entries to filter.

        Returns:
            FlextResult containing valid entries.

        """
        if entries is None:
            return FlextResult.fail(
                FlextLDIFConstants.FlextLDIFValidationMessages.ENTRIES_CANNOT_BE_NONE
            )
        # Use modern FlextResult.safe_unwrap_or_none for safer validation checking
        validation_failed_default = False
        filtered = [
            entry
            for entry in entries
            if FlextResult.safe_unwrap_or_none(self.validate_entry(entry))
            or validation_failed_default
        ]
        return FlextResult.ok(filtered)

    def filter_by_objectclass(
        self,
        entries: list[FlextLDIFModels.Entry],
        objectclass: str,
    ) -> FlextResult:  # type: ignore[type-arg]
        """Filter entries by objectClass.

        Args:
            entries: List of entries to filter.
            objectclass: ObjectClass to filter by.

        Returns:
            FlextResult containing filtered entries.

        """
        return self._repository_service.filter_entries_by_object_class(
            entries, objectclass
        )

    def filter_by_attribute(
        self,
        entries: list[FlextLDIFModels.Entry],
        attribute: str,
        value: str,
    ) -> FlextResult:  # type: ignore[type-arg]
        """Filter entries by attribute value.

        Args:
            entries: List of entries to filter.
            attribute: Attribute name.
            value: Attribute value.

        Returns:
            FlextResult containing filtered entries.

        """
        return self._repository_service.filter_entries_by_attribute(
            entries, attribute, value
        )

    def find_entry_by_dn(
        self,
        entries: list[FlextLDIFModels.Entry],
        dn: str,
    ) -> FlextResult:  # type: ignore[type-arg]
        """Find entry by DN.

        Args:
            entries: List of entries to search.
            dn: Distinguished name to find.

        Returns:
            FlextResult containing found entry or None.

        """
        return self._repository_service.find_entry_by_dn(entries, dn)

    def get_entry_statistics(
        self,
        entries: list[FlextLDIFModels.Entry],
    ) -> FlextResult:  # type: ignore[type-arg]
        """Get entry statistics.

        Args:
            entries: List of entries to analyze.

        Returns:
            FlextResult containing statistics dictionary.

        """
        return self._repository_service.get_statistics(entries)

    def analyze_entry_patterns(
        self,
        entries: list[FlextLDIFModels.Entry],
    ) -> FlextResult:  # type: ignore[type-arg]
        """Analyze patterns in LDIF entries.

        Args:
            entries: List of entries to analyze.

        Returns:
            FlextResult containing pattern analysis.

        """
        return self._analytics_service.analyze_patterns(entries)

    def get_objectclass_distribution(
        self,
        entries: list[FlextLDIFModels.Entry],
    ) -> FlextResult:  # type: ignore[type-arg]
        """Get distribution of objectClass types.

        Args:
            entries: List of entries to analyze.

        Returns:
            FlextResult containing objectClass distribution.

        """
        return self._analytics_service.get_objectclass_distribution(entries)

    def get_dn_depth_analysis(
        self,
        entries: list[FlextLDIFModels.Entry],
    ) -> FlextResult:  # type: ignore[type-arg]
        """Analyze DN depth distribution.

        Args:
            entries: List of entries to analyze.

        Returns:
            FlextResult containing DN depth analysis.

        """
        return self._analytics_service.get_dn_depth_analysis(entries)

    def filter_change_records(
        self,
        entries: list[FlextLDIFModels.Entry] | None,
    ) -> FlextResult:  # type: ignore[type-arg]
        """Filter entries that represent change records.

        Args:
            entries: List of entries to filter.

        Returns:
            FlextResult containing change record entries.

        """
        if entries is None:
            return FlextResult.fail(
                FlextLDIFConstants.FlextLDIFValidationMessages.ENTRIES_CANNOT_BE_NONE
            )
        filtered = [entry for entry in entries if entry.get_attribute("changetype")]
        return FlextResult.ok(filtered)

    def sort_hierarchically(
        self,
        entries: list[FlextLDIFModels.Entry] | None,
    ) -> FlextResult:  # type: ignore[type-arg]
        """Sort entries hierarchically by DN depth.

        Args:
            entries: List of entries to sort.

        Returns:
            FlextResult containing sorted entries.

        """
        if entries is None:
            return FlextResult.fail(
                FlextLDIFConstants.FlextLDIFValidationMessages.ENTRIES_CANNOT_BE_NONE
            )
        try:
            sorted_entries = sorted(
                entries, key=lambda entry: len(entry.dn.value.split(","))
            )
            return FlextResult.ok(sorted_entries)
        except (ValueError, AttributeError, TypeError) as e:
            return FlextResult.fail(
                FlextLDIFConstants.FlextLDIFOperationMessages.SORT_FAILED.format(
                    error=str(e)
                ),
            )

    def _get_files_to_process(
        self,
        directory_path: str | Path | None,
        file_pattern: str,
        file_path: str | Path | None,
    ) -> FlextResult:  # type: ignore[type-arg]
        """Get initial list of files to process based on input parameters."""
        if file_path:
            return self._process_single_file_path(file_path)
        if directory_path:
            return self._process_directory_path(directory_path, file_pattern)
        return self._process_current_directory_pattern(file_pattern)

    def _process_single_file_path(
        self,
        file_path: str | Path,
    ) -> FlextResult:  # type: ignore[type-arg]
        """Process single file path input."""
        file_path_obj = Path(file_path)
        if file_path_obj.exists() and file_path_obj.is_file():
            return FlextResult.ok([file_path_obj])
        return FlextResult.fail(
            FlextLDIFConstants.FlextLDIFValidationMessages.FILE_NOT_FOUND.format(
                file_path=file_path
            ),
        )

    def _process_directory_path(
        self,
        directory_path: str | Path,
        file_pattern: str,
    ) -> FlextResult:  # type: ignore[type-arg]
        """Process directory path with pattern."""
        directory_obj = Path(directory_path)
        if not directory_obj.exists():
            return FlextResult.fail(
                FlextLDIFConstants.FlextLDIFValidationMessages.FILE_NOT_FOUND.format(
                    file_path=directory_path,
                ),
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
    ) -> FlextResult:  # type: ignore[type-arg]
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
                    logger.warning(
                        "Skipping file - size exceeds limit - file_path=%s, file_size=%s, max_size=%s",
                        str(file_path_item),
                        file_path_item.stat().st_size,
                        max_size_bytes,
                    )
            except OSError as e:
                logger.warning(
                    "Could not check file size - file_path=%s, error=%s",
                    str(file_path_item),
                    str(e),
                )
                continue

        return filtered_files


__all__ = [
    "FlextLDIFAPI",
]
