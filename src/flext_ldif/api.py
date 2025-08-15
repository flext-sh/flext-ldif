"""FLEXT-LDIF API."""

from __future__ import annotations

import re as _re
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from flext_core import FlextResult, get_logger

from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifValidationMessages, FlextLdifOperationMessages
from flext_ldif.entry_analytics import FlextLdifAnalyticsService
from flext_ldif.entry_repository import FlextLdifRepositoryService
from flext_ldif.entry_validator import (
    FlextLdifValidatorService as _FlextLdifValidatorService,
)
from flext_ldif.ldif_parser import FlextLdifParserService as _FlextLdifParserService
from flext_ldif.ldif_writer import FlextLdifWriterService as _FlextLdifWriterService

if TYPE_CHECKING:
    from flext_ldif.models import FlextLdifEntry

logger = get_logger(__name__)


class TLdif(_FlextLdifParserService):
    """Legacy TLdif class for backward compatibility."""

    DN_PATTERN: ClassVar[object] = _re.compile(
        r"^[a-zA-Z][a-zA-Z0-9-]*=.+(?:,[a-zA-Z][a-zA-Z0-9-]*=.+)*$",
    )


class FlextLdifAPI:
    """LDIF processing API."""

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize API with configuration.

        Args:
            config: Optional configuration object.

        """
        self.config = config or FlextLdifConfig()

        ns = {
            "FlextLdifConfig": FlextLdifConfig,
        }
        _FlextLdifParserService.model_rebuild(_types_namespace=ns)
        _FlextLdifValidatorService.model_rebuild(_types_namespace=ns)
        _FlextLdifWriterService.model_rebuild(_types_namespace=ns)
        FlextLdifRepositoryService.model_rebuild(_types_namespace=ns)
        FlextLdifAnalyticsService.model_rebuild(_types_namespace=ns)
        self._parser_service = _FlextLdifParserService(config=self.config)
        self._validator_service = _FlextLdifValidatorService(config=self.config)
        self._writer_service = _FlextLdifWriterService(config=self.config)
        self._repository_service = FlextLdifRepositoryService(config=self.config)
        self._analytics_service = FlextLdifAnalyticsService(config=self.config)


    def parse(self, content: str) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF content."""
        result = self._parser_service.parse(content)
        if result.is_failure:
            return result

        entries = result.data or []

        if len(entries) > int(self.config.max_entries):
            error_msg = FlextLdifValidationMessages.ENTRY_COUNT_EXCEEDED.format(
                count=len(entries), limit=self.config.max_entries
            )
            logger.warning(error_msg)
            return FlextResult.fail(error_msg)
        return FlextResult.ok(entries)

    def parse_file(self, file_path: str | Path) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF file."""
        file_path_obj = Path(file_path)
        logger.debug(
            "Starting LDIF file parsing - file_path=%s",
            str(file_path_obj.absolute()),
        )

        result = self._parser_service.parse_ldif_file(file_path_obj)
        if result.is_failure:
            return result

        entries = result.data or []

        if len(entries) > int(self.config.max_entries):
            error_msg = FlextLdifValidationMessages.FILE_ENTRY_COUNT_EXCEEDED.format(
                count=len(entries), limit=self.config.max_entries
            )
            logger.warning(error_msg)
            return FlextResult.fail(error_msg)

        logger.debug("File parsed successfully with %d entries", len(entries))
        return FlextResult.ok(entries)

    def parse_entries_from_string(
        self,
        ldif_string: str,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Parse multiple entries from LDIF string."""
        return self._parser_service.parse_entries_from_string(ldif_string)

    def discover_ldif_files(
        self,
        directory_path: str | Path | None = None,
        file_pattern: str = "*.ldif",
        file_path: str | Path | None = None,
        max_file_size_mb: int = 100,
    ) -> FlextResult[list[Path]]:
        """Discover LDIF files."""

        files_result = self._get_files_to_process(
            directory_path,
            file_pattern,
            file_path,
        )
        if files_result.is_failure:
            return files_result

        files_to_process = files_result.data or []

        filtered_files = self._filter_files_by_size(files_to_process, max_file_size_mb)
        sorted_files = sorted(filtered_files)

        logger.debug(
            "LDIF file discovery completed - files_found=%s, files_skipped=%s",
            len(sorted_files),
            len(files_to_process) - len(filtered_files),
        )

        return FlextResult.ok(sorted_files)

    def write(
        self,
        entries: list[FlextLdifEntry],
        file_path: str | None = None,
    ) -> FlextResult[str]:
        """Write entries to LDIF format.

        Args:
            entries: List of entries to serialize.
            file_path: Optional file path for output.

        Returns:
            FlextResult containing LDIF string or error.

        """
        logger.debug("Preparing to write LDIF output")

        if file_path:
            file_result = self._writer_service.write_file(entries, file_path)
            if file_result.success:
                return FlextResult.ok(FlextLdifOperationMessages.WRITE_SUCCESS.format(path=file_path))
            return FlextResult.fail(file_result.error or FlextLdifOperationMessages.WRITE_FAILED.format(error="File write failed"))

        result = self._writer_service.write(entries)
        if result.is_success:
            logger.debug(
                "LDIF string writing completed - content_length=%s",
                len(result.data or ""),
            )

        return result

    def entries_to_ldif(self, entries: list[FlextLdifEntry]) -> FlextResult[str]:
        """Convert entries to LDIF string format.

        Args:
            entries: List of entries to convert.

        Returns:
            FlextResult containing LDIF string or error.

        """
        return self.write(entries)

    def write_file(
        self,
        entries: list[FlextLdifEntry],
        file_path: str | Path,
    ) -> FlextResult[bool]:
        """Write entries to LDIF file.

        Args:
            entries: List of entries to write.
            file_path: Target file path.

        Returns:
            FlextResult containing success status or error.

        """
        logger.debug("Validating %d entries", len(entries))

        result = self._writer_service.write_file(entries, file_path)
        if result.is_success:
            logger.debug("File write completed successfully")

        return result

    def validate(self, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate multiple LDIF entries.

        Args:
            entries: List of entries to validate.

        Returns:
            FlextResult containing validation status or error.

        """
        logger.debug("debug message")

        if len(entries) > self.config.max_entries:
            error_msg = FlextLdifValidationMessages.ENTRY_COUNT_EXCEEDED.format(
                count=len(entries), limit=self.config.max_entries
            )
            return FlextResult.fail(error_msg)

        result = self._validator_service.validate_entries(entries)
        if result.is_success:
            logger.debug("Bulk validation completed successfully")

        return result

    def validate_entry(self, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Validate single LDIF entry.

        Args:
            entry: Entry to validate.

        Returns:
            FlextResult containing validation status or error.

        """
        logger.debug("Validating single entry")

        return self._validator_service.validate_entry(entry)

    def validate_dn_format(self, dn: str) -> FlextResult[bool]:
        """Validate DN format compliance.

        Args:
            dn: Distinguished name to validate.

        Returns:
            FlextResult containing validation status or error.

        """
        return self._validator_service.validate_dn_format(dn)

    def filter_persons(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter person entries.

        Args:
            entries: List of entries to filter.

        Returns:
            FlextResult containing filtered person entries.

        """
        filtered = [entry for entry in entries if entry.is_person_entry()]
        return FlextResult.ok(filtered)

    def filter_groups(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter group entries.

        Args:
            entries: List of entries to filter.

        Returns:
            FlextResult containing filtered group entries.

        """
        filtered = [entry for entry in entries if entry.is_group_entry()]
        return FlextResult.ok(filtered)

    def filter_organizational_units(
        self,
        entries: list[FlextLdifEntry] | None,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter organizational unit entries.

        Args:
            entries: List of entries to filter.

        Returns:
            FlextResult containing filtered OU entries.

        """
        if entries is None:
            return FlextResult.fail(FlextLdifValidationMessages.ENTRIES_CANNOT_BE_NONE)
        filtered = [
            entry for entry in entries if entry.has_object_class("organizationalUnit")
        ]
        return FlextResult.ok(filtered)

    def filter_valid(
        self,
        entries: list[FlextLdifEntry] | None,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter valid entries.

        Args:
            entries: List of entries to filter.

        Returns:
            FlextResult containing valid entries.

        """
        if entries is None:
            return FlextResult.fail(FlextLdifValidationMessages.ENTRIES_CANNOT_BE_NONE)
        filtered = [entry for entry in entries if self.validate_entry(entry).success]
        return FlextResult.ok(filtered)

    def filter_by_objectclass(
        self,
        entries: list[FlextLdifEntry],
        objectclass: str,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter entries by objectClass.

        Args:
            entries: List of entries to filter.
            objectclass: ObjectClass to filter by.

        Returns:
            FlextResult containing filtered entries.

        """
        return self._repository_service.filter_by_objectclass(entries, objectclass)

    def filter_by_attribute(
        self,
        entries: list[FlextLdifEntry],
        attribute: str,
        value: str,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter entries by attribute value.

        Args:
            entries: List of entries to filter.
            attribute: Attribute name.
            value: Attribute value.

        Returns:
            FlextResult containing filtered entries.

        """
        return self._repository_service.filter_by_attribute(entries, attribute, value)

    def find_entry_by_dn(
        self,
        entries: list[FlextLdifEntry],
        dn: str,
    ) -> FlextResult[FlextLdifEntry | None]:
        """Find entry by DN.

        Args:
            entries: List of entries to search.
            dn: Distinguished name to find.

        Returns:
            FlextResult containing found entry or None.

        """
        return self._repository_service.find_by_dn(entries, dn)

    def get_entry_statistics(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[dict[str, int]]:
        """Get entry statistics.

        Args:
            entries: List of entries to analyze.

        Returns:
            FlextResult containing statistics dictionary.

        """
        return self._repository_service.get_statistics(entries)

    def analyze_entry_patterns(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[dict[str, int]]:
        """Analyze patterns in LDIF entries.

        Args:
            entries: List of entries to analyze.

        Returns:
            FlextResult containing pattern analysis.

        """
        return self._analytics_service.analyze_entry_patterns(entries)

    def get_objectclass_distribution(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[dict[str, int]]:
        """Get distribution of objectClass types.

        Args:
            entries: List of entries to analyze.

        Returns:
            FlextResult containing objectClass distribution.

        """
        return self._analytics_service.get_objectclass_distribution(entries)

    def get_dn_depth_analysis(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[dict[str, int]]:
        """Analyze DN depth distribution.

        Args:
            entries: List of entries to analyze.

        Returns:
            FlextResult containing DN depth analysis.

        """
        return self._analytics_service.get_dn_depth_analysis(entries)

    def filter_change_records(
        self,
        entries: list[FlextLdifEntry] | None,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter entries that represent change records.

        Args:
            entries: List of entries to filter.

        Returns:
            FlextResult containing change record entries.

        """
        if entries is None:
            return FlextResult.fail(FlextLdifValidationMessages.ENTRIES_CANNOT_BE_NONE)
        filtered = [entry for entry in entries if entry.changetype is not None]
        return FlextResult.ok(filtered)

    def sort_hierarchically(
        self,
        entries: list[FlextLdifEntry] | None,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Sort entries hierarchically by DN depth.

        Args:
            entries: List of entries to sort.

        Returns:
            FlextResult containing sorted entries.

        """
        if entries is None:
            return FlextResult.fail(FlextLdifValidationMessages.ENTRIES_CANNOT_BE_NONE)
        try:
            sorted_entries = sorted(entries, key=lambda entry: str(entry.dn).count(","))
            return FlextResult.ok(sorted_entries)
        except Exception as e:
            return FlextResult.fail(FlextLdifOperationMessages.SORT_FAILED.format(error=str(e)))

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
        return FlextResult.fail(FlextLdifValidationMessages.FILE_NOT_FOUND.format(file_path=file_path))

    def _process_directory_path(
        self,
        directory_path: str | Path,
        file_pattern: str,
    ) -> FlextResult[list[Path]]:
        """Process directory path with pattern."""
        directory_obj = Path(directory_path)
        if not directory_obj.exists():
            return FlextResult.fail(FlextLdifValidationMessages.FILE_NOT_FOUND.format(file_path=directory_path))
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
    "FlextLdifAPI",
    "TLdif",
]
