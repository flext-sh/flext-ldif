"""FLEXT-LDIF Application Service Layer - Clean Architecture Implementation.

ARCHITECTURAL CONSOLIDATION: This module consolidates ALL LDIF API functionality from
multiple duplicate sources into ONE centralized application layer following enterprise patterns.

ELIMINATED DUPLICATION:
✅ api.py + api_new.py → ONE unified api.py
✅ Complete flext-core integration - ZERO local duplication
✅ Clean Architecture + Service orchestration patterns throughout
✅ Railway-oriented programming with FlextResult pattern

Key Components:
    - FlextLdifAPI: Primary application service for all LDIF operations
    - Configuration-driven processing with FlextLdifConfig integration
    - Service orchestration using proper infrastructure services
    - Comprehensive entry filtering and validation using business rules

Architecture:
    Application Layer in Clean Architecture, orchestrating domain operations
    through infrastructure services while providing a unified interface for
    all LDIF processing requirements with enterprise-grade reliability.

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from __future__ import annotations

from pathlib import Path
import re as _re
from typing import TYPE_CHECKING, ClassVar

from flext_core import FlextResult, get_logger

from .config import FlextLdifConfig
from .entry_analytics import FlextLdifAnalyticsService
from .entry_repository import FlextLdifRepositoryService
from .entry_validator import FlextLdifValidatorService as _FlextLdifValidatorService
from .ldif_parser import FlextLdifParserService as _FlextLdifParserService
from .ldif_writer import FlextLdifWriterService as _FlextLdifWriterService

if TYPE_CHECKING:
    from .models import FlextLdifEntry

logger = get_logger(__name__)


class TLdif(_FlextLdifParserService):
    """Backward-compat facade exposing patterns for tests."""

    # Simple DN pattern for tests
    DN_PATTERN: ClassVar[object] = _re.compile(
        r"^[a-zA-Z][a-zA-Z0-9-]*=.+(?:,[a-zA-Z][a-zA-Z0-9-]*=.+)*$",
    )


class FlextLdifAPI:
    """Enterprise-grade unified LDIF API with Clean Architecture orchestration.

    This class provides a comprehensive application service interface for all LDIF
    operations, implementing Clean Architecture patterns with proper service
    orchestration, configuration-driven processing, and comprehensive validation.

    The API consolidates all LDIF functionality into a single, consistent interface
    while maintaining clean separation of concerns and comprehensive error handling.
    """

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize API with enterprise configuration management.

        Args:
            config: Optional configuration object with processing settings and limits

        """
        self.config = config or FlextLdifConfig()

        # Ensure Pydantic models are rebuilt with proper namespace context
        ns = {
            "FlextLdifConfig": FlextLdifConfig,
        }
        _FlextLdifParserService.model_rebuild(_types_namespace=ns)
        _FlextLdifValidatorService.model_rebuild(_types_namespace=ns)
        _FlextLdifWriterService.model_rebuild(_types_namespace=ns)
        FlextLdifRepositoryService.model_rebuild(_types_namespace=ns)
        FlextLdifAnalyticsService.model_rebuild(_types_namespace=ns)

        # Initialize infrastructure services using Pydantic field pattern
        self._parser_service = _FlextLdifParserService(config=self.config)
        self._validator_service = _FlextLdifValidatorService(config=self.config)
        self._writer_service = _FlextLdifWriterService(config=self.config)
        self._repository_service = FlextLdifRepositoryService(config=self.config)
        self._analytics_service = FlextLdifAnalyticsService(config=self.config)

        logger.debug(
            "FlextLdifAPI initialized with Clean Architecture services - max_entries=%s, input_encoding=%s",
            self.config.max_entries,
            self.config.input_encoding,
        )

    # ========================================================================
    # CORE LDIF PROCESSING OPERATIONS
    # ========================================================================

    def parse(self, content: str) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF content with configuration-driven processing and validation.

        Args:
            content: LDIF content as string

        Returns:
            FlextResult[list[FlextLdifEntry]]: Success with entries or failure with error

        """
        logger.debug("Parsing LDIF content via parser service")

        # Delegate to infrastructure service
        result = self._parser_service.parse(content)
        if result.is_failure:
            return result

        entries = result.data or []

        # Apply configuration limits
        if len(entries) > int(self.config.max_entries):
            error_msg = f"Entry count {len(entries)} exceeds configured limit {self.config.max_entries}"
            logger.warning(error_msg)
            return FlextResult.fail(error_msg)

        logger.debug("Parse completed successfully with %d entries", len(entries))
        return FlextResult.ok(entries)

    def parse_file(self, file_path: str | Path) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF file with encoding support and path validation.

        Args:
            file_path: Path to LDIF file as string or Path object

        Returns:
            FlextResult[list[FlextLdifEntry]]: Success with entries or failure with error

        """
        file_path_obj = Path(file_path)
        logger.debug(
            "Starting LDIF file parsing - file_path=%s",
            str(file_path_obj.absolute()),
        )

        # Delegate to infrastructure service
        result = self._parser_service.parse_ldif_file(file_path_obj)
        if result.is_failure:
            return result

        entries = result.data or []

        # Apply configuration limits
        if len(entries) > int(self.config.max_entries):
            error_msg = f"File entry count {len(entries)} exceeds configured limit {self.config.max_entries}"
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
        """Discover LDIF files based on configuration parameters.

        Args:
            directory_path: Directory to search for LDIF files
            file_pattern: Glob pattern for file matching (default: *.ldif)
            file_path: Single file path (alternative to directory_path)
            max_file_size_mb: Maximum file size in MB (default: 100)

        Returns:
            FlextResult[list[Path]]: Success with list of discovered files or failure with error

        """
        logger.debug(
            "Starting LDIF file discovery - directory_path=%s, file_pattern=%s, file_path=%s, max_file_size_mb=%s",
            str(directory_path) if directory_path else None,
            file_pattern,
            str(file_path) if file_path else None,
            max_file_size_mb,
        )

        # Get initial files to process
        files_result = self._get_files_to_process(
            directory_path,
            file_pattern,
            file_path,
        )
        if files_result.is_failure:
            return files_result

        files_to_process = files_result.data or []

        # Filter by file size limit
        filtered_files = self._filter_files_by_size(files_to_process, max_file_size_mb)

        # Sort for consistent ordering
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
        """Write entries to LDIF string with formatting configuration.

        Args:
            entries: List of FlextLdifEntry objects to serialize
            file_path: Optional path to write the serialized LDIF output. When
                provided, the content is written to the given file path instead
                of being returned as a string.

        Returns:
            FlextResult[str]: Success with LDIF string or failure with error

        """
        logger.debug("Preparing to write LDIF output")

        # Write to string or file depending on file_path
        if file_path:
            file_result = self._writer_service.write_file(entries, file_path)
            if file_result.success:
                return FlextResult.ok(f"Written successfully to {file_path}")
            return FlextResult.fail(file_result.error or "File write failed")

        # Delegate to infrastructure service for string output
        result = self._writer_service.write(entries)
        if result.is_success:
            logger.debug(
                "LDIF string writing completed - content_length=%s",
                len(result.data or ""),
            )

        return result

    def entries_to_ldif(self, entries: list[FlextLdifEntry]) -> FlextResult[str]:
        """Convert entries to LDIF string format (alias for write method)."""
        return self.write(entries)

    def write_file(
        self,
        entries: list[FlextLdifEntry],
        file_path: str | Path,
    ) -> FlextResult[bool]:
        """Write entries to LDIF file with directory management and encoding.

        Args:
            entries: List of FlextLdifEntry objects to write
            file_path: Target file path as string or Path object

        Returns:
            FlextResult[bool]: Success with True or failure with error

        """
        logger.debug("Validating %d entries", len(entries))

        # Delegate to infrastructure service
        result = self._writer_service.write_file(entries, file_path)
        if result.is_success:
            logger.debug("File write completed successfully")

        return result

    def validate(self, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate multiple LDIF entries with comprehensive rule checking.

        Args:
            entries: List of FlextLdifEntry objects to validate

        Returns:
            FlextResult[bool]: Success with True if all valid, failure with error

        """
        logger.debug("debug message")

        # Check count limits
        if len(entries) > self.config.max_entries:
            error_msg = (
                f"Entry count {len(entries)} exceeds limit {self.config.max_entries}"
            )
            return FlextResult.fail(error_msg)

        # Delegate to infrastructure service
        result = self._validator_service.validate_entries(entries)
        if result.is_success:
            logger.debug("Bulk validation completed successfully")

        return result

    def validate_entry(self, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Validate single LDIF entry with comprehensive rule enforcement.

        Args:
            entry: FlextLdifEntry object to validate

        Returns:
            FlextResult[bool]: Success with True if valid, failure with error

        """
        logger.debug("Validating single entry")

        # Delegate to infrastructure service
        return self._validator_service.validate_entry(entry)

    def validate_dn_format(self, dn: str) -> FlextResult[bool]:
        """Validate DN format compliance."""
        return self._validator_service.validate_dn_format(dn)

    # ========================================================================
    # ENTRY FILTERING AND ANALYSIS OPERATIONS
    # ========================================================================

    def filter_persons(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter person entries."""
        filtered = [entry for entry in entries if entry.is_person_entry()]
        return FlextResult.ok(filtered)

    def filter_groups(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter group entries."""
        filtered = [entry for entry in entries if entry.is_group_entry()]
        return FlextResult.ok(filtered)

    def filter_organizational_units(
        self,
        entries: list[FlextLdifEntry] | None,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter organizational unit entries."""
        if entries is None:
            return FlextResult.fail("Entries list cannot be None")
        filtered = [
            entry for entry in entries if entry.has_object_class("organizationalUnit")
        ]
        return FlextResult.ok(filtered)

    def filter_valid(
        self,
        entries: list[FlextLdifEntry] | None,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter valid entries."""
        if entries is None:
            return FlextResult.fail("Entries list cannot be None")
        filtered = [entry for entry in entries if self.validate_entry(entry).success]
        return FlextResult.ok(filtered)

    def filter_by_objectclass(
        self,
        entries: list[FlextLdifEntry],
        objectclass: str,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter entries by objectClass."""
        return self._repository_service.filter_by_objectclass(entries, objectclass)

    def filter_by_attribute(
        self,
        entries: list[FlextLdifEntry],
        attribute: str,
        value: str,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter entries by attribute value."""
        return self._repository_service.filter_by_attribute(entries, attribute, value)

    def find_entry_by_dn(
        self,
        entries: list[FlextLdifEntry],
        dn: str,
    ) -> FlextResult[FlextLdifEntry | None]:
        """Find entry by DN."""
        return self._repository_service.find_by_dn(entries, dn)

    def get_entry_statistics(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[dict[str, int]]:
        """Get entry statistics."""
        return self._repository_service.get_statistics(entries)

    def analyze_entry_patterns(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[dict[str, int]]:
        """Analyze patterns in LDIF entries."""
        return self._analytics_service.analyze_entry_patterns(entries)

    def get_objectclass_distribution(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[dict[str, int]]:
        """Get distribution of objectClass types."""
        return self._analytics_service.get_objectclass_distribution(entries)

    def get_dn_depth_analysis(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[dict[str, int]]:
        """Analyze DN depth distribution."""
        return self._analytics_service.get_dn_depth_analysis(entries)

    def filter_change_records(
        self,
        entries: list[FlextLdifEntry] | None,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter entries that represent change records (changetype present)."""
        if entries is None:
            return FlextResult.fail("Entries list cannot be None")
        filtered = [entry for entry in entries if entry.changetype is not None]
        return FlextResult.ok(filtered)

    def sort_hierarchically(
        self,
        entries: list[FlextLdifEntry] | None,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Sort entries hierarchically by DN depth."""
        if entries is None:
            return FlextResult.fail("Entries list cannot be None")
        try:
            sorted_entries = sorted(entries, key=lambda entry: str(entry.dn).count(","))
            return FlextResult.ok(sorted_entries)
        except Exception as e:
            return FlextResult.fail(f"Hierarchical sort failed: {e}")

    # ========================================================================
    # PRIVATE HELPER METHODS
    # ========================================================================

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
        return FlextResult.fail(f"File not found or not accessible: {file_path}")

    def _process_directory_path(
        self,
        directory_path: str | Path,
        file_pattern: str,
    ) -> FlextResult[list[Path]]:
        """Process directory path with pattern."""
        directory_obj = Path(directory_path)
        if not directory_obj.exists():
            return FlextResult.fail(f"Directory not found: {directory_path}")
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


# ========================================================================
# SERVICE REGISTRATION FUNCTIONS (Legacy Compatibility)
# ========================================================================


def register_ldif_services() -> FlextResult[None]:
    """Legacy service registration function - no longer needed with direct API."""
    logger.debug(
        "Legacy service registration called - no action needed with direct API",
    )
    return FlextResult.ok(None)


def get_ldif_parser() -> FlextResult[FlextLdifAPI]:
    """Get LDIF parser (returns API instance for compatibility)."""
    return FlextResult.ok(FlextLdifAPI())


def get_ldif_writer() -> FlextResult[FlextLdifAPI]:
    """Get LDIF writer (returns API instance for compatibility)."""
    return FlextResult.ok(FlextLdifAPI())


def get_ldif_validator() -> FlextResult[FlextLdifAPI]:
    """Get LDIF validator (returns API instance for compatibility)."""
    return FlextResult.ok(FlextLdifAPI())


# ========================================================================
# SERVICE CLASS ALIASES (Legacy Compatibility)
# ========================================================================

# Provide aliases for removed service classes
FlextLdifParserService = FlextLdifAPI
FlextLdifValidatorService = FlextLdifAPI
FlextLdifWriterService = FlextLdifAPI

__all__ = [
    "FlextLdifAPI",
    # Legacy compatibility exports
    "FlextLdifParserService",
    "FlextLdifValidatorService",
    "FlextLdifWriterService",
    "get_ldif_parser",
    "get_ldif_validator",
    "get_ldif_writer",
    "register_ldif_services",
]
