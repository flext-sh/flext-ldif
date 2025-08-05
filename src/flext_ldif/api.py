"""FLEXT-LDIF Application Service Layer - Enterprise-Grade LDIF Processing.

This module provides the main application service interface for LDIF operations,
implementing Clean Architecture patterns with direct integration to core processing
infrastructure and comprehensive error handling using flext-core patterns.

Key Components:
    - FlextLdifAPI: Primary application service for all LDIF operations
    - Configuration-driven processing with FlextLdifConfig integration
    - Direct core.py delegation for optimal performance and simplicity
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
from typing import TYPE_CHECKING

from flext_core import FlextResult, get_logger

from .config import FlextLdifConfig
from .core import TLdif
from .utils.validation import LdifValidator

if TYPE_CHECKING:
    from .models import FlextLdifEntry, LDIFContent

logger = get_logger(__name__)


class FlextLdifAPI:
    """Enterprise-grade unified LDIF API with direct core processing delegation.

    This class provides a comprehensive application service interface for all LDIF
    operations, implementing enterprise patterns with configuration-driven processing,
    comprehensive validation, and optimal performance through direct core delegation.

    The API consolidates all LDIF functionality into a single, consistent interface
    while maintaining clean architecture separation and comprehensive error handling.
    """

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize API with enterprise configuration management.

        Args:
            config: Optional configuration object with processing settings and limits

        """
        self.config = config or FlextLdifConfig()
        logger.debug(
            "FlextLdifAPI initialized",
            max_entries=self.config.max_entries,
            encoding=self.config.input_encoding,
        )

    # ========================================================================
    # CORE LDIF PROCESSING OPERATIONS
    # ========================================================================

    def parse(self, content: str | LDIFContent) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF content with configuration-driven processing and validation.

        Args:
            content: LDIF content as string or LDIFContent type

        Returns:
            FlextResult[list[FlextLdifEntry]]: Success with entries or failure with error

        """
        logger.debug("Starting LDIF content parsing", content_size=len(str(content)))

        # Delegate to core parser
        result = TLdif.parse(content)
        if result.is_failure:
            return result

        entries = result.data or []

        # Apply configuration limits
        if len(entries) > self.config.max_entries:
            error_msg = (
                f"Entry count {len(entries)} exceeds limit {self.config.max_entries}"
            )
            logger.warning(error_msg)
            return FlextResult.fail(error_msg)

        logger.debug("LDIF parsing completed", entries_count=len(entries))
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
            "Starting LDIF file parsing", file_path=str(file_path_obj.absolute()),
        )

        # Delegate to core parser with encoding
        result = TLdif.read_file(file_path_obj, self.config.input_encoding)
        if result.is_failure:
            return result

        entries = result.data or []

        # Apply configuration limits
        if len(entries) > self.config.max_entries:
            error_msg = f"File entry count {len(entries)} exceeds limit {self.config.max_entries}"
            logger.warning(error_msg)
            return FlextResult.fail(error_msg)

        logger.debug("LDIF file parsing completed", entries_count=len(entries))
        return FlextResult.ok(entries)

    def write(self, entries: list[FlextLdifEntry]) -> FlextResult[str]:
        """Write entries to LDIF string with formatting configuration.

        Args:
            entries: List of FlextLdifEntry objects to serialize

        Returns:
            FlextResult[str]: Success with LDIF string or failure with error

        """
        logger.debug("Starting LDIF string writing", entries_count=len(entries))

        # Apply attribute sorting if configured
        processed_entries = self._sort_attributes_if_configured(entries)

        # Delegate to core writer
        result = TLdif.write(processed_entries)
        if result.is_success:
            logger.debug(
                "LDIF string writing completed", content_length=len(result.data or ""),
            )

        return result

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
        file_path_obj = Path(file_path)
        logger.debug("Starting LDIF file writing", entries_count=len(entries))

        # Resolve output path
        resolved_path = self._resolve_output_path(file_path_obj)

        # Create directories if configured
        if self.config.create_output_dir and resolved_path.parent:
            try:
                resolved_path.parent.mkdir(parents=True, exist_ok=True)
            except (OSError, PermissionError) as e:
                error_msg = f"Failed to create output directory: {e}"
                logger.exception(error_msg)
                return FlextResult.fail(error_msg)

        # Apply attribute sorting if configured
        processed_entries = self._sort_attributes_if_configured(entries)

        # Delegate to core writer with encoding
        result = TLdif.write_file(
            processed_entries, resolved_path, self.config.output_encoding,
        )
        if result.is_success:
            logger.debug("LDIF file writing completed", file_path=str(resolved_path))

        return result

    def validate(self, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate multiple LDIF entries with comprehensive rule checking.

        Args:
            entries: List of FlextLdifEntry objects to validate

        Returns:
            FlextResult[bool]: Success with True if all valid, failure with error

        """
        logger.debug("Starting bulk validation", entries_count=len(entries))

        # Check count limits
        if len(entries) > self.config.max_entries:
            error_msg = (
                f"Entry count {len(entries)} exceeds limit {self.config.max_entries}"
            )
            return FlextResult.fail(error_msg)

        # Validate each entry
        for i, entry in enumerate(entries):
            result = self.validate_entry(entry)
            if result.is_failure:
                error_msg = (
                    f"Entry {i + 1} validation failed ({entry.dn}): {result.error}"
                )
                logger.error(error_msg)
                return FlextResult.fail(error_msg)

        logger.debug("Bulk validation completed successfully")
        return FlextResult.ok(data=True)

    def validate_entry(self, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Validate single LDIF entry with comprehensive rule enforcement.

        Args:
            entry: FlextLdifEntry object to validate

        Returns:
            FlextResult[bool]: Success with True if valid, failure with error

        """
        logger.debug("Validating entry", entry_dn=str(entry.dn))

        # Core validation
        result = TLdif.validate(entry)
        if result.is_failure:
            return result

        # Entry completeness validation
        completeness_result = LdifValidator.validate_entry_completeness(entry)
        if completeness_result.is_failure:
            return completeness_result

        # Size validation if configured
        if hasattr(self.config, "max_entry_size"):
            try:
                entry_ldif = entry.to_ldif()
                entry_size = len(entry_ldif.encode(self.config.output_encoding))
                if entry_size > self.config.max_entry_size:
                    error_msg = f"Entry size {entry_size} exceeds limit {self.config.max_entry_size}"
                    return FlextResult.fail(error_msg)
            except (UnicodeEncodeError, AttributeError) as e:
                return FlextResult.fail(f"Size validation failed: {e}")

        # Empty attributes validation if configured
        if (
            hasattr(self.config, "allow_empty_attributes")
            and not self.config.allow_empty_attributes
        ):
            for attr_name, attr_values in entry.attributes.attributes.items():
                if not attr_values or any(not v.strip() for v in attr_values):
                    return FlextResult.fail(f"Empty attribute not allowed: {attr_name}")

        return FlextResult.ok(data=True)

    # ========================================================================
    # ENTRY FILTERING AND ANALYSIS OPERATIONS
    # ========================================================================

    def filter_persons(
        self, entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter person entries."""
        filtered = [
            entry for entry in entries if LdifValidator.is_person_entry(entry).success
        ]
        return FlextResult.ok(filtered)

    def filter_groups(
        self, entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter group entries."""
        filtered = [
            entry for entry in entries if LdifValidator.is_group_entry(entry).success
        ]
        return FlextResult.ok(filtered)

    def filter_organizational_units(
        self, entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter organizational unit entries."""
        filtered = [
            entry for entry in entries if LdifValidator.is_ou_entry(entry).success
        ]
        return FlextResult.ok(filtered)

    def filter_valid(
        self, entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter valid entries."""
        filtered = [entry for entry in entries if self.validate_entry(entry).success]
        return FlextResult.ok(filtered)

    def get_entry_statistics(
        self, entries: list[FlextLdifEntry],
    ) -> FlextResult[dict[str, int]]:
        """Get entry statistics."""
        stats = {
            "total": len(entries),
            "persons": len(self.filter_persons(entries).data or []),
            "groups": len(self.filter_groups(entries).data or []),
            "ous": len(self.filter_organizational_units(entries).data or []),
            "valid": len(self.filter_valid(entries).data or []),
        }
        return FlextResult.ok(stats)

    def filter_by_objectclass(
        self, entries: list[FlextLdifEntry], objectclass: str,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter entries by objectClass."""
        filtered = [entry for entry in entries if entry.has_object_class(objectclass)]
        return FlextResult.ok(filtered)

    def find_entry_by_dn(
        self, entries: list[FlextLdifEntry], dn: str,
    ) -> FlextResult[FlextLdifEntry | None]:
        """Find entry by DN."""
        for entry in entries:
            if str(entry.dn.value) == dn:
                return FlextResult.ok(entry)
        return FlextResult.ok(None)

    def sort_hierarchically(
        self, entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Sort entries hierarchically by DN depth."""
        try:
            sorted_entries = sorted(entries, key=lambda e: e.dn.get_depth())
            return FlextResult.ok(sorted_entries)
        except Exception as e:
            return FlextResult.fail(f"Hierarchical sort failed: {e}")

    # ========================================================================
    # PRIVATE HELPER METHODS
    # ========================================================================

    def _sort_attributes_if_configured(
        self, entries: list[FlextLdifEntry],
    ) -> list[FlextLdifEntry]:
        """Sort entry attributes if configured."""
        if not getattr(self.config, "sort_attributes", False):
            return entries

        sorted_entries = []
        for entry in entries:
            try:
                # Sort attributes by name
                sorted_attrs = dict(
                    sorted(
                        entry.attributes.attributes.items(), key=lambda x: x[0].lower(),
                    ),
                )

                # Create new entry with sorted attributes
                new_attrs = entry.attributes.model_copy(
                    update={"attributes": sorted_attrs},
                )
                new_entry = entry.model_copy(update={"attributes": new_attrs})
                sorted_entries.append(new_entry)
            except (AttributeError, ValueError):
                # Fallback to original entry if sorting fails
                sorted_entries.append(entry)

        return sorted_entries

    def _resolve_output_path(self, file_path: Path) -> Path:
        """Resolve output file path with configuration-based directory resolution."""
        if (
            not file_path.is_absolute()
            and hasattr(self.config, "output_directory")
            and self.config.output_directory
        ):
            return self.config.output_directory / file_path
        return file_path


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
