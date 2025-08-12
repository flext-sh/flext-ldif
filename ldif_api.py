"""FLEXT-LDIF Application Service Layer - Enterprise LDIF Processing API.

CONSOLIDATED PEP8 ARCHITECTURE: This module consolidates LDIF API functionality
into ONE centralized, PEP8-compliant application service layer.

CONSOLIDATION MAPPING:
✅ src/flext_ldif/api.py → Complete LDIF application service layer

ARCHITECTURAL CONSOLIDATION: This module consolidates ALL LDIF API functionality from
multiple duplicate sources into ONE centralized application layer following enterprise patterns.

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

import logging
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from flext_core import FlextResult

from .ldif_config import FlextLdifConfig
from .ldif_core import TLdif

if TYPE_CHECKING:
    from .ldif_models import FlextLdifEntry

logger = logging.getLogger(__name__)


class FlextLdifAPI:
    """Primary application service for LDIF processing operations.

    Provides a unified, high-level interface for all LDIF operations including
    parsing, validation, writing, and analytics. Orchestrates infrastructure
    services while maintaining clean separation of concerns.

    Features:
    - Configuration-driven processing
    - Service composition and orchestration
    - Railway-oriented programming with FlextResult
    - Comprehensive error handling and logging
    - Enterprise-grade reliability and performance
    """

    # Class variable for backward compatibility with tests
    DEFAULT_CONFIG: ClassVar[FlextLdifConfig | None] = None

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize API with configuration.

        Args:
            config: Optional configuration object. If None, uses default config.

        """
        self.config = config or FlextLdifConfig()

        # Initialize core processor with config
        self._core_processor = TLdif(
            max_entries=self.config.max_entries,
            max_entry_size=self.config.max_entry_size,
            line_wrap_length=self.config.line_wrap_length,
        )

        logger.debug(f"FlextLdifAPI initialized with config: {self.config}")

    def parse(self, content: str) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF content into domain entities.

        Args:
            content: LDIF content string to parse

        Returns:
            FlextResult containing list of FlextLdifEntry objects or error

        """
        try:
            logger.debug(f"Parsing LDIF content ({len(content)} characters)")

            # Validate input
            if not content or not content.strip():
                return FlextResult.failure("Empty LDIF content provided")

            # Parse using core processor
            parse_result = self._core_processor.parse(content)
            if parse_result.is_failure:
                return parse_result

            entries = parse_result.data or []
            logger.info(f"Successfully parsed {len(entries)} LDIF entries")

            return FlextResult.success(entries)

        except Exception as e:
            error_msg = f"LDIF parsing failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

    def parse_file(self, file_path: str | Path) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF file into domain entities.

        Args:
            file_path: Path to LDIF file to parse

        Returns:
            FlextResult containing list of FlextLdifEntry objects or error

        """
        try:
            path = Path(file_path)
            logger.debug(f"Parsing LDIF file: {path}")

            # Validate file
            if not path.exists():
                return FlextResult.failure(f"LDIF file not found: {file_path}")

            if not path.is_file():
                return FlextResult.failure(f"Path is not a file: {file_path}")

            # Check file size
            file_size_mb = path.stat().st_size / (1024 * 1024)
            if file_size_mb > self.config.max_file_size_mb:
                return FlextResult.failure(
                    f"File too large: {file_size_mb:.1f}MB "
                    f"(max: {self.config.max_file_size_mb}MB)",
                )

            # Parse using core processor
            parse_result = self._core_processor.parse_file(path)
            if parse_result.is_failure:
                return parse_result

            entries = parse_result.data or []
            logger.info(f"Successfully parsed {len(entries)} entries from file: {path}")

            return FlextResult.success(entries)

        except Exception as e:
            error_msg = f"LDIF file parsing failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

    def validate(self, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate LDIF entries using business rules.

        Args:
            entries: List of FlextLdifEntry objects to validate

        Returns:
            FlextResult containing validation result (True/False) or error

        """
        try:
            logger.debug(f"Validating {len(entries)} LDIF entries")

            if not entries:
                return FlextResult.success(True)  # Empty list is valid

            # Validate each entry
            for i, entry in enumerate(entries):
                # Basic domain validation (DN and attributes are already validated)
                if not entry.dn_string:
                    return FlextResult.failure(f"Entry {i} has empty DN")

                if not entry.attributes.names:
                    if not self.config.allow_empty_attributes:
                        return FlextResult.failure(f"Entry {i} has no attributes")

                # Validate required objectClass
                if not entry.object_classes and self.config.strict_validation:
                    return FlextResult.failure(f"Entry {i} missing objectClass attribute")

            logger.info(f"Successfully validated {len(entries)} LDIF entries")
            return FlextResult.success(True)

        except Exception as e:
            error_msg = f"LDIF validation failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

    def validate_format(self, content: str) -> FlextResult[bool]:
        """Validate LDIF format compliance.

        Args:
            content: LDIF content string to validate

        Returns:
            FlextResult containing validation result (True/False) or error

        """
        try:
            logger.debug("Validating LDIF format compliance")

            # Use core processor for format validation
            validation_result = self._core_processor.validate_ldif_format(content)

            if validation_result.success:
                logger.info("LDIF format validation passed")
            else:
                logger.warning(f"LDIF format validation failed: {validation_result.error}")

            return validation_result

        except Exception as e:
            error_msg = f"LDIF format validation failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

    def write(self, entries: list[FlextLdifEntry]) -> FlextResult[str]:
        """Write entries to LDIF string format.

        Args:
            entries: List of FlextLdifEntry objects to write

        Returns:
            FlextResult containing LDIF formatted string or error

        """
        try:
            logger.debug(f"Writing {len(entries)} entries to LDIF string")

            if not entries:
                return FlextResult.success("")  # Empty list produces empty string

            # Write using core processor
            write_result = self._core_processor.write(entries)
            if write_result.is_failure:
                return write_result

            ldif_content = write_result.data or ""
            logger.info(f"Successfully wrote {len(entries)} entries to LDIF string")

            return FlextResult.success(ldif_content)

        except Exception as e:
            error_msg = f"LDIF writing failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

    def write_file(self, entries: list[FlextLdifEntry], file_path: str | Path) -> FlextResult[bool]:
        """Write entries to LDIF file.

        Args:
            entries: List of FlextLdifEntry objects to write
            file_path: Path to output LDIF file

        Returns:
            FlextResult indicating success (True) or failure

        """
        try:
            path = Path(file_path)
            logger.debug(f"Writing {len(entries)} entries to LDIF file: {path}")

            # Create output directory if configured
            if self.config.create_output_dir:
                path.parent.mkdir(parents=True, exist_ok=True)

            # Write using core processor
            write_result = self._core_processor.write_file(entries, path)
            if write_result.is_failure:
                return write_result

            logger.info(f"Successfully wrote {len(entries)} entries to file: {path}")
            return FlextResult.success(True)

        except Exception as e:
            error_msg = f"LDIF file writing failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

    def filter_by_objectclass(self, entries: list[FlextLdifEntry], objectclass: str) -> FlextResult[list[FlextLdifEntry]]:
        """Filter entries by objectClass attribute.

        Args:
            entries: List of FlextLdifEntry objects to filter
            objectclass: ObjectClass value to filter by

        Returns:
            FlextResult containing filtered list of entries or error

        """
        try:
            logger.debug(f"Filtering {len(entries)} entries by objectClass: {objectclass}")

            filtered_entries = [
                entry for entry in entries
                if entry.has_attribute_value("objectClass", objectclass)
            ]

            logger.info(f"Filtered to {len(filtered_entries)} entries with objectClass: {objectclass}")
            return FlextResult.success(filtered_entries)

        except Exception as e:
            error_msg = f"ObjectClass filtering failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

    def filter_by_attribute(self, entries: list[FlextLdifEntry], attribute: str, value: str) -> FlextResult[list[FlextLdifEntry]]:
        """Filter entries by attribute value.

        Args:
            entries: List of FlextLdifEntry objects to filter
            attribute: Attribute name to filter by
            value: Attribute value to filter by

        Returns:
            FlextResult containing filtered list of entries or error

        """
        try:
            logger.debug(f"Filtering {len(entries)} entries by {attribute}: {value}")

            filtered_entries = [
                entry for entry in entries
                if entry.has_attribute_value(attribute, value)
            ]

            logger.info(f"Filtered to {len(filtered_entries)} entries with {attribute}: {value}")
            return FlextResult.success(filtered_entries)

        except Exception as e:
            error_msg = f"Attribute filtering failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

    def find_by_dn(self, entries: list[FlextLdifEntry], dn: str) -> FlextResult[FlextLdifEntry | None]:
        """Find entry by distinguished name.

        Args:
            entries: List of FlextLdifEntry objects to search
            dn: Distinguished name to search for

        Returns:
            FlextResult containing found entry or None if not found

        """
        try:
            logger.debug(f"Searching {len(entries)} entries for DN: {dn}")

            # Normalize DN for comparison
            normalized_dn = dn.lower().replace(" ", "")

            for entry in entries:
                entry_dn_normalized = entry.dn.normalized
                if entry_dn_normalized == normalized_dn:
                    logger.info(f"Found entry with DN: {dn}")
                    return FlextResult.success(entry)

            logger.info(f"No entry found with DN: {dn}")
            return FlextResult.success(None)

        except Exception as e:
            error_msg = f"DN search failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

    def get_statistics(self, entries: list[FlextLdifEntry]) -> FlextResult[dict[str, int]]:
        """Get statistical information about entries.

        Args:
            entries: List of FlextLdifEntry objects to analyze

        Returns:
            FlextResult containing statistics dictionary or error

        """
        try:
            logger.debug(f"Generating statistics for {len(entries)} entries")

            stats = {
                "total_entries": len(entries),
                "person_entries": len([e for e in entries if e.is_person]),
                "group_entries": len([e for e in entries if e.is_group]),
                "ou_entries": len([e for e in entries if e.is_organizational_unit]),
                "other_entries": 0,
            }

            # Calculate other entries
            classified = stats["person_entries"] + stats["group_entries"] + stats["ou_entries"]
            stats["other_entries"] = stats["total_entries"] - classified

            # Calculate attribute statistics
            all_attributes = set()
            for entry in entries:
                all_attributes.update(entry.attributes.names)

            stats["unique_attributes"] = len(all_attributes)

            logger.info(f"Generated statistics for {len(entries)} entries")
            return FlextResult.success(stats)

        except Exception as e:
            error_msg = f"Statistics generation failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

    def analyze_dn_patterns(self, entries: list[FlextLdifEntry]) -> FlextResult[dict[str, int]]:
        """Analyze DN depth and pattern distribution.

        Args:
            entries: List of FlextLdifEntry objects to analyze

        Returns:
            FlextResult containing DN analysis dictionary or error

        """
        try:
            logger.debug(f"Analyzing DN patterns for {len(entries)} entries")

            depth_distribution = {}
            base_dn_distribution = {}

            for entry in entries:
                # Analyze depth
                depth = entry.dn.depth
                depth_distribution[f"depth_{depth}"] = depth_distribution.get(f"depth_{depth}", 0) + 1

                # Analyze base DN (last two components)
                components = entry.dn.components
                if len(components) >= 2:
                    base_dn = ",".join(components[-2:])
                    base_dn_distribution[base_dn] = base_dn_distribution.get(base_dn, 0) + 1

            analysis = {
                "depth_distribution": depth_distribution,
                "base_dn_distribution": base_dn_distribution,
                "avg_depth": sum(entry.dn.depth for entry in entries) / len(entries) if entries else 0,
                "max_depth": max((entry.dn.depth for entry in entries), default=0),
                "min_depth": min((entry.dn.depth for entry in entries), default=0),
            }

            logger.info(f"Completed DN pattern analysis for {len(entries)} entries")
            return FlextResult.success(analysis)

        except Exception as e:
            error_msg = f"DN pattern analysis failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

# =============================================================================
# BACKWARD COMPATIBILITY FUNCTIONS
# =============================================================================


def create_ldif_api(config: FlextLdifConfig | None = None) -> FlextLdifAPI:
    """Create LDIF API instance - convenience function."""
    return FlextLdifAPI(config)


def get_default_api() -> FlextLdifAPI:
    """Get default LDIF API instance - convenience function."""
    return FlextLdifAPI()

# =============================================================================
# PUBLIC API
# =============================================================================


__all__ = [
    # Main API class
    "FlextLdifAPI",

    # Convenience functions
    "create_ldif_api",
    "get_default_api",
]
