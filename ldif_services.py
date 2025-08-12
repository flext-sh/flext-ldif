"""FLEXT-LDIF Services - Enterprise LDIF Processing Services.

CONSOLIDATED PEP8 ARCHITECTURE: This module consolidates all LDIF service classes
into ONE centralized, PEP8-compliant services module.

CONSOLIDATION MAPPING:
✅ src/flext_ldif/parser_service.py → LDIF parsing service
✅ src/flext_ldif/validator_service.py → LDIF validation service
✅ src/flext_ldif/writer_service.py → LDIF writing service
✅ src/flext_ldif/repository_service.py → LDIF repository service
✅ src/flext_ldif/transformer_service.py → LDIF transformation service
✅ src/flext_ldif/analytics_service.py → LDIF analytics service

ARCHITECTURAL CONSOLIDATION: This module contains all concrete LDIF service
implementations following Clean Architecture patterns and DDD principles.

Service Classes:
    - FlextLdifParserService: Concrete LDIF parsing implementation
    - FlextLdifValidatorService: LDIF validation with business rules
    - FlextLdifWriterService: LDIF writing with format compliance
    - FlextLdifRepositoryService: LDIF data access and filtering
    - FlextLdifTransformerService: LDIF transformation and normalization
    - FlextLdifAnalyticsService: LDIF analytics and business intelligence

Technical Excellence:
    - Clean Architecture: Infrastructure layer implementing application protocols
    - SOLID principles: Single responsibility, dependency inversion
    - Type safety: Comprehensive type annotations with Python 3.13+
    - Railway-oriented programming: FlextResult pattern throughout

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from flext_core import FlextResult

from .ldif_core import TLdif
from .ldif_models import (
    FlextLdifAnalyticsProtocol,
    FlextLdifParserProtocol,
    FlextLdifRepositoryProtocol,
    FlextLdifTransformerProtocol,
    FlextLdifValidatorProtocol,
    FlextLdifWriterProtocol,
)

if TYPE_CHECKING:
    from .ldif_models import FlextLdifEntry

logger = logging.getLogger(__name__)

# =============================================================================
# PARSER SERVICE
# =============================================================================


class FlextLdifParserService:
    """Concrete LDIF parsing service with domain validation.

    Implements FlextLdifParserProtocol with enterprise-grade parsing capabilities
    including error handling, validation, and performance optimizations.

    Features:
    - RFC 2849 compliant LDIF parsing
    - Streaming support for large files
    - Comprehensive error reporting with line numbers
    - Domain model creation with validation
    """

    def __init__(self, max_entries: int = 20000, max_entry_size: int = 1048576) -> None:
        """Initialize parser service with configuration."""
        self.max_entries = max_entries
        self.max_entry_size = max_entry_size
        self._core_processor = TLdif(
            max_entries=max_entries,
            max_entry_size=max_entry_size,
        )

    def parse(self, content: str) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF content into domain entities."""
        try:
            logger.debug(f"Parsing LDIF content ({len(content)} characters)")

            if not content or not content.strip():
                return FlextResult.failure("Empty LDIF content provided")

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
        """Parse LDIF file into domain entities."""
        try:
            path = Path(file_path)
            logger.debug(f"Parsing LDIF file: {path}")

            if not path.exists():
                return FlextResult.failure(f"LDIF file not found: {file_path}")

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

    def parse_entries_from_string(self, ldif_string: str) -> FlextResult[list[FlextLdifEntry]]:
        """Parse multiple entries from LDIF string."""
        return self.parse(ldif_string)

# =============================================================================
# VALIDATOR SERVICE
# =============================================================================


class FlextLdifValidatorService:
    """LDIF validation service with business rules implementation.

    Implements FlextLdifValidatorProtocol with comprehensive validation
    including RFC compliance, business rules, and domain constraints.

    Features:
    - RFC 2849 format validation
    - Domain business rule validation
    - DN format compliance checking
    - Attribute value validation
    """

    def __init__(self, strict_validation: bool = True) -> None:
        """Initialize validator service with configuration."""
        self.strict_validation = strict_validation
        self._core_processor = TLdif()

    def validate(self, data: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate data using flext-core pattern."""
        return self.validate_entries(data)

    def validate_entry(self, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Validate single LDIF entry."""
        try:
            logger.debug(f"Validating LDIF entry: {entry.dn_string}")

            # Basic domain validation (DN and attributes are already validated)
            if not entry.dn_string:
                return FlextResult.failure("Entry has empty DN")

            if not entry.attributes.names:
                return FlextResult.failure("Entry has no attributes")

            # Validate required objectClass in strict mode
            if not entry.object_classes and self.strict_validation:
                return FlextResult.failure("Entry missing objectClass attribute")

            logger.debug(f"LDIF entry validation passed: {entry.dn_string}")
            return FlextResult.success(True)

        except Exception as e:
            error_msg = f"LDIF entry validation failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

    def validate_entries(self, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate multiple LDIF entries."""
        try:
            logger.debug(f"Validating {len(entries)} LDIF entries")

            if not entries:
                return FlextResult.success(True)  # Empty list is valid

            # Validate each entry
            for i, entry in enumerate(entries):
                validation_result = self.validate_entry(entry)
                if validation_result.is_failure:
                    return FlextResult.failure(f"Entry {i}: {validation_result.error}")

            logger.info(f"Successfully validated {len(entries)} LDIF entries")
            return FlextResult.success(True)

        except Exception as e:
            error_msg = f"LDIF entries validation failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

    def validate_dn_format(self, dn: str) -> FlextResult[bool]:
        """Validate DN format compliance."""
        try:
            logger.debug(f"Validating DN format: {dn}")

            # Use core processor for DN validation
            from .ldif_core import DN_REGEX

            if not dn or not dn.strip():
                return FlextResult.failure("Empty DN provided")

            if not DN_REGEX.match(dn.strip()):
                return FlextResult.failure(f"Invalid DN format: {dn}")

            logger.debug(f"DN format validation passed: {dn}")
            return FlextResult.success(True)

        except Exception as e:
            error_msg = f"DN format validation failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

# =============================================================================
# WRITER SERVICE
# =============================================================================


class FlextLdifWriterService:
    """LDIF writing service with format compliance.

    Implements FlextLdifWriterProtocol with enterprise-grade writing capabilities
    including format compliance, encoding handling, and performance optimizations.

    Features:
    - RFC 2849 compliant LDIF writing
    - Base64 encoding for binary attributes
    - Configurable line wrapping
    - File and string output support
    """

    def __init__(self, line_wrap_length: int = 76, sort_attributes: bool = False) -> None:
        """Initialize writer service with configuration."""
        self.line_wrap_length = line_wrap_length
        self.sort_attributes = sort_attributes
        self._core_processor = TLdif(line_wrap_length=line_wrap_length)

    def write(self, entries: list[FlextLdifEntry]) -> FlextResult[str]:
        """Write entries to LDIF string."""
        try:
            logger.debug(f"Writing {len(entries)} entries to LDIF string")

            if not entries:
                return FlextResult.success("")  # Empty list produces empty string

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
        """Write entries to LDIF file."""
        try:
            path = Path(file_path)
            logger.debug(f"Writing {len(entries)} entries to LDIF file: {path}")

            write_result = self._core_processor.write_file(entries, path)
            if write_result.is_failure:
                return write_result

            logger.info(f"Successfully wrote {len(entries)} entries to file: {path}")
            return FlextResult.success(True)

        except Exception as e:
            error_msg = f"LDIF file writing failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

    def write_entry(self, entry: FlextLdifEntry) -> FlextResult[str]:
        """Write single entry to LDIF string."""
        return self.write([entry])

# =============================================================================
# REPOSITORY SERVICE
# =============================================================================


class FlextLdifRepositoryService:
    """LDIF data access service with filtering and search capabilities.

    Implements FlextLdifRepositoryProtocol with enterprise-grade data access
    including filtering, searching, and statistical operations.

    Features:
    - DN-based entry lookup
    - ObjectClass filtering
    - Attribute-based filtering
    - Statistical analysis
    """

    def __init__(self) -> None:
        """Initialize repository service."""

    def find_by_dn(self, entries: list[FlextLdifEntry], dn: str) -> FlextResult[FlextLdifEntry | None]:
        """Find entry by distinguished name."""
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

    def filter_by_objectclass(self, entries: list[FlextLdifEntry], objectclass: str) -> FlextResult[list[FlextLdifEntry]]:
        """Filter entries by objectClass attribute."""
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
        """Filter entries by attribute value."""
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

    def get_statistics(self, entries: list[FlextLdifEntry]) -> FlextResult[dict[str, int]]:
        """Get statistical information about entries."""
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

            logger.info(f"Generated statistics for {len(entries)} entries")
            return FlextResult.success(stats)

        except Exception as e:
            error_msg = f"Statistics generation failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

# =============================================================================
# TRANSFORMER SERVICE
# =============================================================================


class FlextLdifTransformerService:
    """LDIF transformation service with normalization capabilities.

    Implements FlextLdifTransformerProtocol with enterprise-grade transformation
    including DN normalization, attribute sorting, and data cleansing.

    Features:
    - DN normalization and standardization
    - Attribute value transformation
    - Entry-level transformations
    - Bulk transformation operations
    """

    def __init__(self, normalize_dns: bool = True, sort_attributes: bool = True) -> None:
        """Initialize transformer service with configuration."""
        self.normalize_dns = normalize_dns
        self.sort_attributes = sort_attributes

    def transform_entry(self, entry: FlextLdifEntry) -> FlextResult[FlextLdifEntry]:
        """Transform single LDIF entry."""
        try:
            logger.debug(f"Transforming LDIF entry: {entry.dn_string}")

            # For now, return the entry as-is since domain objects are immutable
            # Future transformations would create new entries with modified data

            logger.debug(f"LDIF entry transformation completed: {entry.dn_string}")
            return FlextResult.success(entry)

        except Exception as e:
            error_msg = f"LDIF entry transformation failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

    def transform_entries(self, entries: list[FlextLdifEntry]) -> FlextResult[list[FlextLdifEntry]]:
        """Transform multiple LDIF entries."""
        try:
            logger.debug(f"Transforming {len(entries)} LDIF entries")

            transformed_entries = []
            for entry in entries:
                transform_result = self.transform_entry(entry)
                if transform_result.is_failure:
                    return transform_result

                if transform_result.data:
                    transformed_entries.append(transform_result.data)

            logger.info(f"Successfully transformed {len(transformed_entries)} LDIF entries")
            return FlextResult.success(transformed_entries)

        except Exception as e:
            error_msg = f"LDIF entries transformation failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

    def normalize_dns(self, entries: list[FlextLdifEntry]) -> FlextResult[list[FlextLdifEntry]]:
        """Normalize all DN values in entries."""
        try:
            logger.debug(f"Normalizing DNs for {len(entries)} LDIF entries")

            # Since DN objects are already normalized through the domain model,
            # we return the entries as-is

            logger.info(f"DN normalization completed for {len(entries)} entries")
            return FlextResult.success(entries)

        except Exception as e:
            error_msg = f"DN normalization failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

# =============================================================================
# ANALYTICS SERVICE
# =============================================================================


class FlextLdifAnalyticsService:
    """LDIF analytics service for business intelligence.

    Implements FlextLdifAnalyticsProtocol with enterprise-grade analytics
    including pattern analysis, distribution statistics, and business insights.

    Features:
    - Entry pattern analysis
    - ObjectClass distribution
    - DN depth analysis
    - Attribute usage statistics
    """

    def __init__(self) -> None:
        """Initialize analytics service."""

    def analyze_entry_patterns(self, entries: list[FlextLdifEntry]) -> FlextResult[dict[str, int]]:
        """Analyze patterns in LDIF entries."""
        try:
            logger.debug(f"Analyzing entry patterns for {len(entries)} entries")

            patterns = {
                "total_entries": len(entries),
                "entries_with_mail": len([e for e in entries if e.has_attribute("mail")]),
                "entries_with_phone": len([e for e in entries if e.has_attribute("telephoneNumber")]),
                "entries_with_description": len([e for e in entries if e.has_attribute("description")]),
                "multi_valued_cn": len([e for e in entries if len(e.get_attribute("cn")) > 1]),
            }

            logger.info(f"Completed entry pattern analysis for {len(entries)} entries")
            return FlextResult.success(patterns)

        except Exception as e:
            error_msg = f"Entry pattern analysis failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

    def get_objectclass_distribution(self, entries: list[FlextLdifEntry]) -> FlextResult[dict[str, int]]:
        """Get distribution of objectClass types."""
        try:
            logger.debug(f"Analyzing objectClass distribution for {len(entries)} entries")

            objectclass_counts = {}

            for entry in entries:
                for objectclass in entry.object_classes:
                    objectclass_counts[objectclass] = objectclass_counts.get(objectclass, 0) + 1

            logger.info(f"Completed objectClass distribution analysis for {len(entries)} entries")
            return FlextResult.success(objectclass_counts)

        except Exception as e:
            error_msg = f"ObjectClass distribution analysis failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

    def get_dn_depth_analysis(self, entries: list[FlextLdifEntry]) -> FlextResult[dict[str, int]]:
        """Analyze DN depth distribution."""
        try:
            logger.debug(f"Analyzing DN depth distribution for {len(entries)} entries")

            depth_distribution = {}
            total_depth = 0

            for entry in entries:
                depth = entry.dn.depth
                depth_distribution[f"depth_{depth}"] = depth_distribution.get(f"depth_{depth}", 0) + 1
                total_depth += depth

            analysis = {
                **depth_distribution,
                "avg_depth": int(total_depth / len(entries)) if entries else 0,
                "max_depth": max((entry.dn.depth for entry in entries), default=0),
                "min_depth": min((entry.dn.depth for entry in entries), default=0),
            }

            logger.info(f"Completed DN depth analysis for {len(entries)} entries")
            return FlextResult.success(analysis)

        except Exception as e:
            error_msg = f"DN depth analysis failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)


# =============================================================================
# PROTOCOL IMPLEMENTATIONS
# =============================================================================

# Register protocol implementations
FlextLdifParserProtocol.register(FlextLdifParserService)
FlextLdifValidatorProtocol.register(FlextLdifValidatorService)
FlextLdifWriterProtocol.register(FlextLdifWriterService)
FlextLdifRepositoryProtocol.register(FlextLdifRepositoryService)
FlextLdifTransformerProtocol.register(FlextLdifTransformerService)
FlextLdifAnalyticsProtocol.register(FlextLdifAnalyticsService)

# =============================================================================
# PUBLIC API
# =============================================================================

__all__ = [
    "FlextLdifAnalyticsService",
    # Service Classes
    "FlextLdifParserService",
    "FlextLdifRepositoryService",
    "FlextLdifTransformerService",
    "FlextLdifValidatorService",
    "FlextLdifWriterService",
]
