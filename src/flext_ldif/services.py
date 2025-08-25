"""FLEXT-LDIF Services - Consolidated Module.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Consolidated module containing analytics service, writer service, and field definitions
following flext-core consolidated patterns.
"""

from __future__ import annotations

from functools import reduce
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, cast, override

from flext_core import FlextDomainService, FlextResult, FlextValidationError, get_logger
from pydantic import Field
from pydantic.fields import FieldInfo

if TYPE_CHECKING:
    from flext_ldif.models import FlextLdifEntry

# =============================================================================
# CONSOLIDATED FIELD DEFINITIONS - Pydantic field factory functions
# =============================================================================

# DN field with validation
def dn_field(
    *,
    description: str = "Distinguished Name",
    min_length: int = 1,
    max_length: int = 1024,
) -> FieldInfo:
    """Create a DN field with standard validation."""
    return cast(
        "FieldInfo",
        Field(
            description=description,
            min_length=min_length,
            max_length=max_length,
        ),
    )


# Attribute name field
def attribute_name_field(
    *,
    description: str = "LDAP Attribute Name",
    pattern: str = r"^[a-zA-Z][a-zA-Z0-9\-]*$",
    max_length: int = 255,
) -> FieldInfo:
    """Create an attribute name field with validation."""
    return cast(
        "FieldInfo",
        Field(
            description=description,
            pattern=pattern,
            max_length=max_length,
        ),
    )


# Attribute value field
def attribute_value_field(
    *,
    description: str = "LDAP Attribute Value",
    max_length: int = 65536,
) -> FieldInfo:
    """Create an attribute value field with validation."""
    return cast(
        "FieldInfo",
        Field(
            description=description,
            max_length=max_length,
        ),
    )


# Object class field
def object_class_field(
    *,
    description: str = "LDAP Object Class",
    pattern: str = r"^[a-zA-Z][a-zA-Z0-9\-]*$",
    max_length: int = 255,
) -> FieldInfo:
    """Create an object class field with validation."""
    return cast(
        "FieldInfo",
        Field(
            description=description,
            pattern=pattern,
            max_length=max_length,
        ),
    )


# Common field constants
class FieldDefaults:
    """Default values for common field configurations."""

    DN_MAX_LENGTH: ClassVar[int] = 1024
    ATTRIBUTE_NAME_MAX_LENGTH: ClassVar[int] = 255
    ATTRIBUTE_VALUE_MAX_LENGTH: ClassVar[int] = 65536
    LDIF_LINE_MAX_LENGTH: ClassVar[int] = 76

    DN_PATTERN: ClassVar[str] = r"^[a-zA-Z][a-zA-Z0-9\-=,\s]*$"
    ATTRIBUTE_NAME_PATTERN: ClassVar[str] = r"^[a-zA-Z][a-zA-Z0-9\-]*$"


# =============================================================================
# CONSOLIDATED ANALYTICS SERVICE - Business intelligence service
# =============================================================================

logger = get_logger(__name__)


def _get_default_config() -> object:
    """Get default config instance to avoid circular imports."""
    # Import here to avoid circular dependencies
    from flext_ldif.models import FlextLdifConfig
    return FlextLdifConfig()


class FlextLdifAnalyticsService(FlextDomainService["dict[str, int]"]):
    """Concrete LDIF analytics service using flext-core patterns."""

    config: object = Field(default_factory=lambda: _get_default_config())

    @override
    def execute(self) -> FlextResult[dict[str, int]]:
        """Execute analytics operation - required by FlextDomainService."""
        # Import here to avoid circular dependencies
        from flext_ldif.constants import FlextLdifAnalyticsConstants

        # This would be called with specific entries in real usage
        return FlextResult["dict[str, int]"].ok({
            FlextLdifAnalyticsConstants.TOTAL_ENTRIES_KEY: 0
        })

    def analyze_entry_patterns(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[dict[str, int]]:
        """Analyze patterns in LDIF entries."""
        # Import here to avoid circular dependencies
        from flext_ldif.constants import FlextLdifAnalyticsConstants

        patterns = {
            FlextLdifAnalyticsConstants.TOTAL_ENTRIES_KEY: len(entries),
            FlextLdifAnalyticsConstants.ENTRIES_WITH_CN_KEY: 0,
            FlextLdifAnalyticsConstants.ENTRIES_WITH_MAIL_KEY: 0,
            FlextLdifAnalyticsConstants.ENTRIES_WITH_TELEPHONE_KEY: 0,
        }

        for entry in entries:
            if entry.has_attribute(FlextLdifAnalyticsConstants.CN_ATTRIBUTE):
                patterns[FlextLdifAnalyticsConstants.ENTRIES_WITH_CN_KEY] += 1
            if entry.has_attribute(FlextLdifAnalyticsConstants.MAIL_ATTRIBUTE):
                patterns[FlextLdifAnalyticsConstants.ENTRIES_WITH_MAIL_KEY] += 1
            if entry.has_attribute(FlextLdifAnalyticsConstants.TELEPHONE_ATTRIBUTE):
                patterns[FlextLdifAnalyticsConstants.ENTRIES_WITH_TELEPHONE_KEY] += 1

        return FlextResult["dict[str, int]"].ok(patterns)

    def get_objectclass_distribution(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[dict[str, int]]:
        """Get distribution of objectClass types."""
        distribution: dict[str, int] = {}

        for entry in entries:
            object_classes = entry.get_object_classes()
            for obj_class in object_classes:
                distribution[obj_class] = distribution.get(obj_class, 0) + 1

        return FlextResult["dict[str, int]"].ok(distribution)

    def get_dn_depth_analysis(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[dict[str, int]]:
        """Analyze DN depth distribution."""
        # Import here to avoid circular dependencies
        from flext_ldif.constants import FlextLdifAnalyticsConstants

        depth_analysis: dict[str, int] = {}

        for entry in entries:
            depth = entry.dn.get_depth()
            depth_key = FlextLdifAnalyticsConstants.DEPTH_KEY_FORMAT.format(depth=depth)
            depth_analysis[depth_key] = depth_analysis.get(depth_key, 0) + 1

        return FlextResult["dict[str, int]"].ok(depth_analysis)


# =============================================================================
# CONSOLIDATED WRITER SERVICE - LDIF output service
# =============================================================================


class FlextLdifWriterService(FlextDomainService["str"]):
    """Concrete LDIF writing service using flext-core patterns."""

    config: object = Field(default=None)

    @override
    def execute(self) -> FlextResult[str]:
        """Execute writing operation - required by FlextDomainService."""
        # This would be called with specific entries in real usage
        return FlextResult["str"].ok("")

    def write(self, entries: list[FlextLdifEntry]) -> FlextResult[str]:
        """Write entries to LDIF string."""
        # Import here to avoid circular dependencies
        from flext_ldif.constants import FlextLdifCoreMessages

        if not entries:
            return FlextResult["str"].ok("")

        try:
            ldif_blocks = [entry.to_ldif() for entry in entries]
            return FlextResult["str"].ok("\n".join(ldif_blocks))

        except (ValueError, AttributeError, TypeError) as e:
            return FlextResult["str"].fail(
                FlextLdifCoreMessages.WRITE_FAILED.format(error=str(e)),
            )

    def write_file(
        self,
        entries: list[FlextLdifEntry],
        file_path: str | Path,
        encoding: str = "utf-8",
    ) -> FlextResult[bool]:
        """Write entries to LDIF file."""
        try:
            # Use railway programming for content generation
            return self.write(entries).flat_map(
                lambda content: self._write_content_to_file(
                    content, file_path, encoding
                )
            )
        except Exception as e:
            # Import here to avoid circular dependencies
            from flext_ldif.constants import FlextLdifCoreMessages

            return FlextResult["bool"].fail(
                FlextLdifCoreMessages.FILE_WRITE_FAILED.format(error=str(e))
            )

    def _write_content_to_file(
        self, content: str, file_path: Path | str, encoding: str
    ) -> FlextResult[bool]:
        """Write content to file with proper error handling."""
        try:
            # Import here to avoid circular dependencies
            from flext_ldif.constants import FlextLdifCoreMessages

            path_obj = Path(file_path)
            # If parent is root and creation is requested, simulate permission error
            try:
                path_obj.parent.mkdir(parents=True, exist_ok=True)
            except PermissionError as e:
                return FlextResult["bool"].fail(
                    FlextLdifCoreMessages.FILE_WRITE_FAILED.format(error=str(e)),
                )
            path_obj.write_text(content, encoding=encoding)

            return FlextResult["bool"].ok(True)

        except (OSError, UnicodeError) as e:
            # Import here to avoid circular dependencies
            from flext_ldif.constants import FlextLdifCoreMessages

            return FlextResult["bool"].fail(
                FlextLdifCoreMessages.FILE_WRITE_FAILED.format(error=str(e)),
            )

    def write_entry(self, entry: FlextLdifEntry) -> FlextResult[str]:
        """Write single entry to LDIF string."""
        try:
            return FlextResult["str"].ok(entry.to_ldif())
        except (ValueError, AttributeError, TypeError) as e:
            # Import here to avoid circular dependencies
            from flext_ldif.constants import FlextLdifCoreMessages

            return FlextResult["str"].fail(
                FlextLdifCoreMessages.WRITE_FAILED.format(error=str(e)),
            )


# =============================================================================
# CONSOLIDATED REPOSITORY SERVICE - Data access and querying
# =============================================================================


class FlextLdifRepositoryService(FlextDomainService["dict[str, int]"]):
    """Concrete LDIF repository service using flext-core patterns."""

    config: object = Field(default=None)

    @override
    def execute(self) -> FlextResult[dict[str, int]]:
        """Execute repository operation - required by FlextDomainService."""
        # This would be called with specific queries in real usage
        return FlextResult["dict[str, int]"].ok({})

    def find_by_dn(
        self,
        entries: list[FlextLdifEntry],
        dn: str,
    ) -> FlextResult[FlextLdifEntry | None]:
        """Find entry by distinguished name."""
        # Import here to avoid circular dependencies
        from flext_ldif.constants import FlextLdifValidationMessages

        if not dn or not dn.strip():
            return FlextResult["FlextLdifEntry | None"].fail(
                FlextLdifValidationMessages.DN_EMPTY_ERROR
            )

        dn_lower = dn.lower()
        for entry in entries:
            if entry.dn.value.lower() == dn_lower:
                return FlextResult["FlextLdifEntry | None"].ok(entry)

        return FlextResult["FlextLdifEntry | None"].ok(None)

    def filter_by_objectclass(
        self,
        entries: list[FlextLdifEntry],
        objectclass: str,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter entries by objectClass attribute."""
        # Import here to avoid circular dependencies
        from flext_ldif.constants import FlextLdifCoreMessages

        if not objectclass or not objectclass.strip():
            return FlextResult["list[FlextLdifEntry]"].fail(
                FlextLdifCoreMessages.MISSING_OBJECTCLASS
            )

        filtered = [entry for entry in entries if entry.has_object_class(objectclass)]
        return FlextResult["list[FlextLdifEntry]"].ok(filtered)

    def filter_by_attribute(
        self,
        entries: list[FlextLdifEntry],
        attribute: str,
        value: str,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter entries by attribute value."""
        # Import here to avoid circular dependencies
        from flext_ldif.constants import FlextLdifCoreMessages

        if not attribute or not attribute.strip():
            return FlextResult["list[FlextLdifEntry]"].fail(
                FlextLdifCoreMessages.INVALID_ATTRIBUTE_NAME.format(
                    attr_name="attribute",
                ),
            )

        filtered: list[FlextLdifEntry] = []
        for entry in entries:
            attr_values = entry.get_attribute(attribute)
            if attr_values and value in attr_values:
                filtered.append(entry)

        return FlextResult["list[FlextLdifEntry]"].ok(filtered)

    def get_statistics(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[dict[str, int]]:
        """Get statistical information about entries."""
        stats = {
            "total_entries": len(entries),
            "person_entries": 0,
            "group_entries": 0,
            "other_entries": 0,
        }

        for entry in entries:
            if entry.is_person_entry():
                stats["person_entries"] += 1
            elif entry.is_group_entry():
                stats["group_entries"] += 1
            else:
                stats["other_entries"] += 1

        return FlextResult["dict[str, int]"].ok(stats)


# =============================================================================
# CONSOLIDATED VALIDATOR SERVICE - Business rule validation
# =============================================================================


class FlextLdifValidatorService(FlextDomainService["bool"]):
    """Validate LDIF entries applying business and configuration rules.

    This service implements validation logic for LDIF objects following
    Clean Architecture and flext-core patterns.
    """

    config: object = Field(default=None)

    @override
    def execute(self) -> FlextResult[bool]:
        """Execute validation operation.

        Performs a no-op sanity check of the configured rules. This method is
        intentionally lightweight and delegates real validation work to
        validate_entry/validate_entries.

        Returns:
            FlextResult[bool]: Success if configuration is valid.

        """
        # If a config is present, validate its business rules
        if self.config is not None:
            cfg_validation = self.config.validate_business_rules()
            if cfg_validation.is_failure:
                # Import here to avoid circular dependencies
                from flext_ldif.constants import FlextLdifValidationMessages

                return FlextResult["bool"].fail(
                    cfg_validation.error
                    or FlextLdifValidationMessages.INVALID_CONFIGURATION
                )
        return FlextResult["bool"].ok(True)

    def validate_data(self, data: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate a list of LDIF entries.

        Args:
            data: Entries to validate.

        Returns:
            FlextResult[bool]: Success if all entries are valid.

        """
        return self.validate_entries(data)

    def validate_entry(self, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Validate a single LDIF entry.

        Args:
            entry: Entry to validate.

        Returns:
            FlextResult[bool]: Success if the entry is valid; otherwise failure with message.

        """
        business_result = entry.validate_business_rules()
        if business_result.is_failure:
            return FlextResult["bool"].fail(
                business_result.error or "Business rules validation failed"
            )

        return self._validate_configuration_rules(entry)

    def _validate_configuration_rules(self, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Validate configuration-specific rules for an entry."""
        # Import here to avoid circular dependencies
        from flext_ldif.constants import FlextLdifValidationMessages

        # Enforce configuration-driven rules
        if (
            self.config is not None
            and getattr(self.config, "strict_validation", False)
            and not getattr(self.config, "allow_empty_attributes", True)
        ):
            # Empty attribute lists are not allowed in strict mode
            for attr_name, values in entry.attributes.attributes.items():
                if len(values) == 0:
                    return FlextResult["bool"].fail(
                        FlextLdifValidationMessages.EMPTY_ATTRIBUTES_NOT_ALLOWED.format(
                            attr_name=attr_name,
                        ),
                    )
                # Also disallow empty-string values strictly
                if any(isinstance(v, str) and v.strip() == "" for v in values):
                    return FlextResult["bool"].fail(
                        FlextLdifValidationMessages.EMPTY_ATTRIBUTE_VALUE_NOT_ALLOWED.format(
                            attr_name=attr_name,
                        ),
                    )
        return FlextResult["bool"].ok(True)

    def validate_ldif_entries(self, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate multiple LDIF entries - main public interface.

        Args:
            entries: Entries to validate.

        Returns:
            FlextResult[bool]: Success if all entries are valid.

        """
        return self.validate_entries(entries)

    def validate_entries(self, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate multiple LDIF entries.

        Args:
            entries: Entries to validate.

        Returns:
            FlextResult[bool]: Success if all entries are valid.

        """

        def validate_entry_with_index(
            indexed_entry: tuple[int, FlextLdifEntry],
        ) -> FlextResult[bool]:
            # Import here to avoid circular dependencies
            from flext_ldif.constants import FlextLdifValidationMessages

            i, entry = indexed_entry
            entry_result = self.validate_entry(entry)
            if entry_result.is_failure:
                return FlextResult["bool"].fail(
                    f"Entry {i} {FlextLdifValidationMessages.ENTRY_VALIDATION_FAILED.lower()}: {entry_result.error}"
                )
            return entry_result

        # Use reduce to chain validations

        def chain_validations(
            acc: FlextResult[bool], indexed_entry: tuple[int, FlextLdifEntry]
        ) -> FlextResult[bool]:
            return acc.flat_map(lambda _: validate_entry_with_index(indexed_entry))

        return reduce(
            chain_validations,
            enumerate(entries),
            FlextResult["bool"].ok(True),
        )

    def validate_dn_format(self, dn: str) -> FlextResult[bool]:
        """Validate DN format compliance.

        Args:
            dn: Distinguished Name string to validate.

        Returns:
            FlextResult[bool]: Validation result from the consolidated validator.

        """
        # Import here to avoid circular dependencies
        from flext_ldif.format_validator_service import LdifValidator

        # Delegate to consolidated validation that uses flext-ldap APIs
        return LdifValidator.validate_dn(dn)


# =============================================================================
# CONSOLIDATED PARSER SERVICE - LDIF content parsing
# =============================================================================


class FlextLdifParserService(FlextDomainService["list[FlextLdifEntry]"]):
    """Concrete LDIF parsing service using flext-core patterns."""

    config: object = Field(default=None)

    @override
    def execute(self) -> FlextResult[list[FlextLdifEntry]]:
        """Execute the default parsing operation.

        Returns:
            FlextResult[list[FlextLdifEntry]]: Always returns an empty list in
            this implementation. Real executions should call `parse()` with
            concrete content or use `parse_ldif_file()`.

        """
        # This would be called with specific content in real usage
        return FlextResult["list[FlextLdifEntry]"].ok([])

    def parse(self, content: str | object) -> FlextResult[list[FlextLdifEntry]]:
        """Parse raw LDIF content into domain entities.

        Args:
            content: Raw LDIF text. Non-string values result in a failure.

        Returns:
            FlextResult[list[FlextLdifEntry]]: Parsed entries on success. For
            empty or whitespace-only content, returns success with an empty
            list. On parse errors, returns failure with context.

        """
        # Import here to avoid circular dependencies
        from flext_ldif.constants import (
            FlextLdifCoreMessages,
            FlextLdifValidationMessages,
        )

        if not isinstance(content, str):
            return FlextResult["list[FlextLdifEntry]"].fail(
                FlextLdifCoreMessages.INVALID_DN_FORMAT.replace("{dn}", "content type"),
            )
        if not content or not content.strip():
            return FlextResult["list[FlextLdifEntry]"].ok([])

        try:
            entries: list[FlextLdifEntry] = []
            entry_blocks = content.strip().split("\n\n")
            failed_blocks: list[str] = []

            for block in entry_blocks:
                if not block.strip():
                    continue

                # Use railway programming for entry parsing
                def handle_success(entry: FlextLdifEntry) -> None:
                    entries.append(entry)

                def handle_error(error: str) -> None:
                    logger.warning(
                        FlextLdifCoreMessages.PARSE_FAILED.format(error=error)
                    )
                    failed_blocks.append(error or "Unknown parse error")

                self._parse_entry_block(block.strip()).tap(handle_success).tap_error(
                    handle_error
                )

            # If we have content but no successful entries, it's invalid LDIF
            non_empty_blocks = [b for b in entry_blocks if b.strip()]
            if non_empty_blocks and not entries:
                return FlextResult["list[FlextLdifEntry]"].fail(
                    FlextLdifValidationMessages.INVALID_LDIF_FORMAT
                    + f": {len(failed_blocks)} blocks failed to parse",
                )

            return FlextResult["list[FlextLdifEntry]"].ok(entries)

        except (ValueError, AttributeError, TypeError) as e:
            return FlextResult["list[FlextLdifEntry]"].fail(
                FlextLdifCoreMessages.PARSE_FAILED.format(error=str(e)),
            )

    def parse_ldif_file(
        self,
        file_path: str | Path,
        encoding: str = "utf-8",
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Parse an LDIF file into domain entities.

        Args:
            file_path: Path to the LDIF file to read.
            encoding: Text encoding used to read the file.

        Returns:
            FlextResult[list[FlextLdifEntry]]: Parsed entries on success, or
            failure when the file cannot be read or parsed.

        """
        try:
            # Import here to avoid circular dependencies
            from flext_ldif.constants import FlextLdifCoreMessages

            path_obj = Path(file_path)
            if not path_obj.exists():
                return FlextResult["list[FlextLdifEntry]"].fail(
                    FlextLdifCoreMessages.FILE_NOT_FOUND.format(file_path=file_path),
                )

            content = path_obj.read_text(encoding=encoding)
            return self.parse(content)

        except (OSError, UnicodeError) as e:
            # Import here to avoid circular dependencies
            from flext_ldif.constants import FlextLdifCoreMessages

            return FlextResult["list[FlextLdifEntry]"].fail(
                FlextLdifCoreMessages.FILE_READ_FAILED.format(error=str(e)),
            )

    def parse_entries_from_string(
        self,
        ldif_string: str,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Parse multiple entries from a single LDIF string.

        This is a thin wrapper over `parse()` provided for clarity in callers
        that already distinguish entry-oriented inputs.

        Args:
            ldif_string: Raw LDIF text containing one or more entries.

        Returns:
            FlextResult[list[FlextLdifEntry]]: Parsed entries or failure.

        """
        return self.parse(ldif_string)

    def _parse_entry_block(self, block: str) -> FlextResult[FlextLdifEntry]:
        """Parse a single LDIF entry block.

        Args:
            block: A contiguous block of LDIF lines representing one entry.

        Returns:
            FlextResult[FlextLdifEntry]: The parsed entry on success, or a
            failure with a descriptive reason when the block is invalid.

        """
        # Import here to avoid circular dependencies
        from flext_ldif.constants import FlextLdifValidationMessages

        if not block.strip():
            return FlextResult["FlextLdifEntry"].fail(
                FlextLdifValidationMessages.ENTRY_VALIDATION_FAILED
            )

        lines = block.split("\n")
        if not lines:
            return FlextResult["FlextLdifEntry"].fail(
                FlextLdifValidationMessages.ENTRY_VALIDATION_FAILED
            )

        # Parse DN from first line
        dn_line = lines[0].strip()
        if not dn_line.startswith("dn:"):
            return FlextResult["FlextLdifEntry"].fail(
                FlextLdifValidationMessages.RECORD_MISSING_DN
            )

        dn = dn_line[3:].strip()
        if not dn:
            return FlextResult["FlextLdifEntry"].fail(
                FlextLdifValidationMessages.DN_EMPTY_ERROR
            )

        # Parse attributes
        attributes: dict[str, list[str]] = {}
        changetype = None

        for raw_line in lines[1:]:
            line = raw_line.strip()
            if not line or ":" not in line:
                continue

            attr_name, attr_value = line.split(":", 1)
            attr_name = attr_name.strip()
            attr_value = attr_value.strip()

            if attr_name == "changetype":
                changetype = attr_value
                continue

            if attr_name not in attributes:
                attributes[attr_name] = []
            attributes[attr_name].append(attr_value)

        # Create entry with proper error handling
        try:
            # Import here to avoid circular dependencies
            from flext_ldif.models import FlextLdifFactory

            return FlextLdifFactory.create_entry(dn, attributes, changetype)
        except (ValueError, FlextValidationError) as e:
            return FlextResult["FlextLdifEntry"].fail(str(e))


# =============================================================================
# CONSOLIDATED EXPORTS - All services and fields from this module
# =============================================================================

__all__ = [
    # Field Definitions
    "FieldDefaults",
    "attribute_name_field",
    "attribute_value_field",
    "dn_field",
    "object_class_field",

    # Analytics Service
    "FlextLdifAnalyticsService",

    # Writer Service
    "FlextLdifWriterService",

    # Repository Service
    "FlextLdifRepositoryService",

    # Validator Service
    "FlextLdifValidatorService",

    # Parser Service
    "FlextLdifParserService",
]

# Note: Forward references will be resolved when models are imported
