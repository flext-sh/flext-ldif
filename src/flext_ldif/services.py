"""FLEXT-LDIF Services - Consolidated Class Structure.

Single consolidated class containing ALL LDIF services following FLEXT patterns.
Individual services available as nested classes for organization.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar, cast, override

from flext_core import (
    FlextDomainService,
    FlextModels,
    FlextResult,
)
from pydantic import Field
from pydantic.fields import FieldInfo

# Import models needed at runtime
from flext_ldif.models import FlextLDIFEntry, FlextLDIFModels

# Constants for boolean literals
SUCCESS_VALUE = True


# =============================================================================
# FIELD UTILITY FUNCTIONS - Pydantic field factory functions
# =============================================================================


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


# =============================================================================
# CONSOLIDATED SERVICES CLASS - Single class containing ALL LDIF services
# =============================================================================


class FlextLDIFServices(FlextModels):
    """Single consolidated class containing ALL LDIF services.

    Consolidates ALL service operations into one class following FLEXT patterns.
    Individual services available as nested classes for organization.
    """

    class FieldDefaults:
        """Default values for common field configurations."""

        DN_MIN_LENGTH: ClassVar[int] = 3
        DN_MAX_LENGTH: ClassVar[int] = 1024
        ATTRIBUTE_NAME_MAX_LENGTH: ClassVar[int] = 255
        ATTRIBUTE_VALUE_MAX_LENGTH: ClassVar[int] = 65536
        OBJECT_CLASS_MAX_LENGTH: ClassVar[int] = 255

        # LDIF format defaults
        LINE_MAX_LENGTH: ClassVar[int] = 76
        LDIF_LINE_MAX_LENGTH: ClassVar[int] = 76  # Alias for backward compatibility
        ENCODING: ClassVar[str] = "utf-8"
        LINE_SEPARATOR: ClassVar[str] = "\n"

        # Pattern constants
        DN_PATTERN: ClassVar[str] = r"^[a-zA-Z][a-zA-Z0-9\-=,\s]*$"
        ATTRIBUTE_NAME_PATTERN: ClassVar[str] = r"^[a-zA-Z][a-zA-Z0-9\-]*$"

        # Processing defaults
        DEFAULT_BATCH_SIZE: ClassVar[int] = 1000
        DEFAULT_TIMEOUT: ClassVar[int] = 30
        MAX_ENTRIES_DEFAULT: ClassVar[int] = 10000

    class AnalyticsService(FlextDomainService[dict[str, int]]):
        """Analytics service for LDIF processing metrics."""

        def __init__(
            self, entries: list[FlextLDIFEntry] | None = None, config: object = None
        ) -> None:
            # Import here to avoid circular imports
            from flext_ldif.models import FlextLDIFModels

            super().__init__()
            self._entries = entries or []
            self._config = config or FlextLDIFModels.Config()

        @property
        def entries(self) -> list[FlextLDIFEntry]:
            return self._entries

        @property
        def config(self) -> object:
            return self._config

        @override
        def execute(self) -> FlextResult[dict[str, int]]:
            """Execute analytics operation - required by FlextDomainService."""
            if not self.entries:
                # Use standard default metrics
                default_metrics = {"total_entries": 0}
                return FlextResult[dict[str, int]].ok(default_metrics)

            return self.analyze_patterns(self.entries)

        def analyze_patterns(
            self, entries: list[FlextLDIFEntry]
        ) -> FlextResult[dict[str, int]]:
            """Analyze patterns in LDIF entries."""
            from flext_ldif.constants import FlextLDIFAnalyticsConstants

            patterns = {
                FlextLDIFAnalyticsConstants.TOTAL_ENTRIES_KEY: len(entries),
                FlextLDIFAnalyticsConstants.ENTRIES_WITH_CN_KEY: sum(
                    1
                    for entry in entries
                    if entry.has_attribute(FlextLDIFAnalyticsConstants.CN_ATTRIBUTE)
                ),
                FlextLDIFAnalyticsConstants.ENTRIES_WITH_MAIL_KEY: sum(
                    1
                    for entry in entries
                    if entry.has_attribute(FlextLDIFAnalyticsConstants.MAIL_ATTRIBUTE)
                ),
                FlextLDIFAnalyticsConstants.ENTRIES_WITH_TELEPHONE_KEY: sum(
                    1
                    for entry in entries
                    if entry.has_attribute(
                        FlextLDIFAnalyticsConstants.TELEPHONE_ATTRIBUTE
                    )
                ),
                "unique_object_classes": len(
                    {
                        oc.lower()
                        for entry in entries
                        for oc in entry.get_attribute("objectclass") or []
                    }
                ),
                "person_entries": sum(1 for entry in entries if entry.is_person()),
                "group_entries": sum(1 for entry in entries if entry.is_group()),
            }

            return FlextResult[dict[str, int]].ok(patterns)

        def analyze_attribute_distribution(
            self, entries: list[FlextLDIFEntry]
        ) -> FlextResult[dict[str, int]]:
            """Analyze attribute distribution across entries."""
            attr_counts: dict[str, int] = {}

            for entry in entries:
                for attr_name in entry.attributes.data:
                    attr_counts[attr_name] = attr_counts.get(attr_name, 0) + 1

            return FlextResult[dict[str, int]].ok(attr_counts)

        def analyze_dn_depth(
            self, entries: list[FlextLDIFEntry]
        ) -> FlextResult[dict[str, int]]:
            """Analyze DN depth distribution."""
            depth_analysis: dict[str, int] = {}

            for entry in entries:
                dn_components = entry.dn.value.count(",") + 1
                depth_key = f"depth_{dn_components}"
                depth_analysis[depth_key] = depth_analysis.get(depth_key, 0) + 1

            return FlextResult[dict[str, int]].ok(depth_analysis)

        def get_objectclass_distribution(
            self, entries: list[FlextLDIFEntry]
        ) -> FlextResult[dict[str, int]]:
            """Get distribution of objectClass types."""
            distribution: dict[str, int] = {}
            for entry in entries:
                object_classes = entry.get_attribute("objectclass") or []
                for oc in object_classes:
                    distribution[oc] = distribution.get(oc, 0) + 1
            return FlextResult[dict[str, int]].ok(distribution)

        def get_dn_depth_analysis(
            self, entries: list[FlextLDIFEntry]
        ) -> FlextResult[dict[str, int]]:
            """Get DN depth analysis."""
            return self.analyze_dn_depth(entries)

        def analyze_entry_patterns(
            self, entries: list[FlextLDIFEntry]
        ) -> FlextResult[dict[str, int]]:
            """Analyze entry patterns - alias for analyze_patterns."""
            return self.analyze_patterns(entries)

    class WriterService(FlextDomainService[str]):
        """Writer service for LDIF output generation."""

        def __init__(
            self, entries: list[FlextLDIFEntry] | None = None, config: object = None
        ) -> None:
            super().__init__()
            self._entries = entries or []
            self._config = config

        @property
        def entries(self) -> list[FlextLDIFEntry]:
            return self._entries

        @property
        def config(self) -> object:
            return self._config

        @override
        def execute(self) -> FlextResult[str]:
            """Write entries to LDIF string."""
            return self.write_entries_to_string(self.entries)

        def write_entries_to_string(
            self, entries: list[FlextLDIFEntry]
        ) -> FlextResult[str]:
            """Write entries to LDIF string."""
            if not entries:
                return FlextResult[str].ok("")

            try:
                ldif_blocks: list[str] = []

                for entry in entries:
                    # Use entry's to_ldif method to handle AttributeError properly
                    ldif_block = entry.to_ldif()
                    ldif_blocks.append(ldif_block)

                # Join blocks with empty line between entries
                return FlextResult[str].ok("\n\n".join(ldif_blocks))

            except Exception as e:
                from flext_ldif.constants import FlextLDIFCoreMessages

                error_msg = FlextLDIFCoreMessages.WRITE_FAILED.format(error=str(e))
                return FlextResult[str].fail(error_msg)

        def write_entry(self, entry: FlextLDIFEntry) -> FlextResult[str]:
            """Write single entry to LDIF string."""
            try:
                return FlextResult[str].ok(entry.to_ldif())
            except Exception as e:
                from flext_ldif.constants import FlextLDIFCoreMessages

                error_msg = FlextLDIFCoreMessages.WRITE_FAILED.format(error=str(e))
                return FlextResult[str].fail(error_msg)

        def write(self, entries: list[FlextLDIFEntry]) -> FlextResult[str]:
            """Write entries to string - alias for write_entries_to_string."""
            return self.write_entries_to_string(entries)

        def write_file(
            self, entries: list[FlextLDIFEntry], file_path: str, encoding: str = "utf-8"
        ) -> FlextResult[bool]:
            """Write entries to file - alias for write_entries_to_file."""
            return self.write_entries_to_file(entries, file_path, encoding)

        def write_entries_to_file(
            self, entries: list[FlextLDIFEntry], file_path: str, encoding: str = "utf-8"
        ) -> FlextResult[bool]:
            """Write entries to file."""
            try:
                content_result = self.write_entries_to_string(entries)
                if not content_result.is_success:
                    return FlextResult[bool].fail(
                        content_result.error or "Failed to generate LDIF content"
                    )

                content = content_result.value
            except Exception as e:
                error_msg = f"Processing error: {e}"
                return FlextResult[bool].fail(error_msg)

            try:
                path_obj = Path(file_path)

                # Ensure parent directory exists
                path_obj.parent.mkdir(parents=True, exist_ok=True)

                # Write content
                path_obj.write_text(content, encoding=encoding)

                return FlextResult[bool].ok(SUCCESS_VALUE)

            except (OSError, UnicodeError) as e:
                error_msg = f"File write error {file_path}: {e}"
                return FlextResult[bool].fail(error_msg)

        def _write_content_to_file(
            self, content: str, file_path: str, encoding: str
        ) -> FlextResult[bool]:
            """Write content string to file - internal method for testing."""
            try:
                path_obj = Path(file_path)
                # Ensure parent directory exists
                path_obj.parent.mkdir(parents=True, exist_ok=True)
                # Write content
                path_obj.write_text(content, encoding=encoding)
                write_success = True
                return FlextResult[bool].ok(write_success)
            except (OSError, PermissionError, UnicodeError) as e:
                from flext_ldif.constants import FlextLDIFCoreMessages

                error_msg = FlextLDIFCoreMessages.FILE_WRITE_FAILED.format(error=str(e))
                return FlextResult[bool].fail(error_msg)

        def format_entry_for_display(self, entry: FlextLDIFEntry) -> FlextResult[str]:
            """Format single entry for display."""
            try:
                lines = []

                # Format DN
                lines.append(f"DN: {entry.dn.value}")

                # Format attributes
                for attr_name, values in sorted(entry.attributes.data.items()):
                    lines.extend(f"  {attr_name}: {value}" for value in values)

                return FlextResult[str].ok("\n".join(lines))

            except (ValueError, AttributeError, TypeError) as e:
                error_msg = f"Format error: {e}"
                return FlextResult[str].fail(error_msg)

    class RepositoryService(FlextDomainService[dict[str, int]]):
        """Repository service for LDIF data management."""

        # Define config and entries as Pydantic fields for the frozen model

        def __init__(
            self, entries: list[FlextLDIFEntry] | None = None, config: object = None
        ) -> None:
            super().__init__()
            self._entries = entries or []
            self._config = config

        @property
        def entries(self) -> list[FlextLDIFEntry]:
            return self._entries

        @property
        def config(self) -> object:
            return self._config

        @override
        def execute(self) -> FlextResult[dict[str, int]]:
            """Execute repository operation."""
            # Return stats about stored entries
            return FlextResult[dict[str, int]].ok({"total_entries": len(self.entries)})

        def find_entry_by_dn(
            self, entries: list[FlextLDIFEntry], dn: str
        ) -> FlextResult[FlextLDIFEntry | None]:
            """Find entry by distinguished name."""
            if not dn or not dn.strip():
                error_msg = f"Invalid DN: {dn}"
                return FlextResult[FlextLDIFEntry | None].fail(error_msg)

            normalized_dn = dn.strip().lower()

            for entry in entries:
                if entry.dn.value.lower() == normalized_dn:
                    return FlextResult[FlextLDIFEntry | None].ok(entry)

            return FlextResult[FlextLDIFEntry | None].ok(None)

        def filter_entries_by_object_class(
            self, entries: list[FlextLDIFEntry], object_class: str
        ) -> FlextResult[list[FlextLDIFEntry]]:
            """Filter entries by objectClass attribute."""
            # Import here to avoid circular dependencies

            if not object_class or not object_class.strip():
                return FlextResult[list[FlextLDIFEntry]].fail(
                    "Object class cannot be empty"
                )

            normalized_oc = object_class.strip().lower()
            filtered_entries = []

            for entry in entries:
                object_classes = entry.get_attribute("objectclass") or []
                if any(oc.lower() == normalized_oc for oc in object_classes):
                    filtered_entries.append(entry)

            return FlextResult[list[FlextLDIFEntry]].ok(filtered_entries)

        def filter_entries_by_attribute(
            self,
            entries: list[FlextLDIFEntry],
            attribute_name: str,
            attribute_value: str | None = None,
        ) -> FlextResult[list[FlextLDIFEntry]]:
            """Filter entries by attribute name and optionally value."""
            if not attribute_name or not attribute_name.strip():
                return FlextResult[list[FlextLDIFEntry]].fail(
                    "attribute name cannot be empty"
                )

            normalized_attr = attribute_name.strip().lower()
            filtered_entries = []

            for entry in entries:
                if entry.has_attribute(normalized_attr):
                    if attribute_value is None:
                        # Just check for attribute presence
                        filtered_entries.append(entry)
                    else:
                        # Check for specific value
                        values = entry.get_attribute(normalized_attr) or []
                        if any(v.lower() == attribute_value.lower() for v in values):
                            filtered_entries.append(entry)

            return FlextResult[list[FlextLDIFEntry]].ok(filtered_entries)

        def filter_by_attribute(
            self,
            entries: list[FlextLDIFEntry],
            attribute_name: str,
            attribute_value: str | None = None,
        ) -> FlextResult[list[FlextLDIFEntry]]:
            """Filter entries by attribute - alias for filter_entries_by_attribute."""
            return self.filter_entries_by_attribute(
                entries, attribute_name, attribute_value
            )

        def filter_by_objectclass(
            self, entries: list[FlextLDIFEntry], objectclass: str
        ) -> FlextResult[list[FlextLDIFEntry]]:
            """Filter entries by objectClass - alias for filter_entries_by_object_class."""
            return self.filter_entries_by_object_class(entries, objectclass)

        def find_by_dn(
            self, entries: list[FlextLDIFEntry], dn: str
        ) -> FlextResult[FlextLDIFEntry | None]:
            """Find entry by DN (case-insensitive)."""
            if not dn or not dn.strip():
                return FlextResult[FlextLDIFEntry | None].fail("dn cannot be empty")

            normalized_dn = dn.strip().lower()

            for entry in entries:
                if entry.dn.value.lower() == normalized_dn:
                    return FlextResult[FlextLDIFEntry | None].ok(entry)

            return FlextResult[FlextLDIFEntry | None].ok(None)

        def get_statistics(
            self, entries: list[FlextLDIFEntry]
        ) -> FlextResult[dict[str, int]]:
            """Get detailed statistics for entries."""
            person_count = sum(1 for entry in entries if entry.is_person_entry())
            group_count = sum(1 for entry in entries if entry.is_group_entry())
            other_count = len(entries) - person_count - group_count

            stats = {
                "total_entries": len(entries),
                "person_entries": person_count,
                "group_entries": group_count,
                "other_entries": other_count,
            }
            return FlextResult[dict[str, int]].ok(stats)

    class ValidatorService(FlextDomainService[bool]):
        """Validator service for LDIF validation."""

        # Define config and entries as Pydantic fields for the frozen model

        def __init__(
            self, entries: list[FlextLDIFEntry] | None = None, config: object = None
        ) -> None:
            super().__init__()
            self._entries = entries or []
            self._config = config

        @property
        def entries(self) -> list[FlextLDIFEntry]:
            return self._entries

        @property
        def config(self) -> object:
            return self._config

        @override
        def execute(self) -> FlextResult[bool]:
            """Execute validation on entries."""
            return self.validate_entries(self.entries)

        def validate_entries(self, entries: list[FlextLDIFEntry]) -> FlextResult[bool]:
            """Validate all entries."""
            if not entries:
                return FlextResult[bool].ok(SUCCESS_VALUE)

            for entry in entries:
                try:
                    entry.validate_domain_rules()
                except Exception as e:
                    return FlextResult[bool].fail(
                        f"Validation failed for entry {entry.dn.value}: {e}"
                    )

            return FlextResult[bool].ok(SUCCESS_VALUE)

        def validate_entry_structure(self, entry: FlextLDIFEntry) -> FlextResult[bool]:
            """Validate single entry structure."""
            try:
                # Validate DN
                entry.dn.validate_domain_rules()

                # Validate attributes
                entry.attributes.validate_domain_rules()

                return FlextResult[bool].ok(SUCCESS_VALUE)

            except Exception as e:
                return FlextResult[bool].fail(str(e))

        def validate_unique_dns(
            self, entries: list[FlextLDIFEntry]
        ) -> FlextResult[bool]:
            """Validate that all DNs are unique."""
            seen_dns = set()

            for entry in entries:
                dn_value = entry.dn.value
                dn_lower = dn_value.lower()
                if dn_lower in seen_dns:
                    return FlextResult[bool].fail(f"Duplicate DN found: {dn_value}")
                seen_dns.add(dn_lower)

            return FlextResult[bool].ok(SUCCESS_VALUE)

        def validate_ldif_entries(
            self, entries: list[FlextLDIFEntry]
        ) -> FlextResult[bool]:
            """Validate LDIF entries - alias for validate_entries."""
            return self.validate_entries(entries)

        def validate_entry(self, entry: FlextLDIFEntry) -> FlextResult[bool]:
            """Validate single entry."""
            return self.validate_entry_structure(entry)

        def validate_dn_format(self, dn: str) -> FlextResult[bool]:
            """Validate DN format."""
            try:
                from flext_ldif.format_validator_service import LdifValidator

                return LdifValidator.validate_dn(dn)
            except Exception as e:
                return FlextResult[bool].fail(f"DN validation error: {e}")

        def validate_data(self, entries: list[FlextLDIFEntry]) -> FlextResult[bool]:
            """Validate data - alias for validate_entries."""
            return self.validate_entries(entries)

        def _validate_configuration_rules(
            self, entry: FlextLDIFEntry
        ) -> FlextResult[bool]:
            """Validate entry against configuration rules."""
            # If no config, always pass
            if not self.config:
                return FlextResult[bool].ok(SUCCESS_VALUE)

            # Import here to avoid circular imports
            from flext_ldif.constants import FlextLDIFValidationMessages

            config = self.config

            # Check if it's a proper config object with strict_validation
            if hasattr(config, "strict_validation") and getattr(
                config, "strict_validation", False
            ):
                # Strict validation rules
                # Handle both real AttributesDict and Mock objects
                attributes_obj = entry.attributes
                if hasattr(attributes_obj, "attributes"):  # Mock object setup
                    attributes_dict = attributes_obj.attributes
                elif hasattr(attributes_obj, "items"):  # Real AttributesDict
                    attributes_dict = dict(attributes_obj)
                else:
                    return FlextResult[bool].ok(SUCCESS_VALUE)  # Can't validate

                for attr_name, attr_values in attributes_dict.items():
                    if not attr_values:  # Empty attribute list
                        return FlextResult[bool].fail(
                            f"Empty attribute list for {attr_name}"
                        )

                    for value in attr_values:
                        if (
                            not value or not value.strip()
                        ):  # Empty or whitespace-only values
                            return FlextResult[bool].fail(
                                FlextLDIFValidationMessages.EMPTY_ATTRIBUTE_VALUE_NOT_ALLOWED.format(
                                    attr_name=attr_name
                                )
                            )

            return FlextResult[bool].ok(SUCCESS_VALUE)

    class ParserService(FlextDomainService["list[FlextLDIFEntry]"]):
        """Parser service for LDIF parsing."""

        # Define config and content as Pydantic fields for the frozen model

        def __init__(self, content: str = "", config: object = None) -> None:
            super().__init__()
            self._content = content
            self._config = config

        @property
        def content(self) -> str:
            return self._content

        @property
        def config(self) -> object:
            return self._config

        @override
        def execute(self) -> FlextResult[list[FlextLDIFEntry]]:
            """Execute parsing operation."""
            return self.parse_ldif_content(self.content)

        def parse(self, content: str) -> FlextResult[list[FlextLDIFEntry]]:
            """Parse LDIF content - standalone method for direct use."""
            return self.parse_ldif_content(content)

        def parse_entries_from_string(
            self, content: str
        ) -> FlextResult[list[FlextLDIFEntry]]:
            """Parse entries from string - alias for parse_ldif_content."""
            return self.parse_ldif_content(content)

        def parse_ldif_content(self, content: str) -> FlextResult[list[FlextLDIFEntry]]:
            """Parse LDIF content into entries."""
            if not content or not content.strip():
                return FlextResult[list[FlextLDIFEntry]].ok([])

            # Validate syntax first
            syntax_result = self.validate_ldif_syntax(content)
            if not syntax_result.is_success:
                return FlextResult[list[FlextLDIFEntry]].fail(
                    syntax_result.error or "Invalid LDIF syntax"
                )

            try:
                entries: list[FlextLDIFEntry] = []
                current_entry_data: dict[str, str | list[str]] = {}

                for raw_line in content.strip().split("\n"):
                    line = raw_line.strip()

                    if not line:
                        # Empty line - end of entry
                        if current_entry_data:
                            entry = FlextLDIFModels.Entry.from_dict(
                                cast("dict[str, object]", current_entry_data)
                            )
                            entries.append(entry)
                            current_entry_data = {}
                        continue

                    if ":" not in line:
                        continue  # Skip invalid lines

                    attr_name, attr_value = line.split(":", 1)
                    attr_name = attr_name.strip()
                    attr_value = attr_value.strip()

                    if attr_name.lower() == "dn":
                        current_entry_data["dn"] = attr_value
                    else:
                        if attr_name not in current_entry_data:
                            current_entry_data[attr_name] = []
                        attr_list = cast("list[str]", current_entry_data[attr_name])
                        attr_list.append(attr_value)

                # Handle last entry if no trailing empty line
                if current_entry_data:
                    entry = FlextLDIFModels.Entry.from_dict(
                        cast("dict[str, object]", current_entry_data)
                    )
                    entries.append(entry)

                return FlextResult[list[FlextLDIFEntry]].ok(entries)

            except Exception as e:
                return FlextResult[list[FlextLDIFEntry]].fail(f"Parse error: {e}")

        def parse_ldif_file(
            self, file_path: str, encoding: str = "utf-8"
        ) -> FlextResult[list[FlextLDIFEntry]]:
            """Parse LDIF file."""
            try:
                path_obj = Path(file_path)
                if not path_obj.exists():
                    return FlextResult[list[FlextLDIFEntry]].fail(
                        f"File not found: {file_path}"
                    )

                content = path_obj.read_text(encoding=encoding)
                return self.parse_ldif_content(content)

            except Exception as e:
                return FlextResult[list[FlextLDIFEntry]].fail(f"File read error: {e}")

        def validate_ldif_syntax(self, content: str) -> FlextResult[bool]:
            """Validate LDIF syntax without full parsing."""
            if not content or not content.strip():
                return FlextResult[bool].ok(SUCCESS_VALUE)

            try:
                lines = content.strip().split("\n")
                current_entry_has_dn = False

                for line_num, raw_line in enumerate(lines, 1):
                    line = raw_line.strip()

                    if not line:
                        current_entry_has_dn = False
                        continue

                    if ":" not in line:
                        return FlextResult[bool].fail(
                            f"Invalid syntax at line {line_num}: missing colon"
                        )

                    attr_name, _ = line.split(":", 1)
                    attr_name = attr_name.strip()

                    if attr_name.lower() == "dn":
                        current_entry_has_dn = True
                    elif not current_entry_has_dn:
                        return FlextResult[bool].fail(
                            f"Attribute before DN at line {line_num}"
                        )

                return FlextResult[bool].ok(SUCCESS_VALUE)

            except Exception as e:
                return FlextResult[bool].fail(f"Syntax validation error: {e}")

        def _parse_entry_block(self, block: str) -> FlextResult[FlextLDIFEntry | None]:
            """Parse a single LDIF entry block."""
            if not block or not block.strip():
                return FlextResult[FlextLDIFEntry | None].fail("Empty entry block")

            try:
                lines = block.strip().split("\n")
                entry_data: dict[str, str | list[str]] = {}

                for raw_line in lines:
                    line = raw_line.strip()
                    if not line or ":" not in line:
                        continue

                    attr_name, attr_value = line.split(":", 1)
                    attr_name = attr_name.strip()
                    attr_value = attr_value.strip()

                    if attr_name.lower() == "dn":
                        entry_data["dn"] = attr_value
                    else:
                        if attr_name not in entry_data:
                            entry_data[attr_name] = []
                        attr_list = cast("list[str]", entry_data[attr_name])
                        attr_list.append(attr_value)

                if "dn" not in entry_data:
                    return FlextResult[FlextLDIFEntry | None].fail("Entry missing DN")

                entry = FlextLDIFModels.Entry.from_dict(
                    cast("dict[str, object]", entry_data)
                )
                return FlextResult[FlextLDIFEntry | None].ok(entry)

            except Exception as e:
                return FlextResult[FlextLDIFEntry | None].fail(
                    f"Parse entry block error: {e}"
                )

    class TransformerService(FlextDomainService[list[FlextLDIFEntry]]):
        """Transformer service for LDIF entry transformations."""

        # Define config as Pydantic field for the frozen model

        def __init__(self, config: object = None) -> None:
            super().__init__()
            self._config = config

        @property
        def config(self) -> object:
            return self._config

        @override
        def execute(self) -> FlextResult[list[FlextLDIFEntry]]:
            """Execute transformation operation."""
            return FlextResult[list[FlextLDIFEntry]].ok([])

        def transform_entry(self, entry: FlextLDIFEntry) -> FlextResult[FlextLDIFEntry]:
            """Transform a single entry (base implementation returns as-is)."""
            return FlextResult[FlextLDIFEntry].ok(entry)

        def transform_entries(
            self, entries: list[FlextLDIFEntry]
        ) -> FlextResult[list[FlextLDIFEntry]]:
            """Transform multiple entries."""
            if not entries:
                return FlextResult[list[FlextLDIFEntry]].ok([])

            try:
                transformed = []
                for entry in entries:
                    result = self.transform_entry(entry)
                    if not result.is_success:
                        error_msg = result.error or "Transform failed"
                        return FlextResult[list[FlextLDIFEntry]].fail(error_msg)
                    transformed.append(result.value)

                return FlextResult[list[FlextLDIFEntry]].ok(transformed)
            except Exception as e:
                return FlextResult[list[FlextLDIFEntry]].fail(
                    f"Transform entries error: {e}"
                )

        def normalize_dns(
            self, entries: list[FlextLDIFEntry]
        ) -> FlextResult[list[FlextLDIFEntry]]:
            """Normalize DNs in entries (base implementation returns as-is)."""
            return FlextResult[list[FlextLDIFEntry]].ok(entries)


# =============================================================================
# BACKWARD COMPATIBILITY - Legacy class aliases
# =============================================================================

# Direct aliases to nested classes for backward compatibility
FlextLDIFAnalyticsService = FlextLDIFServices.AnalyticsService
FlextLDIFWriterService = FlextLDIFServices.WriterService
FlextLDIFRepositoryService = FlextLDIFServices.RepositoryService
FlextLDIFValidatorService = FlextLDIFServices.ValidatorService
FlextLDIFParserService = FlextLDIFServices.ParserService
FlextLDIFTransformerService = FlextLDIFServices.TransformerService
FieldDefaults = FlextLDIFServices.FieldDefaults

# Export consolidated class and legacy aliases
__all__ = [
    "FieldDefaults",
    # Legacy compatibility aliases
    "FlextLDIFAnalyticsService",
    "FlextLDIFParserService",
    "FlextLDIFRepositoryService",
    # Consolidated class (FLEXT Pattern)
    "FlextLDIFServices",
    "FlextLDIFTransformerService",
    "FlextLDIFValidatorService",
    "FlextLDIFWriterService",
    "attribute_name_field",
    "attribute_value_field",
    # Field utility functions
    "dn_field",
    "object_class_field",
]
