"""FLEXT-LDIF Services - Consolidated Class Structure.

Single consolidated class containing ALL LDIF services following FLEXT patterns.
Individual services available as nested classes for organization.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, cast, override

from flext_core import (
    FlextDomainService,
    FlextModel,
    FlextResult,
)

# Constants for boolean literals
SUCCESS_VALUE = True
from pydantic import Field
from pydantic.fields import FieldInfo

if TYPE_CHECKING:
    from flext_ldif.models import FlextLdifEntry


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


class FlextLdifServices(FlextModel):
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
        ENCODING: ClassVar[str] = "utf-8"
        LINE_SEPARATOR: ClassVar[str] = "\n"

        # Processing defaults
        DEFAULT_BATCH_SIZE: ClassVar[int] = 1000
        DEFAULT_TIMEOUT: ClassVar[int] = 30
        MAX_ENTRIES_DEFAULT: ClassVar[int] = 10000

    class AnalyticsService(FlextDomainService[dict[str, int]]):
        """Analytics service for LDIF processing metrics."""

        def __init__(self, entries: list[FlextLdifEntry] | None = None) -> None:
            super().__init__()
            self._entries = entries or []

        @override
        def execute(self) -> FlextResult[dict[str, int]]:
            """Execute analytics operation - required by FlextDomainService."""
            # Import here to avoid circular dependencies
            from flext_ldif.constants import FlextLdifAnalyticsConstants

            if not self._entries:
                return FlextResult[dict[str, int]].ok(FlextLdifAnalyticsConstants.DEFAULT_METRICS)

            return self.analyze_patterns(self._entries)

        def analyze_patterns(self, entries: list[FlextLdifEntry]) -> FlextResult[dict[str, int]]:
            """Analyze patterns in LDIF entries."""
            # Import here to avoid circular dependencies

            patterns = {
                "total_entries": len(entries),
                "unique_object_classes": len(
                    {
                        oc.lower()
                        for entry in entries
                        for oc in entry.get_attribute("objectclass") or []
                    }
                ),
                "entries_with_cn": sum(
                    1 for entry in entries if entry.has_attribute("cn")
                ),
                "entries_with_mail": sum(
                    1 for entry in entries if entry.has_attribute("mail")
                ),
                "person_entries": sum(1 for entry in entries if entry.is_person()),
                "group_entries": sum(1 for entry in entries if entry.is_group()),
            }

            return FlextResult[dict[str, int]].ok(patterns)

        def analyze_attribute_distribution(self, entries: list[FlextLdifEntry]) -> FlextResult[dict[str, int]]:
            """Analyze attribute distribution across entries."""
            attr_counts: dict[str, int] = {}

            for entry in entries:
                for attr_name in entry.attributes.data:
                    attr_counts[attr_name] = attr_counts.get(attr_name, 0) + 1

            return FlextResult[dict[str, int]].ok(attr_counts)

        def analyze_dn_depth(self, entries: list[FlextLdifEntry]) -> FlextResult[dict[str, int]]:
            """Analyze DN depth distribution."""
            # Import here to avoid circular dependencies

            depth_analysis: dict[str, int] = {}

            for entry in entries:
                dn_components = entry.dn.value.count(",") + 1
                depth_key = f"depth_{dn_components}"
                depth_analysis[depth_key] = depth_analysis.get(depth_key, 0) + 1

            return FlextResult[dict[str, int]].ok(depth_analysis)

    class WriterService(FlextDomainService[str]):
        """Writer service for LDIF output generation."""

        def __init__(self, entries: list[FlextLdifEntry] | None = None) -> None:
            super().__init__()
            self._entries = entries or []

        @override
        def execute(self) -> FlextResult[str]:
            """Write entries to LDIF string."""
            return self.write_entries_to_string(self._entries)

        def write_entries_to_string(self, entries: list[FlextLdifEntry]) -> FlextResult[str]:
            """Write entries to LDIF string."""
            # Import here to avoid circular dependencies

            if not entries:
                return FlextResult[str].ok("")

            ldif_lines: list[str] = []

            for entry in entries:
                # Write DN
                ldif_lines.append(f"dn: {entry.dn.value}")

                # Write attributes
                for attr_name, attr_values in entry.attributes.data.items():
                    ldif_lines.extend(f"{attr_name}: {value}" for value in attr_values)

                # Empty line between entries
                ldif_lines.append("")

            return FlextResult[str].ok("\n".join(ldif_lines))

        def write_entries_to_file(self, entries: list[FlextLdifEntry], file_path: str, encoding: str = "utf-8") -> FlextResult[bool]:
            """Write entries to file."""
            try:
                content_result = self.write_entries_to_string(entries)
                if not content_result.is_success:
                    return FlextResult[bool].fail(content_result.error or "Failed to generate LDIF content")

                content = content_result.value
            except Exception as e:
                # Import here to avoid circular dependencies
                from flext_ldif.constants import FlextLdifCoreMessages

                return FlextResult[bool].fail(
                    FlextLdifCoreMessages.PROCESSING_ERROR.format(error=str(e))
                )

            try:
                # Import here to avoid circular dependencies
                from flext_ldif.constants import FlextLdifCoreMessages

                path_obj = Path(file_path)

                # Ensure parent directory exists
                path_obj.parent.mkdir(parents=True, exist_ok=True)

                # Write content
                path_obj.write_text(content, encoding=encoding)

                return FlextResult[bool].ok(SUCCESS_VALUE)

            except (OSError, UnicodeError) as e:
                # Import here to avoid circular dependencies
                from flext_ldif.constants import FlextLdifCoreMessages

                return FlextResult[bool].fail(
                    FlextLdifCoreMessages.FILE_WRITE_ERROR.format(path=file_path, error=str(e))
                )

        def format_entry_for_display(self, entry: FlextLdifEntry) -> FlextResult[str]:
            """Format single entry for display."""
            try:
                lines = [f"DN: {entry.dn.value}"]

                for attr_name, values in sorted(entry.attributes.data.items()):
                    lines.extend(f"  {attr_name}: {value}" for value in values)

                return FlextResult[str].ok("\n".join(lines))

            except (ValueError, AttributeError, TypeError) as e:
                # Import here to avoid circular dependencies
                from flext_ldif.constants import FlextLdifCoreMessages

                return FlextResult[str].fail(
                    FlextLdifCoreMessages.FORMAT_ERROR.format(error=str(e))
                )

    class RepositoryService(FlextDomainService[dict[str, int]]):
        """Repository service for LDIF data management."""

        def __init__(self, entries: list[FlextLdifEntry] | None = None) -> None:
            super().__init__()
            self._entries = entries or []

        @override
        def execute(self) -> FlextResult[dict[str, int]]:
            """Execute repository operation."""
            # Return stats about stored entries
            return FlextResult[dict[str, int]].ok({"total_entries": len(self._entries)})

        def find_entry_by_dn(self, entries: list[FlextLdifEntry], dn: str) -> FlextResult[FlextLdifEntry | None]:
            """Find entry by distinguished name."""
            # Import here to avoid circular dependencies
            from flext_ldif.constants import FlextLdifValidationMessages

            if not dn or not dn.strip():
                return FlextResult["FlextLdifEntry | None"].fail(
                    FlextLdifValidationMessages.INVALID_DN.format(dn=dn)
                )

            normalized_dn = dn.strip().lower()

            for entry in entries:
                if entry.dn.value.lower() == normalized_dn:
                    return FlextResult["FlextLdifEntry | None"].ok(entry)

            return FlextResult["FlextLdifEntry | None"].ok(None)

        def filter_entries_by_object_class(
            self, entries: list[FlextLdifEntry], object_class: str
        ) -> FlextResult[list[FlextLdifEntry]]:
            """Filter entries by objectClass attribute."""
            # Import here to avoid circular dependencies

            if not object_class or not object_class.strip():
                return FlextResult[list["FlextLdifEntry"]].fail("Object class cannot be empty")

            normalized_oc = object_class.strip().lower()
            filtered_entries = []

            for entry in entries:
                object_classes = entry.get_attribute("objectclass") or []
                if any(oc.lower() == normalized_oc for oc in object_classes):
                    filtered_entries.append(entry)

            return FlextResult[list["FlextLdifEntry"]].ok(filtered_entries)

        def filter_entries_by_attribute(
            self, entries: list[FlextLdifEntry], attribute_name: str, attribute_value: str | None = None
        ) -> FlextResult[list[FlextLdifEntry]]:
            """Filter entries by attribute name and optionally value."""
            if not attribute_name or not attribute_name.strip():
                return FlextResult[list["FlextLdifEntry"]].fail("Attribute name cannot be empty")

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

            return FlextResult[list["FlextLdifEntry"]].ok(filtered_entries)

    class ValidatorService(FlextDomainService[bool]):
        """Validator service for LDIF validation."""

        def __init__(self, entries: list[FlextLdifEntry] | None = None) -> None:
            super().__init__()
            self._entries = entries or []

        @override
        def execute(self) -> FlextResult[bool]:
            """Execute validation on entries."""
            return self.validate_entries(self._entries)

        def validate_entries(self, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
            """Validate all entries."""
            if not entries:
                return FlextResult[bool].ok(SUCCESS_VALUE)

            for entry in entries:
                try:
                    entry.validate_domain_rules()
                except Exception as e:
                    return FlextResult[bool].fail(f"Validation failed for entry {entry.dn.value}: {e}")

            return FlextResult[bool].ok(True)

        def validate_entry_structure(self, entry: FlextLdifEntry) -> FlextResult[bool]:
            """Validate single entry structure."""
            try:
                # Validate DN
                entry.dn.validate_domain_rules()

                # Validate attributes
                entry.attributes.validate_domain_rules()

                return FlextResult[bool].ok(SUCCESS_VALUE)

            except Exception as e:
                return FlextResult[bool].fail(str(e))

        def validate_unique_dns(self, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
            """Validate that all DNs are unique."""
            seen_dns = set()

            for entry in entries:
                dn_lower = entry.dn.value.lower()
                if dn_lower in seen_dns:
                    return FlextResult[bool].fail(f"Duplicate DN found: {entry.dn.value}")
                seen_dns.add(dn_lower)

            return FlextResult[bool].ok(True)

    class ParserService(FlextDomainService[list["FlextLdifEntry"]]):
        """Parser service for LDIF parsing."""

        def __init__(self, content: str = "") -> None:
            super().__init__()
            self._content = content

        @override
        def execute(self) -> FlextResult[list[FlextLdifEntry]]:
            """Execute parsing operation."""
            return self.parse_ldif_content(self._content)

        def parse(self, content: str) -> FlextResult[list[FlextLdifEntry]]:
            """Parse LDIF content - standalone method for direct use."""
            return self.parse_ldif_content(content)

        def parse_ldif_content(self, content: str) -> FlextResult[list[FlextLdifEntry]]:
            """Parse LDIF content into entries."""
            if not content or not content.strip():
                return FlextResult[list["FlextLdifEntry"]].ok([])

            try:
                # Import here to avoid circular dependencies
                from flext_ldif.models import FlextLdifModels

                entries: list[FlextLdifEntry] = []
                current_entry_data: dict[str, object] = {}

                for raw_line in content.strip().split("\n"):
                    line = raw_line.strip()

                    if not line:
                        # Empty line - end of entry
                        if current_entry_data:
                            entry = FlextLdifModels.Entry.from_dict(current_entry_data)
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
                        if isinstance(current_entry_data[attr_name], list):
                            current_entry_data[attr_name].append(attr_value)

                # Handle last entry if no trailing empty line
                if current_entry_data:
                    entry = FlextLdifModels.Entry.from_dict(current_entry_data)
                    entries.append(entry)

                return FlextResult[list["FlextLdifEntry"]].ok(entries)

            except Exception as e:
                return FlextResult[list["FlextLdifEntry"]].fail(f"Parse error: {e}")

        def parse_ldif_file(self, file_path: str, encoding: str = "utf-8") -> FlextResult[list[FlextLdifEntry]]:
            """Parse LDIF file."""
            try:
                path_obj = Path(file_path)
                if not path_obj.exists():
                    return FlextResult[list["FlextLdifEntry"]].fail(f"File not found: {file_path}")

                content = path_obj.read_text(encoding=encoding)
                return self.parse_ldif_content(content)

            except Exception as e:
                return FlextResult[list["FlextLdifEntry"]].fail(f"File read error: {e}")

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
                        return FlextResult[bool].fail(f"Invalid syntax at line {line_num}: missing colon")

                    attr_name, _ = line.split(":", 1)
                    attr_name = attr_name.strip()

                    if attr_name.lower() == "dn":
                        current_entry_has_dn = True
                    elif not current_entry_has_dn:
                        return FlextResult[bool].fail(f"Attribute before DN at line {line_num}")

                return FlextResult[bool].ok(SUCCESS_VALUE)

            except Exception as e:
                return FlextResult[bool].fail(f"Syntax validation error: {e}")


# =============================================================================
# BACKWARD COMPATIBILITY - Legacy class aliases
# =============================================================================

# Direct aliases to nested classes for backward compatibility
FlextLdifAnalyticsService = FlextLdifServices.AnalyticsService
FlextLdifWriterService = FlextLdifServices.WriterService
FlextLdifRepositoryService = FlextLdifServices.RepositoryService
FlextLdifValidatorService = FlextLdifServices.ValidatorService
FlextLdifParserService = FlextLdifServices.ParserService
FieldDefaults = FlextLdifServices.FieldDefaults

# Export consolidated class and legacy aliases
__all__ = [
    "FieldDefaults",
    # Legacy compatibility aliases
    "FlextLdifAnalyticsService",
    "FlextLdifParserService",
    "FlextLdifRepositoryService",
    # Consolidated class (FLEXT Pattern)
    "FlextLdifServices",
    "FlextLdifValidatorService",
    "FlextLdifWriterService",
    "attribute_name_field",
    "attribute_value_field",
    # Field utility functions
    "dn_field",
    "object_class_field",
]
