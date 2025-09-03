"""FLEXT-LDIF Services - Consolidated Class Structure.

Single consolidated class containing ALL LDIF services following FLEXT patterns.
Individual services available as nested classes for organization.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast, override

from flext_core import (
    FlextDomainService,
    FlextModels,
    FlextResult,
    FlextUtilities,
    FlextValidations,
)
from pydantic import Field
from pydantic.fields import FieldInfo

from flext_ldif.models import FlextLDIFModels

# Use FlextConstants instead of local constants
# SUCCESS_VALUE removed - use FlextConstants.Success.TRUE


# =============================================================================
# CONSOLIDATED SERVICES CLASS - Single class containing ALL LDIF services
# =============================================================================


class FlextLDIFServices(FlextModels.BaseConfig):
    """Single consolidated class containing ALL LDIF services.

    Consolidates ALL service operations into one class following FLEXT patterns.
    Individual services available as nested classes for organization.
    """

    # Remove FieldDefaults - use FlextLDIFConstants directly instead

    class AnalyticsService(FlextDomainService[dict[str, int]]):
        """Analytics service for LDIF processing metrics."""

        def __init__(
            self,
            entries: list[FlextLDIFModels.Entry] | None = None,
            config: object = None,
        ) -> None:
            # Import here to avoid circular imports
            from flext_ldif.models import FlextLDIFModels

            super().__init__()
            self._entries = entries or []
            self._config = config or FlextLDIFModels.Config()

        @property
        def entries(self) -> list[FlextLDIFModels.Entry]:
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
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[dict[str, int]]:
            """Analyze patterns in LDIF entries."""
            from flext_ldif.constants import FlextLDIFConstants

            FlextLDIFAnalyticsConstants = FlextLDIFConstants.FlextLDIFAnalyticsConstants

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
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[dict[str, int]]:
            """Analyze attribute distribution across entries."""
            attr_counts: dict[str, int] = {}

            for entry in entries:
                for attr_name in entry.attributes.data:
                    attr_counts[attr_name] = attr_counts.get(attr_name, 0) + 1

            return FlextResult[dict[str, int]].ok(attr_counts)

        def analyze_dn_depth(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[dict[str, int]]:
            """Analyze DN depth distribution."""
            depth_analysis: dict[str, int] = {}

            for entry in entries:
                dn_components = entry.dn.value.count(",") + 1
                depth_key = f"depth_{dn_components}"
                depth_analysis[depth_key] = depth_analysis.get(depth_key, 0) + 1

            return FlextResult[dict[str, int]].ok(depth_analysis)

        def get_objectclass_distribution(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[dict[str, int]]:
            """Get distribution of objectClass types."""
            distribution: dict[str, int] = {}
            for entry in entries:
                object_classes = entry.get_attribute("objectclass") or []
                for oc in object_classes:
                    distribution[oc] = distribution.get(oc, 0) + 1
            return FlextResult[dict[str, int]].ok(distribution)

        def get_dn_depth_analysis(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[dict[str, int]]:
            """Get DN depth analysis."""
            return self.analyze_dn_depth(entries)

        def analyze_entry_patterns(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[dict[str, int]]:
            """Analyze entry patterns - alias for analyze_patterns."""
            return self.analyze_patterns(entries)

    class WriterService(FlextDomainService[str]):
        """Writer service for LDIF output generation."""

        def __init__(
            self,
            entries: list[FlextLDIFModels.Entry] | None = None,
            config: object = None,
        ) -> None:
            super().__init__()
            self._entries = entries or []
            self._config = config

        @property
        def entries(self) -> list[FlextLDIFModels.Entry]:
            return self._entries

        @property
        def config(self) -> object:
            return self._config

        @override
        def execute(self) -> FlextResult[str]:
            """Write entries to LDIF string."""
            return self.write_entries_to_string(self.entries)

        def write_entries_to_string(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[str]:
            """Write entries to LDIF string - Railway pattern optimization."""
            if not entries:
                return FlextResult[str].ok("")

            # Railway pattern - no try/catch needed, entry.to_ldif() handles errors
            ldif_blocks = [entry.to_ldif() for entry in entries]
            return FlextResult[str].ok("\n\n".join(ldif_blocks))

        def write_entry(self, entry: FlextLDIFModels.Entry) -> FlextResult[str]:
            """Write single entry to LDIF string - Railway pattern."""
            # Railway pattern - entry.to_ldif() already handles errors safely
            return FlextResult[str].ok(entry.to_ldif())

        def write(self, entries: list[FlextLDIFModels.Entry]) -> FlextResult[str]:
            """Write entries to string - alias for write_entries_to_string."""
            return self.write_entries_to_string(entries)

        def write_file(
            self,
            entries: list[FlextLDIFModels.Entry],
            file_path: str,
            encoding: str = "utf-8",
        ) -> FlextResult[bool]:
            """Write entries to file - alias for write_entries_to_file."""
            return self.write_entries_to_file(entries, file_path, encoding)

        def write_entries_to_file(
            self,
            entries: list[FlextLDIFModels.Entry],
            file_path: str,
            encoding: str = "utf-8",
        ) -> FlextResult[bool]:
            """Write entries to file - Railway pattern with flat_map."""
            # Railway pattern composition
            return self.write_entries_to_string(entries).flat_map(
                lambda content: self._write_content_to_file(
                    content, file_path, encoding
                )
            )

        def _write_content_to_file(
            self, content: str, file_path: str, encoding: str
        ) -> FlextResult[bool]:
            """Write content string to file using flext-core utilities."""
            # Use Railway pattern with Path and FlextUtilities for IDs/tracking
            path_obj = Path(file_path)

            try:
                # Record performance metric using flext-core
                correlation_id = FlextUtilities.generate_correlation_id()
                FlextUtilities.Performance.record_metric(
                    f"write_file_{correlation_id}", len(content)
                )

                # Ensure parent directory exists and write efficiently
                path_obj.parent.mkdir(parents=True, exist_ok=True)
                path_obj.write_text(content, encoding=encoding)

                return FlextResult[bool].ok(True)

            except (OSError, PermissionError, UnicodeError) as e:
                error_msg = f"File write failed: {e}"
                return FlextResult[bool].fail(error_msg)

        def format_entry_for_display(
            self, entry: FlextLDIFModels.Entry
        ) -> FlextResult[str]:
            """Format single entry for display using flext-core formatters."""
            # Railway pattern - Pydantic models are safe to access
            lines = [f"DN: {entry.dn.value}"]

            # Use sorted() with optimized formatting for better display
            sorted_attrs = sorted(entry.attributes.data.items())
            for attr_name, values in sorted_attrs:
                # Use FlextUtilities.clean_text for better value display
                clean_values = [
                    FlextUtilities.clean_text(str(value)) for value in values
                ]
                lines.extend(f"  {attr_name}: {value}" for value in clean_values)

            return FlextResult[str].ok("\n".join(lines))

    class RepositoryService(FlextDomainService[dict[str, int]]):
        """Repository service for LDIF data management."""

        # Define config and entries as Pydantic fields for the frozen model

        def __init__(
            self,
            entries: list[FlextLDIFModels.Entry] | None = None,
            config: object = None,
        ) -> None:
            super().__init__()
            self._entries = entries or []
            self._config = config

        @property
        def entries(self) -> list[FlextLDIFModels.Entry]:
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
            self, entries: list[FlextLDIFModels.Entry], dn: str
        ) -> FlextResult[FlextLDIFModels.Entry | None]:
            """Find entry by distinguished name using flext-core utilities."""
            # Use FlextUtilities.TypeGuards.is_string_non_empty for validation
            if not FlextUtilities.TypeGuards.is_string_non_empty(dn):
                error_msg = f"Invalid DN: {dn}"
                return FlextResult[FlextLDIFModels.Entry | None].fail(error_msg)

            # Use FlextUtilities.TextProcessor.clean_text for normalization
            normalized_dn = FlextUtilities.TextProcessor.clean_text(dn).lower()

            for entry in entries:
                entry_dn_normalized = FlextUtilities.TextProcessor.clean_text(
                    entry.dn.value
                ).lower()
                if entry_dn_normalized == normalized_dn:
                    return FlextResult[FlextLDIFModels.Entry | None].ok(entry)

            return FlextResult[FlextLDIFModels.Entry | None].ok(None)

        def filter_entries_by_object_class(
            self, entries: list[FlextLDIFModels.Entry], object_class: str
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Filter entries by objectClass attribute using flext-core utilities."""
            # Use FlextUtilities.TypeGuards.is_string_non_empty for validation
            if not FlextUtilities.TypeGuards.is_string_non_empty(object_class):
                return FlextResult[list[FlextLDIFModels.Entry]].fail(
                    "Object class cannot be empty"
                )

            # Use FlextUtilities.TextProcessor.clean_text for normalization
            normalized_oc = FlextUtilities.TextProcessor.clean_text(
                object_class
            ).lower()
            filtered_entries = []

            for entry in entries:
                object_classes = entry.get_attribute("objectclass") or []
                # Use list comprehension with flext-core text processing
                normalized_classes = [
                    FlextUtilities.TextProcessor.clean_text(oc).lower()
                    for oc in object_classes
                ]
                if normalized_oc in normalized_classes:
                    filtered_entries.append(entry)

            return FlextResult[list[FlextLDIFModels.Entry]].ok(filtered_entries)

        def filter_entries_by_attribute(
            self,
            entries: list[FlextLDIFModels.Entry],
            attribute_name: str,
            attribute_value: str | None = None,
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Filter entries by attribute name and optionally value using flext-core utilities."""
            # Use FlextUtilities.TypeGuards.is_string_non_empty for validation
            if not FlextUtilities.TypeGuards.is_string_non_empty(attribute_name):
                return FlextResult[list[FlextLDIFModels.Entry]].fail(
                    "attribute name cannot be empty"
                )

            # Use FlextUtilities.TextProcessor.clean_text for normalization
            normalized_attr = FlextUtilities.TextProcessor.clean_text(
                attribute_name
            ).lower()
            filtered_entries = []

            for entry in entries:
                if entry.has_attribute(normalized_attr):
                    if attribute_value is None:
                        # Just check for attribute presence
                        filtered_entries.append(entry)
                    else:
                        # Check for specific value using flext-core text processing
                        values = entry.get_attribute(normalized_attr) or []
                        normalized_target = FlextUtilities.TextProcessor.clean_text(
                            attribute_value
                        ).lower()
                        normalized_values = [
                            FlextUtilities.TextProcessor.clean_text(v).lower()
                            for v in values
                        ]
                        if normalized_target in normalized_values:
                            filtered_entries.append(entry)

            return FlextResult[list[FlextLDIFModels.Entry]].ok(filtered_entries)

        def filter_by_attribute(
            self,
            entries: list[FlextLDIFModels.Entry],
            attribute_name: str,
            attribute_value: str | None = None,
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Filter entries by attribute - alias for filter_entries_by_attribute."""
            return self.filter_entries_by_attribute(
                entries, attribute_name, attribute_value
            )

        def filter_by_objectclass(
            self, entries: list[FlextLDIFModels.Entry], objectclass: str
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Filter entries by objectClass - alias for filter_entries_by_object_class."""
            return self.filter_entries_by_object_class(entries, objectclass)

        def find_by_dn(
            self, entries: list[FlextLDIFModels.Entry], dn: str
        ) -> FlextResult[FlextLDIFModels.Entry | None]:
            """Find entry by DN (case-insensitive) using flext-core utilities."""
            # Use FlextUtilities.TypeGuards.is_string_non_empty for validation
            if not FlextUtilities.TypeGuards.is_string_non_empty(dn):
                return FlextResult[FlextLDIFModels.Entry | None].fail(
                    "dn cannot be empty"
                )

            # Use FlextUtilities.TextProcessor.clean_text for normalization
            normalized_dn = FlextUtilities.TextProcessor.clean_text(dn).lower()

            for entry in entries:
                entry_dn_normalized = FlextUtilities.TextProcessor.clean_text(
                    entry.dn.value
                ).lower()
                if entry_dn_normalized == normalized_dn:
                    return FlextResult[FlextLDIFModels.Entry | None].ok(entry)

            return FlextResult[FlextLDIFModels.Entry | None].ok(None)

        def get_statistics(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[dict[str, int]]:
            """Get detailed statistics for entries using flext-core utilities."""
            # Use FlextUtilities.TypeGuards.is_list_non_empty for validation
            if not FlextUtilities.TypeGuards.is_list_non_empty(entries):
                default_stats = {
                    "total_entries": 0,
                    "person_entries": 0,
                    "group_entries": 0,
                    "other_entries": 0,
                }
                return FlextResult[dict[str, int]].ok(default_stats)

            # Use FlextUtilities.Conversions.safe_int for safe counting
            person_count = FlextUtilities.Conversions.safe_int(
                sum(1 for entry in entries if entry.is_person_entry()), 0
            )
            group_count = FlextUtilities.Conversions.safe_int(
                sum(1 for entry in entries if entry.is_group_entry()), 0
            )
            total_count = FlextUtilities.Conversions.safe_int(len(entries), 0)
            other_count = max(0, total_count - person_count - group_count)

            stats = {
                "total_entries": total_count,
                "person_entries": person_count,
                "group_entries": group_count,
                "other_entries": other_count,
            }
            return FlextResult[dict[str, int]].ok(stats)

    class ValidatorService(FlextDomainService[bool]):
        """Validator service for LDIF validation."""

        # Define config and entries as Pydantic fields for the frozen model

        def __init__(
            self,
            entries: list[FlextLDIFModels.Entry] | None = None,
            config: object = None,
        ) -> None:
            super().__init__()
            self._entries = entries or []
            self._config = config

        @property
        def entries(self) -> list[FlextLDIFModels.Entry]:
            return self._entries

        @property
        def config(self) -> object:
            return self._config

        @override
        def execute(self) -> FlextResult[bool]:
            """Execute validation on entries."""
            return self.validate_entries(self.entries)

        def validate_entries(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[bool]:
            """Validate all entries using flext-core type guards."""
            # Use FlextUtilities.TypeGuards.is_list_non_empty for validation
            if not FlextUtilities.TypeGuards.is_list_non_empty(entries):
                return FlextResult[bool].ok(True)

            for entry in entries:
                try:
                    entry.validate_domain_rules()
                except Exception as e:
                    return FlextResult[bool].fail(
                        f"Validation failed for entry {entry.dn.value}: {e}"
                    )

            return FlextResult[bool].ok(True)

        def validate_entry_structure(
            self, entry: FlextLDIFModels.Entry
        ) -> FlextResult[bool]:
            """Validate single entry structure."""
            try:
                # Validate DN
                entry.dn.validate_domain_rules()

                # Validate attributes
                entry.attributes.validate_domain_rules()

                return FlextResult[bool].ok(True)

            except Exception as e:
                return FlextResult[bool].fail(str(e))

        def validate_unique_dns(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[bool]:
            """Validate that all DNs are unique using flext-core utilities."""
            # Use FlextUtilities.TypeGuards.is_list_non_empty for validation
            if not FlextUtilities.TypeGuards.is_list_non_empty(entries):
                return FlextResult[bool].ok(True)

            seen_dns = set()

            for entry in entries:
                # Use FlextUtilities.TextProcessor.clean_text for normalization
                dn_value = entry.dn.value
                dn_normalized = FlextUtilities.TextProcessor.clean_text(
                    dn_value
                ).lower()

                if dn_normalized in seen_dns:
                    return FlextResult[bool].fail(f"Duplicate DN found: {dn_value}")
                seen_dns.add(dn_normalized)

            return FlextResult[bool].ok(True)

        def validate_ldif_entries(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[bool]:
            """Validate LDIF entries - alias for validate_entries."""
            return self.validate_entries(entries)

        def validate_entry(self, entry: FlextLDIFModels.Entry) -> FlextResult[bool]:
            """Validate single entry."""
            return self.validate_entry_structure(entry)

        def validate_dn_format(self, dn: str) -> FlextResult[bool]:
            """Validate DN format using flext-core validators."""
            # Use FlextValidations.validate_non_empty_string_func for validation
            if not FlextValidations.validate_non_empty_string_func(dn):
                return FlextResult[bool].fail("DN cannot be empty")

            # Use FlextUtilities.TypeGuards.is_string_non_empty for additional validation
            if FlextUtilities.TypeGuards.is_string_non_empty(dn):
                return FlextResult[bool].ok(True)
            return FlextResult[bool].fail(f"Invalid DN format: {dn}")

        def validate_data(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[bool]:
            """Validate data - alias for validate_entries."""
            return self.validate_entries(entries)

        def _validate_configuration_rules(
            self, entry: FlextLDIFModels.Entry
        ) -> FlextResult[bool]:
            """Validate entry against configuration rules."""
            # Use FlextUtilities.TypeGuards.is_not_none for config validation
            if not FlextUtilities.TypeGuards.is_not_none(self.config):
                return FlextResult[bool].ok(True)

            # Import here to avoid circular imports
            from flext_ldif.constants import FlextLDIFConstants

            config = self.config

            # Use FlextUtilities.TypeGuards.has_attribute for config validation
            if FlextUtilities.TypeGuards.has_attribute(
                config, "strict_validation"
            ) and getattr(config, "strict_validation", False):
                # Strict validation rules
                # Handle both real AttributesDict and Mock objects
                attributes_obj = entry.attributes
                if FlextUtilities.TypeGuards.has_attribute(
                    attributes_obj, "attributes"
                ):  # Mock object setup
                    attributes_dict = attributes_obj.attributes
                elif FlextUtilities.TypeGuards.has_attribute(
                    attributes_obj, "items"
                ):  # Real AttributesDict
                    attributes_dict = dict(attributes_obj)
                else:
                    return FlextResult[bool].ok(True)  # Can't validate

                for attr_name, attr_values in attributes_dict.items():
                    # Use FlextUtilities.TypeGuards.is_list_non_empty for validation
                    if not FlextUtilities.TypeGuards.is_list_non_empty(attr_values):
                        return FlextResult[bool].fail(
                            f"Empty attribute list for {attr_name}"
                        )

                    for value in attr_values:
                        if (
                            not value or not value.strip()
                        ):  # Empty or whitespace-only values
                            return FlextResult[bool].fail(
                                FlextLDIFConstants.FlextLDIFValidationMessages.EMPTY_ATTRIBUTE_VALUE_NOT_ALLOWED.format(
                                    attr_name=attr_name
                                )
                            )

            return FlextResult[bool].ok(True)

    class ParserService(FlextDomainService["list[FlextLDIFModels.Entry]"]):
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
        def execute(self) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Execute parsing operation."""
            return self.parse_ldif_content(self.content)

        def parse(self, content: str) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Parse LDIF content - standalone method for direct use."""
            return self.parse_ldif_content(content)

        def parse_entries_from_string(
            self, content: str
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Parse entries from string - alias for parse_ldif_content."""
            return self.parse_ldif_content(content)

        def parse_ldif_content(
            self, content: str
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Parse LDIF content into entries using flext-core utilities."""
            # Use FlextUtilities.TypeGuards.is_string_non_empty for validation
            if not FlextUtilities.TypeGuards.is_string_non_empty(content):
                return FlextResult[list[FlextLDIFModels.Entry]].ok([])

            # Validate syntax first
            syntax_result = self.validate_ldif_syntax(content)
            if not syntax_result.is_success:
                return FlextResult[list[FlextLDIFModels.Entry]].fail(
                    syntax_result.error or "Invalid LDIF syntax"
                )

            try:
                entries: list[FlextLDIFModels.Entry] = []
                current_entry_data: dict[str, str | list[str]] = {}

                # Use FlextUtilities.TextProcessor.clean_text for line processing
                for raw_line in content.strip().split("\n"):
                    line = FlextUtilities.TextProcessor.clean_text(raw_line)

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
                    # Use FlextUtilities.TextProcessor.clean_text for attribute processing
                    attr_name = FlextUtilities.TextProcessor.clean_text(attr_name)
                    attr_value = FlextUtilities.TextProcessor.clean_text(attr_value)

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

                return FlextResult[list[FlextLDIFModels.Entry]].ok(entries)

            except Exception as e:
                return FlextResult[list[FlextLDIFModels.Entry]].fail(
                    f"Parse error: {e}"
                )

        def parse_ldif_file(
            self, file_path: str, encoding: str = "utf-8"
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Parse LDIF file."""
            try:
                path_obj = Path(file_path)
                if not path_obj.exists():
                    return FlextResult[list[FlextLDIFModels.Entry]].fail(
                        f"File not found: {file_path}"
                    )

                content = path_obj.read_text(encoding=encoding)
                return self.parse_ldif_content(content)

            except Exception as e:
                return FlextResult[list[FlextLDIFModels.Entry]].fail(
                    f"File read error: {e}"
                )

        def validate_ldif_syntax(self, content: str) -> FlextResult[bool]:
            """Validate LDIF syntax without full parsing."""
            if not content or not content.strip():
                return FlextResult[bool].ok(True)

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

                return FlextResult[bool].ok(True)

            except Exception as e:
                return FlextResult[bool].fail(f"Syntax validation error: {e}")

        def _parse_entry_block(
            self, block: str
        ) -> FlextResult[FlextLDIFModels.Entry | None]:
            """Parse a single LDIF entry block."""
            if not block or not block.strip():
                return FlextResult[FlextLDIFModels.Entry | None].fail(
                    "Empty entry block"
                )

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
                    return FlextResult[FlextLDIFModels.Entry | None].fail(
                        "Entry missing DN"
                    )

                entry = FlextLDIFModels.Entry.from_dict(
                    cast("dict[str, object]", entry_data)
                )
                return FlextResult[FlextLDIFModels.Entry | None].ok(entry)

            except Exception as e:
                return FlextResult[FlextLDIFModels.Entry | None].fail(
                    f"Parse entry block error: {e}"
                )

    class TransformerService(FlextDomainService[list[FlextLDIFModels.Entry]]):
        """Transformer service for LDIF entry transformations."""

        # Define config as Pydantic field for the frozen model

        def __init__(self, config: object = None) -> None:
            super().__init__()
            self._config = config

        @property
        def config(self) -> object:
            return self._config

        @override
        def execute(self) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Execute transformation operation."""
            return FlextResult[list[FlextLDIFModels.Entry]].ok([])

        def transform_entry(
            self, entry: FlextLDIFModels.Entry
        ) -> FlextResult[FlextLDIFModels.Entry]:
            """Transform a single entry (base implementation returns as-is)."""
            return FlextResult[FlextLDIFModels.Entry].ok(entry)

        def transform_entries(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Transform multiple entries."""
            if not entries:
                return FlextResult[list[FlextLDIFModels.Entry]].ok([])

            try:
                # Use modern FlextUtilities.ResultUtils.batch_process for efficient batch transformation
                transformation_results = [
                    self.transform_entry(entry) for entry in entries
                ]

                # Check if all transformations succeeded
                failed_results = [r for r in transformation_results if not r.is_success]
                if failed_results:
                    first_error = failed_results[0].error or "Transform failed"
                    return FlextResult[list[FlextLDIFModels.Entry]].fail(first_error)

                # Extract successful values
                transformed = [r.value for r in transformation_results]
                return FlextResult[list[FlextLDIFModels.Entry]].ok(transformed)
            except Exception as e:
                return FlextResult[list[FlextLDIFModels.Entry]].fail(
                    f"Transform entries error: {e}"
                )

        def normalize_dns(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Normalize DNs in entries (base implementation returns as-is)."""
            return FlextResult[list[FlextLDIFModels.Entry]].ok(entries)

    # =========================================================================
    # FIELD UTILITY METHODS - Pydantic field factory methods (moved from loose functions)
    # =========================================================================

    @staticmethod
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

    @staticmethod
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

    @staticmethod
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

    @staticmethod
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


# Backward compatibility aliases
FlextLDIFParserService = FlextLDIFServices.ParserService
FlextLDIFValidatorService = FlextLDIFServices.ValidatorService
FlextLDIFWriterService = FlextLDIFServices.WriterService

# Field function aliases
dn_field = FlextLDIFServices.dn_field
attribute_name_field = FlextLDIFServices.attribute_name_field
attribute_value_field = FlextLDIFServices.attribute_value_field
object_class_field = FlextLDIFServices.object_class_field

# Export consolidated class and legacy aliases
__all__ = [
    "FlextLDIFParserService",  # Legacy alias
    "FlextLDIFServices",
    "FlextLDIFValidatorService",  # Legacy alias
    "FlextLDIFWriterService",  # Legacy alias
    "attribute_name_field",
    "attribute_value_field",
    # Field utility functions
    "dn_field",
    "object_class_field",
]
