"""FLEXT-LDIF Services - Unified Interface.

Provides unified access to all LDIF services while maintaining SOLID principles.
Uses flext-core SOURCE OF TRUTH exclusively.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from flext_core import FlextResult

from flext_ldif.format_handlers import FlextLDIFFormatHandler
from flext_ldif.format_validators import FlextLDIFFormatValidators
from flext_ldif.models import FlextLDIFModels
from pydantic import Field


class FlextLDIFServices:
    """Unified LDIF Services - Complete Implementation with SOLID Principles.

    Single consolidated class implementing all LDIF services while maintaining
    single responsibility principle. Uses flext-core SOURCE OF TRUTH exclusively.
    """

    def __init__(self, config: FlextLDIFModels.Config | None = None) -> None:
        """Initialize unified LDIF services."""
        self._config = config or FlextLDIFModels.Config()
        self._format_handler = FlextLDIFFormatHandler()
        self._format_validator = FlextLDIFFormatValidators()

        # Initialize nested services
        self.parser = self.Parser(self)
        self.validator = self.Validator(self)
        self.writer = self.Writer(self)
        self.analytics = self.Analytics(self)
        self.transformer = self.Transformer(self)
        self.repository = self.Repository(self)

    @property
    def config(self) -> FlextLDIFModels.Config:
        """Get services configuration."""
        return self._config

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute services operation."""
        return FlextResult[dict[str, object]].ok({"status": "ready"})

    class Parser:
        """Nested parser service for LDIF parsing operations."""

        def __init__(self, services_instance: FlextLDIFServices) -> None:
            """Initialize parser with parent services reference."""
            self._services = services_instance
            self._format_handler = services_instance._format_handler

        def parse_ldif_file(
            self, file_path: str | Path
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Parse LDIF file using format handler."""
            try:
                with Path(file_path).open(encoding="utf-8") as f:
                    content = f.read()
                return self.parse_content(content)
            except Exception as e:
                return FlextResult[list[FlextLDIFModels.Entry]].fail(f"File read error: {e}")

        def parse_content(self, content: str) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Parse LDIF content using format handler."""
            if not content.strip():
                return FlextResult[list[FlextLDIFModels.Entry]].ok([])

            try:
                result = self._format_handler.parse_ldif(content)
                if result.is_success:
                    return result
                return FlextResult[list[FlextLDIFModels.Entry]].fail(f"Parse error: {result.error}")
            except Exception as e:
                return FlextResult[list[FlextLDIFModels.Entry]].fail(f"Parse error: {e}")

    class Validator:
        """Nested validator service for LDIF validation operations."""

        def __init__(self, services_instance: FlextLDIFServices) -> None:
            """Initialize validator with parent services reference."""
            self._services = services_instance
            self._format_validator = services_instance._format_validator

        def validate_entries(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[bool]:
            """Validate LDIF entries using format validator."""
            if not entries:
                return FlextResult[bool].fail("Cannot validate empty entry list")

            try:
                for entry in entries:
                    validation_result = self._format_validator.validate_entry(entry)
                    if validation_result.is_failure:
                        return validation_result
                return FlextResult[bool].ok(data=True)
            except Exception as e:
                return FlextResult[bool].fail(f"Validation error: {e}")

        def validate_entry_structure(
            self, entry: FlextLDIFModels.Entry
        ) -> FlextResult[bool]:
            """Validate single entry structure."""
            try:
                return self._format_validator.validate_entry(entry)
            except Exception as e:
                return FlextResult[bool].fail(f"Entry validation error: {e}")

        def validate_dn_format(self, dn: str) -> FlextResult[bool]:
            """Validate DN format."""
            try:
                return self._format_validator.validate_dn_format(dn)
            except Exception as e:
                return FlextResult[bool].fail(f"DN validation error: {e}")

    class Writer:
        """Nested writer service for LDIF writing operations."""

        def __init__(self, services_instance: FlextLDIFServices) -> None:
            """Initialize writer with parent services reference."""
            self._services = services_instance
            self._format_handler = services_instance._format_handler

        def write_entries_to_file(
            self, entries: list[FlextLDIFModels.Entry], file_path: str | Path
        ) -> FlextResult[bool]:
            """Write LDIF entries to file."""
            try:
                content_result = self.write_entries_to_string(entries)
                if content_result.is_failure:
                    return FlextResult[bool].fail(content_result.error or "Content generation failed")

                with Path(file_path).open("w", encoding="utf-8") as f:
                    f.write(content_result.unwrap())
                return FlextResult[bool].ok(data=True)
            except Exception as e:
                return FlextResult[bool].fail(f"File write error: {e}")

        def write_entries_to_string(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[str]:
            """Write LDIF entries to string."""
            try:
                result = self._format_handler.write_ldif(entries)
                if result.is_success:
                    return result
                return FlextResult[str].fail(f"String write error: {result.error}")
            except Exception as e:
                return FlextResult[str].fail(f"String write error: {e}")

    class Analytics:
        """Nested analytics service for LDIF analysis operations."""

        def __init__(self, services_instance: FlextLDIFServices) -> None:
            """Initialize analytics with parent services reference."""
            self._services = services_instance

        def analyze_entries(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[dict[str, int]]:
            """Analyze LDIF entries and return statistics."""
            try:
                stats = {
                    "total_entries": len(entries),
                    "person_entries": sum(1 for e in entries if e.is_person()),
                    "group_entries": sum(1 for e in entries if e.is_group()),
                    "organizational_unit_entries": sum(1 for e in entries if "organizationalunit" in (oc.lower() for oc in (e.get_attribute("objectClass") or []))),
                }
                return FlextResult[dict[str, int]].ok(stats)
            except Exception as e:
                return FlextResult[dict[str, int]].fail(f"Analysis error: {e}")

        def analyze_patterns(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[dict[str, int]]:
            """Analyze patterns in LDIF entries."""
            return self.analyze_entries(entries)

        def get_objectclass_distribution(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[dict[str, int]]:
            """Get distribution of objectClass types."""
            try:
                distribution: dict[str, int] = {}
                for entry in entries:
                    object_classes = entry.get_attribute("objectClass") or []
                    for oc in object_classes:
                        distribution[oc.lower()] = distribution.get(oc.lower(), 0) + 1
                return FlextResult[dict[str, int]].ok(distribution)
            except Exception as e:
                return FlextResult[dict[str, int]].fail(f"Distribution analysis error: {e}")

        def get_dn_depth_analysis(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[dict[str, int]]:
            """Analyze DN depth distribution."""
            try:
                depth_distribution: dict[str, int] = {}
                for entry in entries:
                    depth = len(entry.dn.value.split(","))
                    depth_distribution[f"depth_{depth}"] = depth_distribution.get(f"depth_{depth}", 0) + 1
                return FlextResult[dict[str, int]].ok(depth_distribution)
            except Exception as e:
                return FlextResult[dict[str, int]].fail(f"DN depth analysis error: {e}")

    class Transformer:
        """Nested transformer service for LDIF transformation operations."""

        def __init__(self, services_instance: FlextLDIFServices) -> None:
            """Initialize transformer with parent services reference."""
            self._services = services_instance

        def execute(self) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Execute transformer operation - returns empty list by default."""
            return FlextResult[list[FlextLDIFModels.Entry]].ok([])

        def transform_entries(
            self,
            entries: list[FlextLDIFModels.Entry],
            transform_function: Callable[[FlextLDIFModels.Entry], FlextLDIFModels.Entry],
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Transform LDIF entries using provided function."""
            try:
                transformed = [transform_function(entry) for entry in entries]
                return FlextResult[list[FlextLDIFModels.Entry]].ok(transformed)
            except Exception as e:
                return FlextResult[list[FlextLDIFModels.Entry]].fail(f"Transform error: {e}")

    class Repository:
        """Nested repository service for LDIF data operations."""

        def __init__(self, services_instance: FlextLDIFServices) -> None:
            """Initialize repository with parent services reference."""
            self._services = services_instance

        def filter_entries_by_object_class(
            self, entries: list[FlextLDIFModels.Entry], object_class: str
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Filter entries by objectClass attribute."""
            try:
                filtered = [
                    entry for entry in entries
                    if object_class.lower() in (oc.lower() for oc in (entry.get_attribute("objectClass") or []))
                ]
                return FlextResult[list[FlextLDIFModels.Entry]].ok(filtered)
            except Exception as e:
                return FlextResult[list[FlextLDIFModels.Entry]].fail(f"Filter error: {e}")

        def filter_entries_by_attribute(
            self, entries: list[FlextLDIFModels.Entry], attribute: str, value: str
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Filter entries by specific attribute value."""
            try:
                filtered = [
                    entry for entry in entries
                    if value in (entry.get_attribute(attribute) or [])
                ]
                return FlextResult[list[FlextLDIFModels.Entry]].ok(filtered)
            except Exception as e:
                return FlextResult[list[FlextLDIFModels.Entry]].fail(f"Filter error: {e}")

        def find_entry_by_dn(
            self, entries: list[FlextLDIFModels.Entry], dn: str
        ) -> FlextResult[FlextLDIFModels.Entry | None]:
            """Find entry by DN."""
            try:
                for entry in entries:
                    if entry.dn.value.lower() == dn.lower():
                        return FlextResult[FlextLDIFModels.Entry | None].ok(entry)
                return FlextResult[FlextLDIFModels.Entry | None].ok(None)
            except Exception as e:
                return FlextResult[FlextLDIFModels.Entry | None].fail(f"Find error: {e}")

        def get_statistics(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[dict[str, int]]:
            """Get comprehensive entry statistics."""
            try:
                stats = {
                    "total_entries": len(entries),
                    "unique_dns": len({entry.dn.value for entry in entries}),
                    "total_attributes": sum(len(entry.attributes) for entry in entries),
                }
                return FlextResult[dict[str, int]].ok(stats)
            except Exception as e:
                return FlextResult[dict[str, int]].fail(f"Statistics error: {e}")

    # Convenience methods for backward compatibility
    def parse_ldif_file(
        self, file_path: str | Path
    ) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Parse LDIF file using parser service."""
        return self.parser.parse_ldif_file(file_path)

    def parse_string(self, content: str) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Parse LDIF content using parser service."""
        return self.parser.parse_content(content)

    def validate_entries(
        self, entries: list[FlextLDIFModels.Entry]
    ) -> FlextResult[bool]:
        """Validate LDIF entries using validator service."""
        return self.validator.validate_entries(entries)

    def write_entries_to_file(
        self, entries: list[FlextLDIFModels.Entry], file_path: str | Path
    ) -> FlextResult[bool]:
        """Write LDIF entries to file using writer service."""
        return self.writer.write_entries_to_file(entries, file_path)

    def write_entries_to_string(
        self, entries: list[FlextLDIFModels.Entry]
    ) -> FlextResult[str]:
        """Write LDIF entries to string using writer service."""
        return self.writer.write_entries_to_string(entries)

    def analyze_entries(
        self, entries: list[FlextLDIFModels.Entry]
    ) -> FlextResult[dict[str, int]]:
        """Analyze LDIF entries using analytics service."""
        return self.analytics.analyze_entries(entries)

    def transform_entries(
        self,
        entries: list[FlextLDIFModels.Entry],
        transform_function: Callable[[FlextLDIFModels.Entry], FlextLDIFModels.Entry],
    ) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Transform LDIF entries using transformer service."""
        return self.transformer.transform_entries(entries, transform_function)

    # Field creation methods for Pydantic models
    @staticmethod
    def dn_field(
        min_length: int = 1,
        max_length: int = 1024,
        description: str = "LDAP Distinguished Name",
        **kwargs: object,
    ) -> Field:
        """Create DN field for Pydantic models."""
        return Field(
            min_length=min_length,
            max_length=max_length,
            description=description,
            **kwargs,
        )

    @staticmethod
    def attribute_name_field(
        min_length: int = 1,
        max_length: int = 255,
        description: str = "LDAP Attribute Name",
        **kwargs: object,
    ) -> Field:
        """Create attribute name field for Pydantic models."""
        return Field(
            min_length=min_length,
            max_length=max_length,
            description=description,
            **kwargs,
        )

    @staticmethod
    def attribute_value_field(
        min_length: int = 1,
        max_length: int = 65536,
        description: str = "LDAP Attribute Value",
        **kwargs: object,
    ) -> Field:
        """Create attribute value field for Pydantic models."""
        return Field(
            min_length=min_length,
            max_length=max_length,
            description=description,
            **kwargs,
        )

    @staticmethod
    def object_class_field(
        min_length: int = 1,
        max_length: int = 255,
        description: str = "LDAP Object Class",
        **kwargs: object,
    ) -> Field:
        """Create object class field for Pydantic models."""
        return Field(
            min_length=min_length,
            max_length=max_length,
            description=description,
            **kwargs,
        )


# Backward compatibility aliases - using nested services
class Analytics:
    """Backward compatibility alias for analytics service."""

    def __init__(self, config: FlextLDIFModels.Config | None = None) -> None:
        """Initialize analytics service."""
        self._services = FlextLDIFServices(config)
        self._analytics = self._services.analytics

    def analyze_entries(self, entries: list[FlextLDIFModels.Entry]) -> FlextResult[dict[str, int]]:
        """Analyze LDIF entries."""
        return self._analytics.analyze_entries(entries)


class Parser:
    """Backward compatibility alias for parser service."""

    def __init__(self, config: FlextLDIFModels.Config | None = None) -> None:
        """Initialize parser service."""
        self._services = FlextLDIFServices(config)
        self._parser = self._services.parser

    def parse_ldif_file(self, file_path: str | Path) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Parse LDIF file."""
        return self._parser.parse_ldif_file(file_path)

    def parse_content(self, content: str) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Parse LDIF content."""
        return self._parser.parse_content(content)


class Validator:
    """Backward compatibility alias for validator service."""

    def __init__(self, config: FlextLDIFModels.Config | None = None) -> None:
        """Initialize validator service."""
        self._services = FlextLDIFServices(config)
        self._validator = self._services.validator

    def validate_entries(self, entries: list[FlextLDIFModels.Entry]) -> FlextResult[bool]:
        """Validate LDIF entries."""
        return self._validator.validate_entries(entries)


class Writer:
    """Backward compatibility alias for writer service."""

    def __init__(self, config: FlextLDIFModels.Config | None = None) -> None:
        """Initialize writer service."""
        self._services = FlextLDIFServices(config)
        self._writer = self._services.writer

    def write_entries_to_file(self, entries: list[FlextLDIFModels.Entry], file_path: str | Path) -> FlextResult[bool]:
        """Write LDIF entries to file."""
        return self._writer.write_entries_to_file(entries, file_path)

    def write_entries_to_string(self, entries: list[FlextLDIFModels.Entry]) -> FlextResult[str]:
        """Write LDIF entries to string."""
        return self._writer.write_entries_to_string(entries)


class Transformer:
    """Backward compatibility alias for transformer service."""

    def __init__(self, config: FlextLDIFModels.Config | None = None) -> None:
        """Initialize transformer service."""
        self._services = FlextLDIFServices(config)
        self._transformer = self._services.transformer

    def transform_entries(
        self,
        entries: list[FlextLDIFModels.Entry],
        transform_function: Callable[[FlextLDIFModels.Entry], FlextLDIFModels.Entry],
    ) -> FlextResult[list[FlextLDIFModels.Entry]]:
        """Transform LDIF entries."""
        return self._transformer.transform_entries(entries, transform_function)


__all__ = [
    "Analytics",
    "FlextLDIFServices",
    "Parser",
    "Transformer",
    "Validator",
    "Writer",
]
