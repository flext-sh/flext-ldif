"""FLEXT LDIF Protocols.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from flext_core import FlextProtocols, FlextResult


class FlextLdifProtocols(FlextProtocols):
    """LDIF-specific protocols extending flext-core FlextProtocols.

    Contains ONLY protocol definitions for duck typing support.
    """

    @runtime_checkable
    class LdifEntryProtocol(Protocol):
        """Protocol for LDIF entry objects."""

        @property
        def dn(self) -> object:
            """Get the distinguished name of the entry."""
            ...

        @property
        def attributes(self) -> object:
            """Get the attributes of the entry."""
            ...

        def get_attribute(self, name: str) -> list[str] | None:
            """Get attribute values by name."""
            ...

        def has_object_class(self, object_class: str) -> bool:
            """Check if entry has specified object class."""
            ...

        def is_person_entry(self) -> bool:
            """Check if entry is a person entry."""
            ...

        def validate_business_rules(self) -> FlextResult[bool]:
            """Validate entry against business rules."""
            ...

    @runtime_checkable
    class LdifProcessorProtocol(Protocol):
        """Protocol for LDIF processors."""

        def parse(self, content: str) -> FlextResult[list[object]]:
            """Parse LDIF content string into entries."""
            ...

        def validate_entries(self, entries: list[object]) -> FlextResult[list[object]]:
            """Validate LDIF entries."""
            ...

        def write(self, entries: list[object]) -> FlextResult[str]:
            """Write entries to LDIF string."""
            ...

        def transform_entries(
            self, entries: list[object], transformer: object
        ) -> FlextResult[list[object]]:
            """Transform entries using transformer function."""
            ...

        def analyze_entries(
            self, entries: list[object]
        ) -> FlextResult[dict[str, object]]:
            """Analyze entries and provide statistics."""
            ...

    @runtime_checkable
    class LdifValidatorProtocol(Protocol):
        """Protocol for LDIF validators."""

        def validate_entry(self, entry: object) -> FlextResult[bool]:
            """Validate a single LDIF entry."""
            ...

        def validate_entries(self, entries: list[object]) -> FlextResult[bool]:
            """Validate multiple LDIF entries."""
            ...

        def get_validation_errors(self) -> list[str]:
            """Get list of validation errors."""
            ...

    @runtime_checkable
    class LdifWriterProtocol(Protocol):
        """Protocol for LDIF writers."""

        def write_entries_to_string(self, entries: list[object]) -> FlextResult[str]:
            """Write entries to LDIF format string."""
            ...

        def write_entries_to_file(
            self, entries: list[object], file_path: str
        ) -> FlextResult[bool]:
            """Write entries to LDIF file."""
            ...

    @runtime_checkable
    class LdifAnalyticsProtocol(Protocol):
        """Protocol for LDIF analytics."""

        def analyze_entries(
            self, entries: list[object]
        ) -> FlextResult[dict[str, object]]:
            """Analyze LDIF entries and generate analytics."""
            ...

        def get_statistics(self) -> dict[str, int | float]:
            """Get analytics statistics."""
            ...

        def detect_patterns(self, entries: list[object]) -> dict[str, object]:
            """Detect patterns in LDIF entries."""
            ...


__all__ = ["FlextLdifProtocols"]
