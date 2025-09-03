"""FLEXT-LDIF Protocols - Unified protocol definition following flext-core patterns.

Single class per module containing all LDIF-related protocols as nested classes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from flext_core import FlextResult

from flext_ldif.models import FlextLDIFModels


class FlextLDIFProtocols:
    """Unified LDIF protocols following flext-core single-class-per-module pattern.

    Contains all LDIF-related protocols as nested classes for clean organization.
    """

    @runtime_checkable
    class ParserProtocol(Protocol):
        """LDIF parsing protocol - extends flext-core patterns."""

        def parse(self, content: str) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Parse LDIF content into domain entities."""
            ...

        def parse_file(
            self, file_path: str | Path
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Parse LDIF file into domain entities."""
            ...

        def parse_entries_from_string(
            self,
            ldif_string: str,
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Parse multiple entries from LDIF string."""
            ...

    @runtime_checkable
    class ValidatorProtocol(Protocol):
        """LDIF validation protocol using flext-core patterns."""

        def validate(self, data: list[FlextLDIFModels.Entry]) -> FlextResult[bool]:
            """Validate data using flext-core pattern."""
            ...

        def validate_entry(self, entry: FlextLDIFModels.Entry) -> FlextResult[bool]:
            """Validate single LDIF entry."""
            ...

        def validate_entries(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[bool]:
            """Validate multiple LDIF entries."""
            ...

        def validate_dn_format(self, dn: str) -> FlextResult[bool]:
            """Validate DN format compliance."""
            ...

    @runtime_checkable
    class WriterProtocol(Protocol):
        """LDIF writing protocol."""

        def write(self, entries: list[FlextLDIFModels.Entry]) -> FlextResult[str]:
            """Write entries to LDIF string."""
            ...

        def write_file(
            self,
            entries: list[FlextLDIFModels.Entry],
            file_path: str | Path,
        ) -> FlextResult[bool]:
            """Write entries to LDIF file."""
            ...

        def write_entry(self, entry: FlextLDIFModels.Entry) -> FlextResult[str]:
            """Write single entry to LDIF string."""
            ...

    @runtime_checkable
    class RepositoryProtocol(Protocol):
        """LDIF data access protocol."""

        def find_by_dn(
            self,
            entries: list[FlextLDIFModels.Entry],
            dn: str,
        ) -> FlextResult[FlextLDIFModels.Entry | None]:
            """Find entry by distinguished name."""
            ...

        def filter_by_objectclass(
            self,
            entries: list[FlextLDIFModels.Entry],
            objectclass: str,
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Filter entries by objectClass attribute."""
            ...

        def filter_by_attribute(
            self,
            entries: list[FlextLDIFModels.Entry],
            attribute: str,
            value: str,
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Filter entries by attribute value."""
            ...

        def get_statistics(
            self,
            entries: list[FlextLDIFModels.Entry],
        ) -> FlextResult[dict[str, int]]:
            """Get statistical information about entries."""
            ...

    @runtime_checkable
    class TransformerProtocol(Protocol):
        """LDIF transformation protocol."""

        def transform_entry(
            self, entry: FlextLDIFModels.Entry
        ) -> FlextResult[FlextLDIFModels.Entry]:
            """Transform single LDIF entry."""
            ...

        def transform_entries(
            self,
            entries: list[FlextLDIFModels.Entry],
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Transform multiple LDIF entries."""
            ...

        def normalize_dns(
            self,
            entries: list[FlextLDIFModels.Entry],
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Normalize all DN values in entries."""
            ...

    @runtime_checkable
    class AnalyticsProtocol(Protocol):
        """LDIF analytics protocol for business intelligence."""

        def analyze_entry_patterns(
            self,
            entries: list[FlextLDIFModels.Entry],
        ) -> FlextResult[dict[str, int]]:
            """Analyze patterns in LDIF entries."""
            ...

        def get_objectclass_distribution(
            self,
            entries: list[FlextLDIFModels.Entry],
        ) -> FlextResult[dict[str, int]]:
            """Get distribution of objectClass types."""
            ...

        def get_dn_depth_analysis(
            self,
            entries: list[FlextLDIFModels.Entry],
        ) -> FlextResult[dict[str, int]]:
            """Analyze DN depth distribution."""
            ...


__all__ = [
    "FlextLDIFProtocols",
]
