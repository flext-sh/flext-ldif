"""FLEXT-LDIF Protocols.

Protocol definitions for LDIF processing using flext-core patterns.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from flext_core import (
    FlextResult,
)

from flext_ldif.models import FlextLDIFEntry


@runtime_checkable
class FlextLDIFParserProtocol(Protocol):
    """LDIF parsing protocol - extends flext-core patterns."""

    def parse(self, content: str) -> FlextResult[list[FlextLDIFEntry]]:
        """Parse LDIF content into domain entities."""
        ...

    def parse_file(self, file_path: str | Path) -> FlextResult[list[FlextLDIFEntry]]:
        """Parse LDIF file into domain entities."""
        ...

    def parse_entries_from_string(
        self,
        ldif_string: str,
    ) -> FlextResult[list[FlextLDIFEntry]]:
        """Parse multiple entries from LDIF string."""
        ...


@runtime_checkable
class FlextLDIFValidatorProtocol(Protocol):
    """LDIF validation protocol using flext-core patterns."""

    def validate(self, data: list[FlextLDIFEntry]) -> FlextResult[bool]:
        """Validate data using flext-core pattern."""
        ...

    def validate_entry(self, entry: FlextLDIFEntry) -> FlextResult[bool]:
        """Validate single LDIF entry."""
        ...

    def validate_entries(self, entries: list[FlextLDIFEntry]) -> FlextResult[bool]:
        """Validate multiple LDIF entries."""
        ...

    def validate_dn_format(self, dn: str) -> FlextResult[bool]:
        """Validate DN format compliance."""
        ...


@runtime_checkable
class FlextLDIFWriterProtocol(Protocol):
    """LDIF writing protocol."""

    def write(self, entries: list[FlextLDIFEntry]) -> FlextResult[str]:
        """Write entries to LDIF string."""
        ...

    def write_file(
        self,
        entries: list[FlextLDIFEntry],
        file_path: str | Path,
    ) -> FlextResult[bool]:
        """Write entries to LDIF file."""
        ...

    def write_entry(self, entry: FlextLDIFEntry) -> FlextResult[str]:
        """Write single entry to LDIF string."""
        ...


@runtime_checkable
class FlextLDIFRepositoryProtocol(Protocol):
    """LDIF data access protocol."""

    def find_by_dn(
        self,
        entries: list[FlextLDIFEntry],
        dn: str,
    ) -> FlextResult[FlextLDIFEntry | None]:
        """Find entry by distinguished name."""
        ...

    def filter_by_objectclass(
        self,
        entries: list[FlextLDIFEntry],
        objectclass: str,
    ) -> FlextResult[list[FlextLDIFEntry]]:
        """Filter entries by objectClass attribute."""
        ...

    def filter_by_attribute(
        self,
        entries: list[FlextLDIFEntry],
        attribute: str,
        value: str,
    ) -> FlextResult[list[FlextLDIFEntry]]:
        """Filter entries by attribute value."""
        ...

    def get_statistics(
        self,
        entries: list[FlextLDIFEntry],
    ) -> FlextResult[dict[str, int]]:
        """Get statistical information about entries."""
        ...


@runtime_checkable
class FlextLDIFTransformerProtocol(Protocol):
    """LDIF transformation protocol."""

    def transform_entry(self, entry: FlextLDIFEntry) -> FlextResult[FlextLDIFEntry]:
        """Transform single LDIF entry."""
        ...

    def transform_entries(
        self,
        entries: list[FlextLDIFEntry],
    ) -> FlextResult[list[FlextLDIFEntry]]:
        """Transform multiple LDIF entries."""
        ...

    def normalize_dns(
        self,
        entries: list[FlextLDIFEntry],
    ) -> FlextResult[list[FlextLDIFEntry]]:
        """Normalize all DN values in entries."""
        ...


@runtime_checkable
class FlextLDIFAnalyticsProtocol(Protocol):
    """LDIF analytics protocol for business intelligence."""

    def analyze_entry_patterns(
        self,
        entries: list[FlextLDIFEntry],
    ) -> FlextResult[dict[str, int]]:
        """Analyze patterns in LDIF entries."""
        ...

    def get_objectclass_distribution(
        self,
        entries: list[FlextLDIFEntry],
    ) -> FlextResult[dict[str, int]]:
        """Get distribution of objectClass types."""
        ...

    def get_dn_depth_analysis(
        self,
        entries: list[FlextLDIFEntry],
    ) -> FlextResult[dict[str, int]]:
        """Analyze DN depth distribution."""
        ...


# Removed legacy aliases - use FlextLDIF* versions directly

# =============================================================================
# COMPREHENSIVE PUBLIC API - All protocols exported
# =============================================================================

__all__ = [
    # Modern Protocols - clean API without legacy aliases
    "FlextLDIFAnalyticsProtocol",
    "FlextLDIFParserProtocol",
    "FlextLDIFRepositoryProtocol",
    "FlextLDIFTransformerProtocol",
    "FlextLDIFValidatorProtocol",
    "FlextLDIFWriterProtocol",
]
