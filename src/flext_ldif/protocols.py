"""FLEXT-LDIF Protocols.

Protocol definitions for LDIF processing using flext-core patterns.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

# FOUNDATION: Import ONLY from flext-core - NO duplication

if TYPE_CHECKING:
    from pathlib import Path

    from flext_core import FlextResult

    from .models import FlextLdifEntry


# =============================================================================
# APPLICATION PROTOCOLS - Extending flext-core protocols
# =============================================================================


@runtime_checkable
class FlextLdifParserProtocol(Protocol):
    """LDIF parsing protocol - extends flext-core patterns."""

    def parse(self, content: str) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF content into domain entities."""
        ...

    def parse_file(self, file_path: str | Path) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF file into domain entities."""
        ...

    def parse_entries_from_string(
        self,
        ldif_string: str,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Parse multiple entries from LDIF string."""
        ...


@runtime_checkable
class FlextLdifValidatorProtocol(Protocol):
    """LDIF validation protocol using flext-core patterns."""

    def validate(self, data: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate data using flext-core pattern."""
        ...

    def validate_entry(self, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Validate single LDIF entry."""
        ...

    def validate_entries(self, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate multiple LDIF entries."""
        ...

    def validate_dn_format(self, dn: str) -> FlextResult[bool]:
        """Validate DN format compliance."""
        ...


@runtime_checkable
class FlextLdifWriterProtocol(Protocol):
    """LDIF writing protocol."""

    def write(self, entries: list[FlextLdifEntry]) -> FlextResult[str]:
        """Write entries to LDIF string."""
        ...

    def write_file(
        self,
        entries: list[FlextLdifEntry],
        file_path: str | Path,
    ) -> FlextResult[bool]:
        """Write entries to LDIF file."""
        ...

    def write_entry(self, entry: FlextLdifEntry) -> FlextResult[str]:
        """Write single entry to LDIF string."""
        ...


@runtime_checkable
class FlextLdifRepositoryProtocol(Protocol):
    """LDIF data access protocol."""

    def find_by_dn(
        self,
        entries: list[FlextLdifEntry],
        dn: str,
    ) -> FlextResult[FlextLdifEntry | None]:
        """Find entry by distinguished name."""
        ...

    def filter_by_objectclass(
        self,
        entries: list[FlextLdifEntry],
        objectclass: str,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter entries by objectClass attribute."""
        ...

    def filter_by_attribute(
        self,
        entries: list[FlextLdifEntry],
        attribute: str,
        value: str,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter entries by attribute value."""
        ...

    def get_statistics(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[dict[str, int]]:
        """Get statistical information about entries."""
        ...


@runtime_checkable
class FlextLdifTransformerProtocol(Protocol):
    """LDIF transformation protocol."""

    def transform_entry(self, entry: FlextLdifEntry) -> FlextResult[FlextLdifEntry]:
        """Transform single LDIF entry."""
        ...

    def transform_entries(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Transform multiple LDIF entries."""
        ...

    def normalize_dns(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Normalize all DN values in entries."""
        ...


@runtime_checkable
class FlextLdifAnalyticsProtocol(Protocol):
    """LDIF analytics protocol for business intelligence."""

    def analyze_entry_patterns(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[dict[str, int]]:
        """Analyze patterns in LDIF entries."""
        ...

    def get_objectclass_distribution(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[dict[str, int]]:
        """Get distribution of objectClass types."""
        ...

    def get_dn_depth_analysis(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[dict[str, int]]:
        """Analyze DN depth distribution."""
        ...


# =============================================================================
# BACKWARD COMPATIBILITY ALIASES (DEPRECATED - use FlextLdif* versions)
# =============================================================================

# Legacy protocol aliases for backward compatibility
LdifParserProtocol = FlextLdifParserProtocol
LdifValidatorProtocol = FlextLdifValidatorProtocol
LdifWriterProtocol = FlextLdifWriterProtocol
LdifRepositoryProtocol = FlextLdifRepositoryProtocol
LdifTransformerProtocol = FlextLdifTransformerProtocol

# =============================================================================
# COMPREHENSIVE PUBLIC API - All protocols exported
# =============================================================================

__all__ = [
    # Modern Protocols (RECOMMENDED - use these in new code)
    "FlextLdifAnalyticsProtocol",
    "FlextLdifParserProtocol",
    "FlextLdifRepositoryProtocol",
    "FlextLdifTransformerProtocol",
    "FlextLdifValidatorProtocol",
    "FlextLdifWriterProtocol",
    # Legacy Aliases (DEPRECATED - for backward compatibility only)
    "LdifParserProtocol",  # Use FlextLdifParserProtocol instead
    "LdifRepositoryProtocol",  # Use FlextLdifRepositoryProtocol instead
    "LdifTransformerProtocol",  # Use FlextLdifTransformerProtocol instead
    "LdifValidatorProtocol",  # Use FlextLdifValidatorProtocol instead
    "LdifWriterProtocol",  # Use FlextLdifWriterProtocol instead
]
