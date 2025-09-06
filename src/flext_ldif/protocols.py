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

        def parse(self, content: str) -> FlextResult:
            """Parse LDIF content into domain entities."""
            msg = "Must be implemented by concrete parser"
            raise NotImplementedError(msg)

        def parse_file(self, file_path: str | Path) -> FlextResult:
            """Parse LDIF file into domain entities."""
            msg = "Must be implemented by concrete parser"
            raise NotImplementedError(msg)

        def parse_entries_from_string(
            self,
            ldif_string: str,
        ) -> FlextResult:
            """Parse multiple entries from LDIF string."""
            msg = "Must be implemented by concrete parser"
            raise NotImplementedError(msg)

    @runtime_checkable
    class ValidatorProtocol(Protocol):
        """LDIF validation protocol using flext-core patterns."""

        def validate(self, data: list[FlextLDIFModels.Entry]) -> FlextResult:
            """Validate data using flext-core pattern."""
            msg = "Must be implemented by concrete validator"
            raise NotImplementedError(msg)

        def validate_entry(self, entry: FlextLDIFModels.Entry) -> FlextResult:
            """Validate single LDIF entry."""
            msg = "Must be implemented by concrete validator"
            raise NotImplementedError(msg)

        def validate_entries(self, entries: list[FlextLDIFModels.Entry]) -> FlextResult:
            """Validate multiple LDIF entries."""
            msg = "Must be implemented by concrete validator"
            raise NotImplementedError(msg)

        def validate_dn_format(self, dn: str) -> FlextResult:
            """Validate DN format compliance."""
            msg = "Must be implemented by concrete validator"
            raise NotImplementedError(msg)

    @runtime_checkable
    class WriterProtocol(Protocol):
        """LDIF writing protocol."""

        def write(self, entries: list[FlextLDIFModels.Entry]) -> FlextResult:
            """Write entries to LDIF string."""
            msg = "Must be implemented by concrete writer"
            raise NotImplementedError(msg)

        def write_file(
            self,
            entries: list[FlextLDIFModels.Entry],
            file_path: str | Path,
        ) -> FlextResult:
            """Write entries to LDIF file."""
            msg = "Must be implemented by concrete writer"
            raise NotImplementedError(msg)

        def write_entry(self, entry: FlextLDIFModels.Entry) -> FlextResult:
            """Write single entry to LDIF string."""
            msg = "Must be implemented by concrete writer"
            raise NotImplementedError(msg)

    @runtime_checkable
    class RepositoryProtocol(Protocol):
        """LDIF data access protocol."""

        def find_by_dn(
            self,
            entries: list[FlextLDIFModels.Entry],
            dn: str,
        ) -> FlextResult:
            """Find entry by distinguished name."""
            msg = "Must be implemented by concrete repository"
            raise NotImplementedError(msg)

        def filter_by_objectclass(
            self,
            entries: list[FlextLDIFModels.Entry],
            objectclass: str,
        ) -> FlextResult:
            """Filter entries by objectClass attribute."""
            msg = "Must be implemented by concrete repository"
            raise NotImplementedError(msg)

        def filter_by_attribute(
            self,
            entries: list[FlextLDIFModels.Entry],
            attribute: str,
            value: str,
        ) -> FlextResult:
            """Filter entries by attribute value."""
            msg = "Must be implemented by concrete repository"
            raise NotImplementedError(msg)

        def get_statistics(
            self,
            entries: list[FlextLDIFModels.Entry],
        ) -> FlextResult:
            """Get statistical information about entries."""
            msg = "Must be implemented by concrete repository"
            raise NotImplementedError(msg)

    @runtime_checkable
    class TransformerProtocol(Protocol):
        """LDIF transformation protocol."""

        def transform_entry(self, entry: FlextLDIFModels.Entry) -> FlextResult:
            """Transform single LDIF entry."""
            msg = "Must be implemented by concrete transformer"
            raise NotImplementedError(msg)

        def transform_entries(
            self,
            entries: list[FlextLDIFModels.Entry],
        ) -> FlextResult:
            """Transform multiple LDIF entries."""
            msg = "Must be implemented by concrete transformer"
            raise NotImplementedError(msg)

        def normalize_dns(
            self,
            entries: list[FlextLDIFModels.Entry],
        ) -> FlextResult:
            """Normalize all DN values in entries."""
            msg = "Must be implemented by concrete transformer"
            raise NotImplementedError(msg)

    @runtime_checkable
    class AnalyticsProtocol(Protocol):
        """LDIF analytics protocol for business intelligence."""

        def analyze_patterns(
            self,
            entries: list[FlextLDIFModels.Entry],
        ) -> FlextResult:
            """Analyze patterns in LDIF entries."""
            msg = "Must be implemented by concrete analytics service"
            raise NotImplementedError(msg)

        def analyze_entry_patterns(
            self,
            entries: list[FlextLDIFModels.Entry],
        ) -> FlextResult:
            """Analyze patterns in LDIF entries."""
            msg = "Must be implemented by concrete analytics service"
            raise NotImplementedError(msg)

        def get_objectclass_distribution(
            self,
            entries: list[FlextLDIFModels.Entry],
        ) -> FlextResult:
            """Get distribution of objectClass types."""
            msg = "Must be implemented by concrete analytics service"
            raise NotImplementedError(msg)

        def get_dn_depth_analysis(
            self,
            entries: list[FlextLDIFModels.Entry],
        ) -> FlextResult:
            """Analyze DN depth distribution."""
            msg = "Must be implemented by concrete analytics service"
            raise NotImplementedError(msg)


__all__ = [
    "FlextLDIFProtocols",
]
