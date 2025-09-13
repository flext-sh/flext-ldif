"""FLEXT LDIF Protocols - Type protocols for LDIF operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from flext_core import FlextProtocols, FlextResult

from flext_ldif.models import FlextLDIFModels


class FlextLDIFProtocols:
    """LDIF Protocols using flext-core SOURCE OF TRUTH directly.

    Provides direct access to FlextProtocols plus minimal LDIF-specific
    protocol extensions. No duplication of base functionality.
    """

    # Direct access to flext-core protocols as SOURCE OF TRUTH
    Foundation = FlextProtocols.Foundation  # All foundation protocols
    Service = FlextProtocols.Foundation.Factory  # Use Factory as Service protocol
    Repository = FlextProtocols.Foundation.Factory  # Use Factory as Repository protocol
    Validator = FlextProtocols.Foundation.Validator  # Validator protocol
    Handler = FlextProtocols.Foundation.ErrorHandler  # Handler protocol
    Factory = FlextProtocols.Foundation.Factory  # Factory protocol
    LdapConnection = FlextProtocols.Foundation.Factory  # Use Factory as LDAP connection

    # LDIF-specific protocol extensions (minimal domain-specific additions only)
    @runtime_checkable
    class LdifRepository(
        FlextProtocols.Foundation.Factory[FlextLDIFModels.Entry], Protocol
    ):
        """LDIF-specific repository protocol extending flext-core Factory."""

        def find_by_dn(self, dn: str) -> FlextResult[FlextLDIFModels.Entry | None]:
            """Find entry by DN - domain-specific method."""
            ...

        def filter_by_objectclass(
            self, object_class: str
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Filter entries by objectClass - domain-specific method."""
            ...

    @runtime_checkable
    class LdifParser(Protocol):
        """LDIF-specific parser protocol extending flext-core patterns."""

        def parse_ldif_content(
            self, content: str
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Parse LDIF content - domain-specific method."""
            ...

        def parse_ldif_file(
            self, file_path: str | Path
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Parse LDIF file - domain-specific method."""
            ...

        def parse(self, content: str) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Parse LDIF content - test compatibility alias."""
            ...

        def parse_file(
            self, file_path: str | Path
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Parse LDIF file - test compatibility alias."""
            ...

    @runtime_checkable
    class LdifValidator(
        FlextProtocols.Foundation.Validator[FlextLDIFModels.Entry], Protocol
    ):
        """LDIF-specific validator protocol extending flext-core Validator."""

        def validate_ldif_syntax(self, content: str) -> FlextResult[bool]:
            """Validate LDIF syntax - domain-specific method."""
            ...

        def validate_entry(self, entry: FlextLDIFModels.Entry) -> FlextResult[bool]:
            """Validate single LDIF entry - test compatibility method."""
            ...

        def validate_entries(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[bool]:
            """Validate multiple LDIF entries - test compatibility method."""
            ...

    @runtime_checkable
    class LdifWriter(Protocol):
        """LDIF-specific writer protocol - minimal domain extension."""

        def write_ldif_entries(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[str]:
            """Write LDIF entries - domain-specific method."""
            ...

        def write(self, entries: list[FlextLDIFModels.Entry]) -> FlextResult[str]:
            """Write LDIF entries - test compatibility alias."""
            ...

        def write_file(
            self, entries: list[FlextLDIFModels.Entry], file_path: str | Path
        ) -> FlextResult[bool]:
            """Write LDIF entries to file - test compatibility alias."""
            ...

    @runtime_checkable
    class LdifTransformer(
        FlextProtocols.Foundation.Factory[FlextLDIFModels.Entry], Protocol
    ):
        """LDIF-specific transformer protocol extending flext-core Factory."""

        def transform_entries(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Transform LDIF entries - domain-specific method."""
            ...

        def transform_entry(
            self, entry: FlextLDIFModels.Entry
        ) -> FlextResult[FlextLDIFModels.Entry]:
            """Transform single LDIF entry - test compatibility method."""
            ...

    # Test compatibility alias
    TransformerProtocol = LdifTransformer

    @runtime_checkable
    class LdifAnalyzer(FlextProtocols.Foundation.Factory[dict[str, int]], Protocol):
        """LDIF-specific analyzer protocol extending flext-core Factory."""

        def analyze_patterns(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[dict[str, int]]:
            """Analyze LDIF patterns - domain-specific method."""
            ...

        def get_objectclass_distribution(
            self, entries: list[FlextLDIFModels.Entry]
        ) -> FlextResult[dict[str, int]]:
            """Get object class distribution - domain-specific method."""
            ...

    # SOLID FIX: Removed duplicate protocol aliases - use direct protocol classes
    # Use LdifAnalyzer, LdifValidator, LdifParser, LdifWriter, LdifRepository directly


__all__ = ["FlextLDIFProtocols"]
