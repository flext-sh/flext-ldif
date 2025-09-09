"""FLEXT-LDIF Protocols - Direct flext-core usage.

Minimal LDIF-specific protocol extensions using flext-core directly.
No duplication of existing functionality - only domain-specific additions.

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
    class LdifParser(Protocol):
        """LDIF-specific parser protocol extending flext-core patterns."""

        def parse_ldif_content(self, content: str) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Parse LDIF content - domain-specific method."""
            ...

        def parse_ldif_file(self, file_path: str | Path) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Parse LDIF file - domain-specific method."""
            ...

    @runtime_checkable
    class LdifValidator(Validator[FlextLDIFModels.Entry], Protocol):
        """LDIF-specific validator protocol extending flext-core Validator."""

        def validate_ldif_syntax(self, content: str) -> FlextResult[bool]:
            """Validate LDIF syntax - domain-specific method."""
            ...

    @runtime_checkable
    class LdifWriter(Protocol):
        """LDIF-specific writer protocol - minimal domain extension."""

        def write_ldif_entries(self, entries: list[FlextLDIFModels.Entry]) -> FlextResult[str]:
            """Write LDIF entries - domain-specific method."""
            ...

    @runtime_checkable
    class LdifTransformer(Service, Protocol):
        """LDIF-specific transformer protocol extending flext-core Service."""

        def transform_entries(self, entries: list[FlextLDIFModels.Entry]) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Transform LDIF entries - domain-specific method."""
            ...

    @runtime_checkable
    class LdifAnalyzer(Service, Protocol):
        """LDIF-specific analyzer protocol extending flext-core Service."""

        def analyze_patterns(self, entries: list[FlextLDIFModels.Entry]) -> FlextResult[dict[str, int]]:
            """Analyze LDIF patterns - domain-specific method."""
            ...

    # Simple aliases for test compatibility
    ParserProtocol = LdifParser  # Alias for backward compatibility
    ValidatorProtocol = LdifValidator  # Alias for backward compatibility
    WriterProtocol = LdifWriter  # Alias for backward compatibility
    TransformerProtocol = LdifTransformer  # Alias for backward compatibility
    AnalyzerProtocol = LdifAnalyzer  # Alias for backward compatibility


__all__ = ["FlextLDIFProtocols"]
