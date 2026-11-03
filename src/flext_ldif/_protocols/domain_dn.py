# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/domain_dn
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_cli import FlextCliProtocols

if TYPE_CHECKING:
    from flext_cli import p

    from flext_ldif import t


class FlextLdifProtocolsDomainDn:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class DNStatistics(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def original_dn(self) -> str:
            """Original DN as received from input."""
            ...

        @property
        def cleaned_dn(self) -> str:
            """DN after clean_dn() transformation."""
            ...

        @property
        def normalized_dn(self) -> str:
            """Final normalized DN (RFC 4514 compliant)."""
            ...

        @property
        def transformations(self) -> Sequence[str]:
            """Ordered list of transformations applied."""
            ...

        @property
        def had_tab_chars(self) -> bool:
            """DN contained TAB characters."""
            ...

        @property
        def had_trailing_spaces(self) -> bool:
            """DN had trailing spaces."""
            ...

        @property
        def had_leading_spaces(self) -> bool:
            """DN had leading spaces."""
            ...

        @property
        def had_extra_spaces(self) -> bool:
            """DN had multiple consecutive spaces."""
            ...

        @property
        def was_base64_encoded(self) -> bool:
            """DN was base64 encoded in LDIF (dn::)."""
            ...

        @property
        def had_utf8_chars(self) -> bool:
            """DN contained UTF-8 multi-byte characters."""
            ...

        @property
        def had_escape_sequences(self) -> bool:
            """DN contained LDAP escape sequences."""
            ...

        @property
        def validation_status(self) -> str:
            """Validation status (use ValidationStatus constants)."""
            ...

        @property
        def validation_warnings(self) -> Sequence[str]:
            """Non-fatal validation warnings."""
            ...

        @property
        def validation_errors(self) -> Sequence[str]:
            """Fatal validation errors."""
            ...

        @property
        def has_errors(self) -> bool:
            """Whether any validation errors exist."""
            ...

        @property
        def has_warnings(self) -> bool:
            """Whether any validation warnings exist."""
            ...

        @property
        def transformation_count(self) -> int:
            """Count of unique transformations applied."""
            ...

        @property
        def was_transformed(self) -> bool:
            """Whether any transformations were applied."""
            ...

    @runtime_checkable
    class DN(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def value(self) -> str:
            """DN string value (lenient processing - no max_length)."""
            ...

        @property
        def metadata(self) -> t.MutableJsonMapping:
            """Server-specific metadata for preserving original format."""
            ...

    @runtime_checkable
    class DnRegistry(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        def clear(self) -> None:
            """Clear all DN registrations."""
            ...

        def resolve_canonical_dn(self, dn: str) -> str | None:
            """Get canonical case for a DN (case-insensitive lookup)."""
            ...

        def register_dn(self, dn: str, *, force: bool = False) -> str:
            """Register DN and return its canonical case."""
            ...

        def validate_oud_consistency(self) -> p.Result[bool]:
            """Validate DN case consistency for server conversion."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsDomainDn",
]
