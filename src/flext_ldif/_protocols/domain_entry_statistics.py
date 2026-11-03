# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/domain_entry_statistics
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableSequence
from typing import TYPE_CHECKING, Protocol, Self, runtime_checkable

from flext_cli import FlextCliProtocols

if TYPE_CHECKING:
    from flext_ldif import t
    from flext_ldif._protocols import FlextLdifProtocolsBase


class FlextLdifProtocolsDomainEntryStatistics:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class EntryStatistics(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def was_parsed(self) -> bool:
            """Entry was successfully parsed from LDIF."""
            ...

        @property
        def was_validated(self) -> bool:
            """Entry passed validation checks."""
            ...

        @property
        def was_filtered(self) -> bool:
            """Entry was filtered by rules (base DN, schema, etc.)."""
            ...

        @property
        def was_written(self) -> bool:
            """Entry was written to output LDIF."""
            ...

        @property
        def was_rejected(self) -> bool:
            """Entry was rejected during processing."""
            ...

        @property
        def rejection_category(self) -> str | None:
            """Rejection category (use RejectionCategory constants)."""
            ...

        @property
        def rejection_reason(self) -> str | None:
            """Human-readable rejection reason."""
            ...

        @property
        def attributes_added(self) -> MutableSequence[str]:
            """Attribute names added during processing."""
            ...

        @property
        def attributes_removed(self) -> MutableSequence[str]:
            """Attribute names removed during processing."""
            ...

        @property
        def attributes_modified(self) -> MutableSequence[str]:
            """Attribute names modified during processing."""
            ...

        @property
        def attributes_filtered(self) -> MutableSequence[str]:
            """Attribute names filtered by whitelist/blacklist."""
            ...

        @property
        def objectclasses_original(self) -> MutableSequence[str]:
            """Original objectClass values."""
            ...

        @property
        def objectclasses_final(self) -> MutableSequence[str]:
            """Final objectClass values after transformation."""
            ...

        @property
        def servers_applied(self) -> MutableSequence[str]:
            """List of server types applied to this entry."""
            ...

        @property
        def server_transformations(self) -> int:
            """Count of server transformations applied."""
            ...

        @property
        def dn_statistics(self) -> FlextLdifProtocolsBase.DNStatistics | None:
            """DN transformation statistics (if applicable)."""
            ...

        @property
        def filters_applied(self) -> MutableSequence[str]:
            """List of filters applied (use FilterType constants)."""
            ...

        @property
        def filter_results(self) -> t.MutableBoolMapping:
            """Filter results: {filter_name: passed}."""
            ...

        @property
        def errors(self) -> MutableSequence[str]:
            """Error messages (use ErrorCategory constants for keys)."""
            ...

        @property
        def warnings(self) -> MutableSequence[str]:
            """Warning messages."""
            ...

        @property
        def category_assigned(self) -> str | None:
            """Category assigned (schema, hierarchy, users, groups, acl)."""
            ...

        @property
        def category_confidence(self) -> float:
            """Confidence score for category assignment."""
            ...

        @property
        def dn_was_transformed(self) -> bool:
            """Whether DN underwent transformation."""
            ...

        @property
        def had_errors(self) -> bool:
            """Whether any errors occurred."""
            ...

        @property
        def had_warnings(self) -> bool:
            """Whether any warnings occurred."""
            ...

        @property
        def objectclasses_changed(self) -> bool:
            """Whether objectClass values changed."""
            ...

        @property
        def total_attribute_changes(self) -> int:
            """Total count of attribute modifications."""
            ...

        def add_error(self, error: str) -> Self:
            """Add error message."""
            ...

        def add_warning(self, warning: str) -> Self:
            """Add warning message."""
            ...

        def mark_filtered(self, filter_type: str, *, passed: bool) -> Self:
            """Mark entry as filtered with result."""
            ...

        def mark_rejected(self, category: str, reason: str) -> Self:
            """Mark entry as rejected."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsDomainEntryStatistics",
]
