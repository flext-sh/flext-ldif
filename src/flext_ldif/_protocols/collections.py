# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/collections
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    ItemsView,
    Iterator,
    KeysView,
    Mapping,
    MutableSequence,
    Sequence,
    ValuesView,
)
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_cli import FlextCliProtocols

if TYPE_CHECKING:
    from flext_ldif import t
    from flext_ldif._protocols import (
        FlextLdifProtocolsDomainEntry,
        FlextLdifProtocolsDomainSchema,
    )


class FlextLdifProtocolsCollections:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class DynamicCounts(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def root(self) -> t.IntMapping:
            """Structural member projected from the owning model."""
            ...

        def __getitem__(self, key: str) -> int:
            """Structural member projected from the owning model."""
            ...

        def __len__(self) -> int:
            """Structural member projected from the owning model."""
            ...

        def __contains__(self, key: str) -> bool:
            """Structural member projected from the owning model."""
            ...

        def get(self, key: str, default: int | None = None) -> int | None:
            """Structural member projected from the owning model."""
            ...

        def keys(self) -> KeysView[str]:
            """Structural member projected from the owning model."""
            ...

        def values(self) -> ValuesView[int]:
            """Structural member projected from the owning model."""
            ...

        def items(self) -> ItemsView[str, int]:
            """Structural member projected from the owning model."""
            ...

    @runtime_checkable
    class SchemaContent(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def attributes(
            self,
        ) -> Sequence[FlextLdifProtocolsDomainSchema.SchemaAttribute]:
            """Schema attribute definitions extracted from LDIF."""
            ...

        @property
        def object_classes(
            self,
        ) -> Sequence[FlextLdifProtocolsDomainSchema.SchemaObjectClass]:
            """Schema object class definitions extracted from LDIF."""
            ...

    @runtime_checkable
    class FlexibleCategories(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def categories(
            self,
        ) -> Mapping[str, Sequence[FlextLdifProtocolsDomainEntry.Entry]]:
            """Category name to grouped LDIF entries mapping."""
            ...

        def __getitem__(
            self, category: str
        ) -> MutableSequence[FlextLdifProtocolsDomainEntry.Entry]:
            """Structural member projected from the owning model."""
            ...

        def __setitem__(
            self,
            category: str,
            entries: MutableSequence[FlextLdifProtocolsDomainEntry.Entry],
        ) -> None:
            """Structural member projected from the owning model."""
            ...

        def add_entries(
            self,
            category: str,
            entries: MutableSequence[FlextLdifProtocolsDomainEntry.Entry],
        ) -> None:
            """Structural member projected from the owning model."""
            ...

        def __contains__(self, category: str) -> bool:
            """Structural member projected from the owning model."""
            ...

        def items(
            self,
        ) -> Iterator[tuple[str, MutableSequence[FlextLdifProtocolsDomainEntry.Entry]]]:
            """Structural member projected from the owning model."""
            ...

        def keys(self) -> Iterator[str]:
            """Structural member projected from the owning model."""
            ...

        def get(
            self,
            category: str,
            default: MutableSequence[FlextLdifProtocolsDomainEntry.Entry] | None = None,
        ) -> MutableSequence[FlextLdifProtocolsDomainEntry.Entry]:
            """Structural member projected from the owning model."""
            ...

        def values(
            self,
        ) -> Iterator[MutableSequence[FlextLdifProtocolsDomainEntry.Entry]]:
            """Structural member projected from the owning model."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsCollections",
]
