# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/domain_attributes
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import KeysView, MutableMapping, MutableSequence, ValuesView
from typing import TYPE_CHECKING, Protocol, Self, runtime_checkable

from flext_cli import FlextCliProtocols

if TYPE_CHECKING:
    from flext_ldif import t
    from flext_ldif._constants import FlextLdifConstantsBaseParts


class FlextLdifProtocolsDomainAttributes:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class Attributes(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        attributes: t.MutableStrSequenceMapping
        attribute_metadata: MutableMapping[str, t.MutableAttributeMapping]
        metadata: t.MutableJsonMapping | None

        def __getitem__(self, key: str) -> MutableSequence[str]:
            """Get attribute values by name (case-sensitive LDAP)."""
            ...

        def __setitem__(self, key: str, value: MutableSequence[str]) -> None:
            """Set attribute values by name."""
            ...

        def __len__(self) -> int:
            """Return the number of attributes."""
            ...

        def __contains__(self, key: str) -> bool:
            """Check if attribute exists."""
            ...

        def add_attribute(self, key: str, values: MutableSequence[str]) -> Self:
            """Add or update an attribute with values."""
            ...

        def get(
            self, key: str, default: MutableSequence[str] | None = None
        ) -> MutableSequence[str]:
            """Get attribute values with optional default."""
            ...

        def has_attribute(self, key: str) -> bool:
            """Check if attribute exists."""
            ...

        def items(self) -> MutableSequence[tuple[str, MutableSequence[str]]]:
            """Get attribute name-values pairs."""
            ...

        def iter_attributes(self) -> MutableSequence[str]:
            """Get list of all attribute names."""
            ...

        def keys(self) -> KeysView[str]:
            """Get attribute names."""
            ...

        def remove_attribute(self, key: str) -> Self:
            """Remove an attribute if it exists."""
            ...

        def values(self) -> ValuesView[MutableSequence[str]]:
            """Get attribute values lists."""
            ...

    @runtime_checkable
    class AttributeTransformation(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def original_name(self) -> str:
            """Original attribute name from source server."""
            ...

        @property
        def target_name(self) -> str | None:
            """Transformed attribute name (None if removed)."""
            ...

        @property
        def original_values(self) -> MutableSequence[str]:
            """Original attribute values from source."""
            ...

        @property
        def target_values(self) -> MutableSequence[str] | None:
            """Transformed values (None if removed)."""
            ...

        @property
        def transformation_type(
            self,
        ) -> FlextLdifConstantsBaseParts.FlextLdifConstantsEnums.TransformationType:
            """Type of transformation applied to the attribute."""
            ...

        @property
        def reason(self) -> str:
            """Human-readable reason for transformation."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsDomainAttributes",
]
