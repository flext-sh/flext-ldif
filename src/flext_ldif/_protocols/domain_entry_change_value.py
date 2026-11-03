# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/domain_entry_change_value
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_cli import FlextCliProtocols

if TYPE_CHECKING:
    from flext_ldif._constants import FlextLdifConstantsBaseParts


class FlextLdifProtocolsDomainEntryChangeValue:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class ChangeOperationValue(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def value(self) -> str:
            """Decoded value used by the operation."""
            ...

        @property
        def value_origin(
            self,
        ) -> FlextLdifConstantsBaseParts.FlextLdifConstantsEnums.ValueOrigin:
            """Original LDIF encoding/source for this value."""
            ...

        @property
        def raw_value(self) -> str | None:
            """Original serialized value payload before decoding."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsDomainEntryChangeValue",
]
