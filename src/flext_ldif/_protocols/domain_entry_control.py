# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/domain_entry_control
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_cli import FlextCliProtocols

if TYPE_CHECKING:
    from flext_ldif._constants import FlextLdifConstantsBaseParts


class FlextLdifProtocolsDomainEntryControl:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class Control(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def control_type(self) -> str:
            """LDAP control OID or descriptor."""
            ...

        @property
        def criticality(self) -> bool | None:
            """Optional criticality flag from control line."""
            ...

        @property
        def control_value(self) -> str | None:
            """Optional control value."""
            ...

        @property
        def control_value_origin(
            self,
        ) -> FlextLdifConstantsBaseParts.FlextLdifConstantsEnums.ValueOrigin | None:
            """Original control value encoding/source."""
            ...

        @property
        def raw_value(self) -> str | None:
            """Original serialized control payload."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsDomainEntryControl",
]
