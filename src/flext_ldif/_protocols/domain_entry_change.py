# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/domain_entry_change
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_cli import FlextCliProtocols

if TYPE_CHECKING:
    from flext_ldif._constants import FlextLdifConstantsBaseParts
    from flext_ldif._protocols import FlextLdifProtocolsValues


class FlextLdifProtocolsDomainEntryChange:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class ChangeOperation(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def operation(
            self,
        ) -> FlextLdifConstantsBaseParts.FlextLdifConstantsEnums.ChangeOperation:
            """Modify operation name."""
            ...

        @property
        def attribute(self) -> str:
            """Target attribute for the modify block."""
            ...

        @property
        def values(self) -> Sequence[FlextLdifProtocolsValues.ChangeOperationValue]:
            """Decoded values in the block."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsDomainEntryChange",
]
