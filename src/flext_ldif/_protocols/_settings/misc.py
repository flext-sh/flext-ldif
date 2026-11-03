# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/_settings/misc
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_cli import FlextCliProtocols

if TYPE_CHECKING:
    from flext_ldif import t


class FlextLdifProtocolsSettingsMisc:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class LogContextExtras(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def user_id(self) -> str | None:
            """User identifier."""
            ...

        @property
        def session_id(self) -> str | None:
            """Session identifier."""
            ...

        @property
        def request_id(self) -> str | None:
            """Request identifier."""
            ...

        @property
        def component(self) -> str | None:
            """Component name."""
            ...

        @property
        def correlation_id(self) -> str | None:
            """Correlation identifier."""
            ...

        @property
        def trace_id(self) -> str | None:
            """Trace identifier."""
            ...

    @runtime_checkable
    class RdnProcessingConfig(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        current_attr: str
        current_val: str
        in_value: bool
        pairs: t.MutableStrPairSequence


__all__: list[str] = [
    "FlextLdifProtocolsSettingsMisc",
]
