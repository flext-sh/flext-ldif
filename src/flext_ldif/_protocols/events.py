# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/events
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableSequence
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable

from flext_cli import FlextCliProtocols

if TYPE_CHECKING:
    from flext_cli import p

    from flext_ldif import c, t


class FlextLdifProtocolsEvents:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class DnEventConfig(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        dn_operation: str
        input_dn: str
        output_dn: str | None
        operation_duration_ms: float
        validation_result: bool | None
        parse_components: t.MutableStrPairSequence | None

    @runtime_checkable
    class ConversionEventConfig(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        conversion_operation: str
        source_format: str
        target_format: str
        items_processed: int
        items_converted: int
        items_failed: int
        conversion_duration_ms: float
        error_details: MutableSequence[str] | None

    @runtime_checkable
    class DnEvent(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def message_type(self) -> Literal[c.HandlerType.EVENT]:
            """Immutable event discriminator for union routing."""
            ...

        event_type: t.NonEmptyStr
        aggregate_id: t.NonEmptyStr

        @property
        def data(self) -> p.ConfigMap:
            """Event data container."""
            ...

        dn_operation: str
        input_dn: str
        output_dn: str | None
        dn_duration_ms: float
        validation_result: bool | None
        has_output: bool
        component_count: int

    @runtime_checkable
    class ConversionEvent(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def message_type(self) -> Literal[c.HandlerType.EVENT]:
            """Immutable event discriminator for union routing."""
            ...

        event_type: t.NonEmptyStr
        aggregate_id: t.NonEmptyStr

        @property
        def data(self) -> p.ConfigMap:
            """Event data container."""
            ...

        conversion_operation: str
        source_format: str
        target_format: str
        items_converted: int
        items_failed: int
        conversion_duration_ms: float
        error_details: MutableSequence[str] | None
        conversion_success_rate: float
        throughput_items_per_sec: float


__all__: list[str] = [
    "FlextLdifProtocolsEvents",
]
