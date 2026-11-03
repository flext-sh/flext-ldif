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
    class DnEventConfig(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        dn_operation: str
        input_dn: str

        @property
        def output_dn(self) -> str | None:
            """Resulting DN after operation."""
            ...

        @property
        def operation_duration_ms(self) -> float:
            """Operation duration in milliseconds."""
            ...

        @property
        def validation_result(self) -> bool | None:
            """Whether the DN passed validation."""
            ...

        @property
        def parse_components(self) -> t.MutableStrPairSequence | None:
            """Parsed RDN components as (attribute, value) pairs."""
            ...

    @runtime_checkable
    class ConversionEventConfig(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        conversion_operation: str
        source_format: str
        target_format: str
        items_processed: int

        @property
        def items_converted(self) -> int:
            """Items successfully converted."""
            ...

        @property
        def items_failed(self) -> int:
            """Items that failed conversion."""
            ...

        @property
        def conversion_duration_ms(self) -> float:
            """Conversion duration in milliseconds."""
            ...

        @property
        def error_details(self) -> MutableSequence[str] | None:
            """Error messages for failed items."""
            ...

    @runtime_checkable
    class DnEvent(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def message_type(self) -> Literal[c.HandlerType.EVENT]:
            """Immutable event discriminator for union routing."""
            ...

        @property
        def event_type(self) -> t.NonEmptyStr:
            """Domain event type identifier for subscriber routing."""
            ...

        @property
        def aggregate_id(self) -> t.NonEmptyStr:
            """Identifier of the aggregate root that produced this event."""
            ...

        @property
        def data(self) -> p.ConfigMap:
            """Event data container."""
            ...

        dn_operation: str
        input_dn: str

        @property
        def output_dn(self) -> str | None:
            """Resulting DN after operation."""
            ...

        @property
        def dn_duration_ms(self) -> float:
            """DN operation duration in milliseconds."""
            ...

        @property
        def validation_result(self) -> bool | None:
            """Whether the DN passed validation."""
            ...

        @property
        def has_output(self) -> bool:
            """Whether the operation produced output."""
            ...

        @property
        def component_count(self) -> int:
            """Number of RDN components in the DN."""
            ...

    @runtime_checkable
    class ConversionEvent(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def message_type(self) -> Literal[c.HandlerType.EVENT]:
            """Immutable event discriminator for union routing."""
            ...

        @property
        def event_type(self) -> t.NonEmptyStr:
            """Domain event type identifier for subscriber routing."""
            ...

        @property
        def aggregate_id(self) -> t.NonEmptyStr:
            """Identifier of the aggregate root that produced this event."""
            ...

        @property
        def data(self) -> p.ConfigMap:
            """Event data container."""
            ...

        conversion_operation: str
        source_format: str
        target_format: str

        @property
        def items_converted(self) -> int:
            """Items successfully converted."""
            ...

        @property
        def items_failed(self) -> int:
            """Items that failed conversion."""
            ...

        @property
        def conversion_duration_ms(self) -> float:
            """Conversion duration in milliseconds."""
            ...

        @property
        def error_details(self) -> MutableSequence[str] | None:
            """Error messages for failed items."""
            ...

        @property
        def conversion_success_rate(self) -> float:
            """Percentage of items successfully converted."""
            ...

        @property
        def throughput_items_per_sec(self) -> float:
            """Conversion throughput in items per second."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsEvents",
]
