"""Event and configuration models for LDIF processing."""

from __future__ import annotations

from collections.abc import MutableSequence

from flext_core import FlextModelsDomainEvent, m

_DomainEventBase = FlextModelsDomainEvent.Entry


class FlextLdifModelsEvents:
    """LDIF event and configuration models container class."""

    class DnEventConfig(m.StrictModel):
        dn_operation: str
        input_dn: str
        output_dn: str | None = None
        operation_duration_ms: float = 0.0
        validation_result: bool | None = None
        parse_components: MutableSequence[tuple[str, str]] | None = None

    class ConversionEventConfig(m.StrictModel):
        conversion_operation: str
        source_format: str
        target_format: str
        items_processed: int
        items_converted: int = 0
        items_failed: int = 0
        conversion_duration_ms: float = 0.0
        error_details: MutableSequence[str] | None = None

    class DnEvent(_DomainEventBase):
        dn_operation: str
        input_dn: str
        output_dn: str | None = None
        dn_duration_ms: float = 0.0
        validation_result: bool | None = None
        has_output: bool = False
        component_count: int = 0

    class ConversionEvent(_DomainEventBase):
        conversion_operation: str
        source_format: str
        target_format: str
        items_converted: int = 0
        items_failed: int = 0
        conversion_duration_ms: float = 0.0
        error_details: MutableSequence[str] | None = None
        conversion_success_rate: float = 0.0
        throughput_items_per_sec: float = 0.0
