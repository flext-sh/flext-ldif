"""Event and configuration models for LDIF processing."""

from __future__ import annotations

from collections.abc import MutableSequence

from pydantic import Field

from flext_core import FlextModelsDomainEvent, m

_DomainEventBase = FlextModelsDomainEvent.Entry


class _DnEventConfig(m.StrictModel):
    dn_operation: str = Field(description="DN operation type performed")
    input_dn: str = Field(description="Original DN before operation")
    output_dn: str | None = Field(
        default=None, description="Resulting DN after operation"
    )
    operation_duration_ms: float = Field(
        default=0.0, description="Operation duration in milliseconds"
    )
    validation_result: bool | None = Field(
        default=None, description="Whether the DN passed validation"
    )
    parse_components: MutableSequence[tuple[str, str]] | None = Field(
        default=None,
        description="Parsed RDN components as (attribute, value) pairs",
    )


class _ConversionEventConfig(m.StrictModel):
    conversion_operation: str = Field(description="Conversion operation type performed")
    source_format: str = Field(description="Source LDAP server format")
    target_format: str = Field(description="Target LDAP server format")
    items_processed: int = Field(description="Total items processed in conversion")
    items_converted: int = Field(default=0, description="Items successfully converted")
    items_failed: int = Field(default=0, description="Items that failed conversion")
    conversion_duration_ms: float = Field(
        default=0.0, description="Conversion duration in milliseconds"
    )
    error_details: MutableSequence[str] | None = Field(
        default=None, description="Error messages for failed items"
    )


class _DnEvent(_DomainEventBase):
    dn_operation: str = Field(description="DN operation type performed")
    input_dn: str = Field(description="Original DN before operation")
    output_dn: str | None = Field(
        default=None, description="Resulting DN after operation"
    )
    dn_duration_ms: float = Field(
        default=0.0, description="DN operation duration in milliseconds"
    )
    validation_result: bool | None = Field(
        default=None, description="Whether the DN passed validation"
    )
    has_output: bool = Field(
        default=False, description="Whether the operation produced output"
    )
    component_count: int = Field(
        default=0, description="Number of RDN components in the DN"
    )


class _ConversionEvent(_DomainEventBase):
    conversion_operation: str = Field(description="Conversion operation type performed")
    source_format: str = Field(description="Source LDAP server format")
    target_format: str = Field(description="Target LDAP server format")
    items_converted: int = Field(default=0, description="Items successfully converted")
    items_failed: int = Field(default=0, description="Items that failed conversion")
    conversion_duration_ms: float = Field(
        default=0.0, description="Conversion duration in milliseconds"
    )
    error_details: MutableSequence[str] | None = Field(
        default=None, description="Error messages for failed items"
    )
    conversion_success_rate: float = Field(
        default=0.0, description="Percentage of items successfully converted"
    )
    throughput_items_per_sec: float = Field(
        default=0.0, description="Conversion throughput in items per second"
    )


class FlextLdifModelsEvents:
    """LDIF event and configuration models container class."""

    DnEventConfig = _DnEventConfig
    ConversionEventConfig = _ConversionEventConfig
    DnEvent = _DnEvent
    ConversionEvent = _ConversionEvent
