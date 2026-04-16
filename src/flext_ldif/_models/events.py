"""Event and configuration models for LDIF processing."""

from __future__ import annotations

from collections.abc import MutableSequence
from typing import Annotated

from flext_core import (
    FlextModelsDomainEvent,
    m,
)


class FlextLdifModelsEvents:
    """LDIF event and configuration models container class."""

    class DnEventConfig(m.StrictModel):
        dn_operation: str = m.Field(description="DN operation type performed")
        input_dn: str = m.Field(description="Original DN before operation")
        output_dn: Annotated[
            str | None, m.Field(description="Resulting DN after operation")
        ] = None
        operation_duration_ms: Annotated[
            float, m.Field(description="Operation duration in milliseconds")
        ] = 0.0
        validation_result: Annotated[
            bool | None, m.Field(description="Whether the DN passed validation")
        ] = None
        parse_components: Annotated[
            MutableSequence[tuple[str, str]] | None,
            m.Field(
                description="Parsed RDN components as (attribute, value) pairs",
            ),
        ] = None

    class ConversionEventConfig(m.StrictModel):
        conversion_operation: str = m.Field(
            description="Conversion operation type performed"
        )
        source_format: str = m.Field(description="Source LDAP server format")
        target_format: str = m.Field(description="Target LDAP server format")
        items_processed: int = m.Field(
            description="Total items processed in conversion"
        )
        items_converted: Annotated[
            int, m.Field(description="Items successfully converted")
        ] = 0
        items_failed: Annotated[
            int, m.Field(description="Items that failed conversion")
        ] = 0
        conversion_duration_ms: Annotated[
            float, m.Field(description="Conversion duration in milliseconds")
        ] = 0.0
        error_details: Annotated[
            MutableSequence[str] | None,
            m.Field(description="Error messages for failed items"),
        ] = None

    class DnEvent(FlextModelsDomainEvent.Entry):
        dn_operation: str = m.Field(description="DN operation type performed")
        input_dn: str = m.Field(description="Original DN before operation")
        output_dn: Annotated[
            str | None, m.Field(description="Resulting DN after operation")
        ] = None
        dn_duration_ms: Annotated[
            float, m.Field(description="DN operation duration in milliseconds")
        ] = 0.0
        validation_result: Annotated[
            bool | None, m.Field(description="Whether the DN passed validation")
        ] = None
        has_output: Annotated[
            bool, m.Field(description="Whether the operation produced output")
        ] = False
        component_count: Annotated[
            int, m.Field(description="Number of RDN components in the DN")
        ] = 0

    class ConversionEvent(FlextModelsDomainEvent.Entry):
        conversion_operation: str = m.Field(
            description="Conversion operation type performed"
        )
        source_format: str = m.Field(description="Source LDAP server format")
        target_format: str = m.Field(description="Target LDAP server format")
        items_converted: Annotated[
            int, m.Field(description="Items successfully converted")
        ] = 0
        items_failed: Annotated[
            int, m.Field(description="Items that failed conversion")
        ] = 0
        conversion_duration_ms: Annotated[
            float, m.Field(description="Conversion duration in milliseconds")
        ] = 0.0
        error_details: Annotated[
            MutableSequence[str] | None,
            m.Field(description="Error messages for failed items"),
        ] = None
        conversion_success_rate: Annotated[
            float, m.Field(description="Percentage of items successfully converted")
        ] = 0.0
        throughput_items_per_sec: Annotated[
            float, m.Field(description="Conversion throughput in items per second")
        ] = 0.0


__all__: list[str] = ["FlextLdifModelsEvents"]
