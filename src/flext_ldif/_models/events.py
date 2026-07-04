"""Event and configuration models for LDIF processing."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from flext_core import m
from flext_core.utilities import FlextUtilities as u

if TYPE_CHECKING:
    from flext_ldif import t


class FlextLdifModelsEvents:
    """LDIF event and configuration models container class."""

    class DnEventConfig(m.StrictModel):
        dn_operation: str = u.Field(description="DN operation type performed")
        input_dn: str = u.Field(description="Original DN before operation")
        output_dn: Annotated[
            str | None,
            u.Field(description="Resulting DN after operation"),
        ] = None
        operation_duration_ms: Annotated[
            float,
            u.Field(description="Operation duration in milliseconds"),
        ] = 0.0
        validation_result: Annotated[
            bool | None,
            u.Field(description="Whether the DN passed validation"),
        ] = None
        parse_components: Annotated[
            t.MutableStrPairSequence | None,
            u.Field(
                description="Parsed RDN components as (attribute, value) pairs",
            ),
        ] = None

    class ConversionEventConfig(m.StrictModel):
        conversion_operation: str = u.Field(
            description="Conversion operation type performed",
        )
        source_format: str = u.Field(description="Source LDAP server format")
        target_format: str = u.Field(description="Target LDAP server format")
        items_processed: int = u.Field(
            description="Total items processed in conversion",
        )
        items_converted: Annotated[
            int,
            u.Field(description="Items successfully converted"),
        ] = 0
        items_failed: Annotated[
            int,
            u.Field(description="Items that failed conversion"),
        ] = 0
        conversion_duration_ms: Annotated[
            float,
            u.Field(description="Conversion duration in milliseconds"),
        ] = 0.0
        error_details: Annotated[
            t.MutableSequenceOf[str] | None,
            u.Field(description="Error messages for failed items"),
        ] = None

    class DnEvent(m.DomainEvent):
        dn_operation: str = u.Field(description="DN operation type performed")
        input_dn: str = u.Field(description="Original DN before operation")
        output_dn: Annotated[
            str | None,
            u.Field(description="Resulting DN after operation"),
        ] = None
        dn_duration_ms: Annotated[
            float,
            u.Field(description="DN operation duration in milliseconds"),
        ] = 0.0
        validation_result: Annotated[
            bool | None,
            u.Field(description="Whether the DN passed validation"),
        ] = None
        has_output: Annotated[
            bool,
            u.Field(description="Whether the operation produced output"),
        ] = False
        component_count: Annotated[
            int,
            u.Field(description="Number of RDN components in the DN"),
        ] = 0

    class ConversionEvent(m.DomainEvent):
        conversion_operation: str = u.Field(
            description="Conversion operation type performed",
        )
        source_format: str = u.Field(description="Source LDAP server format")
        target_format: str = u.Field(description="Target LDAP server format")
        items_converted: Annotated[
            int,
            u.Field(description="Items successfully converted"),
        ] = 0
        items_failed: Annotated[
            int,
            u.Field(description="Items that failed conversion"),
        ] = 0
        conversion_duration_ms: Annotated[
            float,
            u.Field(description="Conversion duration in milliseconds"),
        ] = 0.0
        error_details: Annotated[
            t.MutableSequenceOf[str] | None,
            u.Field(description="Error messages for failed items"),
        ] = None
        conversion_success_rate: Annotated[
            float,
            u.Field(description="Percentage of items successfully converted"),
        ] = 0.0
        throughput_items_per_sec: Annotated[
            float,
            u.Field(description="Conversion throughput in items per second"),
        ] = 0.0


__all__: list[str] = ["FlextLdifModelsEvents"]
