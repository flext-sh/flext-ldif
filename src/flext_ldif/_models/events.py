"""Event and configuration models for LDIF processing."""

from __future__ import annotations

from collections.abc import MutableSequence
from pathlib import Path
from typing import Self

from flext_core._models.domain_event import FlextModelsDomainEvent
from pydantic import Field

from flext_ldif import FlextLdifModelsBases, FlextLdifModelsSettings, c

_DomainEventBase = FlextModelsDomainEvent.Entry


def _filter_criteria_factory() -> MutableSequence[
    FlextLdifModelsSettings.FilterCriteria
]:
    return []


class FlextLdifModelsEvents:
    """LDIF event and configuration models container class."""

    class DnEventConfig(FlextLdifModelsBases.Base):
        dn_operation: str
        input_dn: str
        output_dn: str | None = None
        operation_duration_ms: float = 0.0
        validation_result: bool | None = None
        parse_components: MutableSequence[tuple[str, str]] | None = None

    class MigrationEventConfig(FlextLdifModelsBases.Base):
        migration_operation: str
        source_server: str
        target_server: str
        entries_processed: int
        entries_migrated: int = 0
        entries_failed: int = 0
        migration_duration_ms: float = 0.0
        error_details: MutableSequence[str] | None = None

    class ConversionEventConfig(FlextLdifModelsBases.Base):
        conversion_operation: str
        source_format: str
        target_format: str
        items_processed: int
        items_converted: int = 0
        items_failed: int = 0
        conversion_duration_ms: float = 0.0
        error_details: MutableSequence[str] | None = None

    class FilterEvent(_DomainEventBase):
        filter_operation: str
        entries_before: int
        entries_after: int
        filter_criteria: MutableSequence[FlextLdifModelsSettings.FilterCriteria] = (
            Field(default_factory=_filter_criteria_factory)
        )
        filter_duration_ms: float = 0.0

    class ParseEvent(_DomainEventBase):
        parse_operation: str
        source_type: str
        entries_parsed: int = 0
        entries_failed: int = 0
        parse_duration_ms: float = 0.0
        error_details: MutableSequence[str] | None = None

        @classmethod
        def for_file(
            cls,
            file_path: str | Path,
            entries_parsed: int = 0,
            entries_failed: int = 0,
            parse_duration_ms: float = 0.0,
            error_details: MutableSequence[str] | None = None,
        ) -> Self:
            return cls.model_validate({
                "event_type": "ldif.parse",
                "aggregate_id": str(file_path),
                "parse_operation": "parse_file",
                "source_type": "file",
                "entries_parsed": entries_parsed,
                "entries_failed": entries_failed,
                "parse_duration_ms": parse_duration_ms,
                "error_details": error_details,
            })

        @classmethod
        def for_ldap3(
            cls,
            connection_info: str,
            entries_parsed: int = 0,
            entries_failed: int = 0,
            parse_duration_ms: float = 0.0,
            error_details: MutableSequence[str] | None = None,
        ) -> Self:
            return cls.model_validate({
                "event_type": "ldif.parse",
                "aggregate_id": connection_info,
                "parse_operation": "parse_ldap3",
                "source_type": "ldap3",
                "entries_parsed": entries_parsed,
                "entries_failed": entries_failed,
                "parse_duration_ms": parse_duration_ms,
                "error_details": error_details,
            })

        @classmethod
        def for_string(
            cls,
            content_length: int,
            entries_parsed: int = 0,
            entries_failed: int = 0,
            parse_duration_ms: float = 0.0,
            error_details: MutableSequence[str] | None = None,
        ) -> Self:
            return cls.model_validate({
                "event_type": "ldif.parse",
                "aggregate_id": f"content_{content_length}chars",
                "parse_operation": "parse_string",
                "source_type": "string",
                "entries_parsed": entries_parsed,
                "entries_failed": entries_failed,
                "parse_duration_ms": parse_duration_ms,
                "error_details": error_details,
            })

    class WriteEvent(_DomainEventBase):
        write_operation: str = "write_file"
        target_type: str = "file"
        entries_written: int = 0
        entries_failed: int = 0
        write_duration_ms: float = 0.0
        error_details: MutableSequence[str] | None = None

    class CategoryEvent(_DomainEventBase):
        category_operation: str
        entries_categorized: int = 0
        categories_created: MutableSequence[str] = Field(default_factory=list)
        categorization_duration_ms: float = 0.0

    class AclEvent(_DomainEventBase):
        acl_operation: str
        acls_processed: int = 0
        acls_succeeded: int = 0
        acls_failed: int = 0
        acl_duration_ms: float = 0.0
        error_details: MutableSequence[str] | None = None

    class DnEvent(_DomainEventBase):
        dn_operation: str
        input_dn: str
        output_dn: str | None = None
        dn_duration_ms: float = 0.0
        validation_result: bool | None = None
        has_output: bool = False
        component_count: int = 0

    class MigrationEvent(_DomainEventBase):
        migration_operation: str
        source_server: str
        target_server: str
        entries_migrated: int = 0
        entries_failed: int = 0
        migration_duration_ms: float = 0.0
        error_details: MutableSequence[str] | None = None
        migration_success_rate: float = 0.0
        throughput_entries_per_sec: float = 0.0

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

    class SchemaEvent(_DomainEventBase):
        schema_operation: str
        items_processed: int = 0
        items_succeeded: int = 0
        items_failed: int = 0
        schema_duration_ms: float = 0.0
        error_details: MutableSequence[str] | None = None
        schema_success_rate: float = 0.0
        throughput_items_per_sec: float = 0.0

    class SchemaEventConfig(FlextLdifModelsBases.Base):
        schema_operation: str
        items_processed: int = 0
        items_succeeded: int = 0
        items_failed: int = 0
        operation_duration_ms: float = 0.0
        server_type: c.Ldif.ServerTypeLiteral
        schema_type: str = c.Ldif.ServerTypes.RFC.value
