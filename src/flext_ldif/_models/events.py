"""Event and configuration models for LDIF processing.

This module contains event models, configuration models, and related
classes for LDIF processing operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import uuid
from pathlib import Path

from flext_core import FlextModels
from pydantic import ConfigDict, Field


class FlextLdifModelsEvents:
    """LDIF event and configuration models container class.

    This class acts as a namespace container for LDIF event and configuration models.
    All nested classes are accessed via FlextLdifModels.* in the main models.py.
    """

    # Event configuration classes would go here

    class DnEventConfig(FlextModels.Value):
        """Configuration for DN event creation.

        Consolidates parameters for create_dn_event utility function.
        Reduces function signature from 6 parameters to 1 model.

        Example:
            config = FlextLdifModels.DnEventConfig(
                dn_operation="normalize",
                input_dn="CN=Admin,DC=Example",
                output_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example",
                operation_duration_ms=1.2,
            )
            event = FlextLdifUtilities.Events.create_dn_event(config)

        """

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        dn_operation: str = Field(
            ...,
            description="Operation name (parse, validate, normalize, etc.)",
        )
        input_dn: str = Field(
            ...,
            description="Input DN before operation",
        )
        output_dn: str | None = Field(
            default=None,
            description="Output DN after operation (None if failed)",
        )
        operation_duration_ms: float = Field(
            default=0.0,
            description="Duration in milliseconds",
        )
        validation_result: bool | None = Field(
            default=None,
            description="Validation result (None if not validated)",
        )
        parse_components: list[tuple[str, str]] | None = Field(
            default=None,
            description="Parsed DN components",
        )

    class MigrationEventConfig(FlextModels.Value):
        """Configuration for migration event creation.

        Consolidates parameters for create_migration_event utility function.
        Reduces function signature from 8 parameters to 1 model.

        Example:
            config = FlextLdifModels.MigrationEventConfig(
                migration_operation="full_migration",
                source_server="oid",
                target_server="oud",
                entries_processed=1000,
                entries_migrated=980,
                entries_failed=20,
                migration_duration_ms=5420.5,
            )
            event = FlextLdifUtilities.Events.create_migration_event(config)

        """

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        migration_operation: str = Field(
            ...,
            description="Operation name (full_migration, incremental, etc.)",
        )
        source_server: str = Field(
            ...,
            description="Source LDAP server type",
        )
        target_server: str = Field(
            ...,
            description="Target LDAP server type",
        )
        entries_processed: int = Field(
            ...,
            description="Total entries processed",
        )
        entries_migrated: int = Field(
            default=0,
            description="Entries successfully migrated",
        )
        entries_failed: int = Field(
            default=0,
            description="Entries that failed migration",
        )
        migration_duration_ms: float = Field(
            default=0.0,
            description="Duration in milliseconds",
        )
        error_details: list[object] | None = Field(  # Can contain ErrorDetail or dict
            default=None,
            description="Error information for failed entries",
        )

    class ConversionEventConfig(FlextModels.Value):
        """Configuration for conversion event creation.

        Consolidates parameters for create_conversion_event utility function.
        Reduces function signature from 8 parameters to 1 model.

        Example:
            config = FlextLdifModels.ConversionEventConfig(
                conversion_operation="acl_transform",
                source_format="orclaci",
                target_format="olcAccess",
                items_processed=50,
                items_converted=48,
                items_failed=2,
                conversion_duration_ms=125.3,
            )
            event = FlextLdifUtilities.Events.create_conversion_event(config)

        """

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        conversion_operation: str = Field(
            ...,
            description="Operation name (acl_transform, schema_convert, etc.)",
        )
        source_format: str = Field(
            ...,
            description="Source format type",
        )
        target_format: str = Field(
            ...,
            description="Target format type",
        )
        items_processed: int = Field(
            ...,
            description="Total items processed",
        )
        items_converted: int = Field(
            default=0,
            description="Items successfully converted",
        )
        items_failed: int = Field(
            default=0,
            description="Items that failed conversion",
        )
        conversion_duration_ms: float = Field(
            default=0.0,
            description="Duration in milliseconds",
        )
        error_details: list[object] | None = Field(  # Can contain ErrorDetail or dict
            default=None,
            description="Error information for failed conversions",
        )

    # =========================================================================
    # DOMAIN EVENTS - Processing events
    # =========================================================================

    class FilterEvent(FlextModels.DomainEvent):
        """Event emitted when LDIF entries are filtered.

        Tracks filtering operations including criteria applied and results.
        """

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        filter_operation: str = Field(
            ...,
            description="Filter operation name (e.g., 'filter_by_dn_pattern')",
        )
        entries_before: int = Field(
            ...,
            description="Number of entries before filtering",
        )
        entries_after: int = Field(
            ...,
            description="Number of entries after filtering",
        )
        filter_criteria: list[dict[str, object]] = Field(
            default_factory=list,
            description="Filter criteria applied",
        )
        filter_duration_ms: float = Field(
            default=0.0,
            description="Duration in milliseconds",
        )

    class ParseEvent(FlextModels.DomainEvent):
        """Event emitted when LDIF content is parsed.

        Tracks parsing operations including source type and results.
        """

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        parse_operation: str = Field(
            ...,
            description="Parse operation name (e.g., 'parse_file', 'parse_string')",
        )
        source_type: str = Field(
            ...,
            description="Source type (file, string, ldap3)",
        )
        entries_parsed: int = Field(
            default=0,
            description="Number of entries successfully parsed",
        )
        entries_failed: int = Field(
            default=0,
            description="Number of entries that failed parsing",
        )
        parse_duration_ms: float = Field(
            default=0.0,
            description="Duration in milliseconds",
        )
        error_details: list[object] | None = Field(
            default=None,
            description="Error information for failed entries",
        )

        @classmethod
        def for_file(
            cls,
            file_path: str | Path,
            entries_parsed: int = 0,
            entries_failed: int = 0,
            parse_duration_ms: float = 0.0,
            error_details: list[object] | None = None,
        ) -> FlextLdifModelsEvents.ParseEvent:
            """Create ParseEvent for file parsing operation."""
            return cls(
                unique_id=f"parse_file_{uuid.uuid4().hex[:8]}",
                event_type="ldif.parse",
                aggregate_id=str(file_path),
                parse_operation="parse_file",
                source_type="file",
                entries_parsed=entries_parsed,
                entries_failed=entries_failed,
                parse_duration_ms=parse_duration_ms,
                error_details=error_details,
            )

        @classmethod
        def for_ldap3(
            cls,
            connection_info: str,
            entries_parsed: int = 0,
            entries_failed: int = 0,
            parse_duration_ms: float = 0.0,
            error_details: list[object] | None = None,
        ) -> FlextLdifModelsEvents.ParseEvent:
            """Create ParseEvent for LDAP3 parsing operation."""
            return cls(
                unique_id=f"parse_ldap3_{uuid.uuid4().hex[:8]}",
                event_type="ldif.parse",
                aggregate_id=connection_info,
                parse_operation="parse_ldap3",
                source_type="ldap3",
                entries_parsed=entries_parsed,
                entries_failed=entries_failed,
                parse_duration_ms=parse_duration_ms,
                error_details=error_details,
            )

        @classmethod
        def for_string(
            cls,
            content_length: int,
            entries_parsed: int = 0,
            entries_failed: int = 0,
            parse_duration_ms: float = 0.0,
            error_details: list[object] | None = None,
        ) -> FlextLdifModelsEvents.ParseEvent:
            """Create ParseEvent for string parsing operation."""
            return cls(
                unique_id=f"parse_string_{uuid.uuid4().hex[:8]}",
                event_type="ldif.parse",
                aggregate_id=f"content_{content_length}chars",
                parse_operation="parse_string",
                source_type="string",
                entries_parsed=entries_parsed,
                entries_failed=entries_failed,
                parse_duration_ms=parse_duration_ms,
                error_details=error_details,
            )

    class WriteEvent(FlextModels.DomainEvent):
        """Event emitted when LDIF content is written.

        Tracks writing operations including target and results.
        """

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        write_operation: str = Field(
            default="write_file",
            description="Write operation name (e.g., 'write_file', 'write_string')",
        )
        target_type: str = Field(
            default="file",
            description="Target type (file, string)",
        )
        entries_written: int = Field(
            default=0,
            description="Number of entries successfully written",
        )
        entries_failed: int = Field(
            default=0,
            description="Number of entries that failed writing",
        )
        write_duration_ms: float = Field(
            default=0.0,
            description="Duration in milliseconds",
        )
        error_details: list[object] | None = Field(
            default=None,
            description="Error information for failed entries",
        )

    class CategoryEvent(FlextModels.DomainEvent):
        """Event emitted when entries are categorized.

        Tracks categorization operations including rules applied and results.
        """

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        category_operation: str = Field(
            ...,
            description="Category operation name (e.g., 'categorize_by_dn')",
        )
        entries_categorized: int = Field(
            default=0,
            description="Number of entries categorized",
        )
        categories_created: list[str] = Field(
            default_factory=list,
            description="List of categories created",
        )
        categorization_duration_ms: float = Field(
            default=0.0,
            description="Duration in milliseconds",
        )

    class AclEvent(FlextModels.DomainEvent):
        """Event emitted when ACLs are processed.

        Tracks ACL parsing, transformation, and validation operations.
        """

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        acl_operation: str = Field(
            ...,
            description="ACL operation name (e.g., 'parse_acl', 'transform_acl')",
        )
        acls_processed: int = Field(
            default=0,
            description="Number of ACLs processed",
        )
        acls_succeeded: int = Field(
            default=0,
            description="Number of ACLs successfully processed",
        )
        acls_failed: int = Field(
            default=0,
            description="Number of ACLs that failed processing",
        )
        acl_duration_ms: float = Field(
            default=0.0,
            description="Duration in milliseconds",
        )
        error_details: list[object] | None = Field(
            default=None,
            description="Error information for failed ACLs",
        )

    class DnEvent(FlextModels.DomainEvent):
        """Event emitted when DNs are processed.

        Tracks DN parsing, normalization, and validation operations.
        """

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        dn_operation: str = Field(
            ...,
            description="DN operation name (e.g., 'parse_dn', 'normalize_dn')",
        )
        input_dn: str = Field(
            ...,
            description="Input DN before operation",
        )
        output_dn: str | None = Field(
            default=None,
            description="Output DN after operation (None if failed)",
        )
        dn_duration_ms: float = Field(
            default=0.0,
            description="Duration in milliseconds",
        )
        validation_result: bool | None = Field(
            default=None,
            description="Validation result (None if not validated)",
        )
        has_output: bool = Field(
            default=False,
            description="Whether operation produced output DN",
        )
        component_count: int = Field(
            default=0,
            description="Number of DN components parsed",
        )

    class MigrationEvent(FlextModels.DomainEvent):
        """Event emitted during migration operations.

        Tracks server-to-server migration progress and results.
        """

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        migration_operation: str = Field(
            ...,
            description="Migration operation name (e.g., 'full_migration')",
        )
        source_server: str = Field(
            ...,
            description="Source LDAP server type",
        )
        target_server: str = Field(
            ...,
            description="Target LDAP server type",
        )
        entries_migrated: int = Field(
            default=0,
            description="Number of entries successfully migrated",
        )
        entries_failed: int = Field(
            default=0,
            description="Number of entries that failed migration",
        )
        migration_duration_ms: float = Field(
            default=0.0,
            description="Duration in milliseconds",
        )
        error_details: list[object] | None = Field(
            default=None,
            description="Error information for failed entries",
        )
        migration_success_rate: float = Field(
            default=0.0,
            description="Migration success rate as percentage",
        )
        throughput_entries_per_sec: float = Field(
            default=0.0,
            description="Migration throughput in entries per second",
        )

    class ConversionEvent(FlextModels.DomainEvent):
        """Event emitted during conversion operations.

        Tracks format conversion progress and results.
        """

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        conversion_operation: str = Field(
            ...,
            description="Conversion operation name (e.g., 'acl_transform')",
        )
        source_format: str = Field(
            ...,
            description="Source format type",
        )
        target_format: str = Field(
            ...,
            description="Target format type",
        )
        items_converted: int = Field(
            default=0,
            description="Number of items successfully converted",
        )
        items_failed: int = Field(
            default=0,
            description="Number of items that failed conversion",
        )
        conversion_duration_ms: float = Field(
            default=0.0,
            description="Duration in milliseconds",
        )
        error_details: list[object] | None = Field(
            default=None,
            description="Error information for failed conversions",
        )
        conversion_success_rate: float = Field(
            default=0.0,
            description="Conversion success rate as percentage",
        )
        throughput_items_per_sec: float = Field(
            default=0.0,
            description="Conversion throughput in items per second",
        )

    class SchemaEvent(FlextModels.DomainEvent):
        """Event emitted during schema processing.

        Tracks schema parsing, validation, and transformation operations.
        """

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        schema_operation: str = Field(
            ...,
            description="Schema operation name (e.g., 'parse_attribute')",
        )
        items_processed: int = Field(
            default=0,
            description="Number of schema items processed",
        )
        items_succeeded: int = Field(
            default=0,
            description="Number of schema items successfully processed",
        )
        items_failed: int = Field(
            default=0,
            description="Number of schema items that failed processing",
        )
        schema_duration_ms: float = Field(
            default=0.0,
            description="Duration in milliseconds",
        )
        error_details: list[object] | None = Field(
            default=None,
            description="Error information for failed schema items",
        )
        schema_success_rate: float = Field(
            default=0.0,
            description="Schema processing success rate as percentage",
        )
        throughput_items_per_sec: float = Field(
            default=0.0,
            description="Schema processing throughput in items per second",
        )

    class SchemaEventConfig(FlextModels.Value):
        """Configuration for schema event creation."""

        schema_operation: str = Field(description="Schema operation name")
        items_processed: int = Field(default=0, description="Items processed")
        items_succeeded: int = Field(default=0, description="Items succeeded")
        items_failed: int = Field(default=0, description="Items failed")
        operation_duration_ms: float = Field(
            default=0.0, description="Duration in milliseconds"
        )
        server_type: str = Field(description="Server type")
        schema_type: str = Field(default="generic", description="Schema type")
