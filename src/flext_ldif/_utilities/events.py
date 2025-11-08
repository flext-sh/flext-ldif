"""Event Utilities - Domain Event Creation and Management Helpers.

Centralizes all event-related logic to avoid code duplication across services.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Any

from flext_ldif.models import FlextLdifModels


class FlextLdifUtilitiesEvents:
    """Event creation, storage, and statistics helpers for domain events."""

    # ════════════════════════════════════════════════════════════════════════
    # EVENT FACTORY METHODS
    # ════════════════════════════════════════════════════════════════════════

    @staticmethod
    def create_dn_event(
        *,
        dn_operation: str,
        input_dn: str,
        output_dn: str | None = None,
        operation_duration_ms: float = 0.0,
        validation_result: bool | None = None,
        parse_components: list[tuple[str, str]] | None = None,
    ) -> FlextLdifModels.DnEvent:
        """Create DnEvent with standardized fields.

        Args:
            dn_operation: Operation name (parse, validate, normalize, etc.)
            input_dn: Input DN before operation
            output_dn: Output DN after operation (None if failed)
            operation_duration_ms: Duration in milliseconds
            validation_result: Validation result (None if not validated)
            parse_components: Parsed DN components

        Returns:
            Configured DnEvent instance

        """
        return FlextLdifModels.DnEvent(
            event_type="ldif.dn",
            aggregate_id=input_dn,  # Use input DN as aggregate identifier
            dn_operation=dn_operation,
            input_dn=input_dn,
            output_dn=output_dn,
            operation_duration_ms=operation_duration_ms,
            validation_result=validation_result,
            parse_components=parse_components,
        )

    @staticmethod
    def create_migration_event(
        *,
        migration_operation: str,
        source_server: str,
        target_server: str,
        entries_processed: int,
        entries_migrated: int = 0,
        entries_failed: int = 0,
        migration_duration_ms: float = 0.0,
        error_details: list[dict[str, Any]] | None = None,
    ) -> FlextLdifModels.MigrationEvent:
        """Create MigrationEvent with standardized fields.

        Args:
            migration_operation: Operation name (full_migration, incremental, etc.)
            source_server: Source LDAP server type
            target_server: Target LDAP server type
            entries_processed: Total entries processed
            entries_migrated: Entries successfully migrated
            entries_failed: Entries that failed migration
            migration_duration_ms: Duration in milliseconds
            error_details: Error information for failed entries

        Returns:
            Configured MigrationEvent instance

        """
        aggregate_id = f"{source_server}_to_{target_server}_{migration_operation}"
        return FlextLdifModels.MigrationEvent(
            event_type="ldif.migration",
            aggregate_id=aggregate_id,  # Unique identifier for this migration
            migration_operation=migration_operation,
            source_server=source_server,
            target_server=target_server,
            entries_processed=entries_processed,
            entries_migrated=entries_migrated,
            entries_failed=entries_failed,
            migration_duration_ms=migration_duration_ms,
            error_details=error_details or [],
        )

    @staticmethod
    def create_conversion_event(
        *,
        conversion_operation: str,
        source_format: str,
        target_format: str,
        items_processed: int,
        items_converted: int = 0,
        items_failed: int = 0,
        conversion_duration_ms: float = 0.0,
        error_details: list[dict[str, Any]] | None = None,
    ) -> FlextLdifModels.ConversionEvent:
        """Create ConversionEvent with standardized fields.

        Args:
            conversion_operation: Operation name (acl_transform, schema_convert, etc.)
            source_format: Source format type
            target_format: Target format type
            items_processed: Total items processed
            items_converted: Items successfully converted
            items_failed: Items that failed conversion
            conversion_duration_ms: Duration in milliseconds
            error_details: Error information for failed conversions

        Returns:
            Configured ConversionEvent instance

        """
        aggregate_id = f"{source_format}_to_{target_format}_{conversion_operation}"
        return FlextLdifModels.ConversionEvent(
            event_type="ldif.conversion",
            aggregate_id=aggregate_id,  # Unique identifier for this conversion
            conversion_operation=conversion_operation,
            source_format=source_format,
            target_format=target_format,
            items_processed=items_processed,
            items_converted=items_converted,
            items_failed=items_failed,
            conversion_duration_ms=conversion_duration_ms,
            error_details=error_details or [],
        )

    @staticmethod
    def create_schema_event(
        *,
        schema_operation: str,
        items_processed: int,
        items_succeeded: int = 0,
        items_failed: int = 0,
        operation_duration_ms: float = 0.0,
        server_type: str = "rfc",
        error_details: list[dict[str, Any]] | None = None,
    ) -> FlextLdifModels.SchemaEvent:
        """Create SchemaEvent with standardized fields.

        Args:
            schema_operation: Operation name (parse_attribute, parse_objectclass, validate, etc.)
            items_processed: Total number of schema items processed
            items_succeeded: Number of items processed successfully
            items_failed: Number of items that failed processing
            operation_duration_ms: Total operation duration in milliseconds
            server_type: LDAP server type (oid, oud, openldap, etc.)
            error_details: Detailed error information for failed items

        Returns:
            Configured SchemaEvent instance

        """
        aggregate_id = f"{server_type}_schema_{schema_operation}"
        return FlextLdifModels.SchemaEvent(
            event_type="ldif.schema",
            aggregate_id=aggregate_id,
            schema_operation=schema_operation,
            items_processed=items_processed,
            items_succeeded=items_succeeded,
            items_failed=items_failed,
            operation_duration_ms=operation_duration_ms,
            server_type=server_type,
            error_details=error_details or [],
        )

    # ════════════════════════════════════════════════════════════════════════
    # EVENT STORAGE HELPERS
    # ════════════════════════════════════════════════════════════════════════

    @staticmethod
    def store_event_in_instance(
        instance: object,
        event: FlextLdifModels.DomainEvent,
        attr_name: str = "_last_event",
    ) -> None:
        """Store event in Pydantic instance using object.__setattr__.

        Use this for frozen Pydantic models or when direct assignment fails.

        Args:
            instance: Pydantic instance to store event in
            event: Domain event to store
            attr_name: Attribute name (default: "_last_event")

        Example:
            event = create_dn_event(...)
            store_event_in_instance(self, event)

        """
        object.__setattr__(instance, attr_name, event)  # noqa: PLC2801

    # ════════════════════════════════════════════════════════════════════════
    # STATISTICS HELPERS
    # ════════════════════════════════════════════════════════════════════════

    @staticmethod
    def calculate_success_rate(
        successful: int,
        failed: int,
    ) -> float:
        """Calculate success rate percentage.

        Args:
            successful: Number of successful operations
            failed: Number of failed operations

        Returns:
            Success rate as percentage (0.0-100.0)

        """
        total = successful + failed
        if total == 0:
            return 100.0
        return (successful / total) * 100.0

    @staticmethod
    def calculate_throughput(
        items: int,
        duration_ms: float,
    ) -> float:
        """Calculate throughput in items per second.

        Args:
            items: Number of items processed
            duration_ms: Duration in milliseconds

        Returns:
            Throughput in items per second

        """
        if duration_ms == 0:
            return 0.0
        return (items / duration_ms) * 1000.0

    @staticmethod
    def calculate_average(
        total: float,
        count: int,
    ) -> float:
        """Calculate average value.

        Args:
            total: Total sum
            count: Number of items

        Returns:
            Average value (0.0 if count is 0)

        """
        if count == 0:
            return 0.0
        return total / count

    # ════════════════════════════════════════════════════════════════════════
    # INTEGRATED LOGGING & EVENT HELPERS (FlextLogger Integration)
    # ════════════════════════════════════════════════════════════════════════

    @staticmethod
    def log_and_emit_dn_event(
        logger: Any,  # noqa: ANN401 - FlextLogger instance
        *,
        dn_operation: str,
        input_dn: str,
        output_dn: str | None = None,
        operation_duration_ms: float = 0.0,
        validation_result: bool | None = None,
        parse_components: list[tuple[str, str]] | None = None,
        log_level: str = "info",
        **extra_context: Any,  # noqa: ANN401 - Dynamic logging context
    ) -> FlextLdifModels.DnEvent:
        """Create DnEvent, log with context, and attach to logger context.

        This is the ONE-STEP API for DN operations with automatic logging integration.

        Args:
            logger: FlextLogger instance
            dn_operation: Operation name (parse, validate, normalize, etc.)
            input_dn: Input DN before operation
            output_dn: Output DN after operation (None if failed)
            operation_duration_ms: Duration in milliseconds
            validation_result: Validation result (None if not validated)
            parse_components: Parsed DN components
            log_level: Log level (info, debug, warning, error)
            **extra_context: Additional context fields for logging

        Returns:
            Created DnEvent instance

        Example:
            event = FlextLdifUtilities.Events.log_and_emit_dn_event(
                logger=self.logger,
                dn_operation="normalize",
                input_dn="CN=Admin,DC=Example",
                output_dn="cn=admin,dc=example",
                operation_duration_ms=1.2,
            )

        """
        # Create event
        event = FlextLdifUtilitiesEvents.create_dn_event(
            dn_operation=dn_operation,
            input_dn=input_dn,
            output_dn=output_dn,
            operation_duration_ms=operation_duration_ms,
            validation_result=validation_result,
            parse_components=parse_components,
        )

        # Build log context with event data
        log_context = {
            "event_id": event.unique_id,  # From IdentifiableMixin
            "aggregate_id": event.aggregate_id,
            "dn_operation": dn_operation,
            "input_dn": input_dn,
            "output_dn": output_dn,
            "operation_duration_ms": operation_duration_ms,
            "has_output": event.has_output,
            "component_count": event.component_count,
            **extra_context,
        }

        # Log with appropriate level
        log_message = f"DN operation '{dn_operation}' completed"
        if log_level == "debug":
            logger.debug(log_message, **log_context)
        elif log_level == "warning":
            logger.warning(log_message, **log_context)
        elif log_level == "error":
            logger.error(log_message, **log_context)
        else:
            logger.info(log_message, **log_context)

        return event

    @staticmethod
    def log_and_emit_migration_event(
        logger: Any,  # noqa: ANN401 - FlextLogger instance
        *,
        migration_operation: str,
        source_server: str,
        target_server: str,
        entries_processed: int,
        entries_migrated: int = 0,
        entries_failed: int = 0,
        migration_duration_ms: float = 0.0,
        error_details: list[dict[str, Any]] | None = None,
        log_level: str = "info",
        **extra_context: Any,  # noqa: ANN401 - Dynamic logging context
    ) -> FlextLdifModels.MigrationEvent:
        """Create MigrationEvent, log with context, and attach to logger context.

        This is the ONE-STEP API for migration operations with automatic logging integration.

        Args:
            logger: FlextLogger instance
            migration_operation: Operation name (full_migration, incremental, etc.)
            source_server: Source LDAP server type
            target_server: Target LDAP server type
            entries_processed: Total entries processed
            entries_migrated: Entries successfully migrated
            entries_failed: Entries that failed migration
            migration_duration_ms: Duration in milliseconds
            error_details: Error information for failed entries
            log_level: Log level (info, debug, warning, error)
            **extra_context: Additional context fields for logging

        Returns:
            Created MigrationEvent instance

        Example:
            event = FlextLdifUtilities.Events.log_and_emit_migration_event(
                logger=self.logger,
                migration_operation="full_migration",
                source_server="oid",
                target_server="oud",
                entries_processed=1000,
                entries_migrated=980,
                entries_failed=20,
                migration_duration_ms=5420.5,
            )

        """
        # Create event
        event = FlextLdifUtilitiesEvents.create_migration_event(
            migration_operation=migration_operation,
            source_server=source_server,
            target_server=target_server,
            entries_processed=entries_processed,
            entries_migrated=entries_migrated,
            entries_failed=entries_failed,
            migration_duration_ms=migration_duration_ms,
            error_details=error_details,
        )

        # Build log context with event data + computed metrics
        log_context = {
            "event_id": event.unique_id,  # From IdentifiableMixin
            "aggregate_id": event.aggregate_id,
            "migration_operation": migration_operation,
            "source_server": source_server,
            "target_server": target_server,
            "entries_processed": entries_processed,
            "entries_migrated": entries_migrated,
            "entries_failed": entries_failed,
            "migration_duration_ms": migration_duration_ms,
            "success_rate_pct": event.migration_success_rate,
            "throughput_entries_per_sec": event.throughput_entries_per_sec,
            **extra_context,
        }

        # Log with appropriate level
        log_message = f"Migration '{migration_operation}' from {source_server} to {target_server} completed"
        if log_level == "debug":
            logger.debug(log_message, **log_context)
        elif log_level == "warning":
            logger.warning(log_message, **log_context)
        elif log_level == "error":
            logger.error(log_message, **log_context)
        else:
            logger.info(log_message, **log_context)

        return event

    @staticmethod
    def log_and_emit_conversion_event(
        logger: Any,  # noqa: ANN401 - FlextLogger instance
        *,
        conversion_operation: str,
        source_format: str,
        target_format: str,
        items_processed: int,
        items_converted: int = 0,
        items_failed: int = 0,
        conversion_duration_ms: float = 0.0,
        error_details: list[dict[str, Any]] | None = None,
        log_level: str = "info",
        **extra_context: Any,  # noqa: ANN401 - Dynamic logging context
    ) -> FlextLdifModels.ConversionEvent:
        """Create ConversionEvent, log with context, and attach to logger context.

        This is the ONE-STEP API for conversion operations with automatic logging integration.

        Args:
            logger: FlextLogger instance
            conversion_operation: Operation name (acl_transform, schema_convert, etc.)
            source_format: Source format type
            target_format: Target format type
            items_processed: Total items processed
            items_converted: Items successfully converted
            items_failed: Items that failed conversion
            conversion_duration_ms: Duration in milliseconds
            error_details: Error information for failed conversions
            log_level: Log level (info, debug, warning, error)
            **extra_context: Additional context fields for logging

        Returns:
            Created ConversionEvent instance

        Example:
            event = FlextLdifUtilities.Events.log_and_emit_conversion_event(
                logger=self.logger,
                conversion_operation="acl_transform",
                source_format="orclaci",
                target_format="olcAccess",
                items_processed=50,
                items_converted=48,
                items_failed=2,
                conversion_duration_ms=125.3,
            )

        """
        # Create event
        event = FlextLdifUtilitiesEvents.create_conversion_event(
            conversion_operation=conversion_operation,
            source_format=source_format,
            target_format=target_format,
            items_processed=items_processed,
            items_converted=items_converted,
            items_failed=items_failed,
            conversion_duration_ms=conversion_duration_ms,
            error_details=error_details,
        )

        # Build log context with event data + computed metrics
        log_context = {
            "event_id": event.unique_id,  # From IdentifiableMixin
            "aggregate_id": event.aggregate_id,
            "conversion_operation": conversion_operation,
            "source_format": source_format,
            "target_format": target_format,
            "items_processed": items_processed,
            "items_converted": items_converted,
            "items_failed": items_failed,
            "conversion_duration_ms": conversion_duration_ms,
            "success_rate_pct": event.conversion_success_rate,
            "throughput_items_per_sec": event.throughput_items_per_sec,
            **extra_context,
        }

        # Log with appropriate level
        log_message = f"Conversion '{conversion_operation}' from {source_format} to {target_format} completed"
        if log_level == "debug":
            logger.debug(log_message, **log_context)
        elif log_level == "warning":
            logger.warning(log_message, **log_context)
        elif log_level == "error":
            logger.error(log_message, **log_context)
        else:
            logger.info(log_message, **log_context)

        return event

    @staticmethod
    def log_and_emit_schema_event(
        logger: Any,  # noqa: ANN401 - FlextLogger instance
        *,
        schema_operation: str,
        items_processed: int,
        items_succeeded: int = 0,
        items_failed: int = 0,
        operation_duration_ms: float = 0.0,
        server_type: str = "rfc",
        error_details: list[dict[str, Any]] | None = None,
        log_level: str = "info",
        **extra_context: Any,  # noqa: ANN401 - Dynamic logging context
    ) -> FlextLdifModels.SchemaEvent:
        """Create SchemaEvent, log with context, and attach to logger context.

        This is the ONE-STEP API for schema operations with automatic logging integration.

        Args:
            logger: FlextLogger instance
            schema_operation: Operation name (parse_attribute, parse_objectclass, validate, etc.)
            items_processed: Total number of schema items processed
            items_succeeded: Number of items processed successfully
            items_failed: Number of items that failed processing
            operation_duration_ms: Total operation duration in milliseconds
            server_type: LDAP server type (oid, oud, openldap, etc.)
            error_details: Detailed error information for failed items
            log_level: Log level (info, debug, warning, error)
            **extra_context: Additional context fields for logging

        Returns:
            Created SchemaEvent instance

        Example:
            event = FlextLdifUtilities.Events.log_and_emit_schema_event(
                logger=logger,
                schema_operation="parse_attribute",
                items_processed=50,
                items_succeeded=48,
                items_failed=2,
                operation_duration_ms=125.3,
                server_type="oud",
            )

        """
        # Create event
        event = FlextLdifUtilitiesEvents.create_schema_event(
            schema_operation=schema_operation,
            items_processed=items_processed,
            items_succeeded=items_succeeded,
            items_failed=items_failed,
            operation_duration_ms=operation_duration_ms,
            server_type=server_type,
            error_details=error_details,
        )

        # Build log context with event data + computed metrics
        log_context = {
            "event_id": event.unique_id,  # From IdentifiableMixin
            "aggregate_id": event.aggregate_id,
            "schema_operation": schema_operation,
            "items_processed": items_processed,
            "items_succeeded": items_succeeded,
            "items_failed": items_failed,
            "operation_duration_ms": operation_duration_ms,
            "server_type": server_type,
            "success_rate_pct": event.schema_success_rate,
            "throughput_items_per_sec": event.throughput_items_per_sec,
            **extra_context,
        }

        # Log with appropriate level
        log_message = (
            f"Schema operation '{schema_operation}' on {server_type} completed"
        )
        if log_level == "debug":
            logger.debug(log_message, **log_context)
        elif log_level == "warning":
            logger.warning(log_message, **log_context)
        elif log_level == "error":
            logger.error(log_message, **log_context)
        else:
            logger.info(log_message, **log_context)

        return event


__all__ = [
    "FlextLdifUtilitiesEvents",
]
