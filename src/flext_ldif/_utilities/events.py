"""Event Utilities - Domain Event Creation and Management Helpers.

Centralizes all event-related logic to avoid code duplication across services.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextLogger

from flext_ldif.models import FlextLdifModels


class FlextLdifUtilitiesEvents:
    """Event creation, storage, and statistics helpers for domain events."""

    # ════════════════════════════════════════════════════════════════════════
    # EVENT FACTORY METHODS
    # ════════════════════════════════════════════════════════════════════════

    @staticmethod
    def create_dn_event(
        config: FlextLdifModels.DnEventConfig,
    ) -> FlextLdifModels.DnEvent:
        """Create DnEvent with standardized fields from config Model.

        Args:
            config: DN event configuration Model

        Returns:
            Configured DnEvent instance

        Example:
            config = FlextLdifModels.DnEventConfig(
                dn_operation="normalize",
                input_dn="CN=Admin,DC=Example",
                output_dn="cn=admin,dc=example",
                operation_duration_ms=1.2,
            )
            event = FlextLdifUtilities.Events.create_dn_event(config)

        """
        return FlextLdifModels.DnEvent(
            event_type="ldif.dn",
            aggregate_id=config.input_dn,  # Use input DN as aggregate identifier
            dn_operation=config.dn_operation,
            input_dn=config.input_dn,
            output_dn=config.output_dn,
            dn_duration_ms=config.operation_duration_ms,
            validation_result=config.validation_result,
        )

    @staticmethod
    def create_migration_event(
        config: FlextLdifModels.MigrationEventConfig,
    ) -> FlextLdifModels.MigrationEvent:
        """Create MigrationEvent with standardized fields from config Model.

        Args:
            config: Migration event configuration Model

        Returns:
            Configured MigrationEvent instance

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
        aggregate_id = f"{config.source_server}_to_{config.target_server}_{config.migration_operation}"
        # Fast fail if error_details is None when list is required
        error_details_list: list[object] = []
        if config.error_details is not None:
            error_details_list = list(config.error_details)
        return FlextLdifModels.MigrationEvent(
            event_type="ldif.migration",
            aggregate_id=aggregate_id,  # Unique identifier for this migration
            migration_operation=config.migration_operation,
            source_server=config.source_server,
            target_server=config.target_server,
            entries_migrated=config.entries_migrated,
            entries_failed=config.entries_failed,
            migration_duration_ms=config.migration_duration_ms,
            error_details=error_details_list,
        )

    @staticmethod
    def create_conversion_event(
        config: FlextLdifModels.ConversionEventConfig,
    ) -> FlextLdifModels.ConversionEvent:
        """Create ConversionEvent with standardized fields from config Model.

        Args:
            config: Conversion event configuration Model

        Returns:
            Configured ConversionEvent instance

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
        aggregate_id = f"{config.source_format}_to_{config.target_format}_{config.conversion_operation}"
        # Fast fail if error_details is None when list is required
        error_details_list: list[object] = []
        if config.error_details is not None:
            error_details_list = list(config.error_details)
        return FlextLdifModels.ConversionEvent(
            event_type="ldif.conversion",
            aggregate_id=aggregate_id,  # Unique identifier for this conversion
            conversion_operation=config.conversion_operation,
            source_format=config.source_format,
            target_format=config.target_format,
            items_converted=config.items_converted,
            items_failed=config.items_failed,
            conversion_duration_ms=config.conversion_duration_ms,
            error_details=error_details_list,
        )

    @staticmethod
    def create_schema_event(
        config: FlextLdifModels.SchemaEventConfig,
    ) -> FlextLdifModels.SchemaEvent:
        """Create SchemaEvent with standardized fields from config Model.

        Args:
            config: Schema event configuration Model

        Returns:
            Configured SchemaEvent instance

        Example:
            config = FlextLdifModels.SchemaEventConfig(
                schema_operation="parse_attribute",
                items_processed=50,
                items_succeeded=48,
                items_failed=2,
                operation_duration_ms=125.3,
                server_type="oud",
            )
            event = FlextLdifUtilities.Events.create_schema_event(config)

        """
        aggregate_id = f"{config.server_type}_schema_{config.schema_operation}"
        return FlextLdifModels.SchemaEvent(
            event_type="ldif.schema",
            aggregate_id=aggregate_id,
            schema_operation=config.schema_operation,
            items_processed=config.items_processed,
            items_succeeded=config.items_succeeded,
            items_failed=config.items_failed,
            schema_duration_ms=config.operation_duration_ms,
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
        setattr(instance, attr_name, event)

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
    def _process_extras(
        extras: FlextLdifModels.LogContextExtras | None = None,
    ) -> dict[str, object]:
        """Extract and filter extras into a dict of loggable context.

        Handles all known fields + dynamic extra fields from LogContextExtras.

        Args:
            extras: Additional typed context fields for logging

        Returns:
            Filtered dict with string/int/float/bool values only

        """
        filtered_extras: dict[str, object] = {}
        if not extras:
            return filtered_extras

        # Access known fields directly
        if extras.user_id is not None:
            filtered_extras["user_id"] = extras.user_id
        if extras.session_id is not None:
            filtered_extras["session_id"] = extras.session_id
        if extras.request_id is not None:
            filtered_extras["request_id"] = extras.request_id
        if extras.correlation_id is not None:
            filtered_extras["correlation_id"] = extras.correlation_id
        if extras.trace_id is not None:
            filtered_extras["trace_id"] = extras.trace_id
        # Handle extra fields (LogContextExtras has extra="allow")
        for key, value in extras.__dict__.items():
            if (
                key not in filtered_extras
                and value is not None
                and isinstance(value, str | int | float | bool)
            ):
                filtered_extras[key] = value
        return filtered_extras

    @staticmethod
    def log_and_emit_dn_event(
        logger: FlextLogger,
        config: FlextLdifModels.DnEventConfig,
        log_level: str = "info",
        extras: FlextLdifModels.LogContextExtras | None = None,
    ) -> FlextLdifModels.DnEvent:
        """Create DnEvent, log with context, and attach to logger context.

        This is the ONE-STEP API for DN operations with automatic logging integration.

        Args:
            logger: FlextLogger instance
            config: DN event configuration Model
            log_level: Log level (info, debug, warning, error)
            extras: Additional typed context fields for logging

        Returns:
            Created DnEvent instance

        Example:
            config = FlextLdifModels.DnEventConfig(
                dn_operation="normalize",
                input_dn="CN=Admin,DC=Example",
                output_dn="cn=admin,dc=example",
                operation_duration_ms=1.2,
            )
            extras = FlextLdifModels.LogContextExtras(user_id="admin")
            event = FlextLdifUtilities.Events.log_and_emit_dn_event(
                logger=logger,
                config=config,
                extras=extras,
            )

        """
        # Create event
        event = FlextLdifUtilitiesEvents.create_dn_event(config)

        # Build log context with event data (type inferred from values)
        log_context = {
            "aggregate_id": event.aggregate_id,
            "dn_operation": config.dn_operation,
            "input_dn": config.input_dn,
            "output_dn": config.output_dn,
            "operation_duration_ms": config.operation_duration_ms,
            "has_output": event.has_output,
            "component_count": event.component_count,
        }

        # Log with context and extras using shared helper
        log_message = f"DN operation '{config.dn_operation}' completed"
        FlextLdifUtilitiesEvents._log_and_emit_generic_event(
            logger=logger,
            log_context=log_context,
            log_message=log_message,
            log_level=log_level,
            extras=extras,
        )

        return event

    @staticmethod
    def _log_and_emit_generic_event(
        logger: FlextLogger,
        log_context: dict[str, object],
        log_message: str,
        log_level: str = "info",
        extras: FlextLdifModels.LogContextExtras | None = None,
    ) -> None:
        """Generic helper for logging events with context and extras.

        Consolidated logic for all log_and_emit_* methods to eliminate duplication.
        Handles extras filtering and log level routing.

        Args:
            logger: FlextLogger instance
            log_context: Base log context dict (will be modified in-place)
            log_message: Log message template
            log_level: Log level (info, debug, warning, error)
            extras: Additional typed context fields for logging

        """
        # Add extras using shared processing helper
        filtered_extras = FlextLdifUtilitiesEvents._process_extras(extras)
        log_context.update(filtered_extras)

        # Log with appropriate level (common logic for all event types)
        if log_level == "debug":
            logger.debug(log_message, **log_context)
        elif log_level == "warning":
            logger.warning(log_message, **log_context)
        elif log_level == "error":
            logger.error(log_message, **log_context)
        else:
            logger.info(log_message, **log_context)

    @staticmethod
    def log_and_emit_migration_event(
        logger: FlextLogger,
        config: FlextLdifModels.MigrationEventConfig,
        log_level: str = "info",
        extras: FlextLdifModels.LogContextExtras | None = None,
    ) -> FlextLdifModels.MigrationEvent:
        """Create MigrationEvent, log with context, and attach to logger context.

        This is the ONE-STEP API for migration operations with automatic logging integration.

        Args:
            logger: FlextLogger instance
            config: Migration event configuration Model
            log_level: Log level (info, debug, warning, error)
            extras: Additional typed context fields for logging

        Returns:
            Created MigrationEvent instance

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
            event = FlextLdifUtilities.Events.log_and_emit_migration_event(
                logger=logger,
                config=config,
            )

        """
        # Create event
        event = FlextLdifUtilitiesEvents.create_migration_event(config)

        # Build log context with event data + computed metrics
        log_context = {
            "aggregate_id": event.aggregate_id,
            "migration_operation": config.migration_operation,
            "source_server": config.source_server,
            "target_server": config.target_server,
            "entries_processed": config.entries_processed,
            "entries_migrated": config.entries_migrated,
            "entries_failed": config.entries_failed,
            "migration_duration_ms": config.migration_duration_ms,
            "success_rate_pct": event.migration_success_rate,
            "throughput_entries_per_sec": event.throughput_entries_per_sec,
        }

        # Build log message
        log_message = f"Migration '{config.migration_operation}' from {config.source_server} to {config.target_server} completed"

        # Delegate to generic helper for extras and logging
        FlextLdifUtilitiesEvents._log_and_emit_generic_event(
            logger,
            log_context,
            log_message,
            log_level,
            extras,
        )

        return event

    @staticmethod
    def log_and_emit_conversion_event(
        logger: FlextLogger,
        config: FlextLdifModels.ConversionEventConfig,
        log_level: str = "info",
        extras: FlextLdifModels.LogContextExtras | None = None,
    ) -> FlextLdifModels.ConversionEvent:
        """Create ConversionEvent, log with context, and attach to logger context.

        This is the ONE-STEP API for conversion operations with automatic logging integration.

        Args:
            logger: FlextLogger instance
            config: Conversion event configuration Model
            log_level: Log level (info, debug, warning, error)
            extras: Additional typed context fields for logging

        Returns:
            Created ConversionEvent instance

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
            event = FlextLdifUtilities.Events.log_and_emit_conversion_event(
                logger=logger,
                config=config,
            )

        """
        # Create event
        event = FlextLdifUtilitiesEvents.create_conversion_event(config)

        # Build log context with event data + computed metrics
        log_context = {
            "aggregate_id": event.aggregate_id,
            "conversion_operation": config.conversion_operation,
            "source_format": config.source_format,
            "target_format": config.target_format,
            "items_processed": config.items_processed,
            "items_converted": config.items_converted,
            "items_failed": config.items_failed,
            "conversion_duration_ms": config.conversion_duration_ms,
            "success_rate_pct": event.conversion_success_rate,
            "throughput_items_per_sec": event.throughput_items_per_sec,
        }

        # Build log message
        log_message = f"Conversion '{config.conversion_operation}' from {config.source_format} to {config.target_format} completed"

        # Delegate to generic helper for extras and logging
        FlextLdifUtilitiesEvents._log_and_emit_generic_event(
            logger,
            log_context,
            log_message,
            log_level,
            extras,
        )

        return event

    @staticmethod
    def log_and_emit_schema_event(
        logger: FlextLogger,
        config: FlextLdifModels.SchemaEventConfig,
        log_level: str = "info",
        extras: FlextLdifModels.LogContextExtras | None = None,
    ) -> FlextLdifModels.SchemaEvent:
        """Create SchemaEvent, log with context, and attach to logger context.

        This is the ONE-STEP API for schema operations with automatic logging integration.

        Args:
            logger: FlextLogger instance
            config: Schema event configuration Model
            log_level: Log level (info, debug, warning, error)
            extras: Additional typed context fields for logging

        Returns:
            Created SchemaEvent instance

        Example:
            config = FlextLdifModels.SchemaEventConfig(
                schema_operation="parse_attribute",
                items_processed=50,
                items_succeeded=48,
                items_failed=2,
                operation_duration_ms=125.3,
                server_type="oud",
            )
            event = FlextLdifUtilities.Events.log_and_emit_schema_event(
                logger=logger,
                config=config,
            )

        """
        # Create event
        event = FlextLdifUtilitiesEvents.create_schema_event(config)

        # Build log context with event data + computed metrics (type inferred from values)
        log_context = {
            "aggregate_id": event.aggregate_id,
            "schema_operation": config.schema_operation,
            "items_processed": config.items_processed,
            "items_succeeded": config.items_succeeded,
            "items_failed": config.items_failed,
            "operation_duration_ms": config.operation_duration_ms,
            "server_type": config.server_type,
            "success_rate_pct": event.schema_success_rate,
            "throughput_items_per_sec": event.throughput_items_per_sec,
        }

        # Log with context and extras using shared helper
        log_message = f"Schema operation '{config.schema_operation}' on {config.server_type} completed"
        FlextLdifUtilitiesEvents._log_and_emit_generic_event(
            logger=logger,
            log_context=log_context,
            log_message=log_message,
            log_level=log_level,
            extras=extras,
        )

        return event


__all__ = [
    "FlextLdifUtilitiesEvents",
]
