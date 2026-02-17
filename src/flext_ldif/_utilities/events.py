"""Event Utilities - Domain Event Creation and Management Helpers."""

from __future__ import annotations

from flext_core import FlextLogger, FlextTypes, t
from flext_core._models.entity import FlextModelsEntity

from flext_ldif._models.events import FlextLdifModelsEvents
from flext_ldif._models.settings import FlextLdifModelsSettings


class FlextLdifUtilitiesEvents:
    """Event creation, storage, and statistics helpers for domain events."""

    # ════════════════════════════════════════════════════════════════════════
    # EVENT FACTORY METHODS
    # ════════════════════════════════════════════════════════════════════════

    @staticmethod
    def _to_error_details_list(
        error_details: list[object] | tuple[object, ...] | None,
    ) -> list[str]:
        if error_details is None:
            return []
        return [str(detail) for detail in error_details]

    @staticmethod
    def create_dn_event(
        config: FlextLdifModelsEvents.DnEventConfig,
    ) -> FlextLdifModelsEvents.DnEvent:
        """Create DnEvent with standardized fields from config Model."""
        return FlextLdifModelsEvents.DnEvent(
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
        config: FlextLdifModelsEvents.MigrationEventConfig,
    ) -> FlextLdifModelsEvents.MigrationEvent:
        """Create MigrationEvent with standardized fields from config Model."""
        aggregate_id = f"{config.source_server}_to_{config.target_server}_{config.migration_operation}"
        error_details_list = FlextLdifUtilitiesEvents._to_error_details_list(
            list(config.error_details) if config.error_details is not None else None
        )
        return FlextLdifModelsEvents.MigrationEvent(
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
        config: FlextLdifModelsEvents.ConversionEventConfig,
    ) -> FlextLdifModelsEvents.ConversionEvent:
        """Create ConversionEvent with standardized fields from config Model."""
        aggregate_id = f"{config.source_format}_to_{config.target_format}_{config.conversion_operation}"
        error_details_list = FlextLdifUtilitiesEvents._to_error_details_list(
            list(config.error_details) if config.error_details is not None else None
        )
        return FlextLdifModelsEvents.ConversionEvent(
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
        config: FlextLdifModelsEvents.SchemaEventConfig,
    ) -> FlextLdifModelsEvents.SchemaEvent:
        """Create SchemaEvent with standardized fields from config Model."""
        aggregate_id = f"{config.server_type}_schema_{config.schema_operation}"
        return FlextLdifModelsEvents.SchemaEvent(
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
        instance: FlextTypes.GeneralValueType,
        event: FlextModelsEntity.DomainEvent,
        attr_name: str = "_last_event",
    ) -> None:
        """Store event in Pydantic instance using object.__setattr__."""
        setattr(instance, attr_name, event)

    # ════════════════════════════════════════════════════════════════════════
    # STATISTICS HELPERS
    # ════════════════════════════════════════════════════════════════════════

    @staticmethod
    def calculate_success_rate(
        successful: int,
        failed: int,
    ) -> float:
        """Calculate success rate percentage."""
        total = successful + failed
        if total == 0:
            return 100.0
        return (successful / total) * 100.0

    @staticmethod
    def calculate_throughput(
        items: int,
        duration_ms: float,
    ) -> float:
        """Calculate throughput in items per second."""
        if duration_ms == 0:
            return 0.0
        return (items / duration_ms) * 1000.0

    @staticmethod
    def calculate_average(
        total: float,
        count: int,
    ) -> float:
        """Calculate average value."""
        if count == 0:
            return 0.0
        return total / count

    # ════════════════════════════════════════════════════════════════════════
    # INTEGRATED LOGGING & EVENT HELPERS (FlextLogger Integration)
    # ════════════════════════════════════════════════════════════════════════

    @staticmethod
    def _process_extras(
        extras: FlextLdifModelsSettings.LogContextExtras | None = None,
    ) -> dict[str, t.ScalarValue]:
        """Extract and filter extras into a dict of loggable context."""
        filtered_extras: dict[str, t.ScalarValue] = {}
        if not extras:
            return filtered_extras

        # Access known fields directly
        if extras.user_id is not None:
            filtered_extras["user_id"] = extras.user_id
        if extras.session_id is not None:
            filtered_extras["session_id"] = extras.session_id
        if extras.request_id is not None:
            filtered_extras["request_id"] = extras.request_id
        if extras.component is not None:
            filtered_extras["component"] = extras.component
        if extras.correlation_id is not None:
            filtered_extras["correlation_id"] = extras.correlation_id
        if extras.trace_id is not None:
            filtered_extras["trace_id"] = extras.trace_id
        return filtered_extras

    @staticmethod
    def log_and_emit_dn_event(
        logger: FlextLogger,
        config: FlextLdifModelsEvents.DnEventConfig,
        log_level: str = "info",
        extras: FlextLdifModelsSettings.LogContextExtras | None = None,
    ) -> FlextLdifModelsEvents.DnEvent:
        """Create DnEvent, log with context, and attach to logger context."""
        # Create event
        event = FlextLdifUtilitiesEvents.create_dn_event(config)

        # Build log context with event data (explicit type annotation for compatibility)
        log_context: dict[str, t.ScalarValue] = {
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
        log_context: dict[str, t.ScalarValue],
        log_message: str,
        log_level: str = "info",
        extras: FlextLdifModelsSettings.LogContextExtras | None = None,
    ) -> None:
        """Generic helper for logging events with context and extras."""
        # Add extras using shared processing helper
        filtered_extras = FlextLdifUtilitiesEvents._process_extras(extras)
        log_context.update(filtered_extras)

        # Log with appropriate level (common logic for all event types)
        if log_level == "debug":
            logger.debug(log_message, return_result=False, **log_context)
        elif log_level == "warning":
            logger.warning(log_message, return_result=False, **log_context)
        elif log_level == "error":
            logger.error(log_message, return_result=False, **log_context)
        else:
            logger.info(log_message, return_result=False, **log_context)

    @staticmethod
    def _build_operation_event_logging(
        event: FlextLdifModelsEvents.MigrationEvent,
        config: FlextLdifModelsEvents.MigrationEventConfig,
    ) -> tuple[dict[str, t.ScalarValue], str]:
        return (
            {
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
            },
            f"Migration '{config.migration_operation}' from {config.source_server} to {config.target_server} completed",
        )

    @staticmethod
    def _build_conversion_event_logging(
        event: FlextLdifModelsEvents.ConversionEvent,
        config: FlextLdifModelsEvents.ConversionEventConfig,
    ) -> tuple[dict[str, t.ScalarValue], str]:
        return (
            {
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
            },
            f"Conversion '{config.conversion_operation}' from {config.source_format} to {config.target_format} completed",
        )

    @staticmethod
    def log_and_emit_migration_event(
        logger: FlextLogger,
        config: FlextLdifModelsEvents.MigrationEventConfig,
        log_level: str = "info",
        extras: FlextLdifModelsSettings.LogContextExtras | None = None,
    ) -> FlextLdifModelsEvents.MigrationEvent:
        """Create MigrationEvent, log with context, and attach to logger context."""
        # Create event
        event = FlextLdifUtilitiesEvents.create_migration_event(config)

        log_context, log_message = (
            FlextLdifUtilitiesEvents._build_operation_event_logging(
                event,
                config,
            )
        )

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
        config: FlextLdifModelsEvents.ConversionEventConfig,
        log_level: str = "info",
        extras: FlextLdifModelsSettings.LogContextExtras | None = None,
    ) -> FlextLdifModelsEvents.ConversionEvent:
        """Create ConversionEvent, log with context, and attach to logger context."""
        # Create event
        event = FlextLdifUtilitiesEvents.create_conversion_event(config)

        log_context, log_message = (
            FlextLdifUtilitiesEvents._build_conversion_event_logging(
                event,
                config,
            )
        )

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
        config: FlextLdifModelsEvents.SchemaEventConfig,
        log_level: str = "info",
        extras: FlextLdifModelsSettings.LogContextExtras | None = None,
    ) -> FlextLdifModelsEvents.SchemaEvent:
        """Create SchemaEvent, log with context, and attach to logger context."""
        # Create event
        event = FlextLdifUtilitiesEvents.create_schema_event(config)

        # Build log context with event data + computed metrics (explicit type annotation)
        log_context: dict[str, t.ScalarValue] = {
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
