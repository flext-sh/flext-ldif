"""Event Utilities - Domain Event Creation and Management Helpers."""

from __future__ import annotations

from collections.abc import MutableSequence

from flext_ldif import FlextLdifModelsEvents, FlextLdifModelsSettings, p, t


class FlextLdifUtilitiesEvents:
    """Event creation, storage, and statistics helpers for domain events."""

    @staticmethod
    def _build_conversion_event_logging(
        event: FlextLdifModelsEvents.ConversionEvent,
        config: FlextLdifModelsEvents.ConversionEventConfig,
    ) -> tuple[t.MutableScalarMapping, str]:
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
    def _log_and_emit_generic_event(
        logger: p.Logger,
        log_context: t.MutableScalarMapping,
        log_message: str,
        log_level: str = "info",
        extras: FlextLdifModelsSettings.LogContextExtras | None = None,
    ) -> None:
        """Generic helper for logging events with context and extras."""
        filtered_extras = FlextLdifUtilitiesEvents._process_extras(extras)
        merged_context = dict(log_context)
        merged_context.update(filtered_extras)
        if log_level == "debug":
            logger.debug(log_message, return_result=False, **merged_context)
        elif log_level == "warning":
            logger.warning(log_message, return_result=False, **merged_context)
        elif log_level == "error":
            logger.error(log_message, return_result=False, **merged_context)
        else:
            logger.info(log_message, return_result=False, **merged_context)

    @staticmethod
    def _process_extras(
        extras: FlextLdifModelsSettings.LogContextExtras | None = None,
    ) -> t.MutableScalarMapping:
        """Extract and filter extras into a dict of loggable context."""
        filtered_extras: t.MutableScalarMapping = {}
        if not extras:
            return filtered_extras
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
    def _to_error_details_list(
        error_details: t.MutableContainerList | tuple[t.NormalizedValue, ...] | None,
    ) -> MutableSequence[str]:
        if error_details is None:
            return []
        return [str(detail) for detail in error_details]

    @staticmethod
    def create_conversion_event(
        config: FlextLdifModelsEvents.ConversionEventConfig,
    ) -> FlextLdifModelsEvents.ConversionEvent:
        """Create ConversionEvent with standardized fields from config Model."""
        aggregate_id = f"{config.source_format}_to_{config.target_format}_{config.conversion_operation}"
        error_details_list = FlextLdifUtilitiesEvents._to_error_details_list(
            list(config.error_details) if config.error_details is not None else None,
        )
        return FlextLdifModelsEvents.ConversionEvent.model_validate({
            "event_type": "ldif.conversion",
            "aggregate_id": aggregate_id,
            "conversion_operation": config.conversion_operation,
            "source_format": config.source_format,
            "target_format": config.target_format,
            "items_converted": config.items_converted,
            "items_failed": config.items_failed,
            "conversion_duration_ms": config.conversion_duration_ms,
            "error_details": error_details_list,
        })

    @staticmethod
    def create_dn_event(
        config: FlextLdifModelsEvents.DnEventConfig,
    ) -> FlextLdifModelsEvents.DnEvent:
        """Create DnEvent with standardized fields from config Model."""
        return FlextLdifModelsEvents.DnEvent.model_validate({
            "event_type": "ldif.dn",
            "aggregate_id": config.input_dn,
            "dn_operation": config.dn_operation,
            "input_dn": config.input_dn,
            "output_dn": config.output_dn,
            "dn_duration_ms": config.operation_duration_ms,
            "validation_result": config.validation_result,
        })

    @staticmethod
    def log_and_emit_conversion_event(
        logger: p.Logger,
        config: FlextLdifModelsEvents.ConversionEventConfig,
        log_level: str = "info",
        extras: FlextLdifModelsSettings.LogContextExtras | None = None,
    ) -> FlextLdifModelsEvents.ConversionEvent:
        """Create ConversionEvent, log with context, and attach to logger context."""
        event = FlextLdifUtilitiesEvents.create_conversion_event(config)
        log_context, log_message = (
            FlextLdifUtilitiesEvents._build_conversion_event_logging(event, config)
        )
        FlextLdifUtilitiesEvents._log_and_emit_generic_event(
            logger,
            log_context,
            log_message,
            log_level,
            extras,
        )
        return event

    @staticmethod
    def log_and_emit_dn_event(
        logger: p.Logger,
        config: FlextLdifModelsEvents.DnEventConfig,
        log_level: str = "info",
        extras: FlextLdifModelsSettings.LogContextExtras | None = None,
    ) -> FlextLdifModelsEvents.DnEvent:
        """Create DnEvent, log with context, and attach to logger context."""
        event = FlextLdifUtilitiesEvents.create_dn_event(config)
        aggregate_id = event.aggregate_id or ""
        log_context: t.MutableScalarMapping = {
            "aggregate_id": aggregate_id,
            "dn_operation": config.dn_operation,
            "input_dn": config.input_dn,
            "operation_duration_ms": config.operation_duration_ms,
            "has_output": event.has_output,
            "component_count": event.component_count,
        }
        if config.output_dn is not None:
            log_context["output_dn"] = config.output_dn
        log_message = f"DN operation '{config.dn_operation}' completed"
        FlextLdifUtilitiesEvents._log_and_emit_generic_event(
            logger=logger,
            log_context=log_context,
            log_message=log_message,
            log_level=log_level,
            extras=extras,
        )
        return event


__all__ = ["FlextLdifUtilitiesEvents"]
