"""Event Utilities - Domain Event Creation and Management Helpers."""

from __future__ import annotations

from flext_ldif import FlextLdifModels as m, c, p, t


class FlextLdifUtilitiesEvents:
    """Event creation, storage, and statistics helpers for domain events."""

    @staticmethod
    def _build_conversion_event_logging(
        event: p.Ldif.ConversionEvent,
        settings: p.Ldif.ConversionEventConfig,
    ) -> tuple[t.MutableJsonMapping, str]:
        return (
            {
                "aggregate_id": event.aggregate_id,
                "conversion_operation": settings.conversion_operation,
                "source_format": settings.source_format,
                "target_format": settings.target_format,
                "items_processed": settings.items_processed,
                "items_converted": settings.items_converted,
                "items_failed": settings.items_failed,
                "conversion_duration_ms": settings.conversion_duration_ms,
                "success_rate_pct": event.conversion_success_rate,
                "throughput_items_per_sec": event.throughput_items_per_sec,
            },
            f"Conversion '{settings.conversion_operation}' from {settings.source_format} to {settings.target_format} completed",
        )

    @staticmethod
    def _log_and_emit_generic_event(
        logger: p.Logger,
        log_context: t.MutableJsonMapping,
        log_message: str,
        log_level: str = c.Ldif.LogLevelLower.INFO.value,
        extras: p.Ldif.LogContextExtras | None = None,
    ) -> None:
        """Log an event with context and extras."""
        filtered_extras = FlextLdifUtilitiesEvents._process_extras(extras)
        merged_context = dict(log_context)
        merged_context.update(filtered_extras)
        if log_level == c.Ldif.LogLevelLower.DEBUG.value:
            logger.debug(log_message, return_result=False, **merged_context)
        elif log_level == c.Ldif.LogLevelLower.WARNING.value:
            logger.warning(log_message, return_result=False, **merged_context)
        elif log_level == c.Ldif.LogLevelLower.ERROR.value:
            logger.error(log_message, return_result=False, **merged_context)
        else:
            logger.info(log_message, return_result=False, **merged_context)

    @staticmethod
    def _process_extras(
        extras: p.Ldif.LogContextExtras | None = None,
    ) -> t.MutableJsonMapping:
        """Extract and filter extras into a dict of loggable context."""
        filtered_extras: t.MutableJsonMapping = {}
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
        error_details: t.JsonValueList | tuple[t.JsonValue, ...] | None,
    ) -> t.MutableSequenceOf[str]:
        if error_details is None:
            return []
        return [str(detail) for detail in error_details]

    @staticmethod
    def create_conversion_event(
        settings: p.Ldif.ConversionEventConfig,
    ) -> p.Ldif.ConversionEvent:
        """Create ConversionEvent with standardized fields from settings Model."""
        aggregate_id = f"{settings.source_format}_to_{settings.target_format}_{settings.conversion_operation}"
        error_details_list = FlextLdifUtilitiesEvents._to_error_details_list(
            list(settings.error_details)
            if settings.error_details is not None
            else None,
        )
        event: p.Ldif.ConversionEvent = m.Ldif.ConversionEvent.model_validate({
            "event_type": "ldif.conversion",
            "aggregate_id": aggregate_id,
            "conversion_operation": settings.conversion_operation,
            "source_format": settings.source_format,
            "target_format": settings.target_format,
            "items_converted": settings.items_converted,
            "items_failed": settings.items_failed,
            "conversion_duration_ms": settings.conversion_duration_ms,
            "error_details": error_details_list,
        })
        return event

    @staticmethod
    def create_dn_event(
        settings: p.Ldif.DnEventConfig,
    ) -> p.Ldif.DnEvent:
        """Create DnEvent with standardized fields from settings Model."""
        event: p.Ldif.DnEvent = m.Ldif.DnEvent.model_validate({
            "event_type": "ldif.dn",
            "aggregate_id": settings.input_dn,
            "dn_operation": settings.dn_operation,
            "input_dn": settings.input_dn,
            "output_dn": settings.output_dn,
            "dn_duration_ms": settings.operation_duration_ms,
            "validation_result": settings.validation_result,
        })
        return event

    @staticmethod
    def log_and_emit_conversion_event(
        logger: p.Logger,
        settings: p.Ldif.ConversionEventConfig,
        log_level: str = "info",
        extras: p.Ldif.LogContextExtras | None = None,
    ) -> p.Ldif.ConversionEvent:
        """Create ConversionEvent, log with context, and attach to logger context."""
        event = FlextLdifUtilitiesEvents.create_conversion_event(settings)
        log_context, log_message = (
            FlextLdifUtilitiesEvents._build_conversion_event_logging(event, settings)
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
        settings: p.Ldif.DnEventConfig,
        log_level: str = "info",
        extras: p.Ldif.LogContextExtras | None = None,
    ) -> p.Ldif.DnEvent:
        """Create DnEvent, log with context, and attach to logger context."""
        event = FlextLdifUtilitiesEvents.create_dn_event(settings)
        aggregate_id = event.aggregate_id or ""
        log_context: t.MutableJsonMapping = {
            "aggregate_id": aggregate_id,
            "dn_operation": settings.dn_operation,
            "input_dn": settings.input_dn,
            "operation_duration_ms": settings.operation_duration_ms,
            "has_output": event.has_output,
            "component_count": event.component_count,
        }
        if settings.output_dn is not None:
            log_context["output_dn"] = settings.output_dn
        log_message = f"DN operation '{settings.dn_operation}' completed"
        FlextLdifUtilitiesEvents._log_and_emit_generic_event(
            logger=logger,
            log_context=log_context,
            log_message=log_message,
            log_level=log_level,
            extras=extras,
        )
        return event


__all__: list[str] = ["FlextLdifUtilitiesEvents"]
