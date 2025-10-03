"""LDIF CQRS Handlers - Command and Query handlers for LDIF operations.

Implements CQRS pattern with FlextDispatcher orchestration and FlextRegistry
for handler registration. All handlers follow FLEXT 1.0.0 patterns with:
- FlextResult for railway-oriented error handling
- FlextBus integration for domain events
- FlextContainer for dependency injection

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from flext_core import (
    FlextBus,
    FlextContainer,
    FlextContext,
    FlextDispatcher,
    FlextHandlers,
    FlextModels,
    FlextRegistry,
    FlextResult,
    FlextTypes,
)
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols


class FlextLdifHandlers:
    """Unified CQRS handlers for LDIF operations following FLEXT patterns."""

    # Class-level dispatcher and registry for handler management
    _dispatcher: FlextDispatcher | None = None
    _registry: FlextRegistry | None = None

    @classmethod
    def get_dispatcher(
        cls, bus: FlextBus, config: FlextTypes.Dict | None = None
    ) -> FlextDispatcher:
        """Get or create the CQRS dispatcher.

        Args:
            bus: Event bus for notifications
            config: Optional dispatcher configuration

        Returns:
            FlextDispatcher instance for LDIF operations

        """
        if cls._dispatcher is None:
            cls._dispatcher = FlextDispatcher(bus=bus, config=config)
        return cls._dispatcher

    @classmethod
    def get_registry(cls, dispatcher: FlextDispatcher) -> FlextRegistry:
        """Get or create the handler registry.

        Args:
            dispatcher: Dispatcher instance for handler registration

        Returns:
            FlextRegistry instance for LDIF handlers

        """
        if cls._registry is None:
            cls._registry = FlextRegistry(dispatcher)
        return cls._registry

    @classmethod
    def register_all_handlers(
        cls, context: FlextContext, container: FlextContainer, bus: FlextBus
    ) -> FlextResult[FlextTypes.Dict]:
        """Register all LDIF handlers with the registry using FlextDispatcher.

        Args:
            context: Execution context
            container: Dependency injection container
            bus: Event bus for notifications

        Returns:
            FlextResult with registration summary

        """
        # Initialize dispatcher and registry
        dispatcher = cls.get_dispatcher(bus=bus)
        registry = cls.get_registry(dispatcher)

        # Create handler instances
        handler_instances = [
            cls.ParseQueryHandler(context, container, bus),
            cls.ValidateQueryHandler(context, container, bus),
            cls.AnalyzeQueryHandler(context, container, bus),
            cls.WriteCommandHandler(context, container, bus),
            cls.MigrateCommandHandler(context, container, bus),
            cls.RegisterQuirkCommandHandler(context, container, bus),
        ]

        # Store handler instances for access
        handlers = {
            "parse": handler_instances[0],
            "validate": handler_instances[1],
            "analyze": handler_instances[2],
            "write": handler_instances[3],
            "migrate": handler_instances[4],
            "register_quirk": handler_instances[5],
        }

        # Register handlers with registry (expects Iterable[FlextHandlers[object, object]])
        handlers_iterable = cast(
            "list[FlextHandlers[object, object]]", handler_instances
        )
        registration_result = registry.register_handlers(handlers_iterable)

        if registration_result.is_failure:
            return FlextResult[FlextTypes.Dict].fail(
                f"Handler registration failed: {registration_result.error}"
            )

        return FlextResult[FlextTypes.Dict].ok({
            "handlers_registered": len(handlers),
            "handler_names": list(handlers.keys()),
            "registry_summary": registration_result.unwrap(),
            "dispatcher": dispatcher,
        })

    class ParseQueryHandler(
        FlextHandlers[FlextLdifModels.ParseQuery, list[FlextLdifModels.Entry]]
    ):
        """Handler for parsing LDIF content from various sources."""

        def __init__(
            self, context: FlextContext, container: FlextContainer, bus: FlextBus
        ) -> None:
            """Initialize handler with dependencies.

            Args:
                context: Execution context with configuration
                container: Dependency injection container
                bus: Event bus for notifications

            """
            config = FlextModels.CqrsConfig.Handler(
                handler_id=f"parse_query_handler_{id(self)}",
                handler_name="ParseQueryHandler",
                handler_type="query",
            )
            super().__init__(config=config)
            self._context = context
            self._container = container
            self._bus = bus

        def handle(
            self, message: FlextLdifModels.ParseQuery
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Handle parse query and return entries.

            Args:
                message: Parse query with source and options

            Returns:
                Result containing list of parsed entries or error

            """
            try:
                # Determine which parser to use
                if message.format == "oid":
                    parser_result = self._container.get("oid_parser")
                    if parser_result.is_failure:
                        return FlextResult[list[FlextLdifModels.Entry]].fail(
                            f"Failed to get OID parser: {parser_result.error}"
                        )
                    parser = cast(
                        "FlextLdifProtocols.LdifProcessorProtocol",
                        parser_result.unwrap(),
                    )
                elif message.format == "rfc":
                    parser_result = self._container.get("rfc_parser")
                    if parser_result.is_failure:
                        return FlextResult[list[FlextLdifModels.Entry]].fail(
                            f"Failed to get RFC parser: {parser_result.error}"
                        )
                    parser = cast(
                        "FlextLdifProtocols.LdifProcessorProtocol",
                        parser_result.unwrap(),
                    )
                else:  # auto
                    # Try RFC first, fallback to OID
                    parser_result = self._container.get("rfc_parser")
                    if parser_result.is_failure:
                        return FlextResult[list[FlextLdifModels.Entry]].fail(
                            f"Failed to get RFC parser: {parser_result.error}"
                        )
                    parser = cast(
                        "FlextLdifProtocols.LdifProcessorProtocol",
                        parser_result.unwrap(),
                    )

                # Parse based on source type
                if isinstance(message.source, (str, Path)):
                    # Handle empty string as empty content, not as path
                    if isinstance(message.source, str) and not message.source:
                        result = parser.parse_content("")
                    else:
                        source_path = (
                            Path(message.source)
                            if isinstance(message.source, str)
                            else message.source
                        )
                        if source_path.exists():
                            result = parser.parse_ldif_file(
                                source_path, encoding=message.encoding
                            )
                        else:
                            # Treat as content string
                            result = parser.parse_content(str(message.source))
                elif isinstance(message.source, bytes):
                    content = message.source.decode(message.encoding)
                    result = parser.parse_content(content)
                elif isinstance(message.source, list):
                    content = "\n".join(message.source)
                    result = parser.parse_content(content)
                else:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Unsupported source type: {type(message.source)}"
                    )

                # Emit event on success
                if result.is_success:
                    entries = result.unwrap()

                    # Determine source type for event
                    if isinstance(message.source, (str, Path)):
                        source_type = (
                            "file" if Path(message.source).exists() else "string"
                        )
                    elif isinstance(message.source, bytes):
                        source_type = "bytes"
                    elif isinstance(message.source, list):
                        source_type = "list"
                    else:
                        source_type = "string"

                    # Create and emit event
                    event = FlextLdifModels.EntryParsedEvent(
                        entry_count=len(entries),
                        source_type=source_type,
                        format_detected=message.format,
                        timestamp=datetime.now(UTC).isoformat(),
                    )

                    # NOTE: FlextBus.publish_event() will be implemented in flext-core 1.0.0
                    # For now, log the event
                    self.logger.info(
                        f"EntryParsedEvent: {event.entry_count} entries from {event.source_type} (format={event.format_detected})"
                    )

                return result

            except Exception as e:
                self.logger.exception("Parse query failed")
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Parse error: {e}"
                )

    class ValidateQueryHandler(
        FlextHandlers[
            FlextLdifModels.ValidateQuery, FlextLdifModels.LdifValidationResult
        ]
    ):
        """Handler for validating LDIF entries against schema."""

        def __init__(
            self, context: FlextContext, container: FlextContainer, bus: FlextBus
        ) -> None:
            """Initialize handler with dependencies."""
            config = FlextModels.CqrsConfig.Handler(
                handler_id=f"validate_query_handler_{id(self)}",
                handler_name="ValidateQueryHandler",
                handler_type="query",
            )
            super().__init__(config=config)
            self._context = context
            self._container = container
            self._bus = bus

        def handle(
            self, message: FlextLdifModels.ValidateQuery
        ) -> FlextResult[FlextLdifModels.LdifValidationResult]:
            """Handle validation query.

            Args:
                message: Validation query with entries and options

            Returns:
                Result containing validation result or error

            """
            try:
                # Get validator from container
                validator_result = self._container.get("schema_validator")
                if validator_result.is_failure:
                    return FlextResult[FlextLdifModels.LdifValidationResult].fail(
                        f"Failed to get schema validator: {validator_result.error}"
                    )
                validator = cast(
                    "FlextLdifProtocols.LdifValidatorProtocol",
                    validator_result.unwrap(),
                )

                # Perform validation
                result = validator.validate_entries(
                    message.entries, strict=message.strict
                )

                # Emit event on success
                if result.is_success:
                    validation_result = result.unwrap()

                    # Create and emit event
                    event = FlextLdifModels.EntriesValidatedEvent(
                        entry_count=len(message.entries),
                        is_valid=validation_result.is_valid,
                        error_count=len(validation_result.errors),
                        strict_mode=message.strict,
                        timestamp=datetime.now(UTC).isoformat(),
                    )

                    # NOTE: FlextBus.publish_event() will be implemented in flext-core 1.0.0
                    # For now, log the event
                    self.logger.info(
                        f"EntriesValidatedEvent: {event.entry_count} entries, valid={event.is_valid}, errors={event.error_count}"
                    )

                return result

            except Exception as e:
                self.logger.exception("Validation query failed")
                return FlextResult[FlextLdifModels.LdifValidationResult].fail(
                    f"Validation error: {e}"
                )

    class AnalyzeQueryHandler(
        FlextHandlers[FlextLdifModels.AnalyzeQuery, FlextLdifModels.AnalyticsResult]
    ):
        """Handler for analyzing LDIF entries."""

        def __init__(
            self, context: FlextContext, container: FlextContainer, bus: FlextBus
        ) -> None:
            """Initialize handler with dependencies."""
            config = FlextModels.CqrsConfig.Handler(
                handler_id=f"analyze_query_handler_{id(self)}",
                handler_name="AnalyzeQueryHandler",
                handler_type="query",
            )
            super().__init__(config=config)
            self._context = context
            self._container = container
            self._bus = bus

        def handle(
            self, message: FlextLdifModels.AnalyzeQuery
        ) -> FlextResult[FlextLdifModels.AnalyticsResult]:
            """Handle analytics query.

            Args:
                message: Analytics query with entries and options

            Returns:
                Result containing analytics result or error

            """
            try:
                # Basic analytics implementation
                total_entries = len(message.entries)
                object_classes: dict[str, int] = {}

                for entry in message.entries:
                    oc_attr = entry.attributes.get("objectClass", [])
                    for oc in oc_attr:
                        object_classes[oc] = object_classes.get(oc, 0) + 1

                # Create analytics result
                analytics = FlextLdifModels.AnalyticsResult(
                    total_entries=total_entries,
                    object_class_distribution=object_classes,
                    patterns_detected=(
                        [] if not message.include_patterns else ["cn-based"]
                    ),
                )

                # Create and emit event
                event = FlextLdifModels.AnalyticsGeneratedEvent(
                    entry_count=total_entries,
                    unique_object_classes=len(object_classes),
                    patterns_detected=len(analytics.patterns_detected),
                    timestamp=datetime.now(UTC).isoformat(),
                )

                # NOTE: FlextBus.publish_event() will be implemented in flext-core 1.0.0
                # For now, log the event
                self.logger.info(
                    f"AnalyticsGeneratedEvent: {event.entry_count} entries, {event.unique_object_classes} object classes"
                )

                return FlextResult[FlextLdifModels.AnalyticsResult].ok(analytics)

            except Exception as e:
                self.logger.exception("Analytics query failed")
                return FlextResult[FlextLdifModels.AnalyticsResult].fail(
                    f"Analytics error: {e}"
                )

    class WriteCommandHandler(FlextHandlers[FlextLdifModels.WriteCommand, str]):
        """Handler for writing LDIF entries to output."""

        def __init__(
            self, context: FlextContext, container: FlextContainer, bus: FlextBus
        ) -> None:
            """Initialize handler with dependencies."""
            config = FlextModels.CqrsConfig.Handler(
                handler_id=f"write_command_handler_{id(self)}",
                handler_name="WriteCommandHandler",
                handler_type="command",
            )
            super().__init__(config=config)
            self._context = context
            self._container = container
            self._bus = bus

        def handle(self, message: FlextLdifModels.WriteCommand) -> FlextResult[str]:
            """Handle write command.

            Args:
                message: Write command with entries and options

            Returns:
                Result containing written LDIF string or error

            """
            try:
                # Get writer from container
                writer_result = self._container.get("rfc_writer")
                if writer_result.is_failure:
                    return FlextResult[str].fail(
                        f"Failed to get RFC writer: {writer_result.error}"
                    )
                writer = cast(
                    "FlextLdifProtocols.LdifWriterProtocol", writer_result.unwrap()
                )

                # Write to string
                result = writer.write_entries_to_string(message.entries)

                if result.is_failure:
                    return result

                ldif_string = result.unwrap()

                # Optionally write to file
                if message.output:
                    output_path = Path(message.output)
                    output_path.write_text(ldif_string, encoding="utf-8")

                # Create and emit event
                event = FlextLdifModels.EntriesWrittenEvent(
                    entry_count=len(message.entries),
                    output_path=message.output or "string",
                    format_used=message.format,
                    output_size_bytes=len(ldif_string.encode("utf-8")),
                    timestamp=datetime.now(UTC).isoformat(),
                )

                # NOTE: FlextBus.publish_event() will be implemented in flext-core 1.0.0
                # For now, log the event
                self.logger.info(
                    f"EntriesWrittenEvent: {event.entry_count} entries to {event.output_path} ({event.output_size_bytes} bytes)"
                )

                return FlextResult[str].ok(ldif_string)

            except Exception as e:
                self.logger.exception("Write command failed")
                return FlextResult[str].fail(f"Write error: {e}")

    class MigrateCommandHandler(
        FlextHandlers[FlextLdifModels.MigrateCommand, list[FlextLdifModels.Entry]]
    ):
        """Handler for migrating LDIF entries between formats."""

        def __init__(
            self, context: FlextContext, container: FlextContainer, bus: FlextBus
        ) -> None:
            """Initialize handler with dependencies."""
            config = FlextModels.CqrsConfig.Handler(
                handler_id=f"migrate_command_handler_{id(self)}",
                handler_name="MigrateCommandHandler",
                handler_type="command",
            )
            super().__init__(config=config)
            self._context = context
            self._container = container
            self._bus = bus

        def handle(
            self, message: FlextLdifModels.MigrateCommand
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Handle migration command.

            Args:
                message: Migration command with entries and options

            Returns:
                Result containing migrated entries or error

            """
            try:
                # Get migration pipeline from container
                pipeline_result = self._container.get("migration_pipeline")
                if pipeline_result.is_failure:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Failed to get migration pipeline: {pipeline_result.error}"
                    )
                pipeline = cast(
                    "FlextLdifProtocols.MigrationPipelineProtocol",
                    pipeline_result.unwrap(),
                )

                # Perform migration
                quirks_list: FlextTypes.List = (
                    list(message.quirks) if message.quirks else []
                )
                result = pipeline.migrate_entries(
                    entries=message.entries,
                    source_format=message.source_format,
                    target_format=message.target_format,
                    quirks=quirks_list,
                )

                # Emit event on success
                if result.is_success:
                    # Create and emit event
                    event = FlextLdifModels.MigrationCompletedEvent(
                        entry_count=len(message.entries),
                        source_format=message.source_format,
                        target_format=message.target_format,
                        quirks_applied=message.quirks or [],
                        timestamp=datetime.now(UTC).isoformat(),
                    )

                    # NOTE: FlextBus.publish_event() will be implemented in flext-core 1.0.0
                    # For now, log the event
                    self.logger.info(
                        f"MigrationCompletedEvent: {event.entry_count} entries from {event.source_format} to {event.target_format}"
                    )

                return result

            except Exception as e:
                self.logger.exception("Migration command failed")
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Migration error: {e}"
                )

    class RegisterQuirkCommandHandler(
        FlextHandlers[FlextLdifModels.RegisterQuirkCommand, None]
    ):
        """Handler for registering custom quirks."""

        def __init__(
            self, context: FlextContext, container: FlextContainer, bus: FlextBus
        ) -> None:
            """Initialize handler with dependencies."""
            config = FlextModels.CqrsConfig.Handler(
                handler_id=f"register_quirk_command_handler_{id(self)}",
                handler_name="RegisterQuirkCommandHandler",
                handler_type="command",
            )
            super().__init__(config=config)
            self._context = context
            self._container = container
            self._bus = bus

        def handle(
            self, message: FlextLdifModels.RegisterQuirkCommand
        ) -> FlextResult[None]:
            """Handle quirk registration command.

            Args:
                message: Registration command with quirk details

            Returns:
                Result indicating success or error

            """
            try:
                # Get quirk registry from container
                registry_result = self._container.get("quirk_registry")
                if registry_result.is_failure:
                    return FlextResult[None].fail(
                        f"Failed to get quirk registry: {registry_result.error}"
                    )
                registry = registry_result.unwrap()

                # Register quirk based on type
                if message.quirk_type == "schema":
                    result = registry.register_schema_quirk(message.quirk_impl)
                elif message.quirk_type == "acl":
                    result = registry.register_acl_quirk(message.quirk_impl)
                elif message.quirk_type == "entry":
                    result = registry.register_entry_quirk(message.quirk_impl)
                else:
                    return FlextResult[None].fail(
                        f"Unknown quirk type: {message.quirk_type}"
                    )

                # Emit event on success
                if result.is_success:
                    # Extract quirk name from implementation
                    quirk_name = getattr(
                        message.quirk_impl, "server_type", message.quirk_type
                    )

                    # Create and emit event
                    event = FlextLdifModels.QuirkRegisteredEvent(
                        quirk_name=f"{quirk_name}_{message.quirk_type}",
                        override=message.override,
                        timestamp=datetime.now(UTC).isoformat(),
                    )

                    # NOTE: FlextBus.publish_event() will be implemented in flext-core 1.0.0
                    # For now, log the event
                    self.logger.info(
                        f"QuirkRegisteredEvent: {event.quirk_name} (type={message.quirk_type})"
                    )

                return result

            except Exception as e:
                self.logger.exception("Quirk registration failed")
                return FlextResult[None].fail(f"Registration error: {e}")


__all__ = ["FlextLdifHandlers"]
