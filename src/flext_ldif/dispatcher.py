"""Dispatcher integration for flext-ldif operations."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from flext_core import FlextBus, FlextDispatcher, FlextDispatcherRegistry, FlextResult
from flext_ldif.models import FlextLdifModels
from flext_ldif.parser_service import FlextLdifParserService
from flext_ldif.validator_service import FlextLdifValidatorService
from flext_ldif.writer_service import FlextLdifWriterService


class FlextLdifDispatcher:
    """Unified LDIF dispatcher following FLEXT patterns.

    Single responsibility: All LDIF dispatcher operations and command definitions.
    Contains nested classes for commands and protocols.
    """

    class ServiceContainer(Protocol):
        """Protocol describing the services required by dispatcher handlers."""

        parser: FlextLdifParserService
        validator: FlextLdifValidatorService
        writer: FlextLdifWriterService

    @dataclass(slots=True)
    class ParseStringCommand:
        """Command representing LDIF string parsing."""

        content: str

    @dataclass(slots=True)
    class ParseFileCommand:
        """Command representing LDIF file parsing."""

        file_path: str

    @dataclass(slots=True)
    class WriteStringCommand:
        """Command representing writing entries to string."""

        entries: list[FlextLdifModels.Entry]

    @dataclass(slots=True)
    class WriteFileCommand:
        """Command representing writing entries to file."""

        entries: list[FlextLdifModels.Entry]
        file_path: Path

    @dataclass(slots=True)
    class ValidateEntriesCommand:
        """Command representing entry validation."""

        entries: list[FlextLdifModels.Entry]

    @staticmethod
    def build_dispatcher(
        services: FlextLdifDispatcher.ServiceContainer,
        *,
        bus: FlextBus | None = None,
    ) -> FlextDispatcher:
        """Create dispatcher wired to ldif service functions."""
        dispatcher = FlextDispatcher(bus=bus)
        registry = FlextDispatcherRegistry(dispatcher)

        def _parse_string(
            command: FlextLdifDispatcher.ParseStringCommand,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            return services.parser.parse_content(command.content)

        def _parse_file(
            command: FlextLdifDispatcher.ParseFileCommand,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            return services.parser.parse_ldif_file(command.file_path)

        def _write_string(
            command: FlextLdifDispatcher.WriteStringCommand,
        ) -> FlextResult[str]:
            return services.writer.write_entries_to_string(command.entries)

        def _write_file(
            command: FlextLdifDispatcher.WriteFileCommand,
        ) -> FlextResult[bool]:
            return services.writer.write_entries_to_file(
                command.entries,
                str(command.file_path),
            )

        def _validate_entries(
            command: FlextLdifDispatcher.ValidateEntriesCommand,
        ) -> FlextResult[bool]:
            validation_result = services.validator.validate_entries(command.entries)
            if validation_result.is_failure:
                return FlextResult[bool].fail(
                    validation_result.error or "Validation failed"
                )
            return FlextResult[bool].ok(data=True)

        # Note: Complex generics in FlextDispatcherRegistry require careful handling
        # Using the working pattern from client-a-oud-mig for consistency

        # Build handler mapping for registration
        # This pattern avoids complex generic type issues while maintaining functionality
        handler_mapping = {
            FlextLdifDispatcher.ParseStringCommand: (_parse_string, None),
            FlextLdifDispatcher.ParseFileCommand: (_parse_file, None),
            FlextLdifDispatcher.WriteStringCommand: (_write_string, None),
            FlextLdifDispatcher.WriteFileCommand: (_write_file, None),
            FlextLdifDispatcher.ValidateEntriesCommand: (_validate_entries, None),
        }

        # Register using the same pattern as other FLEXT projects
        registration = registry.register_function_map(handler_mapping)
        if registration.is_failure:
            raise RuntimeError(registration.error or "Failed to register LDIF handlers")

        return dispatcher


__all__ = [
    "FlextLdifDispatcher",
]
