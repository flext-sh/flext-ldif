"""Dispatcher integration for flext-ldif operations."""

from __future__ import annotations

from typing import cast

from flext_core import FlextResult
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols


class FlextLdifDispatcher:
    """Unified LDIF dispatcher following FLEXT patterns.

    Single responsibility: All LDIF dispatcher operations and command definitions.
    Contains nested classes for commands and protocols.
    """

    class SimpleDispatcher:
        """Simple dispatcher implementation using available flext-core functionality."""

        def __init__(
            self, services: FlextLdifProtocols.ServiceContainerProtocol,
        ) -> None:
            """Initialize dispatcher with services.

            Args:
                services: Container with parser, validator, and writer services.

            """
            self._services = services

        def dispatch(self, command: object) -> FlextResult[object]:
            """Dispatch command to appropriate handler.

            Args:
                command: Command to dispatch.

            Returns:
                FlextResult containing handler output or error.

            """
            if isinstance(command, FlextLdifModels.ParseStringCommand):
                return self._handle_parse_string(command)
            if isinstance(command, FlextLdifModels.ParseFileCommand):
                return self._handle_parse_file(command)
            if isinstance(command, FlextLdifModels.WriteStringCommand):
                return self._handle_write_string(command)
            if isinstance(command, FlextLdifModels.WriteFileCommand):
                return self._handle_write_file(command)
            if isinstance(command, FlextLdifModels.ValidateEntriesCommand):
                return self._handle_validate_entries(command)
            return FlextResult[object].fail(f"Unknown command type: {type(command)}")

        def _handle_parse_string(
            self, command: FlextLdifModels.ParseStringCommand,
        ) -> FlextResult[object]:
            """Handle parse string command.

            Args:
                command: Command containing LDIF content to parse.

            Returns:
                FlextResult containing parsed entries or error.

            """
            result = self._services.parser.parse_content(command.content)
            if result.is_failure:
                return FlextResult[object].fail(result.error or "Parse failed")
            return FlextResult[object].ok(
                {"entries": result.value, "type": "parse_string"},
            )

        def _handle_parse_file(
            self, command: FlextLdifModels.ParseFileCommand,
        ) -> FlextResult[object]:
            """Handle parse file command.

            Args:
                command: Command containing file path to parse.

            Returns:
                FlextResult containing parsed entries or error.

            """
            result = self._services.parser.parse_ldif_file(command.file_path)
            if result.is_failure:
                return FlextResult[object].fail(result.error or "Parse failed")
            return FlextResult[object].ok(
                {"entries": result.value, "type": "parse_file"},
            )

        def _handle_write_string(
            self, command: FlextLdifModels.WriteStringCommand,
        ) -> FlextResult[object]:
            """Handle write string command.

            Args:
                command: Command containing entries to write.

            Returns:
                FlextResult containing LDIF string content or error.

            """
            result = self._services.writer.write_entries_to_string(
                cast("list[object]", command.entries),
            )
            if result.is_failure:
                return FlextResult[object].fail(result.error or "Write failed")
            return FlextResult[object].ok(
                {"content": result.value, "type": "write_string"},
            )

        def _handle_write_file(
            self, command: FlextLdifModels.WriteFileCommand,
        ) -> FlextResult[object]:
            """Handle write file command.

            Args:
                command: Command containing entries and file path to write.

            Returns:
                FlextResult containing write success status or error.

            """
            result = self._services.writer.write_entries_to_file(
                cast("list[object]", command.entries),
                command.file_path,
            )
            if result.is_failure:
                return FlextResult[object].fail(result.error or "Write failed")
            return FlextResult[object].ok(
                {"success": result.value, "type": "write_file"},
            )

        def _handle_validate_entries(
            self, command: FlextLdifModels.ValidateEntriesCommand,
        ) -> FlextResult[object]:
            """Handle validate entries command.

            Args:
                command: Command containing entries to validate.

            Returns:
                FlextResult containing validation status or error.

            """
            validation_result = self._services.validator.validate_entries(
                cast("list[object]", command.entries),
            )
            if validation_result.is_failure:
                return FlextResult[object].fail(
                    validation_result.error or "Validation failed",
                )
            return FlextResult[object].ok({"valid": True, "type": "validate_entries"})

    @staticmethod
    def build_dispatcher(
        services: FlextLdifProtocols.ServiceContainerProtocol,
    ) -> SimpleDispatcher:
        """Create dispatcher wired to LDIF service functions.

        Args:
            services: Container with parser, validator, and writer services.

        Returns:
            Configured dispatcher ready for LDIF operations.

        """
        return FlextLdifDispatcher.SimpleDispatcher(services)


__all__ = [
    "FlextLdifDispatcher",
]
