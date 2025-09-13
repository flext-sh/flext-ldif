"""FLEXT LDIF CLI service - Unified CLI interface for LDIF operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import sys
from pathlib import Path

from flext_core import FlextContainer, FlextDomainService, FlextLogger, FlextResult

from flext_ldif.api import FlextLDIFAPI


class FlextLDIFCli(FlextDomainService[int]):
    """Unified LDIF CLI service using flext-cli directly with nested helpers.

    Single responsibility class for all LDIF CLI operations.
    Uses flext-cli directly, no wrappers or print statements.
    Follows CLAUDE.md unified class architecture with nested operations.
    """

    def __init__(self) -> None:
        """Initialize unified CLI service with dependency injection."""
        super().__init__()
        self._container = FlextContainer.get_global()
        self._logger = FlextLogger(__name__)

        # Initialize CLI components using flext-core only
        self._cli_config: dict[str, object] = {}
        self._cli_main = None

        # Initialize service dependencies
        self._api_service = FlextLDIFAPI()

        # Initialize nested CLI helpers
        self._operations = self._CliOperations(self)
        self._handlers = self._CliHandlers(self)

    def execute(self) -> FlextResult[int]:
        """Execute the main domain service operation.

        Returns exit code 0 for success, 1 for failure.
        """
        try:
            # Default execution - show usage
            return self._handlers.show_usage()
        except Exception as e:
            self._logger.exception("Execute operation failed")
            return FlextResult[int].fail(f"Execute operation failed: {e}")

    @property
    def operations(self) -> FlextLDIFCli._CliOperations:
        """Get CLI operations helper."""
        return self._operations

    @property
    def handlers(self) -> FlextLDIFCli._CliHandlers:
        """Get CLI handlers helper."""
        return self._handlers

    class _CliOperations:
        """Nested helper for CLI operations."""

        def __init__(self, cli_instance: FlextLDIFCli) -> None:
            """Initialize with parent CLI instance."""
            self._cli = cli_instance
            self._logger = cli_instance._logger
            self._api_service = cli_instance._api_service

        def parse_file(
            self,
            input_file: Path,
            output_file: Path | None = None,
            *,
            should_validate: bool = True,
        ) -> FlextResult[None]:
            """Parse LDIF file and optionally write output."""
            try:
                # Use API service to parse
                result = self._api_service._operations.parse_file(input_file)
                if result.is_failure:
                    self._logger.error(f"Parse failed: {result.error}")
                    return FlextResult[None].fail(f"Parse failed: {result.error}")

                entries = result.unwrap()

                # Validate if requested
                if should_validate:
                    validation_result = self._api_service._operations.validate_entries(
                        entries
                    )
                    if validation_result.is_failure:
                        self._logger.warning(
                            f"Validation issues: {validation_result.error}"
                        )

                # Write output if requested
                if output_file is not None:
                    write_result = self._api_service._operations.write_file(
                        entries, output_file
                    )
                    if write_result.is_failure:
                        return FlextResult[None].fail(
                            f"Write failed: {write_result.error}"
                        )

                self._logger.info(f"Successfully parsed {len(entries)} entries")
                return FlextResult[None].ok(None)

            except Exception:
                self._logger.exception("Parse operation failed")
                return FlextResult[None].fail("Parse operation failed")

        def validate_file(self, input_file: Path) -> FlextResult[None]:
            """Validate LDIF file."""
            try:
                # Use API service to validate
                entries_result = self._api_service._operations.parse_file(input_file)
                if entries_result.is_failure:
                    return FlextResult[None].fail(
                        f"Parse failed: {entries_result.error}"
                    )
                entries = entries_result.unwrap()
                result = self._api_service._operations.validate_entries(entries)
                if result.is_failure:
                    self._logger.error(f"Validation failed: {result.error}")
                    return FlextResult[None].fail(f"Validation failed: {result.error}")

                self._logger.info("File validation successful")
                return FlextResult[None].ok(None)

            except Exception:
                self._logger.exception("Validation operation failed")
                return FlextResult[None].fail("Validation operation failed")

        def analyze_file(self, input_file: Path) -> FlextResult[None]:
            """Analyze LDIF file."""
            try:
                # Use API service to analyze
                entries_result = self._api_service._operations.parse_file(input_file)
                if entries_result.is_failure:
                    return FlextResult[None].fail(
                        f"Parse failed: {entries_result.error}"
                    )
                entries = entries_result.unwrap()
                result = self._api_service._analytics.entry_statistics(entries)
                if result.is_failure:
                    self._logger.error(f"Analysis failed: {result.error}")
                    return FlextResult[None].fail(f"Analysis failed: {result.error}")

                stats = result.unwrap()
                self._logger.info(f"Analysis complete: {stats}")
                return FlextResult[None].ok(None)

            except Exception:
                self._logger.exception("Analysis operation failed")
                return FlextResult[None].fail("Analysis operation failed")

    class _CliHandlers:
        """Nested helper for CLI command handlers."""

        MINIMUM_ARGS_REQUIRED = 2
        PARSE_COMMAND_MIN_ARGS = 2
        VALIDATE_COMMAND_MIN_ARGS = 2
        ANALYZE_COMMAND_MIN_ARGS = 2

        def __init__(self, cli_instance: FlextLDIFCli) -> None:
            """Initialize with parent CLI instance."""
            self._cli = cli_instance
            self._logger = cli_instance._logger
            self._operations = cli_instance._operations

        def handle_parse_command(self, args: list[str]) -> FlextResult[int]:
            """Handle parse command."""
            if len(args) < self.PARSE_COMMAND_MIN_ARGS:
                return FlextResult[int].fail(
                    "Usage: flext-ldif parse <input_file> [output_file]"
                )

            input_file = Path(args[1])
            output_file = (
                Path(args[2]) if len(args) > self.PARSE_COMMAND_MIN_ARGS else None
            )

            result = self._operations.parse_file(input_file, output_file)
            return FlextResult[int].ok(0 if result.is_success else 1)

        def handle_validate_command(self, args: list[str]) -> FlextResult[int]:
            """Handle validate command."""
            if len(args) < self.VALIDATE_COMMAND_MIN_ARGS:
                return FlextResult[int].fail("Usage: flext-ldif validate <input_file>")

            input_file = Path(args[1])
            result = self._operations.validate_file(input_file)
            return FlextResult[int].ok(0 if result.is_success else 1)

        def handle_analyze_command(self, args: list[str]) -> FlextResult[int]:
            """Handle analyze command."""
            if len(args) < self.ANALYZE_COMMAND_MIN_ARGS:
                return FlextResult[int].fail("Usage: flext-ldif analyze <input_file>")

            input_file = Path(args[1])
            result = self._operations.analyze_file(input_file)
            return FlextResult[int].ok(0 if result.is_success else 1)

        def show_usage(self) -> FlextResult[int]:
            """Show usage information."""
            self._logger.info("Usage: flext-ldif <command> [args...]")
            self._logger.info("Commands: parse, validate, analyze")
            return FlextResult[int].ok(1)

    def create_cli_interface(self) -> FlextResult[object]:
        """Create CLI interface using flext-core only."""
        try:
            # Configure main CLI
            main_cli = self._cli_main

            # CLI interface is simplified - commands handled by run_simple_cli
            # No need to add individual commands since we use simple dispatch

            return FlextResult[object].ok(main_cli)

        except Exception as e:
            return FlextResult[object].fail(f"CLI interface creation failed: {e}")

    def run_simple_cli(self, args: list[str]) -> FlextResult[int]:
        """Run simple CLI without full flext-cli setup."""
        try:
            if not args:
                return self._handlers.show_usage()

            command = args[0]

            if command == "parse":
                return self._handlers.handle_parse_command(args)
            if command == "validate":
                return self._handlers.handle_validate_command(args)
            if command == "analyze":
                return self._handlers.handle_analyze_command(args)
            self._logger.error(f"Unknown command: {command}")
            return self._handlers.show_usage()

        except Exception:
            self._logger.exception("CLI execution failed")
            return FlextResult[int].fail("CLI execution failed")

    def run(self, args: list[str] | None = None) -> int:
        """Main CLI entry point."""
        try:
            if args is None:
                args = []

            # Use simple CLI for now since flext-cli integration needs work
            result = self.run_simple_cli(args)

            if result.is_failure:
                self._logger.error(result.error or "Unknown error")
                return 1

            return result.unwrap()

        except Exception:
            self._logger.exception("Unexpected CLI error")
            return 1


def main() -> int:
    """Main CLI function."""
    cli = FlextLDIFCli()
    return cli.run(sys.argv[1:])


# Export unified CLI service
__all__ = ["FlextLDIFCli", "main"]
