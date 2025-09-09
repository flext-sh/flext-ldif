"""FLEXT-LDIF CLI - Enterprise CLI with flext-cli Integration.

Professional CLI implementation using flext-cli exclusively for all CLI functionality
and output, following unified class architecture and SOLID principles.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import sys
import warnings
from pathlib import Path
from typing import TYPE_CHECKING

from flext_cli import (
    FlextCliApi,
    FlextCliConfig,
    FlextCliMain,
)
from flext_core import (
    FlextContainer,
    FlextLogger,
    FlextResult,
)

from flext_ldif.api import FlextLDIFAPI
from flext_ldif.models import FlextLDIFModels
from flext_ldif.services import FlextLDIFServices

# Suppress Pydantic V2 warnings for clean CLI output
warnings.filterwarnings("ignore", category=UserWarning, module="pydantic._internal._config")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="pydantic._internal._config")

# Type aliases for Python 3.13+ generic syntax
if TYPE_CHECKING:
    type FlextResultEntries = FlextResult[list[FlextLDIFModels.Entry]]
    type FlextResultStr = FlextResult[str]
    type FlextResultBool = FlextResult[bool]
else:
    FlextResultEntries = FlextResult
    FlextResultStr = FlextResult
    FlextResultBool = FlextResult


class FlextLDIFCli:
    """Unified CLI class for FLEXT-LDIF operations.

    Enterprise-grade CLI implementation using flext-cli exclusively for all
    CLI functionality and data output. Follows unified class architecture
    with nested operations for organized functionality.
    """

    def __init__(self) -> None:
        """Initialize CLI with flext-cli integration and dependency injection."""
        self._logger = FlextLogger(__name__)
        self._container = FlextContainer.get_global()
        self._cli_api = FlextCliApi()
        self._config = FlextCliConfig()

        # Register LDIF API service
        self._ldif_api = FlextLDIFAPI()
        self._container.register("ldif_api", self._ldif_api)

    class Operations:
        """Nested operations class for organized CLI functionality."""

        def __init__(self, cli_instance: FlextLDIFCli) -> None:
            """Initialize operations with reference to parent CLI instance."""
            self._cli = cli_instance
            self._logger = cli_instance._logger
            self._ldif_api = cli_instance._ldif_api
            self._cli_api = cli_instance._cli_api

        def parse_ldif(
            self,
            input_file: Path,
            output_file: Path | None = None,
            *,
            validate: bool = True
        ) -> FlextResult[None]:
            """Parse LDIF file and optionally write output.

            Args:
                input_file: Path to input LDIF file
                output_file: Optional output file path
                validate: Whether to validate entries after parsing

            Returns:
                FlextResult indicating operation success

            """
            # Validate input file exists
            if not input_file.exists():
                error_msg = f"Input file not found: {input_file}"
                return self._display_error(error_msg)

            # Parse LDIF file using API
            parse_result = self._ldif_api.parse_file(input_file)
            if parse_result.is_failure:
                return self._display_error(f"Parse failed: {parse_result.error}")

            entries = parse_result.unwrap()

            # Display parsing results using flext-cli
            success_msg = f"Successfully parsed {len(entries)} entries"
            display_result = self._cli_api.display_success(success_msg)
            if display_result.is_failure:
                return FlextResult[None].fail(f"Display error: {display_result.error}")

            # Optional validation
            if validate:
                validation_result = self._validate_entries(entries)
                if validation_result.is_failure:
                    return validation_result

            # Optional output file writing
            if output_file:
                write_result = self._write_entries_to_file(entries, output_file)
                if write_result.is_failure:
                    return write_result

            return FlextResult[None].ok(None)

        def validate_ldif(self, input_file: Path) -> FlextResult[None]:
            """Validate LDIF file entries.

            Args:
                input_file: Path to LDIF file to validate

            Returns:
                FlextResult indicating validation success

            """
            # Parse file first
            parse_result = self._ldif_api.parse_file(input_file)
            if parse_result.is_failure:
                return self._display_error(f"Parse failed: {parse_result.error}")

            entries = parse_result.unwrap()
            return self._validate_entries(entries)

        def analyze_ldif(self, input_file: Path) -> FlextResult[None]:
            """Analyze LDIF file and display statistics.

            Args:
                input_file: Path to LDIF file to analyze

            Returns:
                FlextResult indicating analysis success

            """
            # Parse file first
            parse_result = self._ldif_api.parse_file(input_file)
            if parse_result.is_failure:
                return self._display_error(f"Parse failed: {parse_result.error}")

            entries = parse_result.unwrap()

            # Create analytics service
            analytics = FlextLDIFServices.Analytics(entries=entries)

            # Analyze patterns
            analysis_result = analytics.analyze_patterns(entries)
            if analysis_result.is_failure:
                return self._display_error(f"Analysis failed: {analysis_result.error}")

            # Display results as table using flext-cli
            stats = analysis_result.unwrap()
            table_data = [[key, str(value)] for key, value in stats.items()]

            table_result = self._cli_api.create_table(
                headers=["Metric", "Count"],
                rows=table_data,
                title="LDIF Analysis Results"
            )

            if table_result.is_failure:
                return self._display_error(f"Table creation failed: {table_result.error}")

            display_result = self._cli_api.display_output(table_result.unwrap())
            if display_result.is_failure:
                return self._display_error(f"Display failed: {display_result.error}")

            return FlextResult[None].ok(None)

        def _validate_entries(self, entries: list[FlextLDIFModels.Entry]) -> FlextResult[None]:
            """Validate entries and display results using flext-cli.

            Args:
                entries: List of entries to validate

            Returns:
                FlextResult indicating validation success

            """
            # Create validator service
            validator = FlextLDIFServices.Validator(entries=entries)

            # Validate entries
            validation_result = validator.validate_entries(entries)
            if validation_result.is_failure:
                return self._display_error(f"Validation failed: {validation_result.error}")

            # Display success message
            success_msg = f"All {len(entries)} entries validated successfully"
            display_result = self._cli_api.display_success(success_msg)
            if display_result.is_failure:
                return FlextResult[None].fail(f"Display error: {display_result.error}")

            return FlextResult[None].ok(None)

        def _write_entries_to_file(
            self,
            entries: list[FlextLDIFModels.Entry],
            output_file: Path
        ) -> FlextResult[None]:
            """Write entries to output file.

            Args:
                entries: List of entries to write
                output_file: Output file path

            Returns:
                FlextResult indicating write success

            """
            # Create writer service
            writer = FlextLDIFServices.Writer(entries=entries)

            # Write to file
            write_result = writer.write_entries_to_file(entries, str(output_file))
            if write_result.is_failure:
                return self._display_error(f"Write failed: {write_result.error}")

            # Display success message
            success_msg = f"Successfully wrote {len(entries)} entries to {output_file}"
            display_result = self._cli_api.display_success(success_msg)
            if display_result.is_failure:
                return FlextResult[None].fail(f"Display error: {display_result.error}")

            return FlextResult[None].ok(None)

        def _display_error(self, message: str) -> FlextResult[None]:
            """Display error message using flext-cli and return failure result.

            Args:
                message: Error message to display

            Returns:
                FlextResult failure with the error message

            """
            display_result = self._cli_api.display_error(message)
            if display_result.is_failure:
                # Fallback to stderr if flext-cli display fails
                pass

            return FlextResult[None].fail(message)

    def create_cli_interface(self) -> FlextResult[FlextCliMain]:
        """Create main CLI interface using flext-cli patterns.

        Returns:
            FlextResult containing configured CLI main interface

        """
        # Create main CLI instance
        main_cli = FlextCliMain(
            name="flext-ldif",
            description="Enterprise LDIF Processing CLI",
            version="0.9.0"
        )

        # Create operations handler
        operations = self.Operations(self)

        # Register parse command
        parse_command_result = self._create_parse_command(operations)
        if parse_command_result.is_failure:
            return FlextResult[FlextCliMain].fail(f"Parse command creation failed: {parse_command_result.error}")

        # Register validate command
        validate_command_result = self._create_validate_command(operations)
        if validate_command_result.is_failure:
            return FlextResult[FlextCliMain].fail(f"Validate command creation failed: {validate_command_result.error}")

        # Register analyze command
        analyze_command_result = self._create_analyze_command(operations)
        if analyze_command_result.is_failure:
            return FlextResult[FlextCliMain].fail(f"Analyze command creation failed: {analyze_command_result.error}")

        return FlextResult[FlextCliMain].ok(main_cli)

    def _create_parse_command(self, operations: Operations) -> FlextResult[None]:
        """Create parse command using flext-cli command builder.

        Args:
            operations: Operations instance to handle command execution

        Returns:
            FlextResult indicating command creation success

        """
        command_result = self._cli_api.create_command(
            name="parse",
            description="Parse LDIF file and optionally write output",
            handler=lambda args: operations.parse_ldif(
                input_file=Path(args.get("input", "")),
                output_file=Path(args.get("output")) if args.get("output") else None,
                validate=args.get("validate", True)
            ),
            arguments=[
                {"name": "input", "required": True, "help": "Input LDIF file path"},
                {"name": "output", "required": False, "help": "Output file path"},
                {"name": "validate", "type": bool, "default": True, "help": "Validate entries"}
            ]
        )

        if command_result.is_failure:
            return FlextResult[None].fail(f"Parse command creation failed: {command_result.error}")

        return FlextResult[None].ok(None)

    def _create_validate_command(self, operations: Operations) -> FlextResult[None]:
        """Create validate command using flext-cli command builder.

        Args:
            operations: Operations instance to handle command execution

        Returns:
            FlextResult indicating command creation success

        """
        command_result = self._cli_api.create_command(
            name="validate",
            description="Validate LDIF file entries",
            handler=lambda args: operations.validate_ldif(
                input_file=Path(args.get("input", ""))
            ),
            arguments=[
                {"name": "input", "required": True, "help": "Input LDIF file path"}
            ]
        )

        if command_result.is_failure:
            return FlextResult[None].fail(f"Validate command creation failed: {command_result.error}")

        return FlextResult[None].ok(None)

    def _create_analyze_command(self, operations: Operations) -> FlextResult[None]:
        """Create analyze command using flext-cli command builder.

        Args:
            operations: Operations instance to handle command execution

        Returns:
            FlextResult indicating command creation success

        """
        command_result = self._cli_api.create_command(
            name="analyze",
            description="Analyze LDIF file and display statistics",
            handler=lambda args: operations.analyze_ldif(
                input_file=Path(args.get("input", ""))
            ),
            arguments=[
                {"name": "input", "required": True, "help": "Input LDIF file path"}
            ]
        )

        if command_result.is_failure:
            return FlextResult[None].fail(f"Analyze command creation failed: {command_result.error}")

        return FlextResult[None].ok(None)

    def run(self, args: list[str] | None = None) -> int:
        """Run the CLI with provided arguments or sys.argv.

        Args:
            args: Optional command line arguments (uses sys.argv if None)

        Returns:
            Exit code (0 for success, 1 for failure)

        """
        try:
            # Create CLI interface
            cli_result = self.create_cli_interface()
            if cli_result.is_failure:
                return 1

            cli = cli_result.unwrap()

            # Run CLI with args
            run_result = cli.run(args or sys.argv[1:])
            if run_result.is_failure:
                return 1

            return 0

        except KeyboardInterrupt:
            return 1
        except Exception:
            return 1


def main() -> int:
    """Main entry point for the CLI application.

    Returns:
        Exit code (0 for success, 1 for failure)

    """
    cli = FlextLDIFCli()
    return cli.run()


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["FlextLDIFCli", "main"]
