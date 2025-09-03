"""FLEXT-LDIF Command Line Interface using flext-cli patterns.

Enterprise LDIF processing CLI built with flext-cli foundation instead of click/rich.
Follows single-class-per-module and enterprise patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TypeVar

# Use flext-cli instead of click/rich directly - MANDATORY per standards
sys.path.insert(0, "/home/marlonsc/flext/flext-cli/src")

from flext_cli import (
    FlextCliFormatters,
    FlextCliService,
)
from flext_core import FlextLogger, FlextResult

from flext_ldif.api import FlextLDIFAPI
from flext_ldif.models import FlextLDIFModels

T = TypeVar("T")

# Constants for CLI command parsing
MIN_ARGS_WITH_COMMAND = 2
MIN_ARGS_WITH_INPUT_FILE = 3
MAX_ERRORS_TO_SHOW = 10

# Use consolidated class directly - NO aliases
FlextLDIFConfig = FlextLDIFModels.Config
FlextLDIFEntry = FlextLDIFModels.Entry

logger = FlextLogger(__name__)


class FlextLDIFCli(FlextCliService):
    """FLEXT-LDIF CLI using flext-cli patterns - NO click/rich direct usage.

    Enterprise-grade CLI implementation using flext-cli foundation:
    - FlextCliService base class for service architecture
    - FlextCliFormatters for output formatting instead of rich
    - FlextCliContext for execution context instead of click context
    - FlextCliCmd for command handling instead of click commands

    Eliminates direct dependency on click/rich following FLEXT standards.
    """

    def __init__(self, config: FlextLDIFConfig | None = None) -> None:
        """Initialize CLI service with configuration and dependencies."""
        super().__init__()
        self.config = config or FlextLDIFConfig()
        self.api = FlextLDIFAPI(config=self.config)
        self.formatter = FlextCliFormatters()

    def execute(self) -> FlextResult[str]:  # type: ignore[override]
        """Abstract method implementation required by FlextCliService."""
        # This is implemented by individual command functions
        return FlextResult[str].ok("CLI ready")

    def parse_and_process(
        self,
        input_file: Path,
        *,
        output_file: Path | None = None,
        validate: bool = False,
        max_entries: int | None = None,
    ) -> FlextResult[list[FlextLDIFEntry]]:
        """Parse LDIF file using flext-cli patterns instead of click."""
        try:
            # Update config if max_entries specified
            if max_entries:
                self.config.max_entries = max_entries

            # Parse using API
            parse_result = self.api.parse_file(input_file)

            if not parse_result.is_success:
                error_msg = f"Parse failed: {parse_result.error}"
                self.formatter.print_error(error_msg)
                return FlextResult[list[FlextLDIFEntry]].fail(error_msg)

            entries = parse_result.value
            self.formatter.print_success(f"✅ Parsed {len(entries)} entries")

            # Validate if requested
            if validate and entries:
                validation_result = self.validate_entries(entries)
                if not validation_result.is_success:
                    error_msg = f"Validation failed: {validation_result.error}"
                    self.formatter.print_error(error_msg)
                    return FlextResult[list[FlextLDIFEntry]].fail(error_msg)

                _valid_entries, errors = validation_result.value
                if errors:
                    error_summary = f"{len(errors)} validation errors found"
                    self.formatter.print_error(error_summary)
                    return FlextResult[list[FlextLDIFEntry]].fail(error_summary)

            # Use output_file if provided
            if output_file:
                write_result = self.write_entries(entries, output_file)
                if not write_result.is_success:
                    return FlextResult[list[FlextLDIFEntry]].fail(
                        f"Write failed: {write_result.error}"
                    )

            return parse_result

        except Exception as e:
            error_msg = f"CLI processing error: {e}"
            logger.exception(error_msg)
            self.formatter.print_error(error_msg)
            return FlextResult[list[FlextLDIFEntry]].fail(error_msg)

    def validate_entries(
        self, entries: list[FlextLDIFEntry]
    ) -> FlextResult[tuple[list[FlextLDIFEntry], list[str]]]:
        """Validate entries using modern batch processing patterns."""
        try:
            # Use modern FlextUtilities.ResultUtils for batch validation processing
            validation_results = [
                (i, entry, entry.validate_business_rules())
                for i, entry in enumerate(entries, 1)
            ]

            valid_entries: list[FlextLDIFEntry] = []
            errors: list[str] = []

            for i, entry, validation_result in validation_results:
                if validation_result.is_success:
                    valid_entries.append(entry)
                else:
                    error_msg = (
                        f"Entry {i}: {validation_result.error or 'Validation failed'}"
                    )
                    errors.append(error_msg)

            return FlextResult[tuple[list[FlextLDIFEntry], list[str]]].ok(
                (
                    valid_entries,
                    errors,
                )
            )

        except Exception as e:
            error_msg = f"Validation processing error: {e}"
            logger.exception(error_msg)
            return FlextResult[tuple[list[FlextLDIFEntry], list[str]]].fail(error_msg)

    def transform_entries(
        self, entries: list[FlextLDIFEntry], transformations: dict[str, str]
    ) -> FlextResult[list[FlextLDIFEntry]]:
        """Transform entries using flext-cli patterns."""
        try:
            # Apply transformations through API
            result_entries = entries.copy()

            # Simple filtering logic - can be enhanced later
            if "objectclass" in transformations:
                result_entries = [
                    entry
                    for entry in result_entries
                    if entry.has_attribute("objectClass")
                ]

            self.formatter.print_success(
                f"✅ Transformed {len(result_entries)} entries"
            )
            return FlextResult[list[FlextLDIFEntry]].ok(result_entries)

        except Exception as e:
            error_msg = f"Transform error: {e}"
            logger.exception(error_msg)
            self.formatter.print_error(error_msg)
            return FlextResult[list[FlextLDIFEntry]].fail(error_msg)

    def write_entries(
        self, entries: list[FlextLDIFEntry], output_file: Path
    ) -> FlextResult[bool]:
        """Write entries using API."""
        try:
            write_result = self.api.write_file(entries, output_file)

            if write_result.is_success:
                self.formatter.print_success(f"✅ Written to {output_file}")
            else:
                self.formatter.print_error(f"❌ Write failed: {write_result.error}")

            return write_result

        except Exception as e:
            error_msg = f"Write error: {e}"
            logger.exception(error_msg)
            self.formatter.print_error(error_msg)
            return FlextResult[bool].fail(error_msg)

    def get_statistics(
        self, entries: list[FlextLDIFEntry]
    ) -> FlextResult[dict[str, int]]:
        """Get statistics using API."""
        try:
            return self.api.get_entry_statistics(entries)
        except Exception as e:
            error_msg = f"Statistics error: {e}"
            logger.exception(error_msg)
            return FlextResult[dict[str, int]].fail(error_msg)

    def handle_result_or_exit(
        self, result: FlextResult[T], success_msg: str | None = None
    ) -> T:
        """Handle result or exit with error using flext-cli formatters."""
        if result.is_success:
            if success_msg:
                self.formatter.print_success(success_msg)
            return result.value
        self.formatter.print_error(f"❌ Operation failed: {result.error}")
        sys.exit(1)

    # =========================================================================
    # CLI ENTRY POINTS - Moved from loose functions for FLEXT pattern compliance
    # =========================================================================

    @staticmethod
    def create_cli() -> FlextLDIFCli:
        """Factory function to create CLI service."""
        return FlextLDIFCli()

    @staticmethod
    def parse_command(
        input_file: str,
        *,
        output: str | None = None,
        validate: bool = False,
        stats: bool = False,
    ) -> None:
        """Parse command using flext-cli patterns instead of click."""
        service = FlextLDIFCli.create_cli()

        try:
            input_path = Path(input_file)
            if not input_path.exists():
                service.formatter.print_error(f"❌ Input file not found: {input_file}")
                sys.exit(1)

            # Parse entries
            parse_result = service.parse_and_process(
                input_path,
                output_file=Path(output) if output else None,
                validate=validate
            )
            entries = service.handle_result_or_exit(parse_result)

            # Validate if requested
            if validate:
                validation_result = service.validate_entries(entries)
                _, errors = service.handle_result_or_exit(validation_result)

                if errors:
                    service.formatter.print_error(
                        f"❌ Found {len(errors)} validation errors:"
                    )
                    for error in errors[:MAX_ERRORS_TO_SHOW]:
                        service.formatter.print_error(f"  {error}")
                    if len(errors) > MAX_ERRORS_TO_SHOW:
                        service.formatter.print_error(
                            f"  ... and {len(errors) - MAX_ERRORS_TO_SHOW} more errors"
                        )
                    sys.exit(1)
                else:
                    service.formatter.print_success("✅ All entries are valid")

            # Show statistics if requested
            if stats:
                stats_result = service.get_statistics(entries)
                statistics = service.handle_result_or_exit(stats_result)

                # Use flext-cli formatter for table output instead of rich
                # Convert statistics to string format for display
                stats_output = "LDIF Statistics:\n"
                for key, value in statistics.items():
                    stats_output += f"  {key}: {value}\n"
                service.formatter.print_success(stats_output)

        except Exception as e:
            service.formatter.print_error(f"❌ Unexpected error: {e}")
            sys.exit(1)

    @staticmethod
    def validate_command(input_file: str) -> None:
        """Validate command using flext-cli patterns."""
        service = FlextLDIFCli.create_cli()

        try:
            input_path = Path(input_file)
            if not input_path.exists():
                service.formatter.print_error(f"❌ Input file not found: {input_file}")
                sys.exit(1)

            # Parse and validate
            parse_result = service.parse_and_process(input_path, validate=True)
            entries = service.handle_result_or_exit(parse_result)

            validation_result = service.validate_entries(entries)
            _, errors = service.handle_result_or_exit(validation_result)

            if errors:
                service.formatter.print_error(
                    f"❌ Validation failed: {len(errors)} errors found"
                )
                for error in errors:
                    service.formatter.print_error(f"  {error}")
                sys.exit(1)
            else:
                service.formatter.print_success("✅ All entries are valid")

        except Exception as e:
            service.formatter.print_error(f"❌ Unexpected error: {e}")
            sys.exit(1)

    @staticmethod
    def transform_command(
        input_file: str, output_file: str, transformations: str | None = None
    ) -> None:
        """Transform command using flext-cli patterns."""
        service = FlextLDIFCli.create_cli()

        try:
            input_path = Path(input_file)
            output_path = Path(output_file)

            if not input_path.exists():
                service.formatter.print_error(f"❌ Input file not found: {input_file}")
                sys.exit(1)

            # Parse entries
            parse_result = service.parse_and_process(input_path)
            entries = service.handle_result_or_exit(parse_result)

            # Apply transformations
            transform_dict = {}
            if transformations:
                # Parse transformations string - simple implementation
                for transform in transformations.split(","):
                    if "=" in transform:
                        key, value = transform.split("=", 1)
                        transform_dict[key.strip()] = value.strip()

            transform_result = service.transform_entries(entries, transform_dict)
            transformed_entries = service.handle_result_or_exit(transform_result)

            # Write output
            write_result = service.write_entries(transformed_entries, output_path)
            service.handle_result_or_exit(
                write_result, f"✅ Transformed and written to {output_file}"
            )

        except Exception as e:
            service.formatter.print_error(f"❌ Unexpected error: {e}")
            sys.exit(1)

    @staticmethod
    def stats_command(input_file: str) -> None:
        """Statistics command using flext-cli patterns."""
        service = FlextLDIFCli.create_cli()

        try:
            input_path = Path(input_file)
            if not input_path.exists():
                service.formatter.print_error(f"❌ Input file not found: {input_file}")
                sys.exit(1)

            # Parse entries
            parse_result = service.parse_and_process(input_path)
            entries = service.handle_result_or_exit(parse_result)

            # Get and display statistics
            stats_result = service.get_statistics(entries)
            statistics = service.handle_result_or_exit(stats_result)

            # Use flext-cli formatter for structured output
            stats_output = "LDIF Statistics:\n"
            for key, value in statistics.items():
                stats_output += f"  {key}: {value}\n"
            service.formatter.print_success(stats_output)

        except Exception as e:
            service.formatter.print_error(f"❌ Unexpected error: {e}")
            sys.exit(1)

    # Simple main entry point - flext-cli handles complex command parsing
    @staticmethod
    def main() -> None:
        """Main CLI entry point using flext-cli patterns."""
        if len(sys.argv) < MIN_ARGS_WITH_COMMAND:
            sys.exit(1)

        command = sys.argv[1]

        if command == "parse":
            if len(sys.argv) < MIN_ARGS_WITH_INPUT_FILE:
                sys.exit(1)
            FlextLDIFCli.parse_command(
                sys.argv[2],
                validate="--validate" in sys.argv,
                stats="--stats" in sys.argv
            )
        elif command == "validate":
            if len(sys.argv) < MIN_ARGS_WITH_INPUT_FILE:
                sys.exit(1)
            FlextLDIFCli.validate_command(sys.argv[2])
        elif command == "stats":
            if len(sys.argv) < MIN_ARGS_WITH_INPUT_FILE:
                sys.exit(1)
            FlextLDIFCli.stats_command(sys.argv[2])
        else:
            sys.exit(1)


def main() -> None:
    """Main CLI entry point."""
    FlextLDIFCli.main()


if __name__ == "__main__":
    main()
