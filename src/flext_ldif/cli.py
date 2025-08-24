"""FLEXT-LDIF Command Line Interface.

Enterprise LDIF processing CLI built with flext-cli patterns and flext-core foundation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from flext_cli import (
    cli_handle_keyboard_interrupt,
    cli_measure_time,
    flext_cli_output_data,
    get_cli_config,
    setup_cli,
)
from flext_core import FlextResult, get_logger
from rich.console import Console

from .api import FlextLdifAPI
from .models import FlextLdifConfig, FlextLdifEntry
from .utilities import FlextLdifUtilities

# Logger for CLI module
logger = get_logger(__name__)


class FlextLdifCliService:
    """LDIF CLI service using flext-cli and flext-core patterns."""

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize CLI service."""
        self.api = FlextLdifAPI(config or FlextLdifConfig())
        self.console = Console()

    def parse_and_process(
        self,
        input_file: Path,
        *,
        validate: bool = False,
        max_entries: int | None = None,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF file with optional validation."""
        # Update config if max_entries specified
        if max_entries:
            config = FlextLdifConfig(max_entries=max_entries)
            api = FlextLdifAPI(config)
        else:
            api = self.api

        parse_result = (
            api.parse_file(str(input_file))
            .tap(
                lambda entries: logger.info(
                    f"Parsed {len(entries)} entries from {input_file}"
                )
            )
            .tap_error(
                lambda error: logger.error(f"Failed to parse {input_file}: {error}")
            )
        )

        # If validation requested, validate entries after parsing
        if validate and parse_result.is_success:
            validation_result = self.validate_entries(parse_result.value)
            if not validation_result.is_success:
                logger.error(f"Validation failed: {validation_result.error}")
                return FlextResult[list[FlextLdifEntry]].fail(
                    f"Validation failed: {validation_result.error}"
                )
            _, errors = validation_result.value
            if errors:
                error_summary = f"{len(errors)} validation errors found"
                logger.error(error_summary)
                return FlextResult[list[FlextLdifEntry]].fail(error_summary)

        return parse_result

    def validate_entries(
        self, entries: list[FlextLdifEntry]
    ) -> FlextResult[tuple[list[FlextLdifEntry], list[str]]]:
        """Validate entries and return valid entries with error list."""
        valid_entries: list[FlextLdifEntry] = []
        errors: list[str] = []

        for i, entry in enumerate(entries, 1):
            validation_result = entry.validate_business_rules()
            if validation_result.is_success:
                valid_entries.append(entry)
            else:
                error_msg = FlextLdifUtilities.format_entry_error_message(
                    entry, i, validation_result.error or "Validation failed"
                )
                errors.append(error_msg)

        return FlextResult[tuple[list[FlextLdifEntry], list[str]]].ok((
            valid_entries,
            errors,
        ))

    def transform_entries(
        self,
        entries: list[FlextLdifEntry],
        filter_type: str | None = None,
        *,
        sort_hierarchically: bool = False,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Transform entries with filtering and sorting."""
        result_entries = entries

        # Apply filter if specified
        if filter_type:
            filter_result = FlextLdifUtilities.railway_filter_entries(
                self.api, result_entries, filter_type
            )
            result_entries = filter_result

        # Apply sorting if requested
        if sort_hierarchically:
            sort_result = self.api.sort_hierarchically(result_entries)
            return sort_result.tap(
                lambda sorted_entries: logger.info(
                    f"Sorted {len(sorted_entries)} entries hierarchically"
                )
            )

        return FlextResult[list[FlextLdifEntry]].ok(result_entries)

    def write_entries(
        self, entries: list[FlextLdifEntry], output_path: Path
    ) -> FlextResult[bool]:
        """Write entries to output file."""
        return self.api.write_file(entries, str(output_path)).tap(
            lambda _: logger.info(f"Written {len(entries)} entries to {output_path}")
        )

    def get_statistics(
        self, entries: list[FlextLdifEntry]
    ) -> FlextResult[dict[str, int]]:
        """Get comprehensive statistics for entries."""
        return self.api.get_entry_statistics(entries)


# Global CLI service
cli_service = FlextLdifCliService()


def handle_result_or_exit[T](
    result: FlextResult[T], success_msg: str | None = None
) -> T:
    """Handle FlextResult with CLI-appropriate error reporting."""
    if result.is_success:
        if success_msg:
            click.echo(success_msg)
        return result.value

    click.echo(f"Error: {result.error}", err=True)
    sys.exit(1)


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    invoke_without_command=True,
)
@click.version_option()
@click.option("--debug/--no-debug", default=False, help="Enable debug mode")
@click.option("--quiet/--no-quiet", "-q", default=False, help="Suppress output")
@click.option(
    "--output-format",
    "-f",
    type=click.Choice(["table", "json", "yaml", "plain"]),
    default="table",
    help="Output format",
)
@click.pass_context
def cli(
    ctx: click.Context,
    *,
    debug: bool,
    quiet: bool,
    output_format: str,
) -> None:
    """FLEXT LDIF - Enterprise LDIF Processing CLI."""
    # Setup flext-cli
    setup_result = setup_cli()
    if setup_result.is_failure:
        click.echo(f"CLI setup failed: {setup_result.error}", err=True)
        sys.exit(1)

    # Configure CLI context
    config = get_cli_config()
    if debug or quiet:
        config = config.model_copy(
            update={"debug": debug, "quiet": quiet, "output_format": output_format}
        )

    ctx.ensure_object(dict)
    ctx.obj["config"] = config
    ctx.obj["console"] = Console(quiet=quiet)
    ctx.obj["cli_service"] = cli_service

    if debug:
        logger.info(
            "FLEXT LDIF CLI initialized", debug=debug, output_format=output_format
        )

    # Show help if no command
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command()
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), help="Output file")
@click.option("--max-entries", type=int, help="Maximum entries to parse")
@click.option("--validate", is_flag=True, help="Validate entries after parsing")
@click.option("--stats", is_flag=True, help="Show statistics")
@cli_measure_time
@cli_handle_keyboard_interrupt
@click.pass_context
def parse(
    ctx: click.Context,
    input_file: Path,
    output: Path | None,
    max_entries: int | None,
    *,
    validate: bool,
    stats: bool,
) -> None:
    """Parse LDIF file with optional validation and statistics."""
    service: FlextLdifCliService = ctx.obj["cli_service"]
    config = ctx.obj["config"]
    console: Console = ctx.obj["console"]

    # Parse file
    parse_result = service.parse_and_process(
        input_file, validate=validate, max_entries=max_entries
    )
    entries = handle_result_or_exit(parse_result, f"Successfully parsed {input_file}")

    console.print(f"✅ Parsed {len(entries)} entries")

    # Validate if requested
    if validate:
        validation_result = service.validate_entries(entries)
        _, errors = handle_result_or_exit(validation_result)

        if errors:
            console.print(f"❌ Found {len(errors)} validation errors:")
            max_errors_to_show = 5
            for error in errors[:max_errors_to_show]:
                console.print(f"  • {error}")
            if len(errors) > max_errors_to_show:
                console.print(
                    f"  ... and {len(errors) - max_errors_to_show} more errors"
                )
            if not output:  # Exit if validation fails and no output requested
                sys.exit(1)
        else:
            console.print(f"✅ All {len(entries)} entries are valid")

    # Show statistics if requested
    if stats:
        stats_result = service.get_statistics(entries)
        statistics = handle_result_or_exit(stats_result)

        # Use flext-cli output formatting
        output_result = flext_cli_output_data(
            statistics, config.output_format, console=console
        )
        handle_result_or_exit(output_result)

    # Write output if requested
    if output:
        write_result = service.write_entries(entries, output)
        handle_result_or_exit(write_result, f"Entries written to {output}")


@cli.command()
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@cli_measure_time
@cli_handle_keyboard_interrupt
@click.pass_context
def validate(ctx: click.Context, input_file: Path) -> None:
    """Validate LDIF entries for business rule compliance."""
    service: FlextLdifCliService = ctx.obj["cli_service"]
    console: Console = ctx.obj["console"]

    # Parse and validate
    parse_result = service.parse_and_process(input_file)
    entries = handle_result_or_exit(parse_result)

    validation_result = service.validate_entries(entries)
    _, errors = handle_result_or_exit(validation_result)

    if errors:
        console.print(f"❌ Validation failed: {len(errors)} errors found")
        for error in errors:
            console.print(f"  • {error}")
        sys.exit(1)
    else:
        console.print(f"✅ All {len(entries)} entries are valid")


@cli.command()
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@click.argument("output_file", type=click.Path(path_type=Path))
@click.option(
    "--filter",
    "filter_type",
    type=click.Choice(["persons", "groups", "ous", "valid"]),
    help="Filter entries by type",
)
@click.option("--sort", is_flag=True, help="Sort entries hierarchically")
@cli_measure_time
@cli_handle_keyboard_interrupt
@click.pass_context
def transform(
    ctx: click.Context,
    input_file: Path,
    output_file: Path,
    filter_type: str | None,
    *,
    sort: bool,
) -> None:
    """Transform LDIF file with filtering and sorting."""
    service: FlextLdifCliService = ctx.obj["cli_service"]
    console: Console = ctx.obj["console"]

    # Parse file
    parse_result = service.parse_and_process(input_file)
    entries = handle_result_or_exit(parse_result)

    console.print(f"📄 Loaded {len(entries)} entries from {input_file}")

    # Transform entries
    transform_result = service.transform_entries(
        entries, filter_type, sort_hierarchically=sort
    )
    transformed_entries = handle_result_or_exit(transform_result)

    operations: list[str] = []
    if filter_type:
        operations.append(f"filtered to {filter_type}")
    if sort:
        operations.append("sorted hierarchically")

    if operations:
        console.print(f"🔄 Transformed entries: {', '.join(operations)}")
        console.print(f"📊 Result: {len(transformed_entries)} entries")

    # Write transformed entries
    write_result = service.write_entries(transformed_entries, output_file)
    handle_result_or_exit(write_result, f"Transformed entries saved to {output_file}")


@cli.command()
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@click.pass_context
@cli_handle_keyboard_interrupt
def stats(ctx: click.Context, input_file: Path) -> None:
    """Display comprehensive statistics for LDIF file."""
    service: FlextLdifCliService = ctx.obj["cli_service"]
    config = ctx.obj["config"]
    console: Console = ctx.obj["console"]

    # Parse and analyze
    parse_result = service.parse_and_process(input_file)
    entries = handle_result_or_exit(parse_result)

    stats_result = service.get_statistics(entries)
    statistics = handle_result_or_exit(stats_result)

    console.print(f"📊 Statistics for {input_file}:")

    # Use flext-cli formatting
    output_result = flext_cli_output_data(
        statistics, config.output_format, console=console
    )
    handle_result_or_exit(output_result)


def main() -> None:
    """Main entry point."""
    try:
        logger.info("Starting FLEXT LDIF CLI")
        cli()
    except KeyboardInterrupt:
        click.echo("\\nOperation cancelled by user", err=True)
        logger.info("CLI cancelled by user")
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        logger.exception("CLI failed with unexpected error")
        sys.exit(1)


if __name__ == "__main__":
    main()
