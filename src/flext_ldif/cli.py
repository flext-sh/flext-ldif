"""FLEXT-LDIF Command Line Interface.

This module implements the command-line interface for FLEXT-LDIF operations,
providing enterprise-grade CLI functionality built on flext-cli foundation
patterns with comprehensive LDIF processing, validation, and transformation capabilities.

The CLI provides a user-friendly interface for common LDIF operations while
maintaining enterprise-grade error handling, configuration management, and
integration with the broader FLEXT ecosystem.

Commands Available:
    - parse: Parse LDIF files with validation and format conversion
    - validate: Validate LDIF files against business rules and standards
    - transform: Transform LDIF data with filtering and modification options
    - info: Display information about LDIF files and entries

Architecture:
    Part of Interface Layer in Clean Architecture, this module provides
    user interface access to application services without containing
    business logic, delegating all operations to the FlextLdifAPI.

Integration:
    - Built on flext-cli foundation for consistent CLI patterns
    - Uses FlextLdifAPI for all LDIF processing operations
    - Integrates with flext-core logging and error handling
    - Supports enterprise configuration and environment variables

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from flext_core import FlextResult

    from .models import FlextLdifEntry

import click
import yaml

# Use real flext-cli integration
from flext_cli import CLIConfig as FlextCliConfig, setup_cli as flext_setup_cli
from flext_core import get_logger

from .api import FlextLdifAPI
from .config import FlextLdifConfig


# Simple utilities to replace deleted cli_utils
def safe_click_echo(message: str, *, err: bool = False) -> None:
    """Safe echo for click commands."""
    click.echo(message, err=err)


def handle_parse_result(result: FlextResult[list[FlextLdifEntry]]) -> None:
    """Handle parse result output."""
    if result.success and result.data is not None:
        click.echo(f"✅ Parsed {len(result.data)} entries successfully")
    else:
        click.echo(f"❌ Parse failed: {result.error or 'Unknown error'}")


# Logger for CLI module
logger = get_logger(__name__)

# Constants
MAX_DISPLAYED_ERRORS = 5


def create_api_with_config(*, max_entries: int | None = None) -> FlextLdifAPI:
    """Create FlextLdifAPI with optional configuration."""
    if max_entries is not None:
        # Create config with override values
        ldif_config = FlextLdifConfig(max_entries=max_entries)
    else:
        ldif_config = FlextLdifConfig()

    return FlextLdifAPI(ldif_config)


def apply_filter(
    api: FlextLdifAPI,
    entries: list[FlextLdifEntry],
    filter_type: str,
) -> list[FlextLdifEntry]:
    """Apply filtering to entries based on filter type."""
    logger.debug(
        "Applying filter to entries: filter_type=%s, entry_count=%d",
        filter_type,
        len(entries),
    )
    logger.trace("Available filter types: persons, groups, ous, valid")

    try:
        logger.debug("Executing filter operation: %s", filter_type)
        if filter_type == "persons":
            logger.trace("Calling api.filter_persons")
            result = api.filter_persons(entries)
        elif filter_type == "groups":
            logger.trace("Calling api.filter_groups")
            result = api.filter_groups(entries)
        elif filter_type == "ous":
            logger.trace("Calling api.filter_organizational_units")
            result = api.filter_organizational_units(entries)
        elif filter_type == "valid":
            logger.trace("Calling api.filter_valid")
            result = api.filter_valid(entries)
        else:
            logger.error("Unknown filter type provided: %s", filter_type)
            logger.debug("Valid filter types: persons, groups, ous, valid")
            click.echo(f"Unknown filter type: {filter_type}", err=True)
            return entries

        # Type assertion: we know result is FlextResult from our API calls
        result_typed = result
        logger.trace("Filter result success: %s", result_typed.success)

        if result_typed.success and result_typed.data is not None:
            filtered_entries = result_typed.data
            logger.debug(
                "Filter successful: %d entries filtered to %d entries",
                len(entries),
                len(filtered_entries),
            )
            logger.info(
                "Successfully filtered entries",
                filter_type=filter_type,
                original_count=len(entries),
                filtered_count=len(filtered_entries),
            )
            click.echo(f"Filtered to {len(filtered_entries)} {filter_type} entries")
            return filtered_entries

    except (ValueError, TypeError, AttributeError) as e:
        logger.exception("Filter operation failed with exception")
        click.echo(f"Filter operation failed: {e}", err=True)
    else:
        logger.error("Filter operation failed: %s", result_typed.error)
        logger.debug("Filter failure details for filter_type: %s", filter_type)
        click.echo(f"Failed to filter {filter_type}: {result_typed.error}", err=True)

    logger.debug("Returning original entries due to filter failure")
    return entries


def handle_validation_errors(entries: list[FlextLdifEntry]) -> None:
    """Handle validation of entries and display errors."""
    logger.debug("Starting validation error handling for %d entries", len(entries))
    logger.trace("Maximum displayed errors: %d", MAX_DISPLAYED_ERRORS)

    validation_errors = []
    logger.debug("Validating entries for domain rules")

    for i, entry in enumerate(entries):
        logger.trace("Validating entry %d: %s", i + 1, entry.dn)
        validation_result = entry.validate_business_rules()
        if not validation_result.success:
            error_msg: str = f"Entry {i + 1} ({entry.dn}): {validation_result.error}"
            validation_errors.append(error_msg)
            logger.debug(
                "Validation failed for entry %d: %s",
                i + 1,
                validation_result.error,
            )

    logger.debug("Validation completed: %d errors found", len(validation_errors))

    if validation_errors:
        logger.info(
            "Validation errors found",
            total_entries=len(entries),
            error_count=len(validation_errors),
            displayed_errors=min(len(validation_errors), MAX_DISPLAYED_ERRORS),
        )

        click.echo(f"Validation found {len(validation_errors)} errors:", err=True)

        for i, error in enumerate(validation_errors[:MAX_DISPLAYED_ERRORS], 1):
            click.echo(f"  - {error}", err=True)
            logger.trace("Displayed error %d: %s", i, error)

        if len(validation_errors) > MAX_DISPLAYED_ERRORS:
            remaining_errors = len(validation_errors) - MAX_DISPLAYED_ERRORS
            logger.debug("Hiding %d additional errors", remaining_errors)
            click.echo(f"  ... and {remaining_errors} more errors", err=True)
    else:
        logger.info("No validation errors found", total_entries=len(entries))
        click.echo("No validation errors found")


def display_statistics(
    ctx: click.Context,
    api: FlextLdifAPI,
    entries: list[FlextLdifEntry],
) -> None:
    """Display entry statistics in the requested format."""
    logger.debug("Displaying statistics for %d entries", len(entries))
    cli_config = ctx.obj["config"]
    output_format = cli_config.output_format
    logger.trace("Requested output format: %s", output_format)

    logger.debug("Getting entry statistics from API")
    stats_result = api.get_entry_statistics(entries)
    # Some tests mock get_entry_statistics to return a raw dict
    # Handle test compatibility - use type: ignore for this edge case
    if isinstance(stats_result, dict):  # type: ignore[unreachable]
        stats = stats_result  # type: ignore[unreachable]
    else:
        if not stats_result.success or stats_result.data is None:
            logger.error("Failed to get statistics: %s", stats_result.error)
            click.echo(f"Failed to get statistics: {stats_result.error}", err=True)
            sys.exit(1)
        stats = stats_result.data
    logger.trace("Statistics keys: %s", list(stats.keys()))
    logger.info(
        "Statistics generated successfully",
        entry_count=len(entries),
        output_format=output_format,
        stats_count=len(stats),
    )

    logger.debug("Formatting statistics output")
    if output_format == "json":
        logger.trace("Formatting as JSON with indent=2")
        json_output = json.dumps(stats, indent=2)
        logger.debug("JSON output length: %d characters", len(json_output))
        click.echo(json_output)
    elif output_format == "yaml":
        logger.trace("Formatting as YAML")
        yaml_output = yaml.dump(stats, default_flow_style=False)
        logger.debug("YAML output length: %d characters", len(yaml_output))
        click.echo(yaml_output)
    else:
        logger.trace("Formatting as plain text")
        click.echo("Entry Statistics:")
        for key, value in stats.items():
            logger.trace("Displaying stat: %s = %s", key, value)
            click.echo(f"  {key}: {value}")

    logger.debug("Statistics display completed successfully")


def write_entries_to_file(
    api: FlextLdifAPI,
    entries: list[FlextLdifEntry],
    output_path: str,
) -> None:
    """Write entries to output file with error handling."""
    logger.debug("Writing %d entries to file: %s", len(entries), output_path)
    logger.trace("Output path details: %s", output_path)

    logger.debug("Calling API write_file method")
    write_result = api.write_file(entries, output_path)
    logger.trace("Write result success: %s", write_result.success)

    if write_result.success:
        logger.info(
            "Entries successfully written to file",
            entry_count=len(entries),
            output_path=output_path,
        )
        click.echo(f"Entries written to {output_path}")
    else:
        logger.error("Write operation failed: %s", write_result.error)
        logger.debug("Write failure details for file: %s", output_path)
        click.echo(f"Write failed: {write_result.error}", err=True)
        sys.exit(1)


@click.group()
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True),
    help="Configuration file path",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["json", "yaml", "table", "text"]),
    default="text",
    help="Output format",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--quiet", is_flag=True, help="Reduce output verbosity")
@click.option("--debug", is_flag=True, help="Enable debug output")
@click.option("--config-file", type=click.Path(), help="Optional path to config file")
@click.pass_context
def cli(ctx: click.Context, **options: object) -> None:
    """FLEXT LDIF - Enterprise LDIF Processing CLI.

    Comprehensive command-line interface para parsing, validação
    e transformação LDIF com Clean Architecture.

    Args:
        ctx: Contexto Click.
        **options: Opções capturadas (`config`, `output_format`, `verbose`,
            `quiet`, `debug`, `config_file`).

    """
    logger.debug("Initializing FLEXT LDIF CLI")
    logger.trace("CLI options: %s", dict(options))

    # quiet implies not verbose
    output_format = str(options.get("output_format", "text"))
    # Map legacy 'text' to flext-cli 'plain'
    if output_format == "text":
        output_format = "plain"
    verbose = bool(options.get("verbose"))
    quiet = bool(options.get("quiet"))
    debug = bool(options.get("debug"))
    config = options.get("config")
    config_file = options.get("config_file")

    # Build real flext-cli configuration using flat compatibility kwargs
    cli_config = FlextCliConfig(
        output_format=output_format,
        verbose=verbose and not quiet,
        quiet=quiet,
        debug=debug,
    )
    setup_result = flext_setup_cli(cli_config)
    if not setup_result.success:
        click.echo(f"Failed to setup CLI: {setup_result.error}", err=True)
        sys.exit(1)

    logger.debug("Creating CLI context object")
    logger.trace("Creating API with default configuration")
    api = create_api_with_config()

    ctx.obj = {
        "config": cli_config,
        "config_path": config_file or config,
        "api": api,
    }

    logger.info(
        "FLEXT LDIF CLI initialized successfully",
        output_format=output_format,
        verbose=verbose,
        debug=debug,
        config_path=str(config) if isinstance(config, str) else "default",
    )


def _parse_and_log_file(
    api: FlextLdifAPI,
    input_file: str,
    max_entries: int | None,
) -> list[FlextLdifEntry]:
    """Parse LDIF file with logging and return entries."""
    logger.debug("Parsing LDIF file: %s", input_file)
    result = api.parse_file(input_file)
    logger.trace(
        "Parse result success: %s",
        hasattr(result, "success") and result.success,
    )

    # Handle parsing result with utility
    handle_parse_result(result)

    entries = result.data
    if entries is None:  # Safety check
        safe_click_echo(
            "Internal error: entries is None after successful parse",
            err=True,
        )
        sys.exit(1)

    logger.info(
        "LDIF file parsed successfully",
        input_file=input_file,
        entry_count=len(entries),
        max_entries=max_entries or "unlimited",
    )
    safe_click_echo(f"Successfully parsed {len(entries)} entries from {input_file}")
    return entries


def _handle_optional_validation(
    entries: list[FlextLdifEntry],
    *,
    validate: bool,
) -> None:
    """Handle optional validation of entries."""
    if validate:
        logger.debug("Performing validation as requested")
        handle_validation_errors(entries)
    else:
        logger.trace("Skipping validation (not requested)")


def _handle_output_generation(
    ctx: click.Context,
    api: FlextLdifAPI,
    entries: list[FlextLdifEntry],
    output: str | None,
) -> None:
    """Handle output generation - file or statistics display."""
    if output:
        logger.debug("Writing parsed entries to output file: %s", output)
        write_entries_to_file(api, entries, output)
    else:
        logger.debug("Displaying statistics instead of writing to file")
        try:
            display_statistics(ctx, api, entries)
        except (TypeError, AttributeError) as e:
            logger.exception("Statistics display failed")
            safe_click_echo(f"Statistics display failed: {e}", err=True)


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--max-entries", type=int, help="Maximum entries to parse")
@click.option("--validate", is_flag=True, help="Validate entries after parsing")
@click.option(
    "--stats",
    is_flag=True,
    help="Display statistics instead of writing output",
)
@click.pass_context
def parse(
    ctx: click.Context,
    input_file: str,
    output: str | None,
    max_entries: int | None,
    **flags: object,
) -> None:
    """Parse LDIF file and display or save entries."""
    logger.debug("Starting parse command")
    logger.trace(
        "Parse options: input_file=%s, output=%s, max_entries=%s, validate=%s",
        input_file,
        output,
        max_entries,
        validate,
    )

    try:
        logger.debug("Creating API with parse configuration")
        api = create_api_with_config(max_entries=max_entries)

        # Parse file and get entries
        entries = _parse_and_log_file(api, input_file, max_entries)

        # Handle optional validation
        _handle_optional_validation(entries, validate=bool(flags.get("validate")))

        # Generate output or statistics
        stats_flag = bool(flags.get("stats"))
        if stats_flag:
            display_statistics(ctx, api, entries)
        else:
            _handle_output_generation(ctx, api, entries, output)

        logger.info("Parse command completed successfully")

    except FileNotFoundError as e:
        # Ensure exit code 2 for nonexistent files (Click convention)
        safe_click_echo(f"Parse operation failed: {e}", err=True)
        sys.exit(2)
    except Exception as e:  # Broad exception for CLI robustness
        logger.exception("Parse operation failed with unexpected exception")
        safe_click_echo(f"Parse operation failed: {e}", err=True)
        sys.exit(1)


def _create_validation_api(ctx: click.Context, *, strict: bool) -> FlextLdifAPI:
    """Create API instance for validation with appropriate config."""
    if strict:
        config = FlextLdifConfig(strict_validation=strict)
        return FlextLdifAPI(config)
    return cast("FlextLdifAPI", ctx.obj["api"])


def _validate_entries(entries: list[FlextLdifEntry]) -> list[str]:
    """Validate entries and return list of error messages."""
    validation_errors = []
    for i, entry in enumerate(entries):
        validation_result = entry.validate_business_rules()
        if not validation_result.success:
            validation_errors.append(
                f"Entry {i + 1} ({entry.dn}): {validation_result.error}",
            )
    return validation_errors


def _display_validation_results(
    entries: list[FlextLdifEntry],
    validation_errors: list[str],
    *,
    strict: bool,
) -> None:
    """Display validation results and exit if errors found."""
    mode = "strict" if strict else "standard"
    safe_click_echo(f"Validation mode: {mode}")

    if validation_errors:
        safe_click_echo(
            f"Validation failed with {len(validation_errors)} errors:",
            err=True,
        )
        for error in validation_errors:
            safe_click_echo(f"  - {error}", err=True)
        sys.exit(1)
    else:
        safe_click_echo(f"✓ All {len(entries)} entries are valid ({mode} mode)")


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--strict", is_flag=True, help="Enable strict validation mode")
@click.option("--schema", type=str, help="Schema validation rules")
@click.pass_context
def validate(
    ctx: click.Context,
    input_file: str,
    *,
    strict: bool,
    schema: str | None,
) -> None:
    """Validate LDIF file entries against schema rules."""
    try:
        # Create API with appropriate configuration
        api = _create_validation_api(ctx, strict=strict)

        # Parse file and handle errors
        parse_result = api.parse_file(input_file)
        handle_parse_result(parse_result)

        # Type assertion: we know parse_result is successful from handle_parse_result
        entries = parse_result.data

        if entries is None:  # Safety check
            safe_click_echo(
                "Internal error: entries is None after successful parse",
                err=True,
            )
            sys.exit(1)

        # Schema validation info (informational for now)
        if schema:
            safe_click_echo(f"Using schema validation rules: {schema}")
            safe_click_echo(
                "Note: Schema-based validation will be implemented with flext-ldap integration",
            )

        # Validate entries and display results
        validation_errors = _validate_entries(entries)
        _display_validation_results(entries, validation_errors, strict=strict)

    except (OSError, ValueError, TypeError) as e:
        safe_click_echo(f"Validation failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.argument("output_file", type=click.Path())
@click.option(
    "--filter-type",
    type=click.Choice(["persons", "groups", "ous", "valid"]),
    help="Filter entry type",
)
@click.option("--sort", is_flag=True, help="Sort entries hierarchically")
@click.pass_context
def transform(
    ctx: click.Context,
    input_file: str,
    output_file: str,
    filter_type: str | None,
    *,
    sort: bool,
) -> None:
    """Transform LDIF file with filtering and sorting options."""
    try:
        api = ctx.obj["api"]

        # Parse input
        parse_result = api.parse_file(input_file)
        if not parse_result.success or parse_result.data is None:
            click.echo(f"Failed to parse input file: {parse_result.error}", err=True)
            sys.exit(1)

        # Type assertion: we know parse_result is FlextResult from our API and data is not None
        parse_result_typed = cast("FlextResult[list[FlextLdifEntry]]", parse_result)
        entries = parse_result_typed.data
        if (
            entries is None
        ):  # Safety check - should never happen due to validation above
            click.echo(
                "Internal error: entries is None after successful parse",
                err=True,
            )
            sys.exit(1)
        click.echo(f"Loaded {len(entries)} entries")

        # Apply filtering
        if filter_type:
            entries = apply_filter(api, entries, filter_type)

        # Apply sorting
        if sort:
            sort_result = api.sort_hierarchically(entries)
            if sort_result.success and sort_result.data is not None:
                entries = sort_result.data
                click.echo("Entries sorted hierarchically")
            else:
                click.echo(
                    f"Failed to sort hierarchically: {sort_result.error}",
                    err=True,
                )

        # Write output
        write_entries_to_file(api, entries, output_file)

    except (OSError, ValueError, TypeError) as e:
        click.echo(f"Transform operation failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option(
    "--format",
    "-f",
    "stats_format",
    type=click.Choice(["json", "yaml", "table"]),
    default="table",
    help="Statistics format",
)
@click.pass_context
def stats(
    ctx: click.Context,
    input_file: str,
    stats_format: str,
) -> None:
    """Display comprehensive statistics for LDIF file."""
    try:
        api = ctx.obj["api"]

        # Parse file
        parse_result = api.parse_file(input_file)
        if not parse_result.success or parse_result.data is None:
            click.echo(f"Failed to parse file: {parse_result.error}", err=True)
            sys.exit(1)

        # Type assertion: we know parse_result is FlextResult from our API and data is not None
        parse_result_typed = cast("FlextResult[list[FlextLdifEntry]]", parse_result)
        entries = parse_result_typed.data
        if (
            entries is None
        ):  # Safety check - should never happen due to validation above
            click.echo(
                "Internal error: entries is None after successful parse",
                err=True,
            )
            sys.exit(1)
        statistics_result = api.get_entry_statistics(entries)
        if not statistics_result.success or statistics_result.data is None:
            click.echo(f"Failed to get statistics: {statistics_result.error}", err=True)
            sys.exit(1)

        statistics = statistics_result.data

        click.echo(f"Statistics for {input_file}:")

        if stats_format == "json":
            click.echo(json.dumps(statistics, indent=2))
        elif stats_format == "yaml":
            click.echo(yaml.dump(statistics, default_flow_style=False))
        else:
            for key, value in statistics.items():
                click.echo(f"  {key}: {value}")

    except (OSError, ValueError, TypeError) as e:
        click.echo(f"Statistics operation failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.argument("query", required=False)
@click.option(
    "--dn",
    "search_dn",
    type=str,
    help="DN filter pattern (supports substring)",
)
@click.option("--attribute", "search_attr", type=str, help="Attribute name to display")
@click.pass_context
def find(
    ctx: click.Context,
    input_file: str,
    query: str | None,
    search_dn: str | None,
    search_attr: str | None,
) -> None:
    """Find specific entry by Distinguished Name."""
    try:
        api = ctx.obj["api"]

        # Parse file
        parse_result = api.parse_file(input_file)
        if not parse_result.success or parse_result.data is None:
            click.echo(f"Failed to parse file: {parse_result.error}", err=True)
            sys.exit(1)

        # Type assertion: we know parse_result is FlextResult from our API and data is not None
        parse_result_typed = cast("FlextResult[list[FlextLdifEntry]]", parse_result)
        entries = parse_result_typed.data
        if (
            entries is None
        ):  # Safety check - should never happen due to validation above
            click.echo(
                "Internal error: entries is None after successful parse",
                err=True,
            )
            sys.exit(1)
        # Prefer positional query (for compatibility), fallback to --dn
        effective_query = query or search_dn
        _run_find(entries, effective_query, search_attr, api)

    except (OSError, ValueError, TypeError) as e:
        click.echo(f"Find operation failed: {e}", err=True)
        sys.exit(1)


def _run_find(
    entries: list[FlextLdifEntry],
    effective_query: str | None,
    search_attr: str | None,
    api: FlextLdifAPI,
) -> None:
    """Execute the find logic separated to reduce complexity.

    Args:
        entries: Parsed LDIF entries.
        effective_query: DN query or None to list DNs.
        search_attr: Attribute to print if matched.
        api: API instance for LDIF operations.

    """
    if effective_query:
        matched = None
        for entry in entries:
            if effective_query.strip("*") in str(entry.dn):
                matched = entry
                break
        if matched is None:
            click.echo(
                f"Entry with DN matching '{effective_query}' not found",
                err=True,
            )
            sys.exit(1)
        if search_attr:
            values = matched.get_attribute(search_attr) or []
            click.echo("\n".join(values))
            return
        ldif_result = api.entries_to_ldif([matched])
        if ldif_result.success:
            click.echo("Found entry:")
            click.echo(ldif_result.data)
        else:
            click.echo(
                f"Failed to convert entry to LDIF: {ldif_result.error}",
                err=True,
            )
            sys.exit(1)
    else:
        for entry in entries:
            click.echo(str(entry.dn))


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.argument("objectclass", type=str)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file for filtered entries",
)
@click.pass_context
def filter_by_class(
    ctx: click.Context,
    input_file: str,
    objectclass: str,
    output: str | None,
) -> None:
    """Filter entries by objectClass attribute."""
    try:
        api = ctx.obj["api"]

        # Parse file
        parse_result = api.parse_file(input_file)
        if not parse_result.success or parse_result.data is None:
            click.echo(f"Failed to parse file: {parse_result.error}", err=True)
            sys.exit(1)

        # Type assertion: we know parse_result is FlextResult from our API and data is not None
        parse_result_typed = cast("FlextResult[list[FlextLdifEntry]]", parse_result)
        entries = parse_result_typed.data
        if (
            entries is None
        ):  # Safety check - should never happen due to validation above
            click.echo(
                "Internal error: entries is None after successful parse",
                err=True,
            )
            sys.exit(1)
        filtered_result = api.filter_by_objectclass(entries, objectclass)
        if not filtered_result.success:
            click.echo(f"Filter operation failed: {filtered_result.error}", err=True)
            sys.exit(1)

        filtered_entries = filtered_result.data
        click.echo(
            f"Found {len(filtered_entries)} entries with objectClass '{objectclass}'",
        )

        if output:
            write_entries_to_file(api, filtered_entries, output)
        else:
            # Display filtered entries
            ldif_result = api.entries_to_ldif(filtered_entries)
            if ldif_result.success:
                click.echo(ldif_result.data)
            else:
                click.echo(
                    f"Failed to convert entries to LDIF: {ldif_result.error}",
                    err=True,
                )
                sys.exit(1)

    except (OSError, ValueError, TypeError) as e:
        click.echo(f"Filter operation failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["ldif", "json", "yaml", "csv"]),
    default="ldif",
    help="Output format",
)
@click.argument("input_file", type=click.Path(exists=True))
@click.pass_context
def convert(
    ctx: click.Context,
    input_file: str,
    output_format: str,
) -> None:
    """Convert between different file formats."""
    try:
        api = ctx.obj["api"]

        # Parse input
        parse_result = api.parse_file(input_file)
        if not parse_result.success or parse_result.data is None:
            click.echo(f"Failed to parse input file: {parse_result.error}", err=True)
            sys.exit(1)

        # Type assertion: we know parse_result is FlextResult from our API and data is not None
        parse_result_typed = cast("FlextResult[list[FlextLdifEntry]]", parse_result)
        entries = parse_result_typed.data
        if (
            entries is None
        ):  # Safety check - should never happen due to validation above
            click.echo(
                "Internal error: entries is None after successful parse",
                err=True,
            )
            sys.exit(1)

        # Determine output file path automatically next to input
        output_path = Path(input_file).with_suffix(f".{output_format}")

        if output_format == "ldif":
            write_entries_to_file(api, entries, str(output_path))
            click.echo(f"Converted to LDIF: {output_path}")
        elif output_format in {"json", "yaml"}:
            entries_data = [entry.model_dump() for entry in entries]
            if output_format == "json":
                output_path.write_text(
                    json.dumps(entries_data, indent=2, default=str),
                    encoding="utf-8",
                )
            else:
                output_path.write_text(
                    yaml.dump(entries_data, default_flow_style=False),
                    encoding="utf-8",
                )
            click.echo(
                f"Converted {len(entries)} entries to {output_format}: {output_path}",
            )
        elif output_format == "csv":
            # Minimal CSV export: dn and objectClass

            with output_path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["dn", "objectClass"])
                for entry in entries:
                    oc = ";".join(entry.get_object_classes())
                    writer.writerow([str(entry.dn), oc])
            click.echo(
                f"Converted {len(entries)} entries to csv: {output_path}",
            )

    except (OSError, ValueError, TypeError) as e:
        click.echo(f"Convert operation failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.pass_context
def config_check(ctx: click.Context) -> None:
    """Validate CLI configuration and display settings."""
    try:
        cli_config = ctx.obj["config"]
        config_path = ctx.obj["config_path"]

        click.echo("CLI Configuration:")
        click.echo(f"  Output Format: {cli_config.output_format}")
        click.echo(f"  Verbose: {cli_config.verbose}")
        click.echo(f"  Debug: {cli_config.debug}")
        click.echo(f"  Config Path: {config_path or 'None'}")

        # Test API functionality
        api = ctx.obj["api"]

        # Create a test entry to validate API
        test_ldif = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
"""

        parse_result = api.parse(test_ldif)
        if parse_result.success:
            click.echo("✓ API functionality validated")
        else:
            click.echo(f"API test failed: {parse_result.error}", err=True)

    except (OSError, ValueError, TypeError) as e:
        click.echo(f"Configuration check failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("input_file", type=str)
@click.option("--output", "-o", type=click.Path(), help="Output LDIF file path")
@click.option(
    "--line-wrap",
    type=int,
    default=0,
    help="Optional line wrap width (ignored)",
)
@click.pass_context
def write(
    ctx: click.Context,
    input_file: str,
    output: str | None,
    line_wrap: int,
) -> None:
    """Reformat LDIF file and print or save the output."""
    del line_wrap  # currently not applied; kept for CLI compatibility
    try:
        api = ctx.obj["api"]

        parse_result = api.parse_file(input_file)
        if not parse_result.success or parse_result.data is None:
            click.echo(f"Failed to parse file: {parse_result.error}", err=True)
            sys.exit(1)

        entries = parse_result.data
        write_result = api.entries_to_ldif(entries)
        if not write_result.success:
            click.echo(f"Failed to render LDIF: {write_result.error}", err=True)
            sys.exit(1)

        content = write_result.data or ""
        if output:
            out_path = Path(output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(content, encoding="utf-8")
        else:
            click.echo(content)

    except (OSError, ValueError, TypeError) as e:
        click.echo(f"Write operation failed: {e}", err=True)
        sys.exit(1)


def setup_cli() -> object:
    """Set up the CLI environment and return a simple result-like object."""
    # In real integration this would call flext-cli; we keep a small shim
    return type("Result", (), {"success": True, "error": None})()


def main() -> None:
    """Run the CLI application entry point."""
    logger.debug("Starting FLEXT LDIF CLI main entry point")

    try:
        # Setup CLI with flext-cli foundation (using defaults)
        setup_result = flext_setup_cli()
        if not setup_result.success:
            logger.error("CLI setup failed: %s", setup_result.error)
            click.echo(f"CLI setup failed: {setup_result.error}", err=True)
            sys.exit(1)

        logger.debug("CLI setup completed successfully, starting CLI")
        logger.info("FLEXT LDIF CLI starting")
        cli()
        logger.info("FLEXT LDIF CLI completed successfully")

    except KeyboardInterrupt:
        logger.info("CLI operation cancelled by user (Ctrl+C)")
        click.echo("\nOperation cancelled by user", err=True)
        sys.exit(1)
    except (OSError, ValueError, TypeError) as e:
        logger.exception("CLI failed with exception")
        click.echo(f"CLI error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
