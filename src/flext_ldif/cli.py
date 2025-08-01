"""FLEXT LDIF Command Line Interface.

Enterprise-grade CLI for LDIF processing using flext-cli foundation.
Provides comprehensive LDIF parsing, validation, and transformation capabilities.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from flext_core import FlextResult

    from .models import FlextLdifEntry

import click
import yaml
from flext_cli import get_config, setup_cli
from flext_core import get_logger

from .api import FlextLdifAPI
from .config import FlextLdifConfig
from .utils.cli_utils import handle_parse_result, safe_click_echo

# Logger for CLI module
logger = get_logger(__name__)

# Constants
MAX_DISPLAYED_ERRORS = 5


def create_api_with_config(*, max_entries: int | None = None) -> FlextLdifAPI:
    """Create FlextLdifAPI with optional configuration."""
    logger.debug("Creating FlextLdifAPI with configuration")
    logger.trace("max_entries parameter: %s", max_entries)

    if max_entries is not None:
        logger.debug("Creating config with max_entries override: %d", max_entries)
        # Explicitly create config with max_entries override
        ldif_config = FlextLdifConfig()
        ldif_config.max_entries = max_entries
        logger.trace("Config created with max_entries: %d", ldif_config.max_entries)
    else:
        logger.debug("Creating config with default settings")
        ldif_config = FlextLdifConfig()
        logger.trace(
            "Config created with default max_entries: %d",
            ldif_config.max_entries,
        )

    logger.debug("Initializing FlextLdifAPI with configuration")
    api = FlextLdifAPI(ldif_config)
    logger.info(
        "FlextLdifAPI created successfully",
        max_entries=ldif_config.max_entries,
        strict_validation=ldif_config.strict_validation,
    )
    return api


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
        result_typed = cast("FlextResult[list[FlextLdifEntry]]", result)
        logger.trace("Filter result success: %s", result_typed.is_success)

        if result_typed.is_success and result_typed.data is not None:
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
        validation_result = entry.validate_domain_rules()
        if not validation_result.is_success:
            error_msg = f"Entry {i + 1} ({entry.dn}): {validation_result.error}"
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
    stats = api.get_entry_statistics(entries)
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

    logger.debug("Calling API write method")
    write_result = api.write(entries, output_path)
    logger.trace("Write result success: %s", write_result.is_success)

    if write_result.is_success:
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
@click.option("--debug", is_flag=True, help="Enable debug output")
@click.pass_context
def cli(
    ctx: click.Context,
    config: str | None,
    output_format: str,
    *,
    verbose: bool,
    debug: bool,
) -> None:
    """FLEXT LDIF - Enterprise LDIF Processing CLI.

    Comprehensive command-line interface for LDIF parsing, validation,
    and transformation using Clean Architecture patterns.
    """
    logger.debug("Initializing FLEXT LDIF CLI")
    logger.trace(
        "CLI options: config=%s, format=%s, verbose=%s, debug=%s",
        config,
        output_format,
        verbose,
        debug,
    )

    # Use flext-cli configuration
    logger.debug("Getting flext-cli configuration")
    cli_config = get_config()
    cli_config.output_format = output_format
    cli_config.verbose = verbose
    cli_config.debug = debug
    logger.trace("CLI configuration set successfully")

    logger.debug("Creating CLI context object")
    logger.trace("Creating API with default configuration")
    api = create_api_with_config()

    ctx.obj = {
        "config": cli_config,
        "config_path": config,
        "api": api,
    }

    logger.info(
        "FLEXT LDIF CLI initialized successfully",
        output_format=output_format,
        verbose=verbose,
        debug=debug,
        config_path=config or "default",
    )


def _parse_and_log_file(
    api: FlextLdifAPI, input_file: str, max_entries: int | None
) -> list[FlextLdifEntry]:
    """Parse LDIF file with logging and return entries."""
    logger.debug("Parsing LDIF file: %s", input_file)
    result = api.parse_file(input_file)
    logger.trace(
        "Parse result success: %s",
        hasattr(result, "is_success") and result.is_success,
    )

    # Handle parsing result with utility
    handle_parse_result(cast("FlextResult[Any]", result), input_file)

    entries = cast("FlextResult[list[FlextLdifEntry]]", result).data
    if entries is None:  # Safety check
        safe_click_echo(
            "Internal error: entries is None after successful parse", err=True
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
    entries: list[FlextLdifEntry], *, validate: bool
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
@click.pass_context
def parse(
    ctx: click.Context,
    input_file: str,
    output: str | None,
    max_entries: int | None,
    *,
    validate: bool,
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
        _handle_optional_validation(entries, validate=validate)

        # Generate output
        _handle_output_generation(ctx, api, entries, output)

        logger.info("Parse command completed successfully")

    except Exception as e:  # Broad exception for CLI robustness
        logger.exception("Parse operation failed with unexpected exception")
        safe_click_echo(f"Parse operation failed: {e}", err=True)
        sys.exit(1)


def _create_validation_api(ctx: click.Context, *, strict: bool) -> FlextLdifAPI:
    """Create API instance for validation with appropriate config."""
    if strict:
        config = FlextLdifConfig()
        config.strict_validation = strict
        return FlextLdifAPI(config)
    return cast("FlextLdifAPI", ctx.obj["api"])


def _validate_entries(entries: list[FlextLdifEntry]) -> list[str]:
    """Validate entries and return list of error messages."""
    validation_errors = []
    for i, entry in enumerate(entries):
        validation_result = entry.validate_domain_rules()
        if not validation_result.is_success:
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
        handle_parse_result(cast("FlextResult[Any]", parse_result), input_file)

        # Type assertion: we know parse_result is successful from handle_parse_result
        parse_result_typed = cast("FlextResult[list[FlextLdifEntry]]", parse_result)
        entries = parse_result_typed.data

        if entries is None:  # Safety check
            safe_click_echo(
                "Internal error: entries is None after successful parse", err=True
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
        if not parse_result.is_success or parse_result.data is None:
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
            if sort_result.is_success and sort_result.data is not None:
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
        if not parse_result.is_success or parse_result.data is None:
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
        statistics = api.get_entry_statistics(entries)

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
@click.argument("dn", type=str)
@click.pass_context
def find(
    ctx: click.Context,
    input_file: str,
    dn: str,
) -> None:
    """Find specific entry by Distinguished Name."""
    try:
        api = ctx.obj["api"]

        # Parse file
        parse_result = api.parse_file(input_file)
        if not parse_result.is_success or parse_result.data is None:
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
        entry = api.find_entry_by_dn(entries, dn)

        if entry:
            # Convert single entry to LDIF format
            ldif_output = api.entries_to_ldif([entry])
            click.echo("Found entry:")
            click.echo(ldif_output)
        else:
            click.echo(f"Entry with DN '{dn}' not found", err=True)
            sys.exit(1)

    except (OSError, ValueError, TypeError) as e:
        click.echo(f"Find operation failed: {e}", err=True)
        sys.exit(1)


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
        if not parse_result.is_success or parse_result.data is None:
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
        filtered_entries = api.filter_by_objectclass(entries, objectclass)

        click.echo(
            f"Found {len(filtered_entries)} entries with objectClass '{objectclass}'",
        )

        if output:
            write_entries_to_file(api, filtered_entries, output)
        else:
            # Display filtered entries
            ldif_output = api.entries_to_ldif(filtered_entries)
            click.echo(ldif_output)

    except (OSError, ValueError, TypeError) as e:
        click.echo(f"Filter operation failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--input-format",
    type=click.Choice(["ldif"]),
    default="ldif",
    help="Input format",
)
@click.option(
    "--output-format",
    type=click.Choice(["ldif", "json", "yaml"]),
    default="ldif",
    help="Output format",
)
@click.argument("input_file", type=click.Path(exists=True))
@click.argument("output_file", type=click.Path())
@click.pass_context
def convert(
    ctx: click.Context,
    input_format: str,
    output_format: str,
    input_file: str,
    output_file: str,
) -> None:
    """Convert between different file formats."""
    try:
        api = ctx.obj["api"]

        # Currently only supports LDIF input
        if input_format != "ldif":
            click.echo(f"Input format '{input_format}' not supported yet", err=True)
            sys.exit(1)

        # Parse input
        parse_result = api.parse_file(input_file)
        if not parse_result.is_success or parse_result.data is None:
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

        if output_format == "ldif":
            write_entries_to_file(api, entries, output_file)
            click.echo(f"Converted to LDIF: {output_file}")
        else:
            # For JSON/YAML, convert entries to dict format
            entries_data = [entry.model_dump() for entry in entries]

            output_path = Path(output_file)
            if output_format == "json":
                with output_path.open("w", encoding="utf-8") as f:
                    json.dump(entries_data, f, indent=2, default=str)
            elif output_format == "yaml":
                with output_path.open("w", encoding="utf-8") as f:
                    yaml.dump(entries_data, f, default_flow_style=False)

            click.echo(
                f"Converted {len(entries)} entries to {output_format}: {output_file}",
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
        if parse_result.is_success:
            click.echo("✓ API functionality validated")
        else:
            click.echo(f"API test failed: {parse_result.error}", err=True)

    except (OSError, ValueError, TypeError) as e:
        click.echo(f"Configuration check failed: {e}", err=True)
        sys.exit(1)


def main() -> None:
    """CLI application entry point."""
    logger.debug("Starting FLEXT LDIF CLI main entry point")

    try:
        # Setup CLI with flext-cli foundation
        logger.debug("Setting up CLI with flext-cli foundation")
        setup_result = setup_cli()
        logger.trace("CLI setup result success: %s", setup_result.is_success)

        if not setup_result.is_success:
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
