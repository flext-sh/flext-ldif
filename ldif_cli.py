"""FLEXT-LDIF Command Line Interface - Enterprise LDIF Processing CLI.

CONSOLIDATED PEP8 ARCHITECTURE: This module consolidates LDIF CLI functionality
into ONE centralized, PEP8-compliant command-line interface module.

CONSOLIDATION MAPPING:
✅ src/flext_ldif/cli.py → Main CLI implementation with commands
✅ src/flext_ldif/cli_utils.py → CLI utilities and helper functions

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

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flext_core import FlextResult

    from .ldif_models import FlextLdifEntry

import click
import yaml
from flext_core import get_logger

from .ldif_api import FlextLdifAPI
from .ldif_config import FlextLdifConfig

logger = get_logger(__name__)

# =============================================================================
# CLI UTILITIES - CONSOLIDATED FROM CLI_UTILS.PY
# =============================================================================


def safe_click_echo(message: str, color: str | None = None) -> None:
    """Safely echo a message using click with optional color."""
    try:
        if color:
            click.secho(message, fg=color)
        else:
            click.echo(message)
    except Exception as e:
        logger.warning("Failed to display message", error=str(e))
        # Last resort: direct echo to avoid print usage
        try:
            click.echo(message, err=True)
        except Exception:
            # Ultimate fallback - log only, no console output
            logger.exception("Complete display failure: %s", message)


def display_entry_count(count: int, entry_type: str = "entries") -> None:
    """Display entry count with proper formatting."""
    message = f"Found {count} {entry_type}"
    safe_click_echo(message)


def confirm_operation(prompt: str, *, default: bool = False) -> bool:
    """Confirm operation with user using click.confirm."""
    try:
        return click.confirm(prompt, default=default)
    except Exception as e:
        logger.warning("Failed to get user confirmation", error=str(e))
        return default


def display_statistics(entries: list[object]) -> None:
    """Display statistics about LDIF entries."""
    if not entries:
        safe_click_echo("No entries to display statistics for.")
        return

    try:
        safe_click_echo(f"Total entries: {len(entries)}")

        # Count by objectClass if available
        object_classes: dict[str, int] = {}
        for entry in entries:
            if hasattr(entry, "attributes") and hasattr(entry.attributes, "attributes"):
                obj_classes = entry.attributes.attributes.get("objectClass", [])
                for obj_class in obj_classes:
                    object_classes[obj_class] = object_classes.get(obj_class, 0) + 1

        if object_classes:
            safe_click_echo("Object Classes:")
            for obj_class, count in sorted(object_classes.items()):
                safe_click_echo(f"  {obj_class}: {count}")

    except Exception as e:
        logger.exception("Failed to display statistics", error=str(e))
        safe_click_echo("Error displaying statistics")


def validate_cli_result(result: object) -> FlextResult[bool]:
    """Validate CLI result object."""
    try:
        # Import here to avoid circular dependency
        from flext_core import FlextResult

        # Check if result has expected CLI result attributes
        if hasattr(result, "exit_code"):
            if result.exit_code == 0:
                return FlextResult.success(True)
            return FlextResult.failure(
                f"CLI command failed with exit code {result.exit_code}",
            )

        # For other result types, check if it's truthy
        if result:
            return FlextResult.success(True)
        return FlextResult.failure("CLI result validation failed")

    except Exception as e:
        logger.exception("CLI result validation error", error=str(e))
        return FlextResult.failure(f"CLI validation error: {e}")

# =============================================================================
# CLI CONTEXT AND CONFIGURATION
# =============================================================================


class FlextLdifCliContext:
    """CLI context for managing state and configuration."""

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize CLI context."""
        self.config = config or FlextLdifConfig()
        self.api = FlextLdifAPI(self.config)
        self.verbose = False
        self.quiet = False

    def log_info(self, message: str) -> None:
        """Log info message if not quiet."""
        if not self.quiet:
            safe_click_echo(message, color="blue")

    def log_success(self, message: str) -> None:
        """Log success message."""
        safe_click_echo(message, color="green")

    def log_error(self, message: str) -> None:
        """Log error message."""
        safe_click_echo(f"Error: {message}", color="red")

    def log_warning(self, message: str) -> None:
        """Log warning message."""
        safe_click_echo(f"Warning: {message}", color="yellow")


# Global CLI context
cli_context = FlextLdifCliContext()

# =============================================================================
# CLI OPTION DECORATORS
# =============================================================================


def common_options(f):
    """Add common CLI options to commands."""
    f = click.option(
        "--verbose", "-v",
        is_flag=True,
        help="Enable verbose output",
    )(f)
    return click.option(
        "--quiet", "-q",
        is_flag=True,
        help="Suppress informational output",
    )(f)


def input_options(f):
    """Add input-related options to commands."""
    return click.option(
        "--encoding",
        default="utf-8",
        help="Input file encoding (default: utf-8)",
    )(f)


def output_options(f):
    """Add output-related options to commands."""
    f = click.option(
        "--output", "-o",
        type=click.Path(),
        help="Output file path",
    )(f)
    return click.option(
        "--format",
        type=click.Choice(["ldif", "json", "yaml"], case_sensitive=False),
        default="ldif",
        help="Output format (default: ldif)",
    )(f)

# =============================================================================
# CLI COMMAND GROUP
# =============================================================================


@click.group()
@click.version_option("0.9.0", prog_name="flext-ldif")
@common_options
@click.pass_context
def main(ctx: click.Context, verbose: bool, quiet: bool) -> None:
    """FLEXT-LDIF: Enterprise LDIF Processing CLI.

    Process, validate, and transform LDIF files with enterprise-grade
    reliability and comprehensive error handling.
    """
    # Ensure context object exists
    ctx.ensure_object(dict)

    # Update global context
    cli_context.verbose = verbose
    cli_context.quiet = quiet

    if verbose:
        logger.setLevel("DEBUG")
        cli_context.log_info("Verbose mode enabled")

# =============================================================================
# PARSE COMMAND
# =============================================================================


@main.command()
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@input_options
@output_options
@common_options
def parse(input_file: Path, encoding: str, output: str | None, format: str,
          verbose: bool, quiet: bool) -> None:
    """Parse LDIF file and optionally convert format.

    Parses the specified LDIF file, validates its format, and can output
    the parsed entries in various formats (LDIF, JSON, YAML).

    Examples:
        flext-ldif parse input.ldif
        flext-ldif parse input.ldif --output parsed.json --format json
        flext-ldif parse input.ldif --encoding iso-8859-1

    """
    try:
        cli_context.log_info(f"Parsing LDIF file: {input_file}")

        # Update configuration with encoding
        config = FlextLdifConfig(input_encoding=encoding)
        api = FlextLdifAPI(config)

        # Parse the file
        parse_result = api.parse_file(input_file)
        if parse_result.is_failure:
            cli_context.log_error(f"Failed to parse LDIF file: {parse_result.error}")
            sys.exit(1)

        entries = parse_result.data or []
        cli_context.log_success(f"Successfully parsed {len(entries)} entries")

        # Output results
        if output:
            output_path = Path(output)
            _write_output(entries, output_path, format)
            cli_context.log_success(f"Output written to: {output_path}")
        else:
            _display_output(entries, format)

        # Display statistics if verbose
        if verbose:
            display_statistics(entries)

    except Exception as e:
        cli_context.log_error(f"Parse command failed: {e}")
        if verbose:
            logger.exception("Parse command exception")
        sys.exit(1)

# =============================================================================
# VALIDATE COMMAND
# =============================================================================


@main.command()
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@input_options
@common_options
@click.option(
    "--strict",
    is_flag=True,
    help="Enable strict validation mode",
)
def validate(input_file: Path, encoding: str, strict: bool,
             verbose: bool, quiet: bool) -> None:
    """Validate LDIF file format and business rules.

    Validates the specified LDIF file against RFC 2849 format compliance
    and business rules including DN format, attribute names, and object classes.

    Examples:
        flext-ldif validate input.ldif
        flext-ldif validate input.ldif --strict
        flext-ldif validate input.ldif --encoding iso-8859-1

    """
    try:
        cli_context.log_info(f"Validating LDIF file: {input_file}")

        # Update configuration
        config = FlextLdifConfig(
            input_encoding=encoding,
            strict_validation=strict,
        )
        api = FlextLdifAPI(config)

        # Parse and validate
        parse_result = api.parse_file(input_file)
        if parse_result.is_failure:
            cli_context.log_error(f"Parse failed: {parse_result.error}")
            sys.exit(1)

        entries = parse_result.data or []
        cli_context.log_info(f"Parsed {len(entries)} entries")

        # Validate entries
        validation_result = api.validate(entries)
        if validation_result.is_failure:
            cli_context.log_error(f"Validation failed: {validation_result.error}")
            sys.exit(1)

        cli_context.log_success("LDIF file validation passed")

        # Display statistics if verbose
        if verbose:
            display_statistics(entries)

    except Exception as e:
        cli_context.log_error(f"Validate command failed: {e}")
        if verbose:
            logger.exception("Validate command exception")
        sys.exit(1)

# =============================================================================
# INFO COMMAND
# =============================================================================


@main.command()
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@input_options
@common_options
def info(input_file: Path, encoding: str, verbose: bool, quiet: bool) -> None:
    """Display information about LDIF file.

    Analyzes the specified LDIF file and displays comprehensive information
    including entry counts, object class distribution, DN patterns, and more.

    Examples:
        flext-ldif info input.ldif
        flext-ldif info input.ldif --encoding iso-8859-1

    """
    try:
        cli_context.log_info(f"Analyzing LDIF file: {input_file}")

        # Update configuration
        config = FlextLdifConfig(input_encoding=encoding)
        api = FlextLdifAPI(config)

        # Parse file
        parse_result = api.parse_file(input_file)
        if parse_result.is_failure:
            cli_context.log_error(f"Failed to parse LDIF file: {parse_result.error}")
            sys.exit(1)

        entries = parse_result.data or []

        # Get statistics
        stats_result = api.get_statistics(entries)
        if stats_result.is_failure:
            cli_context.log_error(f"Failed to get statistics: {stats_result.error}")
            sys.exit(1)

        stats = stats_result.data or {}

        # Get DN patterns
        dn_analysis_result = api.analyze_dn_patterns(entries)
        if dn_analysis_result.is_failure:
            cli_context.log_warning(f"DN analysis failed: {dn_analysis_result.error}")
            dn_analysis = {}
        else:
            dn_analysis = dn_analysis_result.data or {}

        # Display information
        safe_click_echo("=== LDIF File Information ===")
        safe_click_echo(f"File: {input_file}")
        safe_click_echo(f"File size: {input_file.stat().st_size:,} bytes")
        safe_click_echo()

        safe_click_echo("=== Entry Statistics ===")
        safe_click_echo(f"Total entries: {stats.get('total_entries', 0):,}")
        safe_click_echo(f"Person entries: {stats.get('person_entries', 0):,}")
        safe_click_echo(f"Group entries: {stats.get('group_entries', 0):,}")
        safe_click_echo(f"OU entries: {stats.get('ou_entries', 0):,}")
        safe_click_echo(f"Other entries: {stats.get('other_entries', 0):,}")
        safe_click_echo(f"Unique attributes: {stats.get('unique_attributes', 0):,}")
        safe_click_echo()

        if dn_analysis:
            safe_click_echo("=== DN Analysis ===")
            safe_click_echo(f"Average depth: {dn_analysis.get('avg_depth', 0):.1f}")
            safe_click_echo(f"Max depth: {dn_analysis.get('max_depth', 0)}")
            safe_click_echo(f"Min depth: {dn_analysis.get('min_depth', 0)}")

            depth_dist = dn_analysis.get("depth_distribution", {})
            if depth_dist:
                safe_click_echo("Depth distribution:")
                for depth, count in sorted(depth_dist.items()):
                    safe_click_echo(f"  {depth}: {count:,}")
            safe_click_echo()

        # Display detailed statistics if verbose
        if verbose:
            display_statistics(entries)

    except Exception as e:
        cli_context.log_error(f"Info command failed: {e}")
        if verbose:
            logger.exception("Info command exception")
        sys.exit(1)

# =============================================================================
# FILTER COMMAND
# =============================================================================


@main.command()
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@input_options
@output_options
@common_options
@click.option(
    "--objectclass",
    help="Filter by objectClass value",
)
@click.option(
    "--attribute",
    help="Filter by attribute (format: name=value)",
)
@click.option(
    "--dn-pattern",
    help="Filter by DN pattern (substring match)",
)
def filter(input_file: Path, encoding: str, output: str | None, format: str,
           objectclass: str | None, attribute: str | None, dn_pattern: str | None,
           verbose: bool, quiet: bool) -> None:
    """Filter LDIF entries based on criteria.

    Filters entries from the LDIF file based on various criteria such as
    objectClass, attribute values, or DN patterns.

    Examples:
        flext-ldif filter input.ldif --objectclass person
        flext-ldif filter input.ldif --attribute "mail=*@example.com"
        flext-ldif filter input.ldif --dn-pattern "ou=users"

    """
    try:
        if not any([objectclass, attribute, dn_pattern]):
            cli_context.log_error("At least one filter criterion must be specified")
            sys.exit(1)

        cli_context.log_info(f"Filtering LDIF file: {input_file}")

        # Update configuration
        config = FlextLdifConfig(input_encoding=encoding)
        api = FlextLdifAPI(config)

        # Parse file
        parse_result = api.parse_file(input_file)
        if parse_result.is_failure:
            cli_context.log_error(f"Failed to parse LDIF file: {parse_result.error}")
            sys.exit(1)

        entries = parse_result.data or []
        filtered_entries = entries

        # Apply filters
        if objectclass:
            filter_result = api.filter_by_objectclass(filtered_entries, objectclass)
            if filter_result.is_failure:
                cli_context.log_error(f"ObjectClass filter failed: {filter_result.error}")
                sys.exit(1)
            filtered_entries = filter_result.data or []
            cli_context.log_info(f"ObjectClass filter: {len(filtered_entries)} entries")

        if attribute:
            if "=" not in attribute:
                cli_context.log_error("Attribute filter must be in format 'name=value'")
                sys.exit(1)

            attr_name, attr_value = attribute.split("=", 1)
            filter_result = api.filter_by_attribute(filtered_entries, attr_name, attr_value)
            if filter_result.is_failure:
                cli_context.log_error(f"Attribute filter failed: {filter_result.error}")
                sys.exit(1)
            filtered_entries = filter_result.data or []
            cli_context.log_info(f"Attribute filter: {len(filtered_entries)} entries")

        if dn_pattern:
            # Simple DN pattern filtering (substring match)
            pattern_filtered = [
                entry for entry in filtered_entries
                if dn_pattern.lower() in entry.dn_string.lower()
            ]
            filtered_entries = pattern_filtered
            cli_context.log_info(f"DN pattern filter: {len(filtered_entries)} entries")

        cli_context.log_success(f"Filtered to {len(filtered_entries)} entries")

        # Output results
        if output:
            output_path = Path(output)
            _write_output(filtered_entries, output_path, format)
            cli_context.log_success(f"Filtered output written to: {output_path}")
        else:
            _display_output(filtered_entries, format)

    except Exception as e:
        cli_context.log_error(f"Filter command failed: {e}")
        if verbose:
            logger.exception("Filter command exception")
        sys.exit(1)

# =============================================================================
# OUTPUT HELPERS
# =============================================================================


def _write_output(entries: list[FlextLdifEntry], output_path: Path, format: str) -> None:
    """Write entries to output file in specified format."""
    try:
        if format.lower() == "json":
            data = [entry.to_dict() for entry in entries]
            output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        elif format.lower() == "yaml":
            data = [entry.to_dict() for entry in entries]
            output_path.write_text(yaml.dump(data, default_flow_style=False), encoding="utf-8")
        else:  # ldif format
            api = FlextLdifAPI()
            write_result = api.write_file(entries, output_path)
            if write_result.is_failure:
                msg = f"LDIF write failed: {write_result.error}"
                raise ValueError(msg)
    except Exception as e:
        cli_context.log_error(f"Failed to write output: {e}")
        raise


def _display_output(entries: list[FlextLdifEntry], format: str) -> None:
    """Display entries to stdout in specified format."""
    try:
        if format.lower() == "json":
            data = [entry.to_dict() for entry in entries]
            safe_click_echo(json.dumps(data, indent=2))
        elif format.lower() == "yaml":
            data = [entry.to_dict() for entry in entries]
            safe_click_echo(yaml.dump(data, default_flow_style=False))
        else:  # ldif format
            api = FlextLdifAPI()
            write_result = api.write(entries)
            if write_result.is_failure:
                msg = f"LDIF write failed: {write_result.error}"
                raise ValueError(msg)
            safe_click_echo(write_result.data or "")
    except Exception as e:
        cli_context.log_error(f"Failed to display output: {e}")
        raise

# =============================================================================
# ENTRY POINT
# =============================================================================


if __name__ == "__main__":
    main()

# =============================================================================
# PUBLIC API
# =============================================================================

__all__ = [
    # CLI context
    "FlextLdifCliContext",
    "cli_context",
    "confirm_operation",
    "display_entry_count",
    "display_statistics",
    # Main CLI
    "main",
    # CLI utilities
    "safe_click_echo",
    "validate_cli_result",
]
