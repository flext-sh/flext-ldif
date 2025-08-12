#!/usr/bin/env python3
"""Modern FLEXT LDIF CLI using flext-cli framework.

ENTERPRISE-GRADE CLI with zero boilerplate through flext-cli integration.
Replaces 1,100+ lines of legacy CLI code with modern delegation patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import click
import yaml
from flext_cli import (
    FlextCliAdvancedMixin,
    FlextCliEntity,
    create_flext_cli_config,
    setup_flext_cli,
)
from flext_core import FlextResult, get_logger
from rich.console import Console
from rich.table import Table

from flext_ldif.api import FlextLdifAPI
from flext_ldif.config import FlextLdifConfig

if TYPE_CHECKING:
    from flext_ldif.models import FlextLdifEntry

logger = get_logger(__name__)
console = Console()

# =============================================================================
# FLEXT-CLI PARAMETER OBJECTS - ELIMINATE ARGUMENT EXPLOSION
# =============================================================================


@dataclass
class LDIFParseParams:
    """Parameter object for LDIF parse operations - flext-cli pattern."""

    input_file: str
    output_file: str | None = None
    max_entries: int | None = None
    validate: bool = False
    stats: bool = False

    @classmethod
    def from_click_args(cls, input_file: str, **kwargs) -> LDIFParseParams:
        """Create from Click arguments using flext-cli patterns."""
        return cls(
            input_file=input_file,
            output_file=kwargs.get("output"),
            max_entries=kwargs.get("max_entries"),
            validate=bool(kwargs.get("validate")),
            stats=bool(kwargs.get("stats")),
        )


@dataclass
class LDIFValidateParams:
    """Parameter object for LDIF validation operations - flext-cli pattern."""

    input_file: str
    strict: bool = False
    schema: str | None = None

    @classmethod
    def from_click_args(cls, input_file: str, **kwargs) -> LDIFValidateParams:
        """Create from Click arguments using flext-cli patterns."""
        return cls(
            input_file=input_file,
            strict=bool(kwargs.get("strict")),
            schema=kwargs.get("schema"),
        )


@dataclass
class LDIFTransformParams:
    """Parameter object for LDIF transformation operations - flext-cli pattern."""

    input_file: str
    output_file: str
    filter_type: str | None = None
    sort: bool = False

    @classmethod
    def from_click_args(cls, input_file: str, output_file: str, **kwargs) -> LDIFTransformParams:
        """Create from Click arguments using flext-cli patterns."""
        return cls(
            input_file=input_file,
            output_file=output_file,
            filter_type=kwargs.get("filter_type"),
            sort=bool(kwargs.get("sort")),
        )


@dataclass
class LDIFStatsParams:
    """Parameter object for LDIF statistics operations - flext-cli pattern."""

    input_file: str
    stats_format: str = "table"

    @classmethod
    def from_click_args(cls, input_file: str, **kwargs) -> LDIFStatsParams:
        """Create from Click arguments using flext-cli patterns."""
        return cls(
            input_file=input_file,
            stats_format=kwargs.get("format", "table"),
        )


# =============================================================================
# FLEXT-CLI COMMAND CLASSES - ZERO BOILERPLATE WITH FLEXTCLIADVANCEDMIXIN
# =============================================================================


class FlextLdifParseCommand(FlextCliEntity, FlextCliAdvancedMixin):
    """LDIF parsing using modern flext-cli patterns.

    FlextCliAdvancedMixin provides:
    - FlextCliValidationMixin: Input validation
    - FlextCliInteractiveMixin: User interaction
    - FlextCliProgressMixin: Progress tracking
    - FlextCliResultMixin: Result handling
    - FlextCliConfigMixin: Configuration management
    """

    def __init__(self, command_id: str, name: str, params: LDIFParseParams) -> None:
        super().__init__(id=command_id, name=name)
        self.params = params
        FlextCliAdvancedMixin.__init__(self)

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate LDIF parse parameters."""
        if not Path(self.params.input_file).exists():
            return FlextResult.fail(f"Input file does not exist: {self.params.input_file}")

        if self.params.max_entries is not None and self.params.max_entries <= 0:
            return FlextResult.fail("Max entries must be greater than 0")

        return FlextResult.ok(None)

    def execute(self) -> FlextResult[object]:
        """Execute LDIF parsing using flext-cli patterns."""
        self.flext_cli_print_info(f"Parsing LDIF file: {self.params.input_file}")

        try:
            # Create API with configuration
            if self.params.max_entries:
                config = FlextLdifConfig(max_entries=self.params.max_entries)
                api = FlextLdifAPI(config)
            else:
                api = FlextLdifAPI()

            # Parse file
            parse_result = api.parse_file(self.params.input_file)
            if parse_result.is_failure or parse_result.data is None:
                self.flext_cli_print_error(f"Parse failed: {parse_result.error}")
                return FlextResult.fail(parse_result.error or "Parse failed")

            entries = parse_result.data
            self.flext_cli_print_success(f"Parsed {len(entries)} entries successfully")

            # Optional validation
            if self.params.validate:
                self.flext_cli_print_info("Validating entries...")
                validation_errors = self._validate_entries(entries)
                if validation_errors:
                    self.flext_cli_print_warning(f"Found {len(validation_errors)} validation errors")
                    for error in validation_errors[:5]:  # Show first 5
                        self.flext_cli_print_info(f"  - {error}")
                    if len(validation_errors) > 5:
                        self.flext_cli_print_info(f"  ... and {len(validation_errors) - 5} more")
                else:
                    self.flext_cli_print_success("All entries are valid")

            # Handle output
            if self.params.output_file:
                write_result = api.write_file(entries, self.params.output_file)
                if write_result.is_success:
                    self.flext_cli_print_success(f"Entries written to {self.params.output_file}")
                else:
                    self.flext_cli_print_error(f"Write failed: {write_result.error}")
                    return FlextResult.fail(write_result.error or "Write failed")
            elif self.params.stats:
                self._display_statistics(api, entries)

            return FlextResult.ok({"entries": len(entries), "file": self.params.input_file})

        except Exception as e:
            self.flext_cli_print_error(f"Parse error: {e}")
            return FlextResult.fail(str(e))

    def _validate_entries(self, entries: list[FlextLdifEntry]) -> list[str]:
        """Validate entries and return error messages."""
        validation_errors = []
        for i, entry in enumerate(entries):
            validation_result = entry.validate_business_rules()
            if validation_result.is_failure:
                validation_errors.append(f"Entry {i + 1} ({entry.dn}): {validation_result.error}")
        return validation_errors

    def _display_statistics(self, api: FlextLdifAPI, entries: list[FlextLdifEntry]) -> None:
        """Display entry statistics using Rich formatting."""
        stats_result = api.get_entry_statistics(entries)
        if stats_result.is_success and stats_result.data:
            stats = stats_result.data

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Statistic", style="cyan")
            table.add_column("Value", style="white")

            for key, value in stats.items():
                table.add_row(key, str(value))

            console.print("\n[bold cyan]LDIF Statistics:[/bold cyan]")
            console.print(table)
        else:
            self.flext_cli_print_error(f"Failed to get statistics: {stats_result.error}")


class FlextLdifValidateCommand(FlextCliEntity, FlextCliAdvancedMixin):
    """LDIF validation using modern flext-cli patterns with zero boilerplate."""

    def __init__(self, command_id: str, name: str, params: LDIFValidateParams) -> None:
        super().__init__(id=command_id, name=name)
        self.params = params
        FlextCliAdvancedMixin.__init__(self)

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate LDIF validation parameters."""
        if not Path(self.params.input_file).exists():
            return FlextResult.fail(f"Input file does not exist: {self.params.input_file}")

        return FlextResult.ok(None)

    def execute(self) -> FlextResult[object]:
        """Execute LDIF validation using flext-cli patterns."""
        mode = "strict" if self.params.strict else "standard"
        self.flext_cli_print_info(f"Validating LDIF file in {mode} mode: {self.params.input_file}")

        try:
            # Create API with appropriate configuration
            if self.params.strict:
                config = FlextLdifConfig(strict_validation=True)
                api = FlextLdifAPI(config)
            else:
                api = FlextLdifAPI()

            # Parse file
            parse_result = api.parse_file(self.params.input_file)
            if parse_result.is_failure or parse_result.data is None:
                self.flext_cli_print_error(f"Parse failed: {parse_result.error}")
                return FlextResult.fail(parse_result.error or "Parse failed")

            entries = parse_result.data
            self.flext_cli_print_info(f"Loaded {len(entries)} entries for validation")

            # Schema validation info
            if self.params.schema:
                self.flext_cli_print_info(f"Using schema validation rules: {self.params.schema}")
                self.flext_cli_print_warning("Schema-based validation will be implemented with flext-ldap integration")

            # Validate entries
            validation_errors = []
            for i, entry in enumerate(entries):
                validation_result = entry.validate_business_rules()
                if validation_result.is_failure:
                    validation_errors.append(f"Entry {i + 1} ({entry.dn}): {validation_result.error}")

            # Display results
            if validation_errors:
                self.flext_cli_print_error(f"Validation failed with {len(validation_errors)} errors")
                for error in validation_errors:
                    self.flext_cli_print_info(f"  - {error}")
                return FlextResult.fail(f"Validation failed with {len(validation_errors)} errors")
            self.flext_cli_print_success(f"✓ All {len(entries)} entries are valid ({mode} mode)")
            return FlextResult.ok({"entries": len(entries), "valid": True, "mode": mode})

        except Exception as e:
            self.flext_cli_print_error(f"Validation error: {e}")
            return FlextResult.fail(str(e))


class FlextLdifTransformCommand(FlextCliEntity, FlextCliAdvancedMixin):
    """LDIF transformation using modern flext-cli patterns with zero boilerplate."""

    def __init__(self, command_id: str, name: str, params: LDIFTransformParams) -> None:
        super().__init__(id=command_id, name=name)
        self.params = params
        FlextCliAdvancedMixin.__init__(self)

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate LDIF transformation parameters."""
        if not Path(self.params.input_file).exists():
            return FlextResult.fail(f"Input file does not exist: {self.params.input_file}")

        if self.params.filter_type and self.params.filter_type not in {"persons", "groups", "ous", "valid"}:
            return FlextResult.fail(f"Invalid filter type: {self.params.filter_type}")

        return FlextResult.ok(None)

    def execute(self) -> FlextResult[object]:
        """Execute LDIF transformation using flext-cli patterns."""
        self.flext_cli_print_info(f"Transforming LDIF file: {self.params.input_file}")

        try:
            api = FlextLdifAPI()

            # Parse input
            parse_result = api.parse_file(self.params.input_file)
            if parse_result.is_failure or parse_result.data is None:
                self.flext_cli_print_error(f"Parse failed: {parse_result.error}")
                return FlextResult.fail(parse_result.error or "Parse failed")

            entries = parse_result.data
            original_count = len(entries)
            self.flext_cli_print_info(f"Loaded {original_count} entries")

            # Apply filtering
            if self.params.filter_type:
                self.flext_cli_print_info(f"Applying {self.params.filter_type} filter...")
                entries = self._apply_filter(api, entries, self.params.filter_type)
                self.flext_cli_print_info(f"Filtered to {len(entries)} entries")

            # Apply sorting
            if self.params.sort:
                self.flext_cli_print_info("Sorting entries hierarchically...")
                sort_result = api.sort_hierarchically(entries)
                if sort_result.is_success and sort_result.data is not None:
                    entries = sort_result.data
                    self.flext_cli_print_success("Entries sorted hierarchically")
                else:
                    self.flext_cli_print_warning(f"Sort failed: {sort_result.error}")

            # Write output
            write_result = api.write_file(entries, self.params.output_file)
            if write_result.is_success:
                self.flext_cli_print_success(f"Transformed entries written to {self.params.output_file}")
                return FlextResult.ok({
                    "original_count": original_count,
                    "final_count": len(entries),
                    "output_file": self.params.output_file,
                })
            self.flext_cli_print_error(f"Write failed: {write_result.error}")
            return FlextResult.fail(write_result.error or "Write failed")

        except Exception as e:
            self.flext_cli_print_error(f"Transform error: {e}")
            return FlextResult.fail(str(e))

    def _apply_filter(self, api: FlextLdifAPI, entries: list[FlextLdifEntry], filter_type: str) -> list[FlextLdifEntry]:
        """Apply filtering to entries based on filter type."""
        try:
            if filter_type == "persons":
                result = api.filter_persons(entries)
            elif filter_type == "groups":
                result = api.filter_groups(entries)
            elif filter_type == "ous":
                result = api.filter_organizational_units(entries)
            elif filter_type == "valid":
                result = api.filter_valid(entries)
            else:
                return entries

            if result.is_success and result.data is not None:
                return result.data
            self.flext_cli_print_warning(f"Filter failed: {result.error}")
            return entries

        except Exception as e:
            self.flext_cli_print_warning(f"Filter error: {e}")
            return entries


class FlextLdifStatsCommand(FlextCliEntity, FlextCliAdvancedMixin):
    """LDIF statistics using modern flext-cli patterns with zero boilerplate."""

    def __init__(self, command_id: str, name: str, params: LDIFStatsParams) -> None:
        super().__init__(id=command_id, name=name)
        self.params = params
        FlextCliAdvancedMixin.__init__(self)

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate LDIF statistics parameters."""
        if not Path(self.params.input_file).exists():
            return FlextResult.fail(f"Input file does not exist: {self.params.input_file}")

        if self.params.stats_format not in {"json", "yaml", "table"}:
            return FlextResult.fail(f"Invalid stats format: {self.params.stats_format}")

        return FlextResult.ok(None)

    def execute(self) -> FlextResult[object]:
        """Execute LDIF statistics using flext-cli patterns."""
        self.flext_cli_print_info(f"Generating statistics for: {self.params.input_file}")

        try:
            api = FlextLdifAPI()

            # Parse file
            parse_result = api.parse_file(self.params.input_file)
            if parse_result.is_failure or parse_result.data is None:
                self.flext_cli_print_error(f"Parse failed: {parse_result.error}")
                return FlextResult.fail(parse_result.error or "Parse failed")

            entries = parse_result.data
            self.flext_cli_print_info(f"Analyzing {len(entries)} entries")

            # Get statistics
            stats_result = api.get_entry_statistics(entries)
            if stats_result.is_failure or stats_result.data is None:
                self.flext_cli_print_error(f"Statistics failed: {stats_result.error}")
                return FlextResult.fail(stats_result.error or "Statistics failed")

            statistics = stats_result.data

            # Display in requested format
            if self.params.stats_format == "json":
                json_output = json.dumps(statistics, indent=2)
                console.print("[bold cyan]Statistics (JSON):[/bold cyan]")
                console.print(json_output)
            elif self.params.stats_format == "yaml":
                yaml_output = yaml.dump(statistics, default_flow_style=False)
                console.print("[bold cyan]Statistics (YAML):[/bold cyan]")
                console.print(yaml_output)
            else:
                # Table format (default)
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("Statistic", style="cyan")
                table.add_column("Value", style="white")

                for key, value in statistics.items():
                    table.add_row(key, str(value))

                console.print("\n[bold cyan]LDIF Statistics:[/bold cyan]")
                console.print(table)

            self.flext_cli_print_success("Statistics generated successfully")
            return FlextResult.ok({"statistics": statistics, "format": self.params.stats_format})

        except Exception as e:
            self.flext_cli_print_error(f"Statistics error: {e}")
            return FlextResult.fail(str(e))


# =============================================================================
# MODERN CLICK CLI WITH FLEXT-CLI INTEGRATION
# =============================================================================


@click.group(name="flext-ldif")
@click.version_option(version="0.9.0", prog_name="FLEXT LDIF")
@click.help_option("--help", "-h")
def cli() -> None:
    """FLEXT LDIF - Modern Enterprise LDIF Processing.

    Modern CLI using flext-cli foundation with zero boilerplate.
    Built on Clean Architecture patterns with flext-core integration.
    """
    # Initialize flext-cli
    cli_config_result = create_flext_cli_config(
        debug=False,
        profile="flext-ldif",
    )

    if cli_config_result.is_failure:
        console.print(f"[red]CLI configuration failed: {cli_config_result.error}[/red]")
        return

    setup_result = setup_flext_cli(cli_config_result.data)
    if setup_result.is_failure:
        console.print(f"[red]CLI setup failed: {setup_result.error}[/red]")
        return


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--max-entries", type=int, help="Maximum entries to parse")
@click.option("--validate", is_flag=True, help="Validate entries after parsing")
@click.option("--stats", is_flag=True, help="Display statistics instead of writing output")
def parse(input_file: str, **kwargs) -> None:
    """Parse LDIF file and display or save entries using modern flext-cli patterns.

    Example:
        flext-ldif parse input.ldif --output output.ldif
        flext-ldif parse input.ldif --stats --validate

    """
    import uuid

    params = LDIFParseParams.from_click_args(input_file, **kwargs)

    command = FlextLdifParseCommand(
        command_id=str(uuid.uuid4()),
        name="ldif-parse",
        params=params,
    )

    result = command.execute()
    if result.is_failure:
        console.print(f"[red]Parse failed: {result.error}[/red]")
        sys.exit(1)


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--strict", is_flag=True, help="Enable strict validation mode")
@click.option("--schema", type=str, help="Schema validation rules")
def validate(input_file: str, **kwargs) -> None:
    """Validate LDIF file entries against schema rules using modern flext-cli patterns.

    Example:
        flext-ldif validate input.ldif --strict
        flext-ldif validate input.ldif --schema rules.json

    """
    import uuid

    params = LDIFValidateParams.from_click_args(input_file, **kwargs)

    command = FlextLdifValidateCommand(
        command_id=str(uuid.uuid4()),
        name="ldif-validate",
        params=params,
    )

    result = command.execute()
    if result.is_failure:
        console.print(f"[red]Validation failed: {result.error}[/red]")
        sys.exit(1)


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.argument("output_file", type=click.Path())
@click.option("--filter-type", type=click.Choice(["persons", "groups", "ous", "valid"]), help="Filter entry type")
@click.option("--sort", is_flag=True, help="Sort entries hierarchically")
def transform(input_file: str, output_file: str, **kwargs) -> None:
    """Transform LDIF file with filtering and sorting options using modern flext-cli patterns.

    Example:
        flext-ldif transform input.ldif output.ldif --filter-type persons --sort
        flext-ldif transform input.ldif output.ldif --filter-type valid

    """
    import uuid

    params = LDIFTransformParams.from_click_args(input_file, output_file, **kwargs)

    command = FlextLdifTransformCommand(
        command_id=str(uuid.uuid4()),
        name="ldif-transform",
        params=params,
    )

    result = command.execute()
    if result.is_failure:
        console.print(f"[red]Transform failed: {result.error}[/red]")
        sys.exit(1)


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--format", "-f", "stats_format", type=click.Choice(["json", "yaml", "table"]), default="table", help="Statistics format")
def stats(input_file: str, **kwargs) -> None:
    """Display comprehensive statistics for LDIF file using modern flext-cli patterns.

    Example:
        flext-ldif stats input.ldif
        flext-ldif stats input.ldif --format json

    """
    import uuid

    params = LDIFStatsParams.from_click_args(input_file, **kwargs)

    command = FlextLdifStatsCommand(
        command_id=str(uuid.uuid4()),
        name="ldif-stats",
        params=params,
    )

    result = command.execute()
    if result.is_failure:
        console.print(f"[red]Statistics failed: {result.error}[/red]")
        sys.exit(1)


@cli.command()
def version() -> None:
    """Show version information."""
    console.print("FLEXT LDIF v0.9.0", style="bold green")
    console.print("Modern Enterprise LDIF Processing with flext-cli integration", style="dim")
    console.print("Built on Clean Architecture with zero boilerplate", style="dim")


def main() -> None:
    """Main CLI entry point using flext-cli patterns."""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("[blue]Operation cancelled by user[/blue]")
        raise SystemExit(0) from None
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        raise SystemExit(1) from e


if __name__ == "__main__":
    main()
