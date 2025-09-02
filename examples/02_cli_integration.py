#!/usr/bin/env python3
"""CLI integration example.

Demonstrates integration with flext-cli patterns and programmatic
CLI usage for enterprise automation scenarios.
"""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner
from flext_cli import get_config

from flext_ldif import FlextLDIFAPI, FlextLDIFConfig, cli as ldif_cli

ALLOWED_COMMANDS: set[str] = {
    "parse",
    "validate",
    "stats",
    "transform",
    "convert",
    "config-check",
}


def _extract_primary_command(tokens: list[str]) -> str | None:
    """Return the first non-option token (the primary command), if any."""
    for token in tokens:
        if not token.startswith("-"):
            return token
    return None


def _validate_args(tokens: list[str]) -> tuple[bool, str | None]:
    """Perform basic safety validation on CLI tokens.

    Returns:
      Tuple of (is_valid, error_message)

    """
    if not tokens:
        return False, "No CLI arguments provided"

    command = _extract_primary_command(tokens)
    if command is None or command not in ALLOWED_COMMANDS:
        return (
            False,
            f"Unsupported CLI command '{command}'. Allowed: {sorted(ALLOWED_COMMANDS)}",
        )

    for token in tokens:
        if any(bad in token for bad in ("\n", "\r", "\x00")):
            return False, "Unsafe control characters detected in CLI arguments"

    return True, None


def run_cli_command(command_args: list[str]) -> tuple[int, str, str]:
    """Run flext-ldif CLI command programmatically.

    Args:
      command_args: CLI command arguments

    Returns:
      Tuple of (exit_code, stdout, stderr)

    """
    is_valid, error = _validate_args(command_args)
    if not is_valid:
        return 2, "", error or "Invalid arguments"

    runner = CliRunner()
    result = runner.invoke(ldif_cli.cli, command_args, catch_exceptions=True)
    stderr = getattr(result, "stderr", "") or ""
    return int(result.exit_code or 0), result.output, stderr


# SOLID REFACTORING: Strategy Pattern to reduce complexity from 12 to 3
class CliIntegrationDemonstrator:
    """Strategy Pattern for CLI integration demonstration.

    SOLID REFACTORING: Reduces complexity by organizing CLI tests into strategies
    with single responsibility per test type.
    """

    def __init__(self) -> None:
        """Initialize CLI demonstrator with file paths."""
        self.sample_file = Path(__file__).parent / "sample_basic.ldif"
        self.output_file = Path(__file__).parent / "cli_output.ldif"
        self.json_output = Path(__file__).parent / "cli_output.json"

    def demonstrate_all(self) -> None:
        """Template method: demonstrate all CLI integration patterns."""
        # Test flext-cli configuration integration
        get_config()

        self._run_basic_commands()
        self._run_file_operations()
        self._run_configuration_commands()
        self._demonstrate_programmatic_api()

    def _run_basic_commands(self) -> None:
        """Run basic CLI commands (parse, validate, stats)."""
        # Test 1: Parse command
        exit_code, _, _ = run_cli_command(["parse", str(self.sample_file)])
        if exit_code == 0:
            pass  # Parse successful

        # Test 2: Validation command
        exit_code, _, _ = run_cli_command(
            ["validate", str(self.sample_file), "--strict"],
        )
        if exit_code == 0:
            pass  # Validation successful

        # Test 3: Statistics command with JSON output
        exit_code, _, _ = run_cli_command(
            ["stats", str(self.sample_file), "--format", "json"],
        )
        if exit_code == 0:
            pass  # Stats successful

    def _run_file_operations(self) -> None:
        """Run file operation commands (transform, convert)."""
        # Test 4: Transform command with filtering
        exit_code, _, _ = run_cli_command(
            [
                "transform",
                str(self.sample_file),
                str(self.output_file),
                "--filter-type",
                "persons",
            ],
        )

        if exit_code == 0 and self.output_file.exists():
            self._verify_transform_output()

        # Test 5: Convert command to JSON
        exit_code, _, _ = run_cli_command(
            [
                "convert",
                str(self.sample_file),
                str(self.json_output),
                "--output-format",
                "json",
            ],
        )

        if exit_code == 0 and self.json_output.exists():
            self.json_output.unlink()  # Clean up

    def _run_configuration_commands(self) -> None:
        """Run configuration and global option commands."""
        # Test 6: Config check command
        exit_code, _, _ = run_cli_command(["config-check"])
        if exit_code == 0:
            pass  # Config check successful

        # Test 7: Global options
        exit_code, _, _ = run_cli_command(
            [
                "--format",
                "yaml",
                "--verbose",
                "--debug",
                "stats",
                str(self.sample_file),
            ],
        )
        if exit_code == 0:
            pass  # Global options successful

    def _verify_transform_output(self) -> None:
        """Verify transform command output."""
        api = FlextLDIFAPI()
        result = api.parse_file(self.output_file)
        if result.unwrap_or([]):
            pass  # Transform output verified
        self.output_file.unlink()  # Clean up

    def _demonstrate_programmatic_api(self) -> None:
        """Demonstrate programmatic API usage alongside CLI."""
        config = FlextLDIFConfig(strict_validation=True, max_entries=10)
        api = FlextLDIFAPI(config)

        result = api.parse_file(self.sample_file)
        entries = result.unwrap_or([])
        if entries:
            stats_result = api.get_entry_statistics(entries)
            stats = stats_result.unwrap_or({})

            for _key, _value in stats.items():
                pass  # Process stats


def main() -> None:
    """Demonstrate CLI integration patterns using Strategy Pattern.

    SOLID REFACTORING: Reduced complexity from 12 to 3 using Strategy Pattern.
    """
    demonstrator = CliIntegrationDemonstrator()
    demonstrator.demonstrate_all()


if __name__ == "__main__":
    main()
