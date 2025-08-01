#!/usr/bin/env python3
"""CLI integration example.

Demonstrates integration with flext-cli patterns and programmatic
CLI usage for enterprise automation scenarios.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from flext_cli import get_config

from flext_ldif import FlextLdifAPI, FlextLdifConfig


def run_cli_command(command_args: list[str]) -> tuple[int, str, str]:
    """Run flext-ldif CLI command programmatically.

    Args:
        command_args: CLI command arguments

    Returns:
        Tuple of (exit_code, stdout, stderr)

    """
    try:
        # Build command
        cmd = ["poetry", "run", "flext-ldif", *command_args]

        # Execute
        result = subprocess.run(
            cmd,
            check=False, capture_output=True,
            text=True,
            timeout=30,
        )

        return result.returncode, result.stdout, result.stderr

    except subprocess.TimeoutExpired:
        return 124, "", "Command timed out"
    except Exception as e:
        return 1, "", str(e)


def main() -> None:
    """Demonstrate CLI integration patterns."""
    # Test flext-cli configuration integration
    get_config()

    # Create sample files for CLI testing
    sample_file = Path(__file__).parent / "sample_basic.ldif"
    output_file = Path(__file__).parent / "cli_output.ldif"

    # Test 1: Parse command
    exit_code, stdout, stderr = run_cli_command([
        "parse", str(sample_file),
    ])

    if exit_code == 0:
        pass

    # Test 2: Validation command
    exit_code, stdout, stderr = run_cli_command([
        "validate", str(sample_file), "--strict",
    ])

    if exit_code == 0:
        pass

    # Test 3: Statistics command with JSON output
    exit_code, stdout, stderr = run_cli_command([
        "stats", str(sample_file), "--format", "json",
    ])

    if exit_code == 0:
        pass

    # Test 4: Transform command with filtering
    exit_code, stdout, stderr = run_cli_command([
        "transform", str(sample_file), str(output_file),
        "--filter-type", "persons",
    ])

    if exit_code == 0:

        # Check if output file was created
        if output_file.exists():

            # Parse the output file to verify
            api = FlextLdifAPI()
            result = api.parse_file(output_file)
            if result.is_success and result.data:
                pass

            # Clean up
            output_file.unlink()

    # Test 5: Convert command to JSON
    json_output = Path(__file__).parent / "cli_output.json"

    exit_code, stdout, stderr = run_cli_command([
        "convert", str(sample_file), str(json_output),
        "--output-format", "json",
    ])

    if exit_code == 0 and json_output.exists():
        # Clean up
        json_output.unlink()

    # Test 6: Config check command
    exit_code, stdout, stderr = run_cli_command(["config-check"])

    if exit_code == 0:
        pass

    # Test 7: Global options
    exit_code, _stdout, _stderr = run_cli_command([
        "--format", "yaml", "--verbose", "--debug",
        "stats", str(sample_file),
    ])

    if exit_code == 0:
        pass

    # Demonstrate programmatic API usage alongside CLI

    # Create API with custom configuration
    config = FlextLdifConfig(
        strict_validation=True,
        max_entries=10,
    )
    api = FlextLdifAPI(config)

    # Parse and process
    result = api.parse_file(sample_file)
    if result.is_success and result.data:
        entries = result.data
        stats = api.get_entry_statistics(entries)

        for _key, _value in stats.items():
            pass


if __name__ == "__main__":
    main()
