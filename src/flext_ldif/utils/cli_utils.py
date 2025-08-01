"""CLI utilities for flext-ldif to reduce CLI result processing duplication.

This module provides common CLI patterns used throughout the CLI module,
reducing code duplication and providing consistent error handling.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any, NoReturn

import click

if TYPE_CHECKING:
    from flext_core import FlextResult


def validate_cli_result(result: FlextResult[Any], operation_name: str) -> None:
    """Validate CLI result and exit with error if invalid.

    This function consolidates the repeated pattern of validating CLI results
    and provides consistent error handling across all CLI commands.

    Args:
        result: The result object to validate
        operation_name: Name of the operation for error messages

    Raises:
        SystemExit: If result is invalid (exits with code 1)

    """
    if not hasattr(result, "is_success") or not result.is_success:
        error_msg = getattr(result, "error", "Unknown error")
        click.echo(f"{operation_name} failed: {error_msg}", err=True)
        sys.exit(1)

    if not hasattr(result, "data") or result.data is None:
        click.echo(f"{operation_name} failed: No data returned", err=True)
        sys.exit(1)


def handle_parse_result(result: FlextResult[Any], file_path: str) -> None:
    """Handle parsing result with consistent error reporting.

    This function consolidates the repeated pattern of handling parse results
    across different CLI commands.

    Args:
        result: The FlextResult from parsing operation
        file_path: Path to the file being parsed

    Raises:
        SystemExit: If parsing failed (exits with code 1)

    """
    if not result.is_success:
        error_msg = result.error or "Parsing failed"
        click.echo(f"Failed to parse LDIF file '{file_path}': {error_msg}", err=True)
        sys.exit(1)

    if not result.data:
        click.echo(f"No entries found in LDIF file: {file_path}", err=True)
        sys.exit(1)


def handle_file_operation_result(
    result: FlextResult[Any],
    operation: str,
    file_path: str,
) -> None:
    """Handle file operation result with consistent error reporting.

    Args:
        result: The FlextResult from file operation
        operation: Name of the file operation (e.g., "read", "write")
        file_path: Path to the file being operated on

    Raises:
        SystemExit: If operation failed (exits with code 1)

    """
    if not result.is_success:
        error_msg = result.error or f"{operation.capitalize()} operation failed"
        click.echo(f"Failed to {operation} file '{file_path}': {error_msg}", err=True)
        sys.exit(1)


def safe_click_echo(message: str, *, err: bool = False) -> None:
    """Safely echo messages to CLI with error handling.

    Args:
        message: Message to display
        err: Whether to write to stderr

    """
    try:
        click.echo(message, err=err)
    except (BrokenPipeError, KeyboardInterrupt):
        # Handle broken pipe (e.g., when piping to head)
        # and keyboard interrupt gracefully
        sys.exit(1)


def exit_with_error(error_message: str, exit_code: int = 1) -> NoReturn:
    """Exit CLI with error message and code.

    Args:
        error_message: Error message to display
        exit_code: Exit code (default: 1)

    Raises:
        SystemExit: Always exits with specified code

    """
    click.echo(f"Error: {error_message}", err=True)
    sys.exit(exit_code)


def display_success_message(operation: str, details: str = "") -> None:
    """Display success message with consistent formatting.

    Args:
        operation: Name of the successful operation
        details: Optional additional details

    """
    message = f"✓ {operation} completed successfully"
    if details:
        message += f": {details}"
    safe_click_echo(message)


def display_entry_count(count: int, item_type: str = "entries") -> None:
    """Display entry count with consistent formatting.

    Args:
        count: Number of items
        item_type: Type of items (default: "entries")

    """
    safe_click_echo(f"Found {count} {item_type}")


def confirm_operation(prompt: str, *, default: bool = False) -> bool:
    """Confirm operation with user prompt.

    Args:
        prompt: Confirmation prompt
        default: Default value if user just presses Enter

    Returns:
        True if user confirmed, False otherwise

    """
    return click.confirm(prompt, default=default)
