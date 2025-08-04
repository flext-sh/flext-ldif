"""FLEXT-LDIF CLI Utilities.

This module provides comprehensive CLI utilities and helper functions for
FLEXT-LDIF command-line interface operations, implementing consistent user
interaction patterns, output formatting, and error handling across all CLI commands.

Key Components:
    - CLI result validation and error reporting
    - Consistent output formatting and user feedback
    - File operation helpers with proper error handling
    - User interaction utilities with confirmation patterns

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, NoReturn

import click

if TYPE_CHECKING:
    from flext_core import FlextResult


def validate_cli_result[T](result: FlextResult[T], operation_name: str) -> None:
    """Validate CLI result and exit with error if invalid using Railway-Oriented Programming.

    This function consolidates the repeated pattern of validating CLI results
    and provides consistent error handling across all CLI commands following
    enterprise-grade error reporting standards with structured logging.

    Args:
        result: The FlextResult object to validate with success/failure state
        operation_name: Name of the operation for error messages and logging context

    Raises:
        SystemExit: If result is invalid (exits with code 1) after displaying error

    Example:
        >>> from flext_core import FlextResult
        >>> success_result = FlextResult.ok("data")
        >>> validate_cli_result(success_result, "Parse operation")  # No exception
        >>>
        >>> failure_result = FlextResult.fail("Parse error")
        >>> validate_cli_result(failure_result, "Parse operation")  # SystemExit(1)

    """
    if not hasattr(result, "success") or not result.success:
        error_msg = getattr(result, "error", "Unknown error")
        click.echo(f"{operation_name} failed: {error_msg}", err=True)
        sys.exit(1)

    if not hasattr(result, "data") or result.data is None:
        click.echo(f"{operation_name} failed: No data returned", err=True)
        sys.exit(1)


def handle_parse_result[T](result: FlextResult[T], file_path: str) -> None:
    """Handle parsing result with consistent error reporting and file context.

    This function consolidates the repeated pattern of handling parse results
    across different CLI commands, providing comprehensive error context including
    file path information and data validation checks.

    Args:
        result: The FlextResult from parsing operation with success/failure state
        file_path: Path to the file being parsed for error context

    Raises:
        SystemExit: If parsing failed (exits with code 1) after displaying detailed error

    Example:
        >>> from flext_core import FlextResult
        >>> success_result = FlextResult.ok([])  # Empty but valid
        >>> handle_parse_result(
        ...     success_result, "/path/to/file.ldif"
        ... )  # SystemExit (no entries)
        >>>
        >>> failure_result = FlextResult.fail("Invalid LDIF format")
        >>> handle_parse_result(failure_result, "/path/to/file.ldif")  # SystemExit(1)

    """
    if not result.success:
        error_msg = result.error or "Parsing failed"
        click.echo(f"Failed to parse LDIF file '{file_path}': {error_msg}", err=True)
        sys.exit(1)

    if not result.data:
        click.echo(f"No entries found in LDIF file: {file_path}", err=True)
        sys.exit(1)


def handle_file_operation_result[T](
    result: FlextResult[T],
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
    if not result.success:
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
