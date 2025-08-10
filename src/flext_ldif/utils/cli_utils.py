"""FLEXT-LDIF CLI Utilities - Command Line Interface Helpers.

This module provides utilities for CLI operations including user interaction,
output formatting, and display functions using Click integration.

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from __future__ import annotations

import click
from flext_core import FlextResult, get_logger

logger = get_logger(__name__)


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
        # Check if result has expected CLI result attributes
        if hasattr(result, "exit_code"):
            if result.exit_code == 0:
                return FlextResult.ok(True)
            return FlextResult.fail(
                f"CLI command failed with exit code {result.exit_code}",
            )

        # For other result types, check if it's truthy
        if result:
            return FlextResult.ok(True)
        return FlextResult.fail("CLI result validation failed")

    except Exception as e:
        logger.exception("CLI result validation error", error=str(e))
        return FlextResult.fail(f"CLI validation error: {e}")
