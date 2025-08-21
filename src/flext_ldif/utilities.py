"""FLEXT-LDIF Utilities.

Utility functions and classes following flext-core patterns.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import TYPE_CHECKING, TypeVar

import click
from flext_core import FlextResult

if TYPE_CHECKING:
    from flext_ldif.api import FlextLdifAPI
    from flext_ldif.models import FlextLdifEntry

T = TypeVar("T")


class FlextLdifUtilities:
    """Utility class for FLEXT-LDIF operations using static methods."""

    @staticmethod
    def parse_file_or_exit(api: FlextLdifAPI, file_path: str) -> list[FlextLdifEntry]:
        """Parse file using railway-oriented programming with exit on failure."""

        def exit_on_error(error: str) -> None:
            click.echo(f"Failed to parse file: {error}", err=True)
            sys.exit(1)

        return api.parse_file(file_path).tap_error(exit_on_error).unwrap_or([])

    @staticmethod
    def write_result_or_exit(
        result: FlextResult[T], operation_name: str = "operation"
    ) -> T:
        """Extract result value or exit with error message."""

        def exit_on_error(error: str) -> None:
            click.echo(f"Failed to {operation_name}: {error}", err=True)
            sys.exit(1)

        result.tap_error(exit_on_error)
        return result.unwrap()  # This will also exit via tap_error if failure

    @staticmethod
    def validate_entries_or_warn(
        entries: list[FlextLdifEntry], max_warnings: int = 5
    ) -> list[str]:
        """Validate entries and return warning messages."""
        warnings: list[str] = []

        for i, entry in enumerate(entries):
            if i >= max_warnings:
                warnings.append(f"... and {len(entries) - max_warnings} more entries")
                break

            # Use default parameters to properly capture loop variables
            def handle_error(
                error: str, entry_num: int = i + 1, entry_dn: object = entry.dn
            ) -> None:
                warnings.append(f"Entry {entry_num} ({entry_dn}): {error}")

            entry.validate_business_rules().tap_error(handle_error)

        return warnings

    @staticmethod
    def railway_filter_entries(
        api: FlextLdifAPI, entries: list[FlextLdifEntry], filter_operation: str
    ) -> list[FlextLdifEntry]:
        """Apply filter using railway-oriented programming."""
        filter_methods: dict[
            str, Callable[[list[FlextLdifEntry]], FlextResult[list[FlextLdifEntry]]]
        ] = {
            "persons": api.filter_persons,
            "groups": api.filter_groups,
            "ous": api.filter_organizational_units,
            "valid": api.filter_valid,
        }

        filter_func = filter_methods.get(filter_operation)
        if not filter_func:
            click.echo(f"Unknown filter type: {filter_operation}", err=True)
            return entries

        return filter_func(entries).unwrap_or(entries)

    @staticmethod
    def process_result_with_default[T](
        result: FlextResult[T],
        default: T,
        success_action: Callable[[T], None] | None = None,
        error_action: Callable[[str], None] | None = None,
    ) -> T:
        """Process FlextResult with railway programming patterns.

        Args:
            result: FlextResult to process
            default: Default value if result fails
            success_action: Optional action to perform on success
            error_action: Optional action to perform on error

        Returns:
            Result value or default

        """
        if success_action:
            result.tap(success_action)
        if error_action:
            result.tap_error(error_action)
        return result.unwrap_or(default)


__all__ = ["FlextLdifUtilities"]
