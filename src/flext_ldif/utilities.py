"""FLEXT-LDIF Utilities.

Utility functions and classes following flext-core patterns.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import TYPE_CHECKING, TypeVar

import click
from flext_core import FlextResult
from flext_core.decorators import FlextCallable

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

    @staticmethod
    def safe_execute_callable(
        func: FlextCallable,
        *args: object,
        **kwargs: object,
    ) -> object:
        """Safely execute a FlextCallable function.

        This demonstrates use of FlextCallable type and safe execution pattern.

        Args:
            func: FlextCallable function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Function result or None on error

        """
        # FlextCallable is a type alias for Callable, so this check is always True
        # Keeping the function for API compatibility
        return func(*args, **kwargs)

    @staticmethod
    def create_processing_pipeline(
        *operations: FlextCallable,
    ) -> Callable[[object], object]:
        """Create a processing pipeline using FlextCallable functions.

        This demonstrates functional composition with FlextCallable.

        Args:
            *operations: Sequence of FlextCallable operations to chain

        Returns:
            Composed function that applies all operations in sequence

        """

        def pipeline(initial_value: object) -> object:
            result = initial_value
            for operation in operations:
                if callable(operation):
                    result = operation(result)
            return result

        return pipeline

    @staticmethod
    def validate_callable_chain(
        *functions: FlextCallable,
    ) -> bool:
        """Validate that all functions in a chain are proper FlextCallables.

        Args:
            *functions: Functions to validate

        Returns:
            True if all functions are valid FlextCallables

        """
        return all(callable(func) for func in functions)

    @staticmethod
    def count_entries_by_objectclass(
        entries: list[FlextLdifEntry], objectclass: str
    ) -> int:
        """Count entries that have a specific objectClass.

        Cached utility for performance optimization when counting frequently.

        Args:
            entries: List of LDIF entries to search
            objectclass: ObjectClass to count

        Returns:
            Number of entries with the specified objectClass

        """
        return sum(
            1
            for entry in entries
            if objectclass.lower()
            in [oc.lower() for oc in (entry.get_attribute("objectClass") or [])]
        )

    @staticmethod
    def batch_validate_entries(
        api: FlextLdifAPI, entries: list[FlextLdifEntry], batch_size: int = 100
    ) -> FlextResult[list[bool]]:
        """Validate entries in batches for better performance with large datasets.

        Args:
            api: FlextLdifAPI instance for validation
            entries: List of entries to validate
            batch_size: Size of each validation batch

        Returns:
            FlextResult containing list of validation results

        """
        results: list[bool] = []

        for i in range(0, len(entries), batch_size):
            batch = entries[i : i + batch_size]
            batch_result = api.validate(batch)

            # Handle batch success or fall back to individual validation
            if batch_result.is_success:
                # Use railway programming to handle success case
                validation_result = bool(batch_result.value)
                results.extend([validation_result] * len(batch))
                continue
            # Individual validation on batch failure
            for entry in batch:
                entry_result = api.validate_entry(entry)
                default_validation = False
                results.append(entry_result.unwrap_or(default_validation))

        return FlextResult[list[bool]].ok(results)

    @staticmethod
    def create_ldif_summary_stats(entries: list[FlextLdifEntry]) -> dict[str, object]:
        """Create comprehensive summary statistics for LDIF entries.

        Args:
            entries: List of entries to analyze

        Returns:
            Dictionary with summary statistics

        """
        if not entries:
            return {
                "total_entries": 0,
                "unique_objectclasses": 0,
                "avg_attributes_per_entry": 0,
            }

        # Count unique objectClasses
        all_objectclasses: set[str] = set()
        total_attributes = 0

        for entry in entries:
            objectclasses = entry.get_attribute("objectClass") or []
            all_objectclasses.update(oc.lower() for oc in objectclasses)
            total_attributes += len(entry.attributes.attributes)

        return {
            "total_entries": len(entries),
            "unique_objectclasses": len(all_objectclasses),
            "objectclass_list": sorted(all_objectclasses),
            "avg_attributes_per_entry": round(total_attributes / len(entries), 2),
            "total_attributes": total_attributes,
        }

    @staticmethod
    def find_entries_by_pattern(
        entries: list[FlextLdifEntry], dn_pattern: str
    ) -> list[FlextLdifEntry]:
        """Find entries whose DN matches a pattern.

        Args:
            entries: List of entries to search
            dn_pattern: Pattern to match in DN (case-insensitive substring match)

        Returns:
            List of matching entries

        """
        pattern_lower = dn_pattern.lower()
        return [entry for entry in entries if pattern_lower in str(entry.dn).lower()]

    @staticmethod
    def merge_entry_lists(
        *entry_lists: list[FlextLdifEntry],
    ) -> list[FlextLdifEntry]:
        """Merge multiple lists of entries, removing duplicates by DN.

        Args:
            *entry_lists: Multiple lists of entries to merge

        Returns:
            Merged list with unique entries (by DN)

        """
        seen_dns: set[str] = set()
        merged: list[FlextLdifEntry] = []

        for entry_list in entry_lists:
            for entry in entry_list:
                dn_str = str(entry.dn).lower()
                if dn_str not in seen_dns:
                    seen_dns.add(dn_str)
                    merged.append(entry)

        return merged


__all__ = ["FlextLdifUtilities"]
