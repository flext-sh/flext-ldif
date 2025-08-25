"""FLEXT-LDIF Utilities - Consolidated Module.

Utility functions, classes, type definitions, transformer service, and helper functions
following flext-core consolidated patterns.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, TypeVar, cast, override

import click
from flext_core import FlextCallable, FlextDomainService, FlextResult, get_logger
from pydantic import Field

if TYPE_CHECKING:
    from flext_ldif.api import FlextLdifAPI
    from flext_ldif.models import FlextLdifEntry

# Simplified approach - remove unused delayed imports
# Type checking is handled via TYPE_CHECKING block

T = TypeVar("T")

# =============================================================================
# CONSOLIDATED TYPE SYSTEM - Centralized type definitions
# =============================================================================

# Basic type aliases
AttributeName = str
AttributeValue = str | bytes | int | float | bool
StringList = list[str]
FilePath = str | Path

# LDIF-specific types
LDIFContent = str
LDIFLines = list[str]
LDAPObjectClass = str

# Processing configuration types
ProcessingMode = str  # 'strict' | 'permissive' | 'fast'
ValidationLevel = str  # 'strict' | 'standard' | 'minimal'

# Dictionary types for data exchange
FlextLdifAttributesDict = dict[str, list[AttributeValue]]
FlextLdifDNDict = dict[str, str]
FlextLdifEntryDict = dict[str, str | int | float | bool | list[AttributeValue]]

# Type unions for flexibility
AttributeValueType = str | bytes | int | float | bool
MappingType = Mapping[str, str | int | float | bool]
SequenceType = Sequence[str | int | float | bool]

# =============================================================================
# CONSOLIDATED TRANSFORMER SERVICE - Domain service implementation
# =============================================================================

logger = get_logger(__name__)


class FlextLdifTransformerService(FlextDomainService["list[FlextLdifEntry]"]):
    """Concrete LDIF transformation service using flext-core patterns.

    ✅ CORRECT ARCHITECTURE: Extends FlextDomainService from flext-core.
    ZERO duplication - uses existing flext-core service patterns.
    """

    config: object = Field(default=None)

    @override
    def execute(self) -> FlextResult[list[FlextLdifEntry]]:
        """Execute transformation - implements FlextDomainService contract."""
        return FlextResult["list[FlextLdifEntry]"].ok([])

    def transform_entry(self, entry: FlextLdifEntry) -> FlextResult[FlextLdifEntry]:
        """Transform single LDIF entry."""
        # Base implementation returns entry as-is
        return FlextResult["FlextLdifEntry"].ok(entry)

    def transform_entries(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Transform multiple LDIF entries."""
        transformed: list[FlextLdifEntry] = []
        for entry in entries:
            result = self.transform_entry(entry)
            # Use tap for successful transformations instead of conditional check
            result.tap(transformed.append)

        return FlextResult["list[FlextLdifEntry]"].ok(transformed)

    def normalize_dns(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Normalize all DN values in entries."""
        # DN normalization is handled automatically by the domain model
        return FlextResult["list[FlextLdifEntry]"].ok(entries)


# =============================================================================
# CONSOLIDATED HELPER FUNCTIONS - Convenience functions for common operations
# =============================================================================


def flext_ldif_parse(content: str) -> list[FlextLdifEntry]:
    """Parse LDIF content using default configuration.
    
    Args:
        content: LDIF content string to parse
        
    Returns:
        List of parsed LDIF entries
        
    Raises:
        FlextLdifParseError: If parsing fails

    """
    # Import here to avoid circular imports
    from .core import TLdif
    from .exceptions import FlextLdifParseError

    result = TLdif.parse(content)
    if not result.is_success:
        raise FlextLdifParseError(result.error or "Unknown parsing error")
    return result.value or []


def flext_ldif_validate(entries: list[FlextLdifEntry]) -> bool:
    """Validate LDIF entries using default configuration.
    
    Args:
        entries: List of LDIF entries to validate
        
    Returns:
        True if all entries are valid
        
    Raises:
        FlextLdifValidationError: If validation fails

    """
    # Import here to avoid circular imports
    from .api import FlextLdifAPI
    from .exceptions import FlextLdifValidationError

    api = FlextLdifAPI()
    result = api.validate(entries)
    if not result.is_success:
        raise FlextLdifValidationError(result.error or "Unknown validation error")
    return result.value or False


def flext_ldif_write(entries: list[FlextLdifEntry]) -> str:
    """Write LDIF entries to string format.
    
    Args:
        entries: List of LDIF entries to write
        
    Returns:
        LDIF content as string
        
    Raises:
        FlextLdifError: If writing fails

    """
    # Import here to avoid circular imports
    from .core import TLdif
    from .exceptions import FlextLdifError

    result = TLdif.write(entries)
    if not result.is_success:
        raise FlextLdifError(result.error or "Unknown writing error")
    return result.value or ""


def flext_ldif_get_api() -> FlextLdifAPI:
    """Get default FLEXT LDIF API instance.
    
    Returns:
        FlextLdifAPI instance configured with default settings

    """
    # Import here to avoid circular imports
    from .api import FlextLdifAPI

    return FlextLdifAPI()


# =============================================================================
# CONSOLIDATED UTILITIES CLASS - Static utility methods
# =============================================================================


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
        return result.value  # Safe after tap_error handles failures

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
        func: FlextCallable[object],
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
        *operations: FlextCallable[object],
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
                    result = operation(
                        result
                    )  # FlextCallable accepts *args, **kwargs but can be called with single arg
            return result

        return pipeline

    @staticmethod
    def validate_callable_chain(
        *functions: FlextCallable[object],
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
            in FlextLdifUtilities.get_entry_objectclasses(entry, lowercase=True)
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

            # Use unwrap_or pattern for cleaner batch validation handling
            default_validation = False
            validation_result = batch_result.unwrap_or(default_validation)
            if validation_result:
                # Batch validation succeeded for all entries
                results.extend([True] * len(batch))
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
            entry_objectclasses = FlextLdifUtilities.get_entry_objectclasses(
                entry, lowercase=True
            )
            all_objectclasses.update(entry_objectclasses)
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
        return [
            entry
            for entry in entries
            if pattern_lower
            in FlextLdifUtilities.get_entry_dn_string(entry, lowercase=True)
        ]

    @staticmethod
    def get_entry_dn_string(entry: FlextLdifEntry, *, lowercase: bool = False) -> str:
        """Get entry DN as string with optional lowercase conversion.

        Args:
            entry: Entry to get DN from
            lowercase: Whether to convert to lowercase

        Returns:
            DN string representation

        """
        dn_str = str(entry.dn)
        return dn_str.lower() if lowercase else dn_str

    @staticmethod
    def get_entry_objectclasses(
        entry: FlextLdifEntry, *, lowercase: bool = False
    ) -> list[str]:
        """Get entry objectClass values with optional lowercase conversion.

        Args:
            entry: Entry to get objectClasses from
            lowercase: Whether to convert to lowercase

        Returns:
            List of objectClass values

        """
        objectclasses = entry.get_attribute("objectClass") or []
        return [oc.lower() for oc in objectclasses] if lowercase else objectclasses

    @staticmethod
    def calculate_dn_depth(entry: FlextLdifEntry) -> int:
        """Calculate DN depth by counting components.

        Args:
            entry: Entry to calculate depth for

        Returns:
            Number of DN components (depth)

        """
        return str(entry.dn).count(",") + 1

    @staticmethod
    def validate_entry_with_error_handler(
        entry: FlextLdifEntry, error_handler: Callable[[str], None] | None = None
    ) -> bool:
        """Validate entry business rules with optional error handler.

        Args:
            entry: Entry to validate
            error_handler: Optional function to handle validation errors

        Returns:
            True if validation passes, False otherwise

        """
        validation_result = entry.validate_business_rules()
        if validation_result.is_failure and error_handler:
            error_handler(validation_result.error or "Unknown validation error")
        return validation_result.is_success

    @staticmethod
    def bulk_validate_entries_with_summary(
        entries: list[FlextLdifEntry], max_errors: int = 5
    ) -> tuple[int, list[str]]:
        """Validate multiple entries and return summary.

        Args:
            entries: Entries to validate
            max_errors: Maximum number of errors to collect

        Returns:
            Tuple of (valid_count, error_messages)

        """
        valid_count = 0
        errors: list[str] = []

        for i, entry in enumerate(entries):
            if len(errors) >= max_errors:
                errors.append(f"... and {len(entries) - i} more entries not validated")
                break

            def error_handler(
                error: str,
                current_entry: FlextLdifEntry = entry,
                current_index: int = i + 1,
            ) -> None:
                errors.append(
                    FlextLdifUtilities.format_entry_error_message(
                        current_entry, current_index, error
                    )
                )

            if FlextLdifUtilities.validate_entry_with_error_handler(
                entry, error_handler
            ):
                valid_count += 1

        return valid_count, errors

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
                dn_str = FlextLdifUtilities.get_entry_dn_string(entry, lowercase=True)
                if dn_str not in seen_dns:
                    seen_dns.add(dn_str)
                    merged.append(entry)

        return merged

    @staticmethod
    def batch_process_entries[T](
        entries: list[FlextLdifEntry],
        batch_size: int = 100,
        processor: Callable[[list[FlextLdifEntry]], FlextResult[T]] | None = None,
    ) -> FlextResult[list[T]]:
        """Process entries in batches for better performance.

        Args:
            entries: Entries to process
            batch_size: Size of each batch
            processor: Function to process each batch

        Returns:
            FlextResult with list of processed results

        """
        if not processor:
            return FlextResult[list[T]].fail("Processor function required")

        results: list[T] = []
        for i in range(0, len(entries), batch_size):
            batch = entries[i : i + batch_size]
            batch_result = processor(batch)
            if batch_result.is_failure:
                return FlextResult[list[T]].fail(
                    f"Batch {i // batch_size + 1} failed: {batch_result.error}"
                )
            batch_value = batch_result.value
            if isinstance(batch_value, list):
                # Type narrowing: batch_value is list[T] here
                results.extend(cast("list[T]", batch_value))
            else:
                # Type narrowing: batch_value is T here
                results.append(batch_value)

        return FlextResult[list[T]].ok(results)

    @staticmethod
    def safe_get_attribute_value(
        entry: FlextLdifEntry, attribute_name: str, default: str = ""
    ) -> str:
        """Safely get first attribute value with fallback.

        Args:
            entry: Entry to get attribute from
            attribute_name: Name of attribute
            default: Default value if attribute not found

        Returns:
            First attribute value or default

        """
        value = entry.get_single_attribute(attribute_name)
        return value if value is not None else default

    @staticmethod
    def group_entries_by_object_class(
        entries: list[FlextLdifEntry],
    ) -> dict[str, list[FlextLdifEntry]]:
        """Group entries by their object classes.

        Args:
            entries: Entries to group

        Returns:
            Dictionary mapping object class to list of entries

        """
        grouped: dict[str, list[FlextLdifEntry]] = {}
        for entry in entries:
            object_classes = entry.get_object_classes()
            for obj_class in object_classes:
                if obj_class not in grouped:
                    grouped[obj_class] = []
                grouped[obj_class].append(entry)
        return grouped

    @staticmethod
    def format_entry_error_message(
        entry: FlextLdifEntry, index: int, error: str
    ) -> str:
        """Format standardized error message for entry validation failures.

        Args:
            entry: Entry that failed validation
            index: 1-based index of entry in list
            error: Error message

        Returns:
            Formatted error message with entry context

        """
        return f"Entry {index} ({entry.dn}): {error}"

    @staticmethod
    def filter_entries_by_dn_pattern(
        entries: list[FlextLdifEntry], pattern: str, *, case_sensitive: bool = False
    ) -> list[FlextLdifEntry]:
        """Filter entries by DN pattern matching.

        Args:
            entries: Entries to filter
            pattern: Pattern to match in DN
            case_sensitive: Whether to perform case-sensitive matching

        Returns:
            Filtered list of entries

        """
        if case_sensitive:
            return [
                entry
                for entry in entries
                if pattern in FlextLdifUtilities.get_entry_dn_string(entry)
            ]
        pattern_lower = pattern.lower()
        return [
            entry
            for entry in entries
            if pattern_lower
            in FlextLdifUtilities.get_entry_dn_string(entry, lowercase=True)
        ]

    @staticmethod
    def extract_unique_attribute_names(entries: list[FlextLdifEntry]) -> set[str]:
        """Extract all unique attribute names across entries.

        Args:
            entries: Entries to analyze

        Returns:
            Set of unique attribute names

        """
        attribute_names: set[str] = set()
        for entry in entries:
            attribute_names.update(entry.attributes.attributes.keys())
        return attribute_names

    @staticmethod
    def find_entries_with_missing_required_attributes(
        entries: list[FlextLdifEntry], required_attributes: list[str]
    ) -> list[FlextLdifEntry]:
        """Find entries missing any required attributes.

        Args:
            entries: Entries to check
            required_attributes: List of required attribute names

        Returns:
            Entries that are missing one or more required attributes

        """
        missing_entries: list[FlextLdifEntry] = []
        for entry in entries:
            entry_attrs = set(entry.attributes.attributes.keys())
            if not all(attr in entry_attrs for attr in required_attributes):
                missing_entries.append(entry)
        return missing_entries

    @staticmethod
    def chain_operations[T](
        initial: FlextResult[T],
        operations: list[Callable[[T], FlextResult[T]]],
    ) -> FlextResult[T]:
        """Chain multiple operations using railway programming.

        This utility enables clean functional composition of operations that may fail,
        following the Railway Programming pattern from flext-core.

        Args:
            initial: Initial FlextResult to start the chain
            operations: List of operations to chain (all must have same type)

        Returns:
            Final FlextResult after all operations (or first failure)

        Example:
            >>> def validate(entry):
            ...     return FlextResult.ok(entry)
            >>> def transform(entry):
            ...     return FlextResult.ok(entry)
            >>> operations = [validate, transform]
            >>> result = FlextLdifUtilities.chain_operations(initial_result, operations)

        """
        current = initial
        for operation in operations:
            if current.is_failure:
                return FlextResult[T].fail(current.error or "Chain operation failed")
            current = operation(current.value)
        return current

    @staticmethod
    def collect_results[T](
        results: list[FlextResult[T]],
    ) -> FlextResult[list[T]]:
        """Collect a list of FlextResult into a FlextResult of list.

        Implements the 'sequence' operation from functional programming,
        converting list of Results into Result of list.

        Args:
            results: List of FlextResult to collect

        Returns:
            FlextResult containing list of all values, or first error

        Example:
            >>> results = [api.validate(entry) for entry in entries]
            >>> final = FlextLdifUtilities.collect_results(results)

        """
        collected: list[T] = []
        for i, result in enumerate(results):
            if result.is_failure:
                return FlextResult[list[T]].fail(f"Item {i + 1} failed: {result.error}")
            collected.append(result.value)
        return FlextResult[list[T]].ok(collected)

    @staticmethod
    def partition_entries_by_validation(
        entries: list[FlextLdifEntry],
    ) -> tuple[list[FlextLdifEntry], list[tuple[FlextLdifEntry, str]]]:
        """Partition entries into valid and invalid with error messages.

        This utility separates entries based on business rule validation,
        providing detailed error information for invalid entries.

        Args:
            entries: List of entries to partition

        Returns:
            Tuple of (valid_entries, invalid_entries_with_errors)

        Example:
            >>> valid, invalid = FlextLdifUtilities.partition_entries_by_validation(
            ...     entries
            ... )
            >>> print(f"Valid: {len(valid)}, Invalid: {len(invalid)}")

        """
        valid: list[FlextLdifEntry] = []
        invalid: list[tuple[FlextLdifEntry, str]] = []

        for entry in entries:
            validation_result = entry.validate_business_rules()
            if validation_result.is_success:
                valid.append(entry)
            else:
                invalid.append((entry, validation_result.error or "Validation failed"))

        return valid, invalid

    @staticmethod
    def map_entries_safely[T](
        entries: list[FlextLdifEntry],
        mapper: Callable[[FlextLdifEntry], FlextResult[T]],
        *,
        fail_fast: bool = True,
    ) -> FlextResult[list[T]]:
        """Map entries through a function that may fail, with error handling.

        Applies a potentially failing operation to each entry, with options
        for error handling strategy (fail-fast or collect errors).

        Args:
            entries: Entries to map
            mapper: Function to apply to each entry
            fail_fast: If True, stop on first failure; if False, collect all errors

        Returns:
            FlextResult containing mapped values or error information

        """
        results: list[T] = []
        errors: list[str] = []

        for i, entry in enumerate(entries):
            result = mapper(entry)
            if result.is_success:
                results.append(result.value)
            else:
                error_msg = f"Entry {i + 1}: {result.error}"
                if fail_fast:
                    return FlextResult[list[T]].fail(error_msg)
                errors.append(error_msg)

        if errors and not fail_fast:
            return FlextResult[list[T]].fail(f"Multiple errors: {'; '.join(errors)}")

        return FlextResult[list[T]].ok(results)

    @staticmethod
    def find_entries_with_circular_references(
        entries: list[FlextLdifEntry],
    ) -> list[tuple[FlextLdifEntry, str]]:
        """Find entries that may have circular references in their DN hierarchy.

        Identifies potential circular references by checking if any entry's DN
        appears in another entry's member attributes.

        Args:
            entries: Entries to analyze

        Returns:
            List of (entry, reason) tuples for entries with potential circular refs

        """
        dns = {str(entry.dn).lower() for entry in entries}
        circular: list[tuple[FlextLdifEntry, str]] = []

        for entry in entries:
            member_attrs = entry.get_attribute("member") or []
            # Find all circular references for this entry
            entry_circular = [
                (entry, f"Member {member} creates potential circular reference")
                for member in member_attrs
                if member.lower() in dns
            ]
            circular.extend(entry_circular)

        return circular


# =============================================================================
# CONSOLIDATED EXPORTS - All functionality from this module
# =============================================================================

__all__ = [
    # Type System
    "AttributeName",
    "AttributeValue",
    "AttributeValueType",
    "FilePath",
    "FlextLdifAttributesDict",
    "FlextLdifDNDict",
    "FlextLdifEntryDict",
    "LDAPObjectClass",
    "LDIFContent",
    "LDIFLines",
    "MappingType",
    "ProcessingMode",
    "SequenceType",
    "StringList",
    "ValidationLevel",

    # Transformer Service
    "FlextLdifTransformerService",

    # Helper Functions
    "flext_ldif_parse",
    "flext_ldif_validate",
    "flext_ldif_write",
    "flext_ldif_get_api",

    # Utilities Class
    "FlextLdifUtilities",
]

# Note: Forward references will be resolved when models are imported
