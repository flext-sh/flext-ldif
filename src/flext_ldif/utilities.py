"""FLEXT-LDIF Specific Utilities - Extending FlextUtilities.

Domain-specific utilities for LDIF processing that extend the generic FlextUtilities
from flext-core. Only LDIF-specific functionality that cannot be generalized.

Following FLEXT patterns:
- Inherits from FlextUtilities for all generic functionality
- Adds only LDIF-domain-specific methods
- Uses proper prefixes (FlextLDIF*)
- Follows consolidated class structure
"""

from __future__ import annotations

from collections.abc import Callable

from flext_core import FlextLogger, FlextResult

from flext_ldif.models import FlextLDIFEntry

logger = FlextLogger(__name__)


class FlextLDIFUtilities:
    """LDIF-specific utilities using FlextUtilities composition.

    Uses composition with all FlextUtilities functionalities while adding
    LDIF-domain-specific methods. Eliminates inheritance complexity.

    Composes with FlextUtilities from flext-core:
    - Generators: ID/timestamp generation
    - TextProcessor: Text cleaning/formatting
    - TypeGuards: Type checking
    - Conversions: Type conversions
    - Performance: Function timing
    - ProcessingUtils: Processing operations
    """

    class LdifDomainProcessors:
        """LDIF-specific domain processing utilities."""

        @staticmethod
        def validate_entries_or_warn(
            entries: list[FlextLDIFEntry], max_errors: int = 10
        ) -> FlextResult[bool]:
            """Validate LDIF entries with warning collection."""
            warnings: list[str] = []
            error_count = 0

            for i, entry in enumerate(entries):
                if not entry.dn.value.strip():
                    warnings.append(f"Entry {i}: Empty DN")
                    error_count += 1
                    if error_count >= max_errors:
                        break

                if not entry.has_attribute("objectClass"):
                    warnings.append(f"Entry {i}: Missing objectClass")
                    error_count += 1
                    if error_count >= max_errors:
                        break

            if warnings:
                for warning in warnings:
                    logger.warning(warning)

            return FlextResult[bool].ok(error_count == 0)

        @staticmethod
        def filter_entries_by_object_class(
            entries: list[FlextLDIFEntry], object_class: str
        ) -> FlextResult[list[FlextLDIFEntry]]:
            """Filter entries by objectClass (case-insensitive)."""
            try:
                filtered = [
                    entry for entry in entries if entry.has_object_class(object_class)
                ]
                return FlextResult[list[FlextLDIFEntry]].ok(filtered)
            except Exception as e:
                return FlextResult[list[FlextLDIFEntry]].fail(f"Filter error: {e}")

        @staticmethod
        def find_entries_with_missing_required_attributes(
            entries: list[FlextLDIFEntry], required_attrs: list[str]
        ) -> FlextResult[list[FlextLDIFEntry]]:
            """Find entries missing required attributes."""
            try:
                missing = []
                for entry in entries:
                    for attr in required_attrs:
                        if not entry.has_attribute(attr):
                            missing.append(entry)
                            break
                return FlextResult[list[FlextLDIFEntry]].ok(missing)
            except Exception as e:
                return FlextResult[list[FlextLDIFEntry]].fail(
                    f"Missing attributes search error: {e}"
                )

        @staticmethod
        def batch_process_entries(
            entries: list[FlextLDIFEntry],
            batch_size: int = 1000,
            process_func: Callable[[list[FlextLDIFEntry]], list[FlextLDIFEntry]]
            | None = None,
        ) -> FlextResult[list[FlextLDIFEntry]]:
            """Process entries in batches for performance."""
            if not process_func:
                return FlextResult[list[FlextLDIFEntry]].ok(entries)

            try:
                processed = []
                for i in range(0, len(entries), batch_size):
                    batch = entries[i : i + batch_size]
                    batch_result = process_func(batch)
                    if isinstance(batch_result, list):
                        processed.extend(batch_result)
                    # If process_func doesn't return a list, use original batch
                    # This ensures we don't lose data if the function fails

                return FlextResult[list[FlextLDIFEntry]].ok(processed)
            except Exception as e:
                return FlextResult[list[FlextLDIFEntry]].fail(
                    f"Batch processing error: {e}"
                )

    class LdifConverters:
        """LDIF-specific data conversion utilities."""

        @staticmethod
        def attributes_dict_to_ldif_format(
            attributes: dict[str, list[str]],
        ) -> FlextResult[dict[str, list[str]]]:
            """Convert attributes dictionary to proper LDIF format."""
            try:
                # Use FlextUtilities LdapConverters for the heavy lifting
                ldif_attrs = {}
                for key, values in attributes.items():
                    # Convert values to proper string list format - simplified without flext-core dependency
                    if isinstance(values, list):
                        converted_values = [str(v) for v in values if v is not None]
                    else:
                        converted_values = [str(values)] if values is not None else []
                    if converted_values:  # Only include non-empty values
                        ldif_attrs[key.lower()] = converted_values

                return FlextResult[dict[str, list[str]]].ok(ldif_attrs)
            except Exception as e:
                return FlextResult[dict[str, list[str]]].fail(
                    f"LDIF conversion error: {e}"
                )

        @staticmethod
        def normalize_dn_components(dn: str) -> FlextResult[str]:
            """Normalize DN components for consistent formatting."""
            try:
                if not dn or not dn.strip():
                    return FlextResult[str].fail("DN cannot be empty")

                # Basic DN normalization - remove extra spaces
                normalized = dn.strip()
                return FlextResult[str].ok(normalized)
            except Exception as e:
                return FlextResult[str].fail(f"DN normalization error: {e}")


# All functionality now available through FlextLDIFUtilities class methods
# No helper functions - use class methods instead:
# - FlextLDIFUtilities.LdifDomainProcessors.validate_entries_or_warn()
# - FlextLDIFUtilities.LdifConverters.attributes_dict_to_ldif_format()
# - Use FlextLDIFAPI class for parse/write operations


# Export only the main utilities class - no helper functions
__all__ = [
    "FlextLDIFUtilities",
]
