"""FLEXT-LDIF Specific Utilities - Extending FlextUtilities.

Domain-specific utilities for LDIF processing that extend the generic FlextUtilities
from flext-core. Only LDIF-specific functionality that cannot be generalized.

Following FLEXT patterns:
- Inherits from FlextUtilities for all generic functionality
- Adds only LDIF-domain-specific methods
- Uses proper prefixes (FlextLdif*)
- Follows consolidated class structure
"""

from __future__ import annotations

from collections.abc import Callable

from flext_core import FlextResult, get_logger

from flext_ldif.models import FlextLdifEntry

logger = get_logger(__name__)


class FlextLdifUtilities:
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
            entries: list[FlextLdifEntry], max_errors: int = 10
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
            entries: list[FlextLdifEntry], object_class: str
        ) -> FlextResult[list[FlextLdifEntry]]:
            """Filter entries by objectClass (case-insensitive)."""
            try:
                filtered = [
                    entry for entry in entries if entry.has_object_class(object_class)
                ]
                return FlextResult[list[FlextLdifEntry]].ok(filtered)
            except Exception as e:
                return FlextResult[list[FlextLdifEntry]].fail(f"Filter error: {e}")

        @staticmethod
        def find_entries_with_missing_required_attributes(
            entries: list[FlextLdifEntry], required_attrs: list[str]
        ) -> FlextResult[list[FlextLdifEntry]]:
            """Find entries missing required attributes."""
            try:
                missing = []
                for entry in entries:
                    for attr in required_attrs:
                        if not entry.has_attribute(attr):
                            missing.append(entry)
                            break
                return FlextResult[list[FlextLdifEntry]].ok(missing)
            except Exception as e:
                return FlextResult[list[FlextLdifEntry]].fail(
                    f"Missing attributes search error: {e}"
                )

        @staticmethod
        def batch_process_entries(
            entries: list[FlextLdifEntry],
            batch_size: int = 1000,
            process_func: Callable[[list[FlextLdifEntry]], list[FlextLdifEntry]]
            | None = None,
        ) -> FlextResult[list[FlextLdifEntry]]:
            """Process entries in batches for performance."""
            if not process_func:
                return FlextResult[list[FlextLdifEntry]].ok(entries)

            try:
                processed = []
                for i in range(0, len(entries), batch_size):
                    batch = entries[i : i + batch_size]
                    batch_result = process_func(batch)
                    if isinstance(batch_result, list):
                        processed.extend(batch_result)
                    # If process_func doesn't return a list, use original batch
                    # This ensures we don't lose data if the function fails

                return FlextResult[list[FlextLdifEntry]].ok(processed)
            except Exception as e:
                return FlextResult[list[FlextLdifEntry]].fail(
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
                    # Convert values to proper string list format
                    converted_values = CoreUtilities.LdapConverters.safe_convert_to_ldap_attribute_list(
                        values
                    )
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
                normalized = CoreUtilities.TextProcessor.clean_text(dn)
                return FlextResult[str].ok(normalized)
            except Exception as e:
                return FlextResult[str].fail(f"DN normalization error: {e}")


# Simple functions for backward compatibility (using the utilities above)
def flext_ldif_parse(content: str) -> list[FlextLdifEntry]:
    """Parse LDIF content - simple function using FlextUtilities."""
    # Deferred import to avoid circular dependency
    from flext_ldif.api import FlextLdifAPI

    api = FlextLdifAPI()
    result = api.parse(content)
    if result.is_success and result.value:
        return result.value
    return []


def flext_ldif_validate(entries: list[FlextLdifEntry]) -> bool:
    """Validate LDIF entries - simple function using FlextUtilities."""
    result = FlextLdifUtilities.LdifDomainProcessors.validate_entries_or_warn(entries)
    return result.is_success and result.value is True


def flext_ldif_write(entries: list[FlextLdifEntry]) -> str:
    """Write LDIF entries to string - simple function."""
    if not entries:
        return ""

    lines: list[str] = []
    for entry in entries:
        lines.extend((entry.to_ldif(), ""))  # Empty line between entries

    return "\n".join(lines)


# Export main utilities class and simple functions
__all__ = [
    "FlextLdifUtilities",
    "flext_ldif_parse",
    "flext_ldif_validate",
    "flext_ldif_write",
]
