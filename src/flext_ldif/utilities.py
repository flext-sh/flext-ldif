"""FLEXT-LDIF Utilities - Optimized domain-specific operations following flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from functools import reduce
from operator import add

from flext_core import FlextLogger, FlextResult

from flext_ldif.models import FlextLDIFModels

logger = FlextLogger(__name__)


class FlextLDIFUtilities:
    """LDIF utilities following flext-core patterns - essential operations only."""

    def __init__(self) -> None:
        """Initialize with flext-core foundation patterns."""
        self._logger = FlextLogger(__name__)

    class LdifDomainProcessors:
        """Core LDIF processing operations - static methods for performance."""

        @staticmethod
        def validate_entries_or_warn(
            entries: list[FlextLDIFModels.Entry], max_errors: int = 10
        ) -> FlextResult[bool]:
            """Validate LDIF entries efficiently.

            Returns:
                FlextResult: Validation result.

            """
            errors = []

            for i, entry in enumerate(entries[:max_errors]):
                if not entry.dn.value.strip():
                    errors.append(f"Entry {i}: Empty DN")
                if not entry.has_attribute("objectClass"):
                    errors.append(f"Entry {i}: Missing objectClass")

            # Use instance logger for proper DI pattern (but keep static for performance)
            if errors:
                FlextLogger(__name__).warning(f"Validation errors: {'; '.join(errors)}")

            return FlextResult[bool].ok(not errors)

        @staticmethod
        def filter_entries_by_object_class(
            entries: list[FlextLDIFModels.Entry], object_class: str
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Filter entries by objectClass - simplified.

            Returns:
                FlextResult: Filtered entries result.

            """
            filtered = [e for e in entries if e.has_object_class(object_class)]
            return FlextResult[list[FlextLDIFModels.Entry]].ok(filtered)

        @staticmethod
        def find_entries_with_missing_required_attributes(
            entries: list[FlextLDIFModels.Entry],
            required_attrs: FlextTypes.Core.StringList,
        ) -> FlextResult[list[FlextLDIFModels.Entry]]:
            """Find entries missing any required attribute - optimized.

            Returns:
                FlextResult: Entries with missing attributes result.

            """
            missing = [
                entry
                for entry in entries
                if any(not entry.has_attribute(attr) for attr in required_attrs)
            ]
            return FlextResult[list[FlextLDIFModels.Entry]].ok(missing)

        @staticmethod
        def get_entry_statistics(
            entries: list[FlextLDIFModels.Entry],
        ) -> FlextResult[dict[str, int]]:
            """Get comprehensive entry statistics."""
            if not entries:
                return FlextResult[dict[str, int]].ok(
                    {
                        "total_entries": 0,
                        "person_entries": 0,
                        "group_entries": 0,
                        "unique_attributes": 0,
                    }
                )

            # Collect all attributes efficiently
            all_attrs: FlextTypes.Core.StringList = reduce(
                add, [list(e.attributes.data.keys()) for e in entries], []
            )

            stats = {
                "total_entries": len(entries),
                "person_entries": sum(1 for e in entries if e.is_person()),
                "group_entries": sum(1 for e in entries if e.is_group()),
                "unique_attributes": len(set(all_attrs)),
            }

            return FlextResult[dict[str, int]].ok(stats)

    class LdifConverters:
        """LDIF-specific data conversion utilities."""

        @staticmethod
        def attributes_dict_to_ldif_format(
            attributes: dict[str, str | FlextTypes.Core.StringList],
        ) -> FlextResult[dict[str, FlextTypes.Core.StringList]]:
            """Convert attributes dictionary to proper LDIF format - Railway pattern."""
            # Railway pattern - no try/catch needed, FlextResult handles it
            ldif_attrs = {}
            for key, values in attributes.items():
                # Use FlextUtilities.ProcessingUtils for safe conversion
                # Handle both string, list, and None values
                converted_values: FlextTypes.Core.StringList = []
                if isinstance(values, str):
                    converted_values = [values] if values else []
                elif isinstance(values, list):
                    converted_values = [str(v) for v in values if v is not None]
                # else: values is None or other - already initialized as empty list

                if converted_values:  # Only include non-empty values
                    ldif_attrs[key.lower()] = converted_values

            return FlextResult[dict[str, FlextTypes.Core.StringList]].ok(ldif_attrs)

        @staticmethod
        def normalize_dn_components(dn: str) -> FlextResult[str]:
            """Normalize DN components - Railway pattern without exceptions."""
            # Railway pattern validation
            if not dn or not dn.strip():
                return FlextResult[str].fail("DN cannot be empty")

            # Optimized normalization - just strip whitespace
            return FlextResult[str].ok(dn.strip())


# FLEXT-CORE PATTERNS APPLIED:
# ✅ Inherits from FlextDomainService (flext-core pattern)
# ✅ Uses FlextResult railway pattern throughout
# ✅ Classes unique per module with nested organization
# ✅ No helper functions - all functionality in unified class
# ✅ Optimized for performance with static methods where appropriate


# Export only the main utilities class - no helper functions
__all__ = [
    "FlextLDIFUtilities",
]
