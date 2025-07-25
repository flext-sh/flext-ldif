"""FlextLdif utilities using flext-core patterns.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root namespace imports
from flext_core import FlextResult

if TYPE_CHECKING:
    from .models import FlextLdifEntry
    from .types import LDIFContent


class FlextLdifUtils:
    """LDIF utility functions."""

    @staticmethod
    def entries_to_ldif(entries: list[FlextLdifEntry]) -> LDIFContent:
        """Convert multiple entries to LDIF content.

        Args:
            entries: List of FlextLdifEntry objects

        Returns:
            LDIF content string

        """
        from .types import LDIFContent

        ldif_blocks = [entry.to_ldif() for entry in entries]
        return LDIFContent("\n".join(ldif_blocks))

    @staticmethod
    def filter_entries_by_objectclass(
        entries: list[FlextLdifEntry],
        object_class: str,
    ) -> list[FlextLdifEntry]:
        """Filter entries by objectClass.

        Args:
            entries: List of FlextLdifEntry objects
            object_class: ObjectClass to filter by

        Returns:
            Filtered list of entries

        """
        filtered = []
        for entry in entries:
            object_classes = entry.get_attribute("objectClass") or []
            if object_class in object_classes:
                filtered.append(entry)
        return filtered

    @staticmethod
    def get_entry_by_dn(
        entries: list[FlextLdifEntry],
        dn: str,
    ) -> FlextLdifEntry | None:
        """Get entry by DN.

        Args:
            entries: List of FlextLdifEntry objects
            dn: Distinguished name to search for

        Returns:
            FlextLdifEntry if found, None otherwise

        """
        for entry in entries:
            if str(entry.dn) == dn:
                return entry
        return None


class FlextLdifHierarchicalSorter:
    """Hierarchical sorter for LDIF entries using FLEXT patterns.

    Sorts LDIF entries based on hierarchical relationships to ensure
    parent entries come before child entries in the DN hierarchy.
    """

    def __init__(self) -> None:
        """Initialize the hierarchical sorter."""

    def sort_entries(self, entries: list[FlextLdifEntry]) -> FlextResult[Any]:
        """Sort entries hierarchically.

        Args:
            entries: List of LDIF entries to sort

        Returns:
            FlextResult containing sorted entries or error

        """
        try:
            # Sort by DN depth (number of components) to ensure hierarchy
            sorted_entries = sorted(
                entries,
                key=lambda entry: (
                    str(entry.dn).count(","),  # Primary sort: depth (parents first)
                    str(entry.dn).lower(),  # Secondary sort: alphabetical
                ),
            )
            return FlextResult.ok(sorted_entries)
        except Exception as e:
            return FlextResult.fail(f"Failed to sort entries hierarchically: {e}")

    def sort_by_hierarchy(self, entries: list[FlextLdifEntry]) -> FlextResult[Any]:
        """Alternative method name for compatibility.

        Args:
            entries: List of LDIF entries to sort

        Returns:
            FlextResult containing sorted entries or error

        """
        return self.sort_entries(entries)


# Helper functions with flext_ldif_ prefix following FLEXT naming conventions
def flext_ldif_sort_entries_hierarchically(
    entries: list[FlextLdifEntry],
) -> FlextResult[Any]:
    """Sort LDIF entries hierarchically using helper function naming convention.

    Args:
        entries: List of FlextLdifEntry objects to sort

    Returns:
        FlextResult containing sorted entries or error

    """
    sorter = FlextLdifHierarchicalSorter()
    return sorter.sort_entries(entries)


def flext_ldif_filter_by_objectclass(
    entries: list[FlextLdifEntry],
    object_class: str,
) -> list[FlextLdifEntry]:
    """Filter LDIF entries by objectClass using helper function naming convention.

    Args:
        entries: List of FlextLdifEntry objects
        object_class: ObjectClass to filter by

    Returns:
        Filtered list of entries

    """
    utils = FlextLdifUtils()
    return utils.filter_entries_by_objectclass(entries, object_class)


def flext_ldif_find_entry_by_dn(
    entries: list[FlextLdifEntry],
    dn: str,
) -> FlextLdifEntry | None:
    """Find LDIF entry by DN using helper function naming convention.

    Args:
        entries: List of FlextLdifEntry objects
        dn: Distinguished name to search for

    Returns:
        FlextLdifEntry if found, None otherwise

    """
    utils = FlextLdifUtils()
    return utils.get_entry_by_dn(entries, dn)


__all__ = [
    "FlextLdifHierarchicalSorter",
    "FlextLdifUtils",
    "flext_ldif_filter_by_objectclass",
    "flext_ldif_find_entry_by_dn",
    # Helper functions with flext_ldif_ prefix
    "flext_ldif_sort_entries_hierarchically",
]
