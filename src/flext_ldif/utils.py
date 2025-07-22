"""LDIF utilities using flext-core patterns.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from flext_core.domain.shared_types import ServiceResult

if TYPE_CHECKING:
    from .models import LDIFEntry
    from .types import LDIFContent


class LDIFUtils:
    """LDIF utility functions."""

    @staticmethod
    def entries_to_ldif(entries: list[LDIFEntry]) -> LDIFContent:
        """Convert multiple entries to LDIF content.

        Args:
            entries: List of LDIFEntry objects

        Returns:
            LDIF content string

        """
        from .types import LDIFContent

        ldif_blocks = [entry.to_ldif() for entry in entries]
        return LDIFContent("\n".join(ldif_blocks))

    @staticmethod
    def filter_entries_by_objectclass(
        entries: list[LDIFEntry],
        object_class: str,
    ) -> list[LDIFEntry]:
        """Filter entries by objectClass.

        Args:
            entries: List of LDIFEntry objects
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
    def get_entry_by_dn(entries: list[LDIFEntry], dn: str) -> LDIFEntry | None:
        """Get entry by DN.

        Args:
            entries: List of LDIFEntry objects
            dn: Distinguished name to search for

        Returns:
            LDIFEntry if found, None otherwise

        """
        for entry in entries:
            if str(entry.dn) == dn:
                return entry
        return None


class LDIFHierarchicalSorter:
    """Hierarchical sorter for LDIF entries using FLEXT patterns.

    Sorts LDIF entries based on hierarchical relationships to ensure
    parent entries come before child entries in the DN hierarchy.
    """

    def __init__(self) -> None:
        """Initialize the hierarchical sorter."""

    def sort_entries(self, entries: list[LDIFEntry]) -> ServiceResult[Any]:
        """Sort entries hierarchically.

        Args:
            entries: List of LDIF entries to sort

        Returns:
            ServiceResult containing sorted entries or error

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
            return ServiceResult.ok(sorted_entries)
        except Exception as e:
            return ServiceResult.fail(f"Failed to sort entries hierarchically: {e}")

    def sort_by_hierarchy(self, entries: list[LDIFEntry]) -> ServiceResult[Any]:
        """Alternative method name for compatibility.

        Args:
            entries: List of LDIF entries to sort

        Returns:
            ServiceResult containing sorted entries or error

        """
        return self.sort_entries(entries)


__all__ = [
    "LDIFHierarchicalSorter",
    "LDIFUtils",
]
