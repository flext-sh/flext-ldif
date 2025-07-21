"""LDIF utilities using flext-core patterns.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .types import LDIFContent

if TYPE_CHECKING:
    from .models import LDIFEntry


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
            if entry.dn == dn:
                return entry
        return None


__all__ = [
    "LDIFUtils",
]
