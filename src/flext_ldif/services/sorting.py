"""LDIF Entry Sorting Service.

Provides sorting and ordering utilities for LDIF entries with support for:
- DN hierarchy-based sorting (depth-first)
- Case-insensitive DN name ordering
- Stable ordering for reproducible output
- Schema ordering (attributeTypes before objectClasses)

Used by writer services and categorized pipelines to ensure
deterministic, proper ordering of LDIF entries in output files.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re
from collections.abc import Callable

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels


class FlextLdifSortingService:
    """Service for sorting LDIF entries in multiple contexts.

    Provides methods for sorting entries by various criteria:
    - DN hierarchy (depth, then name)
    - Schema type (attributes, then object classes)
    - Alphabetical ordering
    - Custom predicates

    All sorting is stable and deterministic for reproducible output.

    Note: Accepts ONLY Entry model objects (no dict intermediaries).

    """

    @staticmethod
    def sort_entries_by_hierarchy_and_name(
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort entries by DN hierarchy depth, then case-insensitive DN.

        Ordering rules:
        - Primary: DN depth (number of RDN components)
          - Shallower DNs first (closer to root)
          - Example: ou=users comes before cn=john,ou=users
        - Secondary: Case-insensitive DN string for stable ordering
          - Alphabetical within same depth level

        This ensures:
        - Proper LDAP hierarchy loading order
        - Parent entries before child entries
        - Deterministic, reproducible output

        Args:
            entries: List of Entry objects to sort

        Returns:
            FlextResult with sorted Entry objects

        Example:
            entries = [
                Entry(dn="cn=john,ou=users,dc=example,dc=com", ...),
                Entry(dn="ou=users,dc=example,dc=com", ...),
                Entry(dn="dc=example,dc=com", ...),
            ]
            result = FlextLdifSortingService.sort_entries_by_hierarchy_and_name(entries)
            # Result order: dc=example,dc=com → ou=users... → cn=john...

        """
        try:
            return FlextLdifSortingService._sort_entry_objects_by_hierarchy(entries)

        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Entry sorting failed: {e}",
            )

    @staticmethod
    def _sort_entry_objects_by_hierarchy(
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort Entry objects by DN hierarchy."""
        try:

            def sort_key(entry: FlextLdifModels.Entry) -> tuple[int, str]:
                """Generate sort key: (depth, dn_lowercase)."""
                dn = entry.dn.value

                # DN depth = number of commas + 1 (RDN count)
                depth = dn.count(",") + (1 if dn else 0)

                return (depth, dn.lower())

            sorted_entries = sorted(entries, key=sort_key)

            return FlextResult[list[FlextLdifModels.Entry]].ok(sorted_entries)

        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Entry object sorting failed: {e}",
            )

    @staticmethod
    def sort_entries_alphabetically_by_dn(
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort entries alphabetically by DN (case-insensitive).

        Simple alphabetical ordering without hierarchy consideration.

        Args:
            entries: List of Entry objects

        Returns:
            FlextResult with alphabetically sorted Entry objects

        """
        try:

            def sort_key(entry: FlextLdifModels.Entry) -> str:
                return entry.dn.value.lower()

            sorted_entries = sorted(entries, key=sort_key)
            return FlextResult[list[FlextLdifModels.Entry]].ok(sorted_entries)

        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Alphabetical sorting failed: {e}",
            )

    @staticmethod
    def sort_schema_entries(
        schema_entries: dict[str, object],
    ) -> FlextResult[dict[str, object]]:
        """Sort schema definitions (attributes before object classes).

        Schema ordering:
        1. SchemaFields.ATTRIBUTE_TYPES (OID-based sorting)
        2. SchemaFields.OBJECT_CLASSES (OID-based sorting)
        3. Other schema elements

        Args:
            schema_entries: Dictionary with schema definitions

        Returns:
            FlextResult with ordered schema entries

        """
        try:
            ordered_schema: dict[str, object] = {}

            # Process attributes first
            if FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES in schema_entries:
                attributes = schema_entries[
                    FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES
                ]
                if isinstance(attributes, list):
                    ordered_schema[FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES] = (
                        FlextLdifSortingService._sort_schema_list(attributes)
                    )
                else:
                    ordered_schema[FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES] = (
                        attributes
                    )

            # Process object classes second
            if FlextLdifConstants.SchemaFields.OBJECT_CLASSES in schema_entries:
                objectclasses = schema_entries[
                    FlextLdifConstants.SchemaFields.OBJECT_CLASSES
                ]
                if isinstance(objectclasses, list):
                    ordered_schema[FlextLdifConstants.SchemaFields.OBJECT_CLASSES] = (
                        FlextLdifSortingService._sort_schema_list(objectclasses)
                    )
                else:
                    ordered_schema[FlextLdifConstants.SchemaFields.OBJECT_CLASSES] = (
                        objectclasses
                    )

            # Add remaining schema elements in order
            ordered_schema.update({
                key: value
                for key, value in schema_entries.items()
                if key not in FlextLdifConstants.SchemaFields.ALL_SCHEMA_FIELDS
            })

            return FlextResult[dict[str, object]].ok(ordered_schema)

        except Exception as e:
            return FlextResult[dict[str, object]].fail(f"Schema sorting failed: {e}")

    @staticmethod
    def _sort_schema_list(items: list[object]) -> list[object]:
        """Sort schema items by OID if available, otherwise alphabetically."""
        try:

            def extract_oid(item: object) -> str:
                """Extract OID from schema item."""
                if isinstance(item, str):
                    # Look for OID pattern: ( digits.digits...
                    match = re.search(r"\(\s*([\d.]+)", item)
                    if match:
                        return match.group(1)
                    # Fallback to string comparison
                    return item.lower()
                return ""

            # Sort by extracted OID, with string fallback for comparison
            return sorted(
                items,
                key=lambda x: (extract_oid(x), str(x).lower()),
            )

        except Exception:
            # If sorting fails, return original order
            return items

    @staticmethod
    def sort_by_custom_predicate(
        entries: list[FlextLdifModels.Entry],
        predicate: Callable[[FlextLdifModels.Entry], str | int | float],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort entries using custom comparison predicate.

        Args:
            entries: List of Entry objects to sort
            predicate: Callable that returns sort key from Entry

        Returns:
            FlextResult with sorted Entry objects

        """
        try:
            sorted_entries = sorted(entries, key=predicate)
            return FlextResult[list[FlextLdifModels.Entry]].ok(sorted_entries)

        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Custom predicate sorting failed: {e}",
            )

    @staticmethod
    def get_dn_depth(dn: str) -> int:
        """Get DN depth (RDN component count).

        Args:
            dn: Distinguished name string

        Returns:
            Number of RDN components in DN

        Example:
            FlextLdifSortingService.get_dn_depth("cn=john,ou=users,dc=example,dc=com")
            # Returns: 4

        """
        if not dn:
            return 0
        return dn.count(",") + 1


__all__ = ["FlextLdifSortingService"]
