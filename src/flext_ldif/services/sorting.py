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
from typing import cast

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

    """

    @staticmethod
    def sort_entries_by_hierarchy_and_name(
        entries: list[dict[str, object]] | list[FlextLdifModels.Entry],
    ) -> FlextResult[list[dict[str, object]] | list[FlextLdifModels.Entry]]:
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
            entries: List of entry dicts or Entry objects

        Returns:
            FlextResult with sorted entries (same type as input)

        Example:
            entries = [
                {"dn": "cn=john,ou=users,dc=example,dc=com"},
                {"dn": "ou=users,dc=example,dc=com"},
                {"dn": "dc=example,dc=com"},
            ]
            result = FlextLdifSortingService.sort_entries_by_hierarchy_and_name(entries)
            # Result order: dc=example,dc=com → ou=users... → cn=john...

        """
        try:
            # Check if we're dealing with Entry objects or dicts
            if len(entries) > 0 and isinstance(entries[0], FlextLdifModels.Entry):
                # Type narrow to Entry objects
                entry_list = [
                    e for e in entries if isinstance(e, FlextLdifModels.Entry)
                ]
                result = FlextLdifSortingService._sort_entry_objects_by_hierarchy(
                    entry_list,
                )
                if result.is_success:
                    return cast(
                        "FlextResult[list[dict[str, object]] | list[FlextLdifModels.Entry]]",
                        result,
                    )
                return cast(
                    "FlextResult[list[dict[str, object]] | list[FlextLdifModels.Entry]]",
                    result,
                )
            # Type narrow to dict objects
            dict_list = [e for e in entries if isinstance(e, dict)]
            result = FlextLdifSortingService._sort_entry_dicts_by_hierarchy(dict_list)
            return cast(
                "FlextResult[list[dict[str, object]] | list[FlextLdifModels.Entry]]",
                result,
            )

        except Exception as e:
            return FlextResult[
                list[dict[str, object]] | list[FlextLdifModels.Entry]
            ].fail(f"Entry sorting failed: {e}")

    @staticmethod
    def _sort_entry_dicts_by_hierarchy(
        entries: list[dict[str, object]],
    ) -> FlextResult[list[dict[str, object]]]:
        """Sort entry dictionaries by DN hierarchy."""
        try:

            def sort_key(entry: dict[str, object]) -> tuple[int, str]:
                """Generate sort key: (depth, dn_lowercase)."""
                dn_value = entry.get(FlextLdifConstants.DictKeys.DN, "")
                dn = dn_value if isinstance(dn_value, str) else ""

                # DN depth = number of commas + 1 (RDN count)
                depth = dn.count(",") + (1 if dn else 0)

                return (depth, dn.lower())

            # Separate sortable (valid DN) from non-sortable entries
            sortable = [
                e
                for e in entries
                if isinstance(e.get(FlextLdifConstants.DictKeys.DN), str)
                and len(str(e.get(FlextLdifConstants.DictKeys.DN))) > 0
            ]
            nonsortable = [
                e
                for e in entries
                if not (
                    isinstance(e.get(FlextLdifConstants.DictKeys.DN), str)
                    and len(str(e.get(FlextLdifConstants.DictKeys.DN))) > 0
                )
            ]

            # Sort sortable entries, keep non-sortable at end in original order
            sorted_entries = sorted(sortable, key=sort_key) + nonsortable

            return FlextResult[list[dict[str, object]]].ok(sorted_entries)

        except Exception as e:
            return FlextResult[list[dict[str, object]]].fail(
                f"Dictionary entry sorting failed: {e}",
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
        entries: list[dict[str, object]],
    ) -> FlextResult[list[dict[str, object]]]:
        """Sort entries alphabetically by DN (case-insensitive).

        Simple alphabetical ordering without hierarchy consideration.

        Args:
            entries: List of entry dictionaries

        Returns:
            FlextResult with alphabetically sorted entries

        """
        try:

            def sort_key(entry: dict[str, object]) -> str:
                dn_value = entry.get(FlextLdifConstants.DictKeys.DN, "")
                dn = dn_value if isinstance(dn_value, str) else ""
                return dn.lower()

            sorted_entries = sorted(entries, key=sort_key)
            return FlextResult[list[dict[str, object]]].ok(sorted_entries)

        except Exception as e:
            return FlextResult[list[dict[str, object]]].fail(
                f"Alphabetical sorting failed: {e}",
            )

    @staticmethod
    def sort_schema_entries(
        schema_entries: dict[str, object],
    ) -> FlextResult[dict[str, object]]:
        """Sort schema definitions (attributes before object classes).

        Schema ordering:
        1. attributeTypes (OID-based sorting)
        2. objectClasses (OID-based sorting)
        3. Other schema elements

        Args:
            schema_entries: Dictionary with schema definitions

        Returns:
            FlextResult with ordered schema entries

        """
        try:
            ordered_schema: dict[str, object] = {}

            # Process attributes first
            if "attributeTypes" in schema_entries:
                attributes = schema_entries["attributeTypes"]
                if isinstance(attributes, list):
                    ordered_schema["attributeTypes"] = (
                        FlextLdifSortingService._sort_schema_list(attributes)
                    )
                else:
                    ordered_schema["attributeTypes"] = attributes

            # Process object classes second
            if "objectClasses" in schema_entries:
                objectclasses = schema_entries["objectClasses"]
                if isinstance(objectclasses, list):
                    ordered_schema["objectClasses"] = (
                        FlextLdifSortingService._sort_schema_list(objectclasses)
                    )
                else:
                    ordered_schema["objectClasses"] = objectclasses

            # Add remaining schema elements in order
            ordered_schema.update({
                key: value
                for key, value in schema_entries.items()
                if key not in {"attributeTypes", "objectClasses"}
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
        entries: list[dict[str, object]],
        predicate: Callable[[dict[str, object]], str | int | float],
    ) -> FlextResult[list[dict[str, object]]]:
        """Sort entries using custom comparison predicate.

        Args:
            entries: List of entries to sort
            predicate: Callable that returns sort key from entry

        Returns:
            FlextResult with sorted entries

        """
        try:
            sorted_entries = sorted(entries, key=predicate)
            return FlextResult[list[dict[str, object]]].ok(sorted_entries)

        except Exception as e:
            return FlextResult[list[dict[str, object]]].fail(
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
