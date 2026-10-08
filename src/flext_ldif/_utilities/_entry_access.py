"""LDIF entry attribute access utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable

from flext_ldif import c, p, t


class FlextLdifEntryAccess:
    """Read attributes, DN components, and objectClasses from entries."""

    @staticmethod
    def resolve_attribute_values(
        entry: p.Ldif.Entry,
        attribute_name: str,
    ) -> t.MutableSequenceOf[str]:
        """Get all values for a specific attribute (case-insensitive).

        Args:
            entry: LDIF entry to query
            attribute_name: Name of the attribute to retrieve

        Returns:
            List of attribute values, empty list if attribute doesn't exist

        """
        if entry.attributes is None:
            return []
        attrs_dict = entry.attributes.attributes
        if not attrs_dict:
            return []
        attr_name_lower = attribute_name.lower()
        for stored_name, attr_values in attrs_dict.items():
            if stored_name.lower() == attr_name_lower:
                return attr_values
        return []

    @staticmethod
    def resolve_objectclass_names(entry: p.Ldif.Entry) -> t.MutableSequenceOf[str]:
        """Get list of objectClass attribute values from entry.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        return FlextLdifEntryAccess.resolve_attribute_values(
            entry,
            c.Ldif.DictKeys.OBJECTCLASS,
        )

    @staticmethod
    def has_attribute(entry: p.Ldif.Entry, attribute_name: str) -> bool:
        """Check if entry has a specific attribute (case-insensitive).

        Args:
            entry: LDIF entry to check
            attribute_name: Name of the attribute to check

        Returns:
            True if attribute exists with at least one value, False otherwise

        """
        return bool(
            FlextLdifEntryAccess.resolve_attribute_values(entry, attribute_name)
        )

    @staticmethod
    def has_object_class(entry: p.Ldif.Entry, object_class: str) -> bool:
        """Check if entry has specified object class.

        Args:
            entry: LDIF entry to check
            object_class: Name of the object class to check

        Returns:
            True if entry has the object class, False otherwise

        """
        return object_class in FlextLdifEntryAccess.resolve_attribute_values(
            entry,
            c.Ldif.DictKeys.OBJECTCLASS,
        )

    @staticmethod
    def matches_filter(
        entry: p.Ldif.Entry,
        filter_func: Callable[[p.Ldif.Entry], bool] | None = None,
    ) -> bool:
        """Check if entry matches a filter function.

        If no filter provided, returns True (entry matches).

        Args:
            entry: LDIF entry to check
            filter_func: Optional callable that takes Entry and returns bool

        Returns:
            True if entry matches filter (or no filter provided), False otherwise

        """
        if filter_func is None:
            return True
        return filter_func(entry)


__all__: list[str] = ["FlextLdifEntryAccess"]
