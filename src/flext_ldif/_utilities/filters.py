"""Power Method Filters - Entry filtering classes for pipelines.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides filter classes for the power method pipeline system:
    - EntryFilter: Base class for entry filters
    - Filter: Factory class for creating filters
    - Composable filters with &, |, ~ operators

Python 3.13+ features:
    - PEP 695 type parameter syntax
    - Self type for method chaining
    - Operator overloading for filter composition

Usage:
    from flext_ldif._utilities.filters import Filter

    # Simple filter
    result = FlextLdifUtilities.filter(entries, Filter.by_objectclass("person"))

    # Composite filter with operators
    filter = (
        Filter.by_dn(r".*ou=users.*")
        & Filter.by_objectclass("inetOrgPerson")
        & ~Filter.by_attrs("disabled")
    )
    result = FlextLdifUtilities.filter(entries, filter)
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from re import Pattern
from typing import Literal, cast

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
from flext_ldif.models import m

# =========================================================================
# BASE FILTER CLASS
# =========================================================================


class EntryFilter[T](ABC):
    """Abstract base class for entry filters.

    Filters implement the FilterProtocol and support operator composition:
        - filter1 & filter2 - AND combination
        - filter1 | filter2 - OR combination
        - ~filter - NOT (negation)

    Type Parameters:
        T: The type being filtered (typically Entry)

    Subclasses must implement:
        - matches(): Check if an item matches the filter
    """

    __slots__ = ()

    @abstractmethod
    def matches(self, item: T) -> bool:
        """Check if an item matches the filter criteria.

        Args:
            item: The item to check

        Returns:
            True if the item matches, False otherwise

        """
        ...

    def __and__(self, other: EntryFilter[T]) -> AndFilter[T]:
        """AND combination: filter1 & filter2.

        Args:
            other: Another filter to combine with

        Returns:
            Combined AndFilter

        """
        return AndFilter(self, other)

    def __or__(self, other: EntryFilter[T]) -> OrFilter[T]:
        """OR combination: filter1 | filter2.

        Args:
            other: Another filter to combine with

        Returns:
            Combined OrFilter

        """
        return OrFilter(self, other)

    def __invert__(self) -> NotFilter[T]:
        """NOT negation: ~filter.

        Returns:
            Negated NotFilter

        """
        return NotFilter(self)

    def filter(self, items: Sequence[T]) -> list[T]:
        """Filter a sequence of items.

        Args:
            items: Sequence of items to filter

        Returns:
            List of items matching the filter

        """
        return [item for item in items if self.matches(item)]


# =========================================================================
# COMPOSITE FILTERS - AND, OR, NOT
# =========================================================================


class AndFilter[T](EntryFilter[T]):
    """Filter that combines two filters with AND logic.

    Both filters must match for the composite to match.
    """

    __slots__ = ("_left", "_right")

    def __init__(self, left: EntryFilter[T], right: EntryFilter[T]) -> None:
        """Initialize AND filter.

        Args:
            left: First filter
            right: Second filter

        """
        self._left = left
        self._right = right

    def matches(self, item: T) -> bool:
        """Check if item matches both filters.

        Args:
            item: Item to check

        Returns:
            True if both filters match

        """
        return self._left.matches(item) and self._right.matches(item)


class OrFilter[T](EntryFilter[T]):
    """Filter that combines two filters with OR logic.

    Either filter matching is sufficient.
    """

    __slots__ = ("_left", "_right")

    def __init__(self, left: EntryFilter[T], right: EntryFilter[T]) -> None:
        """Initialize OR filter.

        Args:
            left: First filter
            right: Second filter

        """
        self._left = left
        self._right = right

    def matches(self, item: T) -> bool:
        """Check if item matches either filter.

        Args:
            item: Item to check

        Returns:
            True if either filter matches

        """
        return self._left.matches(item) or self._right.matches(item)


class NotFilter[T](EntryFilter[T]):
    """Filter that negates another filter.

    Matches when the inner filter does NOT match.
    """

    __slots__ = ("_inner",)

    def __init__(self, inner: EntryFilter[T]) -> None:
        """Initialize NOT filter.

        Args:
            inner: Filter to negate

        """
        self._inner = inner

    def matches(self, item: T) -> bool:
        """Check if item does NOT match inner filter.

        Args:
            item: Item to check

        Returns:
            True if inner filter does NOT match

        """
        return not self._inner.matches(item)


# =========================================================================
# DN FILTERS
# =========================================================================


class ByDnFilter(EntryFilter["FlextLdifModelsDomains.Entry"]):
    """Filter entries by DN pattern.

    Matches entries whose DN matches the given regex pattern.
    """

    __slots__ = ("_case_insensitive", "_pattern")

    def __init__(
        self,
        pattern: str | Pattern[str],
        *,
        case_insensitive: bool = True,
    ) -> None:
        """Initialize DN filter.

        Args:
            pattern: Regex pattern to match against DN
            case_insensitive: Whether matching is case-insensitive

        """
        if isinstance(pattern, str):
            flags = re.IGNORECASE if case_insensitive else 0
            self._pattern = re.compile(pattern, flags)
        else:
            self._pattern = pattern
        self._case_insensitive = case_insensitive

    def matches(self, item: FlextLdifModelsDomains.Entry) -> bool:
        """Check if entry DN matches pattern.

        Args:
            item: Entry to check

        Returns:
            True if DN matches pattern

        """
        if item.dn is None:
            return False

        dn_str = item.dn.value if hasattr(item.dn, "value") else str(item.dn)
        return bool(self._pattern.search(dn_str))


class ByDnUnderBaseFilter(EntryFilter["FlextLdifModelsDomains.Entry"]):
    """Filter entries by base DN.

    Matches entries whose DN is under the specified base DN.
    """

    __slots__ = ("_base_dn", "_case_insensitive")

    def __init__(
        self,
        base_dn: str,
        *,
        case_insensitive: bool = True,
    ) -> None:
        """Initialize base DN filter.

        Args:
            base_dn: Base DN to check
            case_insensitive: Whether matching is case-insensitive

        """
        self._base_dn = base_dn.lower() if case_insensitive else base_dn
        self._case_insensitive = case_insensitive

    def matches(self, item: FlextLdifModelsDomains.Entry) -> bool:
        """Check if entry DN is under base DN.

        Args:
            item: Entry to check

        Returns:
            True if DN is under base DN

        """
        if item.dn is None:
            return False

        dn_str = item.dn.value if hasattr(item.dn, "value") else str(item.dn)
        if self._case_insensitive:
            dn_str = dn_str.lower()

        return dn_str.endswith((self._base_dn, f",{self._base_dn}"))


# =========================================================================
# OBJECTCLASS FILTERS
# =========================================================================


class ByObjectClassFilter(EntryFilter["FlextLdifModelsDomains.Entry"]):
    """Filter entries by objectClass.

    Matches entries that have any or all of the specified objectClasses.
    """

    __slots__ = ("_case_insensitive", "_classes", "_mode")

    def __init__(
        self,
        *classes: str,
        mode: Literal["any", "all"] = "any",
        case_insensitive: bool = True,
    ) -> None:
        """Initialize objectClass filter.

        Args:
            *classes: objectClass names to match
            mode: "any" matches if any class is present, "all" requires all
            case_insensitive: Whether matching is case-insensitive

        """
        self._case_insensitive = case_insensitive
        self._classes = (
            {c.lower() for c in classes} if case_insensitive else set(classes)
        )
        self._mode = mode

    def matches(self, item: FlextLdifModelsDomains.Entry) -> bool:
        """Check if entry has matching objectClasses.

        Args:
            item: Entry to check

        Returns:
            True if objectClass criteria is met

        """
        if item.attributes is None:
            return False

        # Get entry's objectClasses
        attrs = (
            item.attributes.attributes if hasattr(item.attributes, "attributes") else {}
        )

        # Find objectClass attribute (case-insensitive lookup)
        entry_classes: set[str] = set()
        for attr_name, values in attrs.items():
            if attr_name.lower() == "objectclass":
                entry_classes = (
                    {v.lower() for v in values}
                    if self._case_insensitive
                    else set(values)
                )
                break

        if self._mode == "any":
            return bool(entry_classes & self._classes)
        # "all"
        return self._classes <= entry_classes


# =========================================================================
# ATTRIBUTE FILTERS
# =========================================================================


class ByAttrsFilter(EntryFilter["FlextLdifModelsDomains.Entry"]):
    """Filter entries by attribute presence.

    Matches entries that have any or all of the specified attributes.
    """

    __slots__ = ("_attrs", "_case_insensitive", "_mode")

    def __init__(
        self,
        *attrs: str,
        mode: Literal["any", "all"] = "any",
        case_insensitive: bool = True,
    ) -> None:
        """Initialize attribute filter.

        Args:
            *attrs: Attribute names to check
            mode: "any" matches if any attr is present, "all" requires all
            case_insensitive: Whether matching is case-insensitive

        """
        self._case_insensitive = case_insensitive
        self._attrs = {a.lower() for a in attrs} if case_insensitive else set(attrs)
        self._mode = mode

    def matches(self, item: FlextLdifModelsDomains.Entry) -> bool:
        """Check if entry has matching attributes.

        Args:
            item: Entry to check

        Returns:
            True if attribute criteria is met

        """
        if item.attributes is None:
            return False

        attrs = (
            item.attributes.attributes if hasattr(item.attributes, "attributes") else {}
        )
        entry_attrs = (
            {k.lower() for k in attrs} if self._case_insensitive else set(attrs.keys())
        )

        if self._mode == "any":
            return bool(entry_attrs & self._attrs)
        # "all"
        return self._attrs <= entry_attrs


class ByAttrValueFilter(EntryFilter["FlextLdifModelsDomains.Entry"]):
    """Filter entries by attribute value.

    Matches entries where a specific attribute has a matching value.
    """

    __slots__ = ("_attr", "_case_insensitive", "_pattern")

    def __init__(
        self,
        attr: str,
        pattern: str | Pattern[str],
        *,
        case_insensitive: bool = True,
    ) -> None:
        """Initialize attribute value filter.

        Args:
            attr: Attribute name to check
            pattern: Regex pattern to match against value
            case_insensitive: Whether matching is case-insensitive

        """
        self._attr = attr.lower() if case_insensitive else attr
        if isinstance(pattern, str):
            flags = re.IGNORECASE if case_insensitive else 0
            self._pattern = re.compile(pattern, flags)
        else:
            self._pattern = pattern
        self._case_insensitive = case_insensitive

    def matches(self, item: FlextLdifModelsDomains.Entry) -> bool:
        """Check if entry has attribute with matching value.

        Args:
            item: Entry to check

        Returns:
            True if attribute value matches pattern

        """
        if item.attributes is None:
            return False

        attrs = (
            item.attributes.attributes if hasattr(item.attributes, "attributes") else {}
        )

        # Find attribute (case-insensitive lookup if needed)
        for attr_name, values in attrs.items():
            attr_key = attr_name.lower() if self._case_insensitive else attr_name
            if attr_key == self._attr:
                return any(self._pattern.search(v) for v in values)

        return False


class ExcludeAttrsFilter(EntryFilter["FlextLdifModelsDomains.Entry"]):
    """Filter entries that do NOT have specific attributes.

    Matches entries that are missing any of the specified attributes.
    """

    __slots__ = ("_attrs", "_case_insensitive")

    def __init__(
        self,
        *attrs: str,
        case_insensitive: bool = True,
    ) -> None:
        """Initialize exclude attributes filter.

        Args:
            *attrs: Attribute names to exclude
            case_insensitive: Whether matching is case-insensitive

        """
        self._case_insensitive = case_insensitive
        self._attrs = {a.lower() for a in attrs} if case_insensitive else set(attrs)

    def matches(self, item: FlextLdifModelsDomains.Entry) -> bool:
        """Check if entry is missing any of the specified attributes.

        Args:
            item: Entry to check

        Returns:
            True if entry does NOT have any of the specified attributes

        """
        if item.attributes is None:
            return True

        attrs = (
            item.attributes.attributes if hasattr(item.attributes, "attributes") else {}
        )
        entry_attrs = (
            {k.lower() for k in attrs} if self._case_insensitive else set(attrs.keys())
        )

        return not bool(entry_attrs & self._attrs)


# =========================================================================
# SPECIAL FILTERS
# =========================================================================


class IsSchemaEntryFilter(EntryFilter["FlextLdifModelsDomains.Entry"]):
    """Filter for schema entries.

    Matches entries that are schema entries (contain schema definitions).
    """

    __slots__ = ("_is_schema",)

    def __init__(self, *, is_schema: bool = True) -> None:
        """Initialize schema entry filter.

        Args:
            is_schema: True to match schema entries, False to exclude them

        """
        self._is_schema = is_schema

    def matches(self, item: FlextLdifModelsDomains.Entry) -> bool:
        """Check if entry is a schema entry.

        Args:
            item: Entry to check

        Returns:
            True if schema status matches expected value

        """
        # Convert FlextLdifModelsDomains.Entry to m.Ldif.Entry for is_schema_entry
        # m.Ldif.Entry is the facade that extends FlextLdifModelsDomains.Entry
        entry_facade: m.Ldif.Entry = cast("m.Ldif.Entry", item)
        result = FlextLdifUtilitiesEntry.is_schema_entry(entry_facade)
        return result == self._is_schema


class CustomFilter(EntryFilter["FlextLdifModelsDomains.Entry"]):
    """Filter using a custom predicate function.

    Allows arbitrary filtering via a callable.
    """

    __slots__ = ("_predicate",)

    def __init__(
        self,
        predicate: Callable[[FlextLdifModelsDomains.Entry], bool],
    ) -> None:
        """Initialize custom filter.

        Args:
            predicate: Function that returns True for matching entries

        """
        self._predicate = predicate

    def matches(self, item: FlextLdifModelsDomains.Entry) -> bool:
        """Check if entry matches custom predicate.

        Args:
            item: Entry to check

        Returns:
            True if predicate returns True

        """
        return self._predicate(item)


# =========================================================================
# FILTER FACTORY
# =========================================================================


class Filter:
    """Factory class for creating entry filters.

    Provides static methods to create filter objects for use in
    pipeline chains. Filters support composition via operators:
        - filter1 & filter2 - AND combination
        - filter1 | filter2 - OR combination
        - ~filter - NOT (negation)

    Examples:
        >>> # Simple filter
        >>> result = entries | Filter.by_objectclass("person")

        >>> # Composite filter
        >>> filter = (
        ...     Filter.by_dn(r".*ou=users.*")
        ...     & Filter.by_objectclass("inetOrgPerson")
        ...     & ~Filter.by_attrs("disabled")
        ... )

    """

    __slots__ = ()

    @staticmethod
    def by_dn(
        pattern: str | Pattern[str],
        *,
        case_insensitive: bool = True,
    ) -> ByDnFilter:
        """Create a DN pattern filter.

        Args:
            pattern: Regex pattern to match against DN
            case_insensitive: Whether matching is case-insensitive

        Returns:
            ByDnFilter instance

        """
        return ByDnFilter(pattern, case_insensitive=case_insensitive)

    @staticmethod
    def by_dn_under(
        base_dn: str,
        *,
        case_insensitive: bool = True,
    ) -> ByDnUnderBaseFilter:
        """Create a base DN filter.

        Args:
            base_dn: Base DN to check
            case_insensitive: Whether matching is case-insensitive

        Returns:
            ByDnUnderBaseFilter instance

        """
        return ByDnUnderBaseFilter(base_dn, case_insensitive=case_insensitive)

    @staticmethod
    def by_objectclass(
        *classes: str,
        mode: Literal["any", "all"] = "any",
        case_insensitive: bool = True,
    ) -> ByObjectClassFilter:
        """Create an objectClass filter.

        Args:
            *classes: objectClass names to match
            mode: "any" matches if any class is present, "all" requires all
            case_insensitive: Whether matching is case-insensitive

        Returns:
            ByObjectClassFilter instance

        """
        return ByObjectClassFilter(
            *classes,
            mode=mode,
            case_insensitive=case_insensitive,
        )

    @staticmethod
    def by_attrs(
        *attrs: str,
        mode: Literal["any", "all"] = "any",
        case_insensitive: bool = True,
    ) -> ByAttrsFilter:
        """Create an attribute presence filter.

        Args:
            *attrs: Attribute names to check
            mode: "any" matches if any attr is present, "all" requires all
            case_insensitive: Whether matching is case-insensitive

        Returns:
            ByAttrsFilter instance

        """
        return ByAttrsFilter(*attrs, mode=mode, case_insensitive=case_insensitive)

    @staticmethod
    def by_value(
        attr: str,
        pattern: str | Pattern[str],
        *,
        case_insensitive: bool = True,
    ) -> ByAttrValueFilter:
        """Create an attribute value filter.

        Args:
            attr: Attribute name to check
            pattern: Regex pattern to match against value
            case_insensitive: Whether matching is case-insensitive

        Returns:
            ByAttrValueFilter instance

        """
        return ByAttrValueFilter(attr, pattern, case_insensitive=case_insensitive)

    @staticmethod
    def exclude_attrs(
        *attrs: str,
        case_insensitive: bool = True,
    ) -> ExcludeAttrsFilter:
        """Create an attribute exclusion filter.

        Matches entries that do NOT have the specified attributes.

        Args:
            *attrs: Attribute names to exclude
            case_insensitive: Whether matching is case-insensitive

        Returns:
            ExcludeAttrsFilter instance

        """
        return ExcludeAttrsFilter(*attrs, case_insensitive=case_insensitive)

    @staticmethod
    def is_schema(*, is_schema: bool = True) -> IsSchemaEntryFilter:
        """Create a schema entry filter.

        Args:
            is_schema: True to match schema entries, False to exclude them

        Returns:
            IsSchemaEntryFilter instance

        """
        return IsSchemaEntryFilter(is_schema=is_schema)

    @staticmethod
    def custom(
        predicate: Callable[[FlextLdifModelsDomains.Entry], bool],
    ) -> CustomFilter:
        """Create a custom filter from a predicate function.

        Args:
            predicate: Function that returns True for matching entries

        Returns:
            CustomFilter instance

        """
        return CustomFilter(predicate)


__all__ = [
    # Composite filters
    "AndFilter",
    "ByAttrValueFilter",
    # Attribute filters
    "ByAttrsFilter",
    # DN filters
    "ByDnFilter",
    "ByDnUnderBaseFilter",
    # ObjectClass filters
    "ByObjectClassFilter",
    "CustomFilter",
    # Base class
    "EntryFilter",
    "ExcludeAttrsFilter",
    # Factory
    "Filter",
    # Special filters
    "IsSchemaEntryFilter",
    "NotFilter",
    "OrFilter",
]
