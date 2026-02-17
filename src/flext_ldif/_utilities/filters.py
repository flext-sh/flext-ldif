"""Power Method Filters - Entry filtering classes for pipelines."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from re import Pattern
from typing import Literal

from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
from flext_ldif.models import FlextLdifModels as m

# BASE FILTER CLASS


class EntryFilter[T](ABC):
    """Abstract base class for entry filters."""

    __slots__ = ()

    @abstractmethod
    def matches(self, item: T) -> bool:
        """Check if an item matches the filter criteria."""
        ...

    def __and__(self, other: EntryFilter[T]) -> AndFilter[T]:
        """AND combination: filter1 & filter2."""
        return AndFilter(self, other)

    def __or__(self, other: EntryFilter[T]) -> OrFilter[T]:
        """OR combination: filter1 | filter2."""
        return OrFilter(self, other)

    def __invert__(self) -> NotFilter[T]:
        """NOT negation: ~filter."""
        return NotFilter(self)

    def filter(self, items: Sequence[T]) -> list[T]:
        """Filter a sequence of items."""
        return [item for item in items if self.matches(item)]


# COMPOSITE FILTERS - AND, OR, NOT


class AndFilter[T](EntryFilter[T]):
    """Filter that combines two filters with AND logic."""

    __slots__ = ("_left", "_right")

    def __init__(self, left: EntryFilter[T], right: EntryFilter[T]) -> None:
        """Initialize AND filter."""
        self._left = left
        self._right = right

    def matches(self, item: T) -> bool:
        """Check if item matches both filters."""
        return self._left.matches(item) and self._right.matches(item)


class OrFilter[T](EntryFilter[T]):
    """Filter that combines two filters with OR logic."""

    __slots__ = ("_left", "_right")

    def __init__(self, left: EntryFilter[T], right: EntryFilter[T]) -> None:
        """Initialize OR filter."""
        self._left = left
        self._right = right

    def matches(self, item: T) -> bool:
        """Check if item matches either filter."""
        return self._left.matches(item) or self._right.matches(item)


class NotFilter[T](EntryFilter[T]):
    """Filter that negates another filter."""

    __slots__ = ("_inner",)

    def __init__(self, inner: EntryFilter[T]) -> None:
        """Initialize NOT filter."""
        self._inner = inner

    def matches(self, item: T) -> bool:
        """Check if item does NOT match inner filter."""
        return not self._inner.matches(item)


# DN FILTERS


class ByDnFilter(EntryFilter["m.Ldif.Entry"]):
    """Filter entries by DN pattern."""

    __slots__ = ("_case_insensitive", "_pattern")

    def __init__(
        self,
        pattern: str | Pattern[str],
        *,
        case_insensitive: bool = True,
    ) -> None:
        """Initialize DN filter."""
        if isinstance(pattern, str):
            flags = re.IGNORECASE if case_insensitive else 0
            self._pattern = re.compile(pattern, flags)
        else:
            self._pattern = pattern
        self._case_insensitive = case_insensitive

    def matches(self, item: m.Ldif.Entry) -> bool:
        """Check if entry DN matches pattern."""
        if item.dn is None:
            return False

        dn_str = item.dn.value if hasattr(item.dn, "value") else str(item.dn)
        return bool(self._pattern.search(dn_str))


class ByDnUnderBaseFilter(EntryFilter["m.Ldif.Entry"]):
    """Filter entries by base DN."""

    __slots__ = ("_base_dn", "_case_insensitive")

    def __init__(
        self,
        base_dn: str,
        *,
        case_insensitive: bool = True,
    ) -> None:
        """Initialize base DN filter."""
        self._base_dn = base_dn.lower() if case_insensitive else base_dn
        self._case_insensitive = case_insensitive

    def matches(self, item: m.Ldif.Entry) -> bool:
        """Check if entry DN is under base DN."""
        if item.dn is None:
            return False

        dn_str = item.dn.value if hasattr(item.dn, "value") else str(item.dn)
        if self._case_insensitive:
            dn_str = dn_str.lower()

        return dn_str.endswith((self._base_dn, f",{self._base_dn}"))


# OBJECTCLASS FILTERS


class ByObjectClassFilter(EntryFilter["m.Ldif.Entry"]):
    """Filter entries by objectClass."""

    __slots__ = ("_case_insensitive", "_classes", "_mode")

    def __init__(
        self,
        *classes: str,
        mode: Literal["any", "all"] = "any",
        case_insensitive: bool = True,
    ) -> None:
        """Initialize objectClass filter."""
        self._case_insensitive = case_insensitive
        self._classes = (
            {c.lower() for c in classes} if case_insensitive else set(classes)
        )
        self._mode = mode

    def matches(self, item: m.Ldif.Entry) -> bool:
        """Check if entry has matching objectClasses."""
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


# ATTRIBUTE FILTERS


class ByAttrsFilter(EntryFilter["m.Ldif.Entry"]):
    """Filter entries by attribute presence."""

    __slots__ = ("_attrs", "_case_insensitive", "_mode")

    def __init__(
        self,
        *attrs: str,
        mode: Literal["any", "all"] = "any",
        case_insensitive: bool = True,
    ) -> None:
        """Initialize attribute filter."""
        self._case_insensitive = case_insensitive
        self._attrs = {a.lower() for a in attrs} if case_insensitive else set(attrs)
        self._mode = mode

    def matches(self, item: m.Ldif.Entry) -> bool:
        """Check if entry has matching attributes."""
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


class ByAttrValueFilter(EntryFilter["m.Ldif.Entry"]):
    """Filter entries by attribute value."""

    __slots__ = ("_attr", "_case_insensitive", "_pattern")

    def __init__(
        self,
        attr: str,
        pattern: str | Pattern[str],
        *,
        case_insensitive: bool = True,
    ) -> None:
        """Initialize attribute value filter."""
        self._attr = attr.lower() if case_insensitive else attr
        if isinstance(pattern, str):
            flags = re.IGNORECASE if case_insensitive else 0
            self._pattern = re.compile(pattern, flags)
        else:
            self._pattern = pattern
        self._case_insensitive = case_insensitive

    def matches(self, item: m.Ldif.Entry) -> bool:
        """Check if entry has attribute with matching value."""
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


class ExcludeAttrsFilter(EntryFilter["m.Ldif.Entry"]):
    """Filter entries that do NOT have specific attributes."""

    __slots__ = ("_attrs", "_case_insensitive")

    def __init__(
        self,
        *attrs: str,
        case_insensitive: bool = True,
    ) -> None:
        """Initialize exclude attributes filter."""
        self._case_insensitive = case_insensitive
        self._attrs = {a.lower() for a in attrs} if case_insensitive else set(attrs)

    def matches(self, item: m.Ldif.Entry) -> bool:
        """Check if entry is missing any of the specified attributes."""
        if item.attributes is None:
            return True

        attrs = (
            item.attributes.attributes if hasattr(item.attributes, "attributes") else {}
        )
        entry_attrs = (
            {k.lower() for k in attrs} if self._case_insensitive else set(attrs.keys())
        )

        return not bool(entry_attrs & self._attrs)


# SPECIAL FILTERS


class IsSchemaEntryFilter(EntryFilter["m.Ldif.Entry"]):
    """Filter for schema entries."""

    __slots__ = ("_is_schema",)

    def __init__(self, *, is_schema: bool = True) -> None:
        """Initialize schema entry filter."""
        self._is_schema = is_schema

    def matches(self, item: m.Ldif.Entry) -> bool:
        """Check if entry is a schema entry."""
        # Use facade Entry type directly
        entry_facade: m.Ldif.Entry = item
        result = FlextLdifUtilitiesEntry.is_schema_entry(entry_facade)
        return result == self._is_schema


class CustomFilter(EntryFilter["m.Ldif.Entry"]):
    """Filter using a custom predicate function."""

    __slots__ = ("_predicate",)

    def __init__(
        self,
        predicate: Callable[[m.Ldif.Entry], bool],
    ) -> None:
        """Initialize custom filter."""
        self._predicate = predicate

    def matches(self, item: m.Ldif.Entry) -> bool:
        """Check if entry matches custom predicate."""
        return self._predicate(item)


# FILTER FACTORY


class Filter:
    """Factory class for creating entry filters."""

    __slots__ = ()

    @staticmethod
    def by_dn(
        pattern: str | Pattern[str],
        *,
        case_insensitive: bool = True,
    ) -> ByDnFilter:
        """Create a DN pattern filter."""
        return ByDnFilter(pattern, case_insensitive=case_insensitive)

    @staticmethod
    def by_dn_under(
        base_dn: str,
        *,
        case_insensitive: bool = True,
    ) -> ByDnUnderBaseFilter:
        """Create a base DN filter."""
        return ByDnUnderBaseFilter(base_dn, case_insensitive=case_insensitive)

    @staticmethod
    def by_objectclass(
        *classes: str,
        mode: Literal["any", "all"] = "any",
        case_insensitive: bool = True,
    ) -> ByObjectClassFilter:
        """Create an objectClass filter."""
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
        """Create an attribute presence filter."""
        return ByAttrsFilter(*attrs, mode=mode, case_insensitive=case_insensitive)

    @staticmethod
    def is_schema(*, is_schema: bool = True) -> IsSchemaEntryFilter:
        """Create a schema entry filter."""
        return IsSchemaEntryFilter(is_schema=is_schema)

    @staticmethod
    def custom(
        predicate: Callable[[m.Ldif.Entry], bool],
    ) -> CustomFilter:
        """Create a custom filter from a predicate function."""
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
