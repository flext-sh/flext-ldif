"""Power Method Filters - Entry filtering classes for pipelines."""

from __future__ import annotations

import re
from collections.abc import Callable, MutableMapping, MutableSequence
from re import Pattern
from typing import TYPE_CHECKING, Literal

from flext_ldif import FlextLdifUtilitiesEntry

if TYPE_CHECKING:
    from flext_ldif import m


class FlextLdifUtilitiesFilters[T]:
    """Base class for entry filters."""

    __slots__ = ()

    def __and__(
        self,
        other: FlextLdifUtilitiesFilters[T],
    ) -> _AndFilter[T]:
        """AND combination: filter1 & filter2."""
        return _AndFilter[T](self, other)

    def __invert__(self) -> _NotFilter[T]:
        """NOT negation: ~filter."""
        return _NotFilter[T](self)

    def __or__(
        self,
        other: FlextLdifUtilitiesFilters[T],
    ) -> _OrFilter[T]:
        """OR combination: filter1 | filter2."""
        return _OrFilter[T](self, other)

    def filter(self, items: MutableSequence[T]) -> MutableSequence[T]:
        """Filter a sequence of items."""
        return [item for item in items if self.matches(item)]

    def matches(self, item: T) -> bool:
        """Check if an item matches the filter criteria."""
        raise NotImplementedError


class _AndFilter[U](FlextLdifUtilitiesFilters[U]):
    """Filter that combines two filters with AND logic."""

    __slots__ = ("_left", "_right")

    def __init__(
        self,
        left: FlextLdifUtilitiesFilters[U],
        right: FlextLdifUtilitiesFilters[U],
    ) -> None:
        """Initialize AND filter."""
        super().__init__()
        self._left = left
        self._right = right

    def matches(self, item: U) -> bool:
        """Check if item matches both filters."""
        return self._left.matches(item) and self._right.matches(item)


class _OrFilter[U](FlextLdifUtilitiesFilters[U]):
    """Filter that combines two filters with OR logic."""

    __slots__ = ("_left", "_right")

    def __init__(
        self,
        left: FlextLdifUtilitiesFilters[U],
        right: FlextLdifUtilitiesFilters[U],
    ) -> None:
        """Initialize OR filter."""
        super().__init__()
        self._left = left
        self._right = right

    def matches(self, item: U) -> bool:
        """Check if item matches either filter."""
        return self._left.matches(item) or self._right.matches(item)


class _NotFilter[U](FlextLdifUtilitiesFilters[U]):
    """Filter that negates another filter."""

    __slots__ = ("_inner",)

    def __init__(self, inner: FlextLdifUtilitiesFilters[U]) -> None:
        """Initialize NOT filter."""
        super().__init__()
        self._inner = inner

    def matches(self, item: U) -> bool:
        """Check if item does NOT match inner filter."""
        return not self._inner.matches(item)


class _ByDnFilter(FlextLdifUtilitiesFilters["m.Ldif.Entry"]):
    """Filter entries by DN pattern."""

    __slots__ = ("_case_insensitive", "_pattern")

    def __init__(
        self,
        pattern: str | Pattern[str],
        *,
        case_insensitive: bool = True,
    ) -> None:
        """Initialize DN filter."""
        super().__init__()
        compiled_pattern: Pattern[str]
        if isinstance(pattern, str):
            flags = re.IGNORECASE if case_insensitive else 0
            compiled_pattern = re.compile(pattern, flags)
        else:
            compiled_pattern = pattern
        self._pattern = compiled_pattern
        self._case_insensitive = case_insensitive

    def matches(self, item: m.Ldif.Entry) -> bool:
        """Check if entry DN matches pattern."""
        if item.dn is None:
            return False
        dn_str = (
            item.dn.value
            if getattr(item.dn, "value", None) is not None
            else str(item.dn)
        )
        return bool(self._pattern.search(dn_str))


class _ByDnUnderBaseFilter(FlextLdifUtilitiesFilters["m.Ldif.Entry"]):
    """Filter entries by base DN."""

    __slots__ = ("_base_dn", "_case_insensitive")

    def __init__(self, base_dn: str, *, case_insensitive: bool = True) -> None:
        """Initialize base DN filter."""
        super().__init__()
        self._base_dn = base_dn.lower() if case_insensitive else base_dn
        self._case_insensitive = case_insensitive

    def matches(self, item: m.Ldif.Entry) -> bool:
        """Check if entry DN is under base DN."""
        if item.dn is None:
            return False
        dn_str = (
            item.dn.value
            if getattr(item.dn, "value", None) is not None
            else str(item.dn)
        )
        if self._case_insensitive:
            dn_str = dn_str.lower()
        return dn_str.endswith((self._base_dn, f",{self._base_dn}"))


class _ByObjectClassFilter(FlextLdifUtilitiesFilters["m.Ldif.Entry"]):
    """Filter entries by objectClass."""

    __slots__ = ("_case_insensitive", "_classes", "_mode")

    def __init__(
        self,
        *classes: str,
        mode: Literal["any", "all"] = "any",
        case_insensitive: bool = True,
    ) -> None:
        """Initialize objectClass filter."""
        super().__init__()
        self._case_insensitive = case_insensitive
        self._classes = (
            {c.lower() for c in classes} if case_insensitive else set(classes)
        )
        self._mode = mode

    def matches(self, item: m.Ldif.Entry) -> bool:
        """Check if entry has matching objectClasses."""
        if item.attributes is None:
            return False
        attrs: MutableMapping[str, MutableSequence[str]] = (
            item.attributes.attributes
            if getattr(item.attributes, "attributes", None) is not None
            else {}
        )
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
        return self._classes <= entry_classes


class _ByAttrsFilter(FlextLdifUtilitiesFilters["m.Ldif.Entry"]):
    """Filter entries by attribute presence."""

    __slots__ = ("_attrs", "_case_insensitive", "_mode")

    def __init__(
        self,
        *attrs: str,
        mode: Literal["any", "all"] = "any",
        case_insensitive: bool = True,
    ) -> None:
        """Initialize attribute filter."""
        super().__init__()
        self._case_insensitive = case_insensitive
        self._attrs = {a.lower() for a in attrs} if case_insensitive else set(attrs)
        self._mode = mode

    def matches(self, item: m.Ldif.Entry) -> bool:
        """Check if entry has matching attributes."""
        if item.attributes is None:
            return False
        attrs: MutableMapping[str, MutableSequence[str]] = (
            item.attributes.attributes
            if getattr(item.attributes, "attributes", None) is not None
            else {}
        )
        entry_attrs = (
            {k.lower() for k in attrs} if self._case_insensitive else set(attrs.keys())
        )
        if self._mode == "any":
            return bool(entry_attrs & self._attrs)
        return self._attrs <= entry_attrs


class _ByAttrValueFilter(FlextLdifUtilitiesFilters["m.Ldif.Entry"]):
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
        super().__init__()
        self._attr = attr.lower() if case_insensitive else attr
        compiled_pattern: Pattern[str]
        if isinstance(pattern, str):
            flags = re.IGNORECASE if case_insensitive else 0
            compiled_pattern = re.compile(pattern, flags)
        else:
            compiled_pattern = pattern
        self._pattern = compiled_pattern
        self._case_insensitive = case_insensitive

    def matches(self, item: m.Ldif.Entry) -> bool:
        """Check if entry has attribute with matching value."""
        if item.attributes is None:
            return False
        attrs: MutableMapping[str, MutableSequence[str]] = (
            item.attributes.attributes
            if getattr(item.attributes, "attributes", None) is not None
            else {}
        )
        for attr_name, values in attrs.items():
            attr_key = attr_name.lower() if self._case_insensitive else attr_name
            if attr_key == self._attr:
                return any(self._pattern.search(v) for v in values)
        return False


class _ExcludeAttrsFilter(FlextLdifUtilitiesFilters["m.Ldif.Entry"]):
    """Filter entries that do NOT have specific attributes."""

    __slots__ = ("_attrs", "_case_insensitive")

    def __init__(self, *attrs: str, case_insensitive: bool = True) -> None:
        """Initialize exclude attributes filter."""
        super().__init__()
        self._case_insensitive = case_insensitive
        self._attrs = {a.lower() for a in attrs} if case_insensitive else set(attrs)

    def matches(self, item: m.Ldif.Entry) -> bool:
        """Check if entry is missing any of the specified attributes."""
        if item.attributes is None:
            return True
        attrs: MutableMapping[str, MutableSequence[str]] = (
            item.attributes.attributes
            if getattr(item.attributes, "attributes", None) is not None
            else {}
        )
        entry_attrs = (
            {k.lower() for k in attrs} if self._case_insensitive else set(attrs.keys())
        )
        return not bool(entry_attrs & self._attrs)


class _IsSchemaFilter(FlextLdifUtilitiesFilters["m.Ldif.Entry"]):
    """Filter for schema entries."""

    __slots__ = ("_is_schema",)

    def __init__(self, *, is_schema: bool = True) -> None:
        """Initialize schema entry filter."""
        super().__init__()
        self._is_schema = is_schema

    def matches(self, item: m.Ldif.Entry) -> bool:
        """Check if entry is a schema entry."""
        entry_facade: m.Ldif.Entry = item
        result = FlextLdifUtilitiesEntry.is_schema_entry(entry_facade)
        return result == self._is_schema


class _CustomFilter(FlextLdifUtilitiesFilters["m.Ldif.Entry"]):
    """Filter using a custom predicate function."""

    __slots__ = ("_predicate",)

    def __init__(self, predicate: Callable[[m.Ldif.Entry], bool]) -> None:
        """Initialize custom filter."""
        super().__init__()
        self._predicate = predicate

    def matches(self, item: m.Ldif.Entry) -> bool:
        """Check if entry matches custom predicate."""
        return self._predicate(item)


class _FilterFactory:
    """Factory class for creating entry filters."""

    __slots__ = ()

    @staticmethod
    def by_attrs(
        *attrs: str,
        mode: Literal["any", "all"] = "any",
        case_insensitive: bool = True,
    ) -> _ByAttrsFilter:
        """Create an attribute presence filter."""
        return _ByAttrsFilter(
            *attrs,
            mode=mode,
            case_insensitive=case_insensitive,
        )

    @staticmethod
    def by_dn(
        pattern: str | Pattern[str],
        *,
        case_insensitive: bool = True,
    ) -> _ByDnFilter:
        """Create a DN pattern filter."""
        return _ByDnFilter(
            pattern,
            case_insensitive=case_insensitive,
        )

    @staticmethod
    def by_dn_under(
        base_dn: str,
        *,
        case_insensitive: bool = True,
    ) -> _ByDnUnderBaseFilter:
        """Create a base DN filter."""
        return _ByDnUnderBaseFilter(
            base_dn,
            case_insensitive=case_insensitive,
        )

    @staticmethod
    def by_objectclass(
        *classes: str,
        mode: Literal["any", "all"] = "any",
        case_insensitive: bool = True,
    ) -> _ByObjectClassFilter:
        """Create an objectClass filter."""
        return _ByObjectClassFilter(
            *classes,
            mode=mode,
            case_insensitive=case_insensitive,
        )

    @staticmethod
    def custom(
        predicate: Callable[[m.Ldif.Entry], bool],
    ) -> _CustomFilter:
        """Create a custom filter from a predicate function."""
        return _CustomFilter(predicate)

    @staticmethod
    def is_schema(
        *,
        is_schema: bool = True,
    ) -> _IsSchemaFilter:
        """Create a schema entry filter."""
        return _IsSchemaFilter(
            is_schema=is_schema,
        )


# Attach inner classes to outer class for backward compatibility
FlextLdifUtilitiesFilters.AndFilter = _AndFilter  # type: ignore[attr-defined]
FlextLdifUtilitiesFilters.OrFilter = _OrFilter  # type: ignore[attr-defined]
FlextLdifUtilitiesFilters.NotFilter = _NotFilter  # type: ignore[attr-defined]
FlextLdifUtilitiesFilters.ByDnFilter = _ByDnFilter  # type: ignore[attr-defined]
FlextLdifUtilitiesFilters.ByDnUnderBaseFilter = _ByDnUnderBaseFilter  # type: ignore[attr-defined]
FlextLdifUtilitiesFilters.ByObjectClassFilter = _ByObjectClassFilter  # type: ignore[attr-defined]
FlextLdifUtilitiesFilters.ByAttrsFilter = _ByAttrsFilter  # type: ignore[attr-defined]
FlextLdifUtilitiesFilters.ByAttrValueFilter = _ByAttrValueFilter  # type: ignore[attr-defined]
FlextLdifUtilitiesFilters.ExcludeAttrsFilter = _ExcludeAttrsFilter  # type: ignore[attr-defined]
FlextLdifUtilitiesFilters.IsSchemaFlextLdifUtilitiesFilters = _IsSchemaFilter  # type: ignore[attr-defined]
FlextLdifUtilitiesFilters.CustomFilter = _CustomFilter  # type: ignore[attr-defined]
FlextLdifUtilitiesFilters.Filter = _FilterFactory  # type: ignore[attr-defined]

# Module-level aliases for backward compatibility (referenced by __init__.py)
AndFilter = _AndFilter
OrFilter = _OrFilter
NotFilter = _NotFilter
ByDnFilter = _ByDnFilter
ByDnUnderBaseFilter = _ByDnUnderBaseFilter
ByObjectClassFilter = _ByObjectClassFilter
ByAttrsFilter = _ByAttrsFilter
ByAttrValueFilter = _ByAttrValueFilter
ExcludeAttrsFilter = _ExcludeAttrsFilter
IsSchemaFlextLdifUtilitiesFilters = _IsSchemaFilter
CustomFilter = _CustomFilter
Filter = _FilterFactory

__all__ = [
    "AndFilter",
    "ByAttrValueFilter",
    "ByAttrsFilter",
    "ByDnFilter",
    "ByDnUnderBaseFilter",
    "ByObjectClassFilter",
    "CustomFilter",
    "ExcludeAttrsFilter",
    "Filter",
    "FlextLdifUtilitiesFilters",
    "IsSchemaFlextLdifUtilitiesFilters",
    "NotFilter",
    "OrFilter",
]
