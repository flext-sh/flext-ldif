"""Test helpers extending flext_tests with flext-ldif specific functionality.

This module provides enhanced test helpers that extend flext_tests base classes
with flext-ldif specific functionality, making tests more concise and parameterized.

All helpers follow the pattern:
- Extend base class from flext_tests
- Add flext-ldif specific methods and parametrization
- Provide unified, general-purpose methods that validate many situations with minimal code

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, MutableSequence, Sequence
from pathlib import Path
from typing import TypeVar

from flext_core import r
from flext_tests import (
    tm,
    tv,
)

from flext_ldif import FlextLdif, FlextLdifEntries
from tests import m, t


class _TestsBase:
    """Base class for test helper types (replaces missing flext_tests.tt)."""

    __test__ = False


tt = _TestsBase

TResult = TypeVar("TResult")


def _unwrap_result[TResult](
    result: r[TResult],
    *,
    msg: str | None = None,
    expected_type: type[TResult] | None = None,
) -> TResult:
    if result.is_failure:
        error_msg = msg or str(result.error)
        raise AssertionError(error_msg)
    value = result.value
    if expected_type is not None and (not isinstance(value, expected_type)):
        error_msg = (
            msg or f"Expected {expected_type.__name__}, got {type(value).__name__}"
        )
        raise AssertionError(error_msg)
    return value


class TestsFlextLdifMatchers(tm):
    """Enhanced matchers for flext-ldif tests.

    Consolidates entry and entries validation into unified, highly parameterized methods.
    Reduces test code while increasing validation coverage.
    """

    __test__ = False

    @staticmethod
    def entry(
        entry: m.Ldif.Entry | r[m.Ldif.Entry],
        *,
        dn: str | None = None,
        dn_contains: str | None = None,
        dn_starts: str | None = None,
        dn_ends: str | None = None,
        has_attr: str | t.StrSequence | None = None,
        not_has_attr: str | t.StrSequence | None = None,
        attr_equals: Mapping[str, str | t.StrSequence] | None = None,
        attr_contains: Mapping[str, str | t.StrSequence] | None = None,
        has_oc: str | t.StrSequence | None = None,
        not_has_oc: str | t.StrSequence | None = None,
        attr_count: int | None = None,
        attr_count_gt: int | None = None,
        attr_count_gte: int | None = None,
        attr_count_lt: int | None = None,
        attr_count_lte: int | None = None,
        oc_count: int | None = None,
        oc_count_gt: int | None = None,
        oc_count_gte: int | None = None,
        oc_count_lt: int | None = None,
        oc_count_lte: int | None = None,
        msg: str | None = None,
    ) -> m.Ldif.Entry:
        """Unified entry validation - ALL entry assertions in ONE method.

        Consolidates multiple entry validation patterns into a single,
        highly parameterized method. Reduces test code significantly while
        allowing validation of many different aspects of an entry in one call.

        Args:
            entry: Entry or r[Entry] to validate
            dn: Exact DN value to match
            dn_contains: String that DN must contain
            dn_starts: String that DN must start with
            dn_ends: String that DN must end with
            has_attr: Attribute(s) that must be present
            not_has_attr: Attribute(s) that must be absent
            attr_equals: Dict of {attr: expected_value} for exact matching
            attr_contains: Dict of {attr: substring} for substring matching in values
            has_oc: ObjectClass(es) that must be present
            not_has_oc: ObjectClass(es) that must be absent
            attr_count: Exact number of attributes expected
            attr_count_gt: Number of attributes must be greater than
            attr_count_gte: Number of attributes must be >=
            attr_count_lt: Number of attributes must be less than
            attr_count_lte: Number of attributes must be <=
            oc_count: Exact number of objectClasses expected
            oc_count_gt: Number of objectClasses must be >
            oc_count_gte: Number of objectClasses must be >=
            oc_count_lt: Number of objectClasses must be <
            oc_count_lte: Number of objectClasses must be <=
            msg: Custom error message

        Returns:
            The validated Entry (unwrapped if r)

        Examples:
            # Validate DN and attributes
            tm.entry(entry, dn="cn=test,dc=example,dc=com", has_attr=["cn", "sn"])

            # Validate attribute values
            tm.entry(entry, attr_equals={"cn": "test"}, attr_contains={"mail": "@"})

            # Validate counts and objectClasses
            tm.entry(entry, attr_count_gte=3, oc_count=2, has_oc="person")

        """
        if isinstance(entry, r):
            if entry.is_failure:
                error_msg = msg or str(entry.error)
                raise AssertionError(error_msg)
            entry_value = entry.value
            entry = entry_value
        if not hasattr(entry, "attributes"):
            raise AssertionError(msg or "Entry has no 'attributes' attribute")
        attrs_obj = entry.attributes
        attrs: Mapping[str, t.StrSequence] = (
            dict(attrs_obj) if isinstance(attrs_obj, dict) else {}
        )
        if not hasattr(entry, "dn"):
            raise AssertionError(msg or "Entry has no 'dn' attribute")
        dn_obj = entry.dn
        if dn_obj is None:
            raise AssertionError(msg or "Entry has no DN value")
        dn_value = dn_obj.value if hasattr(dn_obj, "value") else str(dn_obj)
        oc_seq: t.StrSequence | None = attrs.get("objectClass") or attrs.get(
            "objectclass",
        )
        objectclasses: Sequence[str] = list(oc_seq) if oc_seq else []
        if dn is not None:
            TestsFlextLdifMatchers.that(dn_value, msg=msg, eq=dn)
        if dn_contains is not None:
            TestsFlextLdifMatchers.that(dn_value, msg=msg, contains=dn_contains)
        if dn_starts is not None:
            TestsFlextLdifMatchers.that(dn_value, msg=msg, starts=dn_starts)
        if dn_ends is not None:
            TestsFlextLdifMatchers.that(dn_value, msg=msg, ends=dn_ends)
        if has_attr is not None:
            attr_list = [has_attr] if isinstance(has_attr, str) else list(has_attr)
            for attr in attr_list:
                TestsFlextLdifMatchers.that(attrs, msg=msg, contains=attr)
        if not_has_attr is not None:
            attr_list = (
                [not_has_attr] if isinstance(not_has_attr, str) else list(not_has_attr)
            )
            for attr in attr_list:
                if attr in attrs:
                    error_msg = msg or f"Entry should not have attribute: {attr}"
                    raise AssertionError(error_msg)
        if attr_equals is not None:
            for attr, expected in attr_equals.items():
                TestsFlextLdifMatchers.that(attrs, msg=msg, contains=attr)
                if hasattr(entry, "get_attribute_values"):
                    values = entry.get_attribute_values(attr)
                else:
                    values = attrs.get(attr, [])
                    if isinstance(values, str):
                        values = [values]
                expected_list = (
                    [expected] if isinstance(expected, str) else list(expected)
                )
                TestsFlextLdifMatchers.that(values, msg=msg, eq=expected_list)
        if attr_contains is not None:
            for attr, substring in attr_contains.items():
                TestsFlextLdifMatchers.that(attrs, msg=msg, contains=attr)
                if hasattr(entry, "get_attribute_values"):
                    values = entry.get_attribute_values(attr)
                else:
                    values = attrs.get(attr, [])
                    if isinstance(values, str):
                        values = [values]
                if isinstance(substring, str):
                    if not any(substring in str(v) for v in values):
                        error_msg = (
                            msg or f"Attribute {attr} should contain {substring}"
                        )
                        raise AssertionError(error_msg)
                else:
                    substring_list = list(substring)
                    for sub in substring_list:
                        if not any(str(sub) in str(v) for v in values):
                            error_msg = msg or f"Attribute {attr} should contain {sub}"
                            raise AssertionError(error_msg)
        if has_oc is not None:
            oc_list = [has_oc] if isinstance(has_oc, str) else list(has_oc)
            for oc in oc_list:
                TestsFlextLdifMatchers.that(objectclasses, msg=msg, contains=oc)
        if not_has_oc is not None:
            oc_list = [not_has_oc] if isinstance(not_has_oc, str) else list(not_has_oc)
            for oc in oc_list:
                if oc in objectclasses:
                    error_msg = msg or f"Entry should not have objectClass: {oc}"
                    raise AssertionError(error_msg)
        actual_attr_count = len(attrs)
        if attr_count is not None and actual_attr_count != attr_count:
            error_msg = (
                msg or f"Expected {attr_count} attributes, got {actual_attr_count}"
            )
            raise AssertionError(error_msg)
        if attr_count_gt is not None and actual_attr_count <= attr_count_gt:
            error_msg = (
                msg or f"Expected > {attr_count_gt} attributes, got {actual_attr_count}"
            )
            raise AssertionError(error_msg)
        if attr_count_gte is not None and actual_attr_count < attr_count_gte:
            error_msg = (
                msg
                or f"Expected >= {attr_count_gte} attributes, got {actual_attr_count}"
            )
            raise AssertionError(error_msg)
        if attr_count_lt is not None and actual_attr_count >= attr_count_lt:
            error_msg = (
                msg or f"Expected < {attr_count_lt} attributes, got {actual_attr_count}"
            )
            raise AssertionError(error_msg)
        if attr_count_lte is not None and actual_attr_count > attr_count_lte:
            error_msg = (
                msg
                or f"Expected <= {attr_count_lte} attributes, got {actual_attr_count}"
            )
            raise AssertionError(error_msg)
        if oc_count is not None:
            TestsFlextLdifMatchers.that(objectclasses, length=oc_count, msg=msg)
        if oc_count_gt is not None:
            TestsFlextLdifMatchers.that(objectclasses, length_gt=oc_count_gt, msg=msg)
        if oc_count_gte is not None:
            TestsFlextLdifMatchers.that(objectclasses, length_gte=oc_count_gte, msg=msg)
        if oc_count_lt is not None:
            TestsFlextLdifMatchers.that(objectclasses, length_lt=oc_count_lt, msg=msg)
        if oc_count_lte is not None:
            TestsFlextLdifMatchers.that(objectclasses, length_lte=oc_count_lte, msg=msg)
        return entry

    @staticmethod
    def entries(
        entries: Sequence[m.Ldif.Entry] | r[Sequence[m.Ldif.Entry]],
        *,
        count: int | None = None,
        count_gt: int | None = None,
        count_gte: int | None = None,
        count_lt: int | None = None,
        count_lte: int | None = None,
        empty: bool | None = None,
        all_have_attr: str | t.StrSequence | None = None,
        all_have_oc: str | t.StrSequence | None = None,
        any_has_attr: str | t.StrSequence | None = None,
        any_has_oc: str | t.StrSequence | None = None,
        at_index: Mapping[int, t.ContainerMapping] | None = None,
        msg: str | None = None,
    ) -> Sequence[m.Ldif.Entry]:
        """Unified entries list validation - validates counts and entry properties.

        Consolidates multiple entry list validation patterns into one method.

        Args:
            entries: Sequence of entries or r[Sequence[Entry]]
            count: Exact number of entries expected
            count_gt: Number of entries must be >
            count_gte: Number of entries must be >=
            count_lt: Number of entries must be <
            count_lte: Number of entries must be <=
            empty: Whether list should be empty/non-empty
            all_have_attr: Attribute(s) ALL entries must have
            all_have_oc: ObjectClass(es) ALL entries must have
            any_has_attr: Attribute(s) that at least ONE entry must have
            any_has_oc: ObjectClass(es) that at least ONE entry must have
            at_index: Dict mapping index to entry validation params
            msg: Custom error message

        Returns:
            The validated list of entries

        Examples:
            # Validate count and attribute presence
            tm.entries(result, count=5, all_have_attr="cn")

            # Validate specific entries by index
            tm.entries(entries, at_index={0: {"dn": "cn=first"}, 1: {"has_attr": "mail"}})

        """
        entries_list: Sequence[m.Ldif.Entry]
        if isinstance(entries, r):
            if entries.is_failure:
                error_msg = msg or str(entries.error)
                raise AssertionError(error_msg)
            entries_list = list(entries.value)
        else:
            entries_list = list(entries)
        if count is not None:
            TestsFlextLdifMatchers.that(entries_list, length=count, msg=msg)
        if count_gt is not None:
            TestsFlextLdifMatchers.that(entries_list, length_gt=count_gt, msg=msg)
        if count_gte is not None:
            TestsFlextLdifMatchers.that(entries_list, length_gte=count_gte, msg=msg)
        if count_lt is not None:
            TestsFlextLdifMatchers.that(entries_list, length_lt=count_lt, msg=msg)
        if count_lte is not None:
            TestsFlextLdifMatchers.that(entries_list, length_lte=count_lte, msg=msg)
        if empty is not None:
            TestsFlextLdifMatchers.that(entries_list, msg=msg, empty=empty)
        if all_have_attr is not None:
            attr_list = (
                [all_have_attr]
                if isinstance(all_have_attr, str)
                else list(all_have_attr)
            )
            for entry in entries_list:
                TestsFlextLdifMatchers.entry(entry, has_attr=attr_list, msg=msg)
        if all_have_oc is not None:
            oc_list = (
                [all_have_oc] if isinstance(all_have_oc, str) else list(all_have_oc)
            )
            for entry in entries_list:
                TestsFlextLdifMatchers.entry(entry, has_oc=oc_list, msg=msg)
        if any_has_attr is not None:
            attr_list = (
                [any_has_attr] if isinstance(any_has_attr, str) else list(any_has_attr)
            )
            found = False
            for entry in entries_list:
                if hasattr(entry, "attributes"):
                    attrs_obj = entry.attributes
                    if attrs_obj is None:
                        continue
                    attrs_dict: Mapping[str, object] = (
                        dict(attrs_obj) if isinstance(attrs_obj, dict) else {}
                    )
                    if all(attr in attrs_dict for attr in attr_list):
                        found = True
                        break
            if not found:
                error_msg = msg or f"No entry has all attributes: {attr_list}"
                raise AssertionError(error_msg)
        if any_has_oc is not None:
            oc_list = [any_has_oc] if isinstance(any_has_oc, str) else list(any_has_oc)
            found = False
            for entry in entries_list:
                if hasattr(entry, "attributes"):
                    attrs_obj = entry.attributes
                    if attrs_obj is None:
                        continue
                    oc_attrs: Mapping[str, MutableSequence[str]] = (
                        dict(attrs_obj) if isinstance(attrs_obj, dict) else {}
                    )
                    if oc_attrs:
                        oc_seq_raw: MutableSequence[str] | None = oc_attrs.get(
                            "objectClass",
                        ) or oc_attrs.get("objectclass")
                        objectclasses_parsed: Sequence[str] = (
                            list(oc_seq_raw) if oc_seq_raw else []
                        )
                        if all(oc in objectclasses_parsed for oc in oc_list):
                            found = True
                            break
            if not found:
                error_msg = msg or f"No entry has all objectClasses: {oc_list}"
                raise AssertionError(error_msg)
        if at_index is not None:
            for idx, validation_params in at_index.items():
                if idx >= len(entries_list):
                    error_msg = (
                        msg
                        or f"Index {idx} out of range (list has {len(entries_list)} entries)"
                    )
                    raise AssertionError(error_msg)
                if isinstance(validation_params, dict):
                    raw_dn = validation_params.get("dn")
                    dn_value = raw_dn if isinstance(raw_dn, str) else None
                    raw_has_attr = validation_params.get("has_attr")
                    has_attr_value: str | list[str] | None
                    if isinstance(raw_has_attr, str):
                        has_attr_value = raw_has_attr
                    elif isinstance(raw_has_attr, list):
                        has_attr_value = [
                            item for item in raw_has_attr if isinstance(item, str)
                        ]
                    else:
                        has_attr_value = None
                    raw_not_has_attr = validation_params.get("not_has_attr")
                    not_has_attr_value: str | list[str] | None
                    if isinstance(raw_not_has_attr, str):
                        not_has_attr_value = raw_not_has_attr
                    elif isinstance(raw_not_has_attr, list):
                        not_has_attr_value = [
                            item for item in raw_not_has_attr if isinstance(item, str)
                        ]
                    else:
                        not_has_attr_value = None
                    TestsFlextLdifMatchers.entry(
                        entries_list[idx],
                        msg=msg,
                        dn=dn_value,
                        has_attr=has_attr_value,
                        not_has_attr=not_has_attr_value,
                    )
                else:
                    TestsFlextLdifMatchers.entry(entries_list[idx], msg=msg)
        return entries_list

    @staticmethod
    def ok_entry(
        result: r[m.Ldif.Entry],
        *,
        msg: str | None = None,
        dn: str | None = None,
        dn_contains: str | None = None,
        dn_starts: str | None = None,
        dn_ends: str | None = None,
        has_attr: str | t.StrSequence | None = None,
        not_has_attr: str | t.StrSequence | None = None,
        attr_equals: Mapping[str, str | t.StrSequence] | None = None,
        attr_contains: Mapping[str, str | t.StrSequence] | None = None,
        has_oc: str | t.StrSequence | None = None,
        not_has_oc: str | t.StrSequence | None = None,
        attr_count: int | None = None,
        attr_count_gt: int | None = None,
        attr_count_gte: int | None = None,
        attr_count_lt: int | None = None,
        attr_count_lte: int | None = None,
        oc_count: int | None = None,
        oc_count_gt: int | None = None,
        oc_count_gte: int | None = None,
        oc_count_lt: int | None = None,
        oc_count_lte: int | None = None,
    ) -> m.Ldif.Entry:
        """Assert r success and validate entry.

        Args:
            result: r[Entry] to validate
            msg: Custom error message
            See entry() method for parameter documentation

        Returns:
            The validated Entry

        """
        entry = _unwrap_result(result, msg=msg, expected_type=m.Ldif.Entry)
        return TestsFlextLdifMatchers.entry(
            entry,
            msg=msg,
            dn=dn,
            dn_contains=dn_contains,
            dn_starts=dn_starts,
            dn_ends=dn_ends,
            has_attr=has_attr,
            not_has_attr=not_has_attr,
            attr_equals=attr_equals,
            attr_contains=attr_contains,
            has_oc=has_oc,
            not_has_oc=not_has_oc,
            attr_count=attr_count,
            attr_count_gt=attr_count_gt,
            attr_count_gte=attr_count_gte,
            attr_count_lt=attr_count_lt,
            attr_count_lte=attr_count_lte,
            oc_count=oc_count,
            oc_count_gt=oc_count_gt,
            oc_count_gte=oc_count_gte,
            oc_count_lt=oc_count_lt,
            oc_count_lte=oc_count_lte,
        )

    @staticmethod
    def ok_entries(
        result: r[Sequence[m.Ldif.Entry]],
        *,
        msg: str | None = None,
        count: int | None = None,
        count_gt: int | None = None,
        count_gte: int | None = None,
        count_lt: int | None = None,
        count_lte: int | None = None,
        empty: bool | None = None,
        all_have_attr: str | t.StrSequence | None = None,
        all_have_oc: str | t.StrSequence | None = None,
        any_has_attr: str | t.StrSequence | None = None,
        any_has_oc: str | t.StrSequence | None = None,
        at_index: Mapping[int, t.ContainerMapping] | None = None,
    ) -> Sequence[m.Ldif.Entry]:
        """Assert r success and validate entries list.

        Args:
            result: r[Sequence[Entry]] or r[Sequence[Entry]] to validate
            msg: Custom error message
            See entries() method for parameter documentation

        Returns:
            The validated list of entries

        """
        entries: Sequence[m.Ldif.Entry] = list(_unwrap_result(result, msg=msg))
        return TestsFlextLdifMatchers.entries(
            entries,
            msg=msg,
            count=count,
            count_gt=count_gt,
            count_gte=count_gte,
            count_lt=count_lt,
            count_lte=count_lte,
            empty=empty,
            all_have_attr=all_have_attr,
            all_have_oc=all_have_oc,
            any_has_attr=any_has_attr,
            any_has_oc=any_has_oc,
            at_index=at_index,
        )


class TestsFlextLdifValidators(tv):
    """Enhanced validators for flext-ldif tests.

    Extends tv with flext-ldif specific validation methods.
    """

    __test__ = False

    @classmethod
    def validate_entry_structure(
        cls,
        entry: m.Ldif.Entry,
        *,
        require_dn: bool = True,
        require_attrs: bool = True,
        min_attrs: int = 1,
    ) -> bool:
        """Validate entry has required structure.

        Args:
            entry: Entry to validate
            require_dn: Whether DN is required
            require_attrs: Whether attributes are required
            min_attrs: Minimum number of attributes

        Returns:
            True if entry structure is valid

        """
        if require_dn and (not entry.dn):
            return False
        if require_attrs:
            attrs_obj = entry.attributes
            if attrs_obj is None:
                return False
            actual_count: int = len(attrs_obj)
            if actual_count < min_attrs:
                return False
        return True


class TestsFlextLdifTypes(tt):
    """Enhanced type helpers for flext-ldif tests.

    Extends t with flext-ldif specific type operations.
    """

    __test__ = False

    @classmethod
    def entry_type(cls) -> type[m.Ldif.Entry]:
        """Get Entry type for type checking."""
        return m.Ldif.Entry


class TestsFlextLdifFixtures(tt):
    """Enhanced fixtures for flext-ldif tests.

    Extends tt with flext-ldif specific factory methods.
    Provides parameterized entry creation with common patterns.
    """

    __test__ = False

    @classmethod
    def create_entry(cls, dn: str, **attributes: str | t.StrSequence) -> m.Ldif.Entry:
        """Create test entry from DN and attributes.

        Args:
            dn: Distinguished Name
            **attributes: Attributes as keyword arguments

        Returns:
            Created Entry

        """
        service = FlextLdifEntries()
        attrs_typed: dict[str, str | MutableSequence[str]] = {
            k: ([v] if isinstance(v, str) else list(v)) for k, v in attributes.items()
        }
        result = service.create_entry(dn=dn, attributes=attrs_typed)
        if not result.is_success:
            msg = f"Failed to create entry: {result.error}"
            raise AssertionError(msg)
        return result.value

    @classmethod
    def create_entries(
        cls,
        entries_data: Sequence[tuple[str, Mapping[str, str | t.StrSequence]]],
    ) -> Sequence[m.Ldif.Entry]:
        """Create multiple test entries.

        Args:
            entries_data: List of (dn, attributes) tuples

        Returns:
            List of created entries

        """
        result: Sequence[m.Ldif.Entry] = []
        for dn, attrs in entries_data:
            entry = cls.create_entry(dn, **attrs)
            result.append(entry)
        return result

    @staticmethod
    def run_fixture_roundtrip(
        fixture_path: Path,
        msg: str | None = None,
    ) -> Sequence[m.Ldif.Entry]:
        """Run fixture roundtrip - parse, write, parse again.

        Args:
            fixture_path: Path to the LDIF fixture file
            msg: Optional error message

        Returns:
            List of entries after roundtrip

        """
        api = FlextLdif.get_instance()
        parse_result: r[MutableSequence[m.Ldif.Entry]] = api.parse_ldif(fixture_path)
        entries: MutableSequence[m.Ldif.Entry] = _unwrap_result(parse_result, msg=msg)
        write_result: r[str] = api.write(entries)
        ldif_content: str = _unwrap_result(write_result, msg=msg)
        roundtrip_result: r[MutableSequence[m.Ldif.Entry]] = api.parse_ldif(
            ldif_content,
        )
        return _unwrap_result(roundtrip_result, msg=msg)

    @staticmethod
    def load_fixture_entries(
        fixture_path: Path,
        msg: str | None = None,
    ) -> Sequence[m.Ldif.Entry]:
        """Load fixture entries from LDIF file.

        Args:
            fixture_path: Path to the LDIF fixture file
            msg: Optional error message

        Returns:
            List of parsed entries

        """
        api = FlextLdif.get_instance()
        result: r[MutableSequence[m.Ldif.Entry]] = api.parse_ldif(fixture_path)
        return _unwrap_result(result, msg=msg)

    @staticmethod
    def load_fixture_and_validate_structure(
        fixture_path: Path,
        msg: str | None = None,
    ) -> Sequence[m.Ldif.Entry]:
        """Load fixture and validate structure.

        Args:
            fixture_path: Path to the LDIF fixture file
            msg: Optional error message

        Returns:
            List of validated entries

        """
        api = FlextLdif.get_instance()
        result: r[MutableSequence[m.Ldif.Entry]] = api.parse_ldif(fixture_path)
        entries: MutableSequence[m.Ldif.Entry] = _unwrap_result(result, msg=msg)
        TestsFlextLdifMatchers.entries(entries, msg=msg)
        return entries


tm = TestsFlextLdifMatchers
tv = TestsFlextLdifValidators
tf = TestsFlextLdifFixtures
tt = TestsFlextLdifTypes


__all__ = [
    "TestsFlextLdifFixtures",
    "TestsFlextLdifMatchers",
    "TestsFlextLdifTypes",
    "TestsFlextLdifValidators",
    "tf",
    "tm",
    "tt",
    "tv",
]
