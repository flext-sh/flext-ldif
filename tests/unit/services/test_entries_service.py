"""Data-driven unit tests for FlextLdifEntries service."""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldif.services.entries import FlextLdifEntries
from tests.constants import c
from tests.models import m
from tests.typings import t
from tests.utilities import TestsFlextLdifUtilities as u


class TestsFlextLdifEntriesService:
    """Cover entries service branches via flat data-driven constants."""

    @staticmethod
    def _basic_entry(
        extra_attrs: dict[str, list[str]] | None = None,
    ) -> m.Ldif.Entry:
        attrs: dict[str, list[str]] = {
            "objectClass": list(c.Tests.ENTRIES_OBJECTCLASS_PERSON),
            "cn": ["entries-test"],
            "sn": ["user"],
            "mail": ["entries-test@example.com"],
        }
        if extra_attrs:
            attrs.update(extra_attrs)
        return u.Tests.create_real_entry(
            dn=c.Tests.ENTRIES_DN_VALID,
            attributes=attrs,
        )

    @staticmethod
    def _entry_without_attributes() -> m.Ldif.Entry:
        entry = u.Tests.create_real_entry(
            dn=c.Tests.ENTRIES_DN_VALID,
            attributes={c.Tests.NAME_CN: [c.Tests.ATTR_VALUE_TEST]},
        )
        updated_entry: m.Ldif.Entry = entry.model_copy(update={"attributes": None})
        return updated_entry

    @staticmethod
    def _to_attribute_mapping(
        data: dict[str, str | list[str]],
    ) -> t.MutableAttributeMapping:
        typed: t.MutableAttributeMapping = {}
        for key, value in data.items():
            typed[key] = value if isinstance(value, str) else list(value)
        return typed

    # ── create_entry ──────────────────────────────────────────────────────────

    def test_create_entry_valid_dn(self) -> None:
        result = FlextLdifEntries.create_entry(
            c.Tests.ENTRIES_DN_VALID,
            {"cn": ["x"], "objectClass": ["top"]},
        )
        entry: m.Ldif.Entry = u.Tests.assert_success(result)
        tm.that(entry, is_=m.Ldif.Entry)

    def test_create_entry_with_objectclasses(self) -> None:
        result = FlextLdifEntries.create_entry(
            c.Tests.ENTRIES_DN_VALID,
            {"cn": ["x"]},
            objectclasses=list(c.Tests.ENTRIES_OBJECTCLASS_PERSON),
        )
        entry: m.Ldif.Entry = u.Tests.assert_success(result)
        tm.that(entry.attributes is not None, eq=True)
        if entry.attributes is None:
            pytest.fail("Entry attributes should be present")
        tm.that(c.Tests.NAME_OBJECTCLASS in entry.attributes.attributes, eq=True)

    def test_create_entry_invalid_dn_returns_failure(self) -> None:
        result = FlextLdifEntries.create_entry(
            c.Tests.ENTRIES_DN_INVALID,
            {"cn": ["x"]},
        )
        tm.fail(result, has="Invalid DN")

    # ── normalize_attribute_values ────────────────────────────────────────────

    @pytest.mark.parametrize(
        ("scenario", "value", "should_succeed"),
        tuple(
            (scenario, data[0], data[1])
            for scenario, data in c.Tests.ENTRIES_NORMALIZE_CASES.items()
        ),
    )
    def test_normalize_attribute_values(
        self,
        scenario: str,
        value: str | list[str] | t.StrSequence | set[str] | frozenset[str],
        should_succeed: bool,
    ) -> None:
        tm.that(bool(scenario), eq=True)
        result = FlextLdifEntries.normalize_attribute_values(value)
        if should_succeed:
            values: t.MutableSequenceOf[str] = u.Tests.assert_success(result)
            tm.that(isinstance(values, list), eq=True)
        else:
            tm.fail(result)

    # ── resolve_entry_dn ──────────────────────────────────────────────────────

    def test_resolve_dn_from_model_entry(self) -> None:
        entry = self._basic_entry()
        result = FlextLdifEntries.resolve_entry_dn(entry)
        dn: str = u.Tests.assert_success(result)
        tm.that(dn, eq=c.Tests.ENTRIES_DN_VALID)

    @pytest.mark.parametrize(
        ("scenario", "entry_dict", "should_succeed"),
        tuple(
            (scenario, data[0], data[1])
            for scenario, data in c.Tests.ENTRIES_DN_DICT_CASES.items()
        ),
    )
    def test_resolve_dn_from_dict(
        self,
        scenario: str,
        entry_dict: dict[str, str | list[str]],
        should_succeed: bool,
    ) -> None:
        tm.that(bool(scenario), eq=True)
        result = FlextLdifEntries.resolve_entry_dn(
            self._to_attribute_mapping(entry_dict)
        )
        if should_succeed:
            u.Tests.assert_success(result)
        else:
            tm.fail(result)

    # ── resolve_entry_attributes ──────────────────────────────────────────────

    def test_resolve_entry_attributes_succeeds(self) -> None:
        entry = self._basic_entry()
        result = FlextLdifEntries.resolve_entry_attributes(entry)
        attrs: t.MutableStrSequenceMapping = u.Tests.assert_success(result)
        tm.that("cn" in attrs, eq=True)

    def test_resolve_entry_attributes_fails_when_none(self) -> None:
        entry = self._entry_without_attributes()
        result = FlextLdifEntries.resolve_entry_attributes(entry)
        tm.fail(result, has="no attributes")

    # ── resolve_entry_objectclasses ───────────────────────────────────────────

    def test_resolve_objectclasses_succeeds(self) -> None:
        entry = self._basic_entry()
        result = FlextLdifEntries.resolve_entry_objectclasses(entry)
        ocs: t.MutableSequenceOf[str] = u.Tests.assert_success(result)
        tm.that(len(ocs) > 0, eq=True)

    def test_resolve_objectclasses_fails_when_missing(self) -> None:
        entry = u.Tests.create_real_entry(
            dn=c.Tests.ENTRIES_DN_VALID,
            attributes={"cn": ["x"]},
        )
        result = FlextLdifEntries.resolve_entry_objectclasses(entry)
        tm.fail(result, has="objectClass")

    # ── remove_attributes ─────────────────────────────────────────────────────

    def test_remove_attributes_strips_targeted_keys(self) -> None:
        entry = self._basic_entry()
        result = FlextLdifEntries.remove_attributes(
            entry,
            list(c.Tests.ENTRIES_ATTR_REMOVE_SET),
        )
        cleaned: m.Ldif.Entry = u.Tests.assert_success(result)
        tm.that(cleaned.attributes is not None, eq=True)
        if cleaned.attributes is None:
            pytest.fail("Cleaned entry attributes should be present")
        remaining_keys = set(cleaned.attributes.attributes.keys())
        tm.that(
            remaining_keys.isdisjoint(c.Tests.ENTRIES_ATTR_REMOVE_SET),
            eq=True,
        )

    def test_remove_attributes_noop_when_entry_has_no_attributes(self) -> None:
        entry = self._entry_without_attributes()
        result = FlextLdifEntries.remove_attributes(entry, ["cn"])
        cleaned: m.Ldif.Entry = u.Tests.assert_success(result)
        tm.that(cleaned, is_=m.Ldif.Entry)

    # ── run_configured_operation ──────────────────────────────────────────────

    @pytest.mark.parametrize(
        ("scenario", "op", "should_succeed"),
        tuple(
            (scenario, data[0], data[1])
            for scenario, data in c.Tests.ENTRIES_OP_CASES.items()
        ),
    )
    def test_run_configured_operation(
        self,
        scenario: str,
        op: str | None,
        should_succeed: bool,
    ) -> None:
        tm.that(bool(scenario), eq=True)
        entries_svc = FlextLdifEntries(
            entries=[self._basic_entry()],
            operation=op,
            attributes_to_remove=list(c.Tests.ENTRIES_ATTR_REMOVE_SET),
        )
        result = entries_svc.run_configured_operation()
        if should_succeed:
            cleaned: t.MutableSequenceOf[m.Ldif.Entry] = u.Tests.assert_success(result)
            tm.that(isinstance(cleaned, list), eq=True)
        else:
            tm.fail(result)

    def test_run_configured_operation_fails_when_no_attrs_to_remove(self) -> None:
        entries_svc = FlextLdifEntries(
            entries=[self._basic_entry()],
            operation=c.Tests.ENTRIES_REMOVE_OPERATION,
            attributes_to_remove=[],
        )
        result = entries_svc.run_configured_operation()
        tm.fail(result, has="attributes_to_remove")

    # ── edge-case branches ───────────────────────────────────────────────────

    def test_extract_dn_from_object_missing_dn(self) -> None:
        """Lines 60-61: entry with dn=None."""
        entry = m.Ldif.Entry(dn=None, attributes=m.Ldif.Attributes(attributes={}))
        result = FlextLdifEntries._extract_dn_from_object(entry)
        tm.fail(result, has="DN")

    def test_normalize_list_value_empty_returns_failure(self) -> None:
        """Lines 76-77: empty list → failure."""
        result = FlextLdifEntries._normalize_list_value([])
        tm.fail(result, has="empty")

    def test_normalize_list_value_nonempty_returns_ok(self) -> None:
        """Line 78: list with items → success."""
        result = FlextLdifEntries._normalize_list_value([c.Tests.ANALYSIS_DN_VALID])
        dn_str: str = u.Tests.assert_success(result)
        tm.that(dn_str, eq=c.Tests.ANALYSIS_DN_VALID)

    def test_normalize_string_value_whitespace_returns_failure(self) -> None:
        """Lines 83-84: whitespace-only string → failure."""
        result = FlextLdifEntries._normalize_string_value("   ")
        tm.fail(result, has="empty")

    def test_normalize_string_value_valid_returns_ok(self) -> None:
        """Line 85: valid string → success."""
        result = FlextLdifEntries._normalize_string_value(c.Tests.ANALYSIS_DN_VALID)
        dn_str: str = u.Tests.assert_success(result)
        tm.that(dn_str, eq=c.Tests.ANALYSIS_DN_VALID)

    def test_coerce_attribute_value_unsupported_type(self) -> None:
        """Lines 117-118: unsupported attribute type via normalize_attribute_values."""
        unsupported_value = b"binary-value"
        result = FlextLdifEntries.normalize_attribute_values(unsupported_value)
        tm.fail(result, has="Unsupported")

    def test_resolve_entry_objectclasses_fails_when_no_attrs(self) -> None:
        """Lines 147-150: entry with no attributes → fail."""
        entry = m.Ldif.Entry(dn=c.Tests.ANALYSIS_DN_VALID, attributes=None)
        result = FlextLdifEntries.resolve_entry_objectclasses(entry)
        tm.fail(result, has="attributes")
