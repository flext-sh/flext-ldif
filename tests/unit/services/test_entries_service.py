"""Behavioral unit tests for the FlextLdifEntries service public contract.

Every test exercises an observable, public operation of ``FlextLdifEntries``
(the ``r[T]`` outcome it returns, the public model state it produces, and the
error message it reports on failure). No private attribute/method is touched
and no internal collaborator is spied on.

Coverage note (not tested here, honestly declared): ``FlextLdifEntries``
exposes two private helpers, ``_normalize_list_value`` and
``_normalize_string_value`` (which strips whitespace and rejects empty
strings). Neither is reachable through any public method -- the public
``normalize_attribute_values`` uses its own ``match`` and never strips nor
rejects empty input (``[]`` -> ``ok([])``, ``"  "`` -> ``ok(["  "])``). Their
behavior therefore has no observable public surface, so it is not asserted
here rather than reached via private access.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flext_tests import tm

from flext_ldif.services.entries import FlextLdifEntries
from tests import TestsFlextLdifUtilities as u, c, m

if TYPE_CHECKING:
    from tests import t


class TestsFlextLdifEntries:
    """Public-contract behavior of the FlextLdifEntries service."""

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
        return entry.model_copy(update={"attributes": None})

    @staticmethod
    def _to_attribute_mapping(
        data: dict[str, str | list[str]],
    ) -> t.MutableAttributeMapping:
        typed: t.MutableAttributeMapping = {}
        for key, value in data.items():
            typed[key] = value if isinstance(value, str) else list(value)
        return typed

    # ── create_entry ──────────────────────────────────────────────────────────

    def test_create_entry_returns_entry_preserving_dn_and_attributes(self) -> None:
        result = FlextLdifEntries.create_entry(
            c.Tests.ENTRIES_DN_VALID,
            {"cn": ["x"], "objectClass": ["top"]},
        )
        entry: m.Ldif.Entry = u.Tests.assert_success(result)
        assert entry.attributes is not None
        tm.that("cn" in entry.attributes.attributes, eq=True)
        tm.that(entry.attributes.attributes["cn"], eq=["x"])

    def test_create_entry_injects_supplied_objectclasses(self) -> None:
        result = FlextLdifEntries.create_entry(
            c.Tests.ENTRIES_DN_VALID,
            {"cn": ["x"]},
            objectclasses=list(c.Tests.ENTRIES_OBJECTCLASS_PERSON),
        )
        entry: m.Ldif.Entry = u.Tests.assert_success(result)
        assert entry.attributes is not None
        tm.that(c.Tests.NAME_OBJECTCLASS in entry.attributes.attributes, eq=True)
        tm.that(
            entry.attributes.attributes[c.Tests.NAME_OBJECTCLASS],
            eq=list(c.Tests.ENTRIES_OBJECTCLASS_PERSON),
        )

    def test_create_entry_invalid_dn_fails_with_reason(self) -> None:
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
    def test_normalize_attribute_values_yields_expected_list(
        self,
        scenario: str,
        value: str | list[str] | t.StrSequence | set[str] | frozenset[str],
        should_succeed: bool,
    ) -> None:
        tm.that(bool(scenario), eq=True)
        result = FlextLdifEntries.normalize_attribute_values(value)
        if not should_succeed:
            tm.fail(result)
            return
        values: t.MutableSequenceOf[str] = u.Tests.assert_success(result)
        expected = [value] if isinstance(value, str) else list(value)
        tm.that(values, eq=expected)

    def test_normalize_attribute_values_unsupported_type_fails(self) -> None:
        result = FlextLdifEntries.normalize_attribute_values(b"binary-value")
        tm.fail(result, has="Unsupported")

    # ── resolve_entry_dn ──────────────────────────────────────────────────────

    def test_resolve_dn_reads_dn_from_model_entry(self) -> None:
        result = FlextLdifEntries.resolve_entry_dn(self._basic_entry())
        tm.ok(result, eq=c.Tests.ENTRIES_DN_VALID)

    def test_resolve_dn_from_model_entry_without_dn_fails(self) -> None:
        entry = m.Ldif.Entry(
            dn=None,
            attributes=m.Ldif.Attributes(attributes={}),
        )
        result = FlextLdifEntries.resolve_entry_dn(entry)
        tm.fail(result, has="DN")

    @pytest.mark.parametrize(
        ("scenario", "entry_dict", "should_succeed"),
        tuple(
            (scenario, data[0], data[1])
            for scenario, data in c.Tests.ENTRIES_DN_DICT_CASES.items()
        ),
    )
    def test_resolve_dn_from_dict_yields_expected_value(
        self,
        scenario: str,
        entry_dict: dict[str, str | list[str]],
        should_succeed: bool,
    ) -> None:
        tm.that(bool(scenario), eq=True)
        result = FlextLdifEntries.resolve_entry_dn(
            self._to_attribute_mapping(entry_dict),
        )
        if not should_succeed:
            tm.fail(result)
            return
        dn_value = entry_dict["dn"]
        expected = (
            dn_value if isinstance(dn_value, str) else (dn_value[0] if dn_value else "")
        )
        tm.ok(result, eq=expected)

    # ── resolve_entry_attributes ──────────────────────────────────────────────

    def test_resolve_entry_attributes_returns_mapping_copy(self) -> None:
        result = FlextLdifEntries.resolve_entry_attributes(self._basic_entry())
        attrs: t.MutableStrSequenceMapping = u.Tests.assert_success(result)
        tm.that("cn" in attrs, eq=True)
        tm.that(attrs["cn"], eq=["entries-test"])
        tm.that("mail" in attrs, eq=True)

    def test_resolve_entry_attributes_fails_when_none(self) -> None:
        result = FlextLdifEntries.resolve_entry_attributes(
            self._entry_without_attributes(),
        )
        tm.fail(result, has="no attributes")

    # ── resolve_entry_objectclasses ───────────────────────────────────────────

    def test_resolve_objectclasses_returns_declared_classes(self) -> None:
        result = FlextLdifEntries.resolve_entry_objectclasses(self._basic_entry())
        ocs: t.MutableSequenceOf[str] = u.Tests.assert_success(result)
        tm.that(ocs, eq=list(c.Tests.ENTRIES_OBJECTCLASS_PERSON))

    def test_resolve_objectclasses_fails_when_attribute_missing(self) -> None:
        entry = u.Tests.create_real_entry(
            dn=c.Tests.ENTRIES_DN_VALID,
            attributes={"cn": ["x"]},
        )
        result = FlextLdifEntries.resolve_entry_objectclasses(entry)
        tm.fail(result, has="objectClass")

    def test_resolve_objectclasses_fails_when_entry_has_no_attributes(self) -> None:
        entry = m.Ldif.Entry(dn=c.Tests.ANALYSIS_DN_VALID, attributes=None)
        result = FlextLdifEntries.resolve_entry_objectclasses(entry)
        tm.fail(result, has="attributes")

    # ── remove_attributes ─────────────────────────────────────────────────────

    def test_remove_attributes_strips_targets_and_keeps_others(self) -> None:
        entry = self._basic_entry()
        result = FlextLdifEntries.remove_attributes(
            entry,
            list(c.Tests.ENTRIES_ATTR_REMOVE_SET),
        )
        cleaned: m.Ldif.Entry = u.Tests.assert_success(result)
        assert cleaned.attributes is not None
        remaining = {k.lower() for k in cleaned.attributes.attributes}
        tm.that(remaining.isdisjoint(c.Tests.ENTRIES_ATTR_REMOVE_SET), eq=True)
        tm.that("cn" in remaining, eq=True)
        tm.that("objectclass" in remaining, eq=True)

    def test_remove_attributes_is_idempotent(self) -> None:
        entry = self._basic_entry()
        once: m.Ldif.Entry = u.Tests.assert_success(
            FlextLdifEntries.remove_attributes(
                entry,
                list(c.Tests.ENTRIES_ATTR_REMOVE_SET),
            ),
        )
        twice: m.Ldif.Entry = u.Tests.assert_success(
            FlextLdifEntries.remove_attributes(
                once,
                list(c.Tests.ENTRIES_ATTR_REMOVE_SET),
            ),
        )
        assert once.attributes is not None
        assert twice.attributes is not None
        tm.that(
            set(twice.attributes.attributes) == set(once.attributes.attributes),
            eq=True,
        )

    def test_remove_attributes_noop_when_entry_has_no_attributes(self) -> None:
        entry = self._entry_without_attributes()
        cleaned: m.Ldif.Entry = u.Tests.assert_success(
            FlextLdifEntries.remove_attributes(entry, ["cn"]),
        )
        tm.that(cleaned.attributes is None, eq=True)

    # ── run_configured_operation ──────────────────────────────────────────────

    @pytest.mark.parametrize(
        ("scenario", "op", "should_succeed"),
        tuple(
            (scenario, data[0], data[1])
            for scenario, data in c.Tests.ENTRIES_OP_CASES.items()
        ),
    )
    def test_run_configured_operation_outcome(
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
        if not should_succeed:
            tm.fail(result)
            return
        cleaned: t.MutableSequenceOf[m.Ldif.Entry] = u.Tests.assert_success(result)
        tm.that(len(cleaned) == 1, eq=True)
        stripped = cleaned[0]
        assert stripped.attributes is not None
        remaining = {k.lower() for k in stripped.attributes.attributes}
        tm.that(remaining.isdisjoint(c.Tests.ENTRIES_ATTR_REMOVE_SET), eq=True)

    def test_run_configured_operation_fails_without_attributes_to_remove(self) -> None:
        entries_svc = FlextLdifEntries(
            entries=[self._basic_entry()],
            operation=c.Tests.ENTRIES_REMOVE_OPERATION,
            attributes_to_remove=[],
        )
        result = entries_svc.run_configured_operation()
        tm.fail(result, has="attributes_to_remove")
