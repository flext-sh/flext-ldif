"""Data-driven unit tests for FlextLdifFilters service."""

from __future__ import annotations

from collections.abc import Mapping, MutableSequence

import pytest
from flext_tests import tm

from flext_ldif import FlextLdifFilters, m
from tests import c, u


class TestsFlextLdifFiltersService:
    """Cover filter service branches via flat data-driven constants."""

    @staticmethod
    def _mutable_allowed_oids(
        mapping: Mapping[str, frozenset[str]],
    ) -> dict[str, frozenset[str]]:
        return {key: frozenset(values) for key, values in mapping.items()}

    @staticmethod
    def _entry_without_attributes() -> m.Ldif.Entry:
        entry = u.Ldif.Tests.create_real_entry(
            dn=c.Ldif.FILTERS_DN_BARE,
            attributes={c.Ldif.NAME_CN: [c.Ldif.ATTR_VALUE_TEST]},
        )
        return entry.model_copy(update={"attributes": None})

    @staticmethod
    def _schema_entry(
        attr_oid: str = c.Ldif.FILTERS_ATTR_OID_VALID,
        oc_oid: str = c.Ldif.FILTERS_OC_OID_VALID,
    ) -> m.Ldif.Entry:
        return u.Ldif.Tests.create_real_entry(
            dn=c.Ldif.FILTERS_DN_SCHEMA,
            attributes={
                c.Ldif.FILTERS_SCHEMA_ATTR_KEY: [attr_oid],
                c.Ldif.FILTERS_SCHEMA_OC_KEY: [oc_oid],
                c.Ldif.NAME_OBJECTCLASS: [
                    c.Ldif.NAME_TOP,
                    c.Ldif.NAME_SUBSCHEMA,
                ],
            },
        )

    @staticmethod
    def _regular_entry() -> m.Ldif.Entry:
        return u.Ldif.Tests.create_real_entry(
            dn=c.Ldif.FILTERS_DN_USER,
            attributes={
                c.Ldif.NAME_OBJECTCLASS: [
                    c.Ldif.NAME_TOP,
                    c.Ldif.NAME_PERSON,
                    c.Ldif.FILTERS_FORBIDDEN_OCS[0],
                ],
                c.Ldif.NAME_CN: [c.Ldif.ATTR_VALUE_USER],
                c.Ldif.NAME_SN: [c.Ldif.ATTR_VALUE_TEST],
                c.Ldif.NAME_MAIL: [c.Ldif.FILTERS_USER_MAIL],
                c.Ldif.NAME_DESCRIPTION: [c.Ldif.FILTERS_USER_DESCRIPTION],
            },
        )

    # ── filter_schema_by_oids ─────────────────────────────────────────────────

    @pytest.mark.parametrize(
        "key_name",
        [
            c.Ldif.FILTERS_ALLOWED_ATTR_KEY,
            c.Ldif.FILTERS_ALLOWED_OC_KEY,
            c.Ldif.FILTERS_ALLOWED_MR_KEY,
            c.Ldif.FILTERS_ALLOWED_MRU_KEY,
        ],
    )
    def test_allowed_oids_keys_are_present(self, key_name: str) -> None:
        tm.that(key_name in c.Ldif.FILTERS_ALLOWED_OIDS_FULL, eq=True)
        tm.that(key_name in c.Ldif.FILTERS_ALLOWED_OIDS_EMPTY, eq=True)

    def test_filter_schema_by_oids_keeps_matching_entry(self) -> None:
        entries: MutableSequence[m.Ldif.Entry] = [self._schema_entry()]

        result = FlextLdifFilters.filter_schema_by_oids(
            entries,
            self._mutable_allowed_oids(c.Ldif.FILTERS_ALLOWED_OIDS_FULL),
        )
        filtered = u.Tests.assert_success(result)
        tm.that(len(filtered), eq=1)

    def test_filter_schema_by_oids_excludes_unmatched_entry(self) -> None:
        unmatched = u.Ldif.Tests.create_real_entry(
            dn=c.Ldif.FILTERS_DN_SCHEMA,
            attributes={
                c.Ldif.FILTERS_SCHEMA_ATTR_KEY: [c.Ldif.FILTERS_UNMATCHED_ATTR_OID],
                c.Ldif.NAME_OBJECTCLASS: [
                    c.Ldif.NAME_TOP,
                    c.Ldif.NAME_SUBSCHEMA,
                ],
            },
        )
        result = FlextLdifFilters.filter_schema_by_oids(
            [unmatched],
            self._mutable_allowed_oids(c.Ldif.FILTERS_ALLOWED_OIDS_FULL),
        )
        filtered = u.Tests.assert_success(result)
        tm.that(len(filtered), eq=0)

    def test_filter_schema_by_oids_returns_all_when_allowed_oids_empty(self) -> None:
        entries: MutableSequence[m.Ldif.Entry] = [
            self._schema_entry(),
            self._regular_entry(),
        ]
        result = FlextLdifFilters.filter_schema_by_oids(
            entries,
            self._mutable_allowed_oids(c.Ldif.FILTERS_ALLOWED_OIDS_EMPTY),
        )
        filtered = u.Tests.assert_success(result)
        tm.that(len(filtered), eq=2)

    def test_filter_schema_by_oids_passes_through_non_schema_entries(self) -> None:
        entries: MutableSequence[m.Ldif.Entry] = [self._regular_entry()]
        result = FlextLdifFilters.filter_schema_by_oids(
            entries,
            self._mutable_allowed_oids(c.Ldif.FILTERS_ALLOWED_OIDS_FULL),
        )
        filtered = u.Tests.assert_success(result)
        tm.that(len(filtered), eq=1)

    def test_filter_schema_by_oids_entry_without_attributes(self) -> None:
        bare_entry = self._entry_without_attributes()
        result = FlextLdifFilters.filter_schema_by_oids(
            [bare_entry],
            self._mutable_allowed_oids(c.Ldif.FILTERS_ALLOWED_OIDS_FULL),
        )
        filtered = u.Tests.assert_success(result)
        tm.that(len(filtered), eq=1)

    # ── filter_entry_attributes ───────────────────────────────────────────────

    def test_filter_entry_attributes_removes_forbidden_attrs(self) -> None:
        entry = self._regular_entry()
        result = FlextLdifFilters.filter_entry_attributes(
            entry,
            list(c.Ldif.FILTERS_FORBIDDEN_ATTRS),
            [],
        )
        tm.that(result.attributes is not None, eq=True)
        if result.attributes is None:
            pytest.fail("Filtered entry attributes should be present")
        remaining = set(result.attributes.attributes.keys())
        tm.that(
            remaining.isdisjoint(set(c.Ldif.FILTERS_FORBIDDEN_ATTRS)),
            eq=True,
        )

    def test_filter_entry_attributes_removes_forbidden_objectclasses(self) -> None:
        entry = self._regular_entry()
        result = FlextLdifFilters.filter_entry_attributes(
            entry,
            [],
            list(c.Ldif.FILTERS_FORBIDDEN_OCS),
        )
        tm.that(result.attributes is not None, eq=True)
        if result.attributes is None:
            pytest.fail("Filtered entry attributes should be present")
        ocs = result.attributes.attributes.get(c.Ldif.NAME_OBJECTCLASS, [])
        for forbidden_oc in c.Ldif.FILTERS_FORBIDDEN_OCS:
            tm.that(forbidden_oc not in ocs, eq=True)

    def test_filter_entry_attributes_noop_when_no_attributes_on_entry(self) -> None:
        bare = self._entry_without_attributes()
        result = FlextLdifFilters.filter_entry_attributes(
            bare,
            [c.Ldif.NAME_CN],
            [],
        )
        tm.that(result, is_=m.Ldif.Entry)

    # ── filter_schema_attribute_values ────────────────────────────────────────

    @pytest.mark.parametrize(
        "attr_key",
        [
            c.Ldif.FILTERS_SCHEMA_ATTR_KEY,
            c.Ldif.FILTERS_SCHEMA_OC_KEY,
        ],
    )
    def test_filter_schema_attribute_values_keeps_allowed_oid(
        self,
        attr_key: str,
    ) -> None:
        allowed_oid = (
            c.Ldif.FILTERS_ATTR_OID_ALLOWED
            if attr_key == c.Ldif.FILTERS_SCHEMA_ATTR_KEY
            else c.Ldif.FILTERS_OC_OID_ALLOWED
        )
        raw_oid = (
            c.Ldif.FILTERS_ATTR_OID_VALID
            if attr_key == c.Ldif.FILTERS_SCHEMA_ATTR_KEY
            else c.Ldif.FILTERS_OC_OID_VALID
        )
        entry = u.Ldif.Tests.create_real_entry(
            dn=c.Ldif.FILTERS_DN_SCHEMA,
            attributes={
                attr_key: [raw_oid],
                c.Ldif.NAME_OBJECTCLASS: [c.Ldif.NAME_TOP],
            },
        )
        result = FlextLdifFilters.filter_schema_attribute_values(
            entry,
            {attr_key.lower(): frozenset({allowed_oid})},
        )
        tm.that(result, is_=m.Ldif.Entry)
        tm.that(result.attributes is not None, eq=True)
        if result.attributes is None:
            pytest.fail("Filtered entry attributes should be present")
        attr_vals = result.attributes.attributes.get(attr_key, [])
        tm.that(raw_oid in attr_vals, eq=True)

    def test_filter_schema_attribute_values_drops_disallowed_oid(self) -> None:
        entry = u.Ldif.Tests.create_real_entry(
            dn=c.Ldif.FILTERS_DN_SCHEMA,
            attributes={
                c.Ldif.FILTERS_SCHEMA_ATTR_KEY: [
                    c.Ldif.FILTERS_ATTR_OID_VALID,
                    c.Ldif.FILTERS_UNWANTED_ATTR_OID,
                ],
                c.Ldif.NAME_OBJECTCLASS: [c.Ldif.NAME_TOP],
            },
        )
        result = FlextLdifFilters.filter_schema_attribute_values(
            entry,
            {
                c.Ldif.FILTERS_SCHEMA_ATTR_KEY.lower(): frozenset({
                    c.Ldif.FILTERS_ATTR_OID_ALLOWED
                })
            },
        )
        tm.that(result.attributes is not None, eq=True)
        if result.attributes is None:
            pytest.fail("Filtered entry attributes should be present")
        attr_vals = result.attributes.attributes.get(c.Ldif.FILTERS_SCHEMA_ATTR_KEY, [])
        tm.that(len(attr_vals), eq=1)
        tm.that(c.Ldif.FILTERS_ATTR_OID_VALID in attr_vals, eq=True)

    def test_filter_schema_attribute_values_noop_when_no_attributes(self) -> None:
        bare = self._entry_without_attributes()
        result = FlextLdifFilters.filter_schema_attribute_values(bare, {})
        tm.that(result, is_=m.Ldif.Entry)
