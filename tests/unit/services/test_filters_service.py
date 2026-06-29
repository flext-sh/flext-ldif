"""Data-driven unit tests for ldif service."""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldif import ldif
from tests.constants import c
from tests.models import m
from tests.typings import t
from tests.utilities import TestsFlextLdifUtilities as u


class TestsFlextLdifFiltersService:
    """Cover filter service branches via flat data-driven constants."""

    @staticmethod
    def _mutable_allowed_oids(
        mapping: t.MappingKV[str, frozenset[str]],
    ) -> dict[str, frozenset[str]]:
        return {key: frozenset(values) for key, values in mapping.items()}

    @staticmethod
    def _entry_without_attributes() -> m.Ldif.Entry:
        entry = u.Tests.create_real_entry(
            dn=c.Tests.FILTERS_DN_BARE,
            attributes={c.Tests.NAME_CN: [c.Tests.ATTR_VALUE_TEST]},
        )
        updated_entry: m.Ldif.Entry = entry.model_copy(update={"attributes": None})
        return updated_entry

    @staticmethod
    def _schema_entry(
        attr_oid: str = c.Tests.FILTERS_ATTR_OID_VALID,
        oc_oid: str = c.Tests.FILTERS_OC_OID_VALID,
    ) -> m.Ldif.Entry:
        return u.Tests.create_real_entry(
            dn=c.Tests.FILTERS_DN_SCHEMA,
            attributes={
                c.Tests.FILTERS_SCHEMA_ATTR_KEY: [attr_oid],
                c.Tests.FILTERS_SCHEMA_OC_KEY: [oc_oid],
                c.Tests.NAME_OBJECTCLASS: [
                    c.Tests.NAME_TOP,
                    c.Tests.NAME_SUBSCHEMA,
                ],
            },
        )

    @staticmethod
    def _regular_entry() -> m.Ldif.Entry:
        return u.Tests.create_real_entry(
            dn=c.Tests.FILTERS_DN_USER,
            attributes={
                c.Tests.NAME_OBJECTCLASS: [
                    c.Tests.NAME_TOP,
                    c.Tests.NAME_PERSON,
                    c.Tests.NAME_INET_ORG_PERSON,
                ],
                c.Tests.NAME_CN: [c.Tests.ATTR_VALUE_USER],
                c.Tests.NAME_SN: [c.Tests.ATTR_VALUE_TEST],
                c.Tests.NAME_MAIL: [c.Tests.FILTERS_USER_MAIL],
                c.Tests.NAME_DESCRIPTION: [c.Tests.FILTERS_USER_DESCRIPTION],
            },
        )

    # ── filter_schema_by_oids ─────────────────────────────────────────────────

    @pytest.mark.parametrize(
        "key_name",
        [
            c.Tests.FILTERS_ALLOWED_ATTR_KEY,
            c.Tests.FILTERS_ALLOWED_OC_KEY,
            c.Tests.FILTERS_ALLOWED_MR_KEY,
            c.Tests.FILTERS_ALLOWED_MRU_KEY,
        ],
    )
    def test_allowed_oids_keys_are_present(self, key_name: str) -> None:
        tm.that(key_name in c.Tests.FILTERS_ALLOWED_OIDS_FULL, eq=True)
        tm.that(key_name in c.Tests.FILTERS_ALLOWED_OIDS_EMPTY, eq=True)

    # ── filter_entry_attributes ───────────────────────────────────────────────

    def test_filter_entry_attributes_removes_forbidden_attrs(self) -> None:
        entry = self._regular_entry()
        result = ldif.filter_entry_attributes(
            entry,
            list(c.Tests.FILTERS_FORBIDDEN_ATTRS_ORDERED),
            [],
        )
        tm.that(result.attributes is not None, eq=True)
        if result.attributes is None:
            pytest.fail("Filtered entry attributes should be present")
        remaining = set(result.attributes.attributes.keys())
        tm.that(
            remaining.isdisjoint(c.Tests.FILTERS_FORBIDDEN_ATTRS),
            eq=True,
        )

    def test_filter_entry_attributes_removes_forbidden_objectclasses(self) -> None:
        entry = self._regular_entry()
        result = ldif.filter_entry_attributes(
            entry,
            [],
            list(c.Tests.FILTERS_FORBIDDEN_OCS_ORDERED),
        )
        tm.that(result.attributes is not None, eq=True)
        if result.attributes is None:
            pytest.fail("Filtered entry attributes should be present")
        ocs = result.attributes.attributes.get(c.Tests.NAME_OBJECTCLASS, [])
        for forbidden_oc in c.Tests.FILTERS_FORBIDDEN_OCS_ORDERED:
            tm.that(forbidden_oc not in ocs, eq=True)

    def test_filter_entry_attributes_noop_when_no_attributes_on_entry(self) -> None:
        bare = self._entry_without_attributes()
        result = ldif.filter_entry_attributes(
            bare,
            [c.Tests.NAME_CN],
            [],
        )
        tm.that(result, is_=m.Ldif.Entry)

    # ── filter_schema_attribute_values ────────────────────────────────────────

    @pytest.mark.parametrize(
        "attr_key",
        [
            c.Tests.FILTERS_SCHEMA_ATTR_KEY,
            c.Tests.FILTERS_SCHEMA_OC_KEY,
        ],
    )
    def test_filter_schema_attribute_values_keeps_allowed_oid(
        self,
        attr_key: str,
    ) -> None:
        allowed_oid = (
            c.Tests.FILTERS_ATTR_OID_ALLOWED
            if attr_key == c.Tests.FILTERS_SCHEMA_ATTR_KEY
            else c.Tests.FILTERS_OC_OID_ALLOWED
        )
        raw_oid = (
            c.Tests.FILTERS_ATTR_OID_VALID
            if attr_key == c.Tests.FILTERS_SCHEMA_ATTR_KEY
            else c.Tests.FILTERS_OC_OID_VALID
        )
        entry = u.Tests.create_real_entry(
            dn=c.Tests.FILTERS_DN_SCHEMA,
            attributes={
                attr_key: [raw_oid],
                c.Tests.NAME_OBJECTCLASS: [c.Tests.NAME_TOP],
            },
        )
        result = ldif.filter_schema_attribute_values(
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
        entry = u.Tests.create_real_entry(
            dn=c.Tests.FILTERS_DN_SCHEMA,
            attributes={
                c.Tests.FILTERS_SCHEMA_ATTR_KEY: [
                    c.Tests.FILTERS_ATTR_OID_VALID,
                    c.Tests.FILTERS_UNWANTED_ATTR_OID,
                ],
                c.Tests.NAME_OBJECTCLASS: [c.Tests.NAME_TOP],
            },
        )
        result = ldif.filter_schema_attribute_values(
            entry,
            {
                c.Tests.FILTERS_SCHEMA_ATTR_KEY.lower(): frozenset({
                    c.Tests.FILTERS_ATTR_OID_ALLOWED
                })
            },
        )
        tm.that(result.attributes is not None, eq=True)
        if result.attributes is None:
            pytest.fail("Filtered entry attributes should be present")
        attr_vals = result.attributes.attributes.get(
            c.Tests.FILTERS_SCHEMA_ATTR_KEY, []
        )
        tm.that(len(attr_vals), eq=1)
        tm.that(c.Tests.FILTERS_ATTR_OID_VALID in attr_vals, eq=True)

    def test_filter_schema_attribute_values_accepts_whitelist_rules(self) -> None:
        entry = u.Tests.create_real_entry(
            dn=c.Tests.FILTERS_DN_SCHEMA,
            attributes={
                c.Tests.FILTERS_SCHEMA_ATTR_KEY: [
                    c.Tests.FILTERS_ATTR_OID_VALID,
                    c.Tests.FILTERS_UNWANTED_ATTR_OID,
                ],
                c.Tests.NAME_OBJECTCLASS: [c.Tests.NAME_TOP],
            },
        )
        whitelist_rules = m.Ldif.WhitelistRules.model_validate(
            c.Tests.FILTERS_ALLOWED_OIDS_FULL,
        )
        result = ldif.filter_schema_attribute_values(entry, whitelist_rules)
        tm.that(result.attributes is not None, eq=True)
        if result.attributes is None:
            pytest.fail("Filtered entry attributes should be present")
        attr_vals = result.attributes.attributes.get(
            c.Tests.FILTERS_SCHEMA_ATTR_KEY,
            [],
        )
        tm.that(len(attr_vals), eq=1)
        tm.that(c.Tests.FILTERS_ATTR_OID_VALID in attr_vals, eq=True)

    def test_filter_schema_attribute_values_noop_when_no_attributes(self) -> None:
        bare = self._entry_without_attributes()
        result = ldif.filter_schema_attribute_values(bare, {})
        tm.that(result, is_=m.Ldif.Entry)

    def test_filter_entry_attributes_removes_all_objectclasses(self) -> None:
        """Line 186: all OC values are forbidden → key is popped entirely."""
        entry = u.Tests.create_real_entry(
            dn=c.Tests.FILTERS_DN_USER,
            attributes={
                c.Tests.NAME_OBJECTCLASS: list(c.Tests.FILTERS_FORBIDDEN_OCS_ORDERED)
            },
        )
        result = ldif.filter_entry_attributes(
            entry,
            [],
            list(c.Tests.FILTERS_FORBIDDEN_OCS_ORDERED),
        )
        tm.that(result.attributes is not None, eq=True)
        if result.attributes is None:
            pytest.fail("Filtered entry attributes should be present")
        tm.that(c.Tests.NAME_OBJECTCLASS not in result.attributes.attributes, eq=True)

    def test_filter_schema_attribute_values_drops_all_values_when_none_allowed(
        self,
    ) -> None:
        """Line 226: all attribute values are disallowed → key is deleted."""
        entry = u.Tests.create_real_entry(
            dn=c.Tests.FILTERS_DN_SCHEMA,
            attributes={
                c.Tests.FILTERS_SCHEMA_ATTR_KEY: [c.Tests.FILTERS_UNWANTED_ATTR_OID],
                c.Tests.NAME_OBJECTCLASS: [c.Tests.NAME_TOP],
            },
        )
        result = ldif.filter_schema_attribute_values(
            entry,
            {c.Tests.FILTERS_SCHEMA_ATTR_KEY.lower(): frozenset()},
        )
        tm.that(result.attributes is not None, eq=True)
        if result.attributes is None:
            pytest.fail("Filtered entry attributes should be present")
        tm.that(
            c.Tests.FILTERS_SCHEMA_ATTR_KEY not in result.attributes.attributes,
            eq=True,
        )
