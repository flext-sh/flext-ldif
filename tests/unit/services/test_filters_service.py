"""Behavioral unit tests for the LDIF filters service.

Every test asserts observable public contract: the returned ``m.Ldif.Entry``
model state (via public fields) for the stateless attribute/OID filters, and the
``r[T]`` outcome for the fallible schema-by-OID whitelist filter. No private
attribute access, no internal-collaborator spying, no coverage-line pokes.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flext_ldif import ldif
from flext_ldif.services import FlextLdifFilters
from tests import TestsFlextLdifUtilities as u, c, m, tm

if TYPE_CHECKING:
    from tests import t


class TestsFlextLdifFiltersService:
    """Public-contract behavior of ``filter_*`` operations."""

    # ── fixtures ──────────────────────────────────────────────────────────────

    @staticmethod
    @pytest.fixture
    def regular_entry() -> m.Ldif.Entry:
        """Build a person entry carrying objectClasses plus filterable attributes.

        Returns:
            The resulting ``m.Ldif.Entry``.
        """
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

    @staticmethod
    @pytest.fixture
    def entry_without_attributes() -> m.Ldif.Entry:
        """Build an entry whose ``attributes`` field is ``None``.

        Returns:
            The resulting ``m.Ldif.Entry``.
        """
        entry = u.Tests.create_real_entry(
            dn=c.Tests.FILTERS_DN_BARE,
            attributes={c.Tests.NAME_CN: [c.Tests.ATTR_VALUE_TEST]},
        )
        return entry.model_copy(update={"attributes": None})

    @staticmethod
    def _schema_entry(values: t.StrSequence) -> m.Ldif.Entry:
        return u.Tests.create_real_entry(
            dn=c.Tests.FILTERS_DN_SCHEMA,
            attributes={
                c.Tests.FILTERS_SCHEMA_ATTR_KEY: list(values),
                c.Tests.NAME_OBJECTCLASS: [c.Tests.NAME_TOP, c.Tests.NAME_SUBSCHEMA],
            },
        )

    # ── filter_entry_attributes ───────────────────────────────────────────────

    @staticmethod
    def test_removes_forbidden_attributes_keeping_the_rest(
        regular_entry: m.Ldif.Entry,
    ) -> None:
        """Test removes forbidden attributes keeping the rest."""
        result = ldif.filter_entry_attributes(
            regular_entry,
            list(c.Tests.FILTERS_FORBIDDEN_ATTRS_ORDERED),
            [],
        )

        assert result.attributes is not None
        remaining = set(result.attributes.attributes)
        tm.that(remaining.isdisjoint(c.Tests.FILTERS_FORBIDDEN_ATTRS), eq=True)
        # Non-forbidden attributes survive untouched.
        tm.that(c.Tests.NAME_CN in remaining, eq=True)
        tm.that(c.Tests.NAME_OBJECTCLASS in remaining, eq=True)

    @staticmethod
    def test_removes_forbidden_objectclass_values(
        regular_entry: m.Ldif.Entry,
    ) -> None:
        """Test removes forbidden objectclass values."""
        result = ldif.filter_entry_attributes(
            regular_entry,
            [],
            list(c.Tests.FILTERS_FORBIDDEN_OCS_ORDERED),
        )

        assert result.attributes is not None
        ocs = result.attributes.attributes.get(c.Tests.NAME_OBJECTCLASS, [])
        for forbidden_oc in c.Tests.FILTERS_FORBIDDEN_OCS_ORDERED:
            tm.that(forbidden_oc not in ocs, eq=True)
        # Allowed objectClasses remain.
        tm.that(c.Tests.NAME_PERSON in ocs, eq=True)

    @staticmethod
    def test_drops_objectclass_key_when_all_values_forbidden() -> None:
        """Test drops objectclass key when all values forbidden."""
        entry = u.Tests.create_real_entry(
            dn=c.Tests.FILTERS_DN_USER,
            attributes={
                c.Tests.NAME_OBJECTCLASS: list(c.Tests.FILTERS_FORBIDDEN_OCS_ORDERED),
            },
        )

        result = ldif.filter_entry_attributes(
            entry,
            [],
            list(c.Tests.FILTERS_FORBIDDEN_OCS_ORDERED),
        )

        assert result.attributes is not None
        tm.that(c.Tests.NAME_OBJECTCLASS not in result.attributes.attributes, eq=True)

    @staticmethod
    def test_empty_forbidden_lists_preserve_entry_identity(
        regular_entry: m.Ldif.Entry,
    ) -> None:
        """Test empty forbidden lists preserve entry identity."""
        assert regular_entry.attributes is not None
        result = ldif.filter_entry_attributes(regular_entry, [], [])

        assert result.attributes is not None
        tm.that(
            result.attributes.attributes == regular_entry.attributes.attributes,
            eq=True,
        )

    @staticmethod
    def test_attribute_filtering_is_idempotent(
        regular_entry: m.Ldif.Entry,
    ) -> None:
        """Test attribute filtering is idempotent."""
        forbidden = list(c.Tests.FILTERS_FORBIDDEN_ATTRS_ORDERED)
        once = ldif.filter_entry_attributes(regular_entry, forbidden, [])
        twice = ldif.filter_entry_attributes(once, forbidden, [])

        assert once.attributes is not None
        assert twice.attributes is not None
        tm.that(twice.attributes.attributes == once.attributes.attributes, eq=True)

    @staticmethod
    def test_returns_entry_unchanged_when_no_attributes_present(
        entry_without_attributes: m.Ldif.Entry,
    ) -> None:
        """Test returns entry unchanged when no attributes present."""
        result = ldif.filter_entry_attributes(
            entry_without_attributes,
            [c.Tests.NAME_CN],
            [],
        )

        assert isinstance(result, m.Ldif.Entry)
        tm.that(result.attributes is None, eq=True)

    # ── filter_schema_attribute_values ────────────────────────────────────────

    @staticmethod
    @pytest.mark.parametrize(
        ("attr_key", "allowed_oid", "raw_oid"),
        [
            (
                c.Tests.FILTERS_SCHEMA_ATTR_KEY,
                c.Tests.FILTERS_ATTR_OID_ALLOWED,
                c.Tests.FILTERS_ATTR_OID_VALID,
            ),
            (
                c.Tests.FILTERS_SCHEMA_OC_KEY,
                c.Tests.FILTERS_OC_OID_ALLOWED,
                c.Tests.FILTERS_OC_OID_VALID,
            ),
        ],
    )
    def test_keeps_schema_value_whose_oid_is_whitelisted(
        attr_key: str,
        allowed_oid: str,
        raw_oid: str,
    ) -> None:
        """Test keeps schema value whose oid is whitelisted."""
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

        assert result.attributes is not None
        attr_vals = result.attributes.attributes.get(attr_key, [])
        tm.that(raw_oid in attr_vals, eq=True)

    @staticmethod
    def test_drops_schema_value_whose_oid_is_not_whitelisted() -> None:
        """Test drops schema value whose oid is not whitelisted."""
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
                    c.Tests.FILTERS_ATTR_OID_ALLOWED,
                }),
            },
        )

        assert result.attributes is not None
        attr_vals = result.attributes.attributes.get(
            c.Tests.FILTERS_SCHEMA_ATTR_KEY,
            [],
        )
        tm.that(len(attr_vals), eq=1)
        tm.that(c.Tests.FILTERS_ATTR_OID_VALID in attr_vals, eq=True)
        tm.that(c.Tests.FILTERS_UNWANTED_ATTR_OID not in attr_vals, eq=True)

    @staticmethod
    def test_accepts_whitelist_rules_model_as_allowed_oids() -> None:
        """Test accepts whitelist rules model as allowed oids."""
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

        assert result.attributes is not None
        attr_vals = result.attributes.attributes.get(
            c.Tests.FILTERS_SCHEMA_ATTR_KEY,
            [],
        )
        tm.that(len(attr_vals), eq=1)
        tm.that(c.Tests.FILTERS_ATTR_OID_VALID in attr_vals, eq=True)

    @staticmethod
    def test_removes_key_when_all_schema_values_disallowed() -> None:
        """Test removes key when all schema values disallowed."""
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

        assert result.attributes is not None
        tm.that(
            c.Tests.FILTERS_SCHEMA_ATTR_KEY not in result.attributes.attributes,
            eq=True,
        )

    @staticmethod
    def test_returns_entry_unchanged_when_no_attributes_to_filter(
        entry_without_attributes: m.Ldif.Entry,
    ) -> None:
        """Test returns entry unchanged when no attributes to filter."""
        result = ldif.filter_schema_attribute_values(entry_without_attributes, {})

        assert isinstance(result, m.Ldif.Entry)
        tm.that(result.attributes is None, eq=True)

    # ── filter_schema_by_oids (fallible r[T] contract) ────────────────────────

    def test_schema_by_oids_keeps_entry_matching_whitelist(self) -> None:
        """Test schema by oids keeps entry matching whitelist."""
        entry = self._schema_entry([c.Tests.FILTERS_ATTR_OID_VALID])
        whitelist = m.Ldif.WhitelistRules.model_validate(
            c.Tests.FILTERS_ALLOWED_OIDS_FULL,
        )

        result = FlextLdifFilters.filter_schema_by_oids(
            entries=[entry],
            allowed_oids=whitelist,
        )

        tm.that(result.success, eq=True)
        tm.that(len(result.unwrap()), eq=1)

    def test_schema_by_oids_drops_entry_outside_whitelist(self) -> None:
        """Test schema by oids drops entry outside whitelist."""
        entry = self._schema_entry([c.Tests.FILTERS_UNWANTED_ATTR_OID])
        whitelist = m.Ldif.WhitelistRules.model_validate(
            c.Tests.FILTERS_ALLOWED_OIDS_FULL,
        )

        result = FlextLdifFilters.filter_schema_by_oids(
            entries=[entry],
            allowed_oids=whitelist,
        )

        tm.that(result.success, eq=True)
        tm.that(len(result.unwrap()), eq=0)

    def test_schema_by_oids_returns_all_entries_when_whitelist_empty(self) -> None:
        """Test schema by oids returns all entries when whitelist empty."""
        entry = self._schema_entry([c.Tests.FILTERS_UNWANTED_ATTR_OID])
        empty_whitelist = m.Ldif.WhitelistRules.model_validate(
            c.Tests.FILTERS_ALLOWED_OIDS_EMPTY,
        )

        result = FlextLdifFilters.filter_schema_by_oids(
            entries=[entry],
            allowed_oids=empty_whitelist,
        )

        tm.that(result.success, eq=True)
        tm.that(len(result.unwrap()), eq=1)
