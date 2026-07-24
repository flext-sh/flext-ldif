"""Behavioral integration tests for LDIF categorization with real-world data.

These tests exercise ONLY the public categorization contract exposed by the
``flext_ldif.ldif`` facade:

- ``categorization(...)`` service factory,
- ``validate_dns`` / ``categorize_entries`` / ``filter_by_base_dn`` (``r[T]`` and
  ``FlexibleCategories`` public surface),
- ``parse_ldif`` end-to-end pipeline,
- the ``u.Ldif.is_under_base`` public utility contract.

The core business rule under test: entries are placed and filtered using a
hierarchical DN check (``is_under_base``), never substring matching, so
``dc=example2`` is never treated as being under ``dc=example``.

Generic ``dc=example`` data is used deliberately; project-specific scenarios
live in the consuming migration projects.
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldif import ldif
from tests import c, m, p, t, u

_BASE_DN = "dc=example"


class TestsFlextLdifCategorizationRealData:
    """Behavioral tests for categorization with real-world DN scenarios."""

    @staticmethod
    def _entry(dn: str, objectclass: str) -> p.Ldif.Entry:
        """Build an in-memory entry with a single objectClass."""
        return m.Ldif.Entry(
            dn=m.Ldif.DN(value=dn),
            attributes=m.Ldif.Attributes(
                attributes={"objectClass": [objectclass]}, attribute_metadata={}
            ),
        )

    @staticmethod
    def _acl_entry(dn: str) -> p.Ldif.Entry:
        """Build an in-memory entry carrying an ACI attribute."""
        return m.Ldif.Entry(
            dn=m.Ldif.DN(value=dn),
            attributes=m.Ldif.Attributes(
                attributes={"aci": ['(targetattr="*")(version 3.0;acl "test";)']},
                attribute_metadata={},
            ),
        )

    @pytest.fixture
    def hierarchy_entries(self) -> t.MutableSequenceOf[p.Ldif.Entry]:
        """Mixed entries: three under dc=example, two under dc=example2."""
        return [
            self._entry("dc=example", "domain"),
            self._entry("ou=users,dc=example", "organizationalUnit"),
            self._entry("cn=user1,ou=users,dc=example", "person"),
            self._entry("dc=example2", "domain"),
            self._entry("ou=test,dc=example2", "organizationalUnit"),
        ]

    @staticmethod
    def _dns(entries: t.MutableSequenceOf[p.Ldif.Entry]) -> set[str]:
        """Collect the DN string values from a category bucket."""
        return {e.dn.value for e in entries if e.dn is not None}

    # -- validate_dns ---------------------------------------------------------

    def test_validate_dns_succeeds_and_returns_all_valid_entries(
        self, hierarchy_entries: t.MutableSequenceOf[p.Ldif.Entry]
    ) -> None:
        """validate_dns returns a success result preserving every valid entry."""
        categorization = ldif.categorization(base_dn=_BASE_DN, server_type=c.Tests.OUD)

        result = categorization.validate_dns(hierarchy_entries)

        tm.ok(result)
        tm.that(len(result.value), eq=len(hierarchy_entries))
        tm.that(self._dns(result.value), eq=self._dns(hierarchy_entries))

    # -- categorize_entries ---------------------------------------------------

    def test_categorize_entries_places_domains_ous_and_people_by_contract(
        self, hierarchy_entries: t.MutableSequenceOf[p.Ldif.Entry]
    ) -> None:
        """Domains/OUs categorize as HIERARCHY, person entries as USERS."""
        categorization = ldif.categorization(base_dn=_BASE_DN, server_type=c.Tests.OUD)
        validated = categorization.validate_dns(hierarchy_entries)
        tm.ok(validated)

        result = categorization.categorize_entries(validated.value)

        tm.ok(result)
        categories = result.value
        hierarchy = self._dns(categories.get(c.Ldif.Categories.HIERARCHY))
        users = self._dns(categories.get(c.Ldif.Categories.USERS))
        tm.that(hierarchy, has="dc=example")
        tm.that(hierarchy, has="ou=users,dc=example")
        tm.that(users, has="cn=user1,ou=users,dc=example")

    def test_categorize_entry_with_no_matching_rule_is_rejected(self) -> None:
        """An entry whose objectClass matches no category lands in REJECTED."""
        categorization = ldif.categorization(base_dn=_BASE_DN, server_type=c.Tests.OUD)
        unknown = [self._entry("cn=mystery,dc=example", "unmodeledClass")]
        validated = categorization.validate_dns(unknown)
        tm.ok(validated)

        result = categorization.categorize_entries(validated.value)

        tm.ok(result)
        rejected = self._dns(result.value.get(c.Ldif.Categories.REJECTED))
        tm.that(rejected, has="cn=mystery,dc=example")

    # -- filter_by_base_dn (substring safety) --------------------------------

    def test_filter_by_base_dn_keeps_under_base_and_rejects_outside(
        self, hierarchy_entries: t.MutableSequenceOf[p.Ldif.Entry]
    ) -> None:
        """Base-DN filtering uses hierarchy, so dc=example2 never matches dc=example."""
        categorization = ldif.categorization(base_dn=_BASE_DN, server_type=c.Tests.OUD)
        validated = categorization.validate_dns(hierarchy_entries)
        tm.ok(validated)
        categorized = categorization.categorize_entries(validated.value)
        tm.ok(categorized)

        filtered = categorization.filter_by_base_dn(categorized.value)

        hierarchy = self._dns(filtered.get(c.Ldif.Categories.HIERARCHY))
        users = self._dns(filtered.get(c.Ldif.Categories.USERS))
        rejected = self._dns(filtered.get(c.Ldif.Categories.REJECTED))
        tm.that(hierarchy, has="dc=example")
        tm.that(hierarchy, has="ou=users,dc=example")
        tm.that(users, has="cn=user1,ou=users,dc=example")
        # Substring false-positive prevention: dc=example2 subtree is rejected.
        tm.that(rejected, has="dc=example2")
        tm.that(rejected, has="ou=test,dc=example2")
        tm.that(hierarchy, lacks="dc=example2")
        tm.that(hierarchy, lacks="ou=test,dc=example2")

    def test_filter_by_base_dn_partitions_acls_by_hierarchy(self) -> None:
        """ACLs under the base DN are kept in ACL; those outside are rejected."""
        acl_entries = [
            self._acl_entry("dc=example"),
            self._acl_entry("ou=users,dc=example"),
            self._acl_entry("dc=example2"),
            self._acl_entry("cn=settings"),
        ]
        categorization = ldif.categorization(base_dn=_BASE_DN, server_type=c.Tests.OUD)
        validated = categorization.validate_dns(acl_entries)
        tm.ok(validated)
        categorized = categorization.categorize_entries(validated.value)
        tm.ok(categorized)

        filtered = categorization.filter_by_base_dn(categorized.value)

        acls = self._dns(filtered.get(c.Ldif.Categories.ACL))
        rejected = self._dns(filtered.get(c.Ldif.Categories.REJECTED))
        tm.that(acls, has="dc=example")
        tm.that(acls, has="ou=users,dc=example")
        tm.that(acls, lacks="dc=example2")
        tm.that(rejected, has="dc=example2")
        tm.that(rejected, has="cn=settings")

    @pytest.mark.parametrize(
        ("dn", "base_dn", "expected"),
        [
            ("dc=example", "dc=example", True),
            ("ou=users,dc=example", "dc=example", True),
            ("cn=user1,ou=users,dc=example", "dc=example", True),
            ("DC=Example", "dc=example", True),
            ("dc=example2", "dc=example", False),
            ("ou=test,dc=example2", "dc=example", False),
            ("cn=settings", "dc=example", False),
            ("dc=example", None, False),
            (None, "dc=example", False),
        ],
    )
    def test_is_under_base_uses_hierarchy_not_substring(
        self, dn: str | None, base_dn: str | None, expected: bool
    ) -> None:
        """The public is_under_base contract rejects substring false positives."""
        assert u.Ldif.is_under_base(dn, base_dn) is expected

    # -- end-to-end pipeline --------------------------------------------------

    def test_parse_categorize_filter_pipeline_from_ldif_text(self) -> None:
        """Full pipeline: parse LDIF text, categorize, then filter by base DN."""
        ldif_content = (
            "dn: dc=example\nobjectClass: domain\ndc: example\n\n"
            "dn: ou=users,dc=example\nobjectClass: organizationalUnit\nou: users\n\n"
            "dn: cn=admin,ou=users,dc=example\n"
            "objectClass: person\ncn: admin\nsn: Admin\n\n"
            "dn: cn=user1,ou=users,dc=example\n"
            "objectClass: person\ncn: user1\nsn: User1\n\n"
            "dn: dc=example2\nobjectClass: domain\ndc: example2\n\n"
            "dn: ou=test,dc=example2\nobjectClass: organizationalUnit\nou: test\n"
        )
        api = ldif()

        parsed = api.parse_ldif(value=ldif_content, server_type=c.Tests.RFC)

        tm.ok(parsed)
        entries = parsed.value.entries
        tm.that(len(entries), eq=6)

        categorization = api.categorization(base_dn=_BASE_DN, server_type=c.Tests.OUD)
        validated = categorization.validate_dns(entries)
        tm.ok(validated)
        categorized = categorization.categorize_entries(validated.value)
        tm.ok(categorized)

        filtered = categorization.filter_by_base_dn(categorized.value)

        hierarchy = self._dns(filtered.get(c.Ldif.Categories.HIERARCHY))
        users = self._dns(filtered.get(c.Ldif.Categories.USERS))
        rejected = self._dns(filtered.get(c.Ldif.Categories.REJECTED))
        assert {"dc=example", "ou=users,dc=example"} <= hierarchy
        assert {"cn=admin,ou=users,dc=example", "cn=user1,ou=users,dc=example"} <= users
        assert {"dc=example2", "ou=test,dc=example2"} <= rejected
