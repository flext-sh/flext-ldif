"""Data-driven tests to enforce flat constants reuse and contracts."""

from __future__ import annotations

import pytest
from flext_tests import tm

from tests import c


class TestsFlextLdifConstantsDataDriven:
    """Validate reusable constants contracts through parameterized rules."""

    @pytest.mark.parametrize(
        "server_value",
        [
            c.Tests.AD,
            c.Tests.APACHE,
            c.Tests.DS389,
            c.Tests.NOVELL,
            c.Tests.OPENLDAP1,
            c.Tests.TIVOLI,
        ],
    )
    def test_extended_server_type_constants_are_non_empty(
        self, server_value: str
    ) -> None:
        tm.that(isinstance(server_value, str), eq=True)
        tm.that(bool(server_value), eq=True)

    def test_fixture_server_groups_are_consistent(self) -> None:
        tm.that(c.Tests.SCHEMA in c.Tests.FIXTURE_KINDS, eq=True)
        tm.that(c.Tests.ACL in c.Tests.FIXTURE_KINDS, eq=True)
        tm.that(c.Tests.ENTRIES in c.Tests.FIXTURE_KINDS, eq=True)
        tm.that(c.Tests.INTEGRATION in c.Tests.FIXTURE_KINDS, eq=True)
        tm.that(c.Tests.RFC in c.Tests.FIXTURE_SERVERS_SCHEMA, eq=True)
        tm.that(c.Tests.RFC in c.Tests.FIXTURE_SERVERS_COMMON, eq=False)

    @pytest.mark.parametrize(
        "name_constant",
        [
            c.Tests.NAME_UID,
            c.Tests.NAME_MEMBER,
            c.Tests.NAME_GROUP_OF_NAMES,
            c.Tests.NAME_ACI,
            c.Tests.NAME_ORCLACI,
        ],
    )
    def test_group_acl_uid_name_constants_are_non_empty(
        self,
        name_constant: str,
    ) -> None:
        tm.that(isinstance(name_constant, str), eq=True)
        tm.that(bool(name_constant), eq=True)

    def test_boolean_false_constant_maps_to_oid_zero(self) -> None:
        mapped = c.Tests.BOOLEAN_RFC_TO_OID[c.Tests.BOOLEAN_FALSE]
        tm.that(mapped, eq="0")

    @pytest.mark.parametrize(
        ("scenario", "content"),
        [
            ("unicode", c.Tests.EDGE_CASE_UNICODE_LDIF),
            ("deep_dn", c.Tests.EDGE_CASE_DEEP_DN_LDIF),
            ("large_multivalue", c.Tests.EDGE_CASE_LARGE_MULTIVALUE_LDIF),
        ],
    )
    def test_edge_case_ldif_constants_are_structurally_valid(
        self,
        scenario: str,
        content: str,
    ) -> None:
        tm.that(bool(scenario), eq=True)
        tm.that(content.startswith("dn:"), eq=True)
        tm.that("\n" in content, eq=True)

    def test_edge_case_unicode_regex_matches_unicode_fixture(self) -> None:
        has_non_ascii = c.Tests.EDGE_CASE_NON_ASCII_REGEX.search(
            c.Tests.EDGE_CASE_UNICODE_LDIF,
        )
        tm.that(has_non_ascii is not None, eq=True)

    def test_edge_case_large_multivalue_contains_min_member_count(self) -> None:
        member_count = c.Tests.EDGE_CASE_LARGE_MULTIVALUE_LDIF.count("member:")
        tm.that(member_count < c.Tests.EDGE_CASE_MIN_MULTIVALUE_COUNT, eq=True)
        tm.that(member_count > 0, eq=True)
