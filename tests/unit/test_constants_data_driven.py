"""Behavioral contract tests for the flext-ldif flat test-constants namespace.

These assert the OBSERVABLE contract of ``c.Tests`` — the exact canonical
values, the relationships between constant groups, and the structural
invariants callers rely on — rather than merely probing that values exist.
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from tests.constants import c


class TestsFlextLdifConstantsDataDriven:
    """Validate the public contract of the reusable test-constants namespace."""

    @pytest.mark.parametrize(
        ("constant_value", "expected_server_type"),
        [
            (c.Tests.AD, c.Ldif.ServerTypes.AD.value),
            (c.Tests.APACHE, c.Ldif.ServerTypes.APACHE.value),
            (c.Tests.DS389, c.Ldif.ServerTypes.DS389.value),
            (c.Tests.NOVELL, c.Ldif.ServerTypes.NOVELL.value),
            (c.Tests.OPENLDAP1, c.Ldif.ServerTypes.OPENLDAP1.value),
            (c.Tests.TIVOLI, c.Ldif.ServerTypes.IBM_TIVOLI.value),
        ],
    )
    def test_server_type_constants_expose_canonical_enum_values(
        self,
        constant_value: str,
        expected_server_type: str,
    ) -> None:
        # Arrange / Act done in the parametrize table.
        # Assert the constant is exactly the canonical server-type token.
        tm.that(constant_value, eq=expected_server_type)

    def test_fixture_kinds_are_exactly_the_declared_kinds(self) -> None:
        expected: frozenset[str] = frozenset({
            c.Tests.SCHEMA,
            c.Tests.ACL,
            c.Tests.ENTRIES,
            c.Tests.INTEGRATION,
        })
        tm.that(c.Tests.FIXTURE_KINDS, eq=expected)

    def test_fixture_kind_servers_keys_match_fixture_kinds(self) -> None:
        keys: frozenset[str] = frozenset(c.Tests.FIXTURE_KIND_SERVERS.keys())
        tm.that(keys, eq=c.Tests.FIXTURE_KINDS)

    def test_common_fixture_servers_are_a_subset_of_schema_servers(self) -> None:
        common: frozenset[str] = frozenset(c.Tests.FIXTURE_SERVERS_COMMON)
        schema: frozenset[str] = frozenset(c.Tests.FIXTURE_SERVERS_SCHEMA)
        tm.that(common.issubset(schema), eq=True)

    def test_rfc_belongs_to_schema_servers_only(self) -> None:
        tm.that(c.Tests.RFC in c.Tests.FIXTURE_SERVERS_SCHEMA, eq=True)
        tm.that(c.Tests.RFC in c.Tests.FIXTURE_SERVERS_COMMON, eq=False)

    @pytest.mark.parametrize(
        ("name_constant", "expected_attribute"),
        [
            (c.Tests.NAME_UID, "uid"),
            (c.Tests.NAME_MEMBER, "member"),
            (c.Tests.NAME_GROUP_OF_NAMES, "groupOfNames"),
            (c.Tests.NAME_ACI, "aci"),
            (c.Tests.NAME_ORCLACI, "orclaci"),
        ],
    )
    def test_ldap_name_constants_expose_canonical_attribute_names(
        self,
        name_constant: str,
        expected_attribute: str,
    ) -> None:
        tm.that(name_constant, eq=expected_attribute)

    def test_boolean_rfc_to_oid_maps_true_and_false_to_bits(self) -> None:
        tm.that(c.Tests.BOOLEAN_RFC_TO_OID[c.Tests.BOOLEAN_TRUE], eq="1")
        tm.that(c.Tests.BOOLEAN_RFC_TO_OID[c.Tests.BOOLEAN_FALSE], eq="0")

    @pytest.mark.parametrize("rfc_value", ["TRUE", "FALSE"])
    def test_boolean_oid_and_rfc_maps_are_mutual_inverses(
        self,
        rfc_value: str,
    ) -> None:
        oid_value: str = c.Tests.BOOLEAN_RFC_TO_OID[rfc_value]
        tm.that(c.Tests.BOOLEAN_OID_TO_RFC[oid_value], eq=rfc_value)

    @pytest.mark.parametrize(
        ("content", "expected_dn_prefix"),
        [
            (c.Tests.EDGE_CASE_UNICODE_LDIF, "dn: cn=José"),
            (c.Tests.EDGE_CASE_DEEP_DN_LDIF, "dn: cn=level1"),
            (c.Tests.EDGE_CASE_LARGE_MULTIVALUE_LDIF, "dn: cn=test"),
        ],
    )
    def test_edge_case_ldif_constants_are_well_formed_records(
        self,
        content: str,
        expected_dn_prefix: str,
    ) -> None:
        # A valid single LDIF record starts with its DN line and terminates
        # with a blank-line record separator.
        tm.that(content.startswith(expected_dn_prefix), eq=True)
        tm.that(content.endswith("\n\n"), eq=True)

    def test_non_ascii_regex_flags_unicode_but_not_pure_ascii_fixture(self) -> None:
        unicode_hit = c.Tests.EDGE_CASE_NON_ASCII_REGEX.search(
            c.Tests.EDGE_CASE_UNICODE_LDIF,
        )
        ascii_hit = c.Tests.EDGE_CASE_NON_ASCII_REGEX.search(
            c.Tests.EDGE_CASE_DEEP_DN_LDIF,
        )
        tm.that(unicode_hit is not None, eq=True)
        tm.that(ascii_hit is None, eq=True)

    def test_large_multivalue_fixture_has_expected_member_cardinality(self) -> None:
        member_count: int = c.Tests.EDGE_CASE_LARGE_MULTIVALUE_LDIF.count("member:")
        # The inline fixture carries exactly five members, below the
        # generated-fixture threshold used for on-disk large cases.
        tm.that(member_count, eq=5)
        tm.that(member_count < c.Tests.EDGE_CASE_MIN_MULTIVALUE_COUNT, eq=True)
