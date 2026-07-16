"""Behavioral tests for the 389 Directory Server (DS389) LDIF server contract.

Every test exercises the OBSERVABLE public contract of ``FlextLdifServersDs389``
(the ``schema_server`` / ``entry_server`` / ``acl_server`` facades and their
``can_handle*`` / specialized ``parse_*`` / ``write`` methods). No private
attribute or method is touched, and the real server implementations are used
end-to-end without mocking the unit under test.
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldif.servers.ds389 import FlextLdifServersDs389
from tests import m, p, t, u


class TestsFlextLdifDs389Servers:
    """Public-contract behavior of the DS389 LDIF server facades."""

    @staticmethod
    def _schema_server() -> p.Ldif.SchemaServer:
        """Return the real DS389 schema server via the public facade."""
        server = FlextLdifServersDs389().schema_server
        tm.that(server, is_=FlextLdifServersDs389.Schema)
        return server

    # ------------------------------------------------------------------
    # Attribute detection + parsing
    # ------------------------------------------------------------------

    # mro-0ftd.3.6: consume modeled cases from their canonical facade.
    @pytest.mark.parametrize("test_case", m.Tests.DS389_ATTRIBUTE_TEST_CASES)
    def test_can_handle_attribute_matches_expected(
        self,
        test_case: m.Tests.AttributeTestCase,
    ) -> None:
        """can_handle_attribute reflects DS389 ownership per case table."""
        tm.that(
            self._schema_server().can_handle_attribute(test_case.attr_definition),
            eq=test_case.expected_can_handle,
        )

    def test_can_handle_attribute_is_idempotent(self) -> None:
        """Repeated detection of the same definition yields a stable verdict."""
        server = self._schema_server()
        definition = (
            "( 2.16.840.1.113730.3.1.1 NAME 'nsslapd-suffix' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )"
        )
        first = server.can_handle_attribute(definition)
        second = server.can_handle_attribute(definition)
        tm.that(first, eq=True)
        tm.that(second, eq=first)

    def test_parse_attribute_exposes_public_properties(self) -> None:
        """Parsing an attribute surfaces OID/name/desc/syntax/single-value."""
        attr_def = (
            "( 2.16.840.1.113730.3.1.1 NAME 'nsslapd-suffix' "
            "DESC 'Directory suffix' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )"
        )
        u.Tests.assert_server_schema_parse_and_properties(
            self._schema_server(),
            attr_def,
            expected_oid="2.16.840.1.113730.3.1.1",
            expected_name="nsslapd-suffix",
            expected_desc="Directory suffix",
            expected_syntax="1.3.6.1.4.1.1466.115.121.1.12",
            expected_single_value=True,
        )

    def test_parse_attribute_preserves_syntax_length(self) -> None:
        """Syntax length specification is retained on the parsed attribute."""
        attr_def = (
            "( 2.16.840.1.113730.3.1.2 NAME 'nsslapd-database' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        )
        u.Tests.assert_server_schema_parse_and_properties(
            self._schema_server(),
            attr_def,
            expected_syntax="1.3.6.1.4.1.1466.115.121.1.15",
            expected_length=256,
        )

    def test_parse_attribute_without_oid_fails_with_message(self) -> None:
        """A definition missing its OID yields a failed r[T] with a reason."""
        tm.fail(
            self._schema_server().parse_attribute(
                "NAME 'nsslapd-port' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27",
            ),
            has="missing an OID",
        )

    # ------------------------------------------------------------------
    # objectClass detection + parsing + writing
    # ------------------------------------------------------------------

    @pytest.mark.parametrize("test_case", m.Tests.DS389_OBJECTCLASS_TEST_CASES)
    def test_can_handle_objectclass_matches_expected(
        self,
        test_case: m.Tests.ObjectClassTestCase,
    ) -> None:
        """can_handle_objectclass reflects DS389 ownership per case table."""
        tm.that(
            self._schema_server().can_handle_objectclass(test_case.oc_definition),
            eq=test_case.expected_can_handle,
        )

    def test_parse_structural_objectclass_exposes_hierarchy(self) -> None:
        """STRUCTURAL objectClass parse surfaces kind/sup/must/may."""
        oc_def = (
            "( 2.16.840.1.113730.3.2.1 NAME 'nscontainer' "
            "DESC 'Container class' SUP top STRUCTURAL "
            "MUST ( cn ) MAY ( nsslapd-port ) )"
        )
        u.Tests.assert_server_schema_parse_and_properties(
            self._schema_server(),
            oc_def,
            expected_oid="2.16.840.1.113730.3.2.1",
            expected_name="nscontainer",
            expected_kind="STRUCTURAL",
            expected_sup="top",
            expected_must=["cn"],
            expected_may=["nsslapd-port"],
        )

    def test_parse_auxiliary_objectclass_reports_kind(self) -> None:
        """AUXILIARY objectClass parse reports the AUXILIARY kind."""
        oc_def = (
            "( 2.16.840.1.113730.3.2.2 NAME 'nsds5replica' AUXILIARY "
            "MAY ( nsds5ReplicaId $ nsds5ReplicaRoot ) )"
        )
        u.Tests.assert_server_schema_parse_and_properties(
            self._schema_server(),
            oc_def,
            expected_kind="AUXILIARY",
        )

    def test_parse_abstract_objectclass_reports_kind(self) -> None:
        """ABSTRACT objectClass parse yields a model reporting ABSTRACT kind."""
        parse_result = self._schema_server().parse_objectclass(
            "( 2.16.840.1.113730.3.2.3 NAME 'nsds5base' ABSTRACT )",
        )
        tm.ok(parse_result)
        # mro-0ftd.3.6.1: preserve the SchemaObjectClass Result parameter.
        oc_data = parse_result.unwrap()
        tm.that(oc_data, is_=m.Ldif.SchemaObjectClass)
        if not isinstance(oc_data, m.Ldif.SchemaObjectClass):
            msg = "DS389 schema parser did not return an objectClass model"
            raise AssertionError(msg)
        tm.that(oc_data.kind, eq="ABSTRACT")

    def test_parse_objectclass_without_oid_fails_with_message(self) -> None:
        """A definition missing its OID yields a failed r[T] with a reason."""
        tm.fail(
            self._schema_server().parse_objectclass(
                "NAME 'nscontainer' SUP top STRUCTURAL",
            ),
            has="missing an OID",
        )

    def test_write_objectclass_renders_rfc_tokens(self) -> None:
        """Writing an objectClass emits its OID, name, and kind tokens."""
        oc_data = m.Ldif.SchemaObjectClass(
            oid="2.16.840.1.113730.3.2.1",
            name="nscontainer",
            kind="STRUCTURAL",
            sup="top",
            must=["cn"],
            may=["nsslapd-port"],
        )
        oc_str = tm.ok(self._schema_server().write(oc_data))
        tm.that(
            oc_str,
            has=["2.16.840.1.113730.3.2.1", "nscontainer", "STRUCTURAL"],
        )

    def test_parsed_objectclass_round_trips_through_write(self) -> None:
        """Parse then write preserves the identity tokens (round-trip invariant)."""
        oc_def = (
            "( 2.16.840.1.113730.3.2.1 NAME 'nscontainer' "
            "SUP top STRUCTURAL MUST ( cn ) )"
        )
        server = self._schema_server()
        parse_result = server.parse_objectclass(oc_def)
        tm.ok(parse_result)
        parsed = parse_result.unwrap()
        tm.that(parsed, is_=m.Ldif.SchemaObjectClass)
        write_result = server.write(parsed)
        tm.ok(write_result)
        rendered = write_result.unwrap()
        tm.that(rendered, has=["2.16.840.1.113730.3.2.1", "nscontainer"])

    # ------------------------------------------------------------------
    # Entry detection
    # ------------------------------------------------------------------

    @pytest.mark.parametrize("test_case", m.Tests.DS389_ENTRY_TEST_CASES)
    def test_entry_can_handle_matches_expected(
        self,
        test_case: m.Tests.EntryTestCase,
    ) -> None:
        """Entry.can_handle reflects DS389 ownership per case table."""
        entry_server = FlextLdifServersDs389().entry_server
        tm.that(entry_server, is_=FlextLdifServersDs389.Entry)
        tm.that(
            entry_server.can_handle(test_case.entry_dn, test_case.attributes),
            eq=test_case.expected_can_handle,
        )

    def test_entry_can_handle_rejects_empty_dn(self) -> None:
        """An empty DN with no DS389 markers is not claimed by the server."""
        entry_server = FlextLdifServersDs389().entry_server
        empty_attrs: t.MutableStrSequenceMapping = {}
        tm.that(entry_server.can_handle("", empty_attrs), eq=False)

    # ------------------------------------------------------------------
    # ACL detection
    # ------------------------------------------------------------------

    @pytest.mark.parametrize(
        ("acl_line", "expected"),
        [
            pytest.param('aci: (version 3.0) acl "x"', True, id="aci-prefix"),
            pytest.param('(version 3.0) acl "x"', True, id="version-prefix"),
            pytest.param("cn: some value", False, id="non-acl-attribute"),
            pytest.param("   ", False, id="blank"),
        ],
    )
    def test_acl_can_handle_matches_expected(
        self,
        acl_line: str,
        *,
        expected: bool,
    ) -> None:
        """Acl.can_handle claims aci/version lines and rejects other input."""
        acl_server = FlextLdifServersDs389().acl_server
        tm.that(acl_server, is_=FlextLdifServersDs389.Acl)
        tm.that(acl_server.can_handle_acl(acl_line), eq=expected)
