"""Tests for 389 Directory Server (DS389) LDIF servers handling.

This module tests the FlextLdifServersDs389 implementation for handling 389
Directory Server-specific attributes, object classes, and entries in LDIF format.
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldif import FlextLdifServersDs389
from tests import c, m, u


def _schema_server() -> FlextLdifServersDs389.Schema:
    """Real DS389 schema server (no mocks)."""
    server = FlextLdifServersDs389().schema_server
    assert isinstance(server, FlextLdifServersDs389.Schema)
    return server


class TestsTestFlextLdifDs389Servers:
    """Test ldif DS389 server servers."""

    @pytest.mark.parametrize("test_case", c.Tests.DS389_ATTRIBUTE_TEST_CASES)
    def test_schema_attribute_can_handle(
        self, test_case: m.Tests.AttributeTestCase
    ) -> None:
        """Test attribute detection for various scenarios."""
        tm.that(
            _schema_server().can_handle_attribute(test_case.attr_definition),
            eq=test_case.expected_can_handle,
        )

    def test_parse_attribute_success(self) -> None:
        """Test parsing DS389 attribute definition."""
        attr_def = "( 2.16.840.1.113730.3.1.1 NAME 'nsslapd-suffix' DESC 'Directory suffix' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )"
        u.Tests.assert_server_schema_parse_and_properties(
            _schema_server(),
            attr_def,
            expected_oid="2.16.840.1.113730.3.1.1",
            expected_name="nsslapd-suffix",
            expected_desc="Directory suffix",
            expected_syntax="1.3.6.1.4.1.1466.115.121.1.12",
            expected_single_value=True,
        )

    def test_parse_attribute_with_syntax_length(self) -> None:
        """Test parsing attribute with syntax length specification."""
        attr_def = "( 2.16.840.1.113730.3.1.2 NAME 'nsslapd-database' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        u.Tests.assert_server_schema_parse_and_properties(
            _schema_server(),
            attr_def,
            expected_syntax="1.3.6.1.4.1.1466.115.121.1.15",
            expected_length=256,
        )

    def test_parse_attribute_missing_oid(self) -> None:
        """Test parsing attribute without OID fails."""
        tm.fail(
            _schema_server().parse_input(
                "NAME 'nsslapd-port' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27"
            ),
            has="missing an OID",
        )

    @pytest.mark.parametrize("test_case", c.Tests.DS389_OBJECTCLASS_TEST_CASES)
    def test_schema_objectclass_can_handle(
        self, test_case: m.Tests.ObjectClassTestCase
    ) -> None:
        """Test objectClass detection for various scenarios."""
        tm.that(
            _schema_server().can_handle_objectclass(test_case.oc_definition),
            eq=test_case.expected_can_handle,
        )

    def test_parse_objectclass_structural(self) -> None:
        """Test parsing STRUCTURAL objectClass."""
        oc_def = "( 2.16.840.1.113730.3.2.1 NAME 'nscontainer' DESC 'Container class' SUP top STRUCTURAL MUST ( cn ) MAY ( nsslapd-port ) )"
        u.Tests.assert_server_schema_parse_and_properties(
            _schema_server(),
            oc_def,
            expected_oid="2.16.840.1.113730.3.2.1",
            expected_name="nscontainer",
            expected_kind="STRUCTURAL",
            expected_sup="top",
            expected_must=["cn"],
            expected_may=["nsslapd-port"],
        )

    def test_parse_objectclass_auxiliary(self) -> None:
        """Test parsing AUXILIARY objectClass."""
        oc_def = "( 2.16.840.1.113730.3.2.2 NAME 'nsds5replica' AUXILIARY MAY ( nsds5ReplicaId $ nsds5ReplicaRoot ) )"
        u.Tests.assert_server_schema_parse_and_properties(
            _schema_server(), oc_def, expected_kind="AUXILIARY"
        )

    def test_parse_objectclass_abstract(self) -> None:
        """Test parsing ABSTRACT objectClass."""
        oc_def = "( 2.16.840.1.113730.3.2.3 NAME 'nsds5base' ABSTRACT )"
        result = _schema_server().parse_input(oc_def)
        oc_data = tm.ok(result)
        assert isinstance(oc_data, m.Ldif.SchemaObjectClass)
        tm.that(oc_data.kind, eq="ABSTRACT")

    def test_parse_objectclass_missing_oid(self) -> None:
        """Test parsing objectClass without OID fails."""
        tm.fail(
            _schema_server().parse_input("NAME 'nscontainer' SUP top STRUCTURAL"),
            has="missing an OID",
        )

    def test_write_objectclass_to_rfc(self) -> None:
        """Test writing objectClass to RFC string format."""
        oc_data = m.Ldif.SchemaObjectClass(
            oid="2.16.840.1.113730.3.2.1",
            name="nscontainer",
            kind="STRUCTURAL",
            sup="top",
            must=["cn"],
            may=["nsslapd-port"],
        )
        oc_str = tm.ok(_schema_server().write(oc_data))
        tm.that(oc_str, has=["2.16.840.1.113730.3.2.1", "nscontainer", "STRUCTURAL"])

    @pytest.mark.parametrize("test_case", c.Tests.DS389_ENTRY_TEST_CASES)
    def test_entry_can_handle(self, test_case: m.Tests.EntryTestCase) -> None:
        """Test entry detection for various scenarios."""
        entry_server = FlextLdifServersDs389().entry_server
        tm.that(entry_server, is_=FlextLdifServersDs389.Entry)
        tm.that(
            entry_server.can_handle(test_case.entry_dn, test_case.attributes),
            eq=test_case.expected_can_handle,
        )
