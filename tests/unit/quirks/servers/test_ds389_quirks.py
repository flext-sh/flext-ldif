"""Tests for 389 Directory Server (DS389) LDIF quirks handling.

This module tests the FlextLdifServersDs389 implementation for handling 389
Directory Server-specific attributes, t.NormalizedValue classes, and entries in LDIF format.
"""

from __future__ import annotations

import pytest
from flext_tests import tm
from tests import c, m

from flext_ldif import FlextLdifServersDs389


class TestsTestFlextLdifDs389Quirks:
    """Test ldif DS389 server quirks."""

    def test_server_initialization(self) -> None:
        """Test DS389 server initialization."""
        server = FlextLdifServersDs389()
        tm.that(server.server_type, eq="ds389")
        tm.that(server.priority, eq=30)

    def test_schema_quirk_initialization(self) -> None:
        """Test schema quirk is initialized."""
        server = FlextLdifServersDs389()
        schema_quirk = server.schema_quirk
        tm.that(schema_quirk, none=False)

    def test_acl_quirk_initialization(self) -> None:
        """Test ACL quirk is initialized."""
        server = FlextLdifServersDs389()
        acl_quirk = server.acl_quirk
        tm.that(acl_quirk, none=False)

    def test_entry_quirk_initialization(self) -> None:
        """Test entry quirk is initialized."""
        server = FlextLdifServersDs389()
        entry_quirk = server.entry_quirk
        tm.that(entry_quirk, none=False)

    @pytest.mark.parametrize("test_case", c.Ldif.TestCases.Ds389.ATTRIBUTE_TEST_CASES)
    def test_schema_attribute_can_handle(
        self, test_case: m.Ldif.Tests.AttributeTestCase
    ) -> None:
        """Test attribute detection for various scenarios."""
        server = FlextLdifServersDs389()
        schema_quirk = server.schema_quirk
        tm.that(schema_quirk, is_=FlextLdifServersDs389.Schema)
        result = schema_quirk.can_handle_attribute(test_case.attr_definition)
        tm.that(result is test_case.expected_can_handle, eq=True)

    def test_parse_attribute_success(self) -> None:
        """Test parsing DS389 attribute definition."""
        server = FlextLdifServersDs389()
        schema_quirk = server.schema_quirk
        tm.that(schema_quirk, is_=FlextLdifServersDs389.Schema)
        attr_def = "( 2.16.840.1.113730.3.1.1 NAME 'nsslapd-suffix' DESC 'Directory suffix' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )"
        c.Ldif.RfcTestHelpers.test_quirk_schema_parse_and_assert_properties(
            schema_quirk,
            attr_def,
            expected_oid="2.16.840.1.113730.3.1.1",
            expected_name="nsslapd-suffix",
            expected_desc="Directory suffix",
            expected_syntax="1.3.6.1.4.1.1466.115.121.1.12",
            expected_single_value=True,
        )

    def test_parse_attribute_with_syntax_length(self) -> None:
        """Test parsing attribute with syntax length specification."""
        server = FlextLdifServersDs389()
        schema_quirk = server.schema_quirk
        tm.that(schema_quirk, is_=FlextLdifServersDs389.Schema)
        attr_def = "( 2.16.840.1.113730.3.1.2 NAME 'nsslapd-database' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        c.Ldif.RfcTestHelpers.test_quirk_schema_parse_and_assert_properties(
            schema_quirk,
            attr_def,
            expected_syntax="1.3.6.1.4.1.1466.115.121.1.15",
            expected_length=256,
        )

    def test_parse_attribute_missing_oid(self) -> None:
        """Test parsing attribute without OID fails."""
        server = FlextLdifServersDs389()
        schema_quirk = server.schema_quirk
        tm.that(schema_quirk, is_=FlextLdifServersDs389.Schema)
        attr_def = "NAME 'nsslapd-port' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27"
        result = schema_quirk.parse_input(attr_def)
        tm.that(result.is_failure, eq=True)
        tm.that(result.error, none=False)
        if result.error is not None:
            tm.that(result.error, has="missing an OID")

    @pytest.mark.parametrize("test_case", c.Ldif.TestCases.Ds389.OBJECTCLASS_TEST_CASES)
    def test_schema_objectclass_can_handle(
        self,
        test_case: m.Ldif.Tests.ObjectClassTestCase,
    ) -> None:
        """Test objectClass detection for various scenarios."""
        server = FlextLdifServersDs389()
        schema_quirk = server.schema_quirk
        tm.that(schema_quirk, is_=FlextLdifServersDs389.Schema)
        result = schema_quirk.can_handle_objectclass(test_case.oc_definition)
        tm.that(result is test_case.expected_can_handle, eq=True)

    def test_parse_objectclass_structural(self) -> None:
        """Test parsing STRUCTURAL objectClass."""
        server = FlextLdifServersDs389()
        schema_quirk = server.schema_quirk
        tm.that(schema_quirk, is_=FlextLdifServersDs389.Schema)
        oc_def = "( 2.16.840.1.113730.3.2.1 NAME 'nscontainer' DESC 'Container class' SUP top STRUCTURAL MUST ( cn ) MAY ( nsslapd-port ) )"
        c.Ldif.RfcTestHelpers.test_quirk_schema_parse_and_assert_properties(
            schema_quirk,
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
        server = FlextLdifServersDs389()
        schema_quirk = server.schema_quirk
        tm.that(schema_quirk, is_=FlextLdifServersDs389.Schema)
        oc_def = "( 2.16.840.1.113730.3.2.2 NAME 'nsds5replica' AUXILIARY MAY ( nsds5ReplicaId $ nsds5ReplicaRoot ) )"
        c.Ldif.RfcTestHelpers.test_quirk_schema_parse_and_assert_properties(
            schema_quirk,
            oc_def,
            expected_kind="AUXILIARY",
        )

    def test_parse_objectclass_abstract(self) -> None:
        """Test parsing ABSTRACT objectClass."""
        server = FlextLdifServersDs389()
        schema_quirk = server.schema_quirk
        tm.that(schema_quirk, is_=FlextLdifServersDs389.Schema)
        oc_def = "( 2.16.840.1.113730.3.2.3 NAME 'nsds5base' ABSTRACT )"
        result = schema_quirk.parse_input(oc_def)
        tm.that(result.is_success, eq=True)
        oc_data = result.value
        assert isinstance(oc_data, m.Ldif.SchemaObjectClass)
        tm.that(oc_data.kind, eq="ABSTRACT")

    def test_parse_objectclass_missing_oid(self) -> None:
        """Test parsing objectClass without OID fails."""
        server = FlextLdifServersDs389()
        schema_quirk = server.schema_quirk
        tm.that(schema_quirk, is_=FlextLdifServersDs389.Schema)
        oc_def = "NAME 'nscontainer' SUP top STRUCTURAL"
        result = schema_quirk.parse_input(oc_def)
        tm.that(result.is_failure, eq=True)
        tm.that(result.error, none=False)
        if result.error is not None:
            tm.that(result.error, has="missing an OID")

    def test_write_objectclass_to_rfc(self) -> None:
        """Test writing objectClass to RFC string format."""
        server = FlextLdifServersDs389()
        schema_quirk = server.schema_quirk
        tm.that(schema_quirk, is_=FlextLdifServersDs389.Schema)
        oc_data = m.Ldif.SchemaObjectClass(
            oid="2.16.840.1.113730.3.2.1",
            name="nscontainer",
            kind="STRUCTURAL",
            sup="top",
            must=["cn"],
            may=["nsslapd-port"],
        )
        result = schema_quirk.write(oc_data)
        tm.that(result.is_success, eq=True)
        oc_str = result.value
        tm.that(oc_str, has="2.16.840.1.113730.3.2.1")
        tm.that(oc_str, has="nscontainer")
        tm.that(oc_str, has="STRUCTURAL")

    @pytest.mark.parametrize("test_case", c.Ldif.TestCases.Ds389.ENTRY_TEST_CASES)
    def test_entry_can_handle(self, test_case: m.Ldif.Tests.EntryTestCase) -> None:
        """Test entry detection for various scenarios."""
        server = FlextLdifServersDs389()
        entry_quirk = server.entry_quirk
        tm.that(entry_quirk, is_=FlextLdifServersDs389.Entry)
        result = entry_quirk.can_handle(test_case.entry_dn, test_case.attributes)
        tm.that(result is test_case.expected_can_handle, eq=True)
