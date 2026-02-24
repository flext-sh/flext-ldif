"""Tests for OpenLDAP 1.x server LDIF quirks handling.

This module tests the OpenLDAP 1.x implementation for handling OpenLDAP 1.x-specific
attributes, object classes, and entries in LDIF format.
"""

from __future__ import annotations

from flext_ldif.models import m
from flext_ldif.servers.openldap1 import FlextLdifServersOpenldap1
from tests import RfcTestHelpers, TestDeduplicationHelpers, s


class TestsTestFlextLdifOpenldap1Quirks(s):
    """Test FlextLdif OpenLDAP 1.x server quirks."""

    def test_server_initialization(self) -> None:
        """Test OpenLDAP 1.x schema quirk initialization."""
        server = FlextLdifServersOpenldap1()
        assert server.server_type == "openldap1"
        assert server.priority == 10

    def test_schema_quirk_initialization(self) -> None:
        """Test schema quirk is initialized."""
        server = FlextLdifServersOpenldap1()
        schema_quirk = server.schema_quirk
        assert isinstance(schema_quirk, FlextLdifServersOpenldap1.Schema)

    def test_acl_quirk_initialization(self) -> None:
        """Test ACL quirk is initialized."""
        server = FlextLdifServersOpenldap1()
        acl_quirk = server.acl_quirk
        assert isinstance(acl_quirk, FlextLdifServersOpenldap1.Acl)

    def test_entry_quirk_initialization(self) -> None:
        """Test entry quirk is initialized."""
        server = FlextLdifServersOpenldap1()
        entry_quirk = server.entry_quirk
        assert isinstance(entry_quirk, FlextLdifServersOpenldap1.Entry)

    def test_schema_attribute_with_attributetype_prefix(self) -> None:
        """Test attribute detection with attributetype prefix."""
        quirk = FlextLdifServersOpenldap1.Schema()
        attr_def = "attributetype ( 1.2.3.4 NAME 'test' )"
        RfcTestHelpers.test_quirk_parse_success_and_unwrap(quirk, attr_def)
        assert quirk.can_handle_attribute(attr_def) is True

    def test_schema_attribute_rejects_olc(self) -> None:
        """Test attribute detection rejects olc prefix (OpenLDAP 2.x)."""
        quirk = FlextLdifServersOpenldap1.Schema()
        attr_def = "attributetype ( 1.2.3.4 NAME 'olcTest' )"
        RfcTestHelpers.test_quirk_parse_success_and_unwrap(quirk, attr_def)
        assert quirk.can_handle_attribute(attr_def) is False

    def test_parse_attribute_success(self) -> None:
        """Test successful attribute parsing."""
        quirk = FlextLdifServersOpenldap1.Schema()
        attr_def = "attributetype ( 1.2.3.4 NAME 'testAttr' DESC 'Test attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 EQUALITY caseIgnoreMatch SINGLE-VALUE )"
        RfcTestHelpers.test_schema_quirk_parse_and_assert(
            quirk,
            attr_def,
            expected_oid="1.2.3.4",
            expected_name="testAttr",
            expected_desc="Test attribute",
            expected_syntax="1.3.6.1.4.1.1466.115.121.1.15",
            expected_equality="caseIgnoreMatch",
            expected_single_value=True,
        )

    def test_parse_attribute_no_oid(self) -> None:
        """Test attribute parsing fails without OID."""
        quirk = FlextLdifServersOpenldap1.Schema()
        attr_def = "attributetype NAME 'testAttr'"
        result = quirk.parse(attr_def)
        assert result.is_failure
        assert result.error is not None
        assert "RFC attribute parsing failed: missing an OID" in result.error

    def test_schema_objectclass_with_objectclass_prefix(self) -> None:
        """Test objectClass detection with objectclass prefix."""
        quirk = FlextLdifServersOpenldap1.Schema()
        oc_def = "objectclass ( 1.2.3.4 NAME 'testClass' )"
        RfcTestHelpers.test_quirk_parse_success_and_unwrap(quirk, oc_def)
        assert quirk.can_handle_objectclass(oc_def) is True

    def test_schema_objectclass_rejects_olc(self) -> None:
        """Test objectClass detection rejects olc (OpenLDAP 2.x)."""
        quirk = FlextLdifServersOpenldap1.Schema()
        oc_def = "objectclass ( 1.2.3.4 NAME 'olcTestClass' )"
        RfcTestHelpers.test_quirk_parse_success_and_unwrap(quirk, oc_def)
        assert quirk.can_handle_objectclass(oc_def) is False

    def test_parse_objectclass_success(self) -> None:
        """Test successful objectClass parsing."""
        quirk = FlextLdifServersOpenldap1.Schema()
        oc_def = "objectclass ( 1.2.3.4 NAME 'testClass' DESC 'Test class' SUP top STRUCTURAL MUST ( cn $ sn ) MAY ( description ) )"
        oc_data = RfcTestHelpers.test_schema_quirk_parse_and_assert(
            quirk,
            oc_def,
            expected_oid="1.2.3.4",
            expected_name="testClass",
            expected_desc="Test class",
            expected_sup="top",
            expected_kind="STRUCTURAL",
            expected_must=["cn", "sn"],
            expected_may=["description"],
        )
        assert hasattr(oc_data, "name")

    def test_parse_objectclass_auxiliary(self) -> None:
        """Test parsing AUXILIARY objectClass."""
        quirk = FlextLdifServersOpenldap1.Schema()
        oc_def = "objectclass ( 1.2.3.5 NAME 'auxClass' AUXILIARY )"
        RfcTestHelpers.test_schema_quirk_parse_and_assert(
            quirk,
            oc_def,
            expected_kind="AUXILIARY",
        )

    def test_parse_objectclass_abstract(self) -> None:
        """Test parsing ABSTRACT objectClass."""
        quirk = FlextLdifServersOpenldap1.Schema()
        oc_def = "objectclass ( 1.2.3.6 NAME 'absClass' ABSTRACT )"
        RfcTestHelpers.test_schema_quirk_parse_and_assert(
            quirk,
            oc_def,
            expected_kind="ABSTRACT",
        )

    def test_parse_objectclass_no_oid(self) -> None:
        """Test objectClass parsing fails without OID."""
        quirk = FlextLdifServersOpenldap1.Schema()
        oc_def = "objectclass NAME 'testClass'"
        result = quirk.parse(oc_def)
        assert result.is_failure
        assert result.error is not None
        assert "RFC objectClass parsing failed: missing an OID" in result.error

    def test_write_attribute_to_rfc(self) -> None:
        """Test writing attribute to RFC string format with attributetype prefix."""
        quirk = FlextLdifServersOpenldap1.Schema()
        attr_data = m.Ldif.SchemaAttribute(
            oid="1.2.3.4",
            name="testAttr",
            desc="Test attribute",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            equality="caseIgnoreMatch",
            single_value=True,
        )
        TestDeduplicationHelpers.quirk_write_and_unwrap(
            quirk,
            attr_data,
            write_method="_write_attribute",
            must_contain=[
                "attributetype ( 1.2.3.4",
                "NAME 'testAttr'",
                "DESC 'Test attribute'",
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15",
                "EQUALITY caseIgnoreMatch",
                "SINGLE-VALUE",
                ")",
            ],
        )

    def test_write_objectclass_to_rfc(self) -> None:
        """Test writing objectClass to RFC string format with objectclass prefix."""
        quirk = FlextLdifServersOpenldap1.Schema()
        oc_data = m.Ldif.SchemaObjectClass(
            oid="1.2.3.4",
            name="testClass",
            desc="Test class",
            sup="top",
            kind="STRUCTURAL",
            must=["cn", "sn"],
            may=["description"],
        )
        TestDeduplicationHelpers.quirk_write_and_unwrap(
            quirk,
            oc_data,
            write_method="write_objectclass",
            must_contain=[
                "objectclass ( 1.2.3.4",
                "NAME 'testClass'",
                "SUP top",
                "STRUCTURAL",
                "MUST",
                "MAY",
            ],
        )

    def test_acl_can_handle_with_access_to(self) -> None:
        """Test ACL detection with 'access to' prefix."""
        openldap1_server = FlextLdifServersOpenldap1()
        acl = openldap1_server.Acl()
        acl_line = "access to attrs=userPassword by self write by * auth"
        parse_result = acl.parse(acl_line)
        assert parse_result.is_success, f"Failed to parse ACL: {parse_result.error}"
        parse_result.value
        assert acl.can_handle(acl_line) is True

    def test_acl_can_handle_negative(self) -> None:
        """Test ACL detection returns false for non-OpenLDAP 1.x ACL."""
        openldap1_server = FlextLdifServersOpenldap1()
        acl = openldap1_server.Acl()
        acl_line = "random text"
        parse_result = acl.parse(acl_line)
        if parse_result.is_success:
            parse_result.value
            assert acl.can_handle(acl_line) is False
        else:
            assert parse_result.is_success is False

    def test_acl_parse_success(self) -> None:
        """Test successful ACL parsing."""
        openldap1_server = FlextLdifServersOpenldap1()
        acl = openldap1_server.Acl()
        acl_line = "access to attrs=userPassword by self write by * read"
        result = acl.parse(acl_line)
        assert result.is_success
        acl_data = result.value
        assert isinstance(acl_data, m.Ldif.Acl)
        assert acl_data.target is not None
        assert acl_data.target.attributes == ["userPassword"]
        assert acl_data.subject is not None
        assert acl_data.subject.subject_value == "self"
        assert acl_data.permissions is not None
        assert acl_data.permissions.write is True

    def test_acl_parse_missing_to_clause(self) -> None:
        """Test ACL parsing fails without 'to' clause."""
        openldap1_server = FlextLdifServersOpenldap1()
        acl = openldap1_server.Acl()
        acl_line = "access by * read"
        result = acl.parse(acl_line)
        assert result.is_failure
        assert result.error is not None
        assert "missing 'to' clause" in result.error.lower()

    def test_entry_can_handle_traditional_dit(self) -> None:
        """Test entry detection for traditional DIT (no cn=config)."""
        openldap1_server = FlextLdifServersOpenldap1()
        entry = openldap1_server.Entry()
        dn = m.Ldif.DN(value="cn=test,dc=example,dc=com")
        attributes = m.Ldif.Attributes(
            attributes={"cn": ["test"], "objectclass": ["person"]},
        )
        m.Ldif.Entry(dn=dn, attributes=attributes)
        assert entry.can_handle(dn.value, attributes.attributes) is True

    def test_entry_rejects_config_dn(self) -> None:
        """Test entry detection rejects cn=config DNs (OpenLDAP 2.x)."""
        openldap1_server = FlextLdifServersOpenldap1()
        entry = openldap1_server.Entry()
        dn = m.Ldif.DN(value="cn=config")
        attributes = m.Ldif.Attributes(attributes={"cn": ["config"]})
        m.Ldif.Entry(dn=dn, attributes=attributes)
        assert entry.can_handle(dn.value, attributes.attributes) is False

    def test_entry_rejects_olc_attributes(self) -> None:
        """Test entry detection rejects olc* attributes (OpenLDAP 2.x)."""
        openldap1_server = FlextLdifServersOpenldap1()
        entry = openldap1_server.Entry()
        dn = m.Ldif.DN(value="cn=test,dc=example,dc=com")
        attributes = m.Ldif.Attributes(
            attributes={"olcDatabase": ["{1}mdb"]},
        )
        m.Ldif.Entry(dn=dn, attributes=attributes)
        assert entry.can_handle(dn.value, attributes.attributes) is False
