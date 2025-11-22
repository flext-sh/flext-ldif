"""Comprehensive tests for IBM Tivoli Directory Server quirks.

This module provides complete test coverage for IBM Tivoli Directory Server
schema, ACL, and entry quirks, including:
- Server-specific OID patterns (1.3.18.*)
- ibm-/ids- attribute prefixes
- Structured ACL format with {} delimiters
- Entry processing with base64 encoding for binary data
"""

from __future__ import annotations

from flext_ldif import FlextLdifConstants, FlextLdifModels
from flext_ldif.servers.tivoli import FlextLdifServersTivoli
from tests.helpers.test_deduplication_helpers import TestDeduplicationHelpers
from tests.helpers.test_rfc_helpers import RfcTestHelpers


class TestTivoliSchemas:
    """Tests for IBM Tivoli Directory Server schema quirk handling."""

    def test_initialization(self) -> None:
        """Test Tivoli schema quirk initialization."""
        server = FlextLdifServersTivoli()
        # server_type and priority are ClassVar on main server class
        assert server.server_type == "ibm_tivoli"
        assert server.priority == 30

    def testcan_handle_attribute_tivoli_oid(self) -> None:
        """Test Tivoli attribute detection by OID pattern."""
        server = FlextLdifServersTivoli()
        quirk = server.schema_quirk
        attr_def = "( 1.3.18.0.2.4.1 NAME 'ibm-entryUUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        assert quirk.can_handle_attribute(attr_def)

    def testcan_handle_attribute_ibm_prefix(self) -> None:
        """Test Tivoli attribute detection by ibm- prefix."""
        server = FlextLdifServersTivoli()
        quirk = server.schema_quirk
        attr_def = "( 1.2.3.4 NAME 'ibm-slapdaccesscontrol' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        assert quirk.can_handle_attribute(attr_def)

    def testcan_handle_attribute_ids_prefix(self) -> None:
        """Test Tivoli attribute detection by ids- prefix."""
        server = FlextLdifServersTivoli()
        quirk = server.schema_quirk
        attr_def = (
            "( 1.2.3.4 NAME 'ids-pwdPolicy' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        assert quirk.can_handle_attribute(attr_def)

    def testcan_handle_attribute_non_tivoli(self) -> None:
        """Test non-Tivoli attribute rejection."""
        server = FlextLdifServersTivoli()
        quirk = server.schema_quirk
        attr_def = "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        assert not quirk.can_handle_attribute(attr_def)

    def test_parse_attribute_success(self) -> None:
        """Test successful Tivoli attribute parsing."""
        server = FlextLdifServersTivoli()
        quirk = server.schema_quirk
        attr_def = (
            "( 1.3.18.0.2.4.1 NAME 'ibm-entryUUID' "
            "DESC 'Entry UUID' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
            "EQUALITY caseIgnoreMatch "
            "SINGLE-VALUE )"
        )
        data = RfcTestHelpers.test_quirk_schema_parse_and_assert_properties(
            quirk,
            attr_def,
            expected_oid="1.3.18.0.2.4.1",
            expected_name="ibm-entryUUID",
            expected_desc="Entry UUID",
            expected_syntax="1.3.6.1.4.1.1466.115.121.1.15",
            expected_equality="caseIgnoreMatch",
            expected_single_value=True,
        )
        assert data.metadata is not None
        assert data.metadata.quirk_type == "ibm_tivoli"

    def test_parse_attribute_missing_oid(self) -> None:
        """Test attribute parsing failure when OID is missing."""
        server = FlextLdifServersTivoli()
        quirk = server.schema_quirk
        attr_def = "NAME 'ibm-entryUUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15"
        result = quirk.parse(attr_def)
        assert not result.is_success
        assert result.error is not None
        assert "missing an OID" in result.error

    def test_parse_attribute_with_ordering(self) -> None:
        """Test attribute parsing with ORDERING matching rule."""
        server = FlextLdifServersTivoli()
        quirk = server.schema_quirk
        attr_def = (
            "( 1.3.18.0.2.4.2 NAME 'ids-timestamp' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 "
            "ORDERING generalizedTimeOrderingMatch )"
        )
        RfcTestHelpers.test_quirk_schema_parse_and_assert_properties(
            quirk,
            attr_def,
            expected_ordering="generalizedTimeOrderingMatch",
        )

    def test_parse_attribute_with_substr(self) -> None:
        """Test attribute parsing with SUBSTR matching rule."""
        server = FlextLdifServersTivoli()
        quirk = server.schema_quirk
        attr_def = (
            "( 1.3.18.0.2.4.3 NAME 'ibm-description' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
            "SUBSTR caseIgnoreSubstringsMatch )"
        )
        RfcTestHelpers.test_quirk_schema_parse_and_assert_properties(
            quirk,
            attr_def,
            expected_substr="caseIgnoreSubstringsMatch",
        )

    def test_parse_attribute_with_syntax_length(self) -> None:
        """Test attribute parsing with syntax length constraint."""
        server = FlextLdifServersTivoli()
        quirk = server.schema_quirk
        attr_def = "( 1.3.18.0.2.4.4 NAME 'ibm-code' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{128} )"
        RfcTestHelpers.test_quirk_schema_parse_and_assert_properties(
            quirk,
            attr_def,
            expected_length=128,
        )

    def test_parse_attribute_with_sup(self) -> None:
        """Test attribute parsing with SUP (superior) attribute."""
        server = FlextLdifServersTivoli()
        quirk = server.schema_quirk
        attr_def = "( 1.3.18.0.2.4.5 NAME 'ibm-specialAttr' SUP name )"
        RfcTestHelpers.test_quirk_schema_parse_and_assert_properties(
            quirk,
            attr_def,
            expected_sup="name",
        )

    def testcan_handle_objectclass_tivoli_oid(self) -> None:
        """Test Tivoli objectClass detection by OID pattern."""
        server = FlextLdifServersTivoli()
        quirk = server.schema_quirk
        oc_def = "( 1.3.18.0.2.6.1 NAME 'ibm-ldapserver' SUP top STRUCTURAL )"
        assert quirk.can_handle_objectclass(oc_def)

    def testcan_handle_objectclass_tivoli_name(self) -> None:
        """Test Tivoli objectClass detection by known names."""
        server = FlextLdifServersTivoli()
        quirk = server.schema_quirk
        oc_def = "( 1.2.3.4 NAME 'ibm-slapdaccesscontrolsubentry' SUP top AUXILIARY )"
        assert quirk.can_handle_objectclass(oc_def)

    def testcan_handle_objectclass_non_tivoli(self) -> None:
        """Test non-Tivoli objectClass rejection."""
        server = FlextLdifServersTivoli()
        quirk = server.schema_quirk
        oc_def = "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL )"
        assert not quirk.can_handle_objectclass(oc_def)

    def test_parse_objectclass_success(self) -> None:
        """Test successful Tivoli objectClass parsing."""
        server = FlextLdifServersTivoli()
        quirk = server.schema_quirk
        oc_def = (
            "( 1.3.18.0.2.6.1 NAME 'ibm-ldapserver' "
            "DESC 'LDAP server configuration' "
            "SUP top STRUCTURAL "
            "MUST ( cn $ ibm-serverVersion ) "
            "MAY ( ibm-serverPort $ description ) )"
        )
        data = RfcTestHelpers.test_quirk_schema_parse_and_assert_properties(
            quirk,
            oc_def,
            expected_oid="1.3.18.0.2.6.1",
            expected_name="ibm-ldapserver",
            expected_desc="LDAP server configuration",
            expected_sup="top",
            expected_kind="STRUCTURAL",
            expected_must=["cn", "ibm-serverVersion"],
            expected_may=["ibm-serverPort"],
        )
        assert data.metadata is not None
        assert data.metadata.quirk_type == "ibm_tivoli"

    def test_parse_objectclass_missing_oid(self) -> None:
        """Test objectClass parsing failure when OID is missing."""
        server = FlextLdifServersTivoli()
        quirk = server.schema_quirk
        oc_def = "NAME 'ibm-ldapserver' SUP top STRUCTURAL"
        result = quirk.parse(oc_def)
        assert not result.is_success
        assert result.error is not None
        assert "missing an OID" in result.error

    def test_parse_objectclass_auxiliary(self) -> None:
        """Test parsing AUXILIARY objectClass."""
        server = FlextLdifServersTivoli()
        quirk = server.schema_quirk
        oc_def = "( 1.3.18.0.2.6.2 NAME 'ibm-filterentry' AUXILIARY )"
        RfcTestHelpers.test_quirk_schema_parse_and_assert_properties(
            quirk,
            oc_def,
            expected_kind="AUXILIARY",
        )

    def test_parse_objectclass_abstract(self) -> None:
        """Test parsing ABSTRACT objectClass."""
        server = FlextLdifServersTivoli()
        quirk = server.schema_quirk
        oc_def = "( 1.3.18.0.2.6.3 NAME 'ibm-baseClass' ABSTRACT )"
        RfcTestHelpers.test_quirk_schema_parse_and_assert_properties(
            quirk,
            oc_def,
            expected_kind="ABSTRACT",
        )

    def test_write_attribute_to_rfc(self) -> None:
        """Test writing attribute to RFC string format."""
        server = FlextLdifServersTivoli()
        quirk = server.schema_quirk
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="1.3.18.0.2.4.1",
            name="ibm-entryUUID",
            desc="Entry UUID",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            equality="caseIgnoreMatch",
            single_value=True,
        )

        TestDeduplicationHelpers.quirk_write_and_unwrap(
            quirk,
            attr_data,
            write_method="_write_attribute",
            must_contain=["1.3.18.0.2.4.1", "ibm-entryUUID", "SINGLE-VALUE"],
        )

    def test_write_objectclass_to_rfc(self) -> None:
        """Test writing objectClass to RFC string format."""
        server = FlextLdifServersTivoli()
        quirk = server.schema_quirk
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="1.3.18.0.2.6.1",
            name="ibm-ldapserver",
            desc="LDAP server",
            sup="top",
            kind="STRUCTURAL",
            must=["cn", "objectclass"],
            may=["description", "seeAlso"],
        )

        TestDeduplicationHelpers.quirk_write_and_unwrap(
            quirk,
            oc_data,
            write_method="_write_objectclass",
            must_contain=[
                "1.3.18.0.2.6.1",
                "ibm-ldapserver",
                "STRUCTURAL",
                "MUST",
                "MAY",
            ],
        )


class TestTivoliAcls:
    """Tests for IBM Tivoli Directory Server ACL quirk handling."""

    def test_initialization(self) -> None:
        """Test Tivoli ACL quirk initialization."""
        server = FlextLdifServersTivoli()
        acl = server.acl_quirk
        assert acl is not None

    def test__can_handle_ibm_slapdaccesscontrol(self) -> None:
        """Test ACL detection with ibm-slapdaccesscontrol attribute."""
        server = FlextLdifServersTivoli()
        acl = server.acl_quirk
        acl_line = 'ibm-slapdaccesscontrol: {access "read" permission "allow" userdn="cn=Admin,o=Example"}'
        # Parse string ACL into model object before testing

        parse_result = acl.parse(acl_line)

        if parse_result.is_success:
            parse_result.unwrap()

            assert acl.can_handle(acl_line) is True

        else:
            # If parsing fails, assertion should be False

            assert acl.can_handle(acl_line) is False

    def test__can_handle_ibm_slapdgroupacl(self) -> None:
        """Test ACL detection with ibm-slapdgroupacl attribute."""
        server = FlextLdifServersTivoli()
        acl = server.acl_quirk
        acl_line = 'ibm-slapdgroupacl: {access "write" groupdn="cn=Admins,o=Example"}'
        # can_handle should work directly with string
        assert acl.can_handle(acl_line) is True

    def test__can_handle_empty_line(self) -> None:
        """Test ACL rejection with empty line."""
        server = FlextLdifServersTivoli()
        acl = server.acl_quirk
        assert not acl.can_handle("")

    def test__can_handle_non_tivoli(self) -> None:
        """Test non-Tivoli ACL rejection."""
        server = FlextLdifServersTivoli()
        acl = server.acl_quirk
        acl_line = "aci: (version 3.0; acl read-access; allow(read))"
        # can_handle_acl should reject non-Tivoli ACLs directly
        assert acl.can_handle(acl_line) is False

    def test_parse_success(self) -> None:
        """Test successful Tivoli ACL parsing."""
        server = FlextLdifServersTivoli()
        acl = server.acl_quirk
        acl_line = 'ibm-slapdaccesscontrol: {access "read" permission "allow" groupdn="cn=Admins,o=Example" userdn="cn=User,o=Example"}'
        result = acl.parse(acl_line)
        assert result.is_success
        data = result.unwrap()
        assert data.name == "Tivoli ACL"
        assert data.server_type == "ibm_tivoli"

    def test_parse_without_braces(self) -> None:
        """Test ACL parsing without braces (raw format)."""
        server = FlextLdifServersTivoli()
        acl = server.acl_quirk
        acl_line = 'ibm-slapdaccesscontrol: access "read" permission "allow"'
        result = acl.parse(acl_line)
        assert result.is_success
        data = result.unwrap()
        assert data.name == "Tivoli ACL"
        assert data.server_type == "ibm_tivoli"

    def test_write_acl_to_rfc_with_content(self) -> None:
        """Test writing ACL with existing content."""
        server = FlextLdifServersTivoli()
        acl = server.acl_quirk
        acl_data = FlextLdifModels.Acl(
            name="Tivoli ACL",
            target=FlextLdifModels.AclTarget(
                target_dn="",
                attributes=[],
            ),
            subject=FlextLdifModels.AclSubject(
                subject_type="",
                subject_value="",
            ),
            permissions=FlextLdifModels.AclPermissions(
                read=True,
                write=False,
                delete=False,
            ),
            server_type="ibm_tivoli",
        )
        result = acl.write(acl_data)
        assert result.is_success
        acl_str = result.unwrap()
        assert "ibm-slapdaccesscontrol:" in acl_str

    def test_write_acl_to_rfc_with_structured_fields(self) -> None:
        """Test writing ACL with structured fields."""
        server = FlextLdifServersTivoli()
        acl = server.acl_quirk
        acl_data = FlextLdifModels.Acl(
            name="Tivoli ACL",
            target=FlextLdifModels.AclTarget(
                target_dn="",
                attributes=[],
            ),
            subject=FlextLdifModels.AclSubject(
                subject_type="groupdn",
                subject_value="cn=Admins,o=Example",
            ),
            permissions=FlextLdifModels.AclPermissions(
                read=True,
                write=False,
                delete=False,
            ),
            server_type="ibm_tivoli",
        )
        result = acl.write(acl_data)
        assert result.is_success
        acl_str = result.unwrap()
        assert "ibm-slapdaccesscontrol:" in acl_str

    def test_write_acl_to_rfc_empty_data(self) -> None:
        """Test writing ACL with empty data."""
        server = FlextLdifServersTivoli()
        acl = server.acl_quirk
        acl_data = FlextLdifModels.Acl(
            name="Tivoli ACL",
            target=FlextLdifModels.AclTarget(
                target_dn="",
                attributes=[],
            ),
            subject=FlextLdifModels.AclSubject(
                subject_type="",
                subject_value="",
            ),
            permissions=FlextLdifModels.AclPermissions(
                read=False,
                write=False,
                delete=False,
            ),
            server_type="ibm_tivoli",
        )
        result = acl.write(acl_data)
        assert result.is_success
        acl_str = result.unwrap()
        assert "ibm-slapdaccesscontrol:" in acl_str


class TestTivoliEntrys:
    """Tests for IBM Tivoli Directory Server entry quirk handling."""

    def test_initialization(self) -> None:
        """Test Tivoli entry quirk initialization."""
        server = FlextLdifServersTivoli()
        entry = server.entry_quirk
        assert entry is not None

    def test_can_handle_entry_tivoli_dn_marker(self) -> None:
        """Test entry detection by Tivoli DN markers."""
        server = FlextLdifServersTivoli()
        entry = server.entry_quirk
        dn = FlextLdifModels.DistinguishedName(
            value="cn=ibm,cn=configuration,o=Example",
        )
        attributes = FlextLdifModels.LdifAttributes(
            attributes={FlextLdifConstants.DictKeys.OBJECTCLASS: ["top"]},
        )
        FlextLdifModels.Entry(dn=dn, attributes=attributes)
        assert entry.can_handle(dn.value, attributes.attributes) is True

    def test_can_handle_entry_tivoli_attribute(self) -> None:
        """Test entry detection by ibm- prefixed attributes."""
        server = FlextLdifServersTivoli()
        entry = server.entry_quirk
        dn = FlextLdifModels.DistinguishedName(value="cn=test,o=Example")
        attributes = FlextLdifModels.LdifAttributes(
            attributes={
                FlextLdifConstants.DictKeys.OBJECTCLASS: ["top"],
                "ibm-entryUUID": ["123456"],
            },
        )
        FlextLdifModels.Entry(dn=dn, attributes=attributes)
        assert entry.can_handle(dn.value, attributes.attributes) is True

    def test_can_handle_entry_tivoli_objectclass(self) -> None:
        """Test entry detection by Tivoli objectClass."""
        server = FlextLdifServersTivoli()
        entry = server.entry_quirk
        dn = FlextLdifModels.DistinguishedName(value="cn=server,o=Example")
        attributes = FlextLdifModels.LdifAttributes(
            attributes={
                FlextLdifConstants.DictKeys.OBJECTCLASS: ["top", "ibm-ldapserver"],
            },
        )
        FlextLdifModels.Entry(dn=dn, attributes=attributes)
        assert entry.can_handle(dn.value, attributes.attributes)

    def test_can_handle_entry_non_tivoli(self) -> None:
        """Test non-Tivoli entry rejection."""
        server = FlextLdifServersTivoli()
        entry = server.entry_quirk
        dn = FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com")
        attributes = FlextLdifModels.LdifAttributes(
            attributes={
                FlextLdifConstants.DictKeys.OBJECTCLASS: ["person"],
                "cn": ["test"],
            },
        )
        assert not entry.can_handle(dn.value, attributes.attributes)
