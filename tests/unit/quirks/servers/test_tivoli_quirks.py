"""Comprehensive tests for IBM Tivoli Directory Server quirks.

This module provides complete test coverage for IBM Tivoli Directory Server
schema, ACL, and entry quirks, including:
- Server-specific OID patterns (1.3.18.*)
- ibm-/ids- attribute prefixes
- Structured ACL format with {} delimiters
- Entry processing with base64 encoding for binary data
"""

from __future__ import annotations

import base64

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.tivoli import FlextLdifServersTivoli


class TestTivoliSchemas:
    """Tests for IBM Tivoli Directory Server schema quirk handling."""

    def test_initialization(self) -> None:
        """Test Tivoli schema quirk initialization."""
        quirk = FlextLdifServersTivoli.Schema()
        assert quirk.server_type == FlextLdifConstants.LdapServers.IBM_TIVOLI
        assert quirk.priority == 15

    def test_can_handle_attribute_tivoli_oid(self) -> None:
        """Test Tivoli attribute detection by OID pattern."""
        quirk = FlextLdifServersTivoli.Schema()
        attr_def = "( 1.3.18.0.2.4.1 NAME 'ibm-entryUUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        assert quirk.can_handle_attribute(attr_def)

    def test_can_handle_attribute_ibm_prefix(self) -> None:
        """Test Tivoli attribute detection by ibm- prefix."""
        quirk = FlextLdifServersTivoli.Schema()
        attr_def = "( 1.2.3.4 NAME 'ibm-slapdaccesscontrol' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        assert quirk.can_handle_attribute(attr_def)

    def test_can_handle_attribute_ids_prefix(self) -> None:
        """Test Tivoli attribute detection by ids- prefix."""
        quirk = FlextLdifServersTivoli.Schema()
        attr_def = (
            "( 1.2.3.4 NAME 'ids-pwdPolicy' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        assert quirk.can_handle_attribute(attr_def)

    def test_can_handle_attribute_non_tivoli(self) -> None:
        """Test non-Tivoli attribute rejection."""
        quirk = FlextLdifServersTivoli.Schema()
        attr_def = "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        assert not quirk.can_handle_attribute(attr_def)

    def test_parse_attribute_success(self) -> None:
        """Test successful Tivoli attribute parsing."""
        quirk = FlextLdifServersTivoli.Schema()
        attr_def = (
            "( 1.3.18.0.2.4.1 NAME 'ibm-entryUUID' "
            "DESC 'Entry UUID' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
            "EQUALITY caseIgnoreMatch "
            "SINGLE-VALUE )"
        )
        result = quirk.parse_attribute(attr_def)
        assert result.is_success
        data = result.unwrap()
        assert data.oid == "1.3.18.0.2.4.1"
        assert data.name == "ibm-entryUUID"
        assert data.desc == "Entry UUID"
        assert data.syntax == "1.3.6.1.4.1.1466.115.121.1.15"
        assert data.equality == "caseIgnoreMatch"
        assert data.single_value is True
        assert data.metadata is not None
        assert data.metadata.quirk_type == "ibm_tivoli"

    def test_parse_attribute_missing_oid(self) -> None:
        """Test attribute parsing failure when OID is missing."""
        quirk = FlextLdifServersTivoli.Schema()
        attr_def = "NAME 'ibm-entryUUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15"
        result = quirk.parse_attribute(attr_def)
        assert not result.is_success
        assert result.error is not None
        assert "missing an OID" in result.error

    def test_parse_attribute_with_ordering(self) -> None:
        """Test attribute parsing with ORDERING matching rule."""
        quirk = FlextLdifServersTivoli.Schema()
        attr_def = (
            "( 1.3.18.0.2.4.2 NAME 'ids-timestamp' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 "
            "ORDERING generalizedTimeOrderingMatch )"
        )
        result = quirk.parse_attribute(attr_def)
        assert result.is_success
        data = result.unwrap()
        assert data.ordering == "generalizedTimeOrderingMatch"

    def test_parse_attribute_with_substr(self) -> None:
        """Test attribute parsing with SUBSTR matching rule."""
        quirk = FlextLdifServersTivoli.Schema()
        attr_def = (
            "( 1.3.18.0.2.4.3 NAME 'ibm-description' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
            "SUBSTR caseIgnoreSubstringsMatch )"
        )
        result = quirk.parse_attribute(attr_def)
        assert result.is_success
        data = result.unwrap()
        assert data.substr == "caseIgnoreSubstringsMatch"

    def test_parse_attribute_with_syntax_length(self) -> None:
        """Test attribute parsing with syntax length constraint."""
        quirk = FlextLdifServersTivoli.Schema()
        attr_def = "( 1.3.18.0.2.4.4 NAME 'ibm-code' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{128} )"
        result = quirk.parse_attribute(attr_def)
        assert result.is_success
        data = result.unwrap()
        assert data.length == 128

    def test_parse_attribute_with_sup(self) -> None:
        """Test attribute parsing with SUP (superior) attribute."""
        quirk = FlextLdifServersTivoli.Schema()
        attr_def = "( 1.3.18.0.2.4.5 NAME 'ibm-specialAttr' SUP name )"
        result = quirk.parse_attribute(attr_def)
        assert result.is_success
        data = result.unwrap()
        assert data.sup == "name"

    def test_can_handle_objectclass_tivoli_oid(self) -> None:
        """Test Tivoli objectClass detection by OID pattern."""
        quirk = FlextLdifServersTivoli.Schema()
        oc_def = "( 1.3.18.0.2.6.1 NAME 'ibm-ldapserver' SUP top STRUCTURAL )"
        assert quirk.can_handle_objectclass(oc_def)

    def test_can_handle_objectclass_tivoli_name(self) -> None:
        """Test Tivoli objectClass detection by known names."""
        quirk = FlextLdifServersTivoli.Schema()
        oc_def = "( 1.2.3.4 NAME 'ibm-slapdaccesscontrolsubentry' SUP top AUXILIARY )"
        assert quirk.can_handle_objectclass(oc_def)

    def test_can_handle_objectclass_non_tivoli(self) -> None:
        """Test non-Tivoli objectClass rejection."""
        quirk = FlextLdifServersTivoli.Schema()
        oc_def = "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL )"
        assert not quirk.can_handle_objectclass(oc_def)

    def test_parse_objectclass_success(self) -> None:
        """Test successful Tivoli objectClass parsing."""
        quirk = FlextLdifServersTivoli.Schema()
        oc_def = (
            "( 1.3.18.0.2.6.1 NAME 'ibm-ldapserver' "
            "DESC 'LDAP server configuration' "
            "SUP top STRUCTURAL "
            "MUST ( cn $ ibm-serverVersion ) "
            "MAY ( ibm-serverPort $ description ) )"
        )
        result = quirk.parse_objectclass(oc_def)
        assert result.is_success
        data = result.unwrap()
        assert data.oid == "1.3.18.0.2.6.1"
        assert data.name == "ibm-ldapserver"
        assert data.desc == "LDAP server configuration"
        assert data.sup == "top"
        assert data.kind == "STRUCTURAL"
        assert data.must is not None and "cn" in data.must
        assert data.must is not None and "ibm-serverVersion" in data.must
        assert data.may is not None and "ibm-serverPort" in data.may
        assert data.metadata is not None
        assert data.metadata.quirk_type == "ibm_tivoli"

    def test_parse_objectclass_missing_oid(self) -> None:
        """Test objectClass parsing failure when OID is missing."""
        quirk = FlextLdifServersTivoli.Schema()
        oc_def = "NAME 'ibm-ldapserver' SUP top STRUCTURAL"
        result = quirk.parse_objectclass(oc_def)
        assert not result.is_success
        assert result.error is not None
        assert "missing an OID" in result.error

    def test_parse_objectclass_auxiliary(self) -> None:
        """Test parsing AUXILIARY objectClass."""
        quirk = FlextLdifServersTivoli.Schema()
        oc_def = "( 1.3.18.0.2.6.2 NAME 'ibm-filterentry' AUXILIARY )"
        result = quirk.parse_objectclass(oc_def)
        assert result.is_success
        data = result.unwrap()
        assert data.kind == "AUXILIARY"

    def test_parse_objectclass_abstract(self) -> None:
        """Test parsing ABSTRACT objectClass."""
        quirk = FlextLdifServersTivoli.Schema()
        oc_def = "( 1.3.18.0.2.6.3 NAME 'ibm-baseClass' ABSTRACT )"
        result = quirk.parse_objectclass(oc_def)
        assert result.is_success
        data = result.unwrap()
        assert data.kind == "ABSTRACT"

    def test_convert_attribute_to_rfc(self) -> None:
        """Test attribute conversion to RFC format."""
        quirk = FlextLdifServersTivoli.Schema()
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="1.3.18.0.2.4.1",
            name="ibm-entryUUID",
            desc="Entry UUID",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            equality="caseIgnoreMatch",
            single_value=True,
        )
        result = quirk.convert_attribute_to_rfc(attr_data)
        assert result.is_success
        rfc_data = result.unwrap()
        assert rfc_data.oid == "1.3.18.0.2.4.1"
        assert rfc_data.name == "ibm-entryUUID"

    def test_convert_objectclass_to_rfc(self) -> None:
        """Test objectClass conversion to RFC format."""
        quirk = FlextLdifServersTivoli.Schema()
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="1.3.18.0.2.6.1",
            name="ibm-ldapserver",
            desc="LDAP server",
            sup="top",
            kind="STRUCTURAL",
            must=["cn"],
            may=["description"],
        )
        result = quirk.convert_objectclass_to_rfc(oc_data)
        assert result.is_success
        rfc_data = result.unwrap()
        assert rfc_data.oid == "1.3.18.0.2.6.1"
        assert rfc_data.name == "ibm-ldapserver"

    def test_convert_attribute_from_rfc(self) -> None:
        """Test attribute conversion from RFC format."""
        quirk = FlextLdifServersTivoli.Schema()
        rfc_data = FlextLdifModels.SchemaAttribute(
            oid="1.3.18.0.2.4.1",
            name="ibm-entryUUID",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )
        result = quirk.convert_attribute_from_rfc(rfc_data)
        assert result.is_success
        tivoli_data = result.unwrap()
        assert tivoli_data.metadata is not None
        assert tivoli_data.metadata.quirk_type == "ibm_tivoli"

    def test_convert_objectclass_from_rfc(self) -> None:
        """Test objectClass conversion from RFC format."""
        quirk = FlextLdifServersTivoli.Schema()
        rfc_data = FlextLdifModels.SchemaObjectClass(
            oid="1.3.18.0.2.6.1",
            name="ibm-ldapserver",
            kind="STRUCTURAL",
        )
        result = quirk.convert_objectclass_from_rfc(rfc_data)
        assert result.is_success
        tivoli_data = result.unwrap()
        assert tivoli_data.metadata is not None
        assert tivoli_data.metadata.quirk_type == "ibm_tivoli"

    def test_write_attribute_to_rfc(self) -> None:
        """Test writing attribute to RFC string format."""
        quirk = FlextLdifServersTivoli.Schema()
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="1.3.18.0.2.4.1",
            name="ibm-entryUUID",
            desc="Entry UUID",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            equality="caseIgnoreMatch",
            single_value=True,
        )
        result = quirk.write_attribute_to_rfc(attr_data)
        assert result.is_success
        attr_str = result.unwrap()
        assert "1.3.18.0.2.4.1" in attr_str
        assert "ibm-entryUUID" in attr_str
        assert "SINGLE-VALUE" in attr_str

    def test_write_objectclass_to_rfc(self) -> None:
        """Test writing objectClass to RFC string format."""
        quirk = FlextLdifServersTivoli.Schema()
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="1.3.18.0.2.6.1",
            name="ibm-ldapserver",
            desc="LDAP server",
            sup="top",
            kind="STRUCTURAL",
            must=["cn", "objectclass"],
            may=["description", "seeAlso"],
        )
        result = quirk.write_objectclass_to_rfc(oc_data)
        assert result.is_success
        oc_str = result.unwrap()
        assert "1.3.18.0.2.6.1" in oc_str
        assert "ibm-ldapserver" in oc_str
        assert "STRUCTURAL" in oc_str
        assert "MUST" in oc_str
        assert "MAY" in oc_str


class TestTivoliAcls:
    """Tests for IBM Tivoli Directory Server ACL quirk handling."""

    def test_initialization(self) -> None:
        """Test Tivoli ACL quirk initialization."""
        quirk = FlextLdifServersTivoli.Schema()
        acl_quirk = quirk.Acl()
        assert acl_quirk.server_type == FlextLdifConstants.LdapServers.IBM_TIVOLI
        assert acl_quirk.priority == 15

    def test_can_handle_acl_ibm_slapdaccesscontrol(self) -> None:
        """Test ACL detection with ibm-slapdaccesscontrol attribute."""
        quirk = FlextLdifServersTivoli.Schema()
        acl_quirk = quirk.Acl()
        acl_line = 'ibm-slapdaccesscontrol: {access "read" permission "allow" userdn="cn=Admin,o=Example"}'
        assert acl_quirk.can_handle_acl(acl_line)

    def test_can_handle_acl_ibm_slapdgroupacl(self) -> None:
        """Test ACL detection with ibm-slapdgroupacl attribute."""
        quirk = FlextLdifServersTivoli.Schema()
        acl_quirk = quirk.Acl()
        acl_line = 'ibm-slapdgroupacl: {access "write" groupdn="cn=Admins,o=Example"}'
        assert acl_quirk.can_handle_acl(acl_line)

    def test_can_handle_acl_empty_line(self) -> None:
        """Test ACL rejection with empty line."""
        quirk = FlextLdifServersTivoli.Schema()
        acl_quirk = quirk.Acl()
        assert not acl_quirk.can_handle_acl("")

    def test_can_handle_acl_non_tivoli(self) -> None:
        """Test non-Tivoli ACL rejection."""
        quirk = FlextLdifServersTivoli.Schema()
        acl_quirk = quirk.Acl()
        acl_line = "aci: (version 3.0; acl read-access; allow(read))"
        assert not acl_quirk.can_handle_acl(acl_line)

    def test_parse_acl_success(self) -> None:
        """Test successful Tivoli ACL parsing."""
        quirk = FlextLdifServersTivoli.Schema()
        acl_quirk = quirk.Acl()
        acl_line = 'ibm-slapdaccesscontrol: {access "read" permission "allow" groupdn="cn=Admins,o=Example" userdn="cn=User,o=Example"}'
        result = acl_quirk.parse_acl(acl_line)
        assert result.is_success
        data = result.unwrap()
        assert data.name == "Tivoli ACL"
        assert data.server_type == FlextLdifConstants.LdapServers.IBM_TIVOLI

    def test_parse_acl_without_braces(self) -> None:
        """Test ACL parsing without braces (raw format)."""
        quirk = FlextLdifServersTivoli.Schema()
        acl_quirk = quirk.Acl()
        acl_line = 'ibm-slapdaccesscontrol: access "read" permission "allow"'
        result = acl_quirk.parse_acl(acl_line)
        assert result.is_success
        data = result.unwrap()
        assert data.name == "Tivoli ACL"
        assert data.server_type == FlextLdifConstants.LdapServers.IBM_TIVOLI

    def test_convert_acl_to_rfc(self) -> None:
        """Test ACL conversion to RFC format."""
        quirk = FlextLdifServersTivoli.Schema()
        acl_quirk = quirk.Acl()
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
            server_type=FlextLdifConstants.LdapServers.IBM_TIVOLI,
        )
        result = acl_quirk.convert_acl_to_rfc(acl_data)
        assert result.is_success
        rfc_data = result.unwrap()
        assert rfc_data.name == "Tivoli ACL"

    def test_convert_acl_from_rfc(self) -> None:
        """Test ACL conversion from RFC format."""
        quirk = FlextLdifServersTivoli.Schema()
        acl_quirk = quirk.Acl()
        rfc_data = FlextLdifModels.Acl(
            name="RFC ACL",
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
            server_type="generic",  # Use "generic" instead of "rfc"
        )
        result = acl_quirk.convert_acl_from_rfc(rfc_data)
        assert result.is_success
        tivoli_data = result.unwrap()
        # Verify server_type was updated to tivoli
        assert tivoli_data.server_type == FlextLdifConstants.ServerTypes.IBM_TIVOLI

    def test_write_acl_to_rfc_with_content(self) -> None:
        """Test writing ACL with existing content."""
        quirk = FlextLdifServersTivoli.Schema()
        acl_quirk = quirk.Acl()
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
            server_type=FlextLdifConstants.LdapServers.IBM_TIVOLI,
        )
        result = acl_quirk.write_acl_to_rfc(acl_data)
        assert result.is_success
        acl_str = result.unwrap()
        assert "ibm-slapdaccesscontrol:" in acl_str

    def test_write_acl_to_rfc_with_structured_fields(self) -> None:
        """Test writing ACL with structured fields."""
        quirk = FlextLdifServersTivoli.Schema()
        acl_quirk = quirk.Acl()
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
            server_type=FlextLdifConstants.LdapServers.IBM_TIVOLI,
        )
        result = acl_quirk.write_acl_to_rfc(acl_data)
        assert result.is_success
        acl_str = result.unwrap()
        assert "ibm-slapdaccesscontrol:" in acl_str

    def test_write_acl_to_rfc_empty_data(self) -> None:
        """Test writing ACL with empty data."""
        quirk = FlextLdifServersTivoli.Schema()
        acl_quirk = quirk.Acl()
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
            server_type=FlextLdifConstants.LdapServers.IBM_TIVOLI,
        )
        result = acl_quirk.write_acl_to_rfc(acl_data)
        assert result.is_success
        acl_str = result.unwrap()
        assert "ibm-slapdaccesscontrol:" in acl_str


class TestTivoliEntrys:
    """Tests for IBM Tivoli Directory Server entry quirk handling."""

    def test_initialization(self) -> None:
        """Test Tivoli entry quirk initialization."""
        quirk = FlextLdifServersTivoli.Schema()
        entry_quirk = quirk.Entry()
        assert entry_quirk.server_type == FlextLdifConstants.LdapServers.IBM_TIVOLI
        assert entry_quirk.priority == 15

    def test_can_handle_entry_tivoli_dn_marker(self) -> None:
        """Test entry detection by Tivoli DN markers."""
        quirk = FlextLdifServersTivoli.Schema()
        entry_quirk = quirk.Entry()
        assert entry_quirk.can_handle_entry(
            "cn=ibm,cn=configuration,o=Example",
            {FlextLdifConstants.DictKeys.OBJECTCLASS: ["top"]},
        )

    def test_can_handle_entry_tivoli_attribute(self) -> None:
        """Test entry detection by ibm- prefixed attributes."""
        quirk = FlextLdifServersTivoli.Schema()
        entry_quirk = quirk.Entry()
        assert entry_quirk.can_handle_entry(
            "cn=test,o=Example",
            {
                FlextLdifConstants.DictKeys.OBJECTCLASS: ["top"],
                "ibm-entryUUID": ["123456"],
            },
        )

    def test_can_handle_entry_tivoli_objectclass(self) -> None:
        """Test entry detection by Tivoli objectClass."""
        quirk = FlextLdifServersTivoli.Schema()
        entry_quirk = quirk.Entry()
        assert entry_quirk.can_handle_entry(
            "cn=server,o=Example",
            {FlextLdifConstants.DictKeys.OBJECTCLASS: ["top", "ibm-ldapserver"]},
        )

    def test_can_handle_entry_non_tivoli(self) -> None:
        """Test non-Tivoli entry rejection."""
        quirk = FlextLdifServersTivoli.Schema()
        entry_quirk = quirk.Entry()
        assert not entry_quirk.can_handle_entry(
            "cn=test,dc=example,dc=com",
            {FlextLdifConstants.DictKeys.OBJECTCLASS: ["person"], "cn": ["test"]},
        )

    def test_process_entry_success(self) -> None:
        """Test successful Tivoli entry processing."""
        quirk = FlextLdifServersTivoli.Schema()
        entry_quirk = quirk.Entry()
        entry_dn = "cn=server,o=Example"
        attributes: dict[str, object] = {
            "objectclass": ["top", "ibm-ldapserver"],
            "cn": ["server"],
            "ibm-serverVersion": ["8.5"],
        }
        result = entry_quirk.process_entry(entry_dn, attributes)
        assert result.is_success
        processed = result.unwrap()
        assert processed[FlextLdifConstants.DictKeys.DN] == entry_dn
        assert (
            processed[FlextLdifConstants.DictKeys.SERVER_TYPE]
            == FlextLdifConstants.LdapServers.IBM_TIVOLI
        )
        assert "objectclass" in processed

    def test_process_entry_with_binary_data(self) -> None:
        """Test entry processing with binary data (base64 encoding)."""
        quirk = FlextLdifServersTivoli.Schema()
        entry_quirk = quirk.Entry()
        entry_dn = "cn=test,o=Example"
        binary_data = b"binary_content"
        attributes: dict[str, object] = {
            "objectclass": ["top", "ibm-filterentry"],
            "cn": ["test"],
            "ibm-binaryAttr": binary_data,
        }
        result = entry_quirk.process_entry(entry_dn, attributes)
        assert result.is_success
        processed = result.unwrap()
        encoded_value = processed["ibm-binaryAttr"]
        assert isinstance(encoded_value, str)
        assert encoded_value == base64.b64encode(binary_data).decode("ascii")

    def test_convert_entry_to_rfc(self) -> None:
        """Test entry conversion to RFC format."""
        quirk = FlextLdifServersTivoli.Schema()
        entry_quirk = quirk.Entry()
        entry_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: "cn=server,o=Example",
            FlextLdifConstants.DictKeys.SERVER_TYPE: FlextLdifConstants.LdapServers.IBM_TIVOLI,
            "objectclass": ["top", "ibm-ldapserver"],
            "cn": ["server"],
        }
        result = entry_quirk.convert_entry_to_rfc(entry_data)
        assert result.is_success
        rfc_data = result.unwrap()
        assert FlextLdifConstants.DictKeys.SERVER_TYPE not in rfc_data
        assert rfc_data[FlextLdifConstants.DictKeys.DN] == "cn=server,o=Example"
