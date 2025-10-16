# pyright: reportArgumentType=false, reportOperatorIssue=false, reportOptionalMemberAccess=false, reportIndexIssue=false
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
from flext_ldif.quirks.servers.tivoli_quirks import (
    FlextLdifQuirksServersTivoli,
)
from flext_ldif.typings import FlextLdifTypes


class TestTivoliSchemaQuirks:
    """Tests for IBM Tivoli Directory Server schema quirk handling."""

    def test_initialization(self) -> None:
        """Test Tivoli schema quirk initialization."""
        quirk = FlextLdifQuirksServersTivoli()
        assert quirk.server_type == FlextLdifConstants.LdapServers.IBM_TIVOLI
        assert quirk.priority == 15

    def test_can_handle_attribute_tivoli_oid(self) -> None:
        """Test Tivoli attribute detection by OID pattern."""
        quirk = FlextLdifQuirksServersTivoli()
        attr_def = "( 1.3.18.0.2.4.1 NAME 'ibm-entryUUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        assert quirk.can_handle_attribute(attr_def)

    def test_can_handle_attribute_ibm_prefix(self) -> None:
        """Test Tivoli attribute detection by ibm- prefix."""
        quirk = FlextLdifQuirksServersTivoli()
        attr_def = "( 1.2.3.4 NAME 'ibm-slapdaccesscontrol' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        assert quirk.can_handle_attribute(attr_def)

    def test_can_handle_attribute_ids_prefix(self) -> None:
        """Test Tivoli attribute detection by ids- prefix."""
        quirk = FlextLdifQuirksServersTivoli()
        attr_def = (
            "( 1.2.3.4 NAME 'ids-pwdPolicy' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        assert quirk.can_handle_attribute(attr_def)

    def test_can_handle_attribute_non_tivoli(self) -> None:
        """Test non-Tivoli attribute rejection."""
        quirk = FlextLdifQuirksServersTivoli()
        attr_def = "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        assert not quirk.can_handle_attribute(attr_def)

    def test_parse_attribute_success(self) -> None:
        """Test successful Tivoli attribute parsing."""
        quirk = FlextLdifQuirksServersTivoli()
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
        assert data[FlextLdifConstants.DictKeys.OID] == "1.3.18.0.2.4.1"
        assert data[FlextLdifConstants.DictKeys.NAME] == "ibm-entryUUID"
        assert data[FlextLdifConstants.DictKeys.DESC] == "Entry UUID"
        assert (
            data[FlextLdifConstants.DictKeys.SYNTAX] == "1.3.6.1.4.1.1466.115.121.1.15"
        )
        assert data[FlextLdifConstants.DictKeys.EQUALITY] == "caseIgnoreMatch"
        assert data[FlextLdifConstants.DictKeys.SINGLE_VALUE] is True
        assert (
            data[FlextLdifConstants.DictKeys.SERVER_TYPE]
            == FlextLdifConstants.LdapServers.IBM_TIVOLI
        )

    def test_parse_attribute_missing_oid(self) -> None:
        """Test attribute parsing failure when OID is missing."""
        quirk = FlextLdifQuirksServersTivoli()
        attr_def = "NAME 'ibm-entryUUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15"
        result = quirk.parse_attribute(attr_def)
        assert not result.is_success
        assert result.error is not None
        assert "missing an OID" in result.error

    def test_parse_attribute_with_ordering(self) -> None:
        """Test attribute parsing with ORDERING matching rule."""
        quirk = FlextLdifQuirksServersTivoli()
        attr_def = (
            "( 1.3.18.0.2.4.2 NAME 'ids-timestamp' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 "
            "ORDERING generalizedTimeOrderingMatch )"
        )
        result = quirk.parse_attribute(attr_def)
        assert result.is_success
        data = result.unwrap()
        assert (
            data[FlextLdifConstants.DictKeys.ORDERING] == "generalizedTimeOrderingMatch"
        )

    def test_parse_attribute_with_substr(self) -> None:
        """Test attribute parsing with SUBSTR matching rule."""
        quirk = FlextLdifQuirksServersTivoli()
        attr_def = (
            "( 1.3.18.0.2.4.3 NAME 'ibm-description' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
            "SUBSTR caseIgnoreSubstringsMatch )"
        )
        result = quirk.parse_attribute(attr_def)
        assert result.is_success
        data = result.unwrap()
        assert data[FlextLdifConstants.DictKeys.SUBSTR] == "caseIgnoreSubstringsMatch"

    def test_parse_attribute_with_syntax_length(self) -> None:
        """Test attribute parsing with syntax length constraint."""
        quirk = FlextLdifQuirksServersTivoli()
        attr_def = "( 1.3.18.0.2.4.4 NAME 'ibm-code' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{128} )"
        result = quirk.parse_attribute(attr_def)
        assert result.is_success
        data = result.unwrap()
        assert data["syntax_length"] == 128

    def test_parse_attribute_with_sup(self) -> None:
        """Test attribute parsing with SUP (superior) attribute."""
        quirk = FlextLdifQuirksServersTivoli()
        attr_def = "( 1.3.18.0.2.4.5 NAME 'ibm-specialAttr' SUP name )"
        result = quirk.parse_attribute(attr_def)
        assert result.is_success
        data = result.unwrap()
        assert data[FlextLdifConstants.DictKeys.SUP] == "name"

    def test_can_handle_objectclass_tivoli_oid(self) -> None:
        """Test Tivoli objectClass detection by OID pattern."""
        quirk = FlextLdifQuirksServersTivoli()
        oc_def = "( 1.3.18.0.2.6.1 NAME 'ibm-ldapserver' SUP top STRUCTURAL )"
        assert quirk.can_handle_objectclass(oc_def)

    def test_can_handle_objectclass_tivoli_name(self) -> None:
        """Test Tivoli objectClass detection by known names."""
        quirk = FlextLdifQuirksServersTivoli()
        oc_def = "( 1.2.3.4 NAME 'ibm-slapdaccesscontrolsubentry' SUP top AUXILIARY )"
        assert quirk.can_handle_objectclass(oc_def)

    def test_can_handle_objectclass_non_tivoli(self) -> None:
        """Test non-Tivoli objectClass rejection."""
        quirk = FlextLdifQuirksServersTivoli()
        oc_def = "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL )"
        assert not quirk.can_handle_objectclass(oc_def)

    def test_parse_objectclass_success(self) -> None:
        """Test successful Tivoli objectClass parsing."""
        quirk = FlextLdifQuirksServersTivoli()
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
        assert data[FlextLdifConstants.DictKeys.OID] == "1.3.18.0.2.6.1"
        assert data[FlextLdifConstants.DictKeys.NAME] == "ibm-ldapserver"
        assert data[FlextLdifConstants.DictKeys.DESC] == "LDAP server configuration"
        assert data[FlextLdifConstants.DictKeys.SUP] == "top"
        assert data[FlextLdifConstants.DictKeys.KIND] == "STRUCTURAL"
        must_attrs = data[FlextLdifConstants.DictKeys.MUST]
        may_attrs = data[FlextLdifConstants.DictKeys.MAY]
        assert isinstance(must_attrs, list) and "cn" in must_attrs
        assert isinstance(must_attrs, list) and "ibm-serverVersion" in must_attrs
        assert isinstance(may_attrs, list) and "ibm-serverPort" in may_attrs
        assert (
            data[FlextLdifConstants.DictKeys.SERVER_TYPE]
            == FlextLdifConstants.LdapServers.IBM_TIVOLI
        )

    def test_parse_objectclass_missing_oid(self) -> None:
        """Test objectClass parsing failure when OID is missing."""
        quirk = FlextLdifQuirksServersTivoli()
        oc_def = "NAME 'ibm-ldapserver' SUP top STRUCTURAL"
        result = quirk.parse_objectclass(oc_def)
        assert not result.is_success
        assert result.error is not None
        assert "missing an OID" in result.error

    def test_parse_objectclass_auxiliary(self) -> None:
        """Test parsing AUXILIARY objectClass."""
        quirk = FlextLdifQuirksServersTivoli()
        oc_def = "( 1.3.18.0.2.6.2 NAME 'ibm-filterentry' AUXILIARY )"
        result = quirk.parse_objectclass(oc_def)
        assert result.is_success
        data = result.unwrap()
        assert data[FlextLdifConstants.DictKeys.KIND] == "AUXILIARY"

    def test_parse_objectclass_abstract(self) -> None:
        """Test parsing ABSTRACT objectClass."""
        quirk = FlextLdifQuirksServersTivoli()
        oc_def = "( 1.3.18.0.2.6.3 NAME 'ibm-baseClass' ABSTRACT )"
        result = quirk.parse_objectclass(oc_def)
        assert result.is_success
        data = result.unwrap()
        assert data[FlextLdifConstants.DictKeys.KIND] == "ABSTRACT"

    def test_convert_attribute_to_rfc(self) -> None:
        """Test attribute conversion to RFC format."""
        quirk = FlextLdifQuirksServersTivoli()
        attr_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.OID: "1.3.18.0.2.4.1",
            FlextLdifConstants.DictKeys.NAME: "ibm-entryUUID",
            FlextLdifConstants.DictKeys.DESC: "Entry UUID",
            FlextLdifConstants.DictKeys.SYNTAX: "1.3.6.1.4.1.1466.115.121.1.15",
            FlextLdifConstants.DictKeys.EQUALITY: "caseIgnoreMatch",
            FlextLdifConstants.DictKeys.SINGLE_VALUE: True,
        }
        result = quirk.convert_attribute_to_rfc(attr_data)
        assert result.is_success
        rfc_data = result.unwrap()
        assert rfc_data[FlextLdifConstants.DictKeys.OID] == "1.3.18.0.2.4.1"
        assert rfc_data[FlextLdifConstants.DictKeys.NAME] == "ibm-entryUUID"

    def test_convert_objectclass_to_rfc(self) -> None:
        """Test objectClass conversion to RFC format."""
        quirk = FlextLdifQuirksServersTivoli()
        oc_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.OID: "1.3.18.0.2.6.1",
            FlextLdifConstants.DictKeys.NAME: "ibm-ldapserver",
            FlextLdifConstants.DictKeys.DESC: "LDAP server",
            FlextLdifConstants.DictKeys.SUP: "top",
            FlextLdifConstants.DictKeys.KIND: "STRUCTURAL",
            FlextLdifConstants.DictKeys.MUST: ["cn"],
            FlextLdifConstants.DictKeys.MAY: ["description"],
        }
        result = quirk.convert_objectclass_to_rfc(oc_data)
        assert result.is_success
        rfc_data = result.unwrap()
        assert rfc_data[FlextLdifConstants.DictKeys.OID] == "1.3.18.0.2.6.1"
        assert rfc_data[FlextLdifConstants.DictKeys.NAME] == "ibm-ldapserver"

    def test_convert_attribute_from_rfc(self) -> None:
        """Test attribute conversion from RFC format."""
        quirk = FlextLdifQuirksServersTivoli()
        rfc_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.OID: "1.3.18.0.2.4.1",
            FlextLdifConstants.DictKeys.NAME: "ibm-entryUUID",
            FlextLdifConstants.DictKeys.SYNTAX: "1.3.6.1.4.1.1466.115.121.1.15",
        }
        result = quirk.convert_attribute_from_rfc(rfc_data)
        assert result.is_success
        tivoli_data = result.unwrap()
        assert (
            tivoli_data[FlextLdifConstants.DictKeys.SERVER_TYPE]
            == FlextLdifConstants.LdapServers.IBM_TIVOLI
        )

    def test_convert_objectclass_from_rfc(self) -> None:
        """Test objectClass conversion from RFC format."""
        quirk = FlextLdifQuirksServersTivoli()
        rfc_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.OID: "1.3.18.0.2.6.1",
            FlextLdifConstants.DictKeys.NAME: "ibm-ldapserver",
            FlextLdifConstants.DictKeys.KIND: "STRUCTURAL",
        }
        result = quirk.convert_objectclass_from_rfc(rfc_data)
        assert result.is_success
        tivoli_data = result.unwrap()
        assert (
            tivoli_data[FlextLdifConstants.DictKeys.SERVER_TYPE]
            == FlextLdifConstants.LdapServers.IBM_TIVOLI
        )

    def test_write_attribute_to_rfc(self) -> None:
        """Test writing attribute to RFC string format."""
        quirk = FlextLdifQuirksServersTivoli()
        attr_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.OID: "1.3.18.0.2.4.1",
            FlextLdifConstants.DictKeys.NAME: "ibm-entryUUID",
            FlextLdifConstants.DictKeys.DESC: "Entry UUID",
            FlextLdifConstants.DictKeys.SYNTAX: "1.3.6.1.4.1.1466.115.121.1.15",
            FlextLdifConstants.DictKeys.EQUALITY: "caseIgnoreMatch",
            FlextLdifConstants.DictKeys.SINGLE_VALUE: True,
        }
        result = quirk.write_attribute_to_rfc(attr_data)
        assert result.is_success
        attr_str = result.unwrap()
        assert "1.3.18.0.2.4.1" in attr_str
        assert "ibm-entryUUID" in attr_str
        assert "SINGLE-VALUE" in attr_str

    def test_write_objectclass_to_rfc(self) -> None:
        """Test writing objectClass to RFC string format."""
        quirk = FlextLdifQuirksServersTivoli()
        oc_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.OID: "1.3.18.0.2.6.1",
            FlextLdifConstants.DictKeys.NAME: "ibm-ldapserver",
            FlextLdifConstants.DictKeys.DESC: "LDAP server",
            FlextLdifConstants.DictKeys.SUP: "top",
            FlextLdifConstants.DictKeys.KIND: "STRUCTURAL",
            FlextLdifConstants.DictKeys.MUST: ["cn", "objectClass"],
            FlextLdifConstants.DictKeys.MAY: ["description", "seeAlso"],
        }
        result = quirk.write_objectclass_to_rfc(oc_data)
        assert result.is_success
        oc_str = result.unwrap()
        assert "1.3.18.0.2.6.1" in oc_str
        assert "ibm-ldapserver" in oc_str
        assert "STRUCTURAL" in oc_str
        assert "MUST" in oc_str
        assert "MAY" in oc_str


class TestTivoliAclQuirks:
    """Tests for IBM Tivoli Directory Server ACL quirk handling."""

    def test_initialization(self) -> None:
        """Test Tivoli ACL quirk initialization."""
        quirk = FlextLdifQuirksServersTivoli()
        acl_quirk = quirk.AclQuirk()
        assert acl_quirk.server_type == FlextLdifConstants.LdapServers.IBM_TIVOLI
        assert acl_quirk.priority == 15

    def test_can_handle_acl_ibm_slapdaccesscontrol(self) -> None:
        """Test ACL detection with ibm-slapdaccesscontrol attribute."""
        quirk = FlextLdifQuirksServersTivoli()
        acl_quirk = quirk.AclQuirk()
        acl_line = 'ibm-slapdaccesscontrol: {access "read" permission "allow" userdn="cn=Admin,o=Example"}'
        assert acl_quirk.can_handle_acl(acl_line)

    def test_can_handle_acl_ibm_slapdgroupacl(self) -> None:
        """Test ACL detection with ibm-slapdgroupacl attribute."""
        quirk = FlextLdifQuirksServersTivoli()
        acl_quirk = quirk.AclQuirk()
        acl_line = 'ibm-slapdgroupacl: {access "write" groupdn="cn=Admins,o=Example"}'
        assert acl_quirk.can_handle_acl(acl_line)

    def test_can_handle_acl_empty_line(self) -> None:
        """Test ACL rejection with empty line."""
        quirk = FlextLdifQuirksServersTivoli()
        acl_quirk = quirk.AclQuirk()
        assert not acl_quirk.can_handle_acl("")

    def test_can_handle_acl_non_tivoli(self) -> None:
        """Test non-Tivoli ACL rejection."""
        quirk = FlextLdifQuirksServersTivoli()
        acl_quirk = quirk.AclQuirk()
        acl_line = "aci: (version 3.0; acl read-access; allow(read))"
        assert not acl_quirk.can_handle_acl(acl_line)

    def test_parse_acl_success(self) -> None:
        """Test successful Tivoli ACL parsing."""
        quirk = FlextLdifQuirksServersTivoli()
        acl_quirk = quirk.AclQuirk()
        acl_line = 'ibm-slapdaccesscontrol: {access "read" permission "allow" groupdn="cn=Admins,o=Example" userdn="cn=User,o=Example"}'
        result = acl_quirk.parse_acl(acl_line)
        assert result.is_success
        data = result.unwrap()
        assert data[FlextLdifConstants.DictKeys.TYPE] == FlextLdifConstants.DictKeys.ACL
        assert (
            data[FlextLdifConstants.DictKeys.ACL_ATTRIBUTE] == "ibm-slapdaccesscontrol"
        )
        parsed_data = data.get(FlextLdifConstants.DictKeys.DATA, {})
        assert isinstance(parsed_data, dict)
        assert parsed_data.get("access") == "read"
        assert parsed_data.get("permission") == "allow"
        assert parsed_data.get("groupdn") == "cn=Admins,o=Example"
        assert parsed_data.get("userdn") == "cn=User,o=Example"

    def test_parse_acl_without_braces(self) -> None:
        """Test ACL parsing without braces (raw format)."""
        quirk = FlextLdifQuirksServersTivoli()
        acl_quirk = quirk.AclQuirk()
        acl_line = 'ibm-slapdaccesscontrol: access "read" permission "allow"'
        result = acl_quirk.parse_acl(acl_line)
        assert result.is_success
        data = result.unwrap()
        parsed_data = data.get(FlextLdifConstants.DictKeys.DATA, {})
        assert isinstance(parsed_data, dict)
        assert parsed_data.get("access") == "read"

    def test_convert_acl_to_rfc(self) -> None:
        """Test ACL conversion to RFC format."""
        quirk = FlextLdifQuirksServersTivoli()
        acl_quirk = quirk.AclQuirk()
        acl_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.DictKeys.ACL,
            FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: "ibm-slapdaccesscontrol",
            FlextLdifConstants.DictKeys.DATA: {
                "access": "read",
                "permission": "allow",
            },
        }
        result = acl_quirk.convert_acl_to_rfc(acl_data)
        assert result.is_success
        rfc_data = result.unwrap()
        assert (
            rfc_data[FlextLdifConstants.DictKeys.FORMAT]
            == FlextLdifConstants.AclFormats.RFC_GENERIC
        )

    def test_convert_acl_from_rfc(self) -> None:
        """Test ACL conversion from RFC format."""
        quirk = FlextLdifQuirksServersTivoli()
        acl_quirk = quirk.AclQuirk()
        rfc_data: FlextLdifTypes.Dict = {
            FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.DictKeys.ACL,
            FlextLdifConstants.DictKeys.DATA: {
                "access": "read",
                "permission": "allow",
            },
        }
        result = acl_quirk.convert_acl_from_rfc(rfc_data)
        assert result.is_success
        tivoli_data = result.unwrap()
        assert (
            tivoli_data[FlextLdifConstants.DictKeys.TARGET_FORMAT]
            == "ibm-slapdaccesscontrol"
        )

    def test_write_acl_to_rfc_with_content(self) -> None:
        """Test writing ACL with existing content."""
        quirk = FlextLdifQuirksServersTivoli()
        acl_quirk = quirk.AclQuirk()
        acl_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: "ibm-slapdaccesscontrol",
            FlextLdifConstants.DictKeys.DATA: {
                "content": '{access "read" permission "allow"}',
            },
        }
        result = acl_quirk.write_acl_to_rfc(acl_data)
        assert result.is_success
        acl_str = result.unwrap()
        assert "ibm-slapdaccesscontrol:" in acl_str
        assert '{access "read" permission "allow"}' in acl_str

    def test_write_acl_to_rfc_with_structured_fields(self) -> None:
        """Test writing ACL with structured fields."""
        quirk = FlextLdifQuirksServersTivoli()
        acl_quirk = quirk.AclQuirk()
        acl_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: "ibm-slapdaccesscontrol",
            FlextLdifConstants.DictKeys.DATA: {
                "access": "read",
                "permission": "allow",
                "groupdn": "cn=Admins,o=Example",
                "userdn": "cn=User,o=Example",
            },
        }
        result = acl_quirk.write_acl_to_rfc(acl_data)
        assert result.is_success
        acl_str = result.unwrap()
        assert "ibm-slapdaccesscontrol:" in acl_str
        assert '{access "read"' in acl_str
        assert 'permission "allow"' in acl_str
        assert 'groupdn="cn=Admins,o=Example"' in acl_str
        assert 'userdn="cn=User,o=Example"' in acl_str

    def test_write_acl_to_rfc_empty_data(self) -> None:
        """Test writing ACL with empty data."""
        quirk = FlextLdifQuirksServersTivoli()
        acl_quirk = quirk.AclQuirk()
        acl_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: "ibm-slapdaccesscontrol",
            FlextLdifConstants.DictKeys.DATA: {},
        }
        result = acl_quirk.write_acl_to_rfc(acl_data)
        assert result.is_success
        acl_str = result.unwrap()
        assert acl_str == "ibm-slapdaccesscontrol:"


class TestTivoliEntryQuirks:
    """Tests for IBM Tivoli Directory Server entry quirk handling."""

    def test_initialization(self) -> None:
        """Test Tivoli entry quirk initialization."""
        quirk = FlextLdifQuirksServersTivoli()
        entry_quirk = quirk.EntryQuirk()
        assert entry_quirk.server_type == FlextLdifConstants.LdapServers.IBM_TIVOLI
        assert entry_quirk.priority == 15

    def test_can_handle_entry_tivoli_dn_marker(self) -> None:
        """Test entry detection by Tivoli DN markers."""
        quirk = FlextLdifQuirksServersTivoli()
        entry_quirk = quirk.EntryQuirk()
        assert entry_quirk.can_handle_entry(
            "cn=ibm,cn=configuration,o=Example",
            {"objectClass": ["top"]},
        )

    def test_can_handle_entry_tivoli_attribute(self) -> None:
        """Test entry detection by ibm- prefixed attributes."""
        quirk = FlextLdifQuirksServersTivoli()
        entry_quirk = quirk.EntryQuirk()
        assert entry_quirk.can_handle_entry(
            "cn=test,o=Example",
            {"objectClass": ["top"], "ibm-entryUUID": ["123456"]},
        )

    def test_can_handle_entry_tivoli_objectclass(self) -> None:
        """Test entry detection by Tivoli objectClass."""
        quirk = FlextLdifQuirksServersTivoli()
        entry_quirk = quirk.EntryQuirk()
        assert entry_quirk.can_handle_entry(
            "cn=server,o=Example",
            {"objectClass": ["top", "ibm-ldapserver"]},
        )

    def test_can_handle_entry_non_tivoli(self) -> None:
        """Test non-Tivoli entry rejection."""
        quirk = FlextLdifQuirksServersTivoli()
        entry_quirk = quirk.EntryQuirk()
        assert not entry_quirk.can_handle_entry(
            "cn=test,dc=example,dc=com",
            {"objectClass": ["person"], "cn": ["test"]},
        )

    def test_process_entry_success(self) -> None:
        """Test successful Tivoli entry processing."""
        quirk = FlextLdifQuirksServersTivoli()
        entry_quirk = quirk.EntryQuirk()
        entry_dn = "cn=server,o=Example"
        attributes: dict[str, object] = {
            "objectClass": ["top", "ibm-ldapserver"],
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
        assert "objectClass" in processed

    def test_process_entry_with_binary_data(self) -> None:
        """Test entry processing with binary data (base64 encoding)."""
        quirk = FlextLdifQuirksServersTivoli()
        entry_quirk = quirk.EntryQuirk()
        entry_dn = "cn=test,o=Example"
        binary_data = b"binary_content"
        attributes: dict[str, object] = {
            "objectClass": ["top", "ibm-filterentry"],
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
        quirk = FlextLdifQuirksServersTivoli()
        entry_quirk = quirk.EntryQuirk()
        entry_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: "cn=server,o=Example",
            FlextLdifConstants.DictKeys.SERVER_TYPE: FlextLdifConstants.LdapServers.IBM_TIVOLI,
            "objectClass": ["top", "ibm-ldapserver"],
            "cn": ["server"],
        }
        result = entry_quirk.convert_entry_to_rfc(entry_data)
        assert result.is_success
        rfc_data = result.unwrap()
        assert FlextLdifConstants.DictKeys.SERVER_TYPE not in rfc_data
        assert rfc_data[FlextLdifConstants.DictKeys.DN] == "cn=server,o=Example"
