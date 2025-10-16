"""Tests for Apache Directory Server quirks implementation."""

# pyright: reportArgumentType=false, reportOperatorIssue=false, reportOptionalMemberAccess=false, reportIndexIssue=false

from __future__ import annotations

import base64

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.servers.apache_quirks import FlextLdifQuirksServersApache
from flext_ldif.typings import FlextLdifTypes


class TestApacheDirectorySchemaQuirks:
    """Tests for Apache Directory Server schema quirk handling."""

    def test_initialization(self) -> None:
        """Test Apache Directory Server quirk initialization."""
        quirk = FlextLdifQuirksServersApache()
        assert quirk.server_type == FlextLdifConstants.LdapServers.APACHE_DIRECTORY
        assert quirk.priority == 15

    def test_can_handle_attribute_with_apache_oid(self) -> None:
        """Test attribute detection with Apache DS OID pattern."""
        quirk = FlextLdifQuirksServersApache()
        attr_def = "( 1.3.6.1.4.1.18060.0.4.1.2.100 NAME 'ads-enabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )"
        assert quirk.can_handle_attribute(attr_def) is True

    def test_can_handle_attribute_with_ads_prefix(self) -> None:
        """Test attribute detection with ads- prefix."""
        quirk = FlextLdifQuirksServersApache()
        attr_def = "( 2.16.840.1.113730.3.1.1 NAME 'ads-searchBaseDN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )"
        assert quirk.can_handle_attribute(attr_def) is True

    def test_can_handle_attribute_with_apacheds_name(self) -> None:
        """Test attribute detection with apacheds in name."""
        quirk = FlextLdifQuirksServersApache()
        attr_def = (
            "( 1.2.3.4 NAME 'apachedsSystemId' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        assert quirk.can_handle_attribute(attr_def) is True

    def test_can_handle_attribute_negative(self) -> None:
        """Test attribute detection rejects non-ApacheDS attributes."""
        quirk = FlextLdifQuirksServersApache()
        attr_def = "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        assert quirk.can_handle_attribute(attr_def) is False

    def test_parse_attribute_success(self) -> None:
        """Test parsing Apache DS attribute definition."""
        quirk = FlextLdifQuirksServersApache()
        attr_def = "( 1.3.6.1.4.1.18060.0.4.1.2.100 NAME 'ads-enabled' DESC 'Enable flag' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )"
        result = quirk.parse_attribute(attr_def)

        assert result.is_success
        attr_data = result.unwrap()
        assert (
            attr_data[FlextLdifConstants.DictKeys.OID]
            == "1.3.6.1.4.1.18060.0.4.1.2.100"
        )
        assert attr_data[FlextLdifConstants.DictKeys.NAME] == "ads-enabled"
        assert attr_data[FlextLdifConstants.DictKeys.DESC] == "Enable flag"
        assert (
            attr_data[FlextLdifConstants.DictKeys.SYNTAX]
            == "1.3.6.1.4.1.1466.115.121.1.7"
        )
        assert attr_data[FlextLdifConstants.DictKeys.SINGLE_VALUE] is True

    def test_parse_attribute_with_syntax_length(self) -> None:
        """Test parsing attribute with syntax length specification."""
        quirk = FlextLdifQuirksServersApache()
        attr_def = "( 1.3.6.1.4.1.18060.0.4.1.2.1 NAME 'ads-directoryServiceId' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        result = quirk.parse_attribute(attr_def)

        assert result.is_success
        attr_data = result.unwrap()
        assert (
            attr_data[FlextLdifConstants.DictKeys.SYNTAX]
            == "1.3.6.1.4.1.1466.115.121.1.15"
        )
        assert attr_data["syntax_length"] == 256

    def test_parse_attribute_missing_oid(self) -> None:
        """Test parsing attribute without OID fails."""
        quirk = FlextLdifQuirksServersApache()
        attr_def = "NAME 'ads-enabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7"
        result = quirk.parse_attribute(attr_def)

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None
        assert "missing an OID" in result.error

    def test_can_handle_objectclass_with_apache_oid(self) -> None:
        """Test objectClass detection with Apache DS OID."""
        quirk = FlextLdifQuirksServersApache()
        oc_def = "( 1.3.6.1.4.1.18060.0.4.1.3.100 NAME 'ads-directoryService' SUP top STRUCTURAL )"
        assert quirk.can_handle_objectclass(oc_def) is True

    def test_can_handle_objectclass_with_ads_name(self) -> None:
        """Test objectClass detection with ads- name."""
        quirk = FlextLdifQuirksServersApache()
        oc_def = "( 2.5.6.0 NAME 'ads-base' SUP top ABSTRACT )"
        assert quirk.can_handle_objectclass(oc_def) is True

    def test_can_handle_objectclass_negative(self) -> None:
        """Test objectClass detection rejects non-ApacheDS classes."""
        quirk = FlextLdifQuirksServersApache()
        oc_def = "( 2.5.6.6 NAME 'posixAccount' SUP top STRUCTURAL )"
        assert quirk.can_handle_objectclass(oc_def) is False

    def test_parse_objectclass_structural(self) -> None:
        """Test parsing STRUCTURAL objectClass."""
        quirk = FlextLdifQuirksServersApache()
        oc_def = "( 1.3.6.1.4.1.18060.0.4.1.3.100 NAME 'ads-directoryService' DESC 'Directory service' SUP top STRUCTURAL MUST ( cn $ ads-directoryServiceId ) MAY ( ads-enabled ) )"
        result = quirk.parse_objectclass(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert (
            oc_data[FlextLdifConstants.DictKeys.OID] == "1.3.6.1.4.1.18060.0.4.1.3.100"
        )
        assert oc_data[FlextLdifConstants.DictKeys.NAME] == "ads-directoryService"
        assert oc_data[FlextLdifConstants.DictKeys.KIND] == "STRUCTURAL"
        assert oc_data[FlextLdifConstants.DictKeys.SUP] == "top"
        must_attrs = oc_data[FlextLdifConstants.DictKeys.MUST]
        assert isinstance(must_attrs, list)
        assert "cn" in must_attrs
        assert "ads-directoryServiceId" in must_attrs
        may_attrs = oc_data[FlextLdifConstants.DictKeys.MAY]
        assert isinstance(may_attrs, list)
        assert "ads-enabled" in may_attrs

    def test_parse_objectclass_auxiliary(self) -> None:
        """Test parsing AUXILIARY objectClass."""
        quirk = FlextLdifQuirksServersApache()
        oc_def = "( 1.3.6.1.4.1.18060.0.4.1.3.200 NAME 'ads-partition' AUXILIARY MAY ( ads-partitionSuffix $ ads-contextEntry ) )"
        result = quirk.parse_objectclass(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data[FlextLdifConstants.DictKeys.KIND] == "AUXILIARY"

    def test_parse_objectclass_abstract(self) -> None:
        """Test parsing ABSTRACT objectClass."""
        quirk = FlextLdifQuirksServersApache()
        oc_def = "( 1.3.6.1.4.1.18060.0.4.1.3.1 NAME 'ads-base' ABSTRACT )"
        result = quirk.parse_objectclass(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data[FlextLdifConstants.DictKeys.KIND] == "ABSTRACT"

    def test_parse_objectclass_missing_oid(self) -> None:
        """Test parsing objectClass without OID fails."""
        quirk = FlextLdifQuirksServersApache()
        oc_def = "NAME 'ads-directoryService' SUP top STRUCTURAL"
        result = quirk.parse_objectclass(oc_def)

        assert result.is_failure
        assert result.error is not None
        assert "missing an OID" in result.error

    def test_convert_attribute_to_rfc(self) -> None:
        """Test converting Apache DS attribute to RFC format."""
        quirk = FlextLdifQuirksServersApache()
        attr_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.OID: "1.3.6.1.4.1.18060.0.4.1.2.100",
            FlextLdifConstants.DictKeys.NAME: "ads-enabled",
            FlextLdifConstants.DictKeys.DESC: "Enable flag",
            FlextLdifConstants.DictKeys.SYNTAX: "1.3.6.1.4.1.1466.115.121.1.7",
            FlextLdifConstants.DictKeys.SINGLE_VALUE: True,
        }
        result = quirk.convert_attribute_to_rfc(attr_data)

        assert result.is_success
        rfc_data = result.unwrap()
        assert (
            rfc_data[FlextLdifConstants.DictKeys.OID] == "1.3.6.1.4.1.18060.0.4.1.2.100"
        )
        assert rfc_data[FlextLdifConstants.DictKeys.NAME] == "ads-enabled"

    def test_convert_objectclass_to_rfc(self) -> None:
        """Test converting Apache DS objectClass to RFC format."""
        quirk = FlextLdifQuirksServersApache()
        oc_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.OID: "1.3.6.1.4.1.18060.0.4.1.3.100",
            FlextLdifConstants.DictKeys.NAME: "ads-directoryService",
            FlextLdifConstants.DictKeys.KIND: "STRUCTURAL",
            FlextLdifConstants.DictKeys.SUP: "top",
        }
        result = quirk.convert_objectclass_to_rfc(oc_data)

        assert result.is_success
        rfc_data = result.unwrap()
        assert (
            rfc_data[FlextLdifConstants.DictKeys.OID] == "1.3.6.1.4.1.18060.0.4.1.3.100"
        )

    def test_convert_attribute_from_rfc(self) -> None:
        """Test converting RFC attribute to Apache DS format."""
        quirk = FlextLdifQuirksServersApache()
        rfc_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.OID: "1.3.6.1.4.1.18060.0.4.1.2.100",
            FlextLdifConstants.DictKeys.NAME: "ads-enabled",
        }
        result = quirk.convert_attribute_from_rfc(rfc_data)

        assert result.is_success
        apache_data = result.unwrap()
        assert (
            apache_data[FlextLdifConstants.DictKeys.SERVER_TYPE]
            == FlextLdifConstants.LdapServers.APACHE_DIRECTORY
        )

    def test_convert_objectclass_from_rfc(self) -> None:
        """Test converting RFC objectClass to Apache DS format."""
        quirk = FlextLdifQuirksServersApache()
        rfc_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.OID: "1.3.6.1.4.1.18060.0.4.1.3.100",
            FlextLdifConstants.DictKeys.NAME: "ads-directoryService",
        }
        result = quirk.convert_objectclass_from_rfc(rfc_data)

        assert result.is_success
        apache_data = result.unwrap()
        assert (
            apache_data[FlextLdifConstants.DictKeys.SERVER_TYPE]
            == FlextLdifConstants.LdapServers.APACHE_DIRECTORY
        )

    def test_write_attribute_to_rfc(self) -> None:
        """Test writing attribute to RFC string format."""
        quirk = FlextLdifQuirksServersApache()
        attr_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.OID: "1.3.6.1.4.1.18060.0.4.1.2.100",
            FlextLdifConstants.DictKeys.NAME: "ads-enabled",
            FlextLdifConstants.DictKeys.DESC: "Enable flag",
            FlextLdifConstants.DictKeys.SYNTAX: "1.3.6.1.4.1.1466.115.121.1.7",
            FlextLdifConstants.DictKeys.SINGLE_VALUE: True,
        }
        result = quirk.write_attribute_to_rfc(attr_data)

        assert result.is_success
        attr_str = result.unwrap()
        assert "1.3.6.1.4.1.18060.0.4.1.2.100" in attr_str
        assert "ads-enabled" in attr_str
        assert "SINGLE-VALUE" in attr_str

    def test_write_objectclass_to_rfc(self) -> None:
        """Test writing objectClass to RFC string format."""
        quirk = FlextLdifQuirksServersApache()
        oc_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.OID: "1.3.6.1.4.1.18060.0.4.1.3.100",
            FlextLdifConstants.DictKeys.NAME: "ads-directoryService",
            FlextLdifConstants.DictKeys.KIND: "STRUCTURAL",
            FlextLdifConstants.DictKeys.SUP: "top",
            FlextLdifConstants.DictKeys.MUST: ["cn", "ads-directoryServiceId"],
            FlextLdifConstants.DictKeys.MAY: ["ads-enabled"],
        }
        result = quirk.write_objectclass_to_rfc(oc_data)

        assert result.is_success
        oc_str = result.unwrap()
        assert "1.3.6.1.4.1.18060.0.4.1.3.100" in oc_str
        assert "ads-directoryService" in oc_str
        assert "STRUCTURAL" in oc_str


class TestApacheDirectoryAclQuirks:
    """Tests for Apache Directory Server ACL quirk handling."""

    def test_acl_quirk_initialization(self) -> None:
        """Test ACL quirk initialization."""
        main_quirk = FlextLdifQuirksServersApache()
        acl_quirk = main_quirk.AclQuirk()
        assert acl_quirk.server_type == FlextLdifConstants.LdapServers.APACHE_DIRECTORY
        assert acl_quirk.priority == 15

    def test_can_handle_acl_with_ads_aci(self) -> None:
        """Test ACL detection with ads-aci attribute."""
        main_quirk = FlextLdifQuirksServersApache()
        acl_quirk = main_quirk.AclQuirk()
        acl_line = "ads-aci: ( version 3.0 ) ( deny grantAdd ) ( grantRemove )"
        assert acl_quirk.can_handle_acl(acl_line) is True

    def test_can_handle_acl_with_aci(self) -> None:
        """Test ACL detection with aci attribute."""
        main_quirk = FlextLdifQuirksServersApache()
        acl_quirk = main_quirk.AclQuirk()
        acl_line = "aci: ( version 3.0 ) ( deny grantAdd ) ( grantRemove )"
        assert acl_quirk.can_handle_acl(acl_line) is True

    def test_can_handle_acl_with_version_prefix(self) -> None:
        """Test ACL detection with version prefix."""
        main_quirk = FlextLdifQuirksServersApache()
        acl_quirk = main_quirk.AclQuirk()
        acl_line = "(version 3.0) (deny grantAdd) (grantRemove)"
        assert acl_quirk.can_handle_acl(acl_line) is True

    def test_can_handle_acl_negative(self) -> None:
        """Test ACL detection rejects non-ApacheDS ACLs."""
        main_quirk = FlextLdifQuirksServersApache()
        acl_quirk = main_quirk.AclQuirk()
        acl_line = "access to * by * read"
        assert acl_quirk.can_handle_acl(acl_line) is False

    def test_can_handle_acl_empty_line(self) -> None:
        """Test ACL detection rejects empty lines."""
        main_quirk = FlextLdifQuirksServersApache()
        acl_quirk = main_quirk.AclQuirk()
        acl_line = ""
        assert acl_quirk.can_handle_acl(acl_line) is False

    def test_parse_acl_success(self) -> None:
        """Test parsing Apache DS ACI definition."""
        main_quirk = FlextLdifQuirksServersApache()
        acl_quirk = main_quirk.AclQuirk()
        acl_line = "ads-aci: ( version 3.0 ) ( deny grantAdd ) ( grantRemove )"
        result = acl_quirk.parse_acl(acl_line)

        assert result.is_success
        acl_data = result.unwrap()
        assert (
            acl_data[FlextLdifConstants.DictKeys.TYPE]
            == FlextLdifConstants.DictKeys.ACL
        )
        assert (
            acl_data[FlextLdifConstants.DictKeys.FORMAT]
            == FlextLdifConstants.AclFormats.ACI
        )
        assert acl_data[FlextLdifConstants.DictKeys.ACL_ATTRIBUTE] == "ads-aci"

        data = acl_data[FlextLdifConstants.DictKeys.DATA]
        assert isinstance(data, dict)
        assert "clauses" in data
        clauses = data.get("clauses", [])
        assert isinstance(clauses, list)
        assert len(clauses) == 3

    def test_parse_acl_with_aci_attribute(self) -> None:
        """Test parsing ACI with aci attribute."""
        main_quirk = FlextLdifQuirksServersApache()
        acl_quirk = main_quirk.AclQuirk()
        acl_line = "aci: ( deny grantAdd )"
        result = acl_quirk.parse_acl(acl_line)

        assert result.is_success
        acl_data = result.unwrap()
        assert (
            acl_data[FlextLdifConstants.DictKeys.ACL_ATTRIBUTE]
            == FlextLdifConstants.DictKeys.ACI
        )

    def test_convert_acl_to_rfc(self) -> None:
        """Test converting Apache DS ACL to RFC format."""
        main_quirk = FlextLdifQuirksServersApache()
        acl_quirk = main_quirk.AclQuirk()
        acl_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.DictKeys.ACL,
            FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.ACI,
            FlextLdifConstants.DictKeys.DATA: {
                "clauses": ["( version 3.0 )", "( deny grantAdd )"],
                "content": "( version 3.0 ) ( deny grantAdd )",
            },
        }
        result = acl_quirk.convert_acl_to_rfc(acl_data)

        assert result.is_success
        rfc_acl = result.unwrap()
        assert (
            rfc_acl[FlextLdifConstants.DictKeys.FORMAT]
            == FlextLdifConstants.AclFormats.RFC_GENERIC
        )
        assert (
            rfc_acl[FlextLdifConstants.DictKeys.SOURCE_FORMAT]
            == FlextLdifConstants.AclFormats.ACI
        )

    def test_convert_acl_from_rfc(self) -> None:
        """Test converting RFC ACL to Apache DS format."""
        main_quirk = FlextLdifQuirksServersApache()
        acl_quirk = main_quirk.AclQuirk()
        rfc_acl: FlextLdifTypes.Dict = {
            FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.DictKeys.ACL,
            FlextLdifConstants.DictKeys.DATA: {"content": "( version 3.0 )"},
        }
        result = acl_quirk.convert_acl_from_rfc(rfc_acl)

        assert result.is_success
        apache_acl = result.unwrap()
        assert (
            apache_acl[FlextLdifConstants.DictKeys.FORMAT]
            == FlextLdifConstants.AclFormats.ACI
        )
        assert (
            apache_acl[FlextLdifConstants.DictKeys.TARGET_FORMAT]
            == FlextLdifConstants.DictKeys.ACI
        )

    def test_write_acl_to_rfc_with_content(self) -> None:
        """Test writing ACL with content to RFC string format."""
        main_quirk = FlextLdifQuirksServersApache()
        acl_quirk = main_quirk.AclQuirk()
        acl_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: "ads-aci",
            FlextLdifConstants.DictKeys.DATA: {
                "content": "( version 3.0 ) ( deny grantAdd )",
                "clauses": ["( version 3.0 )", "( deny grantAdd )"],
            },
        }
        result = acl_quirk.write_acl_to_rfc(acl_data)

        assert result.is_success
        acl_str = result.unwrap()
        assert "ads-aci:" in acl_str
        assert "( version 3.0 ) ( deny grantAdd )" in acl_str

    def test_write_acl_to_rfc_with_clauses_only(self) -> None:
        """Test writing ACL with clauses only to RFC string format."""
        main_quirk = FlextLdifQuirksServersApache()
        acl_quirk = main_quirk.AclQuirk()
        acl_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: FlextLdifConstants.DictKeys.ACI,
            FlextLdifConstants.DictKeys.DATA: {
                "clauses": ["( version 3.0 )", "( deny grantAdd )"],
            },
        }
        result = acl_quirk.write_acl_to_rfc(acl_data)

        assert result.is_success
        acl_str = result.unwrap()
        assert "aci:" in acl_str
        assert "( version 3.0 )" in acl_str
        assert "( deny grantAdd )" in acl_str

    def test_write_acl_to_rfc_empty(self) -> None:
        """Test writing empty ACL to RFC string format."""
        main_quirk = FlextLdifQuirksServersApache()
        acl_quirk = main_quirk.AclQuirk()
        acl_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: "ads-aci",
            FlextLdifConstants.DictKeys.DATA: {},
        }
        result = acl_quirk.write_acl_to_rfc(acl_data)

        assert result.is_success
        acl_str = result.unwrap()
        assert acl_str == "ads-aci:"


class TestApacheDirectoryEntryQuirks:
    """Tests for Apache Directory Server entry quirk handling."""

    def test_entry_quirk_initialization(self) -> None:
        """Test entry quirk initialization."""
        main_quirk = FlextLdifQuirksServersApache()
        entry_quirk = main_quirk.EntryQuirk()
        assert (
            entry_quirk.server_type == FlextLdifConstants.LdapServers.APACHE_DIRECTORY
        )
        assert entry_quirk.priority == 15

    def test_can_handle_entry_with_ou_config(self) -> None:
        """Test entry detection with ou=config DN marker."""
        main_quirk = FlextLdifQuirksServersApache()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "ou=config,dc=example,dc=com"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["organizationalUnit"]
        }
        assert entry_quirk.can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_ou_services(self) -> None:
        """Test entry detection with ou=services DN marker."""
        main_quirk = FlextLdifQuirksServersApache()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "ou=services,dc=example,dc=com"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["organizationalUnit"]
        }
        assert entry_quirk.can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_ou_system(self) -> None:
        """Test entry detection with ou=system DN marker."""
        main_quirk = FlextLdifQuirksServersApache()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "ou=system,dc=example,dc=com"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["organizationalUnit"]
        }
        assert entry_quirk.can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_ou_partitions(self) -> None:
        """Test entry detection with ou=partitions DN marker."""
        main_quirk = FlextLdifQuirksServersApache()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "ou=partitions,dc=example,dc=com"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["organizationalUnit"]
        }
        assert entry_quirk.can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_ads_attribute(self) -> None:
        """Test entry detection with ads- attribute prefix."""
        main_quirk = FlextLdifQuirksServersApache()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "cn=test,dc=example,dc=com"
        attributes: dict[str, object] = {
            "ads-enabled": ["TRUE"],
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["top"],
        }
        assert entry_quirk.can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_apacheds_attribute(self) -> None:
        """Test entry detection with apacheds attribute prefix."""
        main_quirk = FlextLdifQuirksServersApache()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "cn=test,dc=example,dc=com"
        attributes: dict[str, object] = {
            "apachedsSystemId": ["test"],
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["top"],
        }
        assert entry_quirk.can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_ads_objectclass(self) -> None:
        """Test entry detection with ads- objectClass."""
        main_quirk = FlextLdifQuirksServersApache()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "cn=test,dc=example,dc=com"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["top", "ads-directoryService"]
        }
        assert entry_quirk.can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_negative(self) -> None:
        """Test entry detection rejects non-ApacheDS entries."""
        main_quirk = FlextLdifQuirksServersApache()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "cn=user,dc=example,dc=com"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["person"],
            "cn": ["user"],
        }
        assert entry_quirk.can_handle_entry(entry_dn, attributes) is False

    def test_process_entry_config_entry(self) -> None:
        """Test processing ApacheDS config entry."""
        main_quirk = FlextLdifQuirksServersApache()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "ou=config,dc=example,dc=com"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["organizationalUnit"],
            "ou": ["config"],
            "ads-enabled": ["TRUE"],
        }
        result = entry_quirk.process_entry(entry_dn, attributes)

        assert result.is_success
        processed_entry = result.unwrap()
        assert processed_entry[FlextLdifConstants.DictKeys.DN] == entry_dn
        assert (
            processed_entry[FlextLdifConstants.DictKeys.SERVER_TYPE]
            == FlextLdifConstants.LdapServers.APACHE_DIRECTORY
        )
        assert processed_entry[FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY] is True

    def test_process_entry_non_config(self) -> None:
        """Test processing non-config ApacheDS entry."""
        main_quirk = FlextLdifQuirksServersApache()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "cn=test,ou=system,dc=example,dc=com"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["top", "ads-base"],
            "cn": ["test"],
        }
        result = entry_quirk.process_entry(entry_dn, attributes)

        assert result.is_success
        processed_entry = result.unwrap()
        assert processed_entry[FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY] is False

    def test_process_entry_with_binary_data(self) -> None:
        """Test processing entry with binary attribute data."""
        main_quirk = FlextLdifQuirksServersApache()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "cn=test,ou=system,dc=example,dc=com"
        binary_data = b"binary_value"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["top"],
            "cn": ["test"],
            "userCertificate": binary_data,
        }
        result = entry_quirk.process_entry(entry_dn, attributes)

        assert result.is_success
        processed_entry = result.unwrap()
        assert "userCertificate" in processed_entry
        cert_value = processed_entry["userCertificate"]
        assert isinstance(cert_value, str)
        assert cert_value == base64.b64encode(binary_data).decode("ascii")

    def test_convert_entry_to_rfc(self) -> None:
        """Test converting Apache DS entry to RFC format."""
        main_quirk = FlextLdifQuirksServersApache()
        entry_quirk = main_quirk.EntryQuirk()
        entry_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: "ou=config,dc=example,dc=com",
            FlextLdifConstants.DictKeys.SERVER_TYPE: FlextLdifConstants.LdapServers.APACHE_DIRECTORY,
            FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY: True,
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["organizationalUnit"],
            "ou": ["config"],
        }
        result = entry_quirk.convert_entry_to_rfc(entry_data)

        assert result.is_success
        rfc_entry = result.unwrap()
        assert FlextLdifConstants.DictKeys.SERVER_TYPE not in rfc_entry
        assert FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY not in rfc_entry
        assert (
            rfc_entry[FlextLdifConstants.DictKeys.DN] == "ou=config,dc=example,dc=com"
        )
        assert FlextLdifConstants.DictKeys.OBJECTCLASS in rfc_entry
