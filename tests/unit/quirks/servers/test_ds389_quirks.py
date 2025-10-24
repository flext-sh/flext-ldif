"""Tests for 389 Directory Server quirks implementation."""

from __future__ import annotations

import base64

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.servers.ds389_quirks import FlextLdifQuirksServersDs389


class TestDs389SchemaQuirks:
    """Tests for 389 Directory Server schema quirk handling."""

    def test_initialization(self) -> None:
        """Test 389 DS quirk initialization."""
        quirk = FlextLdifQuirksServersDs389()
        assert quirk.server_type == FlextLdifConstants.LdapServers.DS_389
        assert quirk.priority == 15

    def test_can_handle_attribute_with_ds389_oid(self) -> None:
        """Test attribute detection with 389 DS OID pattern."""
        quirk = FlextLdifQuirksServersDs389()
        attr_def = "( 2.16.840.1.113730.3.1.1 NAME 'nsslapd-suffix' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )"
        assert quirk.can_handle_attribute(attr_def) is True

    def test_can_handle_attribute_with_nsslapd_prefix(self) -> None:
        """Test attribute detection with nsslapd- prefix."""
        quirk = FlextLdifQuirksServersDs389()
        attr_def = (
            "( 1.2.3.4 NAME 'nsslapd-port' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )"
        )
        assert quirk.can_handle_attribute(attr_def) is True

    def test_can_handle_attribute_with_nsds_prefix(self) -> None:
        """Test attribute detection with nsds prefix."""
        quirk = FlextLdifQuirksServersDs389()
        attr_def = (
            "( 1.2.3.4 NAME 'nsds5ReplicaId' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )"
        )
        assert quirk.can_handle_attribute(attr_def) is True

    def test_can_handle_attribute_with_nsuniqueid(self) -> None:
        """Test attribute detection with nsuniqueid prefix."""
        quirk = FlextLdifQuirksServersDs389()
        attr_def = "( 1.2.3.4 NAME 'nsuniqueid' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        assert quirk.can_handle_attribute(attr_def) is True

    def test_can_handle_attribute_negative(self) -> None:
        """Test attribute detection rejects non-389 DS attributes."""
        quirk = FlextLdifQuirksServersDs389()
        attr_def = "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        assert quirk.can_handle_attribute(attr_def) is False

    def test_parse_attribute_success(self) -> None:
        """Test parsing 389 DS attribute definition."""
        quirk = FlextLdifQuirksServersDs389()
        attr_def = "( 2.16.840.1.113730.3.1.1 NAME 'nsslapd-suffix' DESC 'Directory suffix' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )"
        result = quirk.parse_attribute(attr_def)

        assert result.is_success
        attr_data = result.unwrap()
        assert attr_data[FlextLdifConstants.DictKeys.OID] == "2.16.840.1.113730.3.1.1"
        assert attr_data[FlextLdifConstants.DictKeys.NAME] == "nsslapd-suffix"
        assert attr_data[FlextLdifConstants.DictKeys.DESC] == "Directory suffix"
        assert (
            attr_data[FlextLdifConstants.DictKeys.SYNTAX]
            == "1.3.6.1.4.1.1466.115.121.1.12"
        )
        assert attr_data[FlextLdifConstants.DictKeys.SINGLE_VALUE] is True

    def test_parse_attribute_with_syntax_length(self) -> None:
        """Test parsing attribute with syntax length specification."""
        quirk = FlextLdifQuirksServersDs389()
        attr_def = "( 2.16.840.1.113730.3.1.2 NAME 'nsslapd-database' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
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
        quirk = FlextLdifQuirksServersDs389()
        attr_def = "NAME 'nsslapd-port' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27"
        result = quirk.parse_attribute(attr_def)

        assert result.is_failure
        assert result.error is not None
        assert "missing an OID" in result.error

    def test_can_handle_objectclass_with_ds389_oid(self) -> None:
        """Test objectClass detection with 389 DS OID."""
        quirk = FlextLdifQuirksServersDs389()
        oc_def = "( 2.16.840.1.113730.3.2.1 NAME 'nscontainer' SUP top STRUCTURAL )"
        assert quirk.can_handle_objectclass(oc_def) is True

    def test_can_handle_objectclass_with_ns_name(self) -> None:
        """Test objectClass detection with ns- name."""
        quirk = FlextLdifQuirksServersDs389()
        oc_def = "( 2.5.6.0 NAME 'nsperson' SUP top STRUCTURAL )"
        assert quirk.can_handle_objectclass(oc_def) is True

    def test_can_handle_objectclass_negative(self) -> None:
        """Test objectClass detection rejects non-389 DS classes."""
        quirk = FlextLdifQuirksServersDs389()
        oc_def = "( 2.5.6.6 NAME 'posixAccount' SUP top STRUCTURAL )"
        assert quirk.can_handle_objectclass(oc_def) is False

    def test_parse_objectclass_structural(self) -> None:
        """Test parsing STRUCTURAL objectClass."""
        quirk = FlextLdifQuirksServersDs389()
        oc_def = "( 2.16.840.1.113730.3.2.1 NAME 'nscontainer' DESC 'Container class' SUP top STRUCTURAL MUST ( cn ) MAY ( nsslapd-port ) )"
        result = quirk.parse_objectclass(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data[FlextLdifConstants.DictKeys.OID] == "2.16.840.1.113730.3.2.1"
        assert oc_data[FlextLdifConstants.DictKeys.NAME] == "nscontainer"
        assert oc_data[FlextLdifConstants.DictKeys.KIND] == "STRUCTURAL"
        assert oc_data[FlextLdifConstants.DictKeys.SUP] == "top"
        must_attrs = oc_data[FlextLdifConstants.DictKeys.MUST]
        assert isinstance(must_attrs, list)
        assert "cn" in must_attrs
        may_attrs = oc_data[FlextLdifConstants.DictKeys.MAY]
        assert isinstance(may_attrs, list)
        assert "nsslapd-port" in may_attrs

    def test_parse_objectclass_auxiliary(self) -> None:
        """Test parsing AUXILIARY objectClass."""
        quirk = FlextLdifQuirksServersDs389()
        oc_def = "( 2.16.840.1.113730.3.2.2 NAME 'nsds5replica' AUXILIARY MAY ( nsds5ReplicaId $ nsds5ReplicaRoot ) )"
        result = quirk.parse_objectclass(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data[FlextLdifConstants.DictKeys.KIND] == "AUXILIARY"

    def test_parse_objectclass_abstract(self) -> None:
        """Test parsing ABSTRACT objectClass."""
        quirk = FlextLdifQuirksServersDs389()
        oc_def = "( 2.16.840.1.113730.3.2.3 NAME 'nsds5base' ABSTRACT )"
        result = quirk.parse_objectclass(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data[FlextLdifConstants.DictKeys.KIND] == "ABSTRACT"

    def test_parse_objectclass_missing_oid(self) -> None:
        """Test parsing objectClass without OID fails."""
        quirk = FlextLdifQuirksServersDs389()
        oc_def = "NAME 'nscontainer' SUP top STRUCTURAL"
        result = quirk.parse_objectclass(oc_def)

        assert result.is_failure
        assert result.error is not None
        assert "missing an OID" in result.error

    def test_convert_attribute_to_rfc(self) -> None:
        """Test converting 389 DS attribute to RFC format."""
        quirk = FlextLdifQuirksServersDs389()
        attr_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.OID: "2.16.840.1.113730.3.1.1",
            FlextLdifConstants.DictKeys.NAME: "nsslapd-suffix",
            FlextLdifConstants.DictKeys.DESC: "Directory suffix",
            FlextLdifConstants.DictKeys.SYNTAX: "1.3.6.1.4.1.1466.115.121.1.12",
            FlextLdifConstants.DictKeys.SINGLE_VALUE: True,
        }
        result = quirk.convert_attribute_to_rfc(attr_data)

        assert result.is_success
        rfc_data = result.unwrap()
        assert rfc_data[FlextLdifConstants.DictKeys.OID] == "2.16.840.1.113730.3.1.1"
        assert rfc_data[FlextLdifConstants.DictKeys.NAME] == "nsslapd-suffix"

    def test_convert_objectclass_to_rfc(self) -> None:
        """Test converting 389 DS objectClass to RFC format."""
        quirk = FlextLdifQuirksServersDs389()
        oc_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.OID: "2.16.840.1.113730.3.2.1",
            FlextLdifConstants.DictKeys.NAME: "nscontainer",
            FlextLdifConstants.DictKeys.KIND: "STRUCTURAL",
            FlextLdifConstants.DictKeys.SUP: "top",
        }
        result = quirk.convert_objectclass_to_rfc(oc_data)

        assert result.is_success
        rfc_data = result.unwrap()
        assert rfc_data[FlextLdifConstants.DictKeys.OID] == "2.16.840.1.113730.3.2.1"

    def test_convert_attribute_from_rfc(self) -> None:
        """Test converting RFC attribute to 389 DS format."""
        quirk = FlextLdifQuirksServersDs389()
        rfc_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.OID: "2.16.840.1.113730.3.1.1",
            FlextLdifConstants.DictKeys.NAME: "nsslapd-suffix",
        }
        result = quirk.convert_attribute_from_rfc(rfc_data)

        assert result.is_success
        ds389_data = result.unwrap()
        assert (
            ds389_data[FlextLdifConstants.DictKeys.SERVER_TYPE]
            == FlextLdifConstants.LdapServers.DS_389
        )

    def test_convert_objectclass_from_rfc(self) -> None:
        """Test converting RFC objectClass to 389 DS format."""
        quirk = FlextLdifQuirksServersDs389()
        rfc_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.OID: "2.16.840.1.113730.3.2.1",
            FlextLdifConstants.DictKeys.NAME: "nscontainer",
        }
        result = quirk.convert_objectclass_from_rfc(rfc_data)

        assert result.is_success
        ds389_data = result.unwrap()
        assert (
            ds389_data[FlextLdifConstants.DictKeys.SERVER_TYPE]
            == FlextLdifConstants.LdapServers.DS_389
        )

    def test_write_attribute_to_rfc(self) -> None:
        """Test writing attribute to RFC string format."""
        quirk = FlextLdifQuirksServersDs389()
        attr_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.OID: "2.16.840.1.113730.3.1.1",
            FlextLdifConstants.DictKeys.NAME: "nsslapd-suffix",
            FlextLdifConstants.DictKeys.DESC: "Directory suffix",
            FlextLdifConstants.DictKeys.SYNTAX: "1.3.6.1.4.1.1466.115.121.1.12",
            FlextLdifConstants.DictKeys.SINGLE_VALUE: True,
        }
        result = quirk.write_attribute_to_rfc(attr_data)

        assert result.is_success
        attr_str = result.unwrap()
        assert "2.16.840.1.113730.3.1.1" in attr_str
        assert "nsslapd-suffix" in attr_str
        assert "SINGLE-VALUE" in attr_str

    def test_write_objectclass_to_rfc(self) -> None:
        """Test writing objectClass to RFC string format."""
        quirk = FlextLdifQuirksServersDs389()
        oc_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.OID: "2.16.840.1.113730.3.2.1",
            FlextLdifConstants.DictKeys.NAME: "nscontainer",
            FlextLdifConstants.DictKeys.KIND: "STRUCTURAL",
            FlextLdifConstants.DictKeys.SUP: "top",
            FlextLdifConstants.DictKeys.MUST: ["cn"],
            FlextLdifConstants.DictKeys.MAY: ["nsslapd-port"],
        }
        result = quirk.write_objectclass_to_rfc(oc_data)

        assert result.is_success
        oc_str = result.unwrap()
        assert "2.16.840.1.113730.3.2.1" in oc_str
        assert "nscontainer" in oc_str
        assert "STRUCTURAL" in oc_str


class TestDs389AclQuirks:
    """Tests for 389 Directory Server ACL quirk handling."""

    def test_acl_quirk_initialization(self) -> None:
        """Test ACL quirk initialization."""
        main_quirk = FlextLdifQuirksServersDs389()
        acl_quirk = main_quirk.AclQuirk()
        assert acl_quirk.server_type == FlextLdifConstants.LdapServers.DS_389
        assert acl_quirk.priority == 15

    def test_can_handle_acl_with_aci_attribute(self) -> None:
        """Test ACL detection with aci attribute."""
        main_quirk = FlextLdifQuirksServersDs389()
        acl_quirk = main_quirk.AclQuirk()
        acl_line = 'aci: (version 3.0; acl "Admin Access"; allow (all) userdn = "ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)'
        assert acl_quirk.can_handle_acl(acl_line) is True

    def test_can_handle_acl_with_version_prefix(self) -> None:
        """Test ACL detection with version prefix."""
        main_quirk = FlextLdifQuirksServersDs389()
        acl_quirk = main_quirk.AclQuirk()
        acl_line = '(version 3.0; acl "Admin Access"; allow (all) userdn = "ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)'
        assert acl_quirk.can_handle_acl(acl_line) is True

    def test_can_handle_acl_negative(self) -> None:
        """Test ACL detection rejects non-389 DS ACLs."""
        main_quirk = FlextLdifQuirksServersDs389()
        acl_quirk = main_quirk.AclQuirk()
        acl_line = "access to * by * read"
        assert acl_quirk.can_handle_acl(acl_line) is False

    def test_can_handle_acl_empty_line(self) -> None:
        """Test ACL detection rejects empty lines."""
        main_quirk = FlextLdifQuirksServersDs389()
        acl_quirk = main_quirk.AclQuirk()
        acl_line = ""
        assert acl_quirk.can_handle_acl(acl_line) is False

    def test_parse_acl_success(self) -> None:
        """Test parsing 389 DS ACI definition."""
        main_quirk = FlextLdifQuirksServersDs389()
        acl_quirk = main_quirk.AclQuirk()
        acl_line = 'aci: (version 3.0; acl "Admin Access"; allow (read, write, search) targetattr = "cn, ou" userdn = "ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)'
        result = acl_quirk.parse_acl(acl_line)

        assert result.is_success
        acl_data = result.unwrap()
        assert (
            acl_data[FlextLdifConstants.DictKeys.TYPE]
            == FlextLdifConstants.DictKeys.ACL
        )
        assert (
            acl_data[FlextLdifConstants.DictKeys.FORMAT]
            == FlextLdifConstants.AclFormats.DS389_ACL
        )
        assert (
            acl_data[FlextLdifConstants.DictKeys.ACL_ATTRIBUTE]
            == FlextLdifConstants.DictKeys.ACI
        )

        data = acl_data[FlextLdifConstants.DictKeys.DATA]
        assert hasattr(data, "name")
        assert data.get("version") == "3.0"
        assert data.get("acl_name") == "Admin Access"
        assert "read" in data.get("permissions", [])
        assert "write" in data.get("permissions", [])
        assert data.get("targetattr") == "cn, ou"

    def test_parse_acl_with_multiple_userdns(self) -> None:
        """Test parsing ACI with multiple userdn clauses."""
        main_quirk = FlextLdifQuirksServersDs389()
        acl_quirk = main_quirk.AclQuirk()
        acl_line = 'aci: (version 3.0; acl "Multi User"; allow (read) userdn = "ldap:///cn=user1,dc=example,dc=com" userdn = "ldap:///cn=user2,dc=example,dc=com";)'
        result = acl_quirk.parse_acl(acl_line)

        assert result.is_success
        acl_data = result.unwrap()
        data = acl_data[FlextLdifConstants.DictKeys.DATA]
        assert hasattr(data, "name")
        userdns = data.get("userdns", [])
        assert len(userdns) == 2

    def test_convert_acl_to_rfc(self) -> None:
        """Test converting 389 DS ACL to RFC format."""
        main_quirk = FlextLdifQuirksServersDs389()
        acl_quirk = main_quirk.AclQuirk()
        acl_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.DictKeys.ACL,
            FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.DS389_ACL,
            FlextLdifConstants.DictKeys.DATA: {
                "version": "3.0",
                "acl_name": "Admin Access",
                "permissions": ["read", "write"],
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
            == FlextLdifConstants.AclFormats.DS389_ACL
        )

    def test_convert_acl_from_rfc(self) -> None:
        """Test converting RFC ACL to 389 DS format."""
        main_quirk = FlextLdifQuirksServersDs389()
        acl_quirk = main_quirk.AclQuirk()
        rfc_acl: dict[str, object] = {
            FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.DictKeys.ACL,
            FlextLdifConstants.DictKeys.DATA: {"version": "3.0"},
        }
        result = acl_quirk.convert_acl_from_rfc(rfc_acl)

        assert result.is_success
        ds389_acl = result.unwrap()
        assert (
            ds389_acl[FlextLdifConstants.DictKeys.FORMAT]
            == FlextLdifConstants.AclFormats.DS389_ACL
        )
        assert (
            ds389_acl[FlextLdifConstants.DictKeys.TARGET_FORMAT]
            == FlextLdifConstants.DictKeys.ACI
        )

    def test_write_acl_to_rfc_with_content(self) -> None:
        """Test writing ACL with content to RFC string format."""
        main_quirk = FlextLdifQuirksServersDs389()
        acl_quirk = main_quirk.AclQuirk()
        acl_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: FlextLdifConstants.DictKeys.ACI,
            FlextLdifConstants.DictKeys.DATA: {
                "content": '(version 3.0; acl "Admin"; allow (read) userdn = "ldap:///cn=REDACTED_LDAP_BIND_PASSWORD";)',
            },
        }
        result = acl_quirk.write_acl_to_rfc(acl_data)

        assert result.is_success
        acl_str = result.unwrap()
        assert "aci:" in acl_str
        assert "version 3.0" in acl_str

    def test_write_acl_to_rfc_from_structured(self) -> None:
        """Test writing ACL from structured fields to RFC string format."""
        main_quirk = FlextLdifQuirksServersDs389()
        acl_quirk = main_quirk.AclQuirk()
        acl_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: FlextLdifConstants.DictKeys.ACI,
            FlextLdifConstants.DictKeys.DATA: {
                "version": "3.0",
                "acl_name": "Admin Access",
                "permissions": ["read", "write"],
                "targetattr": "cn",
                "userdns": ["ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"],
            },
        }
        result = acl_quirk.write_acl_to_rfc(acl_data)

        assert result.is_success
        acl_str = result.unwrap()
        assert "aci:" in acl_str
        assert "version 3.0" in acl_str
        assert "Admin Access" in acl_str
        assert "read" in acl_str
        assert "targetattr" in acl_str

    def test_write_acl_to_rfc_empty(self) -> None:
        """Test writing empty ACL to RFC string format."""
        main_quirk = FlextLdifQuirksServersDs389()
        acl_quirk = main_quirk.AclQuirk()
        acl_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: FlextLdifConstants.DictKeys.ACI,
            FlextLdifConstants.DictKeys.DATA: {},
        }
        result = acl_quirk.write_acl_to_rfc(acl_data)

        assert result.is_success
        acl_str = result.unwrap()
        assert acl_str == "aci:"


class TestDs389EntryQuirks:
    """Tests for 389 Directory Server entry quirk handling."""

    def test_entry_quirk_initialization(self) -> None:
        """Test entry quirk initialization."""
        main_quirk = FlextLdifQuirksServersDs389()
        entry_quirk = main_quirk.EntryQuirk()
        assert entry_quirk.server_type == FlextLdifConstants.LdapServers.DS_389
        assert entry_quirk.priority == 15

    def test_can_handle_entry_with_cn_config(self) -> None:
        """Test entry detection with cn=config DN marker."""
        main_quirk = FlextLdifQuirksServersDs389()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "cn=config"
        attributes: dict[str, object] = {"objectclass": ["nscontainer"]}
        assert entry_quirk.can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_cn_monitor(self) -> None:
        """Test entry detection with cn=monitor DN marker."""
        main_quirk = FlextLdifQuirksServersDs389()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "cn=monitor"
        attributes: dict[str, object] = {"objectclass": ["top"]}
        assert entry_quirk.can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_cn_changelog(self) -> None:
        """Test entry detection with cn=changelog DN marker."""
        main_quirk = FlextLdifQuirksServersDs389()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "cn=changelog"
        attributes: dict[str, object] = {"objectclass": ["top"]}
        assert entry_quirk.can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_nsslapd_attribute(self) -> None:
        """Test entry detection with nsslapd- attribute prefix."""
        main_quirk = FlextLdifQuirksServersDs389()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "cn=test,dc=example,dc=com"
        attributes: dict[str, object] = {
            "nsslapd-port": ["389"],
            "objectclass": ["top"],
        }
        assert entry_quirk.can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_nsds_attribute(self) -> None:
        """Test entry detection with nsds attribute prefix."""
        main_quirk = FlextLdifQuirksServersDs389()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "cn=test,dc=example,dc=com"
        attributes: dict[str, object] = {
            "nsds5ReplicaId": ["1"],
            "objectclass": ["top"],
        }
        assert entry_quirk.can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_nsuniqueid_attribute(self) -> None:
        """Test entry detection with nsuniqueid attribute."""
        main_quirk = FlextLdifQuirksServersDs389()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "cn=test,dc=example,dc=com"
        attributes: dict[str, object] = {
            "nsuniqueid": ["12345"],
            "objectclass": ["top"],
        }
        assert entry_quirk.can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_ns_objectclass(self) -> None:
        """Test entry detection with ns- objectClass."""
        main_quirk = FlextLdifQuirksServersDs389()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "cn=test,dc=example,dc=com"
        attributes: dict[str, object] = {"objectclass": ["top", "nscontainer"]}
        assert entry_quirk.can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_negative(self) -> None:
        """Test entry detection rejects non-389 DS entries."""
        main_quirk = FlextLdifQuirksServersDs389()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "cn=user,dc=example,dc=com"
        attributes: dict[str, object] = {"objectclass": ["person"], "cn": ["user"]}
        assert entry_quirk.can_handle_entry(entry_dn, attributes) is False

    def test_process_entry_config_entry(self) -> None:
        """Test processing 389 DS config entry."""
        main_quirk = FlextLdifQuirksServersDs389()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "cn=config"
        attributes: dict[str, object] = {
            "objectclass": ["nscontainer"],
            "cn": ["config"],
            "nsslapd-port": ["389"],
        }
        result = entry_quirk.process_entry(entry_dn, attributes)

        assert result.is_success
        processed_entry = result.unwrap()
        assert processed_entry[FlextLdifConstants.DictKeys.DN] == entry_dn
        assert (
            processed_entry[FlextLdifConstants.DictKeys.SERVER_TYPE]
            == FlextLdifConstants.LdapServers.DS_389
        )
        assert processed_entry[FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY] is True

    def test_process_entry_non_config(self) -> None:
        """Test processing non-config 389 DS entry."""
        main_quirk = FlextLdifQuirksServersDs389()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "cn=test,dc=example,dc=com"
        attributes: dict[str, object] = {
            "objectclass": ["top", "nscontainer"],
            "cn": ["test"],
        }
        result = entry_quirk.process_entry(entry_dn, attributes)

        assert result.is_success
        processed_entry = result.unwrap()
        assert processed_entry[FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY] is False

    def test_process_entry_with_binary_data(self) -> None:
        """Test processing entry with binary attribute data."""
        main_quirk = FlextLdifQuirksServersDs389()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "cn=test,dc=example,dc=com"
        binary_data = b"binary_value"
        attributes: dict[str, object] = {
            "objectclass": ["top"],
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
        """Test converting 389 DS entry to RFC format."""
        main_quirk = FlextLdifQuirksServersDs389()
        entry_quirk = main_quirk.EntryQuirk()
        entry_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: "cn=config",
            FlextLdifConstants.DictKeys.SERVER_TYPE: FlextLdifConstants.LdapServers.DS_389,
            FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY: True,
            "objectclass": ["nscontainer"],
            "cn": ["config"],
        }
        result = entry_quirk.convert_entry_to_rfc(entry_data)

        assert result.is_success
        rfc_entry = result.unwrap()
        assert FlextLdifConstants.DictKeys.SERVER_TYPE not in rfc_entry
        assert FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY not in rfc_entry
        assert rfc_entry[FlextLdifConstants.DictKeys.DN] == "cn=config"
        assert "objectclass" in rfc_entry
