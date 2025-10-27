"""Tests for 389 Directory Server quirks implementation."""

from __future__ import annotations

import base64

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
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
        assert attr_data.oid == "2.16.840.1.113730.3.1.1"
        assert attr_data.name == "nsslapd-suffix"
        assert attr_data.desc == "Directory suffix"
        assert attr_data.syntax == "1.3.6.1.4.1.1466.115.121.1.12"
        assert attr_data.single_value is True

    def test_parse_attribute_with_syntax_length(self) -> None:
        """Test parsing attribute with syntax length specification."""
        quirk = FlextLdifQuirksServersDs389()
        attr_def = "( 2.16.840.1.113730.3.1.2 NAME 'nsslapd-database' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        result = quirk.parse_attribute(attr_def)

        assert result.is_success
        attr_data = result.unwrap()
        assert attr_data.syntax == "1.3.6.1.4.1.1466.115.121.1.15"
        assert attr_data.length == 256

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
        assert oc_data.oid == "2.16.840.1.113730.3.2.1"
        assert oc_data.name == "nscontainer"
        assert oc_data.kind == "STRUCTURAL"
        assert oc_data.sup == "top"
        must_attrs = oc_data.must
        assert isinstance(must_attrs, list)
        assert "cn" in must_attrs
        may_attrs = oc_data.may
        assert isinstance(may_attrs, list)
        assert "nsslapd-port" in may_attrs

    def test_parse_objectclass_auxiliary(self) -> None:
        """Test parsing AUXILIARY objectClass."""
        quirk = FlextLdifQuirksServersDs389()
        oc_def = "( 2.16.840.1.113730.3.2.2 NAME 'nsds5replica' AUXILIARY MAY ( nsds5ReplicaId $ nsds5ReplicaRoot ) )"
        result = quirk.parse_objectclass(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data.kind == "AUXILIARY"

    def test_parse_objectclass_abstract(self) -> None:
        """Test parsing ABSTRACT objectClass."""
        quirk = FlextLdifQuirksServersDs389()
        oc_def = "( 2.16.840.1.113730.3.2.3 NAME 'nsds5base' ABSTRACT )"
        result = quirk.parse_objectclass(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data.kind == "ABSTRACT"

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
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113730.3.1.1",
            name="nsslapd-suffix",
            desc="Directory suffix",
            syntax="1.3.6.1.4.1.1466.115.121.1.12",
            single_value=True,
        )
        result = quirk.convert_attribute_to_rfc(attr_data)

        assert result.is_success
        rfc_data = result.unwrap()
        assert rfc_data.oid == "2.16.840.1.113730.3.1.1"
        assert rfc_data.name == "nsslapd-suffix"

    def test_convert_objectclass_to_rfc(self) -> None:
        """Test converting 389 DS objectClass to RFC format."""
        quirk = FlextLdifQuirksServersDs389()
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.16.840.1.113730.3.2.1",
            name="nscontainer",
            kind="STRUCTURAL",
            sup="top",
        )
        result = quirk.convert_objectclass_to_rfc(oc_data)

        assert result.is_success
        rfc_data = result.unwrap()
        assert rfc_data.oid == "2.16.840.1.113730.3.2.1"

    def test_convert_attribute_from_rfc(self) -> None:
        """Test converting RFC attribute to 389 DS format."""
        quirk = FlextLdifQuirksServersDs389()
        rfc_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113730.3.1.1",
            name="nsslapd-suffix",
        )
        result = quirk.convert_attribute_from_rfc(rfc_data)

        assert result.is_success
        ds389_data = result.unwrap()
        # convert_attribute_from_rfc now returns SchemaAttribute model
        assert ds389_data.metadata is not None
        assert ds389_data.metadata.quirk_type == "389ds"
        assert ds389_data.oid == rfc_data.oid

    def test_convert_objectclass_from_rfc(self) -> None:
        """Test converting RFC objectClass to 389 DS format."""
        quirk = FlextLdifQuirksServersDs389()
        rfc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.16.840.1.113730.3.2.1",
            name="nscontainer",
        )
        result = quirk.convert_objectclass_from_rfc(rfc_data)

        assert result.is_success
        ds389_data = result.unwrap()
        # convert_objectclass_from_rfc now returns SchemaObjectClass model
        assert ds389_data.metadata is not None
        assert ds389_data.metadata.quirk_type == "389ds"
        assert ds389_data.oid == rfc_data.oid

    def test_write_objectclass_to_rfc(self) -> None:
        """Test writing objectClass to RFC string format."""
        quirk = FlextLdifQuirksServersDs389()
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.16.840.1.113730.3.2.1",
            name="nscontainer",
            kind="STRUCTURAL",
            sup="top",
            must=["cn"],
            may=["nsslapd-port"],
        )
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
        acl_line = 'aci: (version 3.0; acl "Admin Access"; allow (all) userdn = "ldap:///cn=admin,dc=example,dc=com";)'
        assert acl_quirk.can_handle_acl(acl_line) is True

    def test_can_handle_acl_with_version_prefix(self) -> None:
        """Test ACL detection with version prefix."""
        main_quirk = FlextLdifQuirksServersDs389()
        acl_quirk = main_quirk.AclQuirk()
        acl_line = '(version 3.0; acl "Admin Access"; allow (all) userdn = "ldap:///cn=admin,dc=example,dc=com";)'
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
        acl_line = 'aci: (version 3.0; acl "Admin Access"; allow (read, write, search) targetattr = "cn, ou" userdn = "ldap:///cn=admin,dc=example,dc=com";)'
        result = acl_quirk.parse_acl(acl_line)

        assert result.is_success
        acl_data = result.unwrap()
        # Check basic ACL properties
        assert acl_data.server_type == "389ds"
        assert acl_data.name == "Admin Access"
        assert acl_data.raw_acl == acl_line
        # Check target attributes
        assert acl_data.target is not None
        assert acl_data.target.target_dn == "*"
        assert set(acl_data.target.attributes or []) == {"cn", "ou"}
        # Check subject
        assert acl_data.subject is not None
        assert acl_data.subject.subject_type == "userdn"
        # Check permissions
        assert acl_data.permissions is not None
        assert acl_data.permissions.read is True
        assert acl_data.permissions.write is True
        assert acl_data.permissions.search is True

    def test_parse_acl_with_multiple_userdns(self) -> None:
        """Test parsing ACI with multiple userdn clauses."""
        main_quirk = FlextLdifQuirksServersDs389()
        acl_quirk = main_quirk.AclQuirk()
        acl_line = 'aci: (version 3.0; acl "Multi User"; allow (read) userdn = "ldap:///cn=user1,dc=example,dc=com" userdn = "ldap:///cn=user2,dc=example,dc=com";)'
        result = acl_quirk.parse_acl(acl_line)

        assert result.is_success
        acl_data = result.unwrap()
        # Check that multiple userdn values are captured in the first one
        assert acl_data.name == "Multi User"
        assert acl_data.subject is not None
        # Note: Current implementation only captures first userdn, not multiple
        # This is expected as Acl model has single subject
        assert acl_data.permissions is not None
        assert acl_data.permissions.read is True

    def test_convert_acl_to_rfc(self) -> None:
        """Test converting 389 DS ACL to RFC format."""
        main_quirk = FlextLdifQuirksServersDs389()
        acl_quirk = main_quirk.AclQuirk()
        acl_data = FlextLdifModels.Acl(
            name="Admin Access",
            target=FlextLdifModels.AclTarget(target_dn="dc=example,dc=com"),
            subject=FlextLdifModels.AclSubject(
                subject_type="user", subject_value="cn=admin,dc=example,dc=com"
            ),
            permissions=FlextLdifModels.AclPermissions(read=True, write=True),
            server_type="389ds",
            raw_acl='aci: (version 3.0; acl "Admin Access"; allow (read, write) userdn = "ldap:///cn=admin,dc=example,dc=com";)',
        )
        result = acl_quirk.convert_acl_to_rfc(acl_data)

        assert result.is_success
        rfc_acl = result.unwrap()
        # Verify it's still an Acl model after conversion
        assert isinstance(rfc_acl, FlextLdifModels.Acl)

    def test_convert_acl_from_rfc(self) -> None:
        """Test converting RFC ACL to 389 DS format."""
        main_quirk = FlextLdifQuirksServersDs389()
        acl_quirk = main_quirk.AclQuirk()
        rfc_acl = FlextLdifModels.Acl(
            name="Admin Access",
            target=FlextLdifModels.AclTarget(target_dn="dc=example,dc=com"),
            subject=FlextLdifModels.AclSubject(
                subject_type="user", subject_value="cn=admin,dc=example,dc=com"
            ),
            permissions=FlextLdifModels.AclPermissions(read=True),
            server_type="generic",
            raw_acl="",
        )
        result = acl_quirk.convert_acl_from_rfc(rfc_acl)

        assert result.is_success
        ds389_acl = result.unwrap()
        # Verify it's still an Acl model and server_type changed to 389ds
        assert isinstance(ds389_acl, FlextLdifModels.Acl)
        assert ds389_acl.server_type == "389ds"

    def test_write_acl_to_rfc_with_content(self) -> None:
        """Test writing ACL with content to RFC string format."""
        main_quirk = FlextLdifQuirksServersDs389()
        acl_quirk = main_quirk.AclQuirk()
        # Create proper Acl model instance with raw_acl
        acl_data = FlextLdifModels.Acl(
            name="Admin",
            target=FlextLdifModels.AclTarget(target_dn="*", attributes=[]),
            subject=FlextLdifModels.AclSubject(
                subject_type="userdn", subject_value="ldap:///cn=admin"
            ),
            permissions=FlextLdifModels.AclPermissions(read=True),
            server_type="389ds",
            raw_acl='(version 3.0; acl "Admin"; allow (read) userdn = "ldap:///cn=admin";)',
        )
        result = acl_quirk.write_acl_to_rfc(acl_data)

        assert result.is_success
        acl_str = result.unwrap()
        assert "version 3.0" in acl_str

    def test_write_acl_to_rfc_from_structured(self) -> None:
        """Test writing ACL from structured fields to RFC string format."""
        main_quirk = FlextLdifQuirksServersDs389()
        acl_quirk = main_quirk.AclQuirk()
        # Create proper Acl model instance
        acl_data = FlextLdifModels.Acl(
            name="Admin Access",
            target=FlextLdifModels.AclTarget(target_dn="*", attributes=["cn"]),
            subject=FlextLdifModels.AclSubject(
                subject_type="userdn",
                subject_value="ldap:///cn=admin,dc=example,dc=com",
            ),
            permissions=FlextLdifModels.AclPermissions(
                read=True,
                write=True,
            ),
            server_type="389ds",
        )
        result = acl_quirk.write_acl_to_rfc(acl_data)

        assert result.is_success
        acl_str = result.unwrap()
        assert "aci:" in acl_str
        assert "Admin Access" in acl_str
        assert "read" in acl_str or "write" in acl_str

    def test_write_acl_to_rfc_empty(self) -> None:
        """Test writing empty ACL to RFC string format."""
        main_quirk = FlextLdifQuirksServersDs389()
        acl_quirk = main_quirk.AclQuirk()
        # Create minimal Acl model instance
        acl_data = FlextLdifModels.Acl(
            name="",
            target=FlextLdifModels.AclTarget(target_dn="*"),
            subject=FlextLdifModels.AclSubject(subject_type="user", subject_value="*"),
            permissions=FlextLdifModels.AclPermissions(),
            server_type="389ds",
        )
        result = acl_quirk.write_acl_to_rfc(acl_data)

        assert result.is_success
        acl_str = result.unwrap()
        assert "aci:" in acl_str


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
