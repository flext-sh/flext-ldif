"""Tests for 389 Directory Server quirks implementation."""

from __future__ import annotations

import base64

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.ds389 import FlextLdifServersDs389

class TestDs389Schemas:
    """Tests for 389 Directory Server schema quirk handling."""

    def test_initialization(self) -> None:
        """Test 389 DS quirk initialization."""
        quirk = FlextLdifServersDs389()
        # server_type and priority are ClassVar - access via Constants
        assert FlextLdifServersDs389.Constants.SERVER_TYPE == "389ds"
        assert FlextLdifServersDs389.Constants.PRIORITY == 15
        # Verify class-level attributes are set from Constants
        assert FlextLdifServersDs389.server_type == "389ds"  # ClassVar from Constants
        assert FlextLdifServersDs389.priority == 15  # ClassVar from Constants

    def test_can_handle_attribute_with_ds389_oid(self) -> None:
        """Test attribute detection with 389 DS OID pattern."""
        quirk = FlextLdifServersDs389()
        attr_def = "( 2.16.840.1.113730.3.1.1 NAME 'nsslapd-suffix' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )"

        # Parse string definition into model object
        parse_result = quirk.parse(attr_def)
        assert parse_result.is_success, (
            f"Failed to parse attribute: {parse_result.error}"
        )
        parse_result.unwrap()

        # Test with the model object
        assert quirk._can_handle_attribute(attr_def) is True

    def test_can_handle_attribute_with_nsslapd_prefix(self) -> None:
        """Test attribute detection with nsslapd- prefix."""
        quirk = FlextLdifServersDs389()
        attr_def = (
            "( 1.2.3.4 NAME 'nsslapd-port' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )"
        )

        # Parse string definition into model object
        parse_result = quirk.parse(attr_def)
        assert parse_result.is_success, (
            f"Failed to parse attribute: {parse_result.error}"
        )
        parse_result.unwrap()

        # Test with the model object
        assert quirk._can_handle_attribute(attr_def) is True

    def test_can_handle_attribute_with_nsds_prefix(self) -> None:
        """Test attribute detection with nsds prefix."""
        quirk = FlextLdifServersDs389()
        attr_def = (
            "( 1.2.3.4 NAME 'nsds5ReplicaId' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )"
        )

        # Parse string definition into model object
        parse_result = quirk.parse(attr_def)
        assert parse_result.is_success, (
            f"Failed to parse attribute: {parse_result.error}"
        )
        parse_result.unwrap()

        # Test with the model object
        assert quirk._can_handle_attribute(attr_def) is True

    def test_can_handle_attribute_with_nsuniqueid(self) -> None:
        """Test attribute detection with nsuniqueid prefix."""
        quirk = FlextLdifServersDs389()
        attr_def = "( 1.2.3.4 NAME 'nsuniqueid' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"

        # Parse string definition into model object
        parse_result = quirk.parse(attr_def)
        assert parse_result.is_success, (
            f"Failed to parse attribute: {parse_result.error}"
        )
        parse_result.unwrap()

        # Test with the model object
        assert quirk._can_handle_attribute(attr_def) is True

    def test_can_handle_attribute_negative(self) -> None:
        """Test attribute detection rejects non-389 DS attributes."""
        quirk = FlextLdifServersDs389()
        attr_def = "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"

        # Parse string definition into model object
        parse_result = quirk.parse(attr_def)
        assert parse_result.is_success, (
            f"Failed to parse attribute: {parse_result.error}"
        )
        parse_result.unwrap()

        # Test with the model object
        assert quirk._can_handle_attribute(attr_def) is False

    def test_parse_attribute_success(self) -> None:
        """Test parsing 389 DS attribute definition."""
        quirk = FlextLdifServersDs389()
        attr_def = "( 2.16.840.1.113730.3.1.1 NAME 'nsslapd-suffix' DESC 'Directory suffix' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )"
        result = quirk.parse(attr_def)

        assert result.is_success
        attr_data = result.unwrap()
        assert attr_data.oid == "2.16.840.1.113730.3.1.1"
        assert attr_data.name == "nsslapd-suffix"
        assert attr_data.desc == "Directory suffix"
        assert attr_data.syntax == "1.3.6.1.4.1.1466.115.121.1.12"
        assert attr_data.single_value is True

    def test_parse_attribute_with_syntax_length(self) -> None:
        """Test parsing attribute with syntax length specification."""
        quirk = FlextLdifServersDs389()
        attr_def = "( 2.16.840.1.113730.3.1.2 NAME 'nsslapd-database' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        result = quirk.parse(attr_def)

        assert result.is_success
        attr_data = result.unwrap()
        assert attr_data.syntax == "1.3.6.1.4.1.1466.115.121.1.15"
        assert attr_data.length == 256

    def test_parse_attribute_missing_oid(self) -> None:
        """Test parsing attribute without OID fails."""
        quirk = FlextLdifServersDs389()
        attr_def = "NAME 'nsslapd-port' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27"
        result = quirk.parse(attr_def)

        assert result.is_failure
        assert result.error is not None
        assert "missing an OID" in result.error

    def test_can_handle_objectclass_with_ds389_oid(self) -> None:
        """Test objectClass detection with 389 DS OID."""
        quirk = FlextLdifServersDs389()
        oc_def = "( 2.16.840.1.113730.3.2.1 NAME 'nscontainer' SUP top STRUCTURAL )"

        # Parse string definition into model object
        parse_result = quirk.parse(oc_def)
        assert parse_result.is_success, (
            f"Failed to parse objectClass: {parse_result.error}"
        )
        parse_result.unwrap()

        # Test with the model object
        assert quirk._can_handle_objectclass(oc_def) is True

    def test_can_handle_objectclass_with_ns_name(self) -> None:
        """Test objectClass detection with ns- name."""
        quirk = FlextLdifServersDs389()
        oc_def = "( 2.5.6.0 NAME 'nsperson' SUP top STRUCTURAL )"

        # Parse string definition into model object
        parse_result = quirk.parse(oc_def)
        assert parse_result.is_success, (
            f"Failed to parse objectClass: {parse_result.error}"
        )
        parse_result.unwrap()

        # Test with the model object
        assert quirk._can_handle_objectclass(oc_def) is True

    def test_can_handle_objectclass_negative(self) -> None:
        """Test objectClass detection rejects non-389 DS classes."""
        quirk = FlextLdifServersDs389()
        oc_def = "( 2.5.6.6 NAME 'posixAccount' SUP top STRUCTURAL )"

        # Parse string definition into model object
        parse_result = quirk.parse(oc_def)
        assert parse_result.is_success, (
            f"Failed to parse objectClass: {parse_result.error}"
        )
        parse_result.unwrap()

        # Test with the model object
        assert quirk._can_handle_objectclass(oc_def) is False

    def test_parse_objectclass_structural(self) -> None:
        """Test parsing STRUCTURAL objectClass."""
        quirk = FlextLdifServersDs389()
        oc_def = "( 2.16.840.1.113730.3.2.1 NAME 'nscontainer' DESC 'Container class' SUP top STRUCTURAL MUST ( cn ) MAY ( nsslapd-port ) )"
        result = quirk.parse(oc_def)

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
        quirk = FlextLdifServersDs389()
        oc_def = "( 2.16.840.1.113730.3.2.2 NAME 'nsds5replica' AUXILIARY MAY ( nsds5ReplicaId $ nsds5ReplicaRoot ) )"
        result = quirk.parse(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data.kind == "AUXILIARY"

    def test_parse_objectclass_abstract(self) -> None:
        """Test parsing ABSTRACT objectClass."""
        quirk = FlextLdifServersDs389()
        oc_def = "( 2.16.840.1.113730.3.2.3 NAME 'nsds5base' ABSTRACT )"
        result = quirk.parse(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data.kind == "ABSTRACT"

    def test_parse_objectclass_missing_oid(self) -> None:
        """Test parsing objectClass without OID fails."""
        quirk = FlextLdifServersDs389()
        oc_def = "NAME 'nscontainer' SUP top STRUCTURAL"
        result = quirk.parse(oc_def)

        assert result.is_failure
        assert result.error is not None
        assert "missing an OID" in result.error

    def test_write_objectclass_to_rfc(self) -> None:
        """Test writing objectClass to RFC string format."""
        quirk = FlextLdifServersDs389()
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.16.840.1.113730.3.2.1",
            name="nscontainer",
            kind="STRUCTURAL",
            sup="top",
            must=["cn"],
            may=["nsslapd-port"],
        )
        result = quirk.write(oc_data)

        assert result.is_success
        oc_str = result.unwrap()
        assert "2.16.840.1.113730.3.2.1" in oc_str
        assert "nscontainer" in oc_str
        assert "STRUCTURAL" in oc_str

class TestDs389Acls:
    """Tests for 389 Directory Server ACL quirk handling."""

    def test_acl_quirk_initialization(self) -> None:
        """Test ACL quirk initialization."""
        main_quirk = FlextLdifServersDs389()
        acl_quirk = main_quirk.acl
        assert acl_quirk is not None

    def test__can_handle_with_aci_attribute(self) -> None:
        """Test ACL detection with aci attribute."""
        main_quirk = FlextLdifServersDs389()
        acl_quirk = main_quirk.acl
        acl_line = 'aci: (version 3.0; acl "Admin Access"; allow (all) userdn = "ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)'
        # Parse string ACL into model object

        parse_result = acl_quirk.parse(acl_line)

        assert parse_result.is_success, f"Failed to parse ACL: {parse_result.error}"

        parse_result.unwrap()

        # Test with the model object

        assert acl_quirk._can_handle(acl_line) is True

    def test__can_handle_with_version_prefix(self) -> None:
        """Test ACL detection with version prefix."""
        main_quirk = FlextLdifServersDs389()
        acl_quirk = main_quirk.acl
        acl_line = '(version 3.0; acl "Admin Access"; allow (all) userdn = "ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)'
        # Parse string ACL into model object

        parse_result = acl_quirk.parse(acl_line)

        assert parse_result.is_success, f"Failed to parse ACL: {parse_result.error}"

        parse_result.unwrap()

        # Test with the model object

        assert acl_quirk._can_handle(acl_line) is True

    def test__can_handle_negative(self) -> None:
        """Test ACL detection rejects non-389 DS ACLs."""
        main_quirk = FlextLdifServersDs389()
        acl_quirk = main_quirk.acl
        acl_line = "access to * by * read"
        # Parse string ACL into model object

        parse_result = acl_quirk.parse(acl_line)

        assert parse_result.is_success, f"Failed to parse ACL: {parse_result.error}"

        parse_result.unwrap()

        # Test with the model object

        assert acl_quirk._can_handle(acl_line) is False

    def test__can_handle_empty_line(self) -> None:
        """Test ACL detection rejects empty lines."""
        main_quirk = FlextLdifServersDs389()
        acl_quirk = main_quirk.acl
        acl_line = ""
        # Empty string should return False for can_handle
        assert acl_quirk._can_handle(acl_line) is False

    def test_parse_success(self) -> None:
        """Test parsing 389 DS ACI definition."""
        main_quirk = FlextLdifServersDs389()
        acl_quirk = main_quirk.acl
        acl_line = 'aci: (version 3.0; acl "Admin Access"; allow (read, write, search) targetattr = "cn, ou" userdn = "ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com";)'
        result = acl_quirk.parse(acl_line)

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

    def test_parse_with_multiple_userdns(self) -> None:
        """Test parsing ACI with multiple userdn clauses."""
        main_quirk = FlextLdifServersDs389()
        acl_quirk = main_quirk.acl
        acl_line = 'aci: (version 3.0; acl "Multi User"; allow (read) userdn = "ldap:///cn=user1,dc=example,dc=com" userdn = "ldap:///cn=user2,dc=example,dc=com";)'
        result = acl_quirk.parse(acl_line)

        assert result.is_success
        acl_data = result.unwrap()
        # Check that multiple userdn values are captured in the first one
        assert acl_data.name == "Multi User"
        assert acl_data.subject is not None
        # Note: Current implementation only captures first userdn, not multiple
        # This is expected as Acl model has single subject
        assert acl_data.permissions is not None
        assert acl_data.permissions.read is True

    def test_write_acl_to_rfc_with_content(self) -> None:
        """Test writing ACL with content to RFC string format."""
        main_quirk = FlextLdifServersDs389()
        acl_quirk = main_quirk.acl
        # Create proper Acl model instance with raw_acl
        acl_data = FlextLdifModels.Acl(
            name="Admin",
            target=FlextLdifModels.AclTarget(target_dn="*", attributes=[]),
            subject=FlextLdifModels.AclSubject(
                subject_type="userdn", subject_value="ldap:///cn=REDACTED_LDAP_BIND_PASSWORD"
            ),
            permissions=FlextLdifModels.AclPermissions(read=True),
            server_type="389ds",
            raw_acl='(version 3.0; acl "Admin"; allow (read) userdn = "ldap:///cn=REDACTED_LDAP_BIND_PASSWORD";)',
        )
        result = acl_quirk.write(acl_data)

        assert result.is_success
        acl_str = result.unwrap()
        assert "version 3.0" in acl_str

    def test_write_acl_to_rfc_from_structured(self) -> None:
        """Test writing ACL from structured fields to RFC string format."""
        main_quirk = FlextLdifServersDs389()
        acl_quirk = main_quirk.acl
        # Create proper Acl model instance
        acl_data = FlextLdifModels.Acl(
            name="Admin Access",
            target=FlextLdifModels.AclTarget(target_dn="*", attributes=["cn"]),
            subject=FlextLdifModels.AclSubject(
                subject_type="userdn",
                subject_value="ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            ),
            permissions=FlextLdifModels.AclPermissions(
                read=True,
                write=True,
            ),
            server_type="389ds",
        )
        result = acl_quirk.write(acl_data)

        assert result.is_success
        acl_str = result.unwrap()
        assert "aci:" in acl_str
        assert "Admin Access" in acl_str
        assert "read" in acl_str or "write" in acl_str

    def test_write_acl_to_rfc_empty(self) -> None:
        """Test writing empty ACL to RFC string format."""
        main_quirk = FlextLdifServersDs389()
        acl_quirk = main_quirk.acl
        # Create minimal Acl model instance
        acl_data = FlextLdifModels.Acl(
            name="",
            target=FlextLdifModels.AclTarget(target_dn="*"),
            subject=FlextLdifModels.AclSubject(subject_type="user", subject_value="*"),
            permissions=FlextLdifModels.AclPermissions(),
            server_type="389ds",
        )
        result = acl_quirk.write(acl_data)

        assert result.is_success
        acl_str = result.unwrap()
        assert "aci:" in acl_str

class TestDs389Entrys:
    """Tests for 389 Directory Server entry quirk handling."""

    def test_entry_quirk_initialization(self) -> None:
        """Test entry quirk initialization."""
        main_quirk = FlextLdifServersDs389()
        entry_quirk = main_quirk.entry
        assert entry_quirk is not None

    def test_can_handle_entry_with_cn_config(self) -> None:
        """Test entry detection with cn=config DN marker."""
        main_quirk = FlextLdifServersDs389()
        entry_quirk = main_quirk.entry
        entry_dn = "cn=config"
        attributes: dict[str, object] = {FlextLdifConstants.DictKeys.OBJECTCLASS: ["nscontainer"]}
        assert entry_quirk._can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_cn_monitor(self) -> None:
        """Test entry detection with cn=monitor DN marker."""
        main_quirk = FlextLdifServersDs389()
        entry_quirk = main_quirk.entry
        entry_dn = "cn=monitor"
        attributes: dict[str, object] = {FlextLdifConstants.DictKeys.OBJECTCLASS: ["top"]}
        assert entry_quirk._can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_cn_changelog(self) -> None:
        """Test entry detection with cn=changelog DN marker."""
        main_quirk = FlextLdifServersDs389()
        entry_quirk = main_quirk.entry
        entry_dn = "cn=changelog"
        attributes: dict[str, object] = {FlextLdifConstants.DictKeys.OBJECTCLASS: ["top"]}
        assert entry_quirk._can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_nsslapd_attribute(self) -> None:
        """Test entry detection with nsslapd- attribute prefix."""
        main_quirk = FlextLdifServersDs389()
        entry_quirk = main_quirk.entry
        entry_dn = "cn=test,dc=example,dc=com"
        attributes: dict[str, object] = {
            "nsslapd-port": ["389"],
            "objectclass": ["top"],
        }
        assert entry_quirk._can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_nsds_attribute(self) -> None:
        """Test entry detection with nsds attribute prefix."""
        main_quirk = FlextLdifServersDs389()
        entry_quirk = main_quirk.entry
        entry_dn = "cn=test,dc=example,dc=com"
        attributes: dict[str, object] = {
            "nsds5ReplicaId": ["1"],
            "objectclass": ["top"],
        }
        assert entry_quirk._can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_nsuniqueid_attribute(self) -> None:
        """Test entry detection with nsuniqueid attribute."""
        main_quirk = FlextLdifServersDs389()
        entry_quirk = main_quirk.entry
        entry_dn = "cn=test,dc=example,dc=com"
        attributes: dict[str, object] = {
            "nsuniqueid": ["12345"],
            "objectclass": ["top"],
        }
        assert entry_quirk._can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_ns_objectclass(self) -> None:
        """Test entry detection with ns- objectClass."""
        main_quirk = FlextLdifServersDs389()
        entry_quirk = main_quirk.entry
        entry_dn = "cn=test,dc=example,dc=com"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["top", "nscontainer"]
        }
        assert entry_quirk._can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_negative(self) -> None:
        """Test entry detection rejects non-389 DS entries."""
        main_quirk = FlextLdifServersDs389()
        entry_quirk = main_quirk.entry
        entry_dn = "cn=user,dc=example,dc=com"
        attributes: dict[str, object] = {FlextLdifConstants.DictKeys.OBJECTCLASS: ["person"], "cn": ["user"]}
        assert entry_quirk._can_handle_entry(entry_dn, attributes) is False

