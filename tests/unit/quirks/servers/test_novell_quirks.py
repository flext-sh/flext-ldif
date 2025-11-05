"""Tests for Novell eDirectory quirks implementation."""

from __future__ import annotations

import base64

import pytest

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.novell import FlextLdifServersNovell

class TestNovellSchemas:
    """Tests for Novell eDirectory schema quirk handling."""

    @pytest.fixture
    def server(self) -> FlextLdifServersNovell:
        """Create Novell server instance."""
        return FlextLdifServersNovell()

    @pytest.fixture
    def quirk(self, server: FlextLdifServersNovell) -> FlextLdifServersNovell.Schema:
        """Create Novell schema quirk instance."""
        return server.schema

    def test_initialization(self, server: FlextLdifServersNovell) -> None:
        """Test Novell eDirectory quirk initialization."""
        assert server.server_type == FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY
        assert server.priority == 15

    def test_can_handle_attribute_with_novell_oid(self) -> None:
        """Test attribute detection with Novell OID pattern."""
        quirk = FlextLdifServersNovell.Schema()
        attr_def = "( 2.16.840.1.113719.1.1.4.1.501 NAME 'nspmPasswordPolicyDN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )"
        # Parse string definition into model object

        parse_result = quirk.parse(attr_def)

        assert parse_result.is_success, (
            f"Failed to parse attribute: {parse_result.error}"
        )

        parse_result.unwrap()

        # Test with the model object

        assert quirk._can_handle_attribute(attr_def) is True

    def test_can_handle_attribute_with_nspm_prefix(self) -> None:
        """Test attribute detection with nspm prefix."""
        quirk = FlextLdifServersNovell.Schema()
        attr_def = (
            "( 1.2.3.4 NAME 'nspmPasswordPolicy' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        # Parse string definition into model object

        parse_result = quirk.parse(attr_def)

        assert parse_result.is_success, (
            f"Failed to parse attribute: {parse_result.error}"
        )

        parse_result.unwrap()

        # Test with the model object

        assert quirk._can_handle_attribute(attr_def) is True

    def test_can_handle_attribute_with_login_prefix(self) -> None:
        """Test attribute detection with login prefix."""
        quirk = FlextLdifServersNovell.Schema()
        attr_def = (
            "( 1.2.3.4 NAME 'loginDisabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )"
        )
        # Parse string definition into model object

        parse_result = quirk.parse(attr_def)

        assert parse_result.is_success, (
            f"Failed to parse attribute: {parse_result.error}"
        )

        parse_result.unwrap()

        # Test with the model object

        assert quirk._can_handle_attribute(attr_def) is True

    def test_can_handle_attribute_with_dirxml_prefix(self) -> None:
        """Test attribute detection with dirxml- prefix."""
        quirk = FlextLdifServersNovell.Schema()
        attr_def = "( 1.2.3.4 NAME 'dirxml-associations' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        # Parse string definition into model object

        parse_result = quirk.parse(attr_def)

        assert parse_result.is_success, (
            f"Failed to parse attribute: {parse_result.error}"
        )

        parse_result.unwrap()

        # Test with the model object

        assert quirk._can_handle_attribute(attr_def) is True

    def test_can_handle_attribute_negative(self) -> None:
        """Test attribute detection rejects non-Novell attributes."""
        quirk = FlextLdifServersNovell.Schema()
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
        """Test parsing Novell eDirectory attribute definition."""
        quirk = FlextLdifServersNovell.Schema()
        attr_def = "( 2.16.840.1.113719.1.1.4.1.501 NAME 'nspmPasswordPolicyDN' DESC 'Password Policy DN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )"
        result = quirk.parse(attr_def)

        assert result.is_success
        attr_data = result.unwrap()
        assert attr_data.oid == "2.16.840.1.113719.1.1.4.1.501"
        assert attr_data.name == "nspmPasswordPolicyDN"
        assert attr_data.desc == "Password Policy DN"
        assert attr_data.syntax == "1.3.6.1.4.1.1466.115.121.1.12"
        assert attr_data.single_value is True

    def test_parse_attribute_with_syntax_length(self) -> None:
        """Test parsing attribute with syntax length specification."""
        quirk = FlextLdifServersNovell.Schema()
        attr_def = "( 2.16.840.1.113719.1.1.4.1.1 NAME 'nspmAdminGroup' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        result = quirk.parse(attr_def)

        assert result.is_success
        attr_data = result.unwrap()
        assert attr_data.syntax == "1.3.6.1.4.1.1466.115.121.1.15"
        # syntax_length is stored in the length field
        assert attr_data.length == 256

    def test_parse_attribute_missing_oid(self) -> None:
        """Test parsing attribute without OID fails."""
        quirk = FlextLdifServersNovell.Schema()
        attr_def = "NAME 'nspmPasswordPolicy' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15"
        result = quirk.parse(attr_def)

        assert result.is_failure
        assert result.error is not None
        assert "missing an OID" in result.error

    def test_can_handle_objectclass_with_novell_oid(self) -> None:
        """Test objectClass detection with Novell OID."""
        quirk = FlextLdifServersNovell.Schema()
        oc_def = "( 2.16.840.1.113719.2.2.6.1 NAME 'ndsPerson' SUP top STRUCTURAL )"
        # Parse string definition into model object

        parse_result = quirk.parse(oc_def)

        assert parse_result.is_success, (
            f"Failed to parse objectClass: {parse_result.error}"
        )

        parse_result.unwrap()

        # Test with the model object

        assert quirk._can_handle_objectclass(oc_def) is True

    def test_can_handle_objectclass_with_nds_name(self) -> None:
        """Test objectClass detection with nds- name."""
        quirk = FlextLdifServersNovell.Schema()
        oc_def = "( 2.5.6.0 NAME 'ndsserver' SUP top STRUCTURAL )"
        # Parse string definition into model object

        parse_result = quirk.parse(oc_def)

        assert parse_result.is_success, (
            f"Failed to parse objectClass: {parse_result.error}"
        )

        parse_result.unwrap()

        # Test with the model object

        assert quirk._can_handle_objectclass(oc_def) is True

    def test_can_handle_objectclass_negative(self) -> None:
        """Test objectClass detection rejects non-Novell classes."""
        quirk = FlextLdifServersNovell.Schema()
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
        quirk = FlextLdifServersNovell.Schema()
        oc_def = "( 2.16.840.1.113719.2.2.6.1 NAME 'ndsPerson' DESC 'NDS Person' SUP top STRUCTURAL MUST ( cn ) MAY ( loginDisabled ) )"
        result = quirk.parse(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data.oid == "2.16.840.1.113719.2.2.6.1"
        assert oc_data.name == "ndsPerson"
        assert oc_data.kind == "STRUCTURAL"
        assert oc_data.sup == "top"
        must_attrs = oc_data.must
        may_attrs = oc_data.may
        assert isinstance(must_attrs, list) and "cn" in must_attrs
        assert isinstance(may_attrs, list) and "loginDisabled" in may_attrs

    def test_parse_objectclass_auxiliary(self) -> None:
        """Test parsing AUXILIARY objectClass."""
        quirk = FlextLdifServersNovell.Schema()
        oc_def = "( 2.16.840.1.113719.2.2.6.2 NAME 'nspmPasswordPolicy' AUXILIARY MAY ( nspmPasswordPolicyDN ) )"
        result = quirk.parse(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data.kind == "AUXILIARY"

    def test_parse_objectclass_abstract(self) -> None:
        """Test parsing ABSTRACT objectClass."""
        quirk = FlextLdifServersNovell.Schema()
        oc_def = "( 2.16.840.1.113719.2.2.6.3 NAME 'ndsbase' ABSTRACT )"
        result = quirk.parse(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data.kind == "ABSTRACT"

    def test_parse_objectclass_missing_oid(self) -> None:
        """Test parsing objectClass without OID fails."""
        quirk = FlextLdifServersNovell.Schema()
        oc_def = "NAME 'ndsPerson' SUP top STRUCTURAL"
        result = quirk.parse(oc_def)

        assert result.is_failure
        assert result.error is not None
        assert "missing an OID" in result.error

    def test_write_attribute_to_rfc(self) -> None:
        """Test writing attribute to RFC string format."""
        quirk = FlextLdifServersNovell.Schema()
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113719.1.1.4.1.501",
            name="nspmPasswordPolicyDN",
            desc="Password Policy DN",
            syntax="1.3.6.1.4.1.1466.115.121.1.12",
            single_value=True,
        )
        result = quirk.write(attr_data)

        assert result.is_success
        attr_str = result.unwrap()
        assert "2.16.840.1.113719.1.1.4.1.501" in attr_str
        assert "nspmPasswordPolicyDN" in attr_str
        assert "SINGLE-VALUE" in attr_str

    def test_write_objectclass_to_rfc(self) -> None:
        """Test writing objectClass to RFC string format."""
        quirk = FlextLdifServersNovell.Schema()
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.16.840.1.113719.2.2.6.1",
            name="ndsPerson",
            kind="STRUCTURAL",
            sup="top",
            must=["cn"],
            may=["loginDisabled"],
        )
        result = quirk.write(oc_data)

        assert result.is_success
        oc_str = result.unwrap()
        assert "2.16.840.1.113719.2.2.6.1" in oc_str
        assert "ndsPerson" in oc_str
        assert "STRUCTURAL" in oc_str

class TestNovellAcls:
    """Tests for Novell eDirectory ACL quirk handling."""

    def test_acl_quirk_initialization(self) -> None:
        """Test ACL quirk initialization."""
        novell_server = FlextLdifServersNovell()
        novell_server.Acl()
        # Nested ACL inherits from RFC.Acl

    def test__can_handle_with_acl_attribute(self) -> None:
        """Test ACL detection with acl attribute."""
        novell_server = FlextLdifServersNovell()
        acl_quirk = novell_server.Acl()
        acl_line = "acl: [Entry Rights]#cn=Admin,o=Example#[BCDRSE]"
        # Parse string ACL into model object

        parse_result = acl_quirk.parse(acl_line)

        assert parse_result.is_success, f"Failed to parse ACL: {parse_result.error}"

        parse_result.unwrap()

        # Test with the model object

        assert acl_quirk._can_handle(acl_line) is True

    def test__can_handle_with_inheritedacl_attribute(self) -> None:
        """Test ACL detection with inheritedacl attribute."""
        novell_server = FlextLdifServersNovell()
        acl_quirk = novell_server.Acl()
        acl_line = "inheritedacl: [Entry Rights]#cn=Admin,o=Example#[BCDRSE]"
        # Parse string ACL into model object

        parse_result = acl_quirk.parse(acl_line)

        assert parse_result.is_success, f"Failed to parse ACL: {parse_result.error}"

        parse_result.unwrap()

        # Test with the model object

        assert acl_quirk._can_handle(acl_line) is True

    def test__can_handle_negative(self) -> None:
        """Test ACL detection rejects non-Novell ACLs."""
        novell_server = FlextLdifServersNovell()
        acl_quirk = novell_server.Acl()
        acl_line = "access to * by * read"
        # Parse string ACL into model object

        parse_result = acl_quirk.parse(acl_line)

        assert parse_result.is_success, f"Failed to parse ACL: {parse_result.error}"

        parse_result.unwrap()

        # Test with the model object

        assert acl_quirk._can_handle(acl_line) is False

    def test__can_handle_empty_line(self) -> None:
        """Test ACL detection rejects empty lines."""
        novell_server = FlextLdifServersNovell()
        acl_quirk = novell_server.Acl()
        acl_line = ""
        # Parse string ACL into model object

        parse_result = acl_quirk.parse(acl_line)

        assert parse_result.is_success, f"Failed to parse ACL: {parse_result.error}"

        parse_result.unwrap()

        # Test with the model object

        assert acl_quirk._can_handle(acl_line) is False

    def test_parse_success(self) -> None:
        """Test parsing Novell eDirectory ACL definition."""
        novell_server = FlextLdifServersNovell()
        acl_quirk = novell_server.Acl()
        acl_line = "acl: [Entry Rights]#cn=Admin,o=Example#[BCDRSE]"
        result = acl_quirk.parse(acl_line)

        assert result.is_success
        acl_data = result.unwrap()
        assert acl_data.name == "Novell eDirectory ACL"
        assert acl_data.server_type == FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY

        # Verify ACL structure from parsed segments
        # Segments: [0]="[Entry Rights]", [1]="cn=Admin,o=Example", [2]="[BCDRSE]"
        # TRUSTEE_INDEX=2, RIGHTS_INDEX=3
        assert acl_data.target is not None
        assert acl_data.target.target_dn == "[Entry Rights]"
        assert acl_data.subject is not None
        assert acl_data.subject.subject_value == "[BCDRSE]"
        assert acl_data.permissions is not None
        assert acl_data.raw_acl == acl_line

    def test_parse_with_multiple_rights(self) -> None:
        """Test parsing ACL with multiple rights segments."""
        novell_server = FlextLdifServersNovell()
        acl_quirk = novell_server.Acl()
        acl_line = (
            "acl: [Entry Rights]#cn=Admin,o=Example#[BCDRSE]#[All Attributes Rights]"
        )
        result = acl_quirk.parse(acl_line)

        assert result.is_success
        acl_data = result.unwrap()
        assert acl_data.name == "Novell eDirectory ACL"
        assert acl_data.target is not None
        assert acl_data.subject is not None
        assert acl_data.permissions is not None
        assert acl_data.raw_acl == acl_line

    def test_write_acl_to_rfc_with_content(self) -> None:
        """Test writing ACL with content to RFC string format."""
        novell_server = FlextLdifServersNovell()
        acl_quirk = novell_server.Acl()
        acl_data = FlextLdifModels.Acl(
            name="Novell eDirectory ACL",
            target=FlextLdifModels.AclTarget(
                target_dn="[Entry Rights]",
                attributes=[],
            ),
            subject=FlextLdifModels.AclSubject(
                subject_type="trustee",
                subject_value="cn=Admin,o=Example",
            ),
            permissions=FlextLdifModels.AclPermissions(
                read=True,
                write=True,
                delete=True,
            ),
            server_type=FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY,
            raw_acl="acl: [Entry Rights]#cn=Admin,o=Example#[BCDRSE]",
        )
        result = acl_quirk.write(acl_data)

        assert result.is_success
        acl_str = result.unwrap()
        assert "acl:" in acl_str or "[Entry Rights]" in acl_str

    def test_write_acl_to_rfc_with_segments(self) -> None:
        """Test writing ACL with segments to RFC string format."""
        novell_server = FlextLdifServersNovell()
        acl_quirk = novell_server.Acl()
        acl_data = FlextLdifModels.Acl(
            name="Novell eDirectory ACL",
            target=FlextLdifModels.AclTarget(
                target_dn="[Entry Rights]",
                attributes=[],
            ),
            subject=FlextLdifModels.AclSubject(
                subject_type="trustee",
                subject_value="cn=Admin,o=Example",
            ),
            permissions=FlextLdifModels.AclPermissions(),
            server_type=FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY,
        )
        result = acl_quirk.write(acl_data)

        assert result.is_success
        acl_str = result.unwrap()
        assert isinstance(acl_str, str)

    def test_write_acl_to_rfc_from_fields(self) -> None:
        """Test writing ACL from structured fields to RFC string format."""
        novell_server = FlextLdifServersNovell()
        acl_quirk = novell_server.Acl()
        acl_data = FlextLdifModels.Acl(
            name="Novell eDirectory ACL",
            target=FlextLdifModels.AclTarget(
                target_dn="[Entry Rights]",
                attributes=[],
            ),
            subject=FlextLdifModels.AclSubject(
                subject_type="trustee",
                subject_value="cn=Admin,o=Example",
            ),
            permissions=FlextLdifModels.AclPermissions(
                read=True,
            ),
            server_type=FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY,
        )
        result = acl_quirk.write(acl_data)

        assert result.is_success
        acl_str = result.unwrap()
        assert "acl:" in acl_str
        assert "[Entry Rights]" in acl_str
        assert "#" in acl_str

    def test_write_acl_to_rfc_empty(self) -> None:
        """Test writing empty ACL to RFC string format."""
        novell_server = FlextLdifServersNovell()
        acl_quirk = novell_server.Acl()
        acl_data = FlextLdifModels.Acl(
            name="Empty ACL",
            target=FlextLdifModels.AclTarget(
                target_dn="",
                attributes=[],
            ),
            subject=FlextLdifModels.AclSubject(
                subject_type="",
                subject_value="",
            ),
            permissions=FlextLdifModels.AclPermissions(),
            server_type=FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY,
        )
        result = acl_quirk.write(acl_data)

        assert result.is_success
        acl_str = result.unwrap()
        assert isinstance(acl_str, str)

class TestNovellEntrys:
    """Tests for Novell eDirectory entry quirk handling."""

    def test_entry_quirk_initialization(self) -> None:
        """Test entry quirk initialization."""
        novell_server = FlextLdifServersNovell()
        novell_server.Entry()
        # Nested Entry inherits from RFC.Entry

    def test_can_handle_entry_with_ou_services(self) -> None:
        """Test entry detection with ou=services DN marker."""
        novell_server = FlextLdifServersNovell()
        entry_quirk = novell_server.Entry()
        entry_dn = "ou=services,o=Example"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["organizationalUnit"]
        }
        assert entry_quirk._can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_ou_apps(self) -> None:
        """Test entry detection with ou=apps DN marker."""
        novell_server = FlextLdifServersNovell()
        entry_quirk = novell_server.Entry()
        entry_dn = "ou=apps,o=Example"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["organizationalUnit"]
        }
        assert entry_quirk._can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_ou_system(self) -> None:
        """Test entry detection with ou=system DN marker."""
        novell_server = FlextLdifServersNovell()
        entry_quirk = novell_server.Entry()
        entry_dn = "ou=system,o=Example"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["organizationalUnit"]
        }
        assert entry_quirk._can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_password_policy_attribute(self) -> None:
        """Test entry detection with nspmpasswordpolicy attribute."""
        novell_server = FlextLdifServersNovell()
        entry_quirk = novell_server.Entry()
        entry_dn = "cn=user,o=Example"
        attributes: dict[str, object] = {
            "nspmpasswordpolicy": ["policy1"],
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["top"],
        }
        assert entry_quirk._can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_login_attribute(self) -> None:
        """Test entry detection with loginDisabled attribute."""
        novell_server = FlextLdifServersNovell()
        entry_quirk = novell_server.Entry()
        entry_dn = "cn=user,o=Example"
        attributes: dict[str, object] = {
            "logindisabled": ["TRUE"],
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["top"],
        }
        assert entry_quirk._can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_nds_objectclass(self) -> None:
        """Test entry detection with nds- objectClass."""
        novell_server = FlextLdifServersNovell()
        entry_quirk = novell_server.Entry()
        entry_dn = "cn=user,o=Example"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["top", "ndsperson"]
        }
        assert entry_quirk._can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_negative(self) -> None:
        """Test entry detection rejects non-Novell entries."""
        novell_server = FlextLdifServersNovell()
        entry_quirk = novell_server.Entry()
        entry_dn = "cn=user,dc=example,dc=com"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["person"],
            "cn": ["user"],
        }
        assert entry_quirk._can_handle_entry(entry_dn, attributes) is False

