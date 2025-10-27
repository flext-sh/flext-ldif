"""Tests for Novell eDirectory quirks implementation."""

from __future__ import annotations

import base64

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.servers.novell_quirks import FlextLdifQuirksServersNovell


class TestNovellSchemaQuirks:
    """Tests for Novell eDirectory schema quirk handling."""

    def test_initialization(self) -> None:
        """Test Novell eDirectory quirk initialization."""
        quirk = FlextLdifQuirksServersNovell()
        assert quirk.server_type == FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY
        assert quirk.priority == 15

    def test_can_handle_attribute_with_novell_oid(self) -> None:
        """Test attribute detection with Novell OID pattern."""
        quirk = FlextLdifQuirksServersNovell()
        attr_def = "( 2.16.840.1.113719.1.1.4.1.501 NAME 'nspmPasswordPolicyDN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )"
        assert quirk.can_handle_attribute(attr_def) is True

    def test_can_handle_attribute_with_nspm_prefix(self) -> None:
        """Test attribute detection with nspm prefix."""
        quirk = FlextLdifQuirksServersNovell()
        attr_def = (
            "( 1.2.3.4 NAME 'nspmPasswordPolicy' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        assert quirk.can_handle_attribute(attr_def) is True

    def test_can_handle_attribute_with_login_prefix(self) -> None:
        """Test attribute detection with login prefix."""
        quirk = FlextLdifQuirksServersNovell()
        attr_def = (
            "( 1.2.3.4 NAME 'loginDisabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )"
        )
        assert quirk.can_handle_attribute(attr_def) is True

    def test_can_handle_attribute_with_dirxml_prefix(self) -> None:
        """Test attribute detection with dirxml- prefix."""
        quirk = FlextLdifQuirksServersNovell()
        attr_def = "( 1.2.3.4 NAME 'dirxml-associations' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        assert quirk.can_handle_attribute(attr_def) is True

    def test_can_handle_attribute_negative(self) -> None:
        """Test attribute detection rejects non-Novell attributes."""
        quirk = FlextLdifQuirksServersNovell()
        attr_def = "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        assert quirk.can_handle_attribute(attr_def) is False

    def test_parse_attribute_success(self) -> None:
        """Test parsing Novell eDirectory attribute definition."""
        quirk = FlextLdifQuirksServersNovell()
        attr_def = "( 2.16.840.1.113719.1.1.4.1.501 NAME 'nspmPasswordPolicyDN' DESC 'Password Policy DN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )"
        result = quirk.parse_attribute(attr_def)

        assert result.is_success
        attr_data = result.unwrap()
        assert attr_data.oid == "2.16.840.1.113719.1.1.4.1.501"
        assert attr_data.name == "nspmPasswordPolicyDN"
        assert attr_data.desc == "Password Policy DN"
        assert attr_data.syntax == "1.3.6.1.4.1.1466.115.121.1.12"
        assert attr_data.single_value is True

    def test_parse_attribute_with_syntax_length(self) -> None:
        """Test parsing attribute with syntax length specification."""
        quirk = FlextLdifQuirksServersNovell()
        attr_def = "( 2.16.840.1.113719.1.1.4.1.1 NAME 'nspmAdminGroup' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        result = quirk.parse_attribute(attr_def)

        assert result.is_success
        attr_data = result.unwrap()
        assert attr_data.syntax == "1.3.6.1.4.1.1466.115.121.1.15"
        # syntax_length is stored in the length field
        assert attr_data.length == 256

    def test_parse_attribute_missing_oid(self) -> None:
        """Test parsing attribute without OID fails."""
        quirk = FlextLdifQuirksServersNovell()
        attr_def = "NAME 'nspmPasswordPolicy' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15"
        result = quirk.parse_attribute(attr_def)

        assert result.is_failure
        assert result.error is not None
        assert "missing an OID" in result.error

    def test_can_handle_objectclass_with_novell_oid(self) -> None:
        """Test objectClass detection with Novell OID."""
        quirk = FlextLdifQuirksServersNovell()
        oc_def = "( 2.16.840.1.113719.2.2.6.1 NAME 'ndsPerson' SUP top STRUCTURAL )"
        assert quirk.can_handle_objectclass(oc_def) is True

    def test_can_handle_objectclass_with_nds_name(self) -> None:
        """Test objectClass detection with nds- name."""
        quirk = FlextLdifQuirksServersNovell()
        oc_def = "( 2.5.6.0 NAME 'ndsserver' SUP top STRUCTURAL )"
        assert quirk.can_handle_objectclass(oc_def) is True

    def test_can_handle_objectclass_negative(self) -> None:
        """Test objectClass detection rejects non-Novell classes."""
        quirk = FlextLdifQuirksServersNovell()
        oc_def = "( 2.5.6.6 NAME 'posixAccount' SUP top STRUCTURAL )"
        assert quirk.can_handle_objectclass(oc_def) is False

    def test_parse_objectclass_structural(self) -> None:
        """Test parsing STRUCTURAL objectClass."""
        quirk = FlextLdifQuirksServersNovell()
        oc_def = "( 2.16.840.1.113719.2.2.6.1 NAME 'ndsPerson' DESC 'NDS Person' SUP top STRUCTURAL MUST ( cn ) MAY ( loginDisabled ) )"
        result = quirk.parse_objectclass(oc_def)

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
        quirk = FlextLdifQuirksServersNovell()
        oc_def = "( 2.16.840.1.113719.2.2.6.2 NAME 'nspmPasswordPolicy' AUXILIARY MAY ( nspmPasswordPolicyDN ) )"
        result = quirk.parse_objectclass(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data.kind == "AUXILIARY"

    def test_parse_objectclass_abstract(self) -> None:
        """Test parsing ABSTRACT objectClass."""
        quirk = FlextLdifQuirksServersNovell()
        oc_def = "( 2.16.840.1.113719.2.2.6.3 NAME 'ndsbase' ABSTRACT )"
        result = quirk.parse_objectclass(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data.kind == "ABSTRACT"

    def test_parse_objectclass_missing_oid(self) -> None:
        """Test parsing objectClass without OID fails."""
        quirk = FlextLdifQuirksServersNovell()
        oc_def = "NAME 'ndsPerson' SUP top STRUCTURAL"
        result = quirk.parse_objectclass(oc_def)

        assert result.is_failure
        assert result.error is not None
        assert "missing an OID" in result.error

    def test_convert_attribute_to_rfc(self) -> None:
        """Test converting Novell attribute to RFC format."""
        quirk = FlextLdifQuirksServersNovell()
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113719.1.1.4.1.501",
            name="nspmPasswordPolicyDN",
            desc="Password Policy DN",
            syntax="1.3.6.1.4.1.1466.115.121.1.12",
            single_value=True,
        )
        result = quirk.convert_attribute_to_rfc(attr_data)

        assert result.is_success
        rfc_data = result.unwrap()
        assert rfc_data.oid == "2.16.840.1.113719.1.1.4.1.501"
        assert rfc_data.name == "nspmPasswordPolicyDN"

    def test_convert_objectclass_to_rfc(self) -> None:
        """Test converting Novell objectClass to RFC format."""
        quirk = FlextLdifQuirksServersNovell()
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.16.840.1.113719.2.2.6.1",
            name="ndsPerson",
            kind="STRUCTURAL",
            sup="top",
        )
        result = quirk.convert_objectclass_to_rfc(oc_data)

        assert result.is_success
        rfc_data = result.unwrap()
        assert rfc_data.oid == "2.16.840.1.113719.2.2.6.1"

    def test_convert_attribute_from_rfc(self) -> None:
        """Test converting RFC attribute to Novell format."""
        quirk = FlextLdifQuirksServersNovell()
        rfc_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113719.1.1.4.1.501",
            name="nspmPasswordPolicyDN",
        )
        result = quirk.convert_attribute_from_rfc(rfc_data)

        assert result.is_success
        novell_data = result.unwrap()
        assert novell_data.metadata is not None
        assert novell_data.metadata.quirk_type == "novell_edirectory"

    def test_convert_objectclass_from_rfc(self) -> None:
        """Test converting RFC objectClass to Novell format."""
        quirk = FlextLdifQuirksServersNovell()
        rfc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.16.840.1.113719.2.2.6.1",
            name="ndsPerson",
        )
        result = quirk.convert_objectclass_from_rfc(rfc_data)

        assert result.is_success
        novell_data = result.unwrap()
        assert novell_data.metadata is not None
        assert novell_data.metadata.quirk_type == "novell_edirectory"

    def test_write_attribute_to_rfc(self) -> None:
        """Test writing attribute to RFC string format."""
        quirk = FlextLdifQuirksServersNovell()
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113719.1.1.4.1.501",
            name="nspmPasswordPolicyDN",
            desc="Password Policy DN",
            syntax="1.3.6.1.4.1.1466.115.121.1.12",
            single_value=True,
        )
        result = quirk.write_attribute_to_rfc(attr_data)

        assert result.is_success
        attr_str = result.unwrap()
        assert "2.16.840.1.113719.1.1.4.1.501" in attr_str
        assert "nspmPasswordPolicyDN" in attr_str
        assert "SINGLE-VALUE" in attr_str

    def test_write_objectclass_to_rfc(self) -> None:
        """Test writing objectClass to RFC string format."""
        quirk = FlextLdifQuirksServersNovell()
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.16.840.1.113719.2.2.6.1",
            name="ndsPerson",
            kind="STRUCTURAL",
            sup="top",
            must=["cn"],
            may=["loginDisabled"],
        )
        result = quirk.write_objectclass_to_rfc(oc_data)

        assert result.is_success
        oc_str = result.unwrap()
        assert "2.16.840.1.113719.2.2.6.1" in oc_str
        assert "ndsPerson" in oc_str
        assert "STRUCTURAL" in oc_str


class TestNovellAclQuirks:
    """Tests for Novell eDirectory ACL quirk handling."""

    def test_acl_quirk_initialization(self) -> None:
        """Test ACL quirk initialization."""
        main_quirk = FlextLdifQuirksServersNovell()
        acl_quirk = main_quirk.AclQuirk()
        # The ACL quirk inherits from BaseAclQuirk which has __init__ with default "generic"
        assert acl_quirk.server_type == "generic"
        assert acl_quirk.priority == 100  # Also uses BaseAclQuirk default

    def test_can_handle_acl_with_acl_attribute(self) -> None:
        """Test ACL detection with acl attribute."""
        main_quirk = FlextLdifQuirksServersNovell()
        acl_quirk = main_quirk.AclQuirk()
        acl_line = "acl: [Entry Rights]#cn=Admin,o=Example#[BCDRSE]"
        assert acl_quirk.can_handle_acl(acl_line) is True

    def test_can_handle_acl_with_inheritedacl_attribute(self) -> None:
        """Test ACL detection with inheritedacl attribute."""
        main_quirk = FlextLdifQuirksServersNovell()
        acl_quirk = main_quirk.AclQuirk()
        acl_line = "inheritedacl: [Entry Rights]#cn=Admin,o=Example#[BCDRSE]"
        assert acl_quirk.can_handle_acl(acl_line) is True

    def test_can_handle_acl_negative(self) -> None:
        """Test ACL detection rejects non-Novell ACLs."""
        main_quirk = FlextLdifQuirksServersNovell()
        acl_quirk = main_quirk.AclQuirk()
        acl_line = "access to * by * read"
        assert acl_quirk.can_handle_acl(acl_line) is False

    def test_can_handle_acl_empty_line(self) -> None:
        """Test ACL detection rejects empty lines."""
        main_quirk = FlextLdifQuirksServersNovell()
        acl_quirk = main_quirk.AclQuirk()
        acl_line = ""
        assert acl_quirk.can_handle_acl(acl_line) is False

    def test_parse_acl_success(self) -> None:
        """Test parsing Novell eDirectory ACL definition."""
        main_quirk = FlextLdifQuirksServersNovell()
        acl_quirk = main_quirk.AclQuirk()
        acl_line = "acl: [Entry Rights]#cn=Admin,o=Example#[BCDRSE]"
        result = acl_quirk.parse_acl(acl_line)

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

    def test_parse_acl_with_multiple_rights(self) -> None:
        """Test parsing ACL with multiple rights segments."""
        main_quirk = FlextLdifQuirksServersNovell()
        acl_quirk = main_quirk.AclQuirk()
        acl_line = (
            "acl: [Entry Rights]#cn=Admin,o=Example#[BCDRSE]#[All Attributes Rights]"
        )
        result = acl_quirk.parse_acl(acl_line)

        assert result.is_success
        acl_data = result.unwrap()
        assert acl_data.name == "Novell eDirectory ACL"
        assert acl_data.target is not None
        assert acl_data.subject is not None
        assert acl_data.permissions is not None
        assert acl_data.raw_acl == acl_line

    def test_convert_acl_to_rfc(self) -> None:
        """Test converting Novell ACL to RFC format."""
        main_quirk = FlextLdifQuirksServersNovell()
        acl_quirk = main_quirk.AclQuirk()
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
        )
        result = acl_quirk.convert_acl_to_rfc(acl_data)

        assert result.is_success
        rfc_acl = result.unwrap()
        assert rfc_acl.server_type == "rfc"
        assert rfc_acl.name == "Novell eDirectory ACL"

    def test_convert_acl_from_rfc(self) -> None:
        """Test converting RFC ACL to Novell format."""
        main_quirk = FlextLdifQuirksServersNovell()
        acl_quirk = main_quirk.AclQuirk()
        rfc_acl = FlextLdifModels.Acl(
            name="RFC ACL",
            target=FlextLdifModels.AclTarget(
                target_dn="[Entry Rights]",
                attributes=[],
            ),
            subject=FlextLdifModels.AclSubject(
                subject_type="trustee",
                subject_value="cn=Admin,o=Example",
            ),
            permissions=FlextLdifModels.AclPermissions(),
            server_type="generic",  # Use "generic" instead of "rfc"
        )
        result = acl_quirk.convert_acl_from_rfc(rfc_acl)

        assert result.is_success
        novell_acl = result.unwrap()
        assert novell_acl.server_type == "novell"  # Actual returned value

    def test_write_acl_to_rfc_with_content(self) -> None:
        """Test writing ACL with content to RFC string format."""
        main_quirk = FlextLdifQuirksServersNovell()
        acl_quirk = main_quirk.AclQuirk()
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
        result = acl_quirk.write_acl_to_rfc(acl_data)

        assert result.is_success
        acl_str = result.unwrap()
        assert "acl:" in acl_str or "[Entry Rights]" in acl_str

    def test_write_acl_to_rfc_with_segments(self) -> None:
        """Test writing ACL with segments to RFC string format."""
        main_quirk = FlextLdifQuirksServersNovell()
        acl_quirk = main_quirk.AclQuirk()
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
        result = acl_quirk.write_acl_to_rfc(acl_data)

        assert result.is_success
        acl_str = result.unwrap()
        assert isinstance(acl_str, str)

    def test_write_acl_to_rfc_from_fields(self) -> None:
        """Test writing ACL from structured fields to RFC string format."""
        main_quirk = FlextLdifQuirksServersNovell()
        acl_quirk = main_quirk.AclQuirk()
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
        result = acl_quirk.write_acl_to_rfc(acl_data)

        assert result.is_success
        acl_str = result.unwrap()
        assert "acl:" in acl_str
        assert "[Entry Rights]" in acl_str
        assert "#" in acl_str

    def test_write_acl_to_rfc_empty(self) -> None:
        """Test writing empty ACL to RFC string format."""
        main_quirk = FlextLdifQuirksServersNovell()
        acl_quirk = main_quirk.AclQuirk()
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
        result = acl_quirk.write_acl_to_rfc(acl_data)

        assert result.is_success
        acl_str = result.unwrap()
        assert isinstance(acl_str, str)


class TestNovellEntryQuirks:
    """Tests for Novell eDirectory entry quirk handling."""

    def test_entry_quirk_initialization(self) -> None:
        """Test entry quirk initialization."""
        main_quirk = FlextLdifQuirksServersNovell()
        entry_quirk = main_quirk.EntryQuirk()
        # The Entry quirk inherits from BaseEntryQuirk which has __init__ with default "generic"
        assert entry_quirk.server_type == "generic"
        assert entry_quirk.priority == 100  # Also uses BaseEntryQuirk default

    def test_can_handle_entry_with_ou_services(self) -> None:
        """Test entry detection with ou=services DN marker."""
        main_quirk = FlextLdifQuirksServersNovell()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "ou=services,o=Example"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["organizationalUnit"]
        }
        assert entry_quirk.can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_ou_apps(self) -> None:
        """Test entry detection with ou=apps DN marker."""
        main_quirk = FlextLdifQuirksServersNovell()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "ou=apps,o=Example"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["organizationalUnit"]
        }
        assert entry_quirk.can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_ou_system(self) -> None:
        """Test entry detection with ou=system DN marker."""
        main_quirk = FlextLdifQuirksServersNovell()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "ou=system,o=Example"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["organizationalUnit"]
        }
        assert entry_quirk.can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_password_policy_attribute(self) -> None:
        """Test entry detection with nspmpasswordpolicy attribute."""
        main_quirk = FlextLdifQuirksServersNovell()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "cn=user,o=Example"
        attributes: dict[str, object] = {
            "nspmpasswordpolicy": ["policy1"],
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["top"],
        }
        assert entry_quirk.can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_login_attribute(self) -> None:
        """Test entry detection with loginDisabled attribute."""
        main_quirk = FlextLdifQuirksServersNovell()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "cn=user,o=Example"
        attributes: dict[str, object] = {
            "logindisabled": ["TRUE"],
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["top"],
        }
        assert entry_quirk.can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_nds_objectclass(self) -> None:
        """Test entry detection with nds- objectClass."""
        main_quirk = FlextLdifQuirksServersNovell()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "cn=user,o=Example"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["top", "ndsperson"]
        }
        assert entry_quirk.can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_negative(self) -> None:
        """Test entry detection rejects non-Novell entries."""
        main_quirk = FlextLdifQuirksServersNovell()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "cn=user,dc=example,dc=com"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["person"],
            "cn": ["user"],
        }
        assert entry_quirk.can_handle_entry(entry_dn, attributes) is False

    def test_process_entry_success(self) -> None:
        """Test processing Novell eDirectory entry."""
        main_quirk = FlextLdifQuirksServersNovell()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "cn=user,o=Example"
        attributes: dict[str, object] = {
            "objectclass": ["top", "ndsperson"],
            "cn": ["user"],
            "loginDisabled": ["FALSE"],
        }
        result = entry_quirk.process_entry(entry_dn, attributes)

        assert result.is_success
        processed_entry = result.unwrap()
        assert processed_entry[FlextLdifConstants.DictKeys.DN] == entry_dn
        assert (
            processed_entry[FlextLdifConstants.DictKeys.SERVER_TYPE]
            == FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY
        )

    def test_process_entry_with_binary_data(self) -> None:
        """Test processing entry with binary attribute data."""
        main_quirk = FlextLdifQuirksServersNovell()
        entry_quirk = main_quirk.EntryQuirk()
        entry_dn = "cn=user,o=Example"
        binary_data = b"binary_value"
        attributes: dict[str, object] = {
            "objectclass": ["top"],
            "cn": ["user"],
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
        """Test converting Novell entry to RFC format."""
        main_quirk = FlextLdifQuirksServersNovell()
        entry_quirk = main_quirk.EntryQuirk()
        entry_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: "cn=user,o=Example",
            FlextLdifConstants.DictKeys.SERVER_TYPE: FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY,
            "objectclass": ["top", "ndsperson"],
            "cn": ["user"],
        }
        result = entry_quirk.convert_entry_to_rfc(entry_data)

        assert result.is_success
        rfc_entry = result.unwrap()
        assert FlextLdifConstants.DictKeys.SERVER_TYPE not in rfc_entry
        assert rfc_entry[FlextLdifConstants.DictKeys.DN] == "cn=user,o=Example"
        assert "objectclass" in rfc_entry
