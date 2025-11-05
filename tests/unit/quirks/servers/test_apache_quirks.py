"""Tests for Apache Directory Server quirks implementation."""

from __future__ import annotations

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.apache import FlextLdifServersApache

class TestApacheDirectorySchemas:
    """Tests for Apache Directory Server schema quirk handling."""

    def test_initialization(self) -> None:
        """Test Apache Directory Server quirk initialization."""
        quirk = FlextLdifServersApache()
        assert (
            FlextLdifServersApache.Constants.SERVER_TYPE
            == FlextLdifConstants.LdapServers.APACHE_DIRECTORY
        )
        assert FlextLdifServersApache.Constants.PRIORITY == 15
        # Verify class-level attributes are set from Constants
        assert FlextLdifServersApache.Constants.SERVER_TYPE == FlextLdifConstants.LdapServers.APACHE_DIRECTORY
        assert FlextLdifServersApache.Constants.PRIORITY == 15
        # Verify class-level attributes are set from Constants
        assert FlextLdifServersApache.server_type == FlextLdifConstants.LdapServers.APACHE_DIRECTORY
        assert FlextLdifServersApache.priority == 15
        # Verify nested instances exist
        assert quirk.schema is not None
        assert quirk.acl is not None
        assert quirk.entry is not None

    def test_can_handle_attribute_with_apache_oid(self) -> None:
        """Test attribute detection with Apache DS OID pattern."""
        main_quirk = FlextLdifServersApache()
        quirk = main_quirk.schema
        attr_def = "( 1.3.6.1.4.1.18060.0.4.1.2.100 NAME 'ads-enabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )"
        # Parse string definition into model object

        parse_result = quirk.parse(attr_def)

        assert parse_result.is_success, (
            f"Failed to parse attribute: {parse_result.error}"
        )

        attr_model = parse_result.unwrap()

        # Test with the model object

        assert quirk._can_handle_attribute(attr_model) is True

    def test_can_handle_attribute_with_ads_prefix(self) -> None:
        """Test attribute detection with ads- prefix."""
        main_quirk = FlextLdifServersApache()
        quirk = main_quirk.schema
        attr_def = "( 2.16.840.1.113730.3.1.1 NAME 'ads-searchBaseDN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )"
        # Parse string definition into model object

        parse_result = quirk.parse(attr_def)

        assert parse_result.is_success, (
            f"Failed to parse attribute: {parse_result.error}"
        )

        attr_model = parse_result.unwrap()

        # Test with the model object

        assert quirk._can_handle_attribute(attr_model) is True

    def test_can_handle_attribute_with_apacheds_name(self) -> None:
        """Test attribute detection with apacheds in name."""
        main_quirk = FlextLdifServersApache()
        quirk = main_quirk.schema
        attr_def = (
            "( 1.2.3.4 NAME 'apachedsSystemId' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        # Parse string definition into model object

        parse_result = quirk.parse(attr_def)

        assert parse_result.is_success, (
            f"Failed to parse attribute: {parse_result.error}"
        )

        attr_model = parse_result.unwrap()

        # Test with the model object

        assert quirk._can_handle_attribute(attr_model) is True

    def test_can_handle_attribute_negative(self) -> None:
        """Test attribute detection rejects non-ApacheDS attributes."""
        main_quirk = FlextLdifServersApache()
        quirk = main_quirk.schema
        attr_def = "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        # Parse string definition into model object

        parse_result = quirk.parse(attr_def)

        assert parse_result.is_success, (
            f"Failed to parse attribute: {parse_result.error}"
        )

        attr_model = parse_result.unwrap()

        # Test with the model object

        assert quirk._can_handle_attribute(attr_model) is False

    def test_parse_attribute_success(self) -> None:
        """Test parsing Apache DS attribute definition."""
        main_quirk = FlextLdifServersApache()
        quirk = main_quirk.schema
        attr_def = "( 1.3.6.1.4.1.18060.0.4.1.2.100 NAME 'ads-enabled' DESC 'Enable flag' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )"
        result = quirk.parse(attr_def)

        assert result.is_success
        attr_data = result.unwrap()
        assert attr_data.oid == "1.3.6.1.4.1.18060.0.4.1.2.100"
        assert attr_data.name == "ads-enabled"
        assert attr_data.desc == "Enable flag"
        assert attr_data.syntax == "1.3.6.1.4.1.1466.115.121.1.7"
        assert attr_data.single_value is True

    def test_parse_attribute_with_syntax_length(self) -> None:
        """Test parsing attribute with syntax length specification."""
        main_quirk = FlextLdifServersApache()
        quirk = main_quirk.schema
        attr_def = "( 1.3.6.1.4.1.18060.0.4.1.2.1 NAME 'ads-directoryServiceId' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        result = quirk.parse(attr_def)

        assert result.is_success
        attr_data = result.unwrap()
        assert attr_data.syntax == "1.3.6.1.4.1.1466.115.121.1.15"
        assert attr_data.length == 256

    def test_parse_attribute_missing_oid(self) -> None:
        """Test parsing attribute without OID fails."""
        main_quirk = FlextLdifServersApache()
        quirk = main_quirk.schema
        attr_def = "NAME 'ads-enabled' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7"
        result = quirk.parse(attr_def)

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None
        assert "missing an OID" in result.error

    def test_can_handle_objectclass_with_apache_oid(self) -> None:
        """Test objectClass detection with Apache DS OID."""
        main_quirk = FlextLdifServersApache()
        quirk = main_quirk.schema
        oc_def = "( 1.3.6.1.4.1.18060.0.4.1.3.100 NAME 'ads-directoryService' SUP top STRUCTURAL )"
        # Parse string definition into model object

        parse_result = quirk.parse(oc_def)

        assert parse_result.is_success, (
            f"Failed to parse objectClass: {parse_result.error}"
        )

        oc_model = parse_result.unwrap()

        # Test with the model object

        assert quirk._can_handle_objectclass(oc_model) is True

    def test_can_handle_objectclass_with_ads_name(self) -> None:
        """Test objectClass detection with ads- name."""
        main_quirk = FlextLdifServersApache()
        quirk = main_quirk.schema
        oc_def = "( 2.5.6.0 NAME 'ads-base' SUP top ABSTRACT )"
        # Parse string definition into model object

        parse_result = quirk.parse(oc_def)

        assert parse_result.is_success, (
            f"Failed to parse objectClass: {parse_result.error}"
        )

        oc_model = parse_result.unwrap()

        # Test with the model object

        assert quirk._can_handle_objectclass(oc_model) is True

    def test_can_handle_objectclass_negative(self) -> None:
        """Test objectClass detection rejects non-ApacheDS classes."""
        main_quirk = FlextLdifServersApache()
        quirk = main_quirk.schema
        oc_def = "( 2.5.6.6 NAME 'posixAccount' SUP top STRUCTURAL )"
        # Parse string definition into model object

        parse_result = quirk.parse(oc_def)

        assert parse_result.is_success, (
            f"Failed to parse objectClass: {parse_result.error}"
        )

        oc_model = parse_result.unwrap()

        # Test with the model object

        assert quirk._can_handle_objectclass(oc_model) is False

    def test_parse_objectclass_structural(self) -> None:
        """Test parsing STRUCTURAL objectClass."""
        main_quirk = FlextLdifServersApache()
        quirk = main_quirk.schema
        oc_def = "( 1.3.6.1.4.1.18060.0.4.1.3.100 NAME 'ads-directoryService' DESC 'Directory service' SUP top STRUCTURAL MUST ( cn $ ads-directoryServiceId ) MAY ( ads-enabled ) )"
        result = quirk.parse(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data.oid == "1.3.6.1.4.1.18060.0.4.1.3.100"
        assert oc_data.name == "ads-directoryService"
        assert oc_data.kind == "STRUCTURAL"
        assert oc_data.sup == "top"
        must_attrs = oc_data.must
        assert isinstance(must_attrs, list)
        assert "cn" in must_attrs
        assert "ads-directoryServiceId" in must_attrs
        may_attrs = oc_data.may
        assert isinstance(may_attrs, list)
        assert "ads-enabled" in may_attrs

    def test_parse_objectclass_auxiliary(self) -> None:
        """Test parsing AUXILIARY objectClass."""
        main_quirk = FlextLdifServersApache()
        quirk = main_quirk.schema
        oc_def = "( 1.3.6.1.4.1.18060.0.4.1.3.200 NAME 'ads-partition' AUXILIARY MAY ( ads-partitionSuffix $ ads-contextEntry ) )"
        result = quirk.parse(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data.kind == "AUXILIARY"

    def test_parse_objectclass_abstract(self) -> None:
        """Test parsing ABSTRACT objectClass."""
        main_quirk = FlextLdifServersApache()
        quirk = main_quirk.schema
        oc_def = "( 1.3.6.1.4.1.18060.0.4.1.3.1 NAME 'ads-base' ABSTRACT )"
        result = quirk.parse(oc_def)

        assert result.is_success
        oc_data = result.unwrap()
        assert oc_data.kind == "ABSTRACT"

    def test_parse_objectclass_missing_oid(self) -> None:
        """Test parsing objectClass without OID fails."""
        main_quirk = FlextLdifServersApache()
        quirk = main_quirk.schema
        oc_def = "NAME 'ads-directoryService' SUP top STRUCTURAL"
        result = quirk.parse(oc_def)

        assert result.is_failure
        assert result.error is not None
        assert "missing an OID" in result.error

    def test_write_attribute_to_rfc(self) -> None:
        """Test writing attribute to RFC string format."""
        main_quirk = FlextLdifServersApache()
        quirk = main_quirk.schema
        # Create proper SchemaAttribute model instead of dict
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="1.3.6.1.4.1.18060.0.4.1.2.100",
            name="ads-enabled",
            desc="Enable flag",
            syntax="1.3.6.1.4.1.1466.115.121.1.7",
            single_value=True,
        )
        result = quirk.write(attr_data)

        assert result.is_success
        attr_str = result.unwrap()
        assert "1.3.6.1.4.1.18060.0.4.1.2.100" in attr_str
        assert "ads-enabled" in attr_str
        assert "SINGLE-VALUE" in attr_str

    def test_write_objectclass_to_rfc(self) -> None:
        """Test writing objectClass to RFC string format."""
        main_quirk = FlextLdifServersApache()
        quirk = main_quirk.schema
        # Create proper SchemaObjectClass model instead of dict
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="1.3.6.1.4.1.18060.0.4.1.3.100",
            name="ads-directoryService",
            kind="STRUCTURAL",
            sup="top",
            must=["cn", "ads-directoryServiceId"],
            may=["ads-enabled"],
        )
        result = quirk.write(oc_data)

        assert result.is_success
        oc_str = result.unwrap()
        assert "1.3.6.1.4.1.18060.0.4.1.3.100" in oc_str
        assert "ads-directoryService" in oc_str
        assert "STRUCTURAL" in oc_str

class TestApacheDirectoryAcls:
    """Tests for Apache Directory Server ACL quirk handling."""

    def test_acl_quirk_initialization(self) -> None:
        """Test ACL quirk initialization."""
        main_quirk = FlextLdifServersApache()
        acl_quirk = main_quirk.acl
        assert (
            FlextLdifServersApache.Constants.SERVER_TYPE
            == FlextLdifConstants.LdapServers.APACHE_DIRECTORY
        )
        assert FlextLdifServersApache.Constants.PRIORITY == 15
        # Verify class-level attributes are set from Constants
        assert FlextLdifServersApache.Constants.SERVER_TYPE == FlextLdifConstants.LdapServers.APACHE_DIRECTORY
        assert FlextLdifServersApache.Constants.PRIORITY == 15
        # Verify class-level attributes are set from Constants
        assert FlextLdifServersApache.server_type == FlextLdifConstants.LdapServers.APACHE_DIRECTORY
        assert FlextLdifServersApache.priority == 15

    def test__can_handle_with_ads_aci(self) -> None:
        """Test ACL detection with ads-aci attribute."""
        main_quirk = FlextLdifServersApache()
        acl_quirk = main_quirk.acl
        acl_line = "ads-aci: ( version 3.0 ) ( deny grantAdd ) ( grantRemove )"
        # Parse string ACL into model object

        parse_result = acl_quirk.parse(acl_line)

        assert parse_result.is_success, f"Failed to parse ACL: {parse_result.error}"

        acl_model = parse_result.unwrap()

        # Test with the model object

        assert acl_quirk._can_handle(acl_model) is True

    def test__can_handle_with_aci(self) -> None:
        """Test ACL detection with aci attribute."""
        main_quirk = FlextLdifServersApache()
        acl_quirk = main_quirk.acl
        acl_line = "aci: ( version 3.0 ) ( deny grantAdd ) ( grantRemove )"
        # Parse string ACL into model object

        parse_result = acl_quirk.parse(acl_line)

        assert parse_result.is_success, f"Failed to parse ACL: {parse_result.error}"

        acl_model = parse_result.unwrap()

        # Test with the model object

        assert acl_quirk._can_handle(acl_model) is True

    def test__can_handle_with_version_prefix(self) -> None:
        """Test ACL detection with version prefix."""
        main_quirk = FlextLdifServersApache()
        acl_quirk = main_quirk.acl
        acl_line = "(version 3.0) (deny grantAdd) (grantRemove)"
        # Parse string ACL into model object

        parse_result = acl_quirk.parse(acl_line)

        assert parse_result.is_success, f"Failed to parse ACL: {parse_result.error}"

        acl_model = parse_result.unwrap()

        # Test with the model object

        assert acl_quirk._can_handle(acl_model) is True

    def test__can_handle_negative(self) -> None:
        """Test ACL detection rejects non-ApacheDS ACLs."""
        main_quirk = FlextLdifServersApache()
        acl_quirk = main_quirk.acl
        acl_line = "access to * by * read"
        # Parse string ACL into model object

        parse_result = acl_quirk.parse(acl_line)

        assert parse_result.is_success, f"Failed to parse ACL: {parse_result.error}"

        acl_model = parse_result.unwrap()

        # Test with the model object

        assert acl_quirk._can_handle(acl_model) is False

    def test__can_handle_empty_line(self) -> None:
        """Test ACL detection rejects empty lines."""
        main_quirk = FlextLdifServersApache()
        acl_quirk = main_quirk.acl
        acl_line = ""
        # Empty string should return False for can_handle
        assert acl_quirk._can_handle(acl_line) is False

    def test_parse_success(self) -> None:
        """Test parsing Apache DS ACI definition."""
        main_quirk = FlextLdifServersApache()
        acl_quirk = main_quirk.acl
        acl_line = "ads-aci: ( version 3.0 ) ( deny grantAdd ) ( grantRemove )"
        result = acl_quirk.parse(acl_line)

        assert result.is_success
        acl_data = result.unwrap()
        assert acl_data.get_acl_format() == FlextLdifConstants.AclFormats.ACI
        assert acl_data.name == "apache-ads-aci"  # Server prefix is prepended
        assert acl_data.raw_acl == acl_line
        assert acl_data.server_type == FlextLdifConstants.LdapServers.APACHE_DIRECTORY

    def test_parse_with_aci_attribute(self) -> None:
        """Test parsing ACI with aci attribute."""
        main_quirk = FlextLdifServersApache()
        acl_quirk = main_quirk.acl
        acl_line = "aci: ( deny grantAdd )"
        result = acl_quirk.parse(acl_line)

        assert result.is_success
        acl_data = result.unwrap()
        # The name will have server prefix: "apache-aci"
        assert acl_data.name == "apache-aci"

    def test_write_acl_to_rfc_with_content(self) -> None:
        """Test writing ACL with content to RFC string format."""
        main_quirk = FlextLdifServersApache()
        acl_quirk = main_quirk.acl

        # Create proper Acl model with raw_acl containing the content
        acl_model = FlextLdifModels.Acl(
            name="ads-aci",
            target=FlextLdifModels.AclTarget(target_dn="", attributes=[]),
            subject=FlextLdifModels.AclSubject(subject_type="", subject_value=""),
            permissions=FlextLdifModels.AclPermissions(),
            server_type="apache_directory",
            raw_acl="( version 3.0 ) ( deny grantAdd )",
        )
        result = acl_quirk.write(acl_model)

        assert result.is_success
        acl_str = result.unwrap()
        # The write method uses the name and raw_acl fields
        assert "aci:" in acl_str or "ads-aci" in acl_str

    def test_write_acl_to_rfc_with_clauses_only(self) -> None:
        """Test writing ACL with clauses only to RFC string format."""
        main_quirk = FlextLdifServersApache()
        acl_quirk = main_quirk.acl

        # Create proper Acl model with raw_acl containing the clauses joined
        acl_model = FlextLdifModels.Acl(
            name="aci",
            target=FlextLdifModels.AclTarget(target_dn="", attributes=[]),
            subject=FlextLdifModels.AclSubject(subject_type="", subject_value=""),
            permissions=FlextLdifModels.AclPermissions(),
            server_type="apache_directory",
            raw_acl="( version 3.0 ) ( deny grantAdd )",
        )
        result = acl_quirk.write(acl_model)

        assert result.is_success
        acl_str = result.unwrap()
        # The write method uses the ACL model fields
        assert "aci:" in acl_str

    def test_write_acl_to_rfc_empty(self) -> None:
        """Test writing empty ACL to RFC string format."""
        main_quirk = FlextLdifServersApache()
        acl_quirk = main_quirk.acl

        # Create proper Acl model with minimal fields
        acl_model = FlextLdifModels.Acl(
            name="ads-aci",
            target=FlextLdifModels.AclTarget(target_dn="", attributes=[]),
            subject=FlextLdifModels.AclSubject(subject_type="", subject_value=""),
            permissions=FlextLdifModels.AclPermissions(),
            server_type="apache_directory",
            raw_acl="",
        )
        result = acl_quirk.write(acl_model)

        assert result.is_success
        acl_str = result.unwrap()
        # The write method uses the ACL name field
        assert "ads-aci" in acl_str or "aci:" in acl_str

class TestApacheDirectoryEntrys:
    """Tests for Apache Directory Server entry quirk handling."""

    def test_entry_quirk_initialization(self) -> None:
        """Test entry quirk initialization."""
        FlextLdifServersApache()
        assert (
            FlextLdifServersApache.Constants.SERVER_TYPE
            == FlextLdifConstants.LdapServers.APACHE_DIRECTORY
        )
        assert FlextLdifServersApache.Constants.PRIORITY == 15
        # Verify class-level attributes are set from Constants
        assert FlextLdifServersApache.Constants.SERVER_TYPE == FlextLdifConstants.LdapServers.APACHE_DIRECTORY
        assert FlextLdifServersApache.Constants.PRIORITY == 15
        # Verify class-level attributes are set from Constants
        assert FlextLdifServersApache.server_type == FlextLdifConstants.LdapServers.APACHE_DIRECTORY
        assert FlextLdifServersApache.priority == 15

    def test_can_handle_entry_with_ou_config(self) -> None:
        """Test entry detection with ou=config DN marker."""
        main_quirk = FlextLdifServersApache()
        entry_quirk = main_quirk.entry
        entry_dn = "ou=config,dc=example,dc=com"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["organizationalUnit"]
        }
        assert entry_quirk._can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_ou_services(self) -> None:
        """Test entry detection with ou=services DN marker."""
        main_quirk = FlextLdifServersApache()
        entry_quirk = main_quirk.entry
        entry_dn = "ou=services,dc=example,dc=com"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["organizationalUnit"]
        }
        assert entry_quirk._can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_ou_system(self) -> None:
        """Test entry detection with ou=system DN marker."""
        main_quirk = FlextLdifServersApache()
        entry_quirk = main_quirk.entry
        entry_dn = "ou=system,dc=example,dc=com"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["organizationalUnit"]
        }
        assert entry_quirk._can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_ou_partitions(self) -> None:
        """Test entry detection with ou=partitions DN marker."""
        main_quirk = FlextLdifServersApache()
        entry_quirk = main_quirk.entry
        entry_dn = "ou=partitions,dc=example,dc=com"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["organizationalUnit"]
        }
        assert entry_quirk._can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_ads_attribute(self) -> None:
        """Test entry detection with ads- attribute prefix."""
        main_quirk = FlextLdifServersApache()
        entry_quirk = main_quirk.entry
        entry_dn = "cn=test,dc=example,dc=com"
        attributes: dict[str, object] = {
            "ads-enabled": ["TRUE"],
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["top"],
        }
        assert entry_quirk._can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_apacheds_attribute(self) -> None:
        """Test entry detection with apacheds attribute prefix."""
        main_quirk = FlextLdifServersApache()
        entry_quirk = main_quirk.entry
        entry_dn = "cn=test,dc=example,dc=com"
        attributes: dict[str, object] = {
            "apachedsSystemId": ["test"],
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["top"],
        }
        assert entry_quirk._can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_with_ads_objectclass(self) -> None:
        """Test entry detection with ads- objectClass."""
        main_quirk = FlextLdifServersApache()
        entry_quirk = main_quirk.entry
        entry_dn = "cn=test,dc=example,dc=com"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["top", "ads-directoryService"]
        }
        assert entry_quirk._can_handle_entry(entry_dn, attributes) is True

    def test_can_handle_entry_negative(self) -> None:
        """Test entry detection rejects non-ApacheDS entries."""
        main_quirk = FlextLdifServersApache()
        entry_quirk = main_quirk.entry
        entry_dn = "cn=user,dc=example,dc=com"
        attributes: dict[str, object] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: ["person"],
            "cn": ["user"],
        }
        assert entry_quirk._can_handle_entry(entry_dn, attributes) is False

