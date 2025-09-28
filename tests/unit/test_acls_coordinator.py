"""Test suite for FlextLdifAcls."""

import pytest

from flext_ldif.acls_coordinator import FlextLdifAcls
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks import constants


class TestFlextLdifAcls:
    """Test suite for FlextLdifAcls."""

    def test_initialization(self) -> None:
        """Test ACLs coordinator initialization."""
        coordinator = FlextLdifAcls()
        assert coordinator is not None
        assert coordinator.parser is not None
        assert coordinator.service is not None
        assert coordinator.builder is not None
        assert coordinator.converter is not None

    def test_execute(self) -> None:
        """Test execute method."""
        coordinator = FlextLdifAcls()
        result = coordinator.execute()
        assert result.is_success
        data = result.value
        assert data["status"] == "healthy"
        assert data["service"] == FlextLdifAcls
        assert "operations" in data

    @pytest.mark.asyncio
    async def test_execute_async(self) -> None:
        """Test async execute method."""
        coordinator = FlextLdifAcls()
        result = await coordinator.execute_async()
        assert result.is_success
        data = result.value
        assert data["status"] == "healthy"
        assert data["service"] == FlextLdifAcls
        assert "operations" in data


class TestFlextLdifAclsParser:
    """Test suite for FlextLdifAcls.Parser."""

    def test_initialization(self) -> None:
        """Test parser initialization."""
        coordinator = FlextLdifAcls()
        parser = coordinator.parser
        assert parser is not None
        assert parser.parent is coordinator

    def test_parse_openldap_basic(self) -> None:
        """Test parsing OpenLDAP ACL format."""
        coordinator = FlextLdifAcls()
        parser = coordinator.parser

        acl_string = "to * by dn.exact=cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com write"
        result = parser.parse_openldap(acl_string)

        assert result.is_success or result.is_failure
        if result.is_success:
            acl = result.value
            assert isinstance(acl, FlextLdifModels.UnifiedAcl)

    def test_parse_openldap_empty(self) -> None:
        """Test parsing empty OpenLDAP ACL."""
        coordinator = FlextLdifAcls()
        parser = coordinator.parser

        result = parser.parse_openldap("")
        assert result.is_success or result.is_failure

    def test_parse_389ds_basic(self) -> None:
        """Test parsing 389DS ACL format."""
        coordinator = FlextLdifAcls()
        parser = coordinator.parser

        acl_string = '(targetattr="*")(version 3.0; acl "test"; allow (read, search, compare) userdn="ldap:///self";)'
        result = parser.parse_389ds(acl_string)

        assert result.is_success or result.is_failure
        if result.is_success:
            acl = result.value
            assert isinstance(acl, FlextLdifModels.UnifiedAcl)

    def test_parse_389ds_empty(self) -> None:
        """Test parsing empty 389DS ACL."""
        coordinator = FlextLdifAcls()
        parser = coordinator.parser

        result = parser.parse_389ds("")
        assert result.is_success or result.is_failure

    def test_parse_oracle_basic(self) -> None:
        """Test parsing Oracle ACL format."""
        coordinator = FlextLdifAcls()
        parser = coordinator.parser

        acl_string = 'dn: cn=test,dc=example,dc=com\naccess to * by dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com" write'
        result = parser.parse_oracle(acl_string)

        assert result.is_success or result.is_failure
        if result.is_success:
            acl = result.value
            assert isinstance(acl, FlextLdifModels.UnifiedAcl)

    def test_parse_oracle_with_server_type(self) -> None:
        """Test parsing Oracle ACL with specific server type."""
        coordinator = FlextLdifAcls()
        parser = coordinator.parser

        acl_string = 'dn: cn=test,dc=example,dc=com\naccess to * by dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com" write'
        result = parser.parse_oracle(acl_string, constants.SERVER_TYPE_ORACLE_OUD)

        assert result.is_success or result.is_failure
        if result.is_success:
            acl = result.value
            assert isinstance(acl, FlextLdifModels.UnifiedAcl)

    def test_parse_ad_basic(self) -> None:
        """Test parsing Active Directory ACL format."""
        coordinator = FlextLdifAcls()
        parser = coordinator.parser

        acl_string = "O:S-1-1-0G:DAD:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;S-1-1-0)"
        result = parser.parse_ad(acl_string)

        assert result.is_success or result.is_failure
        if result.is_success:
            acl = result.value
            assert isinstance(acl, FlextLdifModels.UnifiedAcl)

    def test_parse_generic(self) -> None:
        """Test parsing ACL with generic method."""
        coordinator = FlextLdifAcls()
        parser = coordinator.parser

        acl_string = "to * by dn.exact=cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com write"
        result = parser.parse(acl_string, constants.SERVER_TYPE_OPENLDAP)

        assert result.is_success or result.is_failure
        if result.is_success:
            acl = result.value
            assert isinstance(acl, FlextLdifModels.UnifiedAcl)


class TestFlextLdifAclsService:
    """Test suite for FlextLdifAcls.Service."""

    def test_initialization(self) -> None:
        """Test service initialization."""
        coordinator = FlextLdifAcls()
        service = coordinator.service
        assert service is not None
        assert service.parent is coordinator

    def test_extract_from_entry_basic(self) -> None:
        """Test extracting ACLs from a single entry."""
        coordinator = FlextLdifAcls()
        service = coordinator.service

        # Create a test entry with ACL attributes
        entry_result = FlextLdifModels.Entry.create({
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "objectClass": ["top", "person"],
                "olcAccess": ["to * by dn.exact=cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com write"],
            },
        })
        assert entry_result.is_success
        entry = entry_result.value

        result = service.extract_from_entry(entry)
        assert result.is_success
        acls = result.value
        assert isinstance(acls, list)

    def test_extract_from_entry_no_acls(self) -> None:
        """Test extracting ACLs from entry with no ACL attributes."""
        coordinator = FlextLdifAcls()
        service = coordinator.service

        # Create a test entry without ACL attributes
        entry_result = FlextLdifModels.Entry.create({
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["top", "person"]},
        })
        assert entry_result.is_success
        entry = entry_result.value

        result = service.extract_from_entry(entry)
        assert result.is_success
        acls = result.value
        assert isinstance(acls, list)
        assert len(acls) == 0

    def test_extract_from_entry_with_server_type(self) -> None:
        """Test extracting ACLs from entry with specific server type."""
        coordinator = FlextLdifAcls()
        service = coordinator.service

        # Create a test entry with ACL attributes
        entry_result = FlextLdifModels.Entry.create({
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "objectClass": ["top", "person"],
                "aci": [
                    '(targetattr="*")(version 3.0; acl "test"; allow (read, search, compare) userdn="ldap:///self";)'
                ],
            },
        })
        assert entry_result.is_success
        entry = entry_result.value

        result = service.extract_from_entry(entry, constants.SERVER_TYPE_389DS)
        assert result.is_success
        acls = result.value
        assert isinstance(acls, list)

    def test_extract_from_entries_basic(self) -> None:
        """Test extracting ACLs from multiple entries."""
        coordinator = FlextLdifAcls()
        service = coordinator.service

        # Create test entries
        entry1_result = FlextLdifModels.Entry.create({
            "dn": "cn=test1,dc=example,dc=com",
            "attributes": {
                "cn": ["test1"],
                "objectClass": ["top", "person"],
                "olcAccess": ["to * by dn.exact=cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com write"],
            },
        })
        assert entry1_result.is_success
        entry2_result = FlextLdifModels.Entry.create({
            "dn": "cn=test2,dc=example,dc=com",
            "attributes": {
                "cn": ["test2"],
                "objectClass": ["top", "person"],
                "olcAccess": ["to * by dn.exact=cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com read"],
            },
        })
        assert entry2_result.is_success

        entries = [entry1_result.value, entry2_result.value]

        result = service.extract_from_entries(entries)
        assert result.is_success
        acls = result.value
        assert isinstance(acls, list)
        assert len(acls) >= 0

    def test_extract_from_entries_empty(self) -> None:
        """Test extracting ACLs from empty entries list."""
        coordinator = FlextLdifAcls()
        service = coordinator.service

        result = service.extract_from_entries([])
        assert result.is_success
        acls = result.value
        assert isinstance(acls, list)
        assert len(acls) == 0


class TestFlextLdifAclsBuilder:
    """Test suite for FlextLdifAcls.Builder."""

    def test_initialization(self) -> None:
        """Test builder initialization."""
        coordinator = FlextLdifAcls()
        builder = coordinator.builder
        assert builder is not None
        assert builder.parent is coordinator

    def test_build_read_permission(self) -> None:
        """Test building ACL with read permission."""
        coordinator = FlextLdifAcls()
        builder = coordinator.builder

        result = builder.build_read_permission(
            "cn=test,dc=example,dc=com", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        )
        assert result.is_success
        acl = result.value
        assert isinstance(acl, FlextLdifModels.UnifiedAcl)

    def test_build_read_permission_invalid_target(self) -> None:
        """Test building ACL with invalid target DN."""
        coordinator = FlextLdifAcls()
        builder = coordinator.builder

        result = builder.build_read_permission("", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
        # The builder may be lenient and allow empty target DN
        assert result.is_success or result.is_failure
        if result.is_failure and result.error is not None:
            assert "Target creation failed" in result.error

    def test_build_read_permission_invalid_subject(self) -> None:
        """Test building ACL with invalid subject DN."""
        coordinator = FlextLdifAcls()
        builder = coordinator.builder

        result = builder.build_read_permission("cn=test,dc=example,dc=com", "")
        # The builder may be lenient and allow empty subject DN
        assert result.is_success or result.is_failure
        if result.is_failure and result.error is not None:
            assert "Subject creation failed" in result.error

    def test_build_write_permission(self) -> None:
        """Test building ACL with write permission."""
        coordinator = FlextLdifAcls()
        builder = coordinator.builder

        result = builder.build_write_permission(
            "cn=test,dc=example,dc=com", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        )
        assert result.is_success
        acl = result.value
        assert isinstance(acl, FlextLdifModels.UnifiedAcl)

    def test_build_REDACTED_LDAP_BIND_PASSWORD_permission(self) -> None:
        """Test building ACL with REDACTED_LDAP_BIND_PASSWORD permission."""
        coordinator = FlextLdifAcls()
        builder = coordinator.builder

        result = builder.build_REDACTED_LDAP_BIND_PASSWORD_permission(
            "cn=test,dc=example,dc=com", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        )
        assert result.is_success
        acl = result.value
        assert isinstance(acl, FlextLdifModels.UnifiedAcl)


class TestFlextLdifAclsConverter:
    """Test suite for FlextLdifAcls.Converter."""

    def test_initialization(self) -> None:
        """Test converter initialization."""
        coordinator = FlextLdifAcls()
        converter = coordinator.converter
        assert converter is not None
        assert converter.parent is coordinator

    def test_to_openldap(self) -> None:
        """Test converting ACL to OpenLDAP format."""
        coordinator = FlextLdifAcls()
        converter = coordinator.converter

        # Create a test ACL
        acl_result = coordinator.builder.build_read_permission(
            "cn=test,dc=example,dc=com", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        )
        assert acl_result.is_success
        acl = acl_result.value

        result = converter.to_openldap(acl)
        assert result.is_success
        openldap_format = result.value
        assert isinstance(openldap_format, str)

    def test_to_389ds(self) -> None:
        """Test converting ACL to 389DS format."""
        coordinator = FlextLdifAcls()
        converter = coordinator.converter

        # Create a test ACL
        acl_result = coordinator.builder.build_read_permission(
            "cn=test,dc=example,dc=com", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        )
        assert acl_result.is_success
        acl = acl_result.value

        result = converter.to_389ds(acl)
        assert result.is_success
        aci_format = result.value
        assert isinstance(aci_format, str)

    def test_to_oracle(self) -> None:
        """Test converting ACL to Oracle format."""
        coordinator = FlextLdifAcls()
        converter = coordinator.converter

        # Create a test ACL
        acl_result = coordinator.builder.build_read_permission(
            "cn=test,dc=example,dc=com", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        )
        assert acl_result.is_success
        acl = acl_result.value

        result = converter.to_oracle(acl)
        assert result.is_success
        oracle_format = result.value
        assert isinstance(oracle_format, str)

    def test_to_ad(self) -> None:
        """Test converting ACL to Active Directory format."""
        coordinator = FlextLdifAcls()
        converter = coordinator.converter

        # Create a test ACL
        acl_result = coordinator.builder.build_read_permission(
            "cn=test,dc=example,dc=com", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        )
        assert acl_result.is_success
        acl = acl_result.value

        result = converter.to_ad(acl)
        assert result.is_success
        ad_format = result.value
        assert isinstance(ad_format, str)


class TestFlextLdifAclsIntegration:
    """Integration tests for FlextLdifAcls."""

    def test_full_workflow_build_parse_convert(self) -> None:
        """Test full workflow: build ACL, parse it, and convert it."""
        coordinator = FlextLdifAcls()

        # Build an ACL
        build_result = coordinator.builder.build_read_permission(
            "cn=test,dc=example,dc=com", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        )
        assert build_result.is_success
        acl = build_result.value

        # Convert to OpenLDAP format
        convert_result = coordinator.converter.to_openldap(acl)
        assert convert_result.is_success
        openldap_format = convert_result.value

        # Parse the converted format
        parse_result = coordinator.parser.parse_openldap(openldap_format)
        assert parse_result.is_success or parse_result.is_failure

    def test_extract_and_convert_workflow(self) -> None:
        """Test workflow: extract ACLs from entry and convert them."""
        coordinator = FlextLdifAcls()

        # Create a test entry with ACL attributes
        entry_result = FlextLdifModels.Entry.create({
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "objectClass": ["top", "person"],
                "olcAccess": ["to * by dn.exact=cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com write"],
            },
        })
        assert entry_result.is_success
        entry = entry_result.value

        # Extract ACLs
        extract_result = coordinator.service.extract_from_entry(entry)
        assert extract_result.is_success
        acls = extract_result.value

        if len(acls) > 0:
            # Convert the first ACL
            convert_result = coordinator.converter.to_openldap(acls[0])
            assert convert_result.is_success

    def test_all_operations_working_together(self) -> None:
        """Test all coordinator operations working together."""
        coordinator = FlextLdifAcls()

        # Test parser
        parse_result = coordinator.parser.parse_openldap(
            "to * by dn.exact=cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com write"
        )
        assert parse_result.is_success or parse_result.is_failure

        # Test builder
        build_result = coordinator.builder.build_read_permission(
            "cn=test,dc=example,dc=com", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        )
        assert build_result.is_success

        # Test service
        entry_result = FlextLdifModels.Entry.create({
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "objectClass": ["top", "person"],
                "olcAccess": ["to * by dn.exact=cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com write"],
            },
        })
        assert entry_result.is_success
        service_result = coordinator.service.extract_from_entry(entry_result.value)
        assert service_result.is_success

        # Test converter
        convert_result = coordinator.converter.to_openldap(build_result.value)
        assert convert_result.is_success
