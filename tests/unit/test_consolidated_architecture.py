"""Test consolidated architecture - parser, quirks, schema, ACL modules.

Tests the unified module structure after consolidation:
- FlextLdifParser (consolidated from parser_advanced.py)
- FlextLdifQuirksAdapter (consolidated from server_quirks.py)
- Schema modules in schema/ directory
- ACL modules in acl/ directory
"""

from pathlib import Path

from flext_ldif import (
    FlextLdifManagement,
    FlextLdifModels,
    FlextLdifParser,
)
from flext_ldif.acl import (
    FlextLdifAclParser,
    FlextLdifAclService,
)
from flext_ldif.quirks import (
    FlextLdifEntryQuirks,
    FlextLdifQuirksAdapter,
    FlextLdifQuirksManager,
)
from flext_ldif.schema import (
    FlextLdifObjectClassManager,
    FlextLdifSchemaExtractor,
    FlextLdifSchemaValidator,
)


class TestConsolidatedParser:
    """Test consolidated FlextLdifParser (was FlextLdifAdvancedParser)."""

    def test_parser_imports(self):
        """Verify parser can be imported from consolidated module."""
        assert FlextLdifParser is not None

    def test_parser_instantiation(self):
        """Test parser can be instantiated with config."""
        parser = FlextLdifParser({"encoding": "utf-8", "strict_mode": True})
        assert parser is not None

    def test_parse_simple_entry(self):
        """Test parsing a simple LDIF entry."""
        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
objectClass: top

"""
        parser = FlextLdifParser()
        result = parser.parse_string(ldif_content)

        assert result.is_success
        entries = result.value
        assert len(entries) == 1
        assert entries[0].dn.value == "cn=test,dc=example,dc=com"

    def test_parse_base64_values(self):
        """Test parsing LDIF with Base64 encoded values."""
        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
description:: VGVzdCBEZXNjcmlwdGlvbg==

"""
        parser = FlextLdifParser()
        result = parser.parse_string(ldif_content)

        assert result.is_success
        entries = result.value
        assert len(entries) == 1

    def test_parse_change_record(self):
        """Test parsing LDIF change records."""
        ldif_content = """dn: cn=test,dc=example,dc=com
changetype: add
cn: test
objectClass: person

"""
        parser = FlextLdifParser()
        result = parser.parse_string(ldif_content)

        assert result.is_success
        entries = result.value
        assert len(entries) == 1

    def test_detect_server_type(self):
        """Test server type detection from entries."""
        ldif_content = """dn: cn=config
objectClass: olcGlobal
olcServerID: 1

"""
        parser = FlextLdifParser()
        parse_result = parser.parse_string(ldif_content)
        assert parse_result.is_success

        server_result = parser.detect_server_type(parse_result.value)
        assert server_result.is_success
        assert server_result.value in ["openldap", "generic"]

    def test_validate_rfc_compliance(self):
        """Test RFC 2849 compliance validation."""
        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person

"""
        parser = FlextLdifParser()
        parse_result = parser.parse_string(ldif_content)
        assert parse_result.is_success

        compliance_result = parser.validate_rfc_compliance(parse_result.value)
        assert compliance_result.is_success
        assert "compliance_score" in compliance_result.value


class TestConsolidatedQuirks:
    """Test consolidated quirks modules (adapter, manager, entry_quirks)."""

    def test_quirks_adapter_imports(self):
        """Verify quirks adapter can be imported."""
        assert FlextLdifQuirksAdapter is not None

    def test_quirks_manager_imports(self):
        """Verify quirks manager can be imported."""
        assert FlextLdifQuirksManager is not None

    def test_quirks_adapter_instantiation(self):
        """Test quirks adapter instantiation."""
        adapter = FlextLdifQuirksAdapter(server_type="openldap")
        assert adapter is not None

    def test_adapt_entry_for_server(self):
        """Test entry adaptation for specific server type."""
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "objectClass": ["person"],
            }
        }
        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success

        adapter = FlextLdifQuirksAdapter(server_type="openldap")
        adapted_result = adapter.adapt_entry(entry_result.value, "openldap")
        assert adapted_result.is_success

    def test_validate_server_compliance(self):
        """Test server compliance validation."""
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "objectClass": ["person", "top"],
            }
        }
        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success

        adapter = FlextLdifQuirksAdapter(server_type="openldap")
        validation_result = adapter.validate_server_compliance(entry_result.value)
        assert validation_result.is_success
        assert "compliant" in validation_result.value

    def test_quirks_manager_detect_server(self):
        """Test server type detection using quirks manager."""
        entry_data = {
            "dn": "cn=config",
            "attributes": {
                "objectClass": ["olcGlobal"],
                "olcServerID": ["1"],
            }
        }
        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success

        manager = FlextLdifQuirksManager()
        server_result = manager.detect_server_type([entry_result.value])
        assert server_result.is_success

    def test_get_acl_attribute_name(self):
        """Test getting ACL attribute name for server type."""
        manager = FlextLdifQuirksManager()

        # OpenLDAP uses olcAccess
        acl_attr_result = manager.get_acl_attribute_name("openldap")
        assert acl_attr_result.is_success
        assert acl_attr_result.value == "olcAccess"

    def test_entry_quirks_adaptation(self):
        """Test entry quirks adaptation functionality."""
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "objectClass": ["person"],
            }
        }
        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success

        entry_quirks = FlextLdifEntryQuirks()
        adapted_result = entry_quirks.adapt_entry(
            entry_result.value, "openldap"
        )
        assert adapted_result.is_success


class TestConsolidatedSchema:
    """Test consolidated schema modules in schema/ directory."""

    def test_schema_extractor_import(self):
        """Verify schema extractor can be imported."""
        assert FlextLdifSchemaExtractor is not None

    def test_schema_validator_import(self):
        """Verify schema validator can be imported."""
        assert FlextLdifSchemaValidator is not None

    def test_objectclass_manager_import(self):
        """Verify objectclass manager can be imported from schema/."""
        assert FlextLdifObjectClassManager is not None

    def test_extract_schema_from_entries(self):
        """Test schema extraction from entries."""
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "sn": ["user"],
                "mail": ["test@example.com"],
                "objectClass": ["inetOrgPerson", "person", "top"],
            }
        }
        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success

        extractor = FlextLdifSchemaExtractor()
        schema_result = extractor.extract_from_entries([entry_result.value])
        assert schema_result.is_success

    def test_validate_entry_with_schema(self):
        """Test entry validation against schema."""
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "objectClass": ["person", "top"],
            }
        }
        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success

        # Extract schema first
        extractor = FlextLdifSchemaExtractor()
        schema_result = extractor.extract_from_entries([entry_result.value])
        assert schema_result.is_success

        # Validate entry
        validator = FlextLdifSchemaValidator()
        validation_result = validator.validate_entry_against_schema(
            entry_result.value, schema_result.value
        )
        assert validation_result.is_success


class TestConsolidatedACL:
    """Test consolidated ACL modules in acl/ directory."""

    def test_acl_parser_import(self):
        """Verify ACL parser can be imported."""
        assert FlextLdifAclParser is not None

    def test_acl_service_import(self):
        """Verify ACL service can be imported."""
        assert FlextLdifAclService is not None

    def test_parse_openldap_acl(self):
        """Test parsing OpenLDAP ACL."""
        acl_value = '{0}to * by * read'

        parser = FlextLdifAclParser()
        result = parser.parse_openldap_acl(acl_value)

        assert result.is_success

    def test_extract_acls_from_entries(self):
        """Test ACL extraction from entries."""
        entry_data = {
            "dn": "olcDatabase={1}mdb,cn=config",
            "attributes": {
                "objectClass": ["olcDatabaseConfig"],
                "olcAccess": [
                    '{0}to * by * read',
                    '{1}to dn.base="" by * read',
                ],
            }
        }
        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success

        service = FlextLdifAclService()
        acl_result = service.extract_acls_from_entry(
            entry_result.value, "openldap"
        )
        assert acl_result.is_success


class TestManagementCoordinator:
    """Test the unified management coordinator with consolidated modules."""

    def test_management_uses_consolidated_modules(self):
        """Verify management coordinator uses all consolidated modules."""
        management = FlextLdifManagement()

        # Verify coordinators are initialized
        assert management.schemas is not None
        assert management.entries is not None
        assert management.acls is not None
        assert management.quirks is not None

    def test_complete_ldif_processing(self):
        """Test complete LDIF processing pipeline."""
        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
sn: user
objectClass: person
objectClass: top

"""
        management = FlextLdifManagement()
        result = management.process_ldif_complete(ldif_content)

        assert result.is_success
        assert "entries" in result.value
        assert "server_type" in result.value

    def test_process_entries_with_acl(self):
        """Test processing entries with ACL extraction."""
        entry_data = {
            "dn": "olcDatabase={1}mdb,cn=config",
            "attributes": {
                "objectClass": ["olcDatabaseConfig"],
                "olcAccess": ['{0}to * by * read'],
            }
        }
        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success

        management = FlextLdifManagement()
        result = management.process_entries_with_acl([entry_result.value])

        assert result.is_success
        assert "acl_count" in result.value

    def test_process_entries_with_schema(self):
        """Test processing entries with schema extraction."""
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "objectClass": ["person", "top"],
            }
        }
        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success

        management = FlextLdifManagement()
        result = management.process_entries_with_schema([entry_result.value])

        assert result.is_success
        assert "schema" in result.value

    def test_adapt_entries_for_server(self):
        """Test adapting entries for target server."""
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "objectClass": ["person"],
            }
        }
        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success

        management = FlextLdifManagement()
        result = management.adapt_entries_for_server(
            [entry_result.value], "openldap"
        )

        assert result.is_success


class TestACLModels:
    """Test ACL models consolidated in models.py."""

    def test_acl_target_creation(self):
        """Test ACL target model creation."""
        result = FlextLdifModels.AclTarget.create(
            target_dn="dc=example,dc=com",
            target_filter="(objectClass=*)",
        )
        assert result.is_success
        assert result.value.target_dn == "dc=example,dc=com"

    def test_acl_subject_creation(self):
        """Test ACL subject model creation."""
        result = FlextLdifModels.AclSubject.create(
            subject_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            subject_type="user",
        )
        assert result.is_success
        assert result.value.subject_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"

    def test_acl_permissions_creation(self):
        """Test ACL permissions model creation."""
        result = FlextLdifModels.AclPermissions.create(
            read=True,
            write=True,
            search=True,
        )
        assert result.is_success
        assert result.value.read is True
        assert result.value.write is True

    def test_unified_acl_creation(self):
        """Test unified ACL model creation."""
        target_result = FlextLdifModels.AclTarget.create(
            target_dn="dc=example,dc=com"
        )
        subject_result = FlextLdifModels.AclSubject.create(
            subject_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        )
        perms_result = FlextLdifModels.AclPermissions.create(read=True)

        assert target_result.is_success
        assert subject_result.is_success
        assert perms_result.is_success

        acl_result = FlextLdifModels.UnifiedAcl.create(
            name="test-acl",
            target=target_result.value,
            subject=subject_result.value,
            permissions=perms_result.value,
            server_type="openldap",
            raw_acl='{0}to * by * read',
        )
        assert acl_result.is_success
        assert acl_result.value.name == "test-acl"


class TestNoLegacyModules:
    """Verify no legacy/duplicate modules exist."""

    def test_no_parser_advanced(self):
        """Ensure parser_advanced.py doesn't exist."""
        parser_advanced_path = Path("src/flext_ldif/parser_advanced.py")
        assert not parser_advanced_path.exists(), "Legacy parser_advanced.py still exists!"

    def test_no_server_quirks(self):
        """Ensure server_quirks.py doesn't exist at root."""
        server_quirks_path = Path("src/flext_ldif/server_quirks.py")
        assert not server_quirks_path.exists(), "Legacy server_quirks.py still exists!"

    def test_parser_exists(self):
        """Ensure consolidated parser.py exists."""
        parser_path = Path("src/flext_ldif/parser.py")
        assert parser_path.exists(), "Consolidated parser.py missing!"

    def test_quirks_adapter_exists(self):
        """Ensure quirks/adapter.py exists."""
        adapter_path = Path("src/flext_ldif/quirks/adapter.py")
        assert adapter_path.exists(), "Consolidated quirks/adapter.py missing!"
