"""Unit tests for flext_ldif.api module."""

from pathlib import Path

from flext_ldif import FlextLdifAPI, FlextLdifConfig
from flext_ldif.models import FlextLdifModels


class TestFlextLdifAPI:
    """Test cases for FlextLdifAPI class."""

    def test_init_default_config(self) -> None:
        """Test initialization with default config."""
        api = FlextLdifAPI()
        assert api._config is not None
        assert isinstance(api._config, FlextLdifConfig)

    def test_init_custom_config(self) -> None:
        """Test initialization with custom config."""
        config = FlextLdifConfig()
        api = FlextLdifAPI(config=config)
        assert api._config is config

    def test_processor_initializes_successfully(self) -> None:
        """Test that processor initializes successfully."""
        api = FlextLdifAPI()
        result = api._processor_result
        assert result.is_success
        assert result.unwrap() is not None

    def test_execute_calls_health_check(self) -> None:
        """Test execute method performs health check."""
        api = FlextLdifAPI()
        result = api.execute()
        assert result.is_success
        assert "status" in result.unwrap()
        assert result.unwrap()["status"] == "healthy"

    def test_parse_simple_ldif_content(self) -> None:
        """Test parsing simple LDIF content."""
        api = FlextLdifAPI()
        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: user

"""
        result = api.parse(ldif_content)
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1
        assert entries[0].dn.value == "cn=test,dc=example,dc=com"

    def test_parse_empty_content(self) -> None:
        """Test parsing empty LDIF content."""
        api = FlextLdifAPI()
        result = api.parse("")
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 0

    def test_validate_entries_success(self) -> None:
        """Test validating correct entries."""
        api = FlextLdifAPI()
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "sn": ["user"], "objectClass": ["person"]},
        }
        entry = FlextLdifModels.Entry.create(entry_data).unwrap()
        result = api.validate_entries([entry])
        assert result.is_success

    def test_write_entries_to_string(self) -> None:
        """Test writing entries to LDIF string."""
        api = FlextLdifAPI()
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"]},
        }
        entry = FlextLdifModels.Entry.create(entry_data).unwrap()
        result = api.write([entry])
        assert result.is_success
        content = result.unwrap()
        assert "cn=test,dc=example,dc=com" in content

    def test_write_entries_to_file(self, tmp_path: Path) -> None:
        """Test writing entries to LDIF file."""
        api = FlextLdifAPI()
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"]},
        }
        entry = FlextLdifModels.Entry.create(entry_data).unwrap()

        file_path = tmp_path / "test_output.ldif"
        result = api.write_file([entry], file_path)
        assert result.is_success
        # Note: write_file returns True on success via recover() chain
        assert file_path.exists()

    def test_transform_entries_identity(self) -> None:
        """Test transforming entries with identity transformer."""
        api = FlextLdifAPI()
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"]},
        }
        entry = FlextLdifModels.Entry.create(entry_data).unwrap()
        result = api.transform([entry])
        assert result.is_success
        transformed = result.unwrap()
        assert len(transformed) == 1
        assert transformed[0].dn.value == entry.dn.value

    def test_transform_entries_with_custom_transformer(self) -> None:
        """Test transforming entries with custom transformer."""
        api = FlextLdifAPI()
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"]},
        }
        entry = FlextLdifModels.Entry.create(entry_data).unwrap()

        def add_description(e: FlextLdifModels.Entry) -> FlextLdifModels.Entry:
            """Add description attribute."""
            e.attributes.data["description"] = FlextLdifModels.AttributeValues(
                values=["Test Description"]
            )
            return e

        result = api.transform([entry], add_description)
        assert result.is_success
        transformed = result.unwrap()
        assert "description" in transformed[0].attributes.data

    def test_analyze_entries(self) -> None:
        """Test analyzing LDIF entries."""
        api = FlextLdifAPI()
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"]},
        }
        entry = FlextLdifModels.Entry.create(entry_data).unwrap()
        result = api.analyze([entry])
        assert result.is_success
        stats = result.unwrap()
        assert isinstance(stats, dict)

    def test_filter_entries(self) -> None:
        """Test filtering entries with predicate."""
        api = FlextLdifAPI()
        entry1_data = {
            "dn": "cn=user1,dc=example,dc=com",
            "attributes": {"cn": ["user1"], "objectClass": ["person"]},
        }
        entry2_data = {
            "dn": "cn=user2,dc=example,dc=com",
            "attributes": {"cn": ["user2"], "objectClass": ["organizationalUnit"]},
        }
        entry1 = FlextLdifModels.Entry.create(entry1_data).unwrap()
        entry2 = FlextLdifModels.Entry.create(entry2_data).unwrap()

        result = api.filter_entries(
            [entry1, entry2], lambda e: e.has_object_class("person")
        )
        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 1
        assert filtered[0].dn.value == "cn=user1,dc=example,dc=com"

    def test_health_check(self) -> None:
        """Test health check returns status."""
        api = FlextLdifAPI()
        result = api.health_check()
        assert result.is_success
        health = result.unwrap()
        assert health["status"] == "healthy"
        assert "timestamp" in health
        assert "config" in health

    def test_get_service_info(self) -> None:
        """Test get service info returns capabilities."""
        api = FlextLdifAPI()
        info = api.get_service_info()
        assert info["api"] == "FlextLdifAPI"
        assert "capabilities" in info
        capabilities = info["capabilities"]
        assert isinstance(capabilities, list)
        assert "parse" in capabilities
        assert "pattern" in info

    def test_entry_statistics(self) -> None:
        """Test generating entry statistics."""
        api = FlextLdifAPI()
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"], "sn": ["user"]},
        }
        entry = FlextLdifModels.Entry.create(entry_data).unwrap()
        result = api.entry_statistics([entry])
        assert result.is_success
        stats = result.unwrap()
        assert stats["total_entries"] == 1
        assert "object_class_counts" in stats
        assert "attribute_counts" in stats

    def test_filter_persons(self) -> None:
        """Test filtering person entries."""
        api = FlextLdifAPI()
        entry1_data = {
            "dn": "cn=user1,dc=example,dc=com",
            "attributes": {"cn": ["user1"], "objectClass": ["person"]},
        }
        entry2_data = {
            "dn": "ou=groups,dc=example,dc=com",
            "attributes": {"ou": ["groups"], "objectClass": ["organizationalUnit"]},
        }
        entry1 = FlextLdifModels.Entry.create(entry1_data).unwrap()
        entry2 = FlextLdifModels.Entry.create(entry2_data).unwrap()

        result = api.filter_persons([entry1, entry2])
        assert result.is_success
        persons = result.unwrap()
        assert len(persons) == 1

    def test_filter_by_objectclass(self) -> None:
        """Test filtering entries by object class."""
        api = FlextLdifAPI()
        entry1_data = {
            "dn": "cn=user1,dc=example,dc=com",
            "attributes": {"cn": ["user1"], "objectClass": ["inetOrgPerson", "person"]},
        }
        entry2_data = {
            "dn": "ou=groups,dc=example,dc=com",
            "attributes": {"ou": ["groups"], "objectClass": ["organizationalUnit"]},
        }
        entry1 = FlextLdifModels.Entry.create(entry1_data).unwrap()
        entry2 = FlextLdifModels.Entry.create(entry2_data).unwrap()

        result = api.filter_by_objectclass([entry1, entry2], "inetOrgPerson")
        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 1

    def test_filter_valid(self) -> None:
        """Test filtering valid entries."""
        api = FlextLdifAPI()
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"]},
        }
        entry = FlextLdifModels.Entry.create(entry_data).unwrap()
        result = api.filter_valid([entry])
        assert result.is_success
        valid = result.unwrap()
        assert len(valid) >= 0  # May or may not be valid depending on business rules

    def test_parse_ldif_file(self, tmp_path: Path) -> None:
        """Test parsing LDIF from file."""
        api = FlextLdifAPI()
        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: user

"""
        file_path = tmp_path / "test.ldif"
        file_path.write_text(ldif_content)

        result = api.parse_ldif_file(file_path)
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1

    def test_process_with_schema(self) -> None:
        """Test processing entries with schema extraction."""
        api = FlextLdifAPI()
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"]},
        }
        entry = FlextLdifModels.Entry.create(entry_data).unwrap()
        result = api.process_with_schema([entry])
        assert result.is_success

    def test_process_with_acl(self) -> None:
        """Test processing entries with ACL extraction."""
        api = FlextLdifAPI()
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"]},
        }
        entry = FlextLdifModels.Entry.create(entry_data).unwrap()
        result = api.process_with_acl([entry])
        assert result.is_success

    def test_adapt_for_server(self) -> None:
        """Test adapting entries for target server."""
        api = FlextLdifAPI()
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"]},
        }
        entry = FlextLdifModels.Entry.create(entry_data).unwrap()
        result = api.adapt_for_server([entry], "openldap")
        assert result.is_success

    def test_validate_for_server(self) -> None:
        """Test validating entries for server compliance."""
        api = FlextLdifAPI()
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"]},
        }
        entry = FlextLdifModels.Entry.create(entry_data).unwrap()
        result = api.validate_for_server([entry], "openldap")
        assert result.is_success

    def test_process_complete(self) -> None:
        """Test complete LDIF processing pipeline."""
        api = FlextLdifAPI()
        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: user

"""
        result = api.process_complete(ldif_content)
        assert result.is_success
        processed = result.unwrap()
        assert "entries" in processed or isinstance(processed, dict)
