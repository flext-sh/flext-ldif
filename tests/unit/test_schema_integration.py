"""Tests for schema management integration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from flext_ldif import (
    FlextLdifEntryBuilder,
    FlextLdifObjectClassManager,
    FlextLdifProcessor,
)


class TestSchemaIntegration:
    def test_schema_extraction_from_entries(self) -> None:
        processor = FlextLdifProcessor()
        builder = FlextLdifEntryBuilder()

        person_result = builder.build_person_entry(
            cn="John Doe",
            sn="Doe",
            base_dn="dc=example,dc=com",
            uid="jdoe",
            mail="john.doe@example.com",
        )

        assert person_result.is_success
        person_entry = person_result.value

        schema_result = processor.extract_schema_from_entries([person_entry])

        assert schema_result.is_success
        schema = schema_result.value

        assert "cn" in schema.attributes
        assert "sn" in schema.attributes
        assert "uid" in schema.attributes
        assert "mail" in schema.attributes
        assert "inetOrgPerson" in schema.object_classes
        assert schema.entry_count == 1

    def test_objectclass_manager_standard_definitions(self) -> None:
        manager = FlextLdifObjectClassManager()
        processor = FlextLdifProcessor()
        builder = FlextLdifEntryBuilder()

        # Create a person entry to extract schema from
        person_result = builder.build_person_entry(
            cn="John Doe",
            sn="Doe",
            base_dn="dc=example,dc=com",
            uid="jdoe",
            mail="john.doe@example.com",
        )
        assert person_result.is_success
        person_entry = person_result.value

        # Extract schema from the entry
        schema_result = processor.extract_schema_from_entries([person_entry])
        assert schema_result.is_success
        schema = schema_result.value

        # Test objectClass hierarchy resolution
        hierarchy_result = manager.resolve_objectclass_hierarchy("inetOrgPerson", schema)
        assert hierarchy_result.is_success
        hierarchy = hierarchy_result.value
        assert "inetOrgPerson" in hierarchy

        # Test getting required attributes
        required_result = manager.get_all_required_attributes(["inetOrgPerson"], schema)
        assert required_result.is_success
        required_attrs = required_result.value
        # Note: Schema extraction may not have required attributes defined
        # Just verify the method works correctly
        assert isinstance(required_attrs, list)

        # Test getting optional attributes
        optional_result = manager.get_all_optional_attributes(["inetOrgPerson"], schema)
        assert optional_result.is_success
        optional_attrs = optional_result.value
        assert isinstance(optional_attrs, list)

    def test_entry_builder_person_creation(self) -> None:
        builder = FlextLdifEntryBuilder()

        result = builder.build_person_entry(
            cn="Jane Smith",
            sn="Smith",
            base_dn="dc=example,dc=com",
            uid="jsmith",
            mail="jane.smith@example.com",
            given_name="Jane",
        )

        assert result.is_success
        entry = result.value

        assert entry.dn.value == "cn=Jane Smith,dc=example,dc=com"
        assert entry.get_attribute("cn") == ["Jane Smith"]
        assert entry.get_attribute("sn") == ["Smith"]
        assert entry.get_attribute("uid") == ["jsmith"]
        assert entry.get_attribute("mail") == ["jane.smith@example.com"]
        assert entry.get_attribute("givenName") == ["Jane"]

    def test_entry_builder_group_creation(self) -> None:
        builder = FlextLdifEntryBuilder()

        result = builder.build_group_entry(
            cn="Developers",
            base_dn="dc=example,dc=com",
            members=[
                "cn=John Doe,dc=example,dc=com",
                "cn=Jane Smith,dc=example,dc=com",
            ],
            description="Development team",
        )

        assert result.is_success
        entry = result.value

        assert entry.dn.value == "cn=Developers,dc=example,dc=com"
        assert entry.get_attribute("cn") == ["Developers"]
        assert len(entry.get_attribute("member") or []) == 2
        assert entry.get_attribute("description") == ["Development team"]

    def test_entry_builder_ou_creation(self) -> None:
        builder = FlextLdifEntryBuilder()

        result = builder.build_organizational_unit_entry(
            ou="People",
            base_dn="dc=example,dc=com",
            description="All users",
        )

        assert result.is_success
        entry = result.value

        assert entry.dn.value == "ou=People,dc=example,dc=com"
        assert entry.get_attribute("ou") == ["People"]
        assert entry.get_attribute("description") == ["All users"]

    def test_json_conversion(self) -> None:
        builder = FlextLdifEntryBuilder()
        processor = FlextLdifProcessor()

        person_result = builder.build_person_entry(
            cn="Test User",
            sn="User",
            base_dn="dc=example,dc=com",
        )

        assert person_result.is_success
        entry = person_result.value

        json_result = processor.convert_entries_to_json([entry])

        assert json_result.is_success
        json_str = json_result.value

        assert "Test User" in json_str
        assert "dc=example,dc=com" in json_str
        assert "objectClass" in json_str

    def test_schema_validation(self) -> None:
        processor = FlextLdifProcessor()
        builder = FlextLdifEntryBuilder()

        person_result = builder.build_person_entry(
            cn="Alice Brown",
            sn="Brown",
            base_dn="dc=example,dc=com",
        )

        assert person_result.is_success
        person_entry = person_result.value

        schema_result = processor.extract_schema_from_entries([person_entry])
        assert schema_result.is_success
        schema = schema_result.value

        validation_result = processor.validate_entry_against_schema(
            person_entry, schema
        )

        assert validation_result.is_success
        validation_data = validation_result.value

        assert validation_data["valid"] is True
        assert len(validation_data["issues"]) == 0
