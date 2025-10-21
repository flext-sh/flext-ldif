"""Test suite for FlextLdifModels.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import cast

import pytest
from flext_core import FlextModels, FlextResult
from pydantic import ValidationError

from flext_ldif.models import FlextLdifModels


class TestFlextLdifModels:
    """Test suite for FlextLdifModels."""

    def test_dn_creation(self) -> None:
        """Test DN model creation."""
        dn = FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com")
        assert dn.value == "cn=test,dc=example,dc=com"

    def test_dn_validation(self) -> None:
        """Test DN validation."""
        # Valid DN
        dn = FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com")
        assert dn.value == "cn=test,dc=example,dc=com"

        # Empty DN should fail
        with pytest.raises(ValidationError):
            FlextLdifModels.DistinguishedName(value="")

        # DN too long should fail
        long_dn = "cn=" + "x" * 2048 + ",dc=example,dc=com"
        with pytest.raises(ValidationError):
            FlextLdifModels.DistinguishedName(value=long_dn)

    def test_dn_case_preservation(self) -> None:
        """Test DN case preservation (normalization is in infrastructure layer).

        Note: Domain models validate format only, infrastructure services normalize.
        """
        # Test that DN validation accepts and preserves various case formats
        dn = FlextLdifModels.DistinguishedName(value="CN=Test,DC=Example,DC=Com")
        # Domain model preserves DN as-is (no normalization at domain level)
        assert dn.value == "CN=Test,DC=Example,DC=Com"

    def test_attribute_values_creation(self) -> None:
        """Test AttributeValues model creation."""
        values = FlextLdifModels.AttributeValues(values=["value1", "value2"])
        assert values.values == ["value1", "value2"]

    def test_attribute_values_validation(self) -> None:
        """Test AttributeValues validation."""
        # Valid values
        values = FlextLdifModels.AttributeValues(values=["value1", "value2"])
        assert len(values.values) == 2

        # Empty values should be allowed
        empty_values = FlextLdifModels.AttributeValues(values=[])
        assert empty_values.values == []

    def test_attribute_values_single_value(self) -> None:
        """Test AttributeValues single value property."""
        values = FlextLdifModels.AttributeValues(values=["single_value"])
        assert values.single_value == "single_value"

        empty_values = FlextLdifModels.AttributeValues(values=[])
        assert empty_values.single_value is None

    def test_attributes_creation(self) -> None:
        """Test Attributes model creation."""
        attrs = FlextLdifModels.LdifAttributes(
            attributes={
                "cn": FlextLdifModels.AttributeValues(values=["test"]),
                "sn": FlextLdifModels.AttributeValues(values=["user"]),
            }
        )
        assert len(attrs.attributes) == 2
        assert "cn" in attrs.attributes
        assert "sn" in attrs.attributes

    def test_attributes_get_attribute(self) -> None:
        """Test getting attributes by name."""
        attrs = FlextLdifModels.LdifAttributes(
            attributes={
                "cn": FlextLdifModels.AttributeValues(values=["test"]),
            }
        )

        cn_attr = attrs.get_attribute("cn")
        assert cn_attr is not None
        assert cn_attr.values == ["test"]

        # Non-existent attribute
        missing_attr = attrs.get_attribute("missing")
        assert missing_attr is None

    def test_attributes_add_attribute(self) -> None:
        """Test adding attributes."""
        attrs = FlextLdifModels.LdifAttributes(attributes={})

        attrs.add_attribute("cn", "test")
        cn_attr = attrs.get_attribute("cn")
        assert cn_attr is not None
        assert cn_attr.values == ["test"]

    def test_attributes_add_attribute_multiple_values(self) -> None:
        """Test adding attributes with multiple values."""
        attrs = FlextLdifModels.LdifAttributes(attributes={})

        attrs.add_attribute("cn", ["test1", "test2"])
        cn_attr = attrs.get_attribute("cn")
        assert cn_attr is not None
        assert cn_attr.values == ["test1", "test2"]

    def test_attributes_remove_attribute(self) -> None:
        """Test removing attributes."""
        attrs = FlextLdifModels.LdifAttributes(
            attributes={
                "cn": FlextLdifModels.AttributeValues(values=["test"]),
            }
        )

        attrs.remove_attribute("cn")
        cn_attr = attrs.get_attribute("cn")
        assert cn_attr is None

    def test_attributes_remove_nonexistent_attribute(self) -> None:
        """Test removing non-existent attribute."""
        attrs = FlextLdifModels.LdifAttributes(attributes={})

        # Should not raise error
        attrs.remove_attribute("nonexistent")

    def test_entry_creation(self) -> None:
        """Test Entry model creation."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                    "objectclass": FlextLdifModels.AttributeValues(values=["person"]),
                }
            ),
        )
        assert entry.dn.value == "cn=test,dc=example,dc=com"
        assert "cn" in entry.attributes.attributes

    def test_entry_validation(self) -> None:
        """Test Entry validation."""
        # Valid entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectclass": FlextLdifModels.AttributeValues(values=["person"]),
                }
            ),
        )
        assert entry.dn.value == "cn=test,dc=example,dc=com"

    def test_search_config_creation(self) -> None:
        """Test SearchConfig model creation."""
        config = FlextLdifModels.SearchConfig(
            base_dn="dc=example,dc=com",
            search_filter="(objectClass=person)",
            attributes=["cn", "sn"],
        )
        assert config.base_dn == "dc=example,dc=com"
        assert config.search_filter == "(objectClass=person)"
        assert config.attributes == ["cn", "sn"]

    def test_search_config_validation(self) -> None:
        """Test SearchConfig validation."""
        # Valid config
        config = FlextLdifModels.SearchConfig(
            base_dn="dc=example,dc=com",
            search_filter="(objectClass=person)",
            attributes=["cn", "sn"],
        )
        assert config.base_dn == "dc=example,dc=com"

        # Empty base_dn should fail
        with pytest.raises(ValidationError):
            FlextLdifModels.SearchConfig(
                base_dn="",
                search_filter="(objectClass=person)",
                attributes=["cn"],
            )

    def test_search_config_default_filter(self) -> None:
        """Test SearchConfig with default filter."""
        config = FlextLdifModels.SearchConfig(
            base_dn="dc=example,dc=com",
            attributes=["cn", "sn"],
        )
        assert config.search_filter == "(objectClass=*)"

    def test_search_config_empty_attributes(self) -> None:
        """Test SearchConfig with empty attributes."""
        config = FlextLdifModels.SearchConfig(
            base_dn="dc=example,dc=com",
            search_filter="(objectClass=person)",
            attributes=[],
        )
        assert config.attributes == []

    def test_model_serialization(self) -> None:
        """Test model serialization."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                    "objectclass": FlextLdifModels.AttributeValues(values=["person"]),
                }
            ),
        )

        # Test model_dump
        data = entry.model_dump()
        assert isinstance(data, dict)
        assert data["dn"]["value"] == "cn=test,dc=example,dc=com"

    def test_model_deserialization(self) -> None:
        """Test model deserialization using Entry.create()."""
        # Use Entry.create() for simplified attribute format
        result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "objectclass": ["person"],
            },
        )

        assert result.is_success
        entry = result.unwrap()
        assert entry.dn.value == "cn=test,dc=example,dc=com"
        assert entry.attributes.get_attribute("cn") is not None

    def test_model_validation_errors(self) -> None:
        """Test model validation errors."""
        # Invalid DN
        with pytest.raises(ValidationError):
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value=""),  # Empty DN
                attributes=FlextLdifModels.LdifAttributes(attributes={}),
            )

    def test_model_inheritance(self) -> None:
        """Test that models properly inherit from FlextModels."""
        # Test that all models are properly structured
        assert hasattr(FlextLdifModels, "DistinguishedName")
        assert hasattr(FlextLdifModels, "AttributeValues")
        assert hasattr(FlextLdifModels, "LdifAttributes")
        assert hasattr(FlextLdifModels, "Entry")
        assert hasattr(FlextLdifModels, "SearchConfig")

    def test_edge_cases(self) -> None:
        """Test edge cases in models."""
        # Test DN with special characters (properly escaped per RFC 4514)
        dn = FlextLdifModels.DistinguishedName(value="cn=test\\+user,dc=example,dc=com")
        assert dn.value == "cn=test\\+user,dc=example,dc=com"

        # Test attributes with special characters
        attrs = FlextLdifModels.LdifAttributes(
            attributes={
                "cn;lang-en": FlextLdifModels.AttributeValues(values=["test"]),
            }
        )
        assert "cn;lang-en" in attrs.attributes

        # Test empty attribute values
        attrs = FlextLdifModels.LdifAttributes(
            attributes={
                "cn": FlextLdifModels.AttributeValues(values=[""]),
            }
        )
        cn_attr = attrs.get_attribute("cn")
        assert cn_attr is not None
        assert cn_attr.values == [""]

    def test_entry_parsed_event_creation(self) -> None:
        """Test EntryParsedEvent creation."""
        event = FlextLdifModels.EntryParsedEvent(
            event_type="entry.parsed",
            aggregate_id="ldif-parser",
            entry_count=5,
            source_type="file",
            format_detected="rfc",
            timestamp="2025-01-01T00:00:00Z",
        )
        assert event.entry_count == 5
        assert event.source_type == "file"
        assert event.format_detected == "rfc"
        assert event.event_type == "entry.parsed"
        assert event.aggregate_id == "ldif-parser"

    def test_entries_validated_event_creation(self) -> None:
        """Test EntriesValidatedEvent creation."""
        event = FlextLdifModels.EntriesValidatedEvent(
            event_type="entries.validated",
            aggregate_id="ldif-validator",
            entry_count=10,
            is_valid=True,
            error_count=0,
            strict_mode=True,
            timestamp="2025-01-01T00:00:00Z",
        )
        assert event.entry_count == 10
        assert event.is_valid is True
        assert event.error_count == 0
        assert event.strict_mode is True
        assert event.event_type == "entries.validated"
        assert event.aggregate_id == "ldif-validator"

    def test_analytics_generated_event_creation(self) -> None:
        """Test AnalyticsGeneratedEvent creation."""
        event = FlextLdifModels.AnalyticsGeneratedEvent(
            event_type="analytics.generated",
            aggregate_id="ldif-analytics",
            entry_count=20,
            statistics={"total_attrs": 100, "unique_dns": 15},
            timestamp="2025-01-01T00:00:00Z",
        )
        assert event.entry_count == 20
        assert event.statistics == {"total_attrs": 100, "unique_dns": 15}
        assert event.event_type == "analytics.generated"
        assert event.aggregate_id == "ldif-analytics"

    def test_entries_written_event_creation(self) -> None:
        """Test EntriesWrittenEvent creation."""
        event = FlextLdifModels.EntriesWrittenEvent(
            event_type="entries.written",
            aggregate_id="ldif-writer",
            entry_count=8,
            output_path="/tmp/output.ldif",
            format_used="rfc",
            timestamp="2025-01-01T00:00:00Z",
        )
        assert event.entry_count == 8
        assert event.output_path == "/tmp/output.ldif"
        assert event.format_used == "rfc"
        assert event.event_type == "entries.written"
        assert event.aggregate_id == "ldif-writer"

    def test_migration_completed_event_creation(self) -> None:
        """Test MigrationCompletedEvent creation."""
        event = FlextLdifModels.MigrationCompletedEvent(
            event_type="migration.completed",
            aggregate_id="ldif-migration",
            source_entries=15,
            target_entries=15,
            migration_type="format_conversion",
            timestamp="2025-01-01T00:00:00Z",
        )
        assert event.source_entries == 15
        assert event.target_entries == 15
        assert event.migration_type == "format_conversion"
        assert event.event_type == "migration.completed"
        assert event.aggregate_id == "ldif-migration"

    def test_quirk_registered_event_creation(self) -> None:
        """Test QuirkRegisteredEvent creation."""
        event = FlextLdifModels.QuirkRegisteredEvent(
            event_type="quirk.registered",
            aggregate_id="ldif-quirks",
            server_type="openldap",
            quirk_name="special_handling",
            timestamp="2025-01-01T00:00:00Z",
        )
        assert event.server_type == "openldap"
        assert event.quirk_name == "special_handling"
        assert event.event_type == "quirk.registered"
        assert event.aggregate_id == "ldif-quirks"

    def test_schema_object_class_creation(self) -> None:
        """Test SchemaObjectClass model creation."""
        obj_class = FlextLdifModels.SchemaObjectClass(
            name="person",
            oid="2.5.6.6",
            description="Person object class",
            required_attributes=["cn", "sn"],
            optional_attributes=["telephoneNumber", "seeAlso"],
            structural=True,
        )
        assert obj_class.name == "person"
        assert obj_class.oid == "2.5.6.6"
        assert obj_class.description == "Person object class"
        assert obj_class.required_attributes == ["cn", "sn"]
        assert obj_class.optional_attributes == ["telephoneNumber", "seeAlso"]
        assert obj_class.structural is True

    def test_schema_object_class_direct_instantiation(self) -> None:
        """Test SchemaObjectClass direct instantiation."""
        # Direct instantiation pattern - Pydantic 2 validates natively
        obj_class = FlextLdifModels.SchemaObjectClass(
            name="organizationalUnit",
            oid="2.5.6.5",
            description="Organizational unit",
            required_attributes=["ou"],
        )
        assert isinstance(obj_class, FlextLdifModels.SchemaObjectClass)
        assert obj_class.name == "organizationalUnit"
        assert obj_class.oid == "2.5.6.5"
        assert obj_class.required_attributes == ["ou"]
        assert obj_class.optional_attributes == []
        assert obj_class.description == "Organizational unit"

    def test_schema_discovery_result_creation(self) -> None:
        """Test SchemaDiscoveryResult model creation."""
        result = FlextLdifModels.SchemaDiscoveryResult(
            objectclasses={
                "person": {
                    "oid": "2.5.6.6",
                    "description": "Person class",
                }
            },
            attributes={
                "cn": {
                    "oid": "2.5.4.3",
                    "description": "Common name",
                    "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
                }
            },
            total_attributes=1,
            total_objectclasses=1,
        )
        assert len(result.objectclasses) == 1
        assert len(result.attributes) == 1
        assert result.total_attributes == 1
        assert result.total_objectclasses == 1

    def test_schema_attribute_creation(self) -> None:
        """Test SchemaAttribute model creation."""
        attr = FlextLdifModels.SchemaAttribute(
            name="cn",
            oid="2.5.4.3",
            description="Common name attribute",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )
        assert attr.name == "cn"
        assert attr.oid == "2.5.4.3"
        assert attr.description == "Common name attribute"
        assert attr.syntax == "1.3.6.1.4.1.1466.115.121.1.15"


class TestFlextLdifModelsEntry:
    """Test suite for Entry model."""

    def test_entry_creation(self) -> None:
        """Test creating an Entry instance."""
        result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "objectclass": ["inetOrgPerson", "person"],
                "cn": ["Test User"],
                "sn": ["User"],
            },
        )

        assert result.is_success
        entry = result.unwrap()
        assert isinstance(entry, FlextLdifModels.Entry)
        assert entry.dn.value == "cn=test,dc=example,dc=com"
        assert isinstance(entry.attributes, FlextLdifModels.LdifAttributes)

    def test_entry_with_binary_data(self) -> None:
        """Test Entry with binary attribute data."""
        import base64

        binary_data = b"binary content"
        # Base64 encode the binary data for LDIF compatibility
        encoded_data = base64.b64encode(binary_data).decode("ascii")

        result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "objectclass": ["inetOrgPerson"],
                "cn": ["Test User"],
                "userCertificate;binary": [encoded_data],
            },
        )

        assert result.is_success
        entry = result.unwrap()
        assert isinstance(entry, FlextLdifModels.Entry)
        assert entry.dn.value == "cn=test,dc=example,dc=com"

    def test_entry_validation(self) -> None:
        """Test Entry validation."""
        # Valid entry
        result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"objectclass": ["person"], "cn": ["test"]},
        )
        assert result.is_success

        # Invalid entry - missing DN (empty string)
        result = FlextLdifModels.Entry.create(
            dn="",  # Empty DN should fail
            attributes={"objectclass": ["person"], "cn": ["test"]},
        )
        assert result.is_failure


class TestFlextLdifModelsDistinguishedName:
    """Test suite for DistinguishedName model."""

    def test_dn_creation(self) -> None:
        """Test creating a DistinguishedName instance."""
        dn_string = "cn=test,ou=users,dc=example,dc=com"

        # Direct instantiation pattern - Pydantic 2 validates via @field_validator
        dn = FlextLdifModels.DistinguishedName(value=dn_string)

        assert isinstance(dn, FlextLdifModels.DistinguishedName)
        assert dn.value == dn_string

    def test_dn_normalization(self) -> None:
        """Test DN validation (normalization is done by infrastructure services).

        Note: Per clean architecture, domain models only validate format.
        Full RFC 4514 normalization (lowercasing, escaping) is done by
        infrastructure layer (services/dn_service.py uses ldap3).
        """
        dn_string = "CN=test,OU=users,DC=example,DC=com"

        # Direct instantiation pattern - Pydantic 2 validates via @field_validator
        dn = FlextLdifModels.DistinguishedName(value=dn_string)

        assert isinstance(dn, FlextLdifModels.DistinguishedName)
        # Domain model preserves DN as-is (validation only, no normalization)
        assert dn.value == dn_string

    def test_dn_components_extraction(self) -> None:
        """Test extracting DN components."""
        dn_string = "cn=test,ou=users,dc=example,dc=com"

        # Direct instantiation pattern - Pydantic 2 validates via @field_validator
        dn = FlextLdifModels.DistinguishedName(value=dn_string)

        # Test components field access
        assert hasattr(dn, "components")
        assert isinstance(dn.components, list)
        assert len(dn.components) == 4

    def test_invalid_dn(self) -> None:
        """Test invalid DN handling."""
        invalid_dn = "invalid-dn-format"

        # Direct instantiation pattern - Pydantic 2 raises ValidationError on invalid DN
        with pytest.raises(ValidationError) as exc_info:
            FlextLdifModels.DistinguishedName(value=invalid_dn)

        # Verify the error is related to DN validation
        assert "DN format" in str(exc_info.value) or "value" in str(exc_info.value)


class TestFlextLdifModelsLdifAttributes:
    """Test suite for LdifAttributes model."""

    def test_attributes_creation(self) -> None:
        """Test creating an LdifAttributes instance."""
        attrs_data = {
            "cn": FlextLdifModels.AttributeValues(values=["Test User"]),
            "sn": FlextLdifModels.AttributeValues(values=["User"]),
            "objectclass": FlextLdifModels.AttributeValues(
                values=["inetOrgPerson", "person"]
            ),
        }

        result = FlextLdifModels.LdifAttributes.create(
            cast("dict[str, object]", attrs_data)
        )

        assert result.is_success
        attrs = result.unwrap()
        assert isinstance(attrs, FlextLdifModels.LdifAttributes)
        assert "cn" in attrs.attributes
        assert attrs.attributes["cn"].values == ["Test User"]

    def test_empty_attributes(self) -> None:
        """Test creating empty attributes."""
        result = FlextLdifModels.LdifAttributes.create({})

        assert result.is_success
        attrs = result.unwrap()
        assert isinstance(attrs, FlextLdifModels.LdifAttributes)
        assert attrs.attributes == {}

    def test_attributes_with_options(self) -> None:
        """Test attributes with LDAP options."""
        attrs_data = {
            "cn": FlextLdifModels.AttributeValues(values=["Test User"]),
            "userCertificate;binary": FlextLdifModels.AttributeValues(
                values=["cert-data"]
            ),
        }

        result = FlextLdifModels.LdifAttributes.create(
            cast("dict[str, object]", attrs_data)
        )

        assert result.is_success
        attrs = result.unwrap()
        assert isinstance(attrs, FlextLdifModels.LdifAttributes)
        assert "userCertificate;binary" in attrs.attributes


class TestFlextLdifModelsSchemaObjectClass:
    """Test suite for SchemaObjectClass model."""

    def test_objectclass_creation(self) -> None:
        """Test creating a SchemaObjectClass instance."""
        # Direct instantiation pattern - Pydantic 2 validates natively
        oc = FlextLdifModels.SchemaObjectClass(
            name="inetOrgPerson",
            oid="2.16.840.1.113730.3.2.2",
            description="Internet Organizational Person",
            structural=True,
            required_attributes=["cn", "sn", "objectclass"],
            optional_attributes=["description", "telephoneNumber", "mail"],
        )

        assert isinstance(oc, FlextLdifModels.SchemaObjectClass)
        assert oc.name == "inetOrgPerson"
        assert oc.oid == "2.16.840.1.113730.3.2.2"
        assert oc.required_attributes == ["cn", "sn", "objectclass"]
        assert oc.optional_attributes == ["description", "telephoneNumber", "mail"]

    def test_objectclass_validation(self) -> None:
        """Test object class validation."""
        # Valid object class - Direct instantiation pattern
        oc = FlextLdifModels.SchemaObjectClass(
            name="person",
            oid="2.5.6.6",
            description="Person object class",
            structural=True,
        )
        assert isinstance(oc, FlextLdifModels.SchemaObjectClass)

    def test_computed_fields(self) -> None:
        """Test computed fields on object class."""
        # Direct instantiation pattern - Pydantic 2 validates natively
        oc = FlextLdifModels.SchemaObjectClass(
            name="inetOrgPerson",
            oid="2.16.840.1.113730.3.2.2",
            description="Internet Organizational Person",
            required_attributes=["cn", "sn"],
            optional_attributes=["mail", "telephoneNumber"],
        )
        assert isinstance(oc, FlextLdifModels.SchemaObjectClass)

        # Test field access
        assert oc.required_attributes == ["cn", "sn"]
        assert oc.optional_attributes == ["mail", "telephoneNumber"]


class TestFlextLdifModelsAclTarget:
    """Test suite for ACL Target model."""

    def test_acl_target_creation(self) -> None:
        """Test creating an AclTarget instance."""
        # Direct instantiation pattern - Pydantic 2 validates natively
        target = FlextLdifModels.AclTarget(
            target_dn="dc=example,dc=com",
            attributes=["cn", "sn"],
        )

        assert isinstance(target, FlextLdifModels.AclTarget)
        assert target.target_dn == "dc=example,dc=com"
        assert target.attributes == ["cn", "sn"]


class TestFlextLdifModelsAclSubject:
    """Test suite for ACL Subject model."""

    def test_acl_subject_creation(self) -> None:
        """Test creating an AclSubject instance."""
        # Direct instantiation pattern - Pydantic 2 validates natively
        subject = FlextLdifModels.AclSubject(
            subject_type="user",
            subject_value="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        )

        assert isinstance(subject, FlextLdifModels.AclSubject)
        assert subject.subject_type == "user"


class TestFlextLdifModelsAclPermissions:
    """Test suite for ACL Permissions model."""

    def test_acl_permissions_creation(self) -> None:
        """Test creating an AclPermissions instance."""
        # Direct instantiation pattern - Pydantic 2 validates natively
        # AclPermissions uses individual boolean fields, not a permissions list
        perms = FlextLdifModels.AclPermissions(
            read=True,
            write=True,
        )

        assert isinstance(perms, FlextLdifModels.AclPermissions)
        # Test individual boolean fields
        assert perms.read is True
        assert perms.write is True
        assert perms.add is False
        assert perms.delete is False
        # Test computed permissions field (derived from boolean fields)
        permissions_list = perms.permissions
        assert isinstance(permissions_list, list)
        assert len(permissions_list) == 2
        assert "read" in permissions_list
        assert "write" in permissions_list


class TestFlextLdifModelsAcl:
    """Test suite for Acl model."""

    def test_unified_acl_creation(self) -> None:
        """Test creating a Acl instance."""
        # Create components using direct instantiation pattern
        target = FlextLdifModels.AclTarget(
            target_dn="dc=example,dc=com",
            attributes=["cn"],
        )

        subject = FlextLdifModels.AclSubject(
            subject_type="user",
            subject_value="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        )

        perms = FlextLdifModels.AclPermissions(
            read=True,
            write=True,
        )

        # Create unified ACL using direct instantiation of OracleOudAcl
        # (aggressive Pydantic 2 direct usage pattern - no factory class)
        try:
            oud_acl = FlextLdifModels.OracleOudAcl(
                name="test_acl",
                target=target,
                subject=subject,
                permissions=perms,
                server_type="oracle_oud",
            )
            result = FlextResult[FlextLdifModels.AclBase].ok(oud_acl)
        except Exception as e:  # pragma: no cover
            result = FlextResult[FlextLdifModels.AclBase].fail(str(e))

        assert result.is_success
        acl: FlextLdifModels.AclBase = result.unwrap()
        # Discriminated union returns the specific subtype (OracleOudAcl in this case)
        assert isinstance(acl, FlextLdifModels.AclBase)
        assert isinstance(acl, FlextLdifModels.OracleOudAcl)
        assert acl.name == "test_acl"
        assert acl.server_type == "oracle_oud"


class TestFlextLdifModelsNamespace:
    """Test suite for the FlextLdifModels namespace class."""

    def test_models_namespace_access(self) -> None:
        """Test accessing models through namespace."""
        # Test that all expected model classes are available
        assert hasattr(FlextLdifModels, "Entry")
        assert hasattr(FlextLdifModels, "DistinguishedName")
        assert hasattr(FlextLdifModels, "AttributeValues")
        assert hasattr(FlextLdifModels, "LdifAttributes")
        assert hasattr(FlextLdifModels, "SchemaObjectClass")
        assert hasattr(FlextLdifModels, "AclTarget")
        assert hasattr(FlextLdifModels, "AclSubject")
        assert hasattr(FlextLdifModels, "AclPermissions")
        # Aggressive Pydantic 2 pattern: removed Acl factory class, using direct subclass instantiation
        # Verify discriminated union subtypes are available instead
        assert hasattr(FlextLdifModels, "OpenLdapAcl")
        assert hasattr(FlextLdifModels, "OracleOudAcl")

    def test_computed_fields(self) -> None:
        """Test namespace structure."""
        # FlextLdifModels is a namespace class, not a model with computed fields
        # Verify the class structure is properly organized

        # Test that it inherits from FlextModels
        assert issubclass(FlextLdifModels, FlextModels)

        # Test that key model classes are accessible
        assert hasattr(FlextLdifModels, "Entry")
        assert hasattr(FlextLdifModels, "DistinguishedName")
        assert hasattr(FlextLdifModels, "LdifAttributes")
        assert hasattr(FlextLdifModels, "AttributeValues")
        assert hasattr(FlextLdifModels, "SchemaObjectClass")
        assert hasattr(FlextLdifModels, "AclTarget")
        assert hasattr(FlextLdifModels, "AclSubject")
        assert hasattr(FlextLdifModels, "AclPermissions")
        # Aggressive Pydantic 2 pattern: discriminated union subtypes for ACL
        assert hasattr(FlextLdifModels, "AclBase")
        assert hasattr(FlextLdifModels, "OpenLdapAcl")
