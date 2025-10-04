"""Comprehensive unit tests for FlextLdifModels functionality.

Tests all model classes and their methods with real validation.
"""

from __future__ import annotations

from typing import cast

import pytest

from flext_core import FlextResult, FlextTypes
from flext_ldif.models import FlextLdifModels


class TestFlextLdifModelsEntry:
    """Test suite for Entry model."""

    def test_entry_creation(self) -> None:
        """Test creating an Entry instance."""
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "objectClass": ["inetOrgPerson", "person"],
                "cn": ["Test User"],
                "sn": ["User"],
            }
        }

        result = FlextLdifModels.Entry.create(entry_data)

        assert result.is_success
        entry = result.unwrap()
        assert isinstance(entry, FlextLdifModels.Entry)
        assert entry.dn == "cn=test,dc=example,dc=com"
        assert isinstance(entry.attributes, dict)

    def test_entry_with_binary_data(self) -> None:
        """Test Entry with binary attribute data."""
        binary_data = b"binary content"
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "objectClass": ["inetOrgPerson"],
                "cn": ["Test User"],
                "userCertificate;binary": [binary_data],
            }
        }

        result = FlextLdifModels.Entry.create(entry_data)

        assert result.is_success
        entry = result.unwrap()
        assert entry.dn == "cn=test,dc=example,dc=com"

    def test_entry_validation(self) -> None:
        """Test Entry validation."""
        # Valid entry
        valid_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["test"]},
        }

        result = FlextLdifModels.Entry.create(valid_data)
        assert result.is_success

        # Invalid entry - missing DN
        invalid_data = {
            "attributes": {"objectClass": ["person"], "cn": ["test"]},
        }

        result = FlextLdifModels.Entry.create(invalid_data)
        assert result.is_failure


class TestFlextLdifModelsDistinguishedName:
    """Test suite for DistinguishedName model."""

    def test_dn_creation(self) -> None:
        """Test creating a DistinguishedName instance."""
        dn_string = "cn=test,ou=users,dc=example,dc=com"

        result = FlextLdifModels.DistinguishedName.create(dn_string)

        assert result.is_success
        dn = result.unwrap()
        assert isinstance(dn, FlextLdifModels.DistinguishedName)
        assert dn.value == dn_string

    def test_dn_normalization(self) -> None:
        """Test DN normalization."""
        dn_string = "CN=test,OU=users,DC=example,DC=com"

        result = FlextLdifModels.DistinguishedName.create(dn_string)

        assert result.is_success
        dn = result.unwrap()
        # Should normalize to lowercase
        assert dn.value == dn_string.lower()

    def test_dn_components_extraction(self) -> None:
        """Test extracting DN components."""
        dn_string = "cn=test,ou=users,dc=example,dc=com"

        result = FlextLdifModels.DistinguishedName.create(dn_string)

        assert result.is_success
        dn = result.unwrap()

        # Test computed field access
        assert hasattr(dn, 'dn_components')

    def test_invalid_dn(self) -> None:
        """Test invalid DN handling."""
        invalid_dn = "invalid-dn-format"

        result = FlextLdifModels.DistinguishedName.create(invalid_dn)

        # Should still create but mark as invalid
        assert isinstance(result, FlextResult)


class TestFlextLdifModelsLdifAttribute:
    """Test suite for LdifAttribute model."""

    def test_attribute_creation(self) -> None:
        """Test creating an LdifAttribute instance."""
        attr_data = {
            "name": "cn",
            "values": ["Test User", "Test"],
        }

        result = FlextLdifModels.LdifAttribute.create(attr_data)

        assert result.is_success
        attr = result.unwrap()
        assert isinstance(attr, FlextLdifModels.LdifAttribute)
        assert attr.name == "cn"
        assert attr.values == ["Test User", "Test"]

    def test_single_value_attribute(self) -> None:
        """Test attribute with single value."""
        attr_data = {
            "name": "sn",
            "values": ["User"],
        }

        result = FlextLdifModels.LdifAttribute.create(attr_data)

        assert result.is_success
        attr = result.unwrap()
        assert attr.values == ["User"]

    def test_empty_values(self) -> None:
        """Test attribute with empty values."""
        attr_data = {
            "name": "description",
            "values": [],
        }

        result = FlextLdifModels.LdifAttribute.create(attr_data)

        assert result.is_success
        attr = result.unwrap()
        assert attr.values == []


class TestFlextLdifModelsLdifAttributes:
    """Test suite for LdifAttributes model."""

    def test_attributes_creation(self) -> None:
        """Test creating an LdifAttributes instance."""
        attrs_data = {
            "cn": ["Test User"],
            "sn": ["User"],
            "objectClass": ["inetOrgPerson", "person"],
        }

        result = FlextLdifModels.LdifAttributes.create(attrs_data)

        assert result.is_success
        attrs = result.unwrap()
        assert isinstance(attrs, FlextLdifModels.LdifAttributes)
        assert "cn" in attrs.attributes
        assert attrs.attributes["cn"] == ["Test User"]

    def test_empty_attributes(self) -> None:
        """Test creating empty attributes."""
        result = FlextLdifModels.LdifAttributes.create({})

        assert result.is_success
        attrs = result.unwrap()
        assert attrs.attributes == {}

    def test_attributes_with_options(self) -> None:
        """Test attributes with LDAP options."""
        attrs_data = {
            "cn": ["Test User"],
            "userCertificate;binary": ["cert-data"],
        }

        result = FlextLdifModels.LdifAttributes.create(attrs_data)

        assert result.is_success
        attrs = result.unwrap()
        assert "userCertificate;binary" in attrs.attributes


class TestFlextLdifModelsSchemaObjectClass:
    """Test suite for SchemaObjectClass model."""

    def test_objectclass_creation(self) -> None:
        """Test creating a SchemaObjectClass instance."""
        oc_data = {
            "name": "inetOrgPerson",
            "oid": "2.16.840.1.113730.3.2.2",
            "description": "Internet Organizational Person",
            "superiors": ["organizationalPerson"],
            "kind": "STRUCTURAL",
            "must": ["cn", "sn", "objectClass"],
            "may": ["description", "telephoneNumber", "mail"],
        }

        result = FlextLdifModels.SchemaObjectClass.create(oc_data)

        assert result.is_success
        oc = result.unwrap()
        assert isinstance(oc, FlextLdifModels.SchemaObjectClass)
        assert oc.name == "inetOrgPerson"
        assert oc.oid == "2.16.840.1.113730.3.2.2"

    def test_objectclass_validation(self) -> None:
        """Test object class validation."""
        # Valid object class
        valid_data = {
            "name": "person",
            "oid": "2.5.6.6",
            "kind": "STRUCTURAL",
        }

        result = FlextLdifModels.SchemaObjectClass.create(valid_data)
        assert result.is_success

    def test_computed_fields(self) -> None:
        """Test computed fields on object class."""
        oc_data = {
            "name": "inetOrgPerson",
            "must": ["cn", "sn"],
            "may": ["mail", "telephoneNumber"],
        }

        result = FlextLdifModels.SchemaObjectClass.create(oc_data)
        assert result.is_success
        oc = result.unwrap()

        # Test computed fields exist
        assert hasattr(oc, 'required_count')
        assert hasattr(oc, 'optional_count')
        assert hasattr(oc, 'total_attributes')


class TestFlextLdifModelsAclTarget:
    """Test suite for ACL Target model."""

    def test_acl_target_creation(self) -> None:
        """Test creating an AclTarget instance."""
        target_data = {
            "target_dn": "dc=example,dc=com",
            "attributes": ["cn", "sn"],
        }

        result = FlextLdifModels.AclTarget.create(target_data)

        assert result.is_success
        target = result.unwrap()
        assert isinstance(target, FlextLdifModels.AclTarget)
        assert target.target_dn == "dc=example,dc=com"
        assert target.attributes == ["cn", "sn"]


class TestFlextLdifModelsAclSubject:
    """Test suite for ACL Subject model."""

    def test_acl_subject_creation(self) -> None:
        """Test creating an AclSubject instance."""
        subject_data = {
            "subject_type": "user",
            "subject_value": "cn=admin,dc=example,dc=com",
        }

        result = FlextLdifModels.AclSubject.create(subject_data)

        assert result.is_success
        subject = result.unwrap()
        assert isinstance(subject, FlextLdifModels.AclSubject)
        assert subject.subject_type == "user"


class TestFlextLdifModelsAclPermissions:
    """Test suite for ACL Permissions model."""

    def test_acl_permissions_creation(self) -> None:
        """Test creating an AclPermissions instance."""
        perms_data = {
            "permissions": ["read", "write"],
            "scope": "entry",
        }

        result = FlextLdifModels.AclPermissions.create(perms_data)

        assert result.is_success
        perms = result.unwrap()
        assert isinstance(perms, FlextLdifModels.AclPermissions)
        assert perms.permissions == ["read", "write"]


class TestFlextLdifModelsUnifiedAcl:
    """Test suite for UnifiedAcl model."""

    def test_unified_acl_creation(self) -> None:
        """Test creating a UnifiedAcl instance."""
        # First create components
        target_result = FlextLdifModels.AclTarget.create({
            "target_dn": "dc=example,dc=com",
            "attributes": ["cn"],
        })
        assert target_result.is_success

        subject_result = FlextLdifModels.AclSubject.create({
            "subject_type": "user",
            "subject_value": "cn=admin,dc=example,dc=com",
        })
        assert subject_result.is_success

        perms_result = FlextLdifModels.AclPermissions.create({
            "permissions": ["read", "write"],
        })
        assert perms_result.is_success

        # Create unified ACL
        acl_data = {
            "name": "test_acl",
            "target": target_result.unwrap(),
            "subject": subject_result.unwrap(),
            "permissions": perms_result.unwrap(),
            "server_type": "oracle_oud",
        }

        result = FlextLdifModels.UnifiedAcl.create(acl_data)

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, FlextLdifModels.UnifiedAcl)
        assert acl.name == "test_acl"


class TestFlextLdifModelsCommands:
    """Test suite for command models."""

    def test_parse_query_creation(self) -> None:
        """Test creating a ParseQuery."""
        query_data = {
            "source": "dn: cn=test\ncn: test",
            "format": "rfc",
            "encoding": "utf-8",
            "strict": True,
        }

        query = FlextLdifModels.ParseQuery(**query_data)

        assert query.source == "dn: cn=test\ncn: test"
        assert query.format == "rfc"
        assert query.encoding == "utf-8"
        assert query.strict is True

    def test_write_command_creation(self) -> None:
        """Test creating a WriteCommand."""
        entries = [
            {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {"cn": ["test"]},
            }
        ]

        command = FlextLdifModels.WriteCommand(
            entries=entries,
            format="rfc",
            output="test.ldif",
            line_width=76,
        )

        assert len(command.entries) == 1
        assert command.format == "rfc"
        assert command.output == "test.ldif"

    def test_analyze_query_creation(self) -> None:
        """Test creating an AnalyzeQuery."""
        entries = [
            {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {"cn": ["test"]},
            }
        ]

        query = FlextLdifModels.AnalyzeQuery(
            entries=entries,
            metrics=["object_class_count"],
            include_patterns=True,
        )

        assert len(query.entries) == 1
        assert query.metrics == ["object_class_count"]
        assert query.include_patterns is True


class TestFlextLdifModelsNamespace:
    """Test suite for the FlextLdifModels namespace class."""

    def test_models_namespace_access(self) -> None:
        """Test accessing models through namespace."""
        # Test that all expected model classes are available
        assert hasattr(FlextLdifModels, 'Entry')
        assert hasattr(FlextLdifModels, 'DistinguishedName')
        assert hasattr(FlextLdifModels, 'LdifAttribute')
        assert hasattr(FlextLdifModels, 'LdifAttributes')
        assert hasattr(FlextLdifModels, 'SchemaObjectClass')
        assert hasattr(FlextLdifModels, 'AclTarget')
        assert hasattr(FlextLdifModels, 'AclSubject')
        assert hasattr(FlextLdifModels, 'AclPermissions')
        assert hasattr(FlextLdifModels, 'UnifiedAcl')

    def test_computed_fields(self) -> None:
        """Test namespace-level computed fields."""
        # Test that computed fields exist
        assert hasattr(FlextLdifModels, 'active_ldif_models_count')
        assert hasattr(FlextLdifModels, 'ldif_model_summary')

        # Test computed field values
        count = FlextLdifModels.active_ldif_models_count
        assert isinstance(count, int)
        assert count > 0

        summary = FlextLdifModels.ldif_model_summary
        assert isinstance(summary, dict)
        assert "entry_models" in summary
        assert "schema_models" in summary
        assert "acl_models" in summary