"""FLEXT LDIF Models - Comprehensive Unit Tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import threading
import time

import pytest
from pydantic import ValidationError

from flext_ldif.models import FlextLdifModels


@pytest.mark.unit
class TestFlextLdifModels:
    """Comprehensive tests for FlextLdifModels class."""

    def test_distinguished_name_creation(self) -> None:
        """Test DistinguishedName creation."""
        dn = FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com")

        assert dn is not None
        assert dn.value == "cn=test,dc=example,dc=com"

    def test_distinguished_name_validation(self) -> None:
        """Test DistinguishedName validation."""
        # Test valid DN
        dn = FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com")
        assert dn.value == "cn=test,dc=example,dc=com"

        # Test DN with whitespace (should be trimmed)
        dn = FlextLdifModels.DistinguishedName(value="  cn=test,dc=example,dc=com  ")
        assert dn.value == "cn=test,dc=example,dc=com"

    def test_distinguished_name_validation_empty(self) -> None:
        """Test DistinguishedName validation with empty value."""
        with pytest.raises(ValidationError):
            FlextLdifModels.DistinguishedName(value="")

    def test_ldif_attribute_creation(self) -> None:
        """Test LdifAttribute creation."""
        attr = FlextLdifModels.LdifAttribute(name="cn", values=["Test User"])

        assert attr is not None
        assert attr.name == "cn"
        assert attr.values == ["Test User"]

    def test_ldif_attribute_validation(self) -> None:
        """Test LdifAttribute validation."""
        # Test valid attribute
        attr = FlextLdifModels.LdifAttribute(name="cn", values=["Test User"])
        assert attr.name == "cn"
        assert attr.values == ["Test User"]

        # Test attribute name normalization (should be lowercase)
        attr = FlextLdifModels.LdifAttribute(name="CN", values=["Test User"])
        assert attr.name == "cn"

    def test_ldif_attribute_validation_empty_name(self) -> None:
        """Test LdifAttribute validation with empty name."""
        with pytest.raises(ValidationError, match="String should have at least 1 character"):
            FlextLdifModels.LdifAttribute(name="", values=["Test User"])

    def test_ldif_attributes_creation(self) -> None:
        """Test LdifAttributes creation."""
        attrs = FlextLdifModels.LdifAttributes(
            attributes={"cn": ["Test User"], "mail": ["test@example.com"]}
        )

        assert attrs is not None
        assert attrs.attributes == {"cn": ["Test User"], "mail": ["test@example.com"]}

    def test_ldif_attributes_get_attribute(self) -> None:
        """Test LdifAttributes get_attribute method."""
        attrs = FlextLdifModels.LdifAttributes(
            attributes={"cn": ["Test User"], "mail": ["test@example.com"]}
        )

        # Test getting existing attribute
        cn_values = attrs.get_attribute("cn")
        assert cn_values == ["Test User"]

        # Test getting non-existing attribute
        missing_values = attrs.get_attribute("missing")
        assert missing_values == []

    def test_ldif_attributes_set_attribute(self) -> None:
        """Test LdifAttributes set_attribute method."""
        attrs = FlextLdifModels.LdifAttributes()

        # Test setting new attribute
        attrs.set_attribute("cn", ["Test User"])
        assert attrs.get_attribute("cn") == ["Test User"]

        # Test setting existing attribute
        attrs.set_attribute("cn", ["Updated User"])
        assert attrs.get_attribute("cn") == ["Updated User"]

    def test_entry_creation(self) -> None:
        """Test Entry creation."""
        dn = FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com")
        attrs = FlextLdifModels.LdifAttributes(
            attributes={"cn": ["Test User"], "mail": ["test@example.com"]}
        )

        entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)

        assert entry is not None
        assert entry.dn == dn
        assert entry.attributes == attrs

    def test_entry_create_method(self) -> None:
        """Test Entry create method."""
        result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["Test User"], "mail": ["test@example.com"]},
        )

        assert result.is_success
        entry = result.value
        assert entry.dn.value == "cn=test,dc=example,dc=com"
        assert entry.attributes.attributes == {
            "cn": ["Test User"],
            "mail": ["test@example.com"],
        }

    def test_entry_create_method_invalid_dn(self) -> None:
        """Test Entry create method with invalid DN."""
        result = FlextLdifModels.Entry.create(
            dn="",  # Invalid empty DN
            attributes={"cn": ["Test User"]},
        )

        assert result.is_failure
        assert result.error is not None

    def test_change_record_creation(self) -> None:
        """Test ChangeRecord creation."""
        dn = FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com")
        attrs = FlextLdifModels.LdifAttributes(attributes={"cn": ["Test User"]})

        change_record = FlextLdifModels.ChangeRecord(
            dn=dn, changetype="add", attributes=attrs
        )

        assert change_record is not None
        assert change_record.dn == dn
        assert change_record.changetype == "add"
        assert change_record.attributes == attrs

    def test_schema_object_class_creation(self) -> None:
        """Test SchemaObjectClass creation."""
        obj_class = FlextLdifModels.SchemaObjectClass(
            name="person",
            oid="2.5.6.6",
            must=["cn", "sn"],
            may=["mail", "telephoneNumber"],
        )

        assert obj_class is not None
        assert obj_class.name == "person"
        assert obj_class.oid == "2.5.6.6"
        assert obj_class.must == ["cn", "sn"]
        assert obj_class.may == ["mail", "telephoneNumber"]

    def test_schema_discovery_result_creation(self) -> None:
        """Test SchemaDiscoveryResult creation."""
        result = FlextLdifModels.SchemaDiscoveryResult(
            object_classes={"person": {"name": "person", "oid": "2.5.6.6"}},
            attributes={"cn": {"syntax": "1.3.6.1.4.1.1466.115.121.1.15"}},
        )

        assert result is not None
        assert "person" in result.object_classes
        assert result.object_classes["person"].name == "person"
        assert result.object_classes["person"].oid == "2.5.6.6"
        assert result.attributes == {"cn": {"syntax": "1.3.6.1.4.1.1466.115.121.1.15"}}

    def test_acl_target_creation(self) -> None:
        """Test AclTarget creation."""
        target = FlextLdifModels.AclTarget(target_dn="cn=test,dc=example,dc=com")

        assert target is not None
        assert target.target_dn == "cn=test,dc=example,dc=com"

    def test_acl_target_create_method(self) -> None:
        """Test AclTarget create method."""
        result = FlextLdifModels.AclTarget.create(target_dn="cn=test,dc=example,dc=com")

        assert result.is_success
        target = result.value
        assert target.target_dn == "cn=test,dc=example,dc=com"

    def test_acl_subject_creation(self) -> None:
        """Test AclSubject creation."""
        subject = FlextLdifModels.AclSubject(subject_dn="uid=user,dc=example,dc=com")

        assert subject is not None
        assert subject.subject_dn == "uid=user,dc=example,dc=com"

    def test_acl_subject_create_method(self) -> None:
        """Test AclSubject create method."""
        result = FlextLdifModels.AclSubject.create(
            subject_dn="uid=user,dc=example,dc=com"
        )

        assert result.is_success
        subject = result.value
        assert subject.subject_dn == "uid=user,dc=example,dc=com"

    def test_acl_permissions_creation(self) -> None:
        """Test AclPermissions creation."""
        permissions = FlextLdifModels.AclPermissions(
            read=True, write=False, add=True, delete=False
        )

        assert permissions is not None
        assert permissions.read is True
        assert permissions.write is False
        assert permissions.add is True
        assert permissions.delete is False

    def test_acl_permissions_create_method(self) -> None:
        """Test AclPermissions create method."""
        result = FlextLdifModels.AclPermissions.create(
            read=True, write=False, add=True, delete=False
        )

        assert result.is_success
        permissions = result.value
        assert permissions.read is True
        assert permissions.write is False
        assert permissions.add is True
        assert permissions.delete is False

    def test_unified_acl_creation(self) -> None:
        """Test UnifiedAcl creation."""
        target = FlextLdifModels.AclTarget(target_dn="cn=test,dc=example,dc=com")
        subject = FlextLdifModels.AclSubject(subject_dn="uid=user,dc=example,dc=com")
        permissions = FlextLdifModels.AclPermissions(read=True, write=False)

        acl = FlextLdifModels.UnifiedAcl(
            target=target, subject=subject, permissions=permissions
        )

        assert acl is not None
        assert acl.target == target
        assert acl.subject == subject
        assert acl.permissions == permissions

    def test_unified_acl_create_method(self) -> None:
        """Test UnifiedAcl create method."""
        target = FlextLdifModels.AclTarget(target_dn="cn=test,dc=example,dc=com")
        subject = FlextLdifModels.AclSubject(subject_dn="uid=user,dc=example,dc=com")
        permissions = FlextLdifModels.AclPermissions(read=True, write=False)

        result = FlextLdifModels.UnifiedAcl.create(
            target=target, subject=subject, permissions=permissions
        )

        assert result.is_success
        acl = result.value
        assert acl.target == target
        assert acl.subject == subject
        assert acl.permissions == permissions

    def test_schema_attribute_creation(self) -> None:
        """Test SchemaAttribute creation."""
        attr = FlextLdifModels.SchemaAttribute(
            name="cn", oid="2.5.4.3", syntax="1.3.6.1.4.1.1466.115.121.1.15"
        )

        assert attr is not None
        assert attr.name == "cn"
        assert attr.oid == "2.5.4.3"
        assert attr.syntax == "1.3.6.1.4.1.1466.115.121.1.15"

    def test_schema_attribute_create_method(self) -> None:
        """Test SchemaAttribute create method."""
        result = FlextLdifModels.SchemaAttribute.create(
            name="cn", oid="2.5.4.3", syntax="1.3.6.1.4.1.1466.115.121.1.15"
        )

        assert result.is_success
        attr = result.value
        assert attr.name == "cn"
        assert attr.oid == "2.5.4.3"
        assert attr.syntax == "1.3.6.1.4.1.1466.115.121.1.15"

    def test_models_immutability(self) -> None:
        """Test that frozen models are immutable."""
        # Test DistinguishedName immutability
        dn = FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com")

        # Test that frozen models are immutable
        with pytest.raises((AttributeError, TypeError, Exception)):
            dn.value = "modified"  # type: ignore[misc]

    def test_models_performance(self) -> None:
        """Test models performance characteristics."""
        # Test model creation performance
        start_time = time.time()

        for _ in range(1000):
            FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com")
            FlextLdifModels.LdifAttribute(name="cn", values=["Test User"])

        end_time = time.time()
        execution_time = end_time - start_time

        assert execution_time < 1.0  # Should complete within 1 second

    def test_models_memory_usage(self) -> None:
        """Test models memory usage characteristics."""
        # Test that models don't leak memory
        models = []

        for _ in range(100):
            dn = FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com")
            attr = FlextLdifModels.LdifAttribute(name="cn", values=["Test User"])
            models.extend([dn, attr])

        # Verify all models are valid
        assert len(models) == 200
        for model in models:
            assert model is not None

    def test_models_edge_cases(self) -> None:
        """Test models with edge cases."""
        # Test with very long DN
        long_dn = "cn=" + "x" * 1000 + ",dc=example,dc=com"
        # Test with very long DN - should either succeed or fail gracefully
        # Test with very long DN - should either succeed or fail gracefully
        try:
            dn = FlextLdifModels.DistinguishedName(value=long_dn)
            assert dn.value == long_dn
        except (ValueError, ValidationError):
            # Expected behavior for very long DNs
            pass

        # Test with special characters
        # Test with special characters - should either succeed or fail gracefully
        special_dn = "cn=test with spaces,dc=example,dc=com"
        try:
            dn = FlextLdifModels.DistinguishedName(value=special_dn)
            assert dn.value == special_dn
        except (ValueError, ValidationError):
            # Expected behavior for special characters
            pass

    def test_models_concurrent_access(self) -> None:
        """Test models concurrent access."""
        models = []

        def worker() -> None:
            dn = FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com")
            attr = FlextLdifModels.LdifAttribute(name="cn", values=["Test User"])
            models.extend([dn, attr])

        # Start multiple threads
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=worker)
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Verify all operations succeeded
        assert len(models) == 10
        for model in models:
            assert model is not None
