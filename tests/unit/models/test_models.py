"""Test suite for FlextLdifModels.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import cast

from flext_core import FlextModels, FlextResult

from flext_ldif.models import FlextLdifModels


class TestFlextLdifModels:
    """Test suite for FlextLdifModels."""

    def test_dn_creation(self) -> None:
        """Test DN model creation."""
        dn = FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com")
        assert dn.value == "cn=test,dc=example,dc=com"

    def test_dn_validation(self) -> None:
        """Test DN validation with lenient processing pattern."""
        # Valid DN
        dn = FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com")
        assert dn.value == "cn=test,dc=example,dc=com"

        # Lenient processing: Empty DN is ACCEPTED (validation at Entry level)
        empty_dn = FlextLdifModels.DistinguishedName(value="")
        assert empty_dn.value == ""

        # Lenient processing: Long DN is ACCEPTED (validation at Entry level)
        long_dn_value = "cn=" + "x" * 2048 + ",dc=example,dc=com"
        long_dn = FlextLdifModels.DistinguishedName(value=long_dn_value)
        assert long_dn.value == long_dn_value

        # Note: RFC violations are captured at Entry level in validation_metadata

    def test_dn_case_preservation(self) -> None:
        """Test DN case preservation (normalization is in infrastructure layer).

        Note: Domain models validate format only, infrastructure services normalize.
        """
        # Test that DN validation accepts and preserves various case formats
        dn = FlextLdifModels.DistinguishedName(value="CN=Test,DC=Example,DC=Com")
        # Domain model preserves DN as-is (no normalization at domain level)
        assert dn.value == "CN=Test,DC=Example,DC=Com"

    def test_attributes_creation(self) -> None:
        """Test Attributes model creation."""
        attrs = FlextLdifModels.LdifAttributes(
            attributes={
                "cn": ["test"],
                "sn": ["user"],
            },
        )
        assert len(attrs.attributes) == 2
        assert "cn" in attrs.attributes
        assert "sn" in attrs.attributes

    def test_attributes_get_attribute(self) -> None:
        """Test getting attributes by name."""
        attrs = FlextLdifModels.LdifAttributes(
            attributes={
                "cn": ["test"],
            },
        )

        # Test getting existing attribute
        cn_attr = attrs.get("cn")
        assert cn_attr == ["test"]

        # Test non-existent attribute with default
        missing_attr = attrs.get("missing")
        assert missing_attr == []

    def test_attributes_add_attribute(self) -> None:
        """Test adding attributes."""
        attrs = FlextLdifModels.LdifAttributes(attributes={})

        attrs.add_attribute("cn", "test")
        cn_attr = attrs.get("cn")
        assert cn_attr == ["test"]

    def test_attributes_add_attribute_multiple_values(self) -> None:
        """Test adding attributes with multiple values."""
        attrs = FlextLdifModels.LdifAttributes(attributes={})

        attrs.add_attribute("cn", ["test1", "test2"])
        cn_attr = attrs.get("cn")
        assert cn_attr == ["test1", "test2"]

    def test_attributes_remove_attribute(self) -> None:
        """Test removing attributes."""
        attrs = FlextLdifModels.LdifAttributes(
            attributes={
                "cn": ["test"],
            },
        )

        attrs.remove_attribute("cn")
        # After removal, attribute should not exist
        assert "cn" not in attrs.attributes

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
                    "cn": ["test"],
                    "objectclass": ["person"],
                },
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
                    "objectclass": ["person"],
                },
            ),
        )
        assert entry.dn.value == "cn=test,dc=example,dc=com"

    def test_model_serialization(self) -> None:
        """Test model serialization."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["test"],
                    "objectclass": ["person"],
                },
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
        assert "cn" in entry.attributes.attributes

    def test_model_validation_errors(self) -> None:
        """Test model validation with lenient processing pattern."""
        # Lenient processing: Empty DN is ACCEPTED but captured in validation_metadata
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value=""
            ),  # Empty DN triggers RFC violation
            attributes=FlextLdifModels.LdifAttributes(attributes={}),
        )

        # Entry creation succeeds (lenient processing)
        assert entry is not None

        # Verify RFC violations were captured
        assert entry.metadata.validation_results is not None
        assert "rfc_violations" in entry.metadata.validation_results
        violations = entry.metadata.validation_results["rfc_violations"]

        # Should have 2 violations: empty DN + no attributes
        assert len(violations) >= 2
        assert any("DN" in v for v in violations)
        assert any("attribute" in v for v in violations)

    def test_model_inheritance(self) -> None:
        """Test that models properly inherit from FlextModels."""
        # Test that all models are properly structured
        assert hasattr(FlextLdifModels, "DistinguishedName")
        assert hasattr(FlextLdifModels, "LdifAttributes")
        assert hasattr(FlextLdifModels, "Entry")
        # Note: AttributeValues deleted - use dict[str, list[str]] directly in LdifAttributes
        # Note: SearchConfig deleted (0 usages) - use dict[str, object] for LDAP search config

    def test_edge_cases(self) -> None:
        """Test edge cases in models."""
        # Test DN with special characters (properly escaped per RFC 4514)
        dn = FlextLdifModels.DistinguishedName(value="cn=test\\+user,dc=example,dc=com")
        assert dn.value == "cn=test\\+user,dc=example,dc=com"

        # Test attributes with special characters
        attrs = FlextLdifModels.LdifAttributes(
            attributes={
                "cn;lang-en": ["test"],
            },
        )
        assert "cn;lang-en" in attrs.attributes

        # Test empty attribute values
        attrs = FlextLdifModels.LdifAttributes(
            attributes={
                "cn": [""],
            },
        )
        cn_attr = attrs.get("cn")
        assert cn_attr == [""]

    # NOTE: EntryParsedEvent model was removed as part of simplification.
    # If event-driven patterns are needed, use flext-core event system.

    # NOTE: EntriesValidatedEvent model was removed as part of simplification.

    # NOTE: AnalyticsGeneratedEvent model was removed as part of simplification.

    # NOTE: EntriesWrittenEvent model was removed as part of simplification.

    # NOTE: MigrationCompletedEvent model was removed as part of simplification.

    # NOTE: QuirkRegisteredEvent model was removed as part of simplification.

    def test_schema_object_class_creation(self) -> None:
        """Test SchemaObjectClass model creation."""
        obj_class = FlextLdifModels.SchemaObjectClass(
            name="person",
            oid="2.5.6.6",
            desc="Person object class",
            sup=None,
            must=["cn", "sn"],
            may=["telephoneNumber", "seeAlso"],
            kind="STRUCTURAL",
        )
        assert obj_class.name == "person"
        assert obj_class.oid == "2.5.6.6"
        assert obj_class.desc == "Person object class"
        assert obj_class.must == ["cn", "sn"]
        assert obj_class.may == ["telephoneNumber", "seeAlso"]
        assert obj_class.is_structural is True

    def test_schema_object_class_direct_instantiation(self) -> None:
        """Test SchemaObjectClass direct instantiation."""
        # Direct instantiation pattern - Pydantic 2 validates natively
        obj_class = FlextLdifModels.SchemaObjectClass(
            name="organizationalUnit",
            oid="2.5.6.5",
            desc="Organizational unit",
            sup=None,
            must=["ou"],
        )
        assert isinstance(obj_class, FlextLdifModels.SchemaObjectClass)
        assert obj_class.name == "organizationalUnit"
        assert obj_class.oid == "2.5.6.5"
        assert obj_class.must == ["ou"]
        assert obj_class.may is None  # may defaults to None when not provided
        assert obj_class.desc == "Organizational unit"

    def test_schema_discovery_result_creation(self) -> None:
        """Test SchemaDiscoveryResult model creation."""
        result = FlextLdifModels.SchemaDiscoveryResult(
            objectclasses={
                "person": {
                    "oid": "2.5.6.6",
                    "description": "Person class",
                },
            },
            attributes={
                "cn": {
                    "oid": "2.5.4.3",
                    "description": "Common name",
                    "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
                },
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
            desc="Common name attribute",
            sup=None,
            equality=None,
            ordering=None,
            substr=None,
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            length=None,
            usage=None,
        )
        assert attr.name == "cn"
        assert attr.oid == "2.5.4.3"
        assert attr.desc == "Common name attribute"
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
        # Use duck typing or base class check instead of facade class
        assert hasattr(entry.attributes, "attributes")
        assert isinstance(entry.attributes.attributes, dict)

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
        """Test Entry validation with lenient processing pattern."""
        # Valid entry
        result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"objectclass": ["person"], "cn": ["test"]},
        )
        assert result.is_success

        # Lenient processing: Empty DN is ACCEPTED but captured in validation_metadata
        result = FlextLdifModels.Entry.create(
            dn="",  # Empty DN triggers RFC violation
            attributes={"objectclass": ["person"], "cn": ["test"]},
        )
        assert result.is_success  # Entry NOT rejected (lenient processing)
        entry = result.unwrap()

        # Verify RFC violation was captured in validation_metadata
        assert entry.metadata.validation_results is not None
        assert "rfc_violations" in entry.metadata.validation_results
        violations = entry.metadata.validation_results["rfc_violations"]
        assert any("RFC 2849" in v and "DN" in v for v in violations)


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
        """Test invalid DN format is PRESERVED (lenient processing).

        DistinguishedName accepts ANY string to preserve server-specific DN formats.
        RFC validation happens at Entry level, where violations are captured in metadata.
        """
        invalid_dn = "invalid-dn-format"

        # Lenient processing: DistinguishedName accepts ANY string
        dn = FlextLdifModels.DistinguishedName(value=invalid_dn)

        # DN is accepted (preserves server quirks)
        assert dn.value == invalid_dn

        # Note: Entry-level validation will capture RFC violation in validation_metadata
        # See test_pydantic_validators_rfc_compliance.py for Entry validation tests


class TestFlextLdifModelsLdifAttributes:
    """Test suite for LdifAttributes model."""

    def test_attributes_creation(self) -> None:
        """Test creating an LdifAttributes instance."""
        attrs_data = {
            "cn": ["Test User"],
            "sn": ["User"],
            "objectclass": ["inetOrgPerson", "person"],
        }

        result = FlextLdifModels.LdifAttributes.create(
            cast("dict[str, object]", attrs_data),
        )

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
        assert isinstance(attrs, FlextLdifModels.LdifAttributes)
        assert attrs.attributes == {}

    def test_attributes_with_options(self) -> None:
        """Test attributes with LDAP options."""
        attrs_data = {
            "cn": ["Test User"],
            "userCertificate;binary": ["cert-data"],
        }

        result = FlextLdifModels.LdifAttributes.create(
            cast("dict[str, object]", attrs_data),
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
            desc="Internet Organizational Person",
            sup=None,
            kind="STRUCTURAL",
            must=["cn", "sn", "objectclass"],
            may=["description", "telephoneNumber", "mail"],
        )

        assert isinstance(oc, FlextLdifModels.SchemaObjectClass)
        assert oc.name == "inetOrgPerson"
        assert oc.oid == "2.16.840.1.113730.3.2.2"
        assert oc.must == ["cn", "sn", "objectclass"]
        assert oc.may == ["description", "telephoneNumber", "mail"]

    def test_objectclass_validation(self) -> None:
        """Test object class validation."""
        # Valid object class - Direct instantiation pattern
        oc = FlextLdifModels.SchemaObjectClass(
            name="person",
            oid="2.5.6.6",
            desc="Person object class",
            sup=None,
            kind="STRUCTURAL",
        )
        assert isinstance(oc, FlextLdifModels.SchemaObjectClass)

    def test_computed_fields(self) -> None:
        """Test computed fields on object class."""
        # Direct instantiation pattern - Pydantic 2 validates natively
        oc = FlextLdifModels.SchemaObjectClass(
            name="inetOrgPerson",
            oid="2.16.840.1.113730.3.2.2",
            desc="Internet Organizational Person",
            sup=None,
            must=["cn", "sn"],
            may=["mail", "telephoneNumber"],
        )
        assert isinstance(oc, FlextLdifModels.SchemaObjectClass)

        # Test field access
        assert oc.must == ["cn", "sn"]
        assert oc.may == ["mail", "telephoneNumber"]


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
            subject_value="cn=admin,dc=example,dc=com",
        )

        assert isinstance(subject, FlextLdifModels.AclSubject)
        assert subject.subject_type == "user"


class TestFlextLdifModelsAclPermissions:
    """Test suite for ACL Permissions model."""

    def test_acl_permissions_creation(self) -> None:
        """Test creating an AclPermissions instance."""
        # Direct instantiation pattern - Pydantic 2 validates natively
        # AclPermissions uses individual boolean fields
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

        # Verify computed list of active permissions manually
        active_permissions = [
            perm
            for perm in [
                "read",
                "write",
                "add",
                "delete",
                "search",
                "compare",
                "self_write",
                "proxy",
            ]
            if getattr(perms, perm, False)
        ]
        assert len(active_permissions) == 2
        assert "read" in active_permissions
        assert "write" in active_permissions


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
            subject_value="cn=admin,dc=example,dc=com",
        )

        perms = FlextLdifModels.AclPermissions(
            read=True,
            write=True,
        )

        # Create unified ACL using direct instantiation of OracleOudAcl
        # (aggressive Pydantic 2 direct usage pattern - no factory class)
        try:
            oud_acl = FlextLdifModels.Acl(
                name="test_acl",
                target=target,
                subject=subject,
                permissions=perms,
                server_type="oracle_oud",
            )
            result = FlextResult[FlextLdifModels.Acl].ok(oud_acl)
        except (ValueError, TypeError, AttributeError) as e:  # pragma: no cover
            result = FlextResult[FlextLdifModels.Acl].fail(str(e))

        assert result.is_success
        acl: FlextLdifModels.Acl = result.unwrap()
        # Discriminated union returns the specific subtype (OracleOudAcl in this case)
        assert isinstance(acl, FlextLdifModels.Acl)
        assert isinstance(acl, FlextLdifModels.Acl)
        assert acl.name == "test_acl"
        assert acl.server_type == "oracle_oud"


class TestFlextLdifModelsNamespace:
    """Test suite for the FlextLdifModels namespace class."""

    def test_models_namespace_access(self) -> None:
        """Test accessing models through namespace."""
        # Test that all expected model classes are available
        assert hasattr(FlextLdifModels, "Entry")
        assert hasattr(FlextLdifModels, "DistinguishedName")
        assert hasattr(FlextLdifModels, "LdifAttributes")
        assert hasattr(FlextLdifModels, "SchemaObjectClass")
        assert hasattr(FlextLdifModels, "AclTarget")
        assert hasattr(FlextLdifModels, "AclSubject")
        assert hasattr(FlextLdifModels, "AclPermissions")
        # Universal ACL model consolidation: replaced 7 separate ACL classes with single Acl model
        # Note: OpenLdapAcl, OracleOudAcl, etc. consolidated into FlextLdifModels.Acl with server_type field
        # Note: AttributeValues deleted - LdifAttributes now uses dict[str, list[str]] directly
        assert hasattr(FlextLdifModels, "Acl")

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
        assert hasattr(FlextLdifModels, "SchemaObjectClass")
        assert hasattr(FlextLdifModels, "AclTarget")
        assert hasattr(FlextLdifModels, "AclSubject")
        assert hasattr(FlextLdifModels, "AclPermissions")
        # Universal ACL model consolidation: replaced 7 separate ACL classes with single Acl model
        # Note: OpenLdapAcl, OracleOudAcl, etc. consolidated into FlextLdifModels.Acl with server_type field
        # Note: AttributeValues deleted - LdifAttributes now uses dict[str, list[str]] directly
        assert hasattr(FlextLdifModels, "Acl")
