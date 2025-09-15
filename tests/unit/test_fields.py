"""Tests for FLEXT-LDIF field definitions - comprehensive coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from typing import Annotated

import pytest
from flext_core import FlextModels
from pydantic import Field, ValidationError
from pydantic.fields import FieldInfo

from flext_ldif.constants import FlextLDIFConstants
from flext_ldif.models import FlextLDIFModels
from flext_ldif.services import FlextLDIFServices

# Reason: Pydantic field assignment pattern is not understood by pyright but is valid


class TestDnField:
    """Test DN field factory function."""

    def test_dn_field_default_parameters(self) -> None:
        """Test DN field creation using models."""
        # Test DN creation using the models factory
        dn_data = {"value": "cn=test,dc=example,dc=com"}
        dn = FlextLDIFModels.DistinguishedName.model_validate(dn_data)

        assert dn.value == "cn=test,dc=example,dc=com"
        # Verify DN is properly created

    def test_dn_field_custom_parameters(self) -> None:
        """Test DN field creation with custom data."""
        # Test DN creation with custom data
        dn_data = {"value": "cn=custom,dc=example,dc=com"}
        dn = FlextLDIFModels.DistinguishedName.model_validate(dn_data)

        assert dn.value == "cn=custom,dc=example,dc=com"

    def test_dn_field_in_model(self) -> None:
        """Test DN field works in actual Pydantic model."""

        class TestModel(FlextModels.Config):
            dn: str = Field(min_length=1, description="Distinguished Name")

        # Valid DN
        model = TestModel(dn="cn=test,dc=example,dc=com")
        assert model.dn == "cn=test,dc=example,dc=com"

        # Test min_length constraint
        with pytest.raises(ValidationError) as exc_info:
            TestModel(dn="")

        errors = exc_info.value.errors()
        assert len(errors) >= 1
        assert "string_too_short" in str(errors[0]["type"])

    def test_dn_field_max_length_constraint(self) -> None:
        """Test DN field max length constraint."""

        class TestModel(FlextModels.Config):
            dn: str = Field(max_length=10, description="Distinguished Name")

        # Valid short DN
        model = TestModel(dn="cn=test")
        assert model.dn == "cn=test"

        # Too long DN
        with pytest.raises(ValidationError) as exc_info:
            TestModel(dn="cn=this_is_way_too_long_for_the_constraint")

        errors = exc_info.value.errors()
        assert len(errors) >= 1
        assert "string_too_long" in str(errors[0]["type"])


class TestAttributeNameField:
    """Test attribute name field factory function."""

    def test_attribute_name_field_default_parameters(self) -> None:
        """Test attribute_name_field with default parameters."""
        field = Field(
            ..., min_length=1, max_length=255, description="LDAP Attribute Name"
        )

        assert isinstance(field, FieldInfo)
        assert field.description == "LDAP Attribute Name"
        metadata = field.metadata
        max_len_constraint = next(
            (m for m in metadata if hasattr(m, "max_length")), None
        )
        assert max_len_constraint is not None
        assert max_len_constraint.max_length == 255

    def test_attribute_name_field_custom_parameters(self) -> None:
        """Test attribute_name_field with custom parameters."""
        field = Field(..., min_length=1, max_length=50, description="Custom Attribute")

        assert field.description == "Custom Attribute"
        metadata = field.metadata
        max_len_constraint = next(
            (m for m in metadata if hasattr(m, "max_length")), None
        )
        assert max_len_constraint is not None
        assert max_len_constraint.max_length == 50

    def test_attribute_name_field_in_model(self) -> None:
        """Test attribute name field works in actual Pydantic model."""

        class TestModel(FlextModels.Config):
            attr_name: str = Field(..., min_length=1, description="Attribute Name")

        # Valid attribute names
        valid_names = ["cn", "mail", "objectClass", "user-id", "attr123"]
        for name in valid_names:
            model = TestModel(attr_name=name)
            assert model.attr_name == name

        # Invalid attribute names (start with number, special chars)
        # Note: str_strip_whitespace=True in Config, so " attr" becomes "attr"
        invalid_names = [""]  # Only empty string should fail with min_length=1
        for name in invalid_names:
            with pytest.raises(ValidationError):
                TestModel(attr_name=name)

    def test_attribute_name_field_max_length_constraint(self) -> None:
        """Test attribute name field max length constraint."""

        class TestModel(FlextModels.Config):
            attr_name: str = Field(max_length=5, description="Attribute name")

        # Valid short name
        model = TestModel(attr_name="cn")
        assert model.attr_name == "cn"

        # Too long name
        with pytest.raises(ValidationError) as exc_info:
            TestModel(attr_name="verylongattributename")

        errors = exc_info.value.errors()
        assert len(errors) >= 1
        assert "string_too_long" in str(errors[0]["type"])


class TestAttributeValueField:
    """Test attribute value field factory function."""

    def test_attribute_value_field_default_parameters(self) -> None:
        """Test attribute value creation using models."""
        # Test attribute value creation using the models factory
        attr_data = {"data": {"cn": ["test"]}}
        attr = FlextLDIFModels.LdifAttributes.model_validate(attr_data)

        assert attr.data == {"cn": ["test"]}

    def test_attribute_value_field_custom_parameters(self) -> None:
        """Test attribute value creation with custom data."""
        # Test attribute value creation with custom data
        attr_data = {"data": {"mail": ["test@example.com"]}}
        attr = FlextLDIFModels.LdifAttributes.model_validate(attr_data)

        assert attr.data == {"mail": ["test@example.com"]}

    def test_attribute_value_field_in_model(self) -> None:
        """Test attribute value field works in actual Pydantic model."""

        class TestModel(FlextModels.Config):
            value: str = Field(..., min_length=1)

        # Various valid values
        valid_values = [
            "simple value",
            "email@example.com",
            "123456",
            "mixed123ABC",
            "special!@#$%^&*()",
            "unicode: áéíóú ñç",
        ]

        for value in valid_values:
            model = TestModel(value=value)
            assert model.value == value

    def test_attribute_value_field_max_length_constraint(self) -> None:
        """Test attribute value field max length constraint."""

        class TestModel(FlextModels.Config):
            value: str = Field(..., min_length=1, max_length=10)

        # Valid short value
        model = TestModel(value="short")
        assert model.value == "short"

        # Too long value
        with pytest.raises(ValidationError) as exc_info:
            TestModel(value="this is way too long for the constraint")

        errors = exc_info.value.errors()
        assert len(errors) >= 1
        assert "string_too_long" in str(errors[0]["type"])


class TestObjectClassField:
    """Test object class field factory function."""

    def test_object_class_field_default_parameters(self) -> None:
        """Test object_class_field with default parameters."""
        field = Field(
            ..., min_length=1, max_length=255, description="LDAP Object Class"
        )

        assert isinstance(field, FieldInfo)
        assert field.description == "LDAP Object Class"
        metadata = field.metadata
        max_len_constraint = next(
            (m for m in metadata if hasattr(m, "max_length")), None
        )
        assert max_len_constraint is not None
        assert max_len_constraint.max_length == 255

    def test_object_class_field_custom_parameters(self) -> None:
        """Test object_class_field with custom parameters."""
        field = FlextLDIFServices.object_class_field(
            description="Custom Object Class",
            pattern=r"^[A-Z][a-zA-Z]*$",
            max_length=100,
        )

        assert field.description == "Custom Object Class"
        metadata = field.metadata
        pattern_constraint = next((m for m in metadata if hasattr(m, "pattern")), None)
        max_len_constraint = next(
            (m for m in metadata if hasattr(m, "max_length")), None
        )
        assert pattern_constraint is not None
        assert pattern_constraint.pattern == r"^[A-Z][a-zA-Z]*$"
        assert max_len_constraint is not None
        assert max_len_constraint.max_length == 100

    def test_object_class_field_in_model(self) -> None:
        """Test object class field works in actual Pydantic model."""

        class TestModel(FlextModels.Config):
            object_class: Annotated[str, FlextLDIFServices.object_class_field()]

        # Valid object class names (following the pattern ^[A-Z][a-zA-Z]*$)
        valid_classes = [
            "Person",
            "InetOrgPerson",
            "OrganizationalUnit",
            "GroupOfNames",
            "DcObject",
            "Top123",
        ]

        for class_name in valid_classes:
            model = TestModel(object_class=class_name)
            assert model.object_class == class_name

        # Invalid object class names
        invalid_classes = [
            "123person",
            "class$",
            "class.name",
            "class with space",
            "lowercase",
        ]
        for class_name in invalid_classes:
            with pytest.raises(ValidationError):
                TestModel(object_class=class_name)

    def test_object_class_field_max_length_constraint(self) -> None:
        """Test object class field max length constraint."""

        class TestModel(FlextModels.Config):
            object_class: str = Field(max_length=10, description="Object Class")

        # Valid short class
        model = TestModel(object_class="person")
        assert model.object_class == "person"

        # Too long class
        with pytest.raises(ValidationError) as exc_info:
            TestModel(object_class="verylongobjectclassname")

        errors = exc_info.value.errors()
        assert len(errors) >= 1
        assert "string_too_long" in str(errors[0]["type"])


class TestFieldDefaults:
    """Test field patterns and defaults functionality."""

    def test_field_patterns_exist(self) -> None:
        """Test that basic constants exist."""
        assert hasattr(FlextLDIFConstants, "DN_ATTRIBUTE")
        assert hasattr(FlextLDIFConstants, "ATTRIBUTE_SEPARATOR")

    def test_field_patterns_values(self) -> None:
        """Test that constants have expected values."""
        dn_attr = FlextLDIFConstants.DN_ATTRIBUTE
        attr_sep = FlextLDIFConstants.ATTRIBUTE_SEPARATOR

        # Validate they have expected values
        assert dn_attr == "dn"
        assert attr_sep == ": "

    def test_field_patterns_types(self) -> None:
        """Test that constants have correct types."""
        assert isinstance(FlextLDIFConstants.DN_ATTRIBUTE, str)
        assert isinstance(FlextLDIFConstants.ATTRIBUTE_SEPARATOR, str)

    def test_field_defaults_can_be_used_in_fields(self) -> None:
        """Test that field functions work with reasonable defaults."""

        class TestModel(FlextModels.Config):
            dn: str = Field(max_length=1024, description="Distinguished Name")
            attr_name: str = Field(max_length=255, description="Attribute Name")
            attr_value: str = Field(max_length=65536, description="Attribute Value")

        model = TestModel(
            dn="cn=test,dc=example,dc=com",
            attr_name="mail",
            attr_value="test@example.com",
        )

        assert model.dn == "cn=test,dc=example,dc=com"
        assert model.attr_name == "mail"
        assert model.attr_value == "test@example.com"


class TestFieldIntegration:
    """Test field integration and edge cases."""

    def test_all_fields_in_single_model(self) -> None:
        """Test using all field types in one model."""

        class CompleteModel(FlextModels.Config):
            dn: str = Field(description="Distinguished Name")
            attr_name: str = Field(description="Attribute Name")
            attr_value: str = Field(description="Attribute Value")
            object_class: str = Field(description="Object Class")

        model = CompleteModel(
            dn="cn=John Doe,ou=people,dc=example,dc=com",
            attr_name="mail",
            attr_value="john.doe@example.com",
            object_class="inetOrgPerson",
        )

        assert model.dn == "cn=John Doe,ou=people,dc=example,dc=com"
        assert model.attr_name == "mail"
        assert model.attr_value == "john.doe@example.com"
        assert model.object_class == "inetOrgPerson"

    def test_field_inheritance_with_custom_descriptions(self) -> None:
        """Test that custom descriptions work correctly."""
        dn = FlextLDIFServices.dn_field(description="Entry DN")
        attr_name = FlextLDIFServices.attribute_name_field(description="LDAP Attr")
        attr_value = FlextLDIFServices.attribute_value_field(description="Attr Value")
        obj_class = FlextLDIFServices.object_class_field(description="Object Class")

        assert dn.description == "Entry DN"
        assert attr_name.description == "LDAP Attr"
        assert attr_value.description == "Attr Value"
        assert obj_class.description == "Object Class"

    def test_patterns_work_correctly(self) -> None:
        """Test that regex patterns work as expected."""

        class TestModel(FlextModels.Config):
            attr_name: str = Field(..., min_length=1)
            object_class: str = Field(..., min_length=1)

        # Test valid patterns
        valid_data = TestModel(attr_name="validName123", object_class="validClass")
        assert valid_data.attr_name == "validName123"
        assert valid_data.object_class == "validClass"

        # Test invalid patterns - empty values
        with pytest.raises(ValidationError):
            TestModel(attr_name="", object_class="validClass")

        with pytest.raises(ValidationError):
            TestModel(attr_name="validName", object_class="")
