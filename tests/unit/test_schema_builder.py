"""Test suite for FlextLdifSchemaBuilder."""

import pytest

from flext_ldif.models import FlextLdifModels
from flext_ldif.schema.builder import FlextLdifSchemaBuilder


class TestFlextLdifSchemaBuilder:
    """Test suite for FlextLdifSchemaBuilder."""

    def test_initialization(self) -> None:
        """Test schema builder initialization."""
        builder = FlextLdifSchemaBuilder()
        assert builder is not None
        assert builder.logger is not None
        assert builder.attributes == {}
        assert builder.object_classes == {}
        assert builder.server_type == "generic"
        assert builder.entry_count == 0

    def test_execute(self) -> None:
        """Test execute method."""
        builder = FlextLdifSchemaBuilder()
        result = builder.execute()

        assert result.is_success
        schema = result.value
        assert isinstance(schema, FlextLdifModels.SchemaDiscoveryResult)

    @pytest.mark.asyncio
    async def test_execute_async(self) -> None:
        """Test async execute method."""
        builder = FlextLdifSchemaBuilder()
        result = await builder.execute_async()

        assert result.is_success
        schema = result.value
        assert isinstance(schema, FlextLdifModels.SchemaDiscoveryResult)

    def test_add_attribute_single_value(self) -> None:
        """Test adding single-value attribute."""
        builder = FlextLdifSchemaBuilder()

        result = builder.add_attribute("cn", "Common Name", single_value=True)

        # Should return self for method chaining
        assert result is builder
        assert "cn" in builder.attributes
        attr = builder.attributes["cn"]
        assert attr.name == "cn"
        assert attr.description == "Common Name"
        assert attr.single_value is True

    def test_add_attribute_multi_value(self) -> None:
        """Test adding multi-value attribute."""
        builder = FlextLdifSchemaBuilder()

        result = builder.add_attribute("member", "Group Member")

        # Should return self for method chaining
        assert result is builder
        assert "member" in builder.attributes
        attr = builder.attributes["member"]
        assert attr.name == "member"
        assert attr.description == "Group Member"
        assert attr.single_value is False

    def test_add_object_class(self) -> None:
        """Test adding object class."""
        builder = FlextLdifSchemaBuilder()

        result = builder.add_object_class("person", "Person class", ["cn", "sn"])

        # Should return self for method chaining
        assert result is builder
        assert "person" in builder.object_classes
        oc = builder.object_classes["person"]
        assert oc.name == "person"
        assert oc.description == "Person class"
        assert "cn" in oc.required_attributes
        assert "sn" in oc.required_attributes

    def test_set_server_type(self) -> None:
        """Test setting server type."""
        builder = FlextLdifSchemaBuilder()

        result = builder.set_server_type("openldap")

        # Should return self for method chaining
        assert result is builder
        assert builder.server_type == "openldap"

    def test_fluent_builder_pattern(self) -> None:
        """Test fluent builder pattern with method chaining."""
        builder = FlextLdifSchemaBuilder()

        result = (
            builder.add_attribute("cn", "Common Name", single_value=True)
            .add_attribute("sn", "Surname", single_value=True)
            .add_object_class("person", "Person class", ["cn", "sn"])
            .set_server_type("openldap")
        )

        # Should return the builder for chaining
        assert result is builder
        assert len(builder.attributes) == 2
        assert len(builder.object_classes) == 1
        assert builder.server_type == "openldap"

    def test_build_schema(self) -> None:
        """Test building schema."""
        builder = FlextLdifSchemaBuilder()

        # Add some attributes and object classes
        builder.add_attribute("cn", "Common Name", single_value=True)
        builder.add_attribute("sn", "Surname", single_value=True)
        builder.add_object_class("person", "Person class", ["cn", "sn"])
        builder.set_server_type("openldap")

        result = builder.build()

        assert result.is_success
        schema = result.value
        assert isinstance(schema, FlextLdifModels.SchemaDiscoveryResult)
        assert len(schema.attributes) == 2
        assert len(schema.object_classes) == 1
        assert schema.server_type == "openldap"

    def test_build_empty_schema(self) -> None:
        """Test building empty schema."""
        builder = FlextLdifSchemaBuilder()

        result = builder.build()

        assert result.is_success
        schema = result.value
        assert isinstance(schema, FlextLdifModels.SchemaDiscoveryResult)
        assert len(schema.attributes) == 0
        assert len(schema.object_classes) == 0
        assert schema.server_type == "generic"

    def test_reset_builder(self) -> None:
        """Test resetting builder."""
        builder = FlextLdifSchemaBuilder()

        # Add some data
        builder.add_attribute("cn", "Common Name")
        builder.add_object_class("person", "Person class", ["cn"])
        builder.set_server_type("openldap")

        # Reset
        result = builder.reset()

        # Should return self for method chaining
        assert result is builder
        assert len(builder.attributes) == 0
        assert len(builder.object_classes) == 0
        assert builder.server_type == "generic"
        assert builder.entry_count == 0

    def test_build_standard_person_schema(self) -> None:
        """Test building standard person schema."""
        builder = FlextLdifSchemaBuilder()

        result = builder.build_standard_person_schema()

        assert result.is_success
        schema = result.value
        assert isinstance(schema, FlextLdifModels.SchemaDiscoveryResult)

        # Check that standard person attributes are present
        assert "cn" in schema.attributes
        assert "sn" in schema.attributes
        assert "uid" in schema.attributes
        assert "mail" in schema.attributes
        assert "telephoneNumber" in schema.attributes
        assert "objectClass" in schema.attributes

        # Check that standard person object classes are present
        assert "top" in schema.object_classes
        assert "person" in schema.object_classes
        assert "organizationalPerson" in schema.object_classes
        assert "inetOrgPerson" in schema.object_classes

        # Verify single-value attributes
        assert schema.attributes["cn"].single_value is True
        assert schema.attributes["sn"].single_value is True
        assert schema.attributes["uid"].single_value is True

    def test_build_standard_group_schema(self) -> None:
        """Test building standard group schema."""
        builder = FlextLdifSchemaBuilder()

        result = builder.build_standard_group_schema()

        assert result.is_success
        schema = result.value
        assert isinstance(schema, FlextLdifModels.SchemaDiscoveryResult)

        # Check that standard group attributes are present
        assert "cn" in schema.attributes
        assert "member" in schema.attributes
        assert "uniqueMember" in schema.attributes
        assert "objectClass" in schema.attributes

        # Check that standard group object classes are present
        assert "top" in schema.object_classes
        assert "groupOfNames" in schema.object_classes
        assert "groupOfUniqueNames" in schema.object_classes

        # Verify single-value attributes
        assert schema.attributes["cn"].single_value is True

    def test_build_custom_schema(self) -> None:
        """Test building custom schema with fluent interface."""
        builder = FlextLdifSchemaBuilder()

        result = (
            builder.reset()
            .add_attribute("customAttr", "Custom Attribute", single_value=True)
            .add_attribute("multiAttr", "Multi-value Attribute")
            .add_object_class("customClass", "Custom Class", ["customAttr"])
            .add_object_class("anotherClass", "Another Class", ["multiAttr"])
            .set_server_type("custom")
            .build()
        )

        assert result.is_success
        schema = result.value
        assert isinstance(schema, FlextLdifModels.SchemaDiscoveryResult)

        # Verify custom attributes
        assert "customAttr" in schema.attributes
        assert "multiAttr" in schema.attributes
        assert schema.attributes["customAttr"].single_value is True
        assert schema.attributes["multiAttr"].single_value is False

        # Verify custom object classes
        assert "customClass" in schema.object_classes
        assert "anotherClass" in schema.object_classes
        assert schema.object_classes["customClass"].required_attributes == [
            "customAttr"
        ]
        assert schema.object_classes["anotherClass"].required_attributes == [
            "multiAttr"
        ]

        # Verify server type
        assert schema.server_type == "custom"

    def test_build_schema_with_multiple_resets(self) -> None:
        """Test building multiple schemas with resets."""
        builder = FlextLdifSchemaBuilder()

        # Build first schema
        result1 = (
            builder.add_attribute("attr1", "Attribute 1")
            .add_object_class("class1", "Class 1", ["attr1"])
            .build()
        )

        assert result1.is_success
        schema1 = result1.value
        assert len(schema1.attributes) == 1
        assert len(schema1.object_classes) == 1

        # Reset and build second schema
        result2 = (
            builder.reset()
            .add_attribute("attr2", "Attribute 2")
            .add_object_class("class2", "Class 2", ["attr2"])
            .build()
        )

        assert result2.is_success
        schema2 = result2.value
        assert len(schema2.attributes) == 1
        assert len(schema2.object_classes) == 1
        assert "attr2" in schema2.attributes
        assert "class2" in schema2.object_classes
        assert "attr1" not in schema2.attributes
        assert "class1" not in schema2.object_classes

    def test_build_schema_with_complex_object_class(self) -> None:
        """Test building schema with complex object class requirements."""
        builder = FlextLdifSchemaBuilder()

        result = (
            builder.add_attribute("cn", "Common Name", single_value=True)
            .add_attribute("sn", "Surname", single_value=True)
            .add_attribute("mail", "Email Address")
            .add_attribute("telephoneNumber", "Telephone Number")
            .add_object_class("person", "Person class", ["cn", "sn"])
            .add_object_class(
                "organizationalPerson", "Organizational Person", ["cn", "sn", "mail"]
            )
            .add_object_class(
                "inetOrgPerson",
                "Internet Organizational Person",
                ["cn", "sn", "mail", "telephoneNumber"],
            )
            .build()
        )

        assert result.is_success
        schema = result.value

        # Verify object class requirements
        person_oc = schema.object_classes["person"]
        assert "cn" in person_oc.required_attributes
        assert "sn" in person_oc.required_attributes

        org_person_oc = schema.object_classes["organizationalPerson"]
        assert "cn" in org_person_oc.required_attributes
        assert "sn" in org_person_oc.required_attributes
        assert "mail" in org_person_oc.required_attributes

        inet_org_person_oc = schema.object_classes["inetOrgPerson"]
        assert "cn" in inet_org_person_oc.required_attributes
        assert "sn" in inet_org_person_oc.required_attributes
        assert "mail" in inet_org_person_oc.required_attributes
        assert "telephoneNumber" in inet_org_person_oc.required_attributes
