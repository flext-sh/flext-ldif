"""Test Schema Builder Pattern Implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from flext_ldif.models import FlextLdifModels
from flext_ldif.schema.builder import FlextLdifSchemaBuilder


class TestSchemaBuilderPattern:
    """Test schema builder fluent interface and builder pattern."""

    def test_builder_initialization(self) -> None:
        """Test schema builder initialization."""
        builder = FlextLdifSchemaBuilder()
        assert builder is not None
        assert isinstance(builder._attributes, dict)
        assert isinstance(builder._object_classes, dict)
        assert builder._server_type == "generic"
        assert builder._entry_count == 0

    def test_add_single_value_attribute(self) -> None:
        """Test adding single-value attribute."""
        builder = FlextLdifSchemaBuilder()
        result = builder.add_attribute("cn", "Common Name", single_value=True)

        assert result is builder
        assert "cn" in builder._attributes
        attr = builder._attributes["cn"]
        assert attr.name == "cn"
        assert attr.description == "Common Name"
        assert attr.single_value is True

    def test_add_multi_value_attribute(self) -> None:
        """Test adding multi-value attribute."""
        builder = FlextLdifSchemaBuilder()
        result = builder.add_attribute("mail", "Email Address", single_value=False)

        assert result is builder
        assert "mail" in builder._attributes
        attr = builder._attributes["mail"]
        assert attr.single_value is False

    def test_add_attribute_default_multi_value(self) -> None:
        """Test adding attribute with default multi-value."""
        builder = FlextLdifSchemaBuilder()
        result = builder.add_attribute("telephoneNumber", "Phone Number")

        assert result is builder
        assert "telephoneNumber" in builder._attributes
        attr = builder._attributes["telephoneNumber"]
        assert attr.single_value is False

    def test_add_object_class(self) -> None:
        """Test adding object class."""
        builder = FlextLdifSchemaBuilder()
        result = builder.add_object_class("person", "Person object class", ["cn", "sn"])

        assert result is builder
        assert "person" in builder._object_classes
        oc = builder._object_classes["person"]
        assert oc.name == "person"
        assert oc.description == "Person object class"
        assert set(oc.required_attributes) == {"cn", "sn"}

    def test_set_server_type(self) -> None:
        """Test setting server type."""
        builder = FlextLdifSchemaBuilder()
        result = builder.set_server_type("openldap")

        assert result is builder
        assert builder._server_type == "openldap"

    def test_fluent_interface_chaining(self) -> None:
        """Test fluent interface method chaining."""
        builder = FlextLdifSchemaBuilder()

        result = (
            builder.add_attribute("cn", "Common Name", single_value=True)
            .add_attribute("sn", "Surname", single_value=True)
            .add_object_class("person", "Person class", ["cn", "sn"])
            .set_server_type("openldap")
        )

        assert result is builder
        assert len(builder._attributes) == 2
        assert len(builder._object_classes) == 1
        assert builder._server_type == "openldap"

    def test_build_method(self) -> None:
        """Test build method returns schema."""
        builder = FlextLdifSchemaBuilder()

        builder.add_attribute("cn", "Common Name", single_value=True)
        builder.add_object_class("top", "Top class", ["objectClass"])
        builder.set_server_type("generic")

        result = builder.build()

        assert result.is_success
        schema = result.value
        assert isinstance(schema, FlextLdifModels.SchemaDiscoveryResult)
        assert "cn" in schema.attributes
        assert "top" in schema.object_classes
        assert schema.server_type == "generic"

    def test_reset_method(self) -> None:
        """Test reset method clears builder state."""
        builder = FlextLdifSchemaBuilder()

        builder.add_attribute("cn", "Common Name")
        builder.add_object_class("person", "Person", ["cn"])
        builder.set_server_type("openldap")

        assert len(builder._attributes) > 0
        assert len(builder._object_classes) > 0
        assert builder._server_type != "generic"

        result = builder.reset()

        assert result is builder
        assert len(builder._attributes) == 0
        assert len(builder._object_classes) == 0
        assert builder._server_type == "generic"
        assert builder._entry_count == 0

    def test_build_standard_person_schema(self) -> None:
        """Test building standard person schema."""
        builder = FlextLdifSchemaBuilder()
        result = builder.build_standard_person_schema()

        assert result.is_success
        schema = result.value

        assert "cn" in schema.attributes
        assert "sn" in schema.attributes
        assert "uid" in schema.attributes
        assert "mail" in schema.attributes
        assert "telephoneNumber" in schema.attributes

        assert "top" in schema.object_classes
        assert "person" in schema.object_classes
        assert "organizationalPerson" in schema.object_classes
        assert "inetOrgPerson" in schema.object_classes

        assert schema.server_type == "generic"

    def test_build_standard_group_schema(self) -> None:
        """Test building standard group schema."""
        builder = FlextLdifSchemaBuilder()
        result = builder.build_standard_group_schema()

        assert result.is_success
        schema = result.value

        assert "cn" in schema.attributes
        assert "member" in schema.attributes
        assert "uniqueMember" in schema.attributes

        assert "top" in schema.object_classes
        assert "groupOfNames" in schema.object_classes
        assert "groupOfUniqueNames" in schema.object_classes

        assert schema.server_type == "generic"

    def test_execute_returns_person_schema(self) -> None:
        """Test execute method returns person schema."""
        builder = FlextLdifSchemaBuilder()
        result = builder.execute()

        assert result.is_success
        schema = result.value

        assert "cn" in schema.attributes
        assert "person" in schema.object_classes

    def test_person_schema_attributes(self) -> None:
        """Test person schema attribute properties."""
        builder = FlextLdifSchemaBuilder()
        result = builder.build_standard_person_schema()

        assert result.is_success
        schema = result.value

        cn_attr = schema.attributes["cn"]
        assert cn_attr.single_value is True

        sn_attr = schema.attributes["sn"]
        assert sn_attr.single_value is True

        mail_attr = schema.attributes["mail"]
        assert mail_attr.single_value is False

    def test_person_schema_object_classes(self) -> None:
        """Test person schema object class properties."""
        builder = FlextLdifSchemaBuilder()
        result = builder.build_standard_person_schema()

        assert result.is_success
        schema = result.value

        top_oc = schema.object_classes["top"]
        assert "objectClass" in top_oc.required_attributes

        person_oc = schema.object_classes["person"]
        assert "cn" in person_oc.required_attributes
        assert "sn" in person_oc.required_attributes

    def test_group_schema_attributes(self) -> None:
        """Test group schema attribute properties."""
        builder = FlextLdifSchemaBuilder()
        result = builder.build_standard_group_schema()

        assert result.is_success
        schema = result.value

        cn_attr = schema.attributes["cn"]
        assert cn_attr.single_value is True
        assert cn_attr.description == "Common Name"

        member_attr = schema.attributes["member"]
        assert member_attr.single_value is False

    def test_group_schema_object_classes(self) -> None:
        """Test group schema object class properties."""
        builder = FlextLdifSchemaBuilder()
        result = builder.build_standard_group_schema()

        assert result.is_success
        schema = result.value

        group_oc = schema.object_classes["groupOfNames"]
        assert "cn" in group_oc.required_attributes
        assert "member" in group_oc.required_attributes

        unique_group_oc = schema.object_classes["groupOfUniqueNames"]
        assert "uniqueMember" in unique_group_oc.required_attributes

    def test_custom_schema_workflow(self) -> None:
        """Test custom schema building workflow."""
        builder = FlextLdifSchemaBuilder()

        result = (
            builder.reset()
            .add_attribute("customId", "Custom Identifier", single_value=True)
            .add_attribute("customTags", "Custom Tags", single_value=False)
            .add_object_class("customEntry", "Custom Entry Type", ["customId"])
            .set_server_type("custom")
            .build()
        )

        assert result.is_success
        schema = result.value

        assert "customId" in schema.attributes
        assert schema.attributes["customId"].single_value is True

        assert "customTags" in schema.attributes
        assert schema.attributes["customTags"].single_value is False

        assert "customEntry" in schema.object_classes
        assert schema.server_type == "custom"

    def test_reset_and_rebuild(self) -> None:
        """Test resetting builder and building new schema."""
        builder = FlextLdifSchemaBuilder()

        first_result = builder.build_standard_person_schema()
        assert first_result.is_success
        assert "person" in first_result.value.object_classes

        second_result = builder.build_standard_group_schema()
        assert second_result.is_success
        assert "groupOfNames" in second_result.value.object_classes
        assert "person" not in second_result.value.object_classes

    def test_multiple_schemas_independent(self) -> None:
        """Test that multiple schemas can be built independently."""
        builder1 = FlextLdifSchemaBuilder()
        builder2 = FlextLdifSchemaBuilder()

        schema1 = builder1.build_standard_person_schema()
        schema2 = builder2.build_standard_group_schema()

        assert schema1.is_success
        assert schema2.is_success
        assert "person" in schema1.value.object_classes
        assert "groupOfNames" in schema2.value.object_classes
        assert "person" not in schema2.value.object_classes


class TestSchemaBuilderEdgeCases:
    """Test edge cases for schema builder."""

    def test_empty_schema_build(self) -> None:
        """Test building empty schema."""
        builder = FlextLdifSchemaBuilder()
        builder.reset()
        result = builder.build()

        assert result.is_success
        schema = result.value
        assert len(schema.attributes) == 0
        assert len(schema.object_classes) == 0

    def test_attribute_overwrite(self) -> None:
        """Test that adding same attribute twice overwrites."""
        builder = FlextLdifSchemaBuilder()

        builder.add_attribute("cn", "First Description", single_value=True)
        builder.add_attribute("cn", "Second Description", single_value=False)

        assert len(builder._attributes) == 1
        attr = builder._attributes["cn"]
        assert attr.description == "Second Description"
        assert attr.single_value is False

    def test_object_class_overwrite(self) -> None:
        """Test that adding same object class twice overwrites."""
        builder = FlextLdifSchemaBuilder()

        builder.add_object_class("person", "First", ["cn"])
        builder.add_object_class("person", "Second", ["cn", "sn"])

        assert len(builder._object_classes) == 1
        oc = builder._object_classes["person"]
        assert oc.description == "Second"
        assert "sn" in oc.required_attributes
