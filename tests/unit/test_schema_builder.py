"""Test suite for FlextLdifSchemaBuilder.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import FlextLdifModels
from flext_ldif.schema_builder import FlextLdifSchemaBuilder


class TestFlextLdifSchemaBuilder:
    """Test suite for FlextLdifSchemaBuilder class."""

    def test_initialization(self) -> None:
        """Test schema builder initialization."""
        builder = FlextLdifSchemaBuilder()
        assert builder is not None
        assert builder.logger is not None
        assert builder.server_type == "generic"
        assert builder.entry_count == 0
        assert len(builder.attributes) == 0
        assert len(builder.object_classes) == 0

    def test_initialization_with_server_type(self) -> None:
        """Test schema builder initialization with server type."""
        builder = FlextLdifSchemaBuilder(server_type="oid")
        assert builder.server_type == "oid"

    def test_build_empty_schema(self) -> None:
        """Test building empty schema."""
        builder = FlextLdifSchemaBuilder()
        result = builder.build()

        assert result.is_success
        schema_dict = result.unwrap()
        assert schema_dict["attributes"] == {}
        assert schema_dict["object_classes"] == {}
        assert schema_dict["server_type"] == "generic"
        assert schema_dict["entry_count"] == 0

        # Verify it can be converted to model
        schema_model = FlextLdifModels.create_schema_builder_result(schema_dict)
        assert schema_model.is_empty is True

    def test_build_with_attributes(self) -> None:
        """Test building schema with attributes."""
        builder = FlextLdifSchemaBuilder()
        builder.add_attribute("cn", "Common Name", single_value=True)
        builder.add_attribute("sn", "Surname", single_value=True)

        result = builder.build()

        assert result.is_success
        schema_dict = result.unwrap()
        assert len(schema_dict["attributes"]) == 2
        assert "cn" in schema_dict["attributes"]
        assert "sn" in schema_dict["attributes"]

        # Verify model conversion
        schema_model = FlextLdifModels.create_schema_builder_result(schema_dict)
        assert schema_model.total_attributes == 2
        assert schema_model.is_empty is False

    def test_build_with_object_classes(self) -> None:
        """Test building schema with object classes."""
        builder = FlextLdifSchemaBuilder()
        builder.add_object_class(
            "person", "Person class", required_attributes=["cn", "sn"]
        )

        result = builder.build()

        assert result.is_success
        schema_dict = result.unwrap()
        assert len(schema_dict["object_classes"]) == 1
        assert "person" in schema_dict["object_classes"]

        # Verify model conversion
        schema_model = FlextLdifModels.create_schema_builder_result(schema_dict)
        assert schema_model.total_object_classes == 1

    def test_build_standard_person_schema(self) -> None:
        """Test building standard person schema."""
        builder = FlextLdifSchemaBuilder()
        result = builder.build_standard_person_schema()

        assert result.is_success
        schema_dict = result.unwrap()

        # Verify attributes
        assert "cn" in schema_dict["attributes"]
        assert "sn" in schema_dict["attributes"]
        assert "mail" in schema_dict["attributes"]

        # Verify object classes
        assert "person" in schema_dict["object_classes"]
        assert "inetOrgPerson" in schema_dict["object_classes"]

        # Verify server type
        assert schema_dict["server_type"] == "generic"

        # Verify model conversion with computed fields
        schema_model = FlextLdifModels.create_schema_builder_result(schema_dict)
        assert schema_model.total_attributes > 0
        assert schema_model.total_object_classes > 0
        assert schema_model.is_empty is False

    def test_build_standard_group_schema(self) -> None:
        """Test building standard group schema."""
        builder = FlextLdifSchemaBuilder()
        result = builder.build_standard_group_schema()

        assert result.is_success
        schema_dict = result.unwrap()

        # Verify attributes
        assert "cn" in schema_dict["attributes"]
        assert "member" in schema_dict["attributes"]

        # Verify object classes
        assert "groupOfNames" in schema_dict["object_classes"]

        # Verify model conversion
        schema_model = FlextLdifModels.create_schema_builder_result(schema_dict)
        assert schema_model.total_attributes > 0
        assert schema_model.total_object_classes > 0

    def test_fluent_builder_pattern(self) -> None:
        """Test fluent builder pattern with method chaining."""
        builder = FlextLdifSchemaBuilder()
        result = (
            builder.add_attribute("cn", "Common Name")
            .add_attribute("sn", "Surname")
            .add_object_class(
                "person", "Person class", required_attributes=["cn", "sn"]
            )
            .set_server_type("oud")
            .build()
        )

        assert result.is_success
        schema_dict = result.unwrap()
        assert schema_dict["server_type"] == "oud"
        assert len(schema_dict["attributes"]) == 2
        assert len(schema_dict["object_classes"]) == 1

    def test_reset_builder(self) -> None:
        """Test resetting builder to initial state."""
        builder = FlextLdifSchemaBuilder()
        builder.add_attribute("cn", "Common Name")
        builder.add_object_class("person", "Person class")
        builder.set_server_type("oid")

        # Reset builder
        builder.reset()

        # Verify reset state
        assert builder.server_type == "generic"
        assert builder.entry_count == 0
        assert len(builder.attributes) == 0
        assert len(builder.object_classes) == 0

    def test_build_uses_model_internally(self) -> None:
        """Test that build() uses SchemaBuilderResult model internally."""
        builder = FlextLdifSchemaBuilder(server_type="openldap")
        builder.add_attribute(
            "cn", "Common Name", syntax="1.3.6.1.4.1.1466.115.121.1.15"
        )
        builder.add_object_class("person", "Person", required_attributes=["cn"])

        result = builder.build()

        assert result.is_success
        schema_dict = result.unwrap()

        # Convert to model - should work seamlessly
        schema_model = FlextLdifModels.create_schema_builder_result(schema_dict)

        # Verify computed fields work
        assert schema_model.total_attributes == 1
        assert schema_model.total_object_classes == 1
        assert schema_model.is_empty is False

        # Verify schema_summary computed field
        summary = schema_model.schema_summary
        assert summary["attributes"] == 1
        assert summary["object_classes"] == 1
        assert summary["server_type"] == "openldap"
        assert summary["entry_count"] == 0

    def test_add_attribute_with_kwargs(self) -> None:
        """Test adding attribute with additional kwargs."""
        builder = FlextLdifSchemaBuilder()
        builder.add_attribute(
            "cn",
            "Common Name",
            single_value=True,
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            equality="caseIgnoreMatch",
        )

        result = builder.build()
        assert result.is_success
        schema_dict = result.unwrap()

        cn_attr = schema_dict["attributes"]["cn"]
        assert cn_attr["name"] == "cn"
        assert cn_attr["description"] == "Common Name"
        assert cn_attr["single_value"] is True
        assert cn_attr["syntax"] == "1.3.6.1.4.1.1466.115.121.1.15"
        assert cn_attr["equality"] == "caseIgnoreMatch"

    def test_add_object_class_with_superior(self) -> None:
        """Test adding object class with superior."""
        builder = FlextLdifSchemaBuilder()
        builder.add_object_class(
            "inetOrgPerson",
            "Internet Organizational Person",
            required_attributes=["cn"],
            superior="person",
            structural=True,
        )

        result = builder.build()
        assert result.is_success
        schema_dict = result.unwrap()

        oc = schema_dict["object_classes"]["inetOrgPerson"]
        assert oc["name"] == "inetOrgPerson"
        assert oc["superior"] == "person"
        assert oc["structural"] is True

    def test_execute_method_returns_failure(self) -> None:
        """Test that execute() method returns failure message."""
        builder = FlextLdifSchemaBuilder()
        result = builder.execute()

        assert result.is_failure
        assert result.error is not None
        assert "Use build methods instead" in result.error
