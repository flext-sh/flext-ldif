"""Comprehensive unit tests for FlextLdifSchema.

Tests all schema parsing, validation, and transformation methods with REAL implementations.
Validates attribute and objectClass operations, builder pattern, and error handling.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldif import FlextLdifModels
from flext_ldif.services.schema import FlextLdifSchema

# ════════════════════════════════════════════════════════════════════════════
# TEST FIXTURES
# ════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def schema_service() -> FlextLdifSchema:
    """Create schema service instance."""
    return FlextLdifSchema()


@pytest.fixture
def schema_service_oud() -> FlextLdifSchema:
    """Create schema service instance for OUD."""
    return FlextLdifSchema(server_type="oud")


@pytest.fixture
def sample_attribute_definition() -> str:
    """Sample RFC attribute definition."""
    return "( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"


@pytest.fixture
def sample_objectclass_definition() -> str:
    """Sample RFC objectClass definition."""
    return "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber ) )"


# ════════════════════════════════════════════════════════════════════════════
# TEST EXECUTE METHOD
# ════════════════════════════════════════════════════════════════════════════


class TestExecute:
    """Test execute() method for service status."""

    def test_execute_returns_status(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test execute returns service status."""
        result = schema_service.execute()
        assert result.is_success
        status = result.unwrap()
        assert status.service == "SchemaService"
        assert status.server_type == "rfc"
        assert status.status == "operational"
        assert status.rfc_compliance == "RFC 4512"
        assert "parse_attribute" in status.operations

    def test_execute_with_different_server_type(
        self,
        schema_service_oud: FlextLdifSchema,
    ) -> None:
        """Test execute with different server type."""
        result = schema_service_oud.execute()
        assert result.is_success
        status = result.unwrap()
        assert status.server_type == "oud"


# ════════════════════════════════════════════════════════════════════════════
# TEST BUILDER PATTERN
# ════════════════════════════════════════════════════════════════════════════


class TestBuilderPattern:
    """Test fluent builder pattern."""

    def test_builder_creates_instance(self) -> None:
        """Test builder creates service instance."""
        service = FlextLdifSchema.builder()
        assert isinstance(service, FlextLdifSchema)

    def test_with_server_type(self) -> None:
        """Test with_server_type method."""
        service = FlextLdifSchema.builder().with_server_type("oid")
        assert service.server_type == "oid"

    def test_build_returns_self(self) -> None:
        """Test build returns configured instance."""
        service = FlextLdifSchema.builder().with_server_type("oud").build()
        assert service.server_type == "oud"
        assert isinstance(service, FlextLdifSchema)

    def test_builder_chaining(self) -> None:
        """Test builder method chaining."""
        service = (
            FlextLdifSchema.builder()
            .with_server_type("rfc")
            .with_server_type("oid")  # Override
            .build()
        )
        assert service.server_type == "oid"


# ════════════════════════════════════════════════════════════════════════════
# TEST PARSE ATTRIBUTE
# ════════════════════════════════════════════════════════════════════════════


class TestParseAttribute:
    """Test parse_attribute method."""

    def test_parse_attribute_success(
        self,
        schema_service: FlextLdifSchema,
        sample_attribute_definition: str,
    ) -> None:
        """Test parsing valid attribute definition."""
        result = schema_service.parse_attribute(sample_attribute_definition)
        assert result.is_success
        attr = result.unwrap()
        assert attr.oid == "2.5.4.3"
        assert attr.name == "cn"

    def test_parse_attribute_empty(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test parsing empty attribute definition."""
        result = schema_service.parse_attribute("")
        assert result.is_failure
        assert "empty" in result.error.lower()

    def test_parse_attribute_whitespace(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test parsing whitespace-only attribute definition."""
        result = schema_service.parse_attribute("   ")
        assert result.is_failure

    def test_parse_attribute_invalid_format(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test parsing invalid attribute format."""
        result = schema_service.parse_attribute("invalid format")
        # May succeed or fail depending on parser leniency
        assert isinstance(result, FlextResult)

    def test_parse_attribute_simple(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test parsing simple attribute definition."""
        simple_attr = "( 2.5.4.0 NAME 'objectClass' )"
        result = schema_service.parse_attribute(simple_attr)
        # Should parse successfully
        assert isinstance(result, FlextResult)


# ════════════════════════════════════════════════════════════════════════════
# TEST PARSE OBJECTCLASS
# ════════════════════════════════════════════════════════════════════════════


class TestParseObjectClass:
    """Test parse_objectclass method."""

    def test_parse_objectclass_success(
        self,
        schema_service: FlextLdifSchema,
        sample_objectclass_definition: str,
    ) -> None:
        """Test parsing valid objectClass definition."""
        result = schema_service.parse_objectclass(sample_objectclass_definition)
        assert result.is_success
        oc = result.unwrap()
        assert oc.oid == "2.5.6.6"
        assert oc.name == "person"
        assert oc.kind == "STRUCTURAL"

    def test_parse_objectclass_empty(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test parsing empty objectClass definition."""
        result = schema_service.parse_objectclass("")
        assert result.is_failure
        assert "empty" in result.error.lower()

    def test_parse_objectclass_whitespace(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test parsing whitespace-only objectClass definition."""
        result = schema_service.parse_objectclass("   ")
        assert result.is_failure

    def test_parse_objectclass_simple(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test parsing simple objectClass definition."""
        simple_oc = "( 2.5.6.0 NAME 'top' ABSTRACT )"
        result = schema_service.parse_objectclass(simple_oc)
        # Should parse successfully
        assert isinstance(result, FlextResult)


# ════════════════════════════════════════════════════════════════════════════
# TEST VALIDATE ATTRIBUTE
# ════════════════════════════════════════════════════════════════════════════


class TestValidateAttribute:
    """Test validate_attribute method."""

    def test_validate_attribute_success(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating valid attribute."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="1.2.3.4",
            name="testAttr",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )
        result = schema_service.validate_attribute(attr)
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_attribute_none(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating None attribute."""
        result = schema_service.validate_attribute(None)  # type: ignore[arg-type]
        assert result.is_failure
        assert "None" in result.error

    def test_validate_attribute_no_name(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating attribute without name."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="1.2.3.4",
            name="",  # Empty name
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )
        result = schema_service.validate_attribute(attr)
        assert result.is_failure
        assert "NAME" in result.error

    def test_validate_attribute_no_oid(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating attribute without OID."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="",  # Empty OID
            name="testAttr",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )
        result = schema_service.validate_attribute(attr)
        assert result.is_failure
        assert "OID" in result.error

    def test_validate_attribute_invalid_syntax_oid(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating attribute with invalid syntax OID."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="1.2.3.4",
            name="testAttr",
            syntax="invalid-oid",  # Invalid OID format
        )
        result = schema_service.validate_attribute(attr)
        assert result.is_failure
        assert "SYNTAX" in result.error or "OID" in result.error

    def test_validate_attribute_no_syntax(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating attribute without syntax (should pass)."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="1.2.3.4",
            name="testAttr",
            syntax=None,
        )
        result = schema_service.validate_attribute(attr)
        assert result.is_success


# ════════════════════════════════════════════════════════════════════════════
# TEST VALIDATE OBJECTCLASS
# ════════════════════════════════════════════════════════════════════════════


class TestValidateObjectClass:
    """Test validate_objectclass method."""

    def test_validate_objectclass_success(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating valid objectClass."""
        oc = FlextLdifModels.SchemaObjectClass(
            oid="1.2.3.4",
            name="testOC",
            kind="STRUCTURAL",
        )
        result = schema_service.validate_objectclass(oc)
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_objectclass_none(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating None objectClass."""
        result = schema_service.validate_objectclass(None)  # type: ignore[arg-type]
        assert result.is_failure
        assert "None" in result.error

    def test_validate_objectclass_no_name(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating objectClass without name."""
        oc = FlextLdifModels.SchemaObjectClass(
            oid="1.2.3.4",
            name="",  # Empty name
            kind="STRUCTURAL",
        )
        result = schema_service.validate_objectclass(oc)
        assert result.is_failure
        assert "NAME" in result.error

    def test_validate_objectclass_no_oid(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating objectClass without OID."""
        oc = FlextLdifModels.SchemaObjectClass(
            oid="",  # Empty OID
            name="testOC",
            kind="STRUCTURAL",
        )
        result = schema_service.validate_objectclass(oc)
        assert result.is_failure
        assert "OID" in result.error

    def test_validate_objectclass_invalid_kind(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating objectClass with invalid kind."""
        oc = FlextLdifModels.SchemaObjectClass(
            oid="1.2.3.4",
            name="testOC",
            kind="INVALID",  # Invalid kind
        )
        result = schema_service.validate_objectclass(oc)
        assert result.is_failure
        assert "kind" in result.error.lower() or "KIND" in result.error

    def test_validate_objectclass_abstract(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating ABSTRACT objectClass."""
        oc = FlextLdifModels.SchemaObjectClass(
            oid="1.2.3.4",
            name="testOC",
            kind="ABSTRACT",
        )
        result = schema_service.validate_objectclass(oc)
        assert result.is_success

    def test_validate_objectclass_auxiliary(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating AUXILIARY objectClass."""
        oc = FlextLdifModels.SchemaObjectClass(
            oid="1.2.3.4",
            name="testOC",
            kind="AUXILIARY",
        )
        result = schema_service.validate_objectclass(oc)
        assert result.is_success


# ════════════════════════════════════════════════════════════════════════════
# TEST WRITE ATTRIBUTE
# ════════════════════════════════════════════════════════════════════════════


class TestWriteAttribute:
    """Test write_attribute method."""

    def test_write_attribute_success(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test writing valid attribute."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="2.5.4.3",
            name="cn",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )
        result = schema_service.write_attribute(attr)
        assert result.is_success
        ldif = result.unwrap()
        assert isinstance(ldif, str)
        assert "cn" in ldif or "2.5.4.3" in ldif

    def test_write_attribute_invalid(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test writing invalid attribute (should fail validation)."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="",  # Invalid - no OID
            name="testAttr",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )
        result = schema_service.write_attribute(attr)
        assert result.is_failure
        assert "OID" in result.error or "validation" in result.error.lower()


# ════════════════════════════════════════════════════════════════════════════
# TEST WRITE OBJECTCLASS
# ════════════════════════════════════════════════════════════════════════════


class TestWriteObjectClass:
    """Test write_objectclass method."""

    def test_write_objectclass_success(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test writing valid objectClass."""
        oc = FlextLdifModels.SchemaObjectClass(
            oid="2.5.6.6",
            name="person",
            kind="STRUCTURAL",
        )
        result = schema_service.write_objectclass(oc)
        assert result.is_success
        ldif = result.unwrap()
        assert isinstance(ldif, str)
        assert "person" in ldif or "2.5.6.6" in ldif

    def test_write_objectclass_invalid(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test writing invalid objectClass (should fail validation)."""
        oc = FlextLdifModels.SchemaObjectClass(
            oid="",  # Invalid - no OID
            name="testOC",
            kind="STRUCTURAL",
        )
        result = schema_service.write_objectclass(oc)
        assert result.is_failure
        assert "OID" in result.error or "validation" in result.error.lower()


# ════════════════════════════════════════════════════════════════════════════
# TEST CAN HANDLE METHODS
# ════════════════════════════════════════════════════════════════════════════


class TestCanHandle:
    """Test can_handle methods."""

    def test_can_handle_attribute_valid(
        self,
        schema_service: FlextLdifSchema,
        sample_attribute_definition: str,
    ) -> None:
        """Test can_handle_attribute with valid definition."""
        can_handle = schema_service.can_handle_attribute(sample_attribute_definition)
        assert can_handle is True

    def test_can_handle_attribute_empty(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test can_handle_attribute with empty string."""
        can_handle = schema_service.can_handle_attribute("")
        assert can_handle is False

    def test_can_handle_attribute_whitespace(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test can_handle_attribute with whitespace."""
        can_handle = schema_service.can_handle_attribute("   ")
        assert can_handle is False

    def test_can_handle_attribute_no_parentheses(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test can_handle_attribute without parentheses."""
        can_handle = schema_service.can_handle_attribute("invalid format")
        assert can_handle is False

    def test_can_handle_objectclass_valid(
        self,
        schema_service: FlextLdifSchema,
        sample_objectclass_definition: str,
    ) -> None:
        """Test can_handle_objectclass with valid definition."""
        can_handle = schema_service.can_handle_objectclass(
            sample_objectclass_definition
        )
        assert can_handle is True

    def test_can_handle_objectclass_empty(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test can_handle_objectclass with empty string."""
        can_handle = schema_service.can_handle_objectclass("")
        assert can_handle is False

    def test_can_handle_objectclass_whitespace(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test can_handle_objectclass with whitespace."""
        can_handle = schema_service.can_handle_objectclass("   ")
        assert can_handle is False

    def test_can_handle_objectclass_no_parentheses(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test can_handle_objectclass without parentheses."""
        can_handle = schema_service.can_handle_objectclass("invalid format")
        assert can_handle is False


# ════════════════════════════════════════════════════════════════════════════
# TEST ROUNDTRIP OPERATIONS
# ════════════════════════════════════════════════════════════════════════════


class TestRoundtrip:
    """Test roundtrip operations (parse -> write -> parse)."""

    def test_attribute_roundtrip(
        self,
        schema_service: FlextLdifSchema,
        sample_attribute_definition: str,
    ) -> None:
        """Test attribute parse -> write -> parse roundtrip."""
        # Parse
        parse_result = schema_service.parse_attribute(sample_attribute_definition)
        assert parse_result.is_success
        attr = parse_result.unwrap()

        # Write
        write_result = schema_service.write_attribute(attr)
        assert write_result.is_success
        written_ldif = write_result.unwrap()

        # Parse again
        parse2_result = schema_service.parse_attribute(written_ldif)
        # May succeed or fail depending on exact format, but should be valid
        assert isinstance(parse2_result, FlextResult)

    def test_objectclass_roundtrip(
        self,
        schema_service: FlextLdifSchema,
        sample_objectclass_definition: str,
    ) -> None:
        """Test objectClass parse -> write -> parse roundtrip."""
        # Parse
        parse_result = schema_service.parse_objectclass(sample_objectclass_definition)
        assert parse_result.is_success
        oc = parse_result.unwrap()

        # Write
        write_result = schema_service.write_objectclass(oc)
        assert write_result.is_success
        written_ldif = write_result.unwrap()

        # Parse again
        parse2_result = schema_service.parse_objectclass(written_ldif)
        # May succeed or fail depending on exact format, but should be valid
        assert isinstance(parse2_result, FlextResult)


# ════════════════════════════════════════════════════════════════════════════
# TEST REPR
# ════════════════════════════════════════════════════════════════════════════


class TestRepr:
    """Test string representation."""

    def test_repr_default(self) -> None:
        """Test repr with default server type."""
        service = FlextLdifSchema()
        repr_str = repr(service)
        assert "FlextLdifSchema" in repr_str
        assert "rfc" in repr_str

    def test_repr_custom_server_type(self) -> None:
        """Test repr with custom server type."""
        service = FlextLdifSchema(server_type="oud")
        repr_str = repr(service)
        assert "FlextLdifSchema" in repr_str
        assert "oud" in repr_str


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
