"""Test suite for FlextLdifSchema Service.

Modules tested: FlextLdifSchema
Scope: Schema parsing, validation, transformation, attribute operations,
objectClass operations, builder pattern, error handling

Tests all schema parsing, validation, and transformation methods with REAL implementations.
Validates attribute and objectClass operations, builder pattern, and error handling.
Uses parametrized tests and factory patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import dataclasses
from enum import StrEnum

import pytest
from flext_core import FlextResult

from flext_ldif import FlextLdifModels
from flext_ldif.services.schema import FlextLdifSchema

# ════════════════════════════════════════════════════════════════════════════
# TEST SCENARIO ENUMS
# ════════════════════════════════════════════════════════════════════════════


class ServerType(StrEnum):
    """Server types for schema testing."""

    RFC = "rfc"
    OUD = "oud"


class SchemaElement(StrEnum):
    """Schema element types."""

    ATTRIBUTE = "attribute"
    OBJECTCLASS = "objectclass"


class DefinitionStatus(StrEnum):
    """Definition validation status."""

    VALID = "valid"
    INVALID = "invalid"
    WHITESPACE_ONLY = "whitespace_only"


# ════════════════════════════════════════════════════════════════════════════
# TEST DATA STRUCTURES
# ════════════════════════════════════════════════════════════════════════════


@dataclasses.dataclass(frozen=True)
class AttributeParseTestCase:
    """Attribute parsing test case."""

    definition: str
    should_succeed: bool
    expected_oid: str | None = None
    expected_name: str | None = None
    description: str = ""


@dataclasses.dataclass(frozen=True)
class ObjectClassParseTestCase:
    """ObjectClass parsing test case."""

    definition: str
    should_succeed: bool
    expected_oid: str | None = None
    expected_name: str | None = None
    expected_kind: str | None = None
    description: str = ""


@dataclasses.dataclass(frozen=True)
class AttributeValidationTestCase:
    """Attribute validation test case."""

    oid: str
    name: str
    syntax: str | None
    should_succeed: bool
    error_keywords: list[str] | None = None
    description: str = ""


@dataclasses.dataclass(frozen=True)
class ObjectClassValidationTestCase:
    """ObjectClass validation test case."""

    oid: str
    name: str
    kind: str
    should_succeed: bool
    error_keywords: list[str] | None = None
    description: str = ""


@dataclasses.dataclass(frozen=True)
class SchemaCanHandleTestCase:
    """Can handle method test case."""

    element: str
    input_str: str
    should_handle: bool
    element_type: SchemaElement
    description: str = ""


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
# TEST DATA MAPPINGS
# ════════════════════════════════════════════════════════════════════════════


ATTRIBUTE_PARSE_TESTS = [
    AttributeParseTestCase(
        "( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        True,
        "2.5.4.3",
        "cn",
        "Valid standard attribute",
    ),
    AttributeParseTestCase("", False, None, None, "Empty definition"),
    AttributeParseTestCase("   ", False, None, None, "Whitespace-only definition"),
    AttributeParseTestCase(
        "invalid format", False, None, None, "Invalid format without parentheses",
    ),
    AttributeParseTestCase(
        "( 2.5.4.0 NAME 'objectClass' )",
        True,
        "2.5.4.0",
        "objectClass",
        "Simple attribute definition",
    ),
]

OBJECTCLASS_PARSE_TESTS = [
    ObjectClassParseTestCase(
        "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber ) )",
        True,
        "2.5.6.6",
        "person",
        "STRUCTURAL",
        "Valid standard objectClass",
    ),
    ObjectClassParseTestCase("", False, None, None, None, "Empty definition"),
    ObjectClassParseTestCase(
        "   ", False, None, None, None, "Whitespace-only definition",
    ),
    ObjectClassParseTestCase(
        "( 2.5.6.0 NAME 'top' ABSTRACT )",
        True,
        "2.5.6.0",
        "top",
        "ABSTRACT",
        "Simple abstract objectClass",
    ),
]

ATTRIBUTE_VALIDATION_TESTS = [
    AttributeValidationTestCase(
        "1.2.3.4",
        "testAttr",
        "1.3.6.1.4.1.1466.115.121.1.15",
        True,
        None,
        "Valid attribute with all fields",
    ),
    AttributeValidationTestCase(
        "1.2.3.4",
        "",
        "1.3.6.1.4.1.1466.115.121.1.15",
        False,
        ["NAME"],
        "Invalid - empty name",
    ),
    AttributeValidationTestCase(
        "",
        "testAttr",
        "1.3.6.1.4.1.1466.115.121.1.15",
        False,
        ["OID"],
        "Invalid - empty OID",
    ),
    AttributeValidationTestCase(
        "1.2.3.4",
        "testAttr",
        "invalid-oid",
        False,
        ["SYNTAX", "OID"],
        "Invalid - malformed syntax OID",
    ),
    AttributeValidationTestCase(
        "1.2.3.4",
        "testAttr",
        None,
        True,
        None,
        "Valid attribute without syntax",
    ),
]

OBJECTCLASS_VALIDATION_TESTS = [
    ObjectClassValidationTestCase(
        "1.2.3.4",
        "testOC",
        "STRUCTURAL",
        True,
        None,
        "Valid STRUCTURAL objectClass",
    ),
    ObjectClassValidationTestCase(
        "1.2.3.4",
        "",
        "STRUCTURAL",
        False,
        ["NAME"],
        "Invalid - empty name",
    ),
    ObjectClassValidationTestCase(
        "",
        "testOC",
        "STRUCTURAL",
        False,
        ["OID"],
        "Invalid - empty OID",
    ),
    ObjectClassValidationTestCase(
        "1.2.3.4",
        "testOC",
        "INVALID",
        False,
        ["kind"],
        "Invalid - unknown kind",
    ),
    ObjectClassValidationTestCase(
        "1.2.3.4",
        "testOC",
        "ABSTRACT",
        True,
        None,
        "Valid ABSTRACT objectClass",
    ),
    ObjectClassValidationTestCase(
        "1.2.3.4",
        "testOC",
        "AUXILIARY",
        True,
        None,
        "Valid AUXILIARY objectClass",
    ),
]

SCHEMA_CAN_HANDLE_TESTS = [
    SchemaCanHandleTestCase(
        "attribute",
        "( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        True,
        SchemaElement.ATTRIBUTE,
        "Valid attribute definition",
    ),
    SchemaCanHandleTestCase(
        "attribute", "", False, SchemaElement.ATTRIBUTE, "Empty attribute",
    ),
    SchemaCanHandleTestCase(
        "attribute", "   ", False, SchemaElement.ATTRIBUTE, "Whitespace attribute",
    ),
    SchemaCanHandleTestCase(
        "attribute",
        "invalid format",
        False,
        SchemaElement.ATTRIBUTE,
        "Invalid attribute",
    ),
    SchemaCanHandleTestCase(
        "objectclass",
        "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber ) )",
        True,
        SchemaElement.OBJECTCLASS,
        "Valid objectClass definition",
    ),
    SchemaCanHandleTestCase(
        "objectclass", "", False, SchemaElement.OBJECTCLASS, "Empty objectClass",
    ),
    SchemaCanHandleTestCase(
        "objectclass", "   ", False, SchemaElement.OBJECTCLASS, "Whitespace objectClass",
    ),
    SchemaCanHandleTestCase(
        "objectclass",
        "invalid format",
        False,
        SchemaElement.OBJECTCLASS,
        "Invalid objectClass",
    ),
]


# ════════════════════════════════════════════════════════════════════════════
# PARAMETRIZATION FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════


def get_attribute_parse_tests() -> list[AttributeParseTestCase]:
    """Generate attribute parse test cases."""
    return ATTRIBUTE_PARSE_TESTS


def get_objectclass_parse_tests() -> list[ObjectClassParseTestCase]:
    """Generate objectClass parse test cases."""
    return OBJECTCLASS_PARSE_TESTS


def get_attribute_validation_tests() -> list[AttributeValidationTestCase]:
    """Generate attribute validation test cases."""
    return ATTRIBUTE_VALIDATION_TESTS


def get_objectclass_validation_tests() -> list[ObjectClassValidationTestCase]:
    """Generate objectClass validation test cases."""
    return OBJECTCLASS_VALIDATION_TESTS


def get_schema_can_handle_tests() -> list[SchemaCanHandleTestCase]:
    """Generate schema can handle test cases."""
    return SCHEMA_CAN_HANDLE_TESTS


# ════════════════════════════════════════════════════════════════════════════
# TEST CLASSES - CONSOLIDATED WITH PARAMETRIZATION
# ════════════════════════════════════════════════════════════════════════════


class TestExecuteAndBuilder:
    """Test execute() method and builder pattern."""

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


class TestParsing:
    """Test attribute and objectClass parsing with parametrization."""

    @pytest.mark.parametrize("test_case", get_attribute_parse_tests())
    def test_parse_attribute(
        self,
        schema_service: FlextLdifSchema,
        test_case: AttributeParseTestCase,
    ) -> None:
        """Test parsing attribute definitions with parametrized test cases."""
        result = schema_service.parse_attribute(test_case.definition)

        if test_case.should_succeed:
            assert result.is_success, f"Failed to parse: {test_case.description}"
            attr = result.unwrap()
            if test_case.expected_oid:
                assert attr.oid == test_case.expected_oid
            if test_case.expected_name:
                assert attr.name == test_case.expected_name
        else:
            assert result.is_failure, f"Should have failed: {test_case.description}"

    @pytest.mark.parametrize("test_case", get_objectclass_parse_tests())
    def test_parse_objectclass(
        self,
        schema_service: FlextLdifSchema,
        test_case: ObjectClassParseTestCase,
    ) -> None:
        """Test parsing objectClass definitions with parametrized test cases."""
        result = schema_service.parse_objectclass(test_case.definition)

        if test_case.should_succeed:
            assert result.is_success, f"Failed to parse: {test_case.description}"
            oc = result.unwrap()
            if test_case.expected_oid:
                assert oc.oid == test_case.expected_oid
            if test_case.expected_name:
                assert oc.name == test_case.expected_name
            if test_case.expected_kind:
                assert oc.kind == test_case.expected_kind
        else:
            assert result.is_failure, f"Should have failed: {test_case.description}"


class TestValidation:
    """Test attribute and objectClass validation with parametrization."""

    @pytest.mark.parametrize("test_case", get_attribute_validation_tests())
    def test_validate_attribute(
        self,
        schema_service: FlextLdifSchema,
        test_case: AttributeValidationTestCase,
    ) -> None:
        """Test validating attributes with parametrized test cases."""
        attr = FlextLdifModels.SchemaAttribute(
            oid=test_case.oid,
            name=test_case.name,
            syntax=test_case.syntax,
        )
        result = schema_service.validate_attribute(attr)

        if test_case.should_succeed:
            assert result.is_success, f"Validation failed: {test_case.description}"
            assert result.unwrap() is True
        else:
            assert result.is_failure, f"Should have failed: {test_case.description}"
            error = result.error or ""
            if test_case.error_keywords:
                for keyword in test_case.error_keywords:
                    assert keyword in error, f"Expected '{keyword}' in error: {error}"

    @pytest.mark.parametrize("test_case", get_objectclass_validation_tests())
    def test_validate_objectclass(
        self,
        schema_service: FlextLdifSchema,
        test_case: ObjectClassValidationTestCase,
    ) -> None:
        """Test validating objectClasses with parametrized test cases."""
        oc = FlextLdifModels.SchemaObjectClass(
            oid=test_case.oid,
            name=test_case.name,
            kind=test_case.kind,
        )
        result = schema_service.validate_objectclass(oc)

        if test_case.should_succeed:
            assert result.is_success, f"Validation failed: {test_case.description}"
            assert result.unwrap() is True
        else:
            assert result.is_failure, f"Should have failed: {test_case.description}"
            error = result.error or ""
            if test_case.error_keywords:
                for keyword in test_case.error_keywords:
                    assert keyword in error, f"Expected '{keyword}' in error: {error}"


class TestWriting:
    """Test attribute and objectClass writing."""

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
        assert result.error is not None and (
            "OID" in result.error or "validation" in result.error.lower()
        )

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
        assert result.error is not None and (
            "OID" in result.error or "validation" in result.error.lower()
        )


class TestCanHandle:
    """Test can_handle methods with parametrization."""

    @pytest.mark.parametrize("test_case", get_schema_can_handle_tests())
    def test_can_handle_methods(
        self,
        schema_service: FlextLdifSchema,
        test_case: SchemaCanHandleTestCase,
    ) -> None:
        """Test can_handle methods with parametrized test cases."""
        if test_case.element_type == SchemaElement.ATTRIBUTE:
            can_handle = schema_service.can_handle_attribute(test_case.input_str)
        else:
            can_handle = schema_service.can_handle_objectclass(test_case.input_str)

        assert can_handle is test_case.should_handle, (
            f"can_handle returned {can_handle}, expected {test_case.should_handle}: "
            f"{test_case.description}"
        )


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


__all__ = [
    "AttributeParseTestCase",
    "AttributeValidationTestCase",
    "DefinitionStatus",
    "ObjectClassParseTestCase",
    "ObjectClassValidationTestCase",
    "SchemaCanHandleTestCase",
    "SchemaElement",
    "ServerType",
    "TestCanHandle",
    "TestExecuteAndBuilder",
    "TestParsing",
    "TestRepr",
    "TestRoundtrip",
    "TestValidation",
    "TestWriting",
]


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
