"""Tests for LDIF schema service.

This module tests the FlextLdifSchema service functionality including attribute
definition parsing, objectClass definition parsing, syntax validation, and
server-specific schema quirk handling for different LDAP implementations.
"""

from __future__ import annotations

from typing import cast

import pytest

from flext_ldif.models import m
from flext_ldif.services.schema import FlextLdifSchema
from tests import c, s

# ════════════════════════════════════════════════════════════════════════════
# TEST FIXTURES
# ════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def schema_service() -> FlextLdifSchema:
    """Create FlextLdifSchema instance with default RFC server type."""
    return FlextLdifSchema()


@pytest.fixture
def schema_service_oud() -> FlextLdifSchema:
    """Create FlextLdifSchema instance with OUD server type."""
    return FlextLdifSchema(server_type="oud")


@pytest.fixture
def simple_attribute_definition() -> str:
    """Simple RFC attribute definition."""
    return "( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"


@pytest.fixture
def simple_objectclass_definition() -> str:
    """Simple RFC objectClass definition."""
    return "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber $ seeAlso $ description ) )"


@pytest.fixture
def complex_attribute_definition() -> str:
    """Complex attribute definition with multiple options."""
    return "( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )"


@pytest.fixture
def complex_objectclass_definition() -> str:
    """Complex objectClass definition with SUP and MAY."""
    return "( 2.5.6.2 NAME 'country' SUP top STRUCTURAL MUST c MAY ( searchGuide $ description ) )"


# ════════════════════════════════════════════════════════════════════════════
# TEST EXECUTE (HEALTH CHECK)
# ════════════════════════════════════════════════════════════════════════════


class TestsFlextLdifSchemaServiceExecute(s):
    """Test execute() method (health check)."""

    def test_execute_returns_status(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test execute() returns service status."""
        result = schema_service.execute()
        assert result.is_success
        status = result.value
        assert isinstance(status, m.Ldif.LdifResults.SchemaServiceStatus)
        assert status.service == "SchemaService"
        assert status.status == "operational"
        assert status.rfc_compliance == "RFC 4512"
        assert "parse_attribute" in status.operations

    def test_execute_with_different_server_type(
        self,
        schema_service_oud: FlextLdifSchema,
    ) -> None:
        """Test execute() with different server type."""
        result = schema_service_oud.execute()
        assert result.is_success
        status = result.value
        assert status.server_type == "oud"


# ════════════════════════════════════════════════════════════════════════════
# TEST FLUENT BUILDER PATTERN
# ════════════════════════════════════════════════════════════════════════════


class TestSchemaServiceBuilder:
    """Test fluent builder pattern methods."""

    def test_builder_creates_instance(self) -> None:
        """Test builder() creates new instance."""
        service = FlextLdifSchema.builder()
        assert isinstance(service, FlextLdifSchema)
        assert service.server_type == "rfc"

    def test_with_server_type_chains(self) -> None:
        """Test with_server_type() returns self for chaining."""
        service = FlextLdifSchema.builder()
        chained = service.with_server_type("oud")
        assert chained is service
        assert service.server_type == "oud"

    def test_build_returns_self(self) -> None:
        """Test build() returns configured instance."""
        service = FlextLdifSchema.builder().with_server_type("oid").build()
        assert isinstance(service, FlextLdifSchema)
        assert service.server_type == "oid"

    def test_fluent_builder_complete_chain(self) -> None:
        """Test complete fluent builder chain."""
        service = FlextLdifSchema.builder().with_server_type("oud").build()
        assert service.server_type == "oud"
        result = service.execute()
        assert result.is_success
        status = result.value
        assert status.server_type == "oud"


# ════════════════════════════════════════════════════════════════════════════
# TEST PARSE_ATTRIBUTE
# ════════════════════════════════════════════════════════════════════════════


class TestSchemaServiceParseAttribute:
    """Test parse_attribute() method."""

    def test_parse_simple_attribute(
        self,
        schema_service: FlextLdifSchema,
        simple_attribute_definition: str,
    ) -> None:
        """Test parsing simple attribute definition."""
        result = schema_service.parse_attribute(simple_attribute_definition)
        assert result.is_success
        attr = result.value
        assert isinstance(attr, m.Ldif.SchemaAttribute)
        assert attr.oid == "2.5.4.3"
        assert attr.name == "cn"

    def test_parse_complex_attribute(
        self,
        schema_service: FlextLdifSchema,
        complex_attribute_definition: str,
    ) -> None:
        """Test parsing complex attribute definition."""
        result = schema_service.parse_attribute(complex_attribute_definition)
        assert result.is_success
        attr = result.value
        assert isinstance(attr, m.Ldif.SchemaAttribute)
        assert attr.oid == "2.5.4.0"
        assert attr.name == "objectClass"

    def test_parse_attribute_empty_string(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test parsing empty attribute definition."""
        result = schema_service.parse_attribute("")
        assert result.is_failure
        assert result.error is not None
        assert "empty" in result.error.lower()

    def test_parse_attribute_whitespace_only(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test parsing whitespace-only attribute definition."""
        result = schema_service.parse_attribute("   ")
        assert result.is_failure
        assert result.error is not None
        assert "empty" in result.error.lower()

    def test_parse_attribute_invalid_format(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test parsing invalid attribute definition."""
        result = schema_service.parse_attribute("invalid format")
        assert result.is_failure


# ════════════════════════════════════════════════════════════════════════════
# TEST PARSE_OBJECTCLASS
# ════════════════════════════════════════════════════════════════════════════


class TestSchemaServiceParseObjectClass:
    """Test parse_objectclass() method."""

    def test_parse_simple_objectclass(
        self,
        schema_service: FlextLdifSchema,
        simple_objectclass_definition: str,
    ) -> None:
        """Test parsing simple objectClass definition."""
        result = schema_service.parse_objectclass(simple_objectclass_definition)
        assert result.is_success
        oc = result.value
        assert isinstance(oc, m.Ldif.SchemaObjectClass)
        assert oc.oid == "2.5.6.6"
        assert oc.name == "person"
        assert oc.kind == "STRUCTURAL"

    def test_parse_complex_objectclass(
        self,
        schema_service: FlextLdifSchema,
        complex_objectclass_definition: str,
    ) -> None:
        """Test parsing complex objectClass definition."""
        result = schema_service.parse_objectclass(complex_objectclass_definition)
        assert result.is_success
        oc = result.value
        assert isinstance(oc, m.Ldif.SchemaObjectClass)
        assert oc.oid == "2.5.6.2"
        assert oc.name == "country"
        assert oc.kind == "STRUCTURAL"

    def test_parse_objectclass_empty_string(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test parsing empty objectClass definition."""
        result = schema_service.parse_objectclass("")
        assert result.is_failure
        assert result.error is not None
        assert "empty" in result.error.lower()

    def test_parse_objectclass_whitespace_only(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test parsing whitespace-only objectClass definition."""
        result = schema_service.parse_objectclass("   ")
        assert result.is_failure
        assert result.error is not None
        assert "empty" in result.error.lower()

    def test_parse_objectclass_invalid_format(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test parsing invalid objectClass definition."""
        result = schema_service.parse_objectclass("invalid format")
        assert result.is_failure


# ════════════════════════════════════════════════════════════════════════════
# TEST VALIDATE_ATTRIBUTE
# ════════════════════════════════════════════════════════════════════════════


class TestSchemaServiceValidateAttribute:
    """Test validate_attribute() method."""

    def test_validate_valid_attribute(
        self,
        schema_service: FlextLdifSchema,
        simple_attribute_definition: str,
    ) -> None:
        """Test validating valid attribute."""
        parse_result = schema_service.parse_attribute(simple_attribute_definition)
        assert parse_result.is_success
        attr = parse_result.value

        result = schema_service.validate_attribute(attr)
        assert result.is_success
        assert result.value is True

    def test_validate_attribute_without_name(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating attribute without name."""
        attr = m.Ldif.SchemaAttribute(
            oid="1.2.3.4",
            name="",  # Empty name
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )
        result = schema_service.validate_attribute(attr)
        assert result.is_failure
        assert result.error is not None
        assert "name" in result.error.lower()

    def test_validate_attribute_without_oid(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating attribute without OID."""
        attr = m.Ldif.SchemaAttribute(
            oid="",  # Empty OID
            name="testAttr",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )
        result = schema_service.validate_attribute(attr)
        assert result.is_failure
        assert result.error is not None
        assert "oid" in result.error.lower()

    def test_validate_attribute_with_invalid_syntax_oid(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating attribute with invalid syntax OID."""
        attr = m.Ldif.SchemaAttribute(
            oid="1.2.3.4",
            name="testAttr",
            syntax="invalid-oid",  # Invalid OID format
        )
        result = schema_service.validate_attribute(attr)
        assert result.is_failure
        assert result.error is not None
        assert "syntax" in result.error.lower()

    def test_validate_attribute_none(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating None attribute - skipped as method doesn't accept None."""
        # This test is skipped because validate_attribute doesn't accept None
        # The type system prevents passing None, so this test case is invalid


# ════════════════════════════════════════════════════════════════════════════
# TEST VALIDATE_OBJECTCLASS
# ════════════════════════════════════════════════════════════════════════════


class TestSchemaServiceValidateObjectClass:
    """Test validate_objectclass() method."""

    def test_validate_valid_objectclass(
        self,
        schema_service: FlextLdifSchema,
        simple_objectclass_definition: str,
    ) -> None:
        """Test validating valid objectClass."""
        parse_result = schema_service.parse_objectclass(simple_objectclass_definition)
        assert parse_result.is_success
        oc = parse_result.value

        result = schema_service.validate_objectclass(oc)
        assert result.is_success
        assert result.value is True

    def test_validate_objectclass_without_name(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating objectClass without name."""
        oc = m.Ldif.SchemaObjectClass(
            oid="1.2.3.4",
            name="",  # Empty name
            kind="STRUCTURAL",
        )
        result = schema_service.validate_objectclass(oc)
        assert result.is_failure
        assert result.error is not None
        assert "name" in result.error.lower()

    def test_validate_objectclass_without_oid(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating objectClass without OID."""
        oc = m.Ldif.SchemaObjectClass(
            oid="",  # Empty OID
            name="testOC",
            kind="STRUCTURAL",
        )
        result = schema_service.validate_objectclass(oc)
        assert result.is_failure
        assert result.error is not None
        assert "oid" in result.error.lower()

    def test_validate_objectclass_invalid_kind(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating objectClass with invalid kind."""
        oc = m.Ldif.SchemaObjectClass(
            oid="1.2.3.4",
            name="testOC",
            kind="INVALID",  # Invalid kind
        )
        result = schema_service.validate_objectclass(oc)
        assert result.is_failure
        assert result.error is not None
        assert "kind" in result.error.lower()

    def test_validate_objectclass_valid_kinds(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating objectClass with all valid kinds."""
        for kind in ["ABSTRACT", "STRUCTURAL", "AUXILIARY"]:
            oc = m.Ldif.SchemaObjectClass(
                oid="1.2.3.4",
                name="testOC",
                kind=kind,
            )
            result = schema_service.validate_objectclass(oc)
            assert result.is_success, f"Kind {kind} should be valid"

    def test_validate_objectclass_none(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating None objectClass - skipped as method doesn't accept None."""
        # This test is skipped because validate_objectclass doesn't accept None
        # The type system prevents passing None, so this test case is invalid


# ════════════════════════════════════════════════════════════════════════════
# TEST WRITE_ATTRIBUTE
# ════════════════════════════════════════════════════════════════════════════


class TestSchemaServiceWriteAttribute:
    """Test write_attribute() method."""

    def test_write_valid_attribute(
        self,
        schema_service: FlextLdifSchema,
        simple_attribute_definition: str,
    ) -> None:
        """Test writing valid attribute to LDIF."""
        parse_result = schema_service.parse_attribute(simple_attribute_definition)
        assert parse_result.is_success
        attr = parse_result.value

        result = schema_service.write_attribute(attr)
        assert result.is_success
        ldif = result.value
        assert isinstance(ldif, str)
        assert "cn" in ldif or "2.5.4.3" in ldif

    def test_write_attribute_roundtrip(
        self,
        schema_service: FlextLdifSchema,
        simple_attribute_definition: str,
    ) -> None:
        """Test write then parse roundtrip."""
        # Parse
        parse_result = schema_service.parse_attribute(simple_attribute_definition)
        assert parse_result.is_success
        attr = parse_result.value

        # Write
        write_result = schema_service.write_attribute(attr)
        assert write_result.is_success
        written = write_result.value

        # Parse written
        roundtrip_result = schema_service.parse_attribute(written)
        assert roundtrip_result.is_success
        roundtrip_attr = roundtrip_result.value
        assert roundtrip_attr.oid == attr.oid
        assert roundtrip_attr.name == attr.name

    def test_write_invalid_attribute(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test writing invalid attribute (should fail validation)."""
        attr = m.Ldif.SchemaAttribute(
            oid="",  # Invalid: empty OID
            name="testAttr",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )
        result = schema_service.write_attribute(attr)
        assert result.is_failure
        assert result.error is not None
        assert "oid" in result.error.lower()


# ════════════════════════════════════════════════════════════════════════════
# TEST WRITE_OBJECTCLASS
# ════════════════════════════════════════════════════════════════════════════


class TestSchemaServiceWriteObjectClass:
    """Test write_objectclass() method."""

    def test_write_valid_objectclass(
        self,
        schema_service: FlextLdifSchema,
        simple_objectclass_definition: str,
    ) -> None:
        """Test writing valid objectClass to LDIF."""
        parse_result = schema_service.parse_objectclass(simple_objectclass_definition)
        assert parse_result.is_success
        oc = parse_result.value

        result = schema_service.write_objectclass(oc)
        assert result.is_success
        ldif = result.value
        assert isinstance(ldif, str)
        assert "person" in ldif or "2.5.6.6" in ldif

    def test_write_objectclass_roundtrip(
        self,
        schema_service: FlextLdifSchema,
        simple_objectclass_definition: str,
    ) -> None:
        """Test write then parse roundtrip."""
        # Parse
        parse_result = schema_service.parse_objectclass(simple_objectclass_definition)
        assert parse_result.is_success
        oc = parse_result.value

        # Write
        write_result = schema_service.write_objectclass(oc)
        assert write_result.is_success
        written = write_result.value

        # Parse written
        roundtrip_result = schema_service.parse_objectclass(written)
        assert roundtrip_result.is_success
        roundtrip_oc = roundtrip_result.value
        assert roundtrip_oc.oid == oc.oid
        assert roundtrip_oc.name == oc.name

    def test_write_invalid_objectclass(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test writing invalid objectClass (should fail validation)."""
        oc = m.Ldif.SchemaObjectClass(
            oid="",  # Invalid: empty OID
            name="testOC",
            kind="STRUCTURAL",
        )
        result = schema_service.write_objectclass(oc)
        assert result.is_failure
        assert result.error is not None
        assert "oid" in result.error.lower()


# ════════════════════════════════════════════════════════════════════════════
# TEST CAN_HANDLE_ATTRIBUTE
# ════════════════════════════════════════════════════════════════════════════


class TestSchemaServiceCanHandleAttribute:
    """Test can_handle_attribute() method."""

    def test_can_handle_valid_attribute_definition(
        self,
        schema_service: FlextLdifSchema,
        simple_attribute_definition: str,
    ) -> None:
        """Test can_handle with valid attribute definition."""
        result = schema_service.can_handle_attribute(simple_attribute_definition)
        assert result is True

    def test_can_handle_complex_attribute_definition(
        self,
        schema_service: FlextLdifSchema,
        complex_attribute_definition: str,
    ) -> None:
        """Test can_handle with complex attribute definition."""
        result = schema_service.can_handle_attribute(complex_attribute_definition)
        assert result is True

    def test_can_handle_empty_string(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test can_handle with empty string."""
        result = schema_service.can_handle_attribute("")
        assert result is False

    def test_can_handle_whitespace_only(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test can_handle with whitespace only."""
        result = schema_service.can_handle_attribute("   ")
        assert result is False

    def test_can_handle_invalid_format(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test can_handle with invalid format (no parentheses)."""
        result = schema_service.can_handle_attribute("invalid format")
        assert result is False

    def test_can_handle_with_parentheses(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test can_handle with parentheses (should return True)."""
        result = schema_service.can_handle_attribute("( test )")
        assert result is True


# ════════════════════════════════════════════════════════════════════════════
# TEST REPR
# ════════════════════════════════════════════════════════════════════════════


class TestSchemaServiceRepr:
    """Test __repr__ method."""

    def test_repr_default_server_type(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test __repr__ with default server type."""
        repr_str = repr(schema_service)
        assert "FlextLdifSchema" in repr_str
        assert "rfc" in repr_str

    def test_repr_custom_server_type(
        self,
        schema_service_oud: FlextLdifSchema,
    ) -> None:
        """Test __repr__ with custom server type."""
        repr_str = repr(schema_service_oud)
        assert "FlextLdifSchema" in repr_str
        assert "oud" in repr_str


# ════════════════════════════════════════════════════════════════════════════
# TEST INTEGRATION SCENARIOS
# ════════════════════════════════════════════════════════════════════════════


class TestSchemaServiceIntegration:
    """Test integration scenarios."""

    def test_parse_validate_write_roundtrip_attribute(
        self,
        schema_service: FlextLdifSchema,
        simple_attribute_definition: str,
    ) -> None:
        """Test complete parse → validate → write → parse roundtrip."""
        # Parse
        parse_result = schema_service.parse_attribute(simple_attribute_definition)
        assert parse_result.is_success
        attr = parse_result.value

        # Validate
        validate_result = schema_service.validate_attribute(attr)
        assert validate_result.is_success

        # Write
        write_result = schema_service.write_attribute(attr)
        assert write_result.is_success
        written = write_result.value

        # Parse written
        roundtrip_result = schema_service.parse_attribute(written)
        assert roundtrip_result.is_success
        roundtrip_attr = roundtrip_result.value

        # Verify roundtrip
        assert roundtrip_attr.oid == attr.oid
        assert roundtrip_attr.name == attr.name

    def test_parse_validate_write_roundtrip_objectclass(
        self,
        schema_service: FlextLdifSchema,
        simple_objectclass_definition: str,
    ) -> None:
        """Test complete parse → validate → write → parse roundtrip."""
        # Parse
        parse_result = schema_service.parse_objectclass(simple_objectclass_definition)
        assert parse_result.is_success
        oc = parse_result.value

        # Validate
        validate_result = schema_service.validate_objectclass(oc)
        assert validate_result.is_success

        # Write
        write_result = schema_service.write_objectclass(oc)
        assert write_result.is_success
        written = write_result.value

        # Parse written
        roundtrip_result = schema_service.parse_objectclass(written)
        assert roundtrip_result.is_success
        roundtrip_oc = roundtrip_result.value

        # Verify roundtrip
        assert roundtrip_oc.oid == oc.oid
        assert roundtrip_oc.name == oc.name
        assert roundtrip_oc.kind == oc.kind

    def test_multiple_server_types(
        self,
    ) -> None:
        """Test service works with different server types."""
        for server_type in ["rfc", "oud", "oid", "openldap"]:
            service = FlextLdifSchema(
                server_type=cast(
                    "c.Ldif.LiteralTypes.ServerTypeLiteral",
                    server_type,
                ),
            )
            result = service.execute()
            assert result.is_success
            status = result.value
            assert status.server_type == server_type
