"""Tests for LDIF schema service.

This module tests the FlextLdifSchema service functionality including attribute
definition parsing, objectClass definition parsing, syntax validation, and
server-specific schema quirk handling for different LDAP implementations.
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldif import FlextLdifSchema, FlextLdifServer
from tests import c, m, s


@pytest.fixture
def schema_service() -> FlextLdifSchema:
    """Create FlextLdifSchema instance with default RFC server type."""
    return FlextLdifSchema()


@pytest.fixture
def schema_service_oud() -> FlextLdifSchema:
    """Create FlextLdifSchema instance with OUD server type."""
    return FlextLdifSchema(server_type=c.Ldif.ServerTypes("oud"))


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


class TestsFlextLdifSchemaServiceExecute(s):
    """Test execute() method (health check)."""

    def test_execute_returns_status(self, schema_service: FlextLdifSchema) -> None:
        """Test execute() returns service status."""
        result = schema_service.execute()
        tm.that(result.is_success, eq=True)
        status = result.value
        tm.that(status, is_=m.Ldif.SchemaServiceStatus)
        tm.that(status.service, eq="SchemaService")
        tm.that(status.status, eq="operational")
        tm.that(status.rfc_compliance, eq="RFC 4512")
        tm.that(status.operations, has="parse_attribute")

    def test_execute_with_different_server_type(
        self,
        schema_service_oud: FlextLdifSchema,
    ) -> None:
        """Test execute() with different server type."""
        result = schema_service_oud.execute()
        tm.that(result.is_success, eq=True)
        status = result.value
        tm.that(status.server_type, eq="oud")


class TestSchemaServiceBuilder:
    """Test fluent builder pattern methods."""

    def test_builder_creates_instance(self) -> None:
        """Test builder() creates new instance."""
        service = FlextLdifSchema.builder()
        tm.that(service, is_=FlextLdifSchema)
        tm.that(service.server_type, eq="rfc")

    def test_with_server_type_chains(self) -> None:
        """Test with_server_type() returns self for chaining."""
        service = FlextLdifSchema.builder()
        chained = service.with_server_type(c.Ldif.ServerTypes("oud"))
        tm.that(chained is service, eq=True)
        tm.that(service.server_type, eq="oud")

    def test_build_returns_self(self) -> None:
        """Test build() returns configured instance."""
        service = (
            FlextLdifSchema
            .builder()
            .with_server_type(c.Ldif.ServerTypes("oid"))
            .build_schema()
        )
        tm.that(service, is_=FlextLdifSchema)
        tm.that(service.server_type, eq="oid")

    def test_fluent_builder_complete_chain(self) -> None:
        """Test complete fluent builder chain."""
        service = (
            FlextLdifSchema
            .builder()
            .with_server_type(c.Ldif.ServerTypes("oud"))
            .build_schema()
        )
        tm.that(service.server_type, eq="oud")
        result = service.execute()
        tm.that(result.is_success, eq=True)
        status = result.value
        tm.that(status.server_type, eq="oud")


class TestSchemaServiceParseAttribute:
    """Test parse_attribute() method."""

    def test_parse_simple_attribute(
        self,
        schema_service: FlextLdifSchema,
        simple_attribute_definition: str,
    ) -> None:
        """Test parsing simple attribute definition."""
        result = schema_service.parse_attribute(simple_attribute_definition)
        tm.that(result.is_success, eq=True)
        attr = result.value
        tm.that(attr, is_=m.Ldif.SchemaAttribute)
        tm.that(attr.oid, eq="2.5.4.3")
        tm.that(attr.name, eq="cn")

    def test_parse_complex_attribute(
        self,
        schema_service: FlextLdifSchema,
        complex_attribute_definition: str,
    ) -> None:
        """Test parsing complex attribute definition."""
        result = schema_service.parse_attribute(complex_attribute_definition)
        tm.that(result.is_success, eq=True)
        attr = result.value
        tm.that(attr, is_=m.Ldif.SchemaAttribute)
        tm.that(attr.oid, eq="2.5.4.0")
        tm.that(attr.name, eq="objectClass")

    def test_parse_attribute_empty_string(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test parsing empty attribute definition."""
        result = schema_service.parse_attribute("")
        tm.that(result.is_failure, eq=True)
        tm.that(result.error, none=False)
        if result.error is not None:
            tm.that(result.error.lower(), has="empty")

    def test_parse_attribute_whitespace_only(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test parsing whitespace-only attribute definition."""
        result = schema_service.parse_attribute("   ")
        tm.that(result.is_failure, eq=True)
        tm.that(result.error, none=False)
        if result.error is not None:
            tm.that(result.error.lower(), has="empty")

    def test_parse_attribute_invalid_format(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test parsing invalid attribute definition."""
        result = schema_service.parse_attribute("invalid format")
        tm.that(result.is_failure, eq=True)


class TestSchemaServiceParseObjectClass:
    """Test parse_objectclass() method."""

    def test_parse_simple_objectclass(
        self,
        schema_service: FlextLdifSchema,
        simple_objectclass_definition: str,
    ) -> None:
        """Test parsing simple objectClass definition."""
        result = schema_service.parse_objectclass(simple_objectclass_definition)
        tm.that(result.is_success, eq=True)
        oc = result.value
        tm.that(oc, is_=m.Ldif.SchemaObjectClass)
        tm.that(oc.oid, eq="2.5.6.6")
        tm.that(oc.name, eq="person")
        tm.that(oc.kind, eq="STRUCTURAL")

    def test_parse_complex_objectclass(
        self,
        schema_service: FlextLdifSchema,
        complex_objectclass_definition: str,
    ) -> None:
        """Test parsing complex objectClass definition."""
        result = schema_service.parse_objectclass(complex_objectclass_definition)
        tm.that(result.is_success, eq=True)
        oc = result.value
        tm.that(oc, is_=m.Ldif.SchemaObjectClass)
        tm.that(oc.oid, eq="2.5.6.2")
        tm.that(oc.name, eq="country")
        tm.that(oc.kind, eq="STRUCTURAL")

    def test_parse_objectclass_empty_string(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test parsing empty objectClass definition."""
        result = schema_service.parse_objectclass("")
        tm.that(result.is_failure, eq=True)
        tm.that(result.error, none=False)
        if result.error is not None:
            tm.that(result.error.lower(), has="empty")

    def test_parse_objectclass_whitespace_only(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test parsing whitespace-only objectClass definition."""
        result = schema_service.parse_objectclass("   ")
        tm.that(result.is_failure, eq=True)
        tm.that(result.error, none=False)
        if result.error is not None:
            tm.that(result.error.lower(), has="empty")

    def test_parse_objectclass_invalid_format(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test parsing invalid objectClass definition."""
        result = schema_service.parse_objectclass("invalid format")
        tm.that(result.is_failure, eq=True)


class TestSchemaServiceValidateAttribute:
    """Test validate_attribute() method."""

    def test_validate_valid_attribute(
        self,
        schema_service: FlextLdifSchema,
        simple_attribute_definition: str,
    ) -> None:
        """Test validating valid attribute."""
        parse_result = schema_service.parse_attribute(simple_attribute_definition)
        tm.that(parse_result.is_success, eq=True)
        attr = parse_result.value
        result = schema_service.validate_attribute(attr)
        tm.that(result.is_success, eq=True)
        tm.that(result.value is True, eq=True)

    def test_validate_attribute_without_name(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating attribute without name."""
        attr = m.Ldif.SchemaAttribute(
            oid="1.2.3.4",
            name="",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )
        result = schema_service.validate_attribute(attr)
        tm.that(result.is_failure, eq=True)
        tm.that(result.error, none=False)
        if result.error is not None:
            tm.that(result.error.lower(), has="name")

    def test_validate_attribute_without_oid(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating attribute without OID."""
        attr = m.Ldif.SchemaAttribute(
            oid="",
            name="testAttr",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )
        result = schema_service.validate_attribute(attr)
        tm.that(result.is_failure, eq=True)
        tm.that(result.error, none=False)
        if result.error is not None:
            tm.that(result.error.lower(), has="oid")

    def test_validate_attribute_with_invalid_syntax_oid(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating attribute with invalid syntax OID."""
        attr = m.Ldif.SchemaAttribute(
            oid="1.2.3.4",
            name="testAttr",
            syntax="invalid-oid",
        )
        result = schema_service.validate_attribute(attr)
        tm.that(result.is_failure, eq=True)
        tm.that(result.error, none=False)
        if result.error is not None:
            tm.that(result.error.lower(), has="syntax")

    def test_validate_attribute_none(self, schema_service: FlextLdifSchema) -> None:
        """Test validating None attribute - skipped as method doesn't accept None."""


class TestSchemaServiceValidateObjectClass:
    """Test validate_objectclass() method."""

    def test_validate_valid_objectclass(
        self,
        schema_service: FlextLdifSchema,
        simple_objectclass_definition: str,
    ) -> None:
        """Test validating valid objectClass."""
        parse_result = schema_service.parse_objectclass(simple_objectclass_definition)
        tm.that(parse_result.is_success, eq=True)
        oc = parse_result.value
        result = schema_service.validate_objectclass(oc)
        tm.that(result.is_success, eq=True)
        tm.that(result.value is True, eq=True)

    def test_validate_objectclass_without_name(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating objectClass without name."""
        oc = m.Ldif.SchemaObjectClass(oid="1.2.3.4", name="", kind="STRUCTURAL")
        result = schema_service.validate_objectclass(oc)
        tm.that(result.is_failure, eq=True)
        tm.that(result.error, none=False)
        if result.error is not None:
            tm.that(result.error.lower(), has="name")

    def test_validate_objectclass_without_oid(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating objectClass without OID."""
        oc = m.Ldif.SchemaObjectClass(oid="", name="testOC", kind="STRUCTURAL")
        result = schema_service.validate_objectclass(oc)
        tm.that(result.is_failure, eq=True)
        tm.that(result.error, none=False)
        if result.error is not None:
            tm.that(result.error.lower(), has="oid")

    def test_validate_objectclass_invalid_kind(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating objectClass with invalid kind."""
        oc = m.Ldif.SchemaObjectClass(oid="1.2.3.4", name="testOC", kind="INVALID")
        result = schema_service.validate_objectclass(oc)
        tm.that(result.is_failure, eq=True)
        tm.that(result.error, none=False)
        if result.error is not None:
            tm.that(result.error.lower(), has="kind")

    def test_validate_objectclass_valid_kinds(
        self,
        schema_service: FlextLdifSchema,
    ) -> None:
        """Test validating objectClass with all valid kinds."""
        for kind in ["ABSTRACT", "STRUCTURAL", "AUXILIARY"]:
            oc = m.Ldif.SchemaObjectClass(oid="1.2.3.4", name="testOC", kind=kind)
            result = schema_service.validate_objectclass(oc)
            _ = tm.that(result.is_success, eq=True)

    def test_validate_objectclass_none(self, schema_service: FlextLdifSchema) -> None:
        """Test validating None objectClass - skipped as method doesn't accept None."""


class TestSchemaServiceWriteAttribute:
    """Test write_attribute() method."""

    def test_write_valid_attribute(
        self,
        schema_service: FlextLdifSchema,
        simple_attribute_definition: str,
    ) -> None:
        """Test writing valid attribute to LDIF."""
        parse_result = schema_service.parse_attribute(simple_attribute_definition)
        tm.that(parse_result.is_success, eq=True)
        attr = parse_result.value
        result = schema_service.write_attribute(attr)
        tm.that(result.is_success, eq=True)
        ldif = result.value
        tm.that(ldif, is_=str)
        tm.that("cn" in ldif or "2.5.4.3" in ldif, eq=True)

    def test_write_attribute_roundtrip(
        self,
        schema_service: FlextLdifSchema,
        simple_attribute_definition: str,
    ) -> None:
        """Test write then parse roundtrip."""
        parse_result = schema_service.parse_attribute(simple_attribute_definition)
        tm.that(parse_result.is_success, eq=True)
        attr = parse_result.value
        write_result = schema_service.write_attribute(attr)
        tm.that(write_result.is_success, eq=True)
        written = write_result.value
        roundtrip_result = schema_service.parse_attribute(written)
        tm.that(roundtrip_result.is_success, eq=True)
        roundtrip_attr = roundtrip_result.value
        tm.that(roundtrip_attr.oid, eq=attr.oid)
        tm.that(roundtrip_attr.name, eq=attr.name)

    def test_write_invalid_attribute(self, schema_service: FlextLdifSchema) -> None:
        """Test writing invalid attribute (should fail validation)."""
        attr = m.Ldif.SchemaAttribute(
            oid="",
            name="testAttr",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )
        result = schema_service.write_attribute(attr)
        tm.that(result.is_failure, eq=True)
        tm.that(result.error, none=False)
        if result.error is not None:
            tm.that(result.error.lower(), has="oid")


class TestSchemaServiceWriteObjectClass:
    """Test write_objectclass() method."""

    def test_write_valid_objectclass(
        self,
        schema_service: FlextLdifSchema,
        simple_objectclass_definition: str,
    ) -> None:
        """Test writing valid objectClass to LDIF."""
        parse_result = schema_service.parse_objectclass(simple_objectclass_definition)
        tm.that(parse_result.is_success, eq=True)
        oc = parse_result.value
        result = schema_service.write_objectclass(oc)
        tm.that(result.is_success, eq=True)
        ldif = result.value
        tm.that(ldif, is_=str)
        tm.that("person" in ldif or "2.5.6.6" in ldif, eq=True)

    def test_write_objectclass_roundtrip(
        self,
        schema_service: FlextLdifSchema,
        simple_objectclass_definition: str,
    ) -> None:
        """Test write then parse roundtrip."""
        parse_result = schema_service.parse_objectclass(simple_objectclass_definition)
        tm.that(parse_result.is_success, eq=True)
        oc = parse_result.value
        write_result = schema_service.write_objectclass(oc)
        tm.that(write_result.is_success, eq=True)
        written = write_result.value
        roundtrip_result = schema_service.parse_objectclass(written)
        tm.that(roundtrip_result.is_success, eq=True)
        roundtrip_oc = roundtrip_result.value
        tm.that(roundtrip_oc.oid, eq=oc.oid)
        tm.that(roundtrip_oc.name, eq=oc.name)

    def test_write_invalid_objectclass(self, schema_service: FlextLdifSchema) -> None:
        """Test writing invalid objectClass (should fail validation)."""
        oc = m.Ldif.SchemaObjectClass(oid="", name="testOC", kind="STRUCTURAL")
        result = schema_service.write_objectclass(oc)
        tm.that(result.is_failure, eq=True)
        tm.that(result.error, none=False)
        if result.error is not None:
            tm.that(result.error.lower(), has="oid")


class TestSchemaServiceCanHandleAttribute:
    """Test can_handle_attribute() method."""

    def test_can_handle_valid_attribute_definition(
        self,
        schema_service: FlextLdifSchema,
        simple_attribute_definition: str,
    ) -> None:
        """Test can_handle with valid attribute definition."""
        result = schema_service.can_handle_attribute(simple_attribute_definition)
        tm.that(result is True, eq=True)

    def test_can_handle_complex_attribute_definition(
        self,
        schema_service: FlextLdifSchema,
        complex_attribute_definition: str,
    ) -> None:
        """Test can_handle with complex attribute definition."""
        result = schema_service.can_handle_attribute(complex_attribute_definition)
        tm.that(result is True, eq=True)

    def test_can_handle_empty_string(self, schema_service: FlextLdifSchema) -> None:
        """Test can_handle with empty string."""
        result = schema_service.can_handle_attribute("")
        tm.that(result is False, eq=True)

    def test_can_handle_whitespace_only(self, schema_service: FlextLdifSchema) -> None:
        """Test can_handle with whitespace only."""
        result = schema_service.can_handle_attribute("   ")
        tm.that(result is False, eq=True)

    def test_can_handle_invalid_format(self, schema_service: FlextLdifSchema) -> None:
        """Test can_handle with invalid format (no parentheses)."""
        result = schema_service.can_handle_attribute("invalid format")
        tm.that(result is False, eq=True)

    def test_can_handle_with_parentheses(self, schema_service: FlextLdifSchema) -> None:
        """Test can_handle with parentheses (should return True)."""
        result = schema_service.can_handle_attribute("( test )")
        tm.that(result is True, eq=True)


class TestSchemaServiceRepr:
    """Test __repr__ method."""

    def test_repr_default_server_type(self, schema_service: FlextLdifSchema) -> None:
        """Test __repr__ with default server type."""
        repr_str = repr(schema_service)
        tm.that(repr_str, has="FlextLdifSchema")
        tm.that(repr_str, has="rfc")

    def test_repr_custom_server_type(self, schema_service_oud: FlextLdifSchema) -> None:
        """Test __repr__ with custom server type."""
        repr_str = repr(schema_service_oud)
        tm.that(repr_str, has="FlextLdifSchema")
        tm.that(repr_str, has="oud")


class TestSchemaServiceIntegration:
    """Test integration scenarios."""

    def test_parse_validate_write_roundtrip_attribute(
        self,
        schema_service: FlextLdifSchema,
        simple_attribute_definition: str,
    ) -> None:
        """Test complete parse → validate → write → parse roundtrip."""
        parse_result = schema_service.parse_attribute(simple_attribute_definition)
        tm.that(parse_result.is_success, eq=True)
        attr = parse_result.value
        validate_result = schema_service.validate_attribute(attr)
        tm.that(validate_result.is_success, eq=True)
        write_result = schema_service.write_attribute(attr)
        tm.that(write_result.is_success, eq=True)
        written = write_result.value
        roundtrip_result = schema_service.parse_attribute(written)
        tm.that(roundtrip_result.is_success, eq=True)
        roundtrip_attr = roundtrip_result.value
        tm.that(roundtrip_attr.oid, eq=attr.oid)
        tm.that(roundtrip_attr.name, eq=attr.name)

    def test_parse_validate_write_roundtrip_objectclass(
        self,
        schema_service: FlextLdifSchema,
        simple_objectclass_definition: str,
    ) -> None:
        """Test complete parse → validate → write → parse roundtrip."""
        parse_result = schema_service.parse_objectclass(simple_objectclass_definition)
        tm.that(parse_result.is_success, eq=True)
        oc = parse_result.value
        validate_result = schema_service.validate_objectclass(oc)
        tm.that(validate_result.is_success, eq=True)
        write_result = schema_service.write_objectclass(oc)
        tm.that(write_result.is_success, eq=True)
        written = write_result.value
        roundtrip_result = schema_service.parse_objectclass(written)
        tm.that(roundtrip_result.is_success, eq=True)
        roundtrip_oc = roundtrip_result.value
        tm.that(roundtrip_oc.oid, eq=oc.oid)
        tm.that(roundtrip_oc.name, eq=oc.name)
        tm.that(roundtrip_oc.kind, eq=oc.kind)

    def test_multiple_server_types(self) -> None:
        """Test service works with different server types."""
        server_registry = FlextLdifServer.get_global_instance()
        server_types: tuple[c.Ldif.ServerTypes, ...] = (
            c.Ldif.ServerTypes.RFC,
            c.Ldif.ServerTypes.OUD,
            c.Ldif.ServerTypes.OID,
            c.Ldif.ServerTypes.OPENLDAP,
        )
        for server_type in server_types:
            service = FlextLdifSchema(server_type=server_type, registry=server_registry)
            result = service.execute()
            tm.that(result.is_success, eq=True)
            status = result.value
            tm.that(status.server_type, eq=server_type)
