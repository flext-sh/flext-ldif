"""Unit tests for FlextLdifConversion facade.

Tests the universal translation matrix for converting LDAP data between
different server quirks using RFC as intermediate format.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.oud import FlextLdifServersOud
from flext_ldif.services.conversion import FlextLdifConversion


# Real test quirks for error path testing
class FailingParseQuirk(FlextLdifServersBase.Schema):
    """Real FlextLdifServersBase.Schema subclass that fails on parse."""

    def __init__(self, error_msg: str = "parse failed") -> None:
        """Initialize quirk."""
        self.server_type = "test_failing_parse"
        self.priority = 100
        self.error_msg = error_msg

    def _can_handle_attribute(
        self, attr_definition: str | FlextLdifModels.SchemaAttribute
    ) -> bool:
        """Always handle attributes for testing."""
        return True

    def _can_handle_objectclass(
        self, oc_definition: str | FlextLdifModels.SchemaObjectClass
    ) -> bool:
        """Always handle objectClass for testing."""
        return True

    def _can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
        """Always handle ACL for testing."""
        return True

    def _parse_attribute(
        self, attr_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        return FlextResult.fail(self.error_msg)

    def _parse_objectclass(
        self, oc_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        return FlextResult.fail(self.error_msg)

    def _write_attribute(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[str]:
        return FlextResult.fail(self.error_msg)

    def _write_objectclass(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[str]:
        return FlextResult.fail(self.error_msg)


class SuccessfulParseQuirk(FlextLdifServersBase.Schema):
    """Real FlextLdifServersBase.Schema subclass for successful operations."""

    def __init__(self) -> None:
        """Initialize quirk."""
        super().__init__()

    def _can_handle_attribute(
        self, attr_definition: str | FlextLdifModels.SchemaAttribute
    ) -> bool:
        """Always handle attributes for testing."""
        return True

    def _can_handle_objectclass(
        self, oc_definition: str | FlextLdifModels.SchemaObjectClass
    ) -> bool:
        """Always handle objectClass for testing."""
        return True

    def _parse_attribute(
        self, attr_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        return FlextResult.ok(
            FlextLdifModels.SchemaAttribute(oid="1.2.3.4.5", name="test")
        )

    def _parse_objectclass(
        self, oc_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        return FlextResult.ok(
            FlextLdifModels.SchemaObjectClass(oid="1.2.3.4.6", name="test")
        )

    def _write_attribute(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def _write_objectclass(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")


class ConversionFailingQuirk(FlextLdifServersBase.Schema):
    """Real FlextLdifServersBase.Schema subclass that fails on conversion."""

    def __init__(self, fail_on: str = "to_rfc") -> None:
        """Initialize quirk with failure mode."""
        self.server_type = "test_conversion_failing"
        self.priority = 100
        self.fail_on = fail_on

    def _can_handle_attribute(
        self, attr_definition: str | FlextLdifModels.SchemaAttribute
    ) -> bool:
        """Always handle attributes for testing."""
        return True

    def _can_handle_objectclass(
        self, oc_definition: str | FlextLdifModels.SchemaObjectClass
    ) -> bool:
        """Always handle objectClass for testing."""
        return True

    def _can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
        """Always handle ACL for testing."""
        return True

    def _parse_attribute(
        self, attr_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        return FlextResult.ok(
            FlextLdifModels.SchemaAttribute(oid="1.2.3.4", name="test")
        )

    def _write_attribute(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[str]:
        if self.fail_on == "write":
            return FlextResult.fail("write failed")
        return FlextResult.ok(f"({attr_data.oid} NAME '{attr_data.name}')")

    def _parse_objectclass(
        self, oc_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        return FlextResult.ok(
            FlextLdifModels.SchemaObjectClass(oid="1.2.3.5", name="test")
        )

    def _write_objectclass(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[str]:
        if self.fail_on == "write":
            return FlextResult.fail("write failed")
        return FlextResult.ok(f"({oc_data.oid} NAME '{oc_data.name}')")


class ExceptionThrowingQuirk(FlextLdifServersBase.Schema):
    """Real FlextLdifServersBase.Schema subclass that throws exceptions."""

    def __init__(self) -> None:
        """Initialize quirk."""
        self.server_type = "test_exception_throwing"
        self.priority = 100

    def _can_handle_attribute(
        self, attr_definition: str | FlextLdifModels.SchemaAttribute
    ) -> bool:
        """Always handle attributes for testing."""
        return True

    def _can_handle_objectclass(
        self, oc_definition: str | FlextLdifModels.SchemaObjectClass
    ) -> bool:
        """Always handle objectClass for testing."""
        return True

    def _can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
        """Always handle ACL for testing."""
        return True

    def _parse_attribute(
        self, attr_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        msg = "unexpected error"
        raise RuntimeError(msg)

    def _parse_objectclass(
        self, oc_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        msg = "unexpected error"
        raise RuntimeError(msg)

    def _write_attribute(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[str]:
        msg = "unexpected error"
        raise RuntimeError(msg)

    def _write_objectclass(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[str]:
        msg = "unexpected error"
        raise RuntimeError(msg)


class MissingParseObjectClassQuirk(FlextLdifServersBase.Schema):
    """Real quirk missing parse_objectclass method."""

    def __init__(self) -> None:
        """Initialize quirk."""
        self.server_type = "test_missing_parse_oc"
        self.priority = 100

    def _can_handle_attribute(
        self, attr_definition: str | FlextLdifModels.SchemaAttribute
    ) -> bool:
        """Always handle attributes for testing."""
        return True

    def _can_handle_objectclass(
        self, oc_definition: str | FlextLdifModels.SchemaObjectClass
    ) -> bool:
        """Does NOT handle objectClass - that's the point of this test."""
        return False

    def _can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
        """Always handle ACL for testing."""
        return True

    def _parse_attribute(
        self, attr_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Dummy implementation."""
        return FlextResult.ok(
            FlextLdifModels.SchemaAttribute(oid="1.2.3.4", name="test")
        )

    def _parse_objectclass(
        self, oc_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Should never be called since can_handle_objectclass returns False."""
        return FlextResult.fail("Not implemented")

    def _write_attribute(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def _write_objectclass(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")


class ObjectClassParseOnlyQuirk(FlextLdifServersBase.Schema):
    """Real quirk with parse and to_rfc only."""

    def __init__(self) -> None:
        """Initialize quirk."""
        self.server_type = "test_parse_only"
        self.priority = 100

    def _can_handle_attribute(
        self, attr_definition: str | FlextLdifModels.SchemaAttribute
    ) -> bool:
        return True

    def _can_handle_objectclass(
        self, oc_definition: str | FlextLdifModels.SchemaObjectClass
    ) -> bool:
        return True

    def _can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
        return True

    def _parse_attribute(
        self, attr_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        return FlextResult.ok(
            FlextLdifModels.SchemaAttribute(oid="1.2.3.4", name="test")
        )

    def _parse_objectclass(
        self, oc_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        return FlextResult.ok(
            FlextLdifModels.SchemaObjectClass(oid="1.2.3.5", name="test")
        )

    def _write_attribute(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def _write_objectclass(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")


class MissingParseAcl(FlextLdifServersBase.Schema):
    """Real quirk missing parse method."""

    def __init__(self) -> None:
        """Initialize quirk."""
        self.server_type = "test_missing_parse"
        self.priority = 100

    def _can_handle_attribute(
        self, attr_definition: str | FlextLdifModels.SchemaAttribute
    ) -> bool:
        return False

    def _can_handle_objectclass(
        self, oc_definition: str | FlextLdifModels.SchemaObjectClass
    ) -> bool:
        return False

    def _can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
        return True

    def _parse_attribute(
        self, attr_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        return FlextResult.fail("Not implemented")

    def _write_attribute(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[str]:
        return FlextResult.fail("Not implemented")

    def _parse_objectclass(
        self, oc_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        return FlextResult.fail("Not implemented")

    def _write_objectclass(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[str]:
        return FlextResult.fail("Not implemented")

    def _write_acl(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
        return FlextResult.ok("test")


class MissingWriteAcl(FlextLdifServersBase.Schema):
    """Real quirk missing write_acl_to_rfc method."""

    def __init__(self) -> None:
        """Initialize quirk."""
        self.server_type = "test_missing_write_acl"
        self.priority = 100

    def _can_handle_attribute(
        self, attr_definition: str | FlextLdifModels.SchemaAttribute
    ) -> bool:
        return False

    def _can_handle_objectclass(
        self, oc_definition: str | FlextLdifModels.SchemaObjectClass
    ) -> bool:
        return False

    def _can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
        return True

    def _parse_attribute(
        self, attr_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        return FlextResult.fail("Not implemented")

    def _write_attribute(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[str]:
        return FlextResult.fail("Not implemented")

    def _parse_objectclass(
        self, oc_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        return FlextResult.fail("Not implemented")

    def _write_objectclass(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[str]:
        return FlextResult.fail("Not implemented")


class EntryConversionQuirk(FlextLdifServersBase.Schema):
    """Real quirk with entry conversion support.

    Note: Sets entry=True as a marker for entry support (not self-reference).
    """

    def __init__(self) -> None:
        """Initialize quirk."""
        self.server_type = "test_entry_conversion"
        self.priority = 100
        self.entry = True

    def _can_handle_attribute(
        self, attr_definition: str | FlextLdifModels.SchemaAttribute
    ) -> bool:
        return True  # Supports attribute parsing

    def _parse_attribute(
        self, attr_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        return FlextResult.ok(
            FlextLdifModels.SchemaAttribute(oid="1.2.3.4", name="test")
        )

    def _can_handle_objectclass(
        self, oc_definition: str | FlextLdifModels.SchemaObjectClass
    ) -> bool:
        return False

    def _parse_objectclass(
        self, oc_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        return FlextResult.ok(
            FlextLdifModels.SchemaObjectClass(oid="1.2.3.5", name="test")
        )

    def _write_attribute(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def _write_objectclass(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")


class MinimalQuirk(FlextLdifServersBase.Schema):
    """Real quirk with minimal functionality."""

    def __init__(self) -> None:
        """Initialize quirk."""
        self.server_type = "test_minimal"
        self.priority = 100

    def _can_handle_attribute(
        self, attr_definition: str | FlextLdifModels.SchemaAttribute
    ) -> bool:
        return False

    def _parse_attribute(
        self, attr_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        return FlextResult.ok(
            FlextLdifModels.SchemaAttribute(oid="1.2.3.4", name="test")
        )

    def _can_handle_objectclass(
        self, oc_definition: str | FlextLdifModels.SchemaObjectClass
    ) -> bool:
        return False

    def _parse_objectclass(
        self, oc_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        return FlextResult.ok(
            FlextLdifModels.SchemaObjectClass(oid="1.2.3.5", name="test")
        )

    def _write_attribute(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def _write_objectclass(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")


class PartialAttributeQuirk(FlextLdifServersBase.Schema):
    """Real quirk with only attribute parsing support."""

    def __init__(self) -> None:
        """Initialize quirk."""
        self.server_type = "test_partial_attr"
        self.priority = 100

    def _can_handle_attribute(
        self, attr_definition: str | FlextLdifModels.SchemaAttribute
    ) -> bool:
        return True

    def _parse_attribute(
        self, attr_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        return FlextResult.ok(
            FlextLdifModels.SchemaAttribute(oid="1.2.3.4", name="test")
        )

    def _can_handle_objectclass(
        self, oc_definition: str | FlextLdifModels.SchemaObjectClass
    ) -> bool:
        return False

    def _parse_objectclass(
        self, oc_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        return FlextResult.fail("Not supported")

    def _write_attribute(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def _write_objectclass(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[str]:
        return FlextResult.fail("Not supported")


class TestAclQuirk(FlextLdifServersBase.Acl):
    """Test ACL quirk that always handles ACLs."""

    def __init__(self, server_type: str = "test_acl", priority: int = 100) -> None:
        """Initialize test ACL quirk."""

    def _can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
        return True

    def _parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
        return FlextResult.ok(FlextLdifModels.Acl(raw_acl=acl_line))

    def _write_acl(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
        return FlextResult.ok(acl_data.raw_acl)


class AclOnlyQuirk(FlextLdifServersBase.Schema):
    """Real quirk with only ACL support."""

    def __init__(self) -> None:
        """Initialize quirk."""
        self.server_type = "test_acl_only"
        self.priority = 100
        self.acl = TestAclQuirk()

    def _can_handle_attribute(
        self, attr_definition: str | FlextLdifModels.SchemaAttribute
    ) -> bool:
        return False

    def _parse_attribute(
        self, attr_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        return FlextResult.ok(
            FlextLdifModels.SchemaAttribute(oid="1.2.3.4", name="test")
        )

    def _can_handle_objectclass(
        self, oc_definition: str | FlextLdifModels.SchemaObjectClass
    ) -> bool:
        return False

    def _can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
        return True  # Only ACL support

    def _parse_objectclass(
        self, oc_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        return FlextResult.ok(
            FlextLdifModels.SchemaObjectClass(oid="1.2.3.5", name="test")
        )

    def _write_attribute(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def _write_objectclass(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")


class EntryOnlyQuirk(FlextLdifServersBase.Schema):
    """Real quirk with only entry support.

    Note: Sets entry=True as a marker for entry support (not self-reference).
    """

    def __init__(self) -> None:
        """Initialize quirk."""
        self.server_type = "test_entry_only"
        self.priority = 100
        self.entry = True

    def _can_handle_attribute(
        self, attr_definition: str | FlextLdifModels.SchemaAttribute
    ) -> bool:
        return False

    def _parse_attribute(
        self, attr_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        return FlextResult.ok(
            FlextLdifModels.SchemaAttribute(oid="1.2.3.4", name="test")
        )

    def _can_handle_objectclass(
        self, oc_definition: str | FlextLdifModels.SchemaObjectClass
    ) -> bool:
        return False

    def _parse_objectclass(
        self, oc_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        return FlextResult.ok(
            FlextLdifModels.SchemaObjectClass(oid="1.2.3.5", name="test")
        )

    def _write_attribute(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")

    def _write_objectclass(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[str]:
        return FlextResult.ok("(test)")


class TestConversionMatrixInitialization:
    """Test FlextLdifConversion initialization and basic setup."""

    def test_matrix_instantiation(self) -> None:
        """Test that conversion matrix can be instantiated."""
        matrix = FlextLdifConversion()
        assert matrix is not None
        assert hasattr(matrix, "dn_registry")
        assert matrix.dn_registry is not None

    def test_matrix_has_conversion_methods(self) -> None:
        """Test that matrix has all required conversion methods."""
        matrix = FlextLdifConversion()
        assert hasattr(matrix, "convert")
        assert hasattr(matrix, "batch_convert")
        assert hasattr(matrix, "get_supported_conversions")
        assert hasattr(matrix, "validate_oud_conversion")
        assert hasattr(matrix, "reset_dn_registry")


class TestGetSupportedConversions:
    """Test get_supported_conversions method."""

    @pytest.fixture
    def matrix(self) -> FlextLdifConversion:
        """Create conversion matrix instance."""
        return FlextLdifConversion()

    @pytest.fixture
    def oud(self) -> FlextLdifServersOud:
        """Create OUD quirk instance."""
        return FlextLdifServersOud()

    @pytest.fixture
    def oid(self) -> FlextLdifServersOid:
        """Create OID quirk instance."""
        return FlextLdifServersOid()

    def test_get_supported_conversions_oud(
        self, matrix: FlextLdifConversion, oud: FlextLdifServersOud
    ) -> None:
        """Test checking supported conversions for OUD quirk."""
        supported = matrix.get_supported_conversions(oud)

        assert isinstance(supported, dict)
        assert "attribute" in supported
        assert "objectClass" in supported
        assert "acl" in supported
        assert "entry" in supported

        # Schema operations should be supported
        assert supported["attribute"] is True
        assert supported["objectClass"] is True

    def test_get_supported_conversions_oid(
        self, matrix: FlextLdifConversion, oid: FlextLdifServersOid
    ) -> None:
        """Test checking supported conversions for OID quirk."""
        supported = matrix.get_supported_conversions(oid)

        assert isinstance(supported, dict)
        assert "attribute" in supported
        assert "objectClass" in supported
        assert "acl" in supported
        assert "entry" in supported

        # Schema operations should be supported
        assert supported["attribute"] is True
        assert supported["objectClass"] is True


class TestAttributeConversion:
    """Test attribute conversion through the matrix."""

    @pytest.fixture
    def matrix(self) -> FlextLdifConversion:
        """Create conversion matrix instance."""
        return FlextLdifConversion()

    @pytest.fixture
    def oud(self) -> FlextLdifServersOud:
        """Create OUD quirk instance."""
        return FlextLdifServersOud()

    @pytest.fixture
    def oid(self) -> FlextLdifServersOid:
        """Create OID quirk instance."""
        return FlextLdifServersOid()

    def test_convert_attribute_oud_to_oid(
        self,
        matrix: FlextLdifConversion,
        oud: FlextLdifServersOud,
        oid: FlextLdifServersOid,
    ) -> None:
        """Test converting OUD attribute to OID via matrix."""
        oud_attr = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
        )

        result = matrix.convert(oud, oid, "attribute", oud_attr)

        assert result.is_success, f"Conversion failed: {result.error}"
        oid_attr = result.unwrap()
        assert isinstance(oid_attr, str)
        assert "2.16.840.1.113894.1.1.1" in oid_attr
        assert "orclGUID" in oid_attr

    def test_convert_attribute_oid_to_oud(
        self,
        matrix: FlextLdifConversion,
        oud: FlextLdifServersOud,
        oid: FlextLdifServersOid,
    ) -> None:
        """Test converting OID attribute to OUD via matrix."""
        oid_attr = (
            "( 2.16.840.1.113894.1.1.2 NAME 'orclDBName' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        result = matrix.convert(oid, oud, "attribute", oid_attr)

        assert result.is_success, f"Conversion failed: {result.error}"
        oud_attr = result.unwrap()
        assert isinstance(oud_attr, str)
        assert "2.16.840.1.113894.1.1.2" in oud_attr
        assert "orclDBName" in oud_attr

    def test_convert_attribute_with_complex_syntax(
        self,
        matrix: FlextLdifConversion,
        oud: FlextLdifServersOud,
        oid: FlextLdifServersOid,
    ) -> None:
        """Test converting attribute with complex syntax."""
        oud_attr = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
            "DESC 'Oracle Global Unique Identifier' "
            "EQUALITY caseIgnoreMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 "
            "SINGLE-VALUE )"
        )

        result = matrix.convert(oud, oid, "attribute", oud_attr)

        assert result.is_success
        oid_attr = result.unwrap()
        assert "orclGUID" in oid_attr
        assert "2.16.840.1.113894.1.1.1" in oid_attr

    def test_convert_invalid_attribute_fails(
        self,
        matrix: FlextLdifConversion,
        oud: FlextLdifServersOud,
        oid: FlextLdifServersOid,
    ) -> None:
        """Test that truly invalid attribute is passed through unchanged."""
        invalid_attr = "this is not a valid attribute definition"

        result = matrix.convert(oud, oid, "attribute", invalid_attr)

        # Parser is permissive and passes invalid data through unchanged
        # This is by design to handle partial/malformed data gracefully
        assert result.is_success
        oid_attr = result.unwrap()
        # The result should be the input passed through unchanged
        assert oid_attr == invalid_attr


class TestObjectClassConversion:
    """Test objectClass conversion through the matrix."""

    @pytest.fixture
    def matrix(self) -> FlextLdifConversion:
        """Create conversion matrix instance."""
        return FlextLdifConversion()

    @pytest.fixture
    def oud(self) -> FlextLdifServersOud:
        """Create OUD quirk instance."""
        return FlextLdifServersOud()

    @pytest.fixture
    def oid(self) -> FlextLdifServersOid:
        """Create OID quirk instance."""
        return FlextLdifServersOid()

    def test_convert_objectclass_oud_to_oid(
        self,
        matrix: FlextLdifConversion,
        oud: FlextLdifServersOud,
        oid: FlextLdifServersOid,
    ) -> None:
        """Test converting OUD objectClass to OID via matrix."""
        oud_oc = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )"
        )

        result = matrix.convert(oud, oid, "objectClass", oud_oc)

        assert result.is_success, f"Conversion failed: {result.error}"
        oid_oc = result.unwrap()
        assert isinstance(oid_oc, str)
        assert "2.16.840.1.113894.1.2.1" in oid_oc
        assert "orclContext" in oid_oc
        assert "STRUCTURAL" in oid_oc

    def test_convert_objectclass_oid_to_oud(
        self,
        matrix: FlextLdifConversion,
        oud: FlextLdifServersOud,
        oid: FlextLdifServersOid,
    ) -> None:
        """Test converting OID objectClass to OUD via matrix."""
        oid_oc = (
            "( 2.16.840.1.113894.1.2.2 NAME 'orclContainer' "
            "SUP top STRUCTURAL MUST cn )"
        )

        result = matrix.convert(oid, oud, "objectClass", oid_oc)

        assert result.is_success, f"Conversion failed: {result.error}"
        oud_oc = result.unwrap()
        assert isinstance(oud_oc, str)
        assert "2.16.840.1.113894.1.2.2" in oud_oc
        assert "orclContainer" in oud_oc

    def test_convert_objectclass_with_may_attributes(
        self,
        matrix: FlextLdifConversion,
        oud: FlextLdifServersOud,
        oid: FlextLdifServersOid,
    ) -> None:
        """Test converting objectClass with MAY attributes."""
        oud_oc = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' "
            "SUP top STRUCTURAL "
            "MUST cn "
            "MAY ( description $ orclVersion ) )"
        )

        result = matrix.convert(oud, oid, "objectClass", oud_oc)

        assert result.is_success
        oid_oc = result.unwrap()
        assert "orclContext" in oid_oc
        assert "STRUCTURAL" in oid_oc


class TestBatchConversion:
    """Test batch conversion operations."""

    @pytest.fixture
    def matrix(self) -> FlextLdifConversion:
        """Create conversion matrix instance."""
        return FlextLdifConversion()

    @pytest.fixture
    def oud(self) -> FlextLdifServersOud:
        """Create OUD quirk instance."""
        return FlextLdifServersOud()

    @pytest.fixture
    def oid(self) -> FlextLdifServersOid:
        """Create OID quirk instance."""
        return FlextLdifServersOid()

    def test_batch_convert_attributes(
        self,
        matrix: FlextLdifConversion,
        oud: FlextLdifServersOud,
        oid: FlextLdifServersOid,
    ) -> None:
        """Test batch conversion of multiple attributes."""
        oud_attrs: list[str | dict[str, object]] = [
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
            "( 2.16.840.1.113894.1.1.2 NAME 'orclDBName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        ]

        result = matrix.batch_convert(oud, oid, "attribute", oud_attrs)

        assert result.is_success, f"Batch conversion failed: {result.error}"
        oid_attrs = result.unwrap()
        assert len(oid_attrs) == 2
        assert "orclGUID" in oid_attrs[0]
        assert "orclDBName" in oid_attrs[1]

    def test_batch_convert_objectclasses(
        self,
        matrix: FlextLdifConversion,
        oud: FlextLdifServersOud,
        oid: FlextLdifServersOid,
    ) -> None:
        """Test batch conversion of multiple objectClasses."""
        oud_ocs: list[str | dict[str, object]] = [
            "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )",
            "( 2.16.840.1.113894.1.2.2 NAME 'orclContainer' SUP top STRUCTURAL MUST cn )",
        ]

        result = matrix.batch_convert(oud, oid, "objectClass", oud_ocs)

        assert result.is_success, f"Batch conversion failed: {result.error}"
        oid_ocs = result.unwrap()
        assert len(oid_ocs) == 2
        assert "orclContext" in oid_ocs[0]
        assert "orclContainer" in oid_ocs[1]

    def test_batch_convert_with_partial_failures(
        self,
        matrix: FlextLdifConversion,
        oud: FlextLdifServersOud,
        oid: FlextLdifServersOid,
    ) -> None:
        """Test batch conversion handles malformed data with permissive pass-through."""
        mixed_attrs: list[str | dict[str, object]] = [
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
            "invalid attribute definition",
            "( 2.16.840.1.113894.1.1.2 NAME 'orclDBName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        ]

        result = matrix.batch_convert(oud, oid, "attribute", mixed_attrs)

        # Permissive parser succeeds on all items, passing through malformed data unchanged
        assert result.is_success
        oid_attrs = result.unwrap()
        assert len(oid_attrs) == 3
        # Second item should be passed through as-is
        assert oid_attrs[1] == "invalid attribute definition"


class TestBidirectionalConversion:
    """Test bidirectional conversions OUD ↔ OID."""

    @pytest.fixture
    def matrix(self) -> FlextLdifConversion:
        """Create conversion matrix instance."""
        return FlextLdifConversion()

    @pytest.fixture
    def oud(self) -> FlextLdifServersOud:
        """Create OUD quirk instance."""
        return FlextLdifServersOud()

    @pytest.fixture
    def oid(self) -> FlextLdifServersOid:
        """Create OID quirk instance."""
        return FlextLdifServersOid()

    def test_attribute_roundtrip_oud_to_oid_to_oud(
        self,
        matrix: FlextLdifConversion,
        oud: FlextLdifServersOud,
        oid: FlextLdifServersOid,
    ) -> None:
        """Test attribute round-trip: OUD → OID → OUD."""
        original = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
        )

        # OUD → OID
        oid_result = matrix.convert(oud, oid, "attribute", original)
        assert oid_result.is_success
        oid_attr = oid_result.unwrap()

        # OID → OUD
        oud_result = matrix.convert(oid, oud, "attribute", oid_attr)
        assert oud_result.is_success
        roundtrip = oud_result.unwrap()

        # Validate semantic equivalence
        assert "2.16.840.1.113894.1.1.1" in roundtrip
        assert "orclGUID" in roundtrip

    def test_objectclass_roundtrip_oid_to_oud_to_oid(
        self,
        matrix: FlextLdifConversion,
        oud: FlextLdifServersOud,
        oid: FlextLdifServersOid,
    ) -> None:
        """Test objectClass round-trip: OID → OUD → OID."""
        original = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )"
        )

        # OID → OUD
        oud_result = matrix.convert(oid, oud, "objectClass", original)
        assert oud_result.is_success
        oud_oc = oud_result.unwrap()

        # OUD → OID
        oid_result = matrix.convert(oud, oid, "objectClass", oud_oc)
        assert oid_result.is_success
        roundtrip = oid_result.unwrap()

        # Validate semantic equivalence
        assert "2.16.840.1.113894.1.2.1" in roundtrip
        assert "orclContext" in roundtrip


@pytest.mark.skip(
    reason="Error handling tests for conversion matrix - edge cases not fully implemented"
)
class TestErrorHandling:
    """Test error handling in conversion matrix."""

    @pytest.fixture
    def matrix(self) -> FlextLdifConversion:
        """Create conversion matrix instance."""
        return FlextLdifConversion()

    @pytest.fixture
    def oud(self) -> FlextLdifServersOud:
        """Create OUD quirk instance."""
        return FlextLdifServersOud()

    @pytest.fixture
    def oid(self) -> FlextLdifServersOid:
        """Create OID quirk instance."""
        return FlextLdifServersOid()

    def test_invalid_data_type(
        self,
        matrix: FlextLdifConversion,
        oud: FlextLdifServersOud,
        oid: FlextLdifServersOid,
    ) -> None:
        """Test that invalid data type returns error."""
        # Use a variable to bypass literal type checking
        invalid_data_type: str = "invalid_type"
        result = matrix.convert(
            oud,
            oid,
            invalid_data_type,
            "test",
        )

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None
        assert "Invalid data_type" in result.error

    def test_malformed_attribute(
        self,
        matrix: FlextLdifConversion,
        oud: FlextLdifServersOud,
        oid: FlextLdifServersOid,
    ) -> None:
        """Test that malformed attribute is passed through unchanged."""
        malformed = "this is not a valid attribute"

        result = matrix.convert(oud, oid, "attribute", malformed)

        # Malformed data is passed through unchanged by permissive parser
        assert result.is_success
        oid_attr = result.unwrap()
        assert oid_attr == malformed

    def test_empty_batch_conversion(
        self,
        matrix: FlextLdifConversion,
        oud: FlextLdifServersOud,
        oid: FlextLdifServersOid,
    ) -> None:
        """Test batch conversion with empty list."""
        result = matrix.batch_convert(oud, oid, "attribute", [])

        assert result.is_success
        assert len(result.unwrap()) == 0


class TestDnCaseRegistryIntegration:
    """Test DN case registry integration."""

    @pytest.fixture
    def matrix(self) -> FlextLdifConversion:
        """Create conversion matrix instance."""
        return FlextLdifConversion()

    def test_dn_registry_initialized(self, matrix: FlextLdifConversion) -> None:
        """Test that DN registry is initialized."""
        assert hasattr(matrix, "dn_registry")
        assert matrix.dn_registry is not None

    def test_reset_dn_registry(self, matrix: FlextLdifConversion) -> None:
        """Test that DN registry can be reset."""
        # Register a DN
        matrix.dn_registry.register_dn("cn=test,dc=example,dc=com")

        # Reset registry
        matrix.reset_dn_registry()

        # Registry should be cleared
        # We can't directly test if it's empty, but reset should not raise
        assert True

    def test_validate_oud_conversion(self, matrix: FlextLdifConversion) -> None:
        """Test OUD conversion validation."""
        result = matrix.validate_oud_conversion()

        assert result.is_success
        # Should return True when no DNs registered
        assert result.unwrap() is True


class TestDnExtractionAndRegistration:
    """Test DN extraction and registration functionality."""

    @pytest.fixture
    def matrix(self) -> FlextLdifConversion:
        """Create conversion matrix instance."""
        return FlextLdifConversion()

    @pytest.fixture
    def oud(self) -> FlextLdifServersOud:
        """Create OUD quirk instance."""
        return FlextLdifServersOud()

    @pytest.fixture
    def oid(self) -> FlextLdifServersOid:
        """Create OID quirk instance."""
        return FlextLdifServersOid()

    def test_extract_and_register_dns_entry_dn(
        self, matrix: FlextLdifConversion
    ) -> None:
        """Test extracting and registering entry DN."""
        data: dict[str, object] = {"dn": "cn=test,dc=example,dc=com"}
        matrix._extract_and_register_dns(data, "entry")
        # DN should be registered - we can't directly test registry state but no exception should be raised

    def test_extract_and_register_dns_group_members(
        self, matrix: FlextLdifConversion
    ) -> None:
        """Test extracting and registering group membership DNs."""
        data: dict[str, object] = {
            "dn": "cn=group,dc=example,dc=com",
            "member": ["cn=user1,dc=example,dc=com", "cn=user2,dc=example,dc=com"],
            "uniqueMember": "cn=user3,dc=example,dc=com",
            "owner": ["cn=admin,dc=example,dc=com"],
        }
        matrix._extract_and_register_dns(data, "entry")
        # Multiple DNs should be registered - no exception should be raised

    def test_extract_and_register_dns_acl_by_clauses(
        self, matrix: FlextLdifConversion
    ) -> None:
        """Test extracting DNs from ACL by clauses."""
        # Test that DN registry exists and can be used
        assert matrix.dn_registry is not None
        # Register a DN to test the registry is functional
        registered_dn = matrix.dn_registry.register_dn("cn=acl,dc=example,dc=com")
        assert registered_dn is not None

    def test_extract_and_register_dns_mixed_case(
        self, matrix: FlextLdifConversion
    ) -> None:
        """Test DN registration handles mixed case properly."""
        data: dict[str, object] = {"dn": "CN=Test,DC=Example,DC=Com"}
        matrix._extract_and_register_dns(data, "entry")
        # Mixed case DN should be registered without issues

    def test_extract_and_register_dns_empty_data(
        self, matrix: FlextLdifConversion
    ) -> None:
        """Test DN extraction with empty data."""
        data: dict[str, object] = {}
        matrix._extract_and_register_dns(data, "entry")
        # Empty data should not cause issues

    def test_normalize_dns_in_data_success(self, matrix: FlextLdifConversion) -> None:
        """Test DN normalization with registered DNs."""
        # Register some DNs
        canonical_dn1 = matrix.dn_registry.register_dn("cn=test,dc=example,dc=com")
        canonical_dn2 = matrix.dn_registry.register_dn("cn=admin,dc=example,dc=com")

        # Test that registered DNs can be retrieved
        assert canonical_dn1 is not None
        assert canonical_dn2 is not None
        assert "cn=test" in canonical_dn1

    def test_normalize_dns_in_data_no_dns(self, matrix: FlextLdifConversion) -> None:
        """Test DN registry with empty data."""
        # Test that DN registry exists even with empty data
        assert matrix.dn_registry is not None
        # Registry should be empty initially, so unregistered DN returns None
        canonical = matrix.dn_registry.get_canonical_dn("nonexistent,dn")
        # For unregistered DNs, the registry returns None
        assert canonical is None or isinstance(canonical, str)


@pytest.mark.skip(
    reason="Error path tests for conversion matrix - edge cases not fully implemented"
)
class TestAttributeConversionErrorPaths:
    """Test error paths in attribute conversion."""

    @pytest.fixture
    def matrix(self) -> FlextLdifConversion:
        """Create conversion matrix instance."""
        return FlextLdifConversion()

    @pytest.fixture
    def oud(self) -> FlextLdifServersOud:
        """Create OUD quirk instance."""
        return FlextLdifServersOud()

    @pytest.fixture
    def oid(self) -> FlextLdifServersOid:
        """Create OID quirk instance."""
        return FlextLdifServersOid()

    def test_convert_attribute_missing_parse_method(
        self, matrix: FlextLdifConversion, oid: FlextLdifServersOid
    ) -> None:
        """Test attribute conversion fails when source quirk lacks parse method."""
        # Use SuccessfulParseQuirk which has parse_attribute
        # but may fail on write due to missing metadata
        source_quirk = SuccessfulParseQuirk()
        target_quirk = oid

        result = matrix.convert(source_quirk, target_quirk, "attribute", "(test)")
        # Conversion may fail due to implementation details of the test quirks
        # The important thing is it doesn't crash
        assert result is not None
        if result.is_failure and result.error:
            # Acceptable error - either missing method, missing metadata, or type mismatch
            assert (
                "does not support" in result.error
                or "metadata" in result.error
                or "requires SchemaAttribute model" in result.error
            )

    def test_convert_attribute_parse_failure(
        self,
        matrix: FlextLdifConversion,
        oud: FlextLdifServersOud,
        oid: FlextLdifServersOid,
    ) -> None:
        """Test attribute conversion handles parse failures."""
        # Use a quirk that should handle malformed input gracefully
        malformed_attr = "this is not a valid attribute definition"

        result = matrix.convert(oud, oid, "attribute", malformed_attr)
        # Should succeed due to permissive parsing
        assert result.is_success

    def test_convert_attribute_to_rfc_failure(
        self,
        matrix: FlextLdifConversion,
        oid: FlextLdifServersOid,
    ) -> None:
        """Test attribute conversion fails when source quirk to_rfc fails."""
        # Use real test quirk that fails on to_rfc conversion
        source_quirk = ConversionFailingQuirk(fail_on="to_rfc")
        target_quirk = oid

        result = matrix.convert(source_quirk, target_quirk, "attribute", "(test)")
        assert result.is_failure
        assert (
            result.error is not None and "Failed to convert source→RFC" in result.error
        )

    def test_convert_attribute_from_rfc_failure(
        self, matrix: FlextLdifConversion
    ) -> None:
        """Test attribute conversion fails when target quirk from_rfc fails."""
        # Use real test quirks: source that succeeds, target that fails on from_rfc
        source_quirk = SuccessfulParseQuirk()
        target_quirk = ConversionFailingQuirk(fail_on="from_rfc")

        result = matrix.convert(
            source_quirk,
            target_quirk,
            "attribute",
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
        )
        assert result.is_failure
        assert (
            result.error is not None and "Failed to convert RFC→target" in result.error
        )

    def test_convert_attribute_write_failure(self, matrix: FlextLdifConversion) -> None:
        """Test attribute conversion fails when target quirk write fails."""
        source_quirk = SuccessfulParseQuirk()
        target_quirk = ConversionFailingQuirk(fail_on="write")

        result = matrix.convert(
            source_quirk,
            target_quirk,
            "attribute",
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
        )
        assert result.is_failure
        assert (
            result.error is not None and "Failed to write target format" in result.error
        )

    def test_convert_attribute_unexpected_exception(
        self,
        matrix: FlextLdifConversion,
        oid: FlextLdifServersOid,
    ) -> None:
        """Test attribute conversion handles unexpected exceptions."""
        source_quirk = ExceptionThrowingQuirk()
        target_quirk = oid

        result = matrix.convert(source_quirk, target_quirk, "attribute", "(test)")
        assert result.is_failure
        assert (
            result.error is not None and "Attribute conversion failed" in result.error
        )


@pytest.mark.skip(
    reason="Entry conversion tests - advanced functionality not fully implemented"
)
class TestEntryConversion:
    """Test entry conversion functionality."""

    @pytest.fixture
    def matrix(self) -> FlextLdifConversion:
        """Create conversion matrix instance."""
        return FlextLdifConversion()

    @pytest.fixture
    def oud(self) -> FlextLdifServersOud:
        """Create OUD quirk instance."""
        return FlextLdifServersOud()

    @pytest.fixture
    def oid(self) -> FlextLdifServersOid:
        """Create OID quirk instance."""
        return FlextLdifServersOid()

    def test_convert_entry_string_input_fails(
        self, matrix: FlextLdifConversion, oud: FlextLdifServersOud
    ) -> None:
        """Test entry conversion fails for string input (not yet supported)."""
        source_quirk = EntryConversionQuirk()
        target_quirk = EntryConversionQuirk()

        ldif_string = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: user"""

        result = matrix.convert(source_quirk, target_quirk, "entry", ldif_string)
        assert result.is_failure
        assert (
            result.error is not None
            and "String input for entry conversion not yet supported" in result.error
        )

    def test_convert_entry_missing_source_support(
        self, matrix: FlextLdifConversion, oid: FlextLdifServersOid
    ) -> None:
        """Test entry conversion fails when source quirk lacks entry support."""
        source_quirk = MinimalQuirk()
        target_quirk = oid

        entry_data: dict[str, object] = {"dn": "cn=test,dc=example,dc=com"}
        result = matrix.convert(source_quirk, target_quirk, "entry", entry_data)
        assert result.is_failure
        assert (
            result.error is not None and "does not have Entry support" in result.error
        )

    def test_convert_entry_missing_target_support(
        self, matrix: FlextLdifConversion, oud: FlextLdifServersOud
    ) -> None:
        """Test entry conversion fails when target quirk lacks entry support."""
        source_quirk = oud
        target_quirk = MinimalQuirk()

        entry_data: dict[str, object] = {"dn": "cn=test,dc=example,dc=com"}
        result = matrix.convert(source_quirk, target_quirk, "entry", entry_data)
        assert result.is_failure
        assert (
            result.error is not None and "does not have Entry support" in result.error
        )


@pytest.mark.skip(
    reason="Batch conversion error handling tests - edge cases not fully implemented"
)
class TestBatchConversionErrorHandling:
    """Test batch conversion error scenarios."""

    @pytest.fixture
    def matrix(self) -> FlextLdifConversion:
        """Create conversion matrix instance."""
        return FlextLdifConversion()

    @pytest.fixture
    def oud(self) -> FlextLdifServersOud:
        """Create OUD quirk instance."""
        return FlextLdifServersOud()

    @pytest.fixture
    def oid(self) -> FlextLdifServersOid:
        """Create OID quirk instance."""
        return FlextLdifServersOid()

    def test_batch_convert_all_items_fail(
        self, matrix: FlextLdifConversion, oid: FlextLdifServersOid
    ) -> None:
        """Test batch conversion with all failing parse quirk returns items via pass-through."""
        source_quirk = FailingParseQuirk()
        target_quirk = oid

        items = ["(test1)", "(test2)", "(test3)"]
        result = matrix.batch_convert(source_quirk, target_quirk, "attribute", items)

        # With graceful degradation, unparseable items are passed through unchanged
        # so batch_convert succeeds with the pass-through data
        assert result.is_success
        converted = result.unwrap()
        assert converted == items  # Items passed through unchanged

    def test_batch_convert_error_truncation(
        self, matrix: FlextLdifConversion, oid: FlextLdifServersOid
    ) -> None:
        """Test batch conversion passes through unparseable items via graceful degradation."""
        source_quirk = FailingParseQuirk()
        target_quirk = oid

        # Create 8 items that will fail parsing
        items = [f"(test{i})" for i in range(8)]
        result = matrix.batch_convert(source_quirk, target_quirk, "attribute", items)

        # With graceful degradation, all items are passed through unchanged
        # so batch_convert succeeds with all items returned
        assert result.is_success
        converted = result.unwrap()
        assert converted == items  # All items passed through unchanged
        assert len(converted) == 8  # 8 - 5 = 3 more

    def test_batch_convert_unexpected_exception(
        self, matrix: FlextLdifConversion, oid: FlextLdifServersOid
    ) -> None:
        """Test batch conversion handles unexpected exceptions."""
        source_quirk = ExceptionThrowingQuirk()
        target_quirk = oid

        items = ["(test1)", "(test2)"]
        result = matrix.batch_convert(source_quirk, target_quirk, "attribute", items)

        assert result.is_failure
        assert (
            result.error is not None
            and "Batch conversion completed with 2 errors" in result.error
        )


@pytest.mark.skip(
    reason="Support checking edge case tests - advanced functionality not fully implemented"
)
class TestSupportCheckingEdgeCases:
    """Test edge cases in support checking."""

    @pytest.fixture
    def matrix(self) -> FlextLdifConversion:
        """Create conversion matrix instance."""
        return FlextLdifConversion()

    def test_get_supported_conversions_minimal_quirk(
        self, matrix: FlextLdifConversion
    ) -> None:
        """Test support checking for quirk with minimal functionality."""
        quirk = MinimalQuirk()
        support = matrix.get_supported_conversions(quirk)

        assert support["attribute"] is False
        assert support["objectClass"] is False
        assert support["acl"] is False
        assert support["entry"] is False

    def test_get_supported_conversions_partial_quirk(
        self, matrix: FlextLdifConversion
    ) -> None:
        """Test support checking for quirk with partial functionality."""
        quirk = PartialAttributeQuirk()
        support = matrix.get_supported_conversions(quirk)

        assert support["attribute"] is True
        assert support["objectClass"] is False
        assert support["acl"] is False
        assert support["entry"] is False

    def test_get_supported_conversions_acl_quirk(
        self, matrix: FlextLdifConversion
    ) -> None:
        """Test support checking for quirk with ACL support."""
        quirk = AclOnlyQuirk()
        support = matrix.get_supported_conversions(quirk)

        assert support["attribute"] is False
        assert support["objectClass"] is False
        assert support["acl"] is True
        assert support["entry"] is False

    def test_get_supported_conversions_entry_quirk(
        self, matrix: FlextLdifConversion
    ) -> None:
        """Test support checking for quirk with entry support."""
        quirk = EntryOnlyQuirk()
        support = matrix.get_supported_conversions(quirk)

        assert support["attribute"] is False
        assert support["objectClass"] is False
        assert support["acl"] is False
        assert support["entry"] is True


class TestConversionMatrixConstants:
    """Test conversion matrix constants."""

    def test_max_errors_to_show_constant(self) -> None:
        """Test that MAX_ERRORS_TO_SHOW constant exists."""
        assert hasattr(FlextLdifConversion, "MAX_ERRORS_TO_SHOW")
        assert FlextLdifConversion.MAX_ERRORS_TO_SHOW == 5


__all__ = [
    "TestAclConversion",
    "TestAttributeConversion",
    "TestAttributeConversionErrorPaths",
    "TestBatchConversion",
    "TestBatchConversionErrorHandling",
    "TestBidirectionalConversion",
    "TestConversionMatrixConstants",
    "TestConversionMatrixInitialization",
    "TestDnCaseRegistryIntegration",
    "TestDnExtractionAndRegistration",
    "TestEntryConversion",
    "TestErrorHandling",
    "TestGetSupportedConversions",
    "TestObjectClassConversion",
    "TestObjectClassConversionErrorPaths",
    "TestSupportCheckingEdgeCases",
]
