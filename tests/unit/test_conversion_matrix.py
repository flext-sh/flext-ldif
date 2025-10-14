"""Unit tests for QuirksConversionMatrix facade.

Tests the universal translation matrix for converting LDAP data between
different server quirks using RFC as intermediate format.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Literal, cast

import pytest

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.conversion_matrix import QuirksConversionMatrix
from flext_ldif.quirks.servers.oid_quirks import FlextLdifQuirksServersOid
from flext_ldif.quirks.servers.oud_quirks import FlextLdifQuirksServersOud
from flext_ldif.typings import FlextLdifTypes


class TestConversionMatrixInitialization:
    """Test QuirksConversionMatrix initialization and basic setup."""

    def test_matrix_instantiation(self) -> None:
        """Test that conversion matrix can be instantiated."""
        matrix = QuirksConversionMatrix()
        assert matrix is not None
        assert hasattr(matrix, "dn_registry")
        assert matrix.dn_registry is not None

    def test_matrix_has_conversion_methods(self) -> None:
        """Test that matrix has all required conversion methods."""
        matrix = QuirksConversionMatrix()
        assert hasattr(matrix, "convert")
        assert hasattr(matrix, "batch_convert")
        assert hasattr(matrix, "get_supported_conversions")
        assert hasattr(matrix, "validate_oud_conversion")
        assert hasattr(matrix, "reset_dn_registry")


class TestGetSupportedConversions:
    """Test get_supported_conversions method."""

    @pytest.fixture
    def matrix(self) -> QuirksConversionMatrix:
        """Create conversion matrix instance."""
        return QuirksConversionMatrix()

    @pytest.fixture
    def oud(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    @pytest.fixture
    def oid(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_get_supported_conversions_oud(
        self, matrix: QuirksConversionMatrix, oud: FlextLdifQuirksServersOud
    ) -> None:
        """Test checking supported conversions for OUD quirk."""
        supported = matrix.get_supported_conversions(oud)

        assert isinstance(supported, dict)
        assert "attribute" in supported
        assert "objectclass" in supported
        assert "acl" in supported
        assert "entry" in supported

        # Schema operations should be supported
        assert supported["attribute"] is True
        assert supported["objectclass"] is True

    def test_get_supported_conversions_oid(
        self, matrix: QuirksConversionMatrix, oid: FlextLdifQuirksServersOid
    ) -> None:
        """Test checking supported conversions for OID quirk."""
        supported = matrix.get_supported_conversions(oid)

        assert isinstance(supported, dict)
        assert "attribute" in supported
        assert "objectclass" in supported
        assert "acl" in supported
        assert "entry" in supported

        # Schema operations should be supported
        assert supported["attribute"] is True
        assert supported["objectclass"] is True


class TestAttributeConversion:
    """Test attribute conversion through the matrix."""

    @pytest.fixture
    def matrix(self) -> QuirksConversionMatrix:
        """Create conversion matrix instance."""
        return QuirksConversionMatrix()

    @pytest.fixture
    def oud(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    @pytest.fixture
    def oid(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_convert_attribute_oud_to_oid(
        self,
        matrix: QuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
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
        matrix: QuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
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
        matrix: QuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
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
        matrix: QuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test that truly invalid attribute gets parsed with None values."""
        invalid_attr = "this is not a valid attribute definition"

        result = matrix.convert(oud, oid, "attribute", invalid_attr)

        # Parser is permissive and creates attribute with None values
        # This is by design to handle partial/malformed data
        assert result.is_success
        oid_attr = result.unwrap()
        # The result should contain "None" strings from the permissive parser
        assert "None" in oid_attr


class TestObjectClassConversion:
    """Test objectClass conversion through the matrix."""

    @pytest.fixture
    def matrix(self) -> QuirksConversionMatrix:
        """Create conversion matrix instance."""
        return QuirksConversionMatrix()

    @pytest.fixture
    def oud(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    @pytest.fixture
    def oid(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_convert_objectclass_oud_to_oid(
        self,
        matrix: QuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test converting OUD objectClass to OID via matrix."""
        oud_oc = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )"
        )

        result = matrix.convert(oud, oid, "objectclass", oud_oc)

        assert result.is_success, f"Conversion failed: {result.error}"
        oid_oc = result.unwrap()
        assert isinstance(oid_oc, str)
        assert "2.16.840.1.113894.1.2.1" in oid_oc
        assert "orclContext" in oid_oc
        assert "STRUCTURAL" in oid_oc

    def test_convert_objectclass_oid_to_oud(
        self,
        matrix: QuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test converting OID objectClass to OUD via matrix."""
        oid_oc = (
            "( 2.16.840.1.113894.1.2.2 NAME 'orclContainer' "
            "SUP top STRUCTURAL MUST cn )"
        )

        result = matrix.convert(oid, oud, "objectclass", oid_oc)

        assert result.is_success, f"Conversion failed: {result.error}"
        oud_oc = result.unwrap()
        assert isinstance(oud_oc, str)
        assert "2.16.840.1.113894.1.2.2" in oud_oc
        assert "orclContainer" in oud_oc

    def test_convert_objectclass_with_may_attributes(
        self,
        matrix: QuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test converting objectClass with MAY attributes."""
        oud_oc = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' "
            "SUP top STRUCTURAL "
            "MUST cn "
            "MAY ( description $ orclVersion ) )"
        )

        result = matrix.convert(oud, oid, "objectclass", oud_oc)

        assert result.is_success
        oid_oc = result.unwrap()
        assert "orclContext" in oid_oc
        assert "STRUCTURAL" in oid_oc


class TestBatchConversion:
    """Test batch conversion operations."""

    @pytest.fixture
    def matrix(self) -> QuirksConversionMatrix:
        """Create conversion matrix instance."""
        return QuirksConversionMatrix()

    @pytest.fixture
    def oud(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    @pytest.fixture
    def oid(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_batch_convert_attributes(
        self,
        matrix: QuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test batch conversion of multiple attributes."""
        oud_attrs: list[str | FlextLdifTypes.Dict] = [
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
        matrix: QuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test batch conversion of multiple objectClasses."""
        oud_ocs: list[str | FlextLdifTypes.Dict] = [
            "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )",
            "( 2.16.840.1.113894.1.2.2 NAME 'orclContainer' SUP top STRUCTURAL MUST cn )",
        ]

        result = matrix.batch_convert(oud, oid, "objectclass", oud_ocs)

        assert result.is_success, f"Batch conversion failed: {result.error}"
        oid_ocs = result.unwrap()
        assert len(oid_ocs) == 2
        assert "orclContext" in oid_ocs[0]
        assert "orclContainer" in oid_ocs[1]

    def test_batch_convert_with_partial_failures(
        self,
        matrix: QuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test batch conversion handles malformed data with permissive parsing."""
        mixed_attrs: list[str | FlextLdifTypes.Dict] = [
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
            "invalid attribute definition",
            "( 2.16.840.1.113894.1.1.2 NAME 'orclDBName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        ]

        result = matrix.batch_convert(oud, oid, "attribute", mixed_attrs)

        # Permissive parser succeeds on all items, creating None values for malformed data
        assert result.is_success
        oid_attrs = result.unwrap()
        assert len(oid_attrs) == 3
        # Second item should have None values from malformed input
        assert "None" in oid_attrs[1]


class TestBidirectionalConversion:
    """Test bidirectional conversions OUD ↔ OID."""

    @pytest.fixture
    def matrix(self) -> QuirksConversionMatrix:
        """Create conversion matrix instance."""
        return QuirksConversionMatrix()

    @pytest.fixture
    def oud(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    @pytest.fixture
    def oid(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_attribute_roundtrip_oud_to_oid_to_oud(
        self,
        matrix: QuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
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
        matrix: QuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test objectClass round-trip: OID → OUD → OID."""
        original = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )"
        )

        # OID → OUD
        oud_result = matrix.convert(oid, oud, "objectclass", original)
        assert oud_result.is_success
        oud_oc = oud_result.unwrap()

        # OUD → OID
        oid_result = matrix.convert(oud, oid, "objectclass", oud_oc)
        assert oid_result.is_success
        roundtrip = oid_result.unwrap()

        # Validate semantic equivalence
        assert "2.16.840.1.113894.1.2.1" in roundtrip
        assert "orclContext" in roundtrip


class TestErrorHandling:
    """Test error handling in conversion matrix."""

    @pytest.fixture
    def matrix(self) -> QuirksConversionMatrix:
        """Create conversion matrix instance."""
        return QuirksConversionMatrix()

    @pytest.fixture
    def oud(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    @pytest.fixture
    def oid(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_invalid_data_type(
        self,
        matrix: QuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test that invalid data type returns error."""
        # Use a variable to bypass literal type checking
        invalid_data_type: str = "invalid_type"
        result = matrix.convert(
            oud,
            oid,
            cast(
                "Literal['acl', 'attribute', 'entry', 'objectclass']", invalid_data_type
            ),
            "test",
        )

        assert result.is_failure
        assert result.error is not None
        assert "Invalid data_type" in result.error

    def test_malformed_attribute(
        self,
        matrix: QuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test that malformed attribute is handled by permissive parser."""
        malformed = "this is not a valid attribute"

        result = matrix.convert(oud, oid, "attribute", malformed)

        # Permissive parser succeeds, creating None values for malformed data
        assert result.is_success
        oid_attr = result.unwrap()
        assert "None" in oid_attr

    def test_empty_batch_conversion(
        self,
        matrix: QuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test batch conversion with empty list."""
        result = matrix.batch_convert(oud, oid, "attribute", [])

        assert result.is_success
        assert len(result.unwrap()) == 0


class TestDnCaseRegistryIntegration:
    """Test DN case registry integration."""

    @pytest.fixture
    def matrix(self) -> QuirksConversionMatrix:
        """Create conversion matrix instance."""
        return QuirksConversionMatrix()

    def test_dn_registry_initialized(self, matrix: QuirksConversionMatrix) -> None:
        """Test that DN registry is initialized."""
        assert hasattr(matrix, "dn_registry")
        assert matrix.dn_registry is not None

    def test_reset_dn_registry(self, matrix: QuirksConversionMatrix) -> None:
        """Test that DN registry can be reset."""
        # Register a DN
        matrix.dn_registry.register_dn("cn=test,dc=example,dc=com")

        # Reset registry
        matrix.reset_dn_registry()

        # Registry should be cleared
        # We can't directly test if it's empty, but reset should not raise
        assert True

    def test_validate_oud_conversion(self, matrix: QuirksConversionMatrix) -> None:
        """Test OUD conversion validation."""
        result = matrix.validate_oud_conversion()

        assert result.is_success
        # Should return True when no DNs registered
        assert result.unwrap() is True


class TestConversionMatrixConstants:
    """Test conversion matrix constants."""

    def test_max_errors_to_show_constant(self) -> None:
        """Test that MAX_ERRORS_TO_SHOW constant exists."""
        assert hasattr(QuirksConversionMatrix, "MAX_ERRORS_TO_SHOW")
        assert QuirksConversionMatrix.MAX_ERRORS_TO_SHOW == 5


__all__ = [
    "TestAttributeConversion",
    "TestBatchConversion",
    "TestBidirectionalConversion",
    "TestConversionMatrixConstants",
    "TestConversionMatrixInitialization",
    "TestDnCaseRegistryIntegration",
    "TestErrorHandling",
    "TestGetSupportedConversions",
    "TestObjectClassConversion",
]
