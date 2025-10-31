"""Unit tests for Syntax Service - RFC 4517 Validation and Resolution.

Comprehensive testing of FlextLdifSyntaxService for OID validation,
syntax resolution, and type-specific value validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif.services.syntax import FlextLdifSyntaxService


class TestSyntaxServiceInitialization:
    """Test Syntax service initialization and status checking."""

    def test_service_initialization(self) -> None:
        """Test Syntax service can be instantiated."""
        service = FlextLdifSyntaxService()
        assert service is not None

    def test_execute_returns_status(self) -> None:
        """Test execute returns service status."""
        service = FlextLdifSyntaxService()
        result = service.execute()

        assert result.is_success
        status = result.unwrap()
        assert status["service"] == "SyntaxService"
        assert status["status"] == "operational"
        assert status["rfc_compliance"] == "RFC 4517"
        assert status["total_syntaxes"] > 0
        assert status["common_syntaxes"] > 0


class TestOidValidation:
    """Test OID format validation."""

    def test_validate_valid_boolean_oid(self) -> None:
        """Test validation of valid Boolean syntax OID."""
        service = FlextLdifSyntaxService()
        result = service.validate_oid("1.3.6.1.4.1.1466.115.121.1.7")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_valid_directory_string_oid(self) -> None:
        """Test validation of valid Directory String OID."""
        service = FlextLdifSyntaxService()
        result = service.validate_oid("1.3.6.1.4.1.1466.115.121.1.15")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_empty_oid(self) -> None:
        """Test validation of empty OID."""
        service = FlextLdifSyntaxService()
        result = service.validate_oid("")

        assert result.is_success
        assert result.unwrap() is False

    def test_validate_invalid_oid_format(self) -> None:
        """Test validation of invalid OID format."""
        service = FlextLdifSyntaxService()
        result = service.validate_oid("not.an.oid")

        assert result.is_success
        assert result.unwrap() is False

    def test_validate_oid_with_letters(self) -> None:
        """Test validation rejects OIDs with letters."""
        service = FlextLdifSyntaxService()
        result = service.validate_oid("1.3.6.a.1.b.1")

        assert result.is_success
        assert result.unwrap() is False

    def test_validate_oid_single_number(self) -> None:
        """Test validation of single numeric OID."""
        service = FlextLdifSyntaxService()
        result = service.validate_oid("2")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_very_long_valid_oid(self) -> None:
        """Test validation of very long but valid OID."""
        service = FlextLdifSyntaxService()
        result = service.validate_oid("1.2.3.4.5.6.7.8.9.10.11.12.13.14.15")

        assert result.is_success
        assert result.unwrap() is True


class TestRfc4517Standard:
    """Test RFC 4517 standard OID detection."""

    def test_is_rfc4517_boolean(self) -> None:
        """Test detection of RFC 4517 Boolean OID."""
        service = FlextLdifSyntaxService()
        result = service.is_rfc4517_standard("1.3.6.1.4.1.1466.115.121.1.7")

        assert result.is_success
        assert result.unwrap() is True

    def test_is_rfc4517_directory_string(self) -> None:
        """Test detection of RFC 4517 Directory String OID."""
        service = FlextLdifSyntaxService()
        result = service.is_rfc4517_standard("1.3.6.1.4.1.1466.115.121.1.15")

        assert result.is_success
        assert result.unwrap() is True

    def test_is_not_rfc4517_oracle_oid(self) -> None:
        """Test detection of non-RFC 4517 OID (Oracle)."""
        service = FlextLdifSyntaxService()
        result = service.is_rfc4517_standard("2.16.840.1.113894.1.1.1")

        assert result.is_success
        assert result.unwrap() is False

    def test_is_rfc4517_empty_oid(self) -> None:
        """Test detection with empty OID."""
        service = FlextLdifSyntaxService()
        result = service.is_rfc4517_standard("")

        assert result.is_success
        assert result.unwrap() is False


class TestOidLookup:
    """Test OID to name lookup."""

    def test_lookup_boolean_oid(self) -> None:
        """Test looking up Boolean syntax name."""
        service = FlextLdifSyntaxService()
        result = service.lookup_oid("1.3.6.1.4.1.1466.115.121.1.7")

        assert result.is_success
        name = result.unwrap()
        assert name == "boolean"

    def test_lookup_directory_string_oid(self) -> None:
        """Test looking up Directory String syntax name."""
        service = FlextLdifSyntaxService()
        result = service.lookup_oid("1.3.6.1.4.1.1466.115.121.1.15")

        assert result.is_success
        name = result.unwrap()
        assert name == "directory_string"

    def test_lookup_integer_oid(self) -> None:
        """Test looking up Integer syntax name (IA5 String)."""
        service = FlextLdifSyntaxService()
        result = service.lookup_oid("1.3.6.1.4.1.1466.115.121.1.27")

        assert result.is_success
        name = result.unwrap()
        assert name == "ia5_string"

    def test_lookup_unknown_oid(self) -> None:
        """Test lookup of unknown OID returns None."""
        service = FlextLdifSyntaxService()
        result = service.lookup_oid("9.9.9.9.9.9")

        assert result.is_success
        assert result.unwrap() is None

    def test_lookup_empty_oid(self) -> None:
        """Test lookup of empty OID returns None."""
        service = FlextLdifSyntaxService()
        result = service.lookup_oid("")

        assert result.is_success
        assert result.unwrap() is None


class TestNameLookup:
    """Test name to OID lookup."""

    def test_lookup_boolean_name(self) -> None:
        """Test looking up Boolean syntax OID."""
        service = FlextLdifSyntaxService()
        result = service.lookup_name("boolean")

        assert result.is_success
        oid = result.unwrap()
        assert oid == "1.3.6.1.4.1.1466.115.121.1.7"

    def test_lookup_directory_string_name(self) -> None:
        """Test looking up Directory String syntax OID."""
        service = FlextLdifSyntaxService()
        result = service.lookup_name("directory_string")

        assert result.is_success
        oid = result.unwrap()
        assert oid == "1.3.6.1.4.1.1466.115.121.1.21"

    def test_lookup_integer_name(self) -> None:
        """Test looking up IA5 String syntax OID."""
        service = FlextLdifSyntaxService()
        result = service.lookup_name("ia5_string")

        assert result.is_success
        oid = result.unwrap()
        assert oid == "1.3.6.1.4.1.1466.115.121.1.27"

    def test_lookup_unknown_name(self) -> None:
        """Test lookup of unknown name returns None."""
        service = FlextLdifSyntaxService()
        result = service.lookup_name("Unknown Syntax Type")

        assert result.is_success
        assert result.unwrap() is None

    def test_lookup_empty_name(self) -> None:
        """Test lookup of empty name returns None."""
        service = FlextLdifSyntaxService()
        result = service.lookup_name("")

        assert result.is_success
        assert result.unwrap() is None


class TestResolveSyntax:
    """Test syntax resolution to Syntax model."""

    def test_resolve_boolean_syntax(self) -> None:
        """Test resolving Boolean syntax."""
        service = FlextLdifSyntaxService()
        result = service.resolve_syntax("1.3.6.1.4.1.1466.115.121.1.7")

        assert result.is_success
        syntax = result.unwrap()
        assert syntax.oid == "1.3.6.1.4.1.1466.115.121.1.7"
        assert syntax.name == "boolean"
        assert syntax.is_rfc4517_standard is True

    def test_resolve_syntax_with_manual_name(self) -> None:
        """Test resolving syntax with manually provided name."""
        service = FlextLdifSyntaxService()
        result = service.resolve_syntax(
            "1.3.6.1.4.1.1466.115.121.1.7",
            name="Custom Boolean",
        )

        assert result.is_success
        syntax = result.unwrap()
        assert syntax.name == "Custom Boolean"

    def test_resolve_syntax_with_description(self) -> None:
        """Test resolving syntax with description."""
        service = FlextLdifSyntaxService()
        result = service.resolve_syntax(
            "1.3.6.1.4.1.1466.115.121.1.7",
            desc="Boolean value syntax",
        )

        assert result.is_success
        syntax = result.unwrap()
        assert syntax.desc == "Boolean value syntax"

    def test_resolve_syntax_with_server_type(self) -> None:
        """Test resolving syntax with server-specific type."""
        service = FlextLdifSyntaxService()
        result = service.resolve_syntax(
            "1.3.6.1.4.1.1466.115.121.1.7",
            server_type="oid",
        )

        assert result.is_success
        syntax = result.unwrap()
        assert syntax.metadata is not None
        assert syntax.metadata.quirk_type == "oid"

    def test_resolve_unknown_oid_succeeds(self) -> None:
        """Test resolving syntax with unknown but valid OID format succeeds."""
        service = FlextLdifSyntaxService()
        result = service.resolve_syntax("9.9.9.9.9.9")

        assert result.is_success
        syntax = result.unwrap()
        assert syntax.oid == "9.9.9.9.9.9"


class TestValueValidation:
    """Test value validation against syntax types."""

    def test_validate_boolean_true(self) -> None:
        """Test validating Boolean value TRUE."""
        service = FlextLdifSyntaxService()
        result = service.validate_value(
            "TRUE",
            "1.3.6.1.4.1.1466.115.121.1.7",
        )

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_boolean_false(self) -> None:
        """Test validating Boolean value FALSE."""
        service = FlextLdifSyntaxService()
        result = service.validate_value(
            "FALSE",
            "1.3.6.1.4.1.1466.115.121.1.7",
        )

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_boolean_lowercase_true(self) -> None:
        """Test validating Boolean value with lowercase."""
        service = FlextLdifSyntaxService()
        result = service.validate_value(
            "true",
            "1.3.6.1.4.1.1466.115.121.1.7",
        )

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_boolean_invalid(self) -> None:
        """Test validating invalid Boolean value."""
        service = FlextLdifSyntaxService()
        result = service.validate_value(
            "MAYBE",
            "1.3.6.1.4.1.1466.115.121.1.7",
        )

        assert result.is_success
        # Invalid boolean value should return False (validation fails)
        assert result.unwrap() is False

    def test_validate_integer_via_numeric_string(self) -> None:
        """Test validating numeric string (IA5 String defaults to string validation)."""
        service = FlextLdifSyntaxService()
        result = service.validate_value(
            "12345",
            "1.3.6.1.4.1.1466.115.121.1.27",
        )

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_numeric_negative(self) -> None:
        """Test validating negative numeric value."""
        service = FlextLdifSyntaxService()
        result = service.validate_value(
            "-999",
            "1.3.6.1.4.1.1466.115.121.1.27",
        )

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_string_value(self) -> None:
        """Test validating string value (default is string validation)."""
        service = FlextLdifSyntaxService()
        result = service.validate_value(
            "not_a_number",
            "1.3.6.1.4.1.1466.115.121.1.27",
        )

        assert result.is_success
        # String validation passes for string types
        assert result.unwrap() is True

    def test_validate_empty_value(self) -> None:
        """Test validating empty value (should pass)."""
        service = FlextLdifSyntaxService()
        result = service.validate_value(
            "",
            "1.3.6.1.4.1.1466.115.121.1.7",
        )

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_unknown_syntax_oid_uses_default(self) -> None:
        """Test validating value against unknown syntax OID uses default validation."""
        service = FlextLdifSyntaxService()
        result = service.validate_value(
            "value",
            "9.9.9.9.9.9",
        )

        assert result.is_success
        # Unknown syntax defaults to string validation
        assert result.unwrap() is True


class TestSyntaxCategory:
    """Test syntax type category retrieval."""

    def test_get_category_boolean(self) -> None:
        """Test getting category for Boolean syntax."""
        service = FlextLdifSyntaxService()
        result = service.get_syntax_category("1.3.6.1.4.1.1466.115.121.1.7")

        assert result.is_success
        category = result.unwrap()
        assert category == "boolean"  # Boolean syntax OID

    def test_get_category_ia5_string(self) -> None:
        """Test getting category for IA5 String syntax."""
        service = FlextLdifSyntaxService()
        result = service.get_syntax_category("1.3.6.1.4.1.1466.115.121.1.27")

        assert result.is_success
        category = result.unwrap()
        assert category == "string"  # Default type_category

    def test_get_category_directory_string(self) -> None:
        """Test getting category for Directory String syntax."""
        service = FlextLdifSyntaxService()
        result = service.get_syntax_category("1.3.6.1.4.1.1466.115.121.1.15")

        assert result.is_success
        category = result.unwrap()
        assert category == "string"

    def test_get_category_unknown_oid_succeeds(self) -> None:
        """Test getting category for unknown OID (succeeds with default)."""
        service = FlextLdifSyntaxService()
        result = service.get_syntax_category("9.9.9.9.9.9")

        assert result.is_success
        category = result.unwrap()
        assert category == "string"  # Default


class TestListSyntaxes:
    """Test listing available syntaxes."""

    def test_list_common_syntaxes(self) -> None:
        """Test listing all common RFC 4517 syntaxes."""
        service = FlextLdifSyntaxService()
        result = service.list_common_syntaxes()

        assert result.is_success
        syntaxes = result.unwrap()
        assert isinstance(syntaxes, list)
        assert len(syntaxes) > 0
        assert "1.3.6.1.4.1.1466.115.121.1.7" in syntaxes

    def test_list_syntaxes_sorted(self) -> None:
        """Test that listed syntaxes are sorted."""
        service = FlextLdifSyntaxService()
        result = service.list_common_syntaxes()

        assert result.is_success
        syntaxes = result.unwrap()
        assert syntaxes == sorted(syntaxes)


class TestMultipleServices:
    """Test multiple service instances are independent."""

    def test_multiple_service_instances(self) -> None:
        """Test that multiple service instances don't interfere."""
        service1 = FlextLdifSyntaxService()
        service2 = FlextLdifSyntaxService()

        result1 = service1.validate_oid("1.3.6.1.4.1.1466.115.121.1.7")
        result2 = service2.validate_oid("1.3.6.1.4.1.1466.115.121.1.7")

        assert result1.is_success
        assert result2.is_success
        assert result1.unwrap() is True
        assert result2.unwrap() is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
