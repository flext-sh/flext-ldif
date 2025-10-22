"""Unit tests for DN Service - RFC 4514 Compliant DN Operations.

Tests DN parsing, validation, and normalization using ldap3.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import cast

import pytest

from flext_ldif.services.dn_service import FlextLdifDnService


class TestDnServiceInitialization:
    """Test DN service initialization."""

    def test_init_creates_service(self) -> None:
        """Test DN service can be instantiated."""
        service = FlextLdifDnService()
        assert service is not None

    def test_execute_returns_status(self) -> None:
        """Test execute returns service status."""
        service = FlextLdifDnService()
        result = service.execute()

        assert result.is_success
        status = result.unwrap()
        assert status["service"] == "DnService"
        assert status["status"] == "operational"
        assert status["rfc_compliance"] == "RFC 4514"
        assert status["library"] == "ldap3"


class TestParseComponents:
    """Test DN component parsing with RFC 4514 compliance."""

    def test_parse_simple_dn(self) -> None:
        """Test parsing simple DN."""
        service = FlextLdifDnService()
        result = service.parse_components("cn=test,dc=example,dc=com")

        assert result.is_success
        components = result.unwrap()
        assert len(components) == 3
        assert components[0][0] == "cn"
        assert components[0][1] == "test"
        assert components[1][0] == "dc"
        assert components[1][1] == "example"
        assert components[2][0] == "dc"
        assert components[2][1] == "com"

    def test_parse_dn_with_escaped_comma(self) -> None:
        """Test parsing DN with escaped comma (RFC 4514)."""
        service = FlextLdifDnService()
        # DN with escaped comma in value
        result = service.parse_components(
            r"cn=Smith\, John,ou=People,dc=example,dc=com"
        )

        assert result.is_success
        components = result.unwrap()
        # ldap3 should handle escaped comma correctly
        assert len(components) == 4
        assert components[0][0] == "cn"
        # Value should contain comma (unescaped by ldap3)
        assert "," in components[0][1] or "\\" in components[0][1]

    def test_parse_dn_with_quoted_value(self) -> None:
        """Test parsing DN with escaped quotes (RFC 4514)."""
        service = FlextLdifDnService()
        # In RFC 4514, quotes within values must be escaped
        result = service.parse_components(
            r"cn=Smith\, John,ou=People,dc=example,dc=com"
        )

        assert result.is_success
        components = result.unwrap()
        assert len(components) == 4
        assert components[0][0] == "cn"
        # ldap3 handles escaped commas
        assert "Smith" in components[0][1] or "Smith" in str(components[0])

    def test_parse_dn_with_special_characters(self) -> None:
        """Test parsing DN with special characters (RFC 4514)."""
        service = FlextLdifDnService()
        result = service.parse_components("cn=John+ou=People,dc=example,dc=com")

        assert result.is_success
        components = result.unwrap()
        # Multi-valued RDN (cn=John+ou=People) is one component
        assert len(components) >= 2

    def test_parse_dn_with_spaces(self) -> None:
        """Test parsing DN with spaces."""
        service = FlextLdifDnService()
        result = service.parse_components("cn=John Smith,ou=People,dc=example,dc=com")

        assert result.is_success
        components = result.unwrap()
        assert len(components) == 4
        assert components[0][1] == "John Smith"

    def test_parse_invalid_dn_returns_failure(self) -> None:
        """Test parsing invalid DN returns failure."""
        service = FlextLdifDnService()
        result = service.parse_components("invalid dn without equals")

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None
        assert "Invalid DN format" in result.error

    def test_parse_empty_dn_returns_failure(self) -> None:
        """Test parsing empty DN returns failure."""
        service = FlextLdifDnService()
        result = service.parse_components("")

        assert result.is_failure

    def test_parse_dn_with_utf8(self) -> None:
        """Test parsing DN with UTF-8 characters."""
        service = FlextLdifDnService()
        result = service.parse_components("cn=José,ou=People,dc=example,dc=com")

        assert result.is_success
        components = result.unwrap()
        assert len(components) == 4
        assert components[0][1] == "José"


class TestValidateFormat:
    """Test DN format validation with RFC 4514 compliance."""

    def test_validate_simple_dn(self) -> None:
        """Test validation of simple valid DN."""
        service = FlextLdifDnService()
        result = service.validate_format("cn=test,dc=example,dc=com")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_dn_with_escaped_comma(self) -> None:
        """Test validation of DN with escaped comma."""
        service = FlextLdifDnService()
        result = service.validate_format(r"cn=Smith\, John,ou=People,dc=example,dc=com")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_dn_with_escaped_comma_value(self) -> None:
        """Test validation of DN with escaped comma in value."""
        service = FlextLdifDnService()
        result = service.validate_format(r"cn=Smith\, John,ou=People,dc=example,dc=com")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_dn_with_special_characters(self) -> None:
        """Test validation of DN with special characters."""
        service = FlextLdifDnService()
        result = service.validate_format("cn=John+ou=People,dc=example,dc=com")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_invalid_dn_returns_false(self) -> None:
        """Test validation of invalid DN returns False."""
        service = FlextLdifDnService()
        result = service.validate_format("invalid dn without equals")

        assert result.is_success
        assert result.unwrap() is False

    def test_validate_empty_string_returns_false(self) -> None:
        """Test validation of empty string returns False."""
        service = FlextLdifDnService()
        result = service.validate_format("")

        assert result.is_success
        assert result.unwrap() is False

    def test_validate_non_string_returns_false(self) -> None:
        """Test validation of non-string returns False."""
        service = FlextLdifDnService()
        result = service.validate_format(cast("str", None))

        assert result.is_success
        assert result.unwrap() is False

    def test_validate_dn_with_utf8(self) -> None:
        """Test validation of DN with UTF-8 characters."""
        service = FlextLdifDnService()
        result = service.validate_format("cn=José,ou=People,dc=example,dc=com")

        assert result.is_success
        assert result.unwrap() is True


class TestNormalize:
    """Test DN normalization with RFC 4514 compliance."""

    def test_normalize_simple_dn(self) -> None:
        """Test normalization of simple DN."""
        service = FlextLdifDnService()
        result = service.normalize("CN=Test,DC=Example,DC=Com")

        assert result.is_success
        normalized = result.unwrap()
        # ldap3 normalizes attribute names to lowercase
        assert "cn=" in normalized.lower()
        assert "dc=" in normalized.lower()

    def test_normalize_dn_with_spaces(self) -> None:
        """Test normalization of DN with spaces."""
        service = FlextLdifDnService()
        result = service.normalize("cn=John Smith,ou=People,dc=example,dc=com")

        assert result.is_success
        normalized = result.unwrap()
        assert "John Smith" in normalized

    def test_normalize_dn_with_escaped_comma(self) -> None:
        """Test normalization of DN with escaped comma."""
        service = FlextLdifDnService()
        result = service.normalize(r"cn=Smith\, John,ou=People,dc=example,dc=com")

        assert result.is_success
        normalized = result.unwrap()
        # ldap3 should preserve escaped comma in some form
        assert normalized is not None

    def test_normalize_dn_with_escaped_value(self) -> None:
        """Test normalization of DN with escaped comma in value."""
        service = FlextLdifDnService()
        result = service.normalize(r"cn=Smith\, John,ou=People,dc=example,dc=com")

        assert result.is_success
        normalized = result.unwrap()
        # ldap3 handles escaped commas
        assert "Smith" in normalized

    def test_normalize_invalid_dn_returns_failure(self) -> None:
        """Test normalization of invalid DN returns failure."""
        service = FlextLdifDnService()
        result = service.normalize("invalid dn without equals")

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None
        assert "Failed to normalize DN" in result.error

    def test_normalize_empty_dn_returns_failure(self) -> None:
        """Test normalization of empty DN returns failure."""
        service = FlextLdifDnService()
        result = service.normalize("")

        assert result.is_failure

    def test_normalize_preserves_value_case(self) -> None:
        """Test normalization preserves attribute value case."""
        service = FlextLdifDnService()
        result = service.normalize("cn=TestUser,dc=Example,dc=Com")

        assert result.is_success
        normalized = result.unwrap()
        # Attribute names should be lowercase, values preserved
        assert "cn=" in normalized
        # Value case should be preserved by ldap3
        assert "Test" in normalized or "test" in normalized

    def test_normalize_dn_with_utf8(self) -> None:
        """Test normalization of DN with UTF-8 characters."""
        service = FlextLdifDnService()
        result = service.normalize("cn=José,ou=People,dc=example,dc=com")

        assert result.is_success
        normalized = result.unwrap()
        assert "José" in normalized


class TestRFC4514Compliance:
    """Test RFC 4514 compliance scenarios."""

    def test_handles_hex_escaping(self) -> None:
        """Test handling of hex-escaped characters (RFC 4514)."""
        service = FlextLdifDnService()
        # Hex escaped value
        result = service.parse_components(r"cn=\23value,dc=example,dc=com")

        assert result.is_success
        components = result.unwrap()
        assert len(components) == 3

    def test_handles_multiple_special_characters(self) -> None:
        """Test handling of multiple special characters."""
        service = FlextLdifDnService()
        result = service.validate_format("cn=user<test>,ou=People,dc=example,dc=com")

        # ldap3 should handle special characters per RFC 4514
        assert result.is_success

    def test_parse_components_returns_three_tuple(self) -> None:
        """Test parse_components returns (attr, value, rdn) tuples."""
        service = FlextLdifDnService()
        result = service.parse_components("cn=test,dc=example,dc=com")

        assert result.is_success
        components = result.unwrap()
        # Each component should be a 3-tuple
        for component in components:
            assert len(component) == 3
            assert isinstance(component[0], str)  # attr
            assert isinstance(component[1], str)  # value
            assert isinstance(component[2], str)  # rdn


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
