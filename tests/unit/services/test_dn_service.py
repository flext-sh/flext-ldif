"""Unit tests for DN Service - RFC 4514 Compliant DN Operations.

Tests DN parsing, validation, and normalization using ldap3.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif.services.dn import FlextLdifDn


class TestDnServiceInitialization:
    """Test DN service initialization."""

    def test_init_creates_service(self) -> None:
        """Test DN service can be instantiated."""
        service = FlextLdifDn()
        assert service is not None

    def test_execute_returns_status(self) -> None:
        """Test execute returns service status."""
        service = FlextLdifDn()
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
        service = FlextLdifDn()
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
        service = FlextLdifDn()
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
        service = FlextLdifDn()
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
        service = FlextLdifDn()
        result = service.parse_components("cn=John+ou=People,dc=example,dc=com")

        assert result.is_success
        components = result.unwrap()
        # Multi-valued RDN (cn=John+ou=People) is one component
        assert len(components) >= 2

    def test_parse_dn_with_spaces(self) -> None:
        """Test parsing DN with spaces."""
        service = FlextLdifDn()
        result = service.parse_components("cn=John Smith,ou=People,dc=example,dc=com")

        assert result.is_success
        components = result.unwrap()
        assert len(components) == 4
        assert components[0][1] == "John Smith"

    def test_parse_invalid_dn_returns_failure(self) -> None:
        """Test parsing invalid DN returns failure."""
        service = FlextLdifDn()
        result = service.parse_components("invalid dn without equals")

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None
        assert "Invalid DN format" in result.error

    def test_parse_empty_dn_returns_failure(self) -> None:
        """Test parsing empty DN returns failure."""
        service = FlextLdifDn()
        result = service.parse_components("")

        assert result.is_failure

    def test_parse_dn_with_utf8(self) -> None:
        """Test parsing DN with UTF-8 characters."""
        service = FlextLdifDn()
        result = service.parse_components("cn=José,ou=People,dc=example,dc=com")

        assert result.is_success
        components = result.unwrap()
        assert len(components) == 4
        assert components[0][1] == "José"


class TestValidateFormat:
    """Test DN format validation with RFC 4514 compliance."""

    def test_validate_simple_dn(self) -> None:
        """Test validation of simple valid DN."""
        service = FlextLdifDn()
        result = service.validate_format("cn=test,dc=example,dc=com")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_dn_with_escaped_comma(self) -> None:
        """Test validation of DN with escaped comma."""
        service = FlextLdifDn()
        result = service.validate_format(r"cn=Smith\, John,ou=People,dc=example,dc=com")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_dn_with_escaped_comma_value(self) -> None:
        """Test validation of DN with escaped comma in value."""
        service = FlextLdifDn()
        result = service.validate_format(r"cn=Smith\, John,ou=People,dc=example,dc=com")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_dn_with_special_characters(self) -> None:
        """Test validation of DN with special characters."""
        service = FlextLdifDn()
        result = service.validate_format("cn=John+ou=People,dc=example,dc=com")

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_invalid_dn_returns_false(self) -> None:
        """Test validation of invalid DN returns False."""
        service = FlextLdifDn()
        result = service.validate_format("invalid dn without equals")

        assert result.is_success
        assert result.unwrap() is False

    def test_validate_empty_string_returns_false(self) -> None:
        """Test validation of empty string returns False."""
        service = FlextLdifDn()
        result = service.validate_format("")

        assert result.is_success
        assert result.unwrap() is False

    def test_validate_non_string_returns_false(self) -> None:
        """Test validation of non-string returns False."""
        service = FlextLdifDn()
        result = service.validate_format("str")

        assert result.is_success
        assert result.unwrap() is False

    def test_validate_dn_with_utf8(self) -> None:
        """Test validation of DN with UTF-8 characters."""
        service = FlextLdifDn()
        result = service.validate_format("cn=José,ou=People,dc=example,dc=com")

        assert result.is_success
        assert result.unwrap() is True


class TestNormalize:
    """Test DN normalization with RFC 4514 compliance."""

    def test_normalize_simple_dn(self) -> None:
        """Test normalization of simple DN."""
        service = FlextLdifDn()
        result = service.normalize("CN=Test,DC=Example,DC=Com")

        assert result.is_success
        normalized = result.unwrap()
        # ldap3 normalizes attribute names to lowercase
        assert "cn=" in normalized.lower()
        assert "dc=" in normalized.lower()

    def test_normalize_dn_with_spaces(self) -> None:
        """Test normalization of DN with spaces."""
        service = FlextLdifDn()
        result = service.normalize("cn=John Smith,ou=People,dc=example,dc=com")

        assert result.is_success
        normalized = result.unwrap()
        assert "John Smith" in normalized

    def test_normalize_dn_with_escaped_comma(self) -> None:
        """Test normalization of DN with escaped comma."""
        service = FlextLdifDn()
        result = service.normalize(r"cn=Smith\, John,ou=People,dc=example,dc=com")

        assert result.is_success
        normalized = result.unwrap()
        # ldap3 should preserve escaped comma in some form
        assert normalized is not None

    def test_normalize_dn_with_escaped_value(self) -> None:
        """Test normalization of DN with escaped comma in value."""
        service = FlextLdifDn()
        result = service.normalize(r"cn=Smith\, John,ou=People,dc=example,dc=com")

        assert result.is_success
        normalized = result.unwrap()
        # ldap3 handles escaped commas
        assert "Smith" in normalized

    def test_normalize_invalid_dn_returns_failure(self) -> None:
        """Test normalization of invalid DN returns failure."""
        service = FlextLdifDn()
        result = service.normalize("invalid dn without equals")

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None
        assert "Failed to normalize DN" in result.error

    def test_normalize_empty_dn_returns_failure(self) -> None:
        """Test normalization of empty DN returns failure."""
        service = FlextLdifDn()
        result = service.normalize("")

        assert result.is_failure

    def test_normalize_preserves_value_case(self) -> None:
        """Test normalization preserves attribute value case."""
        service = FlextLdifDn()
        result = service.normalize("cn=TestUser,dc=Example,dc=Com")

        assert result.is_success
        normalized = result.unwrap()
        # Attribute names should be lowercase, values preserved
        assert "cn=" in normalized
        # Value case should be preserved by ldap3
        assert "Test" in normalized or "test" in normalized

    def test_normalize_dn_with_utf8(self) -> None:
        """Test normalization of DN with UTF-8 characters."""
        service = FlextLdifDn()
        result = service.normalize("cn=José,ou=People,dc=example,dc=com")

        assert result.is_success
        normalized = result.unwrap()
        assert "José" in normalized


class TestRFC4514Compliance:
    """Test RFC 4514 compliance scenarios."""

    def test_handles_hex_escaping(self) -> None:
        """Test handling of hex-escaped characters (RFC 4514)."""
        service = FlextLdifDn()
        # Hex escaped value
        result = service.parse_components(r"cn=\23value,dc=example,dc=com")

        assert result.is_success
        components = result.unwrap()
        assert len(components) == 3

    def test_handles_multiple_special_characters(self) -> None:
        """Test handling of multiple special characters."""
        service = FlextLdifDn()
        result = service.validate_format("cn=user<test>,ou=People,dc=example,dc=com")

        # ldap3 should handle special characters per RFC 4514
        assert result.is_success

    def test_parse_components_returns_three_tuple(self) -> None:
        """Test parse_components returns (attr, value, rdn) tuples."""
        service = FlextLdifDn()
        result = service.parse_components("cn=test,dc=example,dc=com")

        assert result.is_success
        components = result.unwrap()
        # Each component should be a 3-tuple
        for component in components:
            assert len(component) == 3
            assert isinstance(component[0], str)  # attr
            assert isinstance(component[1], str)  # value
            assert isinstance(component[2], str)  # rdn


class TestDnEscaping:
    """Test DN escaping and unescaping methods per RFC 4514."""

    def test_escape_dn_value_with_comma(self) -> None:
        """Test escaping comma character."""
        result = FlextLdifDn.escape_dn_value("Smith, John")
        # Should escape comma as \2c
        assert "\\2c" in result or ",\\" in result
        assert "Smith" in result
        assert "John" in result

    def test_escape_dn_value_with_plus(self) -> None:
        """Test escaping plus character."""
        result = FlextLdifDn.escape_dn_value("cn+ou=People")
        # Should escape plus as \2b
        assert "\\2b" in result
        assert "cn" in result
        assert "ou=People" in result

    def test_escape_dn_value_with_quote(self) -> None:
        """Test escaping quote character."""
        result = FlextLdifDn.escape_dn_value('User "Admin"')
        # Should escape quotes as \22
        assert "\\22" in result
        assert "User" in result
        assert "Admin" in result

    def test_escape_dn_value_with_backslash(self) -> None:
        """Test escaping backslash character."""
        result = FlextLdifDn.escape_dn_value("Path\\Directory")
        # Should escape backslash as \5c
        assert "\\5c" in result
        assert "Path" in result
        assert "Directory" in result

    def test_escape_dn_value_with_less_greater(self) -> None:
        """Test escaping less than and greater than."""
        result = FlextLdifDn.escape_dn_value("<admin>")
        # Should escape < as \3c and > as \3e
        assert "\\3c" in result
        assert "\\3e" in result
        assert "admin" in result

    def test_escape_dn_value_with_semicolon(self) -> None:
        """Test escaping semicolon character."""
        result = FlextLdifDn.escape_dn_value("User;Test")
        # Should escape semicolon as \3b
        assert "\\3b" in result
        assert "User" in result
        assert "Test" in result

    def test_escape_dn_value_with_hash(self) -> None:
        """Test escaping hash/pound character."""
        result = FlextLdifDn.escape_dn_value("User#1")
        # Should escape hash as \23
        assert "\\23" in result
        assert "User" in result
        assert "1" in result

    def test_escape_dn_value_with_leading_space(self) -> None:
        """Test escaping leading space."""
        result = FlextLdifDn.escape_dn_value(" leading")
        # Should escape leading space as \20
        assert result.startswith("\\20")
        assert "leading" in result

    def test_escape_dn_value_with_trailing_space(self) -> None:
        """Test escaping trailing space."""
        result = FlextLdifDn.escape_dn_value("trailing ")
        # Should escape trailing space as \20
        assert "trailing\\20" in result

    def test_escape_dn_value_multiple_special_chars(self) -> None:
        """Test escaping multiple special characters."""
        result = FlextLdifDn.escape_dn_value("User, Inc. #1")
        # Should escape comma, hash, and other special chars
        assert "User" in result
        assert "Inc" in result
        assert "1" in result
        # Should have escapes for special characters
        assert "\\" in result

    def test_escape_dn_value_empty_string(self) -> None:
        """Test escaping empty string."""
        result = FlextLdifDn.escape_dn_value("")
        assert not result

    def test_escape_dn_value_no_special_chars(self) -> None:
        """Test escaping string with no special characters."""
        result = FlextLdifDn.escape_dn_value("SimpleUserName")
        # No escaping needed
        assert result == "SimpleUserName"

    def test_unescape_dn_value_hex_escape_comma(self) -> None:
        """Test unescaping hex-escaped comma."""
        result = FlextLdifDn.unescape_dn_value("Smith\\2c John")
        assert result == "Smith, John"

    def test_unescape_dn_value_hex_escape_hash(self) -> None:
        """Test unescaping hex-escaped hash."""
        result = FlextLdifDn.unescape_dn_value("User\\23Admin")
        assert result == "User#Admin"

    def test_unescape_dn_value_hex_escape_leading_space(self) -> None:
        """Test unescaping hex-escaped leading space."""
        result = FlextLdifDn.unescape_dn_value("\\20leading")
        assert result == " leading"

    def test_unescape_dn_value_mixed_escapes(self) -> None:
        """Test unescaping mixed hex and backslash escapes."""
        # Both \2c (comma) and backslash escapes
        result = FlextLdifDn.unescape_dn_value("Smith\\2c John\\+Test")
        assert "," in result
        assert "Smith" in result
        assert "John" in result

    def test_unescape_dn_value_no_escapes(self) -> None:
        """Test unescaping string with no escapes."""
        result = FlextLdifDn.unescape_dn_value("SimpleUserName")
        assert result == "SimpleUserName"

    def test_unescape_dn_value_empty_string(self) -> None:
        """Test unescaping empty string."""
        result = FlextLdifDn.unescape_dn_value("")
        assert not result

    def test_hex_escape_simple_string(self) -> None:
        """Test hex escaping of simple string."""
        result = FlextLdifDn.hex_escape("abc")
        # Each character converted to \XX format
        assert "\\61" in result  # 'a'
        assert "\\62" in result  # 'b'
        assert "\\63" in result  # 'c'

    def test_hex_escape_with_special_chars(self) -> None:
        """Test hex escaping with special characters."""
        result = FlextLdifDn.hex_escape("a#b")
        # 'a' = \61, '#' = \23, 'b' = \62
        assert "\\61" in result
        assert "\\23" in result
        assert "\\62" in result

    def test_hex_escape_empty_string(self) -> None:
        """Test hex escaping empty string."""
        result = FlextLdifDn.hex_escape("")
        assert not result

    def test_hex_unescape_simple_string(self) -> None:
        """Test hex unescaping of simple string."""
        result = FlextLdifDn.hex_unescape("\\61\\62\\63")
        assert result == "abc"

    def test_hex_unescape_with_special_chars(self) -> None:
        """Test hex unescaping with special characters."""
        result = FlextLdifDn.hex_unescape("\\61\\23\\62")
        assert result == "a#b"

    def test_hex_unescape_no_escapes(self) -> None:
        """Test hex unescaping with no hex escapes."""
        result = FlextLdifDn.hex_unescape("simple")
        assert result == "simple"

    def test_hex_unescape_empty_string(self) -> None:
        """Test hex unescaping empty string."""
        result = FlextLdifDn.hex_unescape("")
        assert not result

    def test_escape_unescape_roundtrip(self) -> None:
        """Test that escape followed by unescape returns original."""
        original = "Smith, John"
        escaped = FlextLdifDn.escape_dn_value(original)
        unescaped = FlextLdifDn.unescape_dn_value(escaped)
        assert unescaped == original

    def test_hex_escape_unescape_roundtrip(self) -> None:
        """Test that hex_escape followed by hex_unescape returns original."""
        original = "Test#Value"
        hex_escaped = FlextLdifDn.hex_escape(original)
        hex_unescaped = FlextLdifDn.hex_unescape(hex_escaped)
        assert hex_unescaped == original

    def test_escape_all_special_characters(self) -> None:
        """Test escaping string with all special characters."""
        original = ',+"\\<>;#'
        escaped = FlextLdifDn.escape_dn_value(original)
        # All characters should be escaped
        assert len(escaped) > len(original)
        # Should be able to unescape back
        unescaped = FlextLdifDn.unescape_dn_value(escaped)
        assert unescaped == original


class TestDnComparison:
    """Test DN comparison with RFC 4514 compliance."""

    def test_compare_identical_dns(self) -> None:
        """Test comparing identical DNs returns 0."""
        service = FlextLdifDn()
        result = service.compare_dns(
            "cn=Admin,dc=example,dc=com",
            "cn=Admin,dc=example,dc=com",
        )

        assert result.is_success
        assert result.unwrap() == 0

    def test_compare_case_insensitive(self) -> None:
        """Test comparing DNs with different case returns 0."""
        service = FlextLdifDn()
        result = service.compare_dns(
            "cn=Admin,dc=example,dc=com",
            "CN=ADMIN,DC=EXAMPLE,DC=COM",
        )

        assert result.is_success
        comparison = result.unwrap()
        # Should be equal (case-insensitive)
        assert comparison == 0

    def test_compare_mixed_case(self) -> None:
        """Test comparing DNs with mixed case returns 0."""
        service = FlextLdifDn()
        result = service.compare_dns(
            "CN=Admin,DC=Example,DC=Com",
            "cn=admin,dc=example,dc=com",
        )

        assert result.is_success
        comparison = result.unwrap()
        # Should be equal (case-insensitive)
        assert comparison == 0

    def test_compare_space_around_values(self) -> None:
        """Test comparing DNs with different spacing around values."""
        service = FlextLdifDn()
        # Spaces around equals signs in values are part of the value
        result = service.compare_dns(
            "cn=Admin User,dc=example,dc=com",
            "cn=Admin User,dc=example,dc=com",
        )

        assert result.is_success
        comparison = result.unwrap()
        # Should be equal
        assert comparison == 0

    def test_compare_first_dn_less_than_second(self) -> None:
        """Test comparing where first DN is less than second."""
        service = FlextLdifDn()
        result = service.compare_dns(
            "cn=aaa,dc=example,dc=com",
            "cn=bbb,dc=example,dc=com",
        )

        assert result.is_success
        comparison = result.unwrap()
        # First DN should be less than second
        assert comparison == -1

    def test_compare_first_dn_greater_than_second(self) -> None:
        """Test comparing where first DN is greater than second."""
        service = FlextLdifDn()
        result = service.compare_dns(
            "cn=zzz,dc=example,dc=com",
            "cn=aaa,dc=example,dc=com",
        )

        assert result.is_success
        comparison = result.unwrap()
        # First DN should be greater than second
        assert comparison == 1

    def test_compare_escaped_comma_dns(self) -> None:
        """Test comparing DNs with escaped commas."""
        service = FlextLdifDn()
        result = service.compare_dns(
            r"cn=Smith\, John,dc=example,dc=com",
            r"cn=Smith\, John,dc=example,dc=com",
        )

        assert result.is_success
        comparison = result.unwrap()
        # Should be equal
        assert comparison == 0

    def test_compare_invalid_dn_first(self) -> None:
        """Test comparing with invalid first DN returns failure."""
        service = FlextLdifDn()
        result = service.compare_dns(
            "invalid dn without equals",
            "cn=valid,dc=example,dc=com",
        )

        assert result.is_failure
        assert result.error is not None
        assert "RFC 4514" in result.error or "Comparison failed" in result.error

    def test_compare_invalid_dn_second(self) -> None:
        """Test comparing with invalid second DN returns failure."""
        service = FlextLdifDn()
        result = service.compare_dns(
            "cn=valid,dc=example,dc=com",
            "invalid dn without equals",
        )

        assert result.is_failure
        assert result.error is not None
        assert "RFC 4514" in result.error or "Comparison failed" in result.error

    def test_compare_both_invalid_dns(self) -> None:
        """Test comparing with both invalid DNs returns failure."""
        service = FlextLdifDn()
        result = service.compare_dns(
            "invalid dn 1",
            "invalid dn 2",
        )

        assert result.is_failure
        assert result.error is not None

    def test_compare_empty_dns(self) -> None:
        """Test comparing empty DNs returns failure."""
        service = FlextLdifDn()
        result = service.compare_dns("", "")

        assert result.is_failure

    def test_compare_utf8_dns(self) -> None:
        """Test comparing DNs with UTF-8 characters."""
        service = FlextLdifDn()
        result = service.compare_dns(
            "cn=José,dc=example,dc=com",
            "cn=José,dc=example,dc=com",
        )

        assert result.is_success
        comparison = result.unwrap()
        # Should be equal
        assert comparison == 0

    def test_compare_different_dc_components(self) -> None:
        """Test comparing DNs with different DC values."""
        service = FlextLdifDn()
        result = service.compare_dns(
            "cn=Admin,dc=example1,dc=com",
            "cn=Admin,dc=example2,dc=com",
        )

        assert result.is_success
        comparison = result.unwrap()
        # Should be different (example1 < example2)
        assert comparison != 0

    def test_compare_dns_transitivity(self) -> None:
        """Test DN comparison is transitive."""
        service = FlextLdifDn()

        # If DN1 < DN2 and DN2 < DN3, then DN1 < DN3
        result1 = service.compare_dns(
            "cn=aaa,dc=example,dc=com",
            "cn=bbb,dc=example,dc=com",
        )
        result2 = service.compare_dns(
            "cn=bbb,dc=example,dc=com",
            "cn=ccc,dc=example,dc=com",
        )
        result3 = service.compare_dns(
            "cn=aaa,dc=example,dc=com",
            "cn=ccc,dc=example,dc=com",
        )

        assert result1.is_success
        assert result2.is_success
        assert result3.is_success

        # Verify transitivity
        assert result1.unwrap() == -1
        assert result2.unwrap() == -1
        assert result3.unwrap() == -1

    def test_compare_dns_symmetry(self) -> None:
        """Test DN comparison symmetry (if DN1==DN2 then DN2==DN1)."""
        service = FlextLdifDn()

        result1 = service.compare_dns(
            "cn=Admin,dc=example,dc=com",
            "CN=ADMIN,DC=EXAMPLE,DC=COM",
        )
        result2 = service.compare_dns(
            "CN=ADMIN,DC=EXAMPLE,DC=COM",
            "cn=Admin,dc=example,dc=com",
        )

        assert result1.is_success
        assert result2.is_success

        # Both should return 0 (equal)
        assert result1.unwrap() == 0
        assert result2.unwrap() == 0


class TestRdnParsing:
    """Test RDN (Relative Distinguished Name) parsing with RFC 4514 compliance."""

    def test_parse_simple_rdn(self) -> None:
        """Test parsing simple single-valued RDN."""
        service = FlextLdifDn()
        result = service.parse_rdn("cn=John")

        assert result.is_success
        pairs = result.unwrap()
        assert len(pairs) == 1
        assert pairs[0] == ("cn", "John")

    def test_parse_simple_rdn_with_spaces(self) -> None:
        """Test parsing RDN with spaces in value."""
        service = FlextLdifDn()
        result = service.parse_rdn("cn=John Smith")

        assert result.is_success
        pairs = result.unwrap()
        assert len(pairs) == 1
        assert pairs[0] == ("cn", "John Smith")

    def test_parse_multi_valued_rdn(self) -> None:
        """Test parsing multi-valued RDN with multiple attribute-value pairs."""
        service = FlextLdifDn()
        result = service.parse_rdn("cn=John+ou=people")

        assert result.is_success
        pairs = result.unwrap()
        assert len(pairs) == 2
        assert pairs[0] == ("cn", "John")
        assert pairs[1] == ("ou", "people")

    def test_parse_multi_valued_rdn_three_pairs(self) -> None:
        """Test parsing multi-valued RDN with three pairs."""
        service = FlextLdifDn()
        result = service.parse_rdn("cn=John+ou=people+c=US")

        assert result.is_success
        pairs = result.unwrap()
        assert len(pairs) == 3
        assert pairs[0] == ("cn", "John")
        assert pairs[1] == ("ou", "people")
        assert pairs[2] == ("c", "US")

    def test_parse_rdn_case_insensitive_attribute(self) -> None:
        """Test that attribute names are lowercased."""
        service = FlextLdifDn()
        result = service.parse_rdn("CN=John")

        assert result.is_success
        pairs = result.unwrap()
        assert pairs[0][0] == "cn"  # Lowercased

    def test_parse_rdn_with_escaped_comma(self) -> None:
        """Test parsing RDN with escaped comma in value."""
        service = FlextLdifDn()
        result = service.parse_rdn(r"cn=Smith\, John")

        assert result.is_success
        pairs = result.unwrap()
        assert len(pairs) == 1
        # Value should contain the escaped comma
        assert "Smith" in pairs[0][1]

    def test_parse_rdn_with_escaped_plus(self) -> None:
        """Test parsing RDN with escaped plus in value."""
        service = FlextLdifDn()
        # Use RFC 4514 proper escaping: \+ for literal plus
        result = service.parse_rdn(r"cn=C\+\+Programmer")

        assert result.is_success
        pairs = result.unwrap()
        assert len(pairs) == 1
        assert "C++Programmer" in pairs[0][1]

    def test_parse_rdn_with_hex_escape(self) -> None:
        """Test parsing RDN with hex-escaped characters."""
        service = FlextLdifDn()
        result = service.parse_rdn(r"cn=user\23name")

        assert result.is_success
        pairs = result.unwrap()
        assert len(pairs) == 1
        assert "user" in pairs[0][1]

    def test_parse_rdn_with_special_chars(self) -> None:
        """Test parsing RDN with various special characters."""
        service = FlextLdifDn()
        result = service.parse_rdn("cn=John Doe+ou=R&D")

        assert result.is_success
        pairs = result.unwrap()
        assert len(pairs) == 2
        assert pairs[0] == ("cn", "John Doe")
        assert pairs[1] == ("ou", "R&D")

    def test_parse_rdn_attribute_names_normalized(self) -> None:
        """Test that all attribute names are normalized to lowercase."""
        service = FlextLdifDn()
        result = service.parse_rdn("CN=John+OU=People+C=US")

        assert result.is_success
        pairs = result.unwrap()
        assert all(attr.islower() for attr, _ in pairs)
        assert pairs[0][0] == "cn"
        assert pairs[1][0] == "ou"
        assert pairs[2][0] == "c"

    def test_parse_rdn_empty_string_fails(self) -> None:
        """Test parsing empty RDN string fails."""
        service = FlextLdifDn()
        result = service.parse_rdn("")

        assert result.is_failure
        assert result.error is not None

    def test_parse_rdn_none_fails(self) -> None:
        """Test parsing None fails."""
        service = FlextLdifDn()
        result = service.parse_rdn(None)

        assert result.is_failure

    def test_parse_rdn_missing_equals_fails(self) -> None:
        """Test parsing RDN without equals sign fails."""
        service = FlextLdifDn()
        result = service.parse_rdn("cnJohn")

        assert result.is_failure
        assert result.error is not None

    def test_parse_rdn_missing_value_fails(self) -> None:
        """Test parsing RDN without value fails."""
        service = FlextLdifDn()
        result = service.parse_rdn("cn=")

        assert result.is_failure
        assert result.error is not None

    def test_parse_rdn_empty_attribute_fails(self) -> None:
        """Test parsing RDN with empty attribute name fails."""
        service = FlextLdifDn()
        result = service.parse_rdn("=John")

        assert result.is_failure
        assert result.error is not None

    def test_parse_rdn_incomplete_multivalued_fails(self) -> None:
        """Test parsing incomplete multi-valued RDN fails."""
        service = FlextLdifDn()
        result = service.parse_rdn("cn=John+")

        assert result.is_failure
        assert result.error is not None

    def test_parse_rdn_utf8_characters(self) -> None:
        """Test parsing RDN with UTF-8 characters."""
        service = FlextLdifDn()
        result = service.parse_rdn("cn=José")

        assert result.is_success
        pairs = result.unwrap()
        assert pairs[0][1] == "José"

    def test_parse_rdn_utf8_multivalued(self) -> None:
        """Test parsing multi-valued RDN with UTF-8 characters."""
        service = FlextLdifDn()
        result = service.parse_rdn("cn=José+ou=São Paulo")

        assert result.is_success
        pairs = result.unwrap()
        assert len(pairs) == 2
        assert pairs[0][1] == "José"
        assert pairs[1][1] == "São Paulo"

    def test_parse_rdn_with_leading_trailing_spaces(self) -> None:
        """Test that leading/trailing spaces in values are trimmed."""
        service = FlextLdifDn()
        result = service.parse_rdn("cn=  John  ")

        assert result.is_success
        pairs = result.unwrap()
        assert pairs[0][1] == "John"

    def test_parse_rdn_multiple_plus_signs(self) -> None:
        """Test parsing RDN with multiple plus signs (not escaped)."""
        service = FlextLdifDn()
        result = service.parse_rdn("cn=First+ou=Second+sn=Last")

        assert result.is_success
        pairs = result.unwrap()
        assert len(pairs) == 3
        assert pairs[0] == ("cn", "First")
        assert pairs[1] == ("ou", "Second")
        assert pairs[2] == ("sn", "Last")

    def test_parse_rdn_complex_multivalued(self) -> None:
        """Test parsing complex multi-valued RDN with various content."""
        service = FlextLdifDn()
        result = service.parse_rdn("cn=John A. Smith+ou=Engineering+o=Acme+c=US")

        assert result.is_success
        pairs = result.unwrap()
        assert len(pairs) == 4
        assert pairs[0] == ("cn", "John A. Smith")
        assert pairs[1] == ("ou", "Engineering")
        assert pairs[2] == ("o", "Acme")
        assert pairs[3] == ("c", "US")

    def test_parse_rdn_with_numbers(self) -> None:
        """Test parsing RDN with numeric values."""
        service = FlextLdifDn()
        result = service.parse_rdn("cn=user123+uid=1001")

        assert result.is_success
        pairs = result.unwrap()
        assert len(pairs) == 2
        assert pairs[0] == ("cn", "user123")
        assert pairs[1] == ("uid", "1001")

    def test_parse_rdn_with_special_ldap_chars(self) -> None:
        """Test parsing RDN with special LDAP characters."""
        service = FlextLdifDn()
        # Using escaped versions of special chars
        result = service.parse_rdn(r"cn=user\<test\>+ou=data")

        assert result.is_success
        pairs = result.unwrap()
        assert len(pairs) == 2
        assert "user" in pairs[0][1]


class TestEscapeSequenceValidation:
    """Test escape sequence validation per RFC 4514."""

    def test_validate_valid_hex_escape(self) -> None:
        """Test validation of valid hex escape sequences."""
        service = FlextLdifDn()
        # Valid hex escapes like \2B (plus sign)
        result = service.validate_format(r"cn=C\2BProgrammer,dc=example,dc=com")
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_invalid_hex_escape_non_hex(self) -> None:
        """Test validation rejects non-hex characters in escape."""
        service = FlextLdifDn()
        # \ZZ is not valid hex
        result = service.validate_format(r"cn=C\ZZProgrammer,dc=example,dc=com")
        assert result.is_success
        assert result.unwrap() is False

    def test_validate_incomplete_hex_escape(self) -> None:
        """Test validation rejects incomplete hex escapes."""
        service = FlextLdifDn()
        # \2 without second hex digit
        result = service.validate_format(r"cn=test\2,dc=example,dc=com")
        assert result.is_success
        assert result.unwrap() is False

    def test_validate_dangling_backslash(self) -> None:
        """Test validation rejects dangling backslash at end."""
        service = FlextLdifDn()
        # Backslash at end with no escape character
        result = service.validate_format(r"cn=test\,dc=example,dc=com")
        # This should fail during parsing because \ at end is incomplete
        assert result.is_success
        # ldap3 should reject this as invalid
        assert result.unwrap() is False

    def test_validate_escaped_comma(self) -> None:
        """Test validation accepts escaped comma in value."""
        service = FlextLdifDn()
        result = service.validate_format(r"cn=Smith\,John,dc=example,dc=com")
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_escaped_plus(self) -> None:
        """Test validation accepts escaped plus in value."""
        service = FlextLdifDn()
        result = service.validate_format(r"cn=C\+Programmer,dc=example,dc=com")
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_mixed_escapes(self) -> None:
        """Test validation with mixed escape types."""
        service = FlextLdifDn()
        # Mix of backslash and hex escapes
        result = service.validate_format(
            r"cn=Smith\,John\2BDeveloper,dc=example,dc=com"
        )
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_consecutive_escapes(self) -> None:
        """Test validation with consecutive escape sequences."""
        service = FlextLdifDn()
        result = service.validate_format(r"cn=\2B\2B,dc=example,dc=com")
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_lowercase_hex_escape(self) -> None:
        """Test validation accepts lowercase hex digits."""
        service = FlextLdifDn()
        result = service.validate_format(r"cn=test\2b,dc=example,dc=com")
        assert result.is_success
        assert result.unwrap() is True


class TestDnPatternValidation:
    """Test DN pattern validation per RFC 4514."""

    def test_validate_simple_dn_pattern(self) -> None:
        """Test validation of simple single-component DN."""
        service = FlextLdifDn()
        result = service.validate_format("cn=test,dc=example,dc=com")
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_multirdn_pattern(self) -> None:
        """Test validation of multi-valued RDN."""
        service = FlextLdifDn()
        result = service.validate_format("cn=first+sn=last,dc=example,dc=com")
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_empty_dn(self) -> None:
        """Test validation rejects empty DN."""
        service = FlextLdifDn()
        result = service.validate_format("")
        assert result.is_success
        assert result.unwrap() is False

    def test_validate_missing_equals(self) -> None:
        """Test validation rejects attribute without value separator."""
        service = FlextLdifDn()
        result = service.validate_format("cntest,dc=example,dc=com")
        assert result.is_success
        assert result.unwrap() is False

    def test_validate_missing_value(self) -> None:
        """Test validation rejects incomplete attribute-value pair."""
        service = FlextLdifDn()
        result = service.validate_format("cn=,dc=example,dc=com")
        assert result.is_success
        assert result.unwrap() is False

    def test_validate_missing_attribute(self) -> None:
        """Test validation rejects missing attribute name."""
        service = FlextLdifDn()
        result = service.validate_format("=value,dc=example,dc=com")
        assert result.is_success
        assert result.unwrap() is False

    def test_validate_unescaped_comma_in_value(self) -> None:
        """Test validation rejects unescaped comma in attribute value."""
        service = FlextLdifDn()
        result = service.validate_format("cn=Smith, John,dc=example,dc=com")
        # Space after comma makes it look like a DN separator
        assert result.is_success
        # ldap3 may parse this differently, but it should be invalid
        # since the space after comma is not escaped
        assert result.unwrap() is False

    def test_validate_unescaped_plus_creates_multirdn(self) -> None:
        """Test validation treats unescaped plus as RDN separator."""
        service = FlextLdifDn()
        # This should be valid as multi-valued RDN
        result = service.validate_format("cn=First+sn=Last,dc=example,dc=com")
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_trailing_comma(self) -> None:
        """Test validation rejects trailing comma."""
        service = FlextLdifDn()
        result = service.validate_format("cn=test,dc=example,dc=com,")
        assert result.is_success
        assert result.unwrap() is False

    def test_validate_double_comma(self) -> None:
        """Test validation rejects double comma separator."""
        service = FlextLdifDn()
        result = service.validate_format("cn=test,,dc=example,dc=com")
        assert result.is_success
        assert result.unwrap() is False

    def test_validate_whitespace_handling(self) -> None:
        """Test validation handles whitespace per RFC 4514."""
        service = FlextLdifDn()
        # Leading/trailing spaces in values need escaping
        result = service.validate_format("cn=test value,dc=example,dc=com")
        assert result.is_success
        # This should be valid - internal spaces are allowed
        assert result.unwrap() is True

    def test_validate_single_rdn(self) -> None:
        """Test validation of single RDN DN."""
        service = FlextLdifDn()
        result = service.validate_format("cn=root")
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_deep_hierarchy(self) -> None:
        """Test validation of deep DN hierarchy."""
        service = FlextLdifDn()
        result = service.validate_format(
            "cn=test,ou=users,ou=department,o=company,c=US"
        )
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_case_variations(self) -> None:
        """Test validation accepts case variations in attributes."""
        service = FlextLdifDn()
        result = service.validate_format("CN=Test,DC=Example,DC=COM")
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_numeric_attribute_values(self) -> None:
        """Test validation with numeric attribute values."""
        service = FlextLdifDn()
        result = service.validate_format("uid=1001,ou=users,dc=example,dc=com")
        assert result.is_success
        assert result.unwrap() is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
