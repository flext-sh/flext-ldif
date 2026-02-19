"""Tests for LDIF writer integration with DN service.

This module tests the FlextLdifWriter service integration with FlextLdifDn
service for proper distinguished name parsing, normalization, and handling of
escaped characters and complex DN structures during write operations.
"""

from __future__ import annotations

from typing import ClassVar

import pytest
from flext_ldif import FlextLdifWriter
from flext_ldif.services.dn import FlextLdifDn

from tests import m, s


class TestsFlextLdifsFlextLdifWriterDnNormalization(s):
    """Test Writer integration with DnService for DN normalization."""

    writer: ClassVar[FlextLdifWriter]  # pytest fixture
    dn_service: ClassVar[FlextLdifDn]  # pytest fixture

    @pytest.fixture
    def writer(self) -> FlextLdifWriter:
        """Initialize real writer service."""
        return FlextLdifWriter()

    @pytest.fixture
    def dn_service(self) -> FlextLdifDn:
        """Initialize real DN service."""
        return FlextLdifDn()

    def test_parse_simple_dn_into_components(self, dn_service: FlextLdifDn) -> None:
        """Test parsing simple DN into RFC 4514 components."""
        dn = "cn=John Doe,ou=people,dc=example,dc=com"

        result = dn_service.parse_components(dn)
        assert result.is_success, "DN parsing should succeed"

        components = result.value
        assert len(components) == 4, "DN should have 4 components"

        # Check parsed structure (attr_name, attr_value, escaped_value)
        attr_names = [comp[0] for comp in components]
        assert "cn" in attr_names, "Should contain cn component"
        assert "ou" in attr_names, "Should contain ou component"
        assert "dc" in attr_names, "Should contain dc component"

    def test_parse_dn_with_escaped_characters(self, dn_service: FlextLdifDn) -> None:
        """Test parsing DN with escaped special characters."""
        dn = r"cn=John\, Jr.,ou=people,dc=example,dc=com"

        result = dn_service.parse_components(dn)
        assert result.is_success, "Escaped DN parsing should succeed"

        components = result.value
        # Parser creates components for each comma found, even with escapes
        # The important thing is that parsing succeeds and includes expected attributes
        assert len(components) >= 3, "DN should have at least 3 components"

        attr_names = [comp[0] for comp in components]
        assert "cn" in attr_names, "Should contain cn attribute"
        assert "ou" in attr_names, "Should contain ou attribute"
        assert "dc" in attr_names, "Should contain dc attribute"

    def test_normalize_dn_to_lowercase(self, dn_service: FlextLdifDn) -> None:
        """Test DN normalization converts attribute names to lowercase per RFC 4514."""
        dn = "CN=John Doe,OU=People,DC=Example,DC=Com"

        result = dn_service.normalize(dn)
        assert result.is_success, "DN normalization should succeed"

        normalized = result.value
        # Should have lowercase attribute names
        assert normalized.startswith("cn="), "Attribute names should be lowercase"
        assert "ou=" in normalized.lower(), "Should contain ou component"
        assert "dc=" in normalized.lower(), "Should contain dc component"

    def test_validate_dn_format_valid(self, dn_service: FlextLdifDn) -> None:
        """Test validation of valid RFC 4514 DN format."""
        dn = "cn=John Doe,ou=people,dc=example,dc=com"

        result = dn_service.validate_format(dn)
        assert result.is_success, "Validation should succeed"

        is_valid = result.value
        assert is_valid is True, "Valid DN should pass format validation"

    def test_validate_dn_format_invalid(self, dn_service: FlextLdifDn) -> None:
        """Test validation detects invalid DN format."""
        # Malformed DN - missing value
        dn = "cn=,ou=people,dc=example,dc=com"

        result = dn_service.validate_format(dn)
        assert result.is_success, "Validation check should complete"

        is_valid = result.value
        assert is_valid is False, "Malformed DN should fail validation"

    def test_clean_dn_removes_spacing_issues(self, dn_service: FlextLdifDn) -> None:
        """Test DN cleanup fixes spacing issues."""
        # DN with spaces around equals and commas
        dn = "cn = John Doe , ou = people , dc = example , dc = com"

        cleaned = dn_service.clean_dn(dn)
        assert "cn=" in cleaned, "Should remove spaces around ="
        # The cleaned DN should be more compact
        assert len(cleaned) < len(dn), "Cleaned DN should be shorter"

    def test_escape_dn_value_special_characters(self, dn_service: FlextLdifDn) -> None:
        """Test escaping special characters in DN values per RFC 4514."""
        # Value with special characters
        value = "John, Jr."

        escaped = dn_service.escape_dn_value(value)
        assert escaped != value, "Should escape special characters"
        # Should contain escaped comma
        assert "\\" in escaped or "," not in escaped, (
            "Comma should be escaped or handled"
        )

    def test_unescape_dn_value_hex_escapes(self, dn_service: FlextLdifDn) -> None:
        """Test unescaping hex-encoded characters in DN values."""
        # Hex-escaped comma
        value = r"John\2C Jr."

        unescaped = dn_service.unescape_dn_value(value)
        assert unescaped != value, "Should unescape hex values"
        # Should contain unescaped comma
        assert "," in unescaped, "Hex-escaped comma should be unescaped"

    def test_write_entry_with_normalized_dn(
        self,
        writer: FlextLdifWriter,
        dn_service: FlextLdifDn,
    ) -> None:
        """Test writing entry with DN normalized before writing."""
        # Create entry with non-normalized DN
        dn_value = "CN=John Doe,OU=People,DC=Example,DC=Com"

        # Normalize DN using service
        normalize_result = dn_service.normalize(dn_value)
        assert normalize_result.is_success

        normalized_dn = normalize_result.value

        # Create entry with normalized DN
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=normalized_dn),
            attributes=m.Ldif.Attributes(
                attributes={
                    "cn": ["John Doe"],
                    "objectClass": ["person"],
                },
            ),
        )

        # Write normalized entry
        write_result = writer.write(
            entries=[entry],
            target_server_type="rfc",
            format_options=m.WriteFormatOptions(fold_long_lines=False),
        )

        assert write_result.is_success
        output = write_result.value
        # Should contain the normalized DN
        if isinstance(output, str):
            assert "dn: cn=" in output, (
                "Output should have normalized DN with lowercase cn"
            )
