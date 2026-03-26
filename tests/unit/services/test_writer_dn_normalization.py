"""Tests for LDIF writer integration with DN service.

This module tests the FlextLdifWriter service integration with FlextLdifDn
service for proper distinguished name parsing, normalization, and handling of
escaped characters and complex DN structures during write operations.
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldif import FlextLdifDn, FlextLdifWriter
from tests import m


class TestsFlextLdifsFlextLdifWriterDnNormalization:
    """Test Writer integration with DnService for DN normalization."""

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
        _ = tm.that(result.is_success, eq=True)
        components = result.value
        _ = tm.that(len(components), eq=4)
        attr_names = [comp[0] for comp in components]
        _ = tm.that(attr_names, has="cn")
        _ = tm.that(attr_names, has="ou")
        _ = tm.that(attr_names, has="dc")

    def test_parse_dn_with_escaped_characters(self, dn_service: FlextLdifDn) -> None:
        """Test parsing DN with escaped special characters."""
        dn = "cn=John\\, Jr.,ou=people,dc=example,dc=com"
        result = dn_service.parse_components(dn)
        _ = tm.that(result.is_success, eq=True)
        components = result.value
        _ = tm.that(len(components), gte=3)
        attr_names = [comp[0] for comp in components]
        _ = tm.that(attr_names, has="cn")
        _ = tm.that(attr_names, has="ou")
        _ = tm.that(attr_names, has="dc")

    def test_normalize_dn_to_lowercase(self, dn_service: FlextLdifDn) -> None:
        """Test DN normalization converts attribute names to lowercase per RFC 4514."""
        dn = "CN=John Doe,OU=People,DC=Example,DC=Com"
        result = dn_service.normalize_dn(dn)
        _ = tm.that(result.is_success, eq=True)
        normalized = result.value
        _ = tm.that(normalized.startswith("cn="), eq=True)
        _ = tm.that(normalized.lower(), has="ou=")
        _ = tm.that(normalized.lower(), has="dc=")

    def test_validate_dn_format_valid(self, dn_service: FlextLdifDn) -> None:
        """Test validation of valid RFC 4514 DN format."""
        dn = "cn=John Doe,ou=people,dc=example,dc=com"
        result = dn_service.validate_format(dn)
        _ = tm.that(result.is_success, eq=True)
        is_valid = result.value
        _ = tm.that(is_valid is True, eq=True)

    def test_validate_dn_format_invalid(self, dn_service: FlextLdifDn) -> None:
        """Test validation detects invalid DN format."""
        dn = "cn=,ou=people,dc=example,dc=com"
        result = dn_service.validate_format(dn)
        _ = tm.that(result.is_success, eq=True)
        is_valid = result.value
        _ = tm.that(is_valid is False, eq=True)

    def test_clean_dn_removes_spacing_issues(self, dn_service: FlextLdifDn) -> None:
        """Test DN cleanup fixes spacing issues."""
        dn = "cn = John Doe , ou = people , dc = example , dc = com"
        cleaned = dn_service.clean_dn(dn)
        _ = tm.that(cleaned, has="cn=")
        _ = tm.that(len(cleaned), lt=len(dn))

    def test_escape_dn_value_special_characters(self, dn_service: FlextLdifDn) -> None:
        """Test escaping special characters in DN values per RFC 4514."""
        value = "John, Jr."
        escaped = dn_service.escape_dn_value(value)
        _ = tm.that(escaped, ne=value)
        _ = tm.that("\\" in escaped or "," not in escaped, eq=True)

    def test_unescape_dn_value_hex_escapes(self, dn_service: FlextLdifDn) -> None:
        """Test unescaping hex-encoded characters in DN values."""
        value = "John\\2C Jr."
        unescaped = dn_service.unescape_dn_value(value)
        _ = tm.that(unescaped, ne=value)
        _ = tm.that(unescaped, has=",")

    def test_write_entry_with_normalized_dn(
        self,
        writer: FlextLdifWriter,
        dn_service: FlextLdifDn,
    ) -> None:
        """Test writing entry with DN normalized before writing."""
        dn_value = "CN=John Doe,OU=People,DC=Example,DC=Com"
        normalize_result = dn_service.normalize_dn(dn_value)
        tm.that(normalize_result.is_success, eq=True)
        normalized_dn = normalize_result.value
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=normalized_dn),
            attributes=m.Ldif.Attributes(
                attributes={"cn": ["John Doe"], "objectClass": ["person"]},
                attribute_metadata={},
            ),
        )
        write_result = writer.write(
            entries=[entry],
            target_server_type="rfc",
            format_options=m.Ldif.WriteFormatOptions(fold_long_lines=False),
        )
        tm.that(write_result.is_success, eq=True)
        output = write_result.value
        if isinstance(output, str):
            _ = tm.that(output, has="dn: cn=")
