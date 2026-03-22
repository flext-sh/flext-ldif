"""Tests for LDIF writer integration with DN service.

This module tests the FlextLdifWriter service integration with FlextLdifDn
service for proper distinguished name parsing, normalization, and handling of
escaped characters and complex DN structures during write operations.
"""

from __future__ import annotations

from typing import ClassVar

import pytest
from flext_tests import tm

from flext_ldif import FlextLdifDn, FlextLdifWriter
from tests import m, s


class TestsFlextLdifsFlextLdifWriterDnNormalization(s):
    """Test Writer integration with DnService for DN normalization."""

    writer: ClassVar[FlextLdifWriter]
    dn_service: ClassVar[FlextLdifDn]

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
        tm.that(result.is_success, eq=True), "DN parsing should succeed"
        components = result.value
        (
            tm.that(len(components) == 4, eq=True),
            "DN should have 4 components",
        )
        attr_names = [comp[0] for comp in components]
        (
            tm.that("cn" in attr_names, eq=True),
            "Should contain cn component",
        )
        (
            tm.that("ou" in attr_names, eq=True),
            "Should contain ou component",
        )
        (
            tm.that("dc" in attr_names, eq=True),
            "Should contain dc component",
        )

    def test_parse_dn_with_escaped_characters(self, dn_service: FlextLdifDn) -> None:
        """Test parsing DN with escaped special characters."""
        dn = "cn=John\\, Jr.,ou=people,dc=example,dc=com"
        result = dn_service.parse_components(dn)
        (
            tm.that(result.is_success, eq=True),
            "Escaped DN parsing should succeed",
        )
        components = result.value
        (
            tm.that(len(components) >= 3, eq=True),
            "DN should have at least 3 components",
        )
        attr_names = [comp[0] for comp in components]
        (
            tm.that("cn" in attr_names, eq=True),
            "Should contain cn attribute",
        )
        (
            tm.that("ou" in attr_names, eq=True),
            "Should contain ou attribute",
        )
        (
            tm.that("dc" in attr_names, eq=True),
            "Should contain dc attribute",
        )

    def test_normalize_dn_to_lowercase(self, dn_service: FlextLdifDn) -> None:
        """Test DN normalization converts attribute names to lowercase per RFC 4514."""
        dn = "CN=John Doe,OU=People,DC=Example,DC=Com"
        result = dn_service.normalize(dn)
        (
            tm.that(result.is_success, eq=True),
            "DN normalization should succeed",
        )
        normalized = result.value
        (
            tm.that(normalized.startswith("cn="), eq=True),
            "Attribute names should be lowercase",
        )
        (
            tm.that("ou=" in normalized.lower(), eq=True),
            "Should contain ou component",
        )
        (
            tm.that("dc=" in normalized.lower(), eq=True),
            "Should contain dc component",
        )

    def test_validate_dn_format_valid(self, dn_service: FlextLdifDn) -> None:
        """Test validation of valid RFC 4514 DN format."""
        dn = "cn=John Doe,ou=people,dc=example,dc=com"
        result = dn_service.validate_format(dn)
        tm.that(result.is_success, eq=True), "Validation should succeed"
        is_valid = result.value
        (
            tm.that(is_valid is True, eq=True),
            "Valid DN should pass format validation",
        )

    def test_validate_dn_format_invalid(self, dn_service: FlextLdifDn) -> None:
        """Test validation detects invalid DN format."""
        dn = "cn=,ou=people,dc=example,dc=com"
        result = dn_service.validate_format(dn)
        (
            tm.that(result.is_success, eq=True),
            "Validation check should complete",
        )
        is_valid = result.value
        (
            tm.that(is_valid is False, eq=True),
            "Malformed DN should fail validation",
        )

    def test_clean_dn_removes_spacing_issues(self, dn_service: FlextLdifDn) -> None:
        """Test DN cleanup fixes spacing issues."""
        dn = "cn = John Doe , ou = people , dc = example , dc = com"
        cleaned = dn_service.clean_dn(dn)
        (
            tm.that("cn=" in cleaned, eq=True),
            "Should remove spaces around =",
        )
        (
            tm.that(len(cleaned) < len(dn), eq=True),
            "Cleaned DN should be shorter",
        )

    def test_escape_dn_value_special_characters(self, dn_service: FlextLdifDn) -> None:
        """Test escaping special characters in DN values per RFC 4514."""
        value = "John, Jr."
        escaped = dn_service.escape_dn_value(value)
        (
            tm.that(escaped != value, eq=True),
            "Should escape special characters",
        )
        (
            tm.that("\\" in escaped or "," not in escaped, eq=True),
            ("Comma should be escaped or handled"),
        )

    def test_unescape_dn_value_hex_escapes(self, dn_service: FlextLdifDn) -> None:
        """Test unescaping hex-encoded characters in DN values."""
        value = "John\\2C Jr."
        unescaped = dn_service.unescape_dn_value(value)
        tm.that(unescaped != value, eq=True), "Should unescape hex values"
        (
            tm.that("," in unescaped, eq=True),
            "Hex-escaped comma should be unescaped",
        )

    def test_write_entry_with_normalized_dn(
        self, writer: FlextLdifWriter, dn_service: FlextLdifDn
    ) -> None:
        """Test writing entry with DN normalized before writing."""
        dn_value = "CN=John Doe,OU=People,DC=Example,DC=Com"
        normalize_result = dn_service.normalize(dn_value)
        tm.that(normalize_result.is_success, eq=True)
        normalized_dn = normalize_result.value
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=normalized_dn),
            attributes=m.Ldif.Attributes(
                attributes={"cn": ["John Doe"], "objectClass": ["person"]}
            ),
        )
        write_result = writer.write(
            entries=[entry],
            target_server_type="rfc",
            format_options=m.WriteFormatOptions(fold_long_lines=False),
        )
        tm.that(write_result.is_success, eq=True)
        output = write_result.value
        if isinstance(output, str):
            (
                tm.that("dn: cn=" in output, eq=True),
                ("Output should have normalized DN with lowercase cn"),
            )
