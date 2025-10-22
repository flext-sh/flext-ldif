"""Unit tests for FlextLdifClient - LDIF/Encoding Utility Methods.

Tests the integrated LDIF and encoding utility methods in FlextLdifClient.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif.client import FlextLdifClient


@pytest.fixture
def client() -> FlextLdifClient:
    """Create a FlextLdifClient with real initialization."""
    return FlextLdifClient()


class TestDetectEncoding:
    """Test encoding detection from raw bytes."""

    def test_detect_utf8_encoding(self, client: FlextLdifClient) -> None:
        """Test detection of UTF-8 encoded content."""
        utf8_content = "dn: cn=José,dc=example,dc=com\n".encode()

        result = client.detect_encoding(utf8_content)

        assert result.is_success
        assert result.unwrap() == "utf-8"

    def test_detect_invalid_utf8_fails(self, client: FlextLdifClient) -> None:
        """Test that non-UTF-8 content fails (RFC 2849 compliance).

        RFC 2849 mandates UTF-8 encoding. Invalid UTF-8 bytes should
        not be silently accepted via fallback - they indicate a non-compliant LDIF file.
        """
        # Create bytes that are invalid UTF-8 but valid latin-1
        invalid_utf8_content = b"dn: cn=test\x80invalid\x90utf8,dc=example,dc=com\n"

        result = client.detect_encoding(invalid_utf8_content)

        # Should fail - not RFC 2849 compliant
        assert result.is_failure
        assert "RFC 2849 violation" in result.error
        assert "not valid UTF-8" in result.error

    def test_detect_encoding_empty_bytes(self, client: FlextLdifClient) -> None:
        """Test encoding detection with empty bytes."""
        empty_content = b""

        result = client.detect_encoding(empty_content)

        assert result.is_success
        # Empty bytes should decode as UTF-8
        assert result.unwrap() == "utf-8"

    def test_detect_encoding_ascii_compatible(self, client: FlextLdifClient) -> None:
        """Test ASCII content (UTF-8 compatible)."""
        ascii_content = b"dn: cn=test,dc=example,dc=com\n"

        result = client.detect_encoding(ascii_content)

        assert result.is_success
        assert result.unwrap() == "utf-8"

    def test_detect_encoding_unicode_characters(self, client: FlextLdifClient) -> None:
        """Test UTF-8 with various Unicode characters."""
        unicode_content = "dn: cn=日本語テスト,dc=example,dc=com\n".encode()

        result = client.detect_encoding(unicode_content)

        assert result.is_success
        assert result.unwrap() == "utf-8"


class TestNormalizeEncoding:
    """Test encoding normalization."""

    def test_normalize_to_utf8(self, client: FlextLdifClient) -> None:
        """Test normalization to UTF-8."""
        content = "dn: cn=José,dc=example,dc=com\n"

        result = client.normalize_encoding(content, "utf-8")

        assert result.is_success
        normalized = result.unwrap()
        assert normalized == content

    def test_normalize_to_latin1(self, client: FlextLdifClient) -> None:
        """Test normalization to latin-1."""
        # Use only latin-1 compatible characters
        content = "dn: cn=test,dc=example,dc=com\n"

        result = client.normalize_encoding(content, "latin-1")

        assert result.is_success
        normalized = result.unwrap()
        assert normalized == content

    def test_normalize_encoding_default_utf8(self, client: FlextLdifClient) -> None:
        """Test normalization with default UTF-8 encoding."""
        content = "dn: cn=test,dc=example,dc=com\n"

        result = client.normalize_encoding(content)

        assert result.is_success
        assert result.unwrap() == content

    def test_normalize_encoding_invalid_characters(
        self, client: FlextLdifClient
    ) -> None:
        """Test normalization failure with invalid characters for target encoding."""
        # Unicode characters not representable in ASCII
        content = "dn: cn=José,dc=example,dc=com\n"

        result = client.normalize_encoding(content, "ascii")

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None
        assert "not representable in ascii" in result.error.lower()

    def test_normalize_empty_content(self, client: FlextLdifClient) -> None:
        """Test normalization of empty content."""
        content = ""

        result = client.normalize_encoding(content, "utf-8")

        assert result.is_success
        assert not result.unwrap()

    def test_normalize_unicode_content(self, client: FlextLdifClient) -> None:
        """Test normalization with Unicode characters."""
        content = "dn: cn=日本語テスト,dc=example,dc=com\n"

        result = client.normalize_encoding(content, "utf-8")

        assert result.is_success
        assert result.unwrap() == content


class TestValidateLdifSyntax:
    """Test LDIF syntax validation."""

    def test_validate_valid_single_entry(self, client: FlextLdifClient) -> None:
        """Test validation of valid single entry LDIF."""
        ldif_content = "dn: cn=test,dc=example,dc=com\ncn: test\n"

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_valid_multiple_entries(self, client: FlextLdifClient) -> None:
        """Test validation of valid multiple entry LDIF."""
        ldif_content = (
            "dn: cn=test1,dc=example,dc=com\n"
            "cn: test1\n\n"
            "dn: cn=test2,dc=example,dc=com\n"
            "cn: test2\n"
        )

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_empty_content(self, client: FlextLdifClient) -> None:
        """Test validation of empty content returns False."""
        ldif_content = ""

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is False

    def test_validate_whitespace_only(self, client: FlextLdifClient) -> None:
        """Test validation of whitespace-only content returns False."""
        ldif_content = "   \n  \t  \n"

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is False

    def test_validate_missing_dn_line(self, client: FlextLdifClient) -> None:
        """Test validation fails when no dn: line present."""
        ldif_content = "cn: test\nobjectClass: person\n"

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is False

    def test_validate_case_insensitive_dn(self, client: FlextLdifClient) -> None:
        """Test validation accepts DN: (uppercase)."""
        ldif_content = "DN: cn=test,dc=example,dc=com\ncn: test\n"

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_dn_with_spaces(self, client: FlextLdifClient) -> None:
        """Test validation with DN containing spaces."""
        ldif_content = "dn: cn=John Smith,ou=People,dc=example,dc=com\ncn: John Smith\n"

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_dn_with_special_chars(self, client: FlextLdifClient) -> None:
        """Test validation with DN containing special characters."""
        ldif_content = (
            r"dn: cn=Smith\, John,ou=People,dc=example,dc=com" + "\ncn: Smith, John\n"
        )

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_minimal_ldif(self, client: FlextLdifClient) -> None:
        """Test validation with minimal valid LDIF (just dn:)."""
        ldif_content = "dn: dc=example,dc=com\n"

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is True


class TestCountLdifEntries:
    """Test LDIF entry counting."""

    def test_count_single_entry(self, client: FlextLdifClient) -> None:
        """Test counting single LDIF entry."""
        ldif_content = "dn: cn=test,dc=example,dc=com\ncn: test\n"

        result = client.count_ldif_entries(ldif_content)

        assert result.is_success
        assert result.unwrap() == 1

    def test_count_multiple_entries(self, client: FlextLdifClient) -> None:
        """Test counting multiple LDIF entries."""
        ldif_content = (
            "dn: cn=test1,dc=example,dc=com\n"
            "cn: test1\n\n"
            "dn: cn=test2,dc=example,dc=com\n"
            "cn: test2\n\n"
            "dn: cn=test3,dc=example,dc=com\n"
            "cn: test3\n"
        )

        result = client.count_ldif_entries(ldif_content)

        assert result.is_success
        assert result.unwrap() == 3

    def test_count_empty_content(self, client: FlextLdifClient) -> None:
        """Test counting empty content returns 0."""
        ldif_content = ""

        result = client.count_ldif_entries(ldif_content)

        assert result.is_success
        assert result.unwrap() == 0

    def test_count_whitespace_only(self, client: FlextLdifClient) -> None:
        """Test counting whitespace-only content returns 0."""
        ldif_content = "   \n  \t  \n"

        result = client.count_ldif_entries(ldif_content)

        assert result.is_success
        assert result.unwrap() == 0

    def test_count_entries_no_blank_lines(self, client: FlextLdifClient) -> None:
        """Test counting entries without blank line separators."""
        ldif_content = (
            "dn: cn=test1,dc=example,dc=com\n"
            "cn: test1\n"
            "dn: cn=test2,dc=example,dc=com\n"
            "cn: test2\n"
        )

        result = client.count_ldif_entries(ldif_content)

        assert result.is_success
        # Should count by "dn:" lines
        assert result.unwrap() == 2

    def test_count_case_insensitive_dn(self, client: FlextLdifClient) -> None:
        """Test counting with uppercase DN:."""
        ldif_content = (
            "DN: cn=test1,dc=example,dc=com\n"
            "cn: test1\n\n"
            "dn: cn=test2,dc=example,dc=com\n"
            "cn: test2\n"
        )

        result = client.count_ldif_entries(ldif_content)

        assert result.is_success
        assert result.unwrap() == 2

    def test_count_entries_with_comments(self, client: FlextLdifClient) -> None:
        """Test counting entries with LDIF comments."""
        ldif_content = (
            "# First entry\n"
            "dn: cn=test1,dc=example,dc=com\n"
            "cn: test1\n\n"
            "# Second entry\n"
            "dn: cn=test2,dc=example,dc=com\n"
            "cn: test2\n"
        )

        result = client.count_ldif_entries(ldif_content)

        assert result.is_success
        assert result.unwrap() == 2

    def test_count_large_number_of_entries(self, client: FlextLdifClient) -> None:
        """Test counting large number of entries."""
        # Generate 100 entries
        entries = [
            f"dn: cn=test{i},dc=example,dc=com\ncn: test{i}\n\n" for i in range(100)
        ]
        ldif_content = "".join(entries)

        result = client.count_ldif_entries(ldif_content)

        assert result.is_success
        assert result.unwrap() == 100


class TestParseLdif:
    """Test LDIF parsing from files and content strings."""

    def test_parse_ldif_from_content_string(self, client: FlextLdifClient) -> None:
        """Test parsing LDIF from content string."""
        ldif_content = (
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n\n"
        )

        result = client.parse_ldif(ldif_content)

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1
        assert entries[0].dn.value == "cn=test,dc=example,dc=com"
        assert entries[0].attributes.get("cn") == ["test"]

    def test_parse_ldif_from_path_object(
        self, client: FlextLdifClient, tmp_path: Path
    ) -> None:
        """Test parsing LDIF from Path object."""
        # Create test LDIF file
        ldif_content = (
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n\n"
        )
        test_file = tmp_path / "test.ldif"
        test_file.write_text(ldif_content)

        result = client.parse_ldif(test_file)

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1
        assert entries[0].dn.value == "cn=test,dc=example,dc=com"
        assert entries[0].attributes.get("cn") == ["test"]

    def test_parse_ldif_with_minimal_container(self) -> None:
        """Test parse_ldif behavior with minimal container (real test, no mocks)."""
        # Create a real client with actual container
        # The default FlextLdifClient has parser registered, so this tests normal path
        client = FlextLdifClient()

        # Parse LDIF content with proper objectClass - should succeed with real parser
        ldif_content = "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n\n"
        result = client.parse_ldif(ldif_content)

        # Should succeed with real parser
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1
        assert entries[0].dn.value == "cn=test,dc=example,dc=com"
        assert entries[0].attributes.get("cn") == ["test"]


class TestWriteLdif:
    """Test LDIF writing to files and strings."""

    def test_write_ldif_to_string(self, client: FlextLdifClient) -> None:
        """Test writing LDIF to string (output_path=None)."""
        from flext_ldif.models import FlextLdifModels

        # Create test entry
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"], "objectclass": ["person"]},
        )
        entries = [entry_result.unwrap()]

        result = client.write_ldif(entries, output_path=None)

        assert result.is_success
        ldif_content = result.unwrap()
        # Real writer includes version header
        assert "version: 1" in ldif_content
        assert "dn: cn=test,dc=example,dc=com" in ldif_content
        assert "cn: test" in ldif_content
        assert "objectclass: person" in ldif_content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
