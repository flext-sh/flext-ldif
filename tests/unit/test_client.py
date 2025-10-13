"""Unit tests for FlextLdifClient - LDIF/Encoding Utility Methods.

Tests the integrated LDIF and encoding utility methods in FlextLdifClient.

NOTE: Due to pre-existing FlextLdifClient initialization issues (FlextLdifQuirksRegistry
Pydantic model not fully defined), these tests use mocking to test the new utility methods
without requiring full client initialization. The methods themselves are tested in isolation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from flext_ldif.client import FlextLdifClient


@pytest.fixture
def mock_client() -> FlextLdifClient:
    """Create a FlextLdifClient with mocked initialization.

    Bypasses the pre-existing initialization issues to test utility methods in isolation.
    """
    with patch.object(FlextLdifClient, "model_post_init", return_value=None):
        client = object.__new__(FlextLdifClient)
        # Initialize only what's needed for utility methods (nothing)
        return client


class TestDetectEncoding:
    """Test encoding detection from raw bytes."""

    def test_detect_utf8_encoding(self, mock_client: FlextLdifClient) -> None:
        """Test detection of UTF-8 encoded content."""
        client = mock_client
        utf8_content = "dn: cn=José,dc=example,dc=com\n".encode()

        result = client.detect_encoding(utf8_content)

        assert result.is_success
        assert result.unwrap() == "utf-8"

    def test_detect_latin1_encoding_fallback(self, mock_client: FlextLdifClient) -> None:
        """Test fallback to latin-1 for non-UTF-8 content."""
        client = mock_client
        # Create bytes that are invalid UTF-8 but valid latin-1
        latin1_content = b"dn: cn=test\x80invalid\x90utf8,dc=example,dc=com\n"

        result = client.detect_encoding(latin1_content)

        assert result.is_success
        assert result.unwrap() == "latin-1"

    def test_detect_encoding_empty_bytes(self, mock_client: FlextLdifClient) -> None:
        """Test encoding detection with empty bytes."""
        client = mock_client
        empty_content = b""

        result = client.detect_encoding(empty_content)

        assert result.is_success
        # Empty bytes should decode as UTF-8
        assert result.unwrap() == "utf-8"

    def test_detect_encoding_ascii_compatible(self, mock_client: FlextLdifClient) -> None:
        """Test ASCII content (UTF-8 compatible)."""
        client = mock_client
        ascii_content = b"dn: cn=test,dc=example,dc=com\n"

        result = client.detect_encoding(ascii_content)

        assert result.is_success
        assert result.unwrap() == "utf-8"

    def test_detect_encoding_unicode_characters(self, mock_client: FlextLdifClient) -> None:
        """Test UTF-8 with various Unicode characters."""
        client = mock_client
        unicode_content = "dn: cn=日本語テスト,dc=example,dc=com\n".encode()

        result = client.detect_encoding(unicode_content)

        assert result.is_success
        assert result.unwrap() == "utf-8"


class TestNormalizeEncoding:
    """Test encoding normalization."""

    def test_normalize_to_utf8(self, mock_client: FlextLdifClient) -> None:
        """Test normalization to UTF-8."""
        client = mock_client
        content = "dn: cn=José,dc=example,dc=com\n"

        result = client.normalize_encoding(content, "utf-8")

        assert result.is_success
        normalized = result.unwrap()
        assert normalized == content

    def test_normalize_to_latin1(self, mock_client: FlextLdifClient) -> None:
        """Test normalization to latin-1."""
        client = mock_client
        # Use only latin-1 compatible characters
        content = "dn: cn=test,dc=example,dc=com\n"

        result = client.normalize_encoding(content, "latin-1")

        assert result.is_success
        normalized = result.unwrap()
        assert normalized == content

    def test_normalize_encoding_default_utf8(self, mock_client: FlextLdifClient) -> None:
        """Test normalization with default UTF-8 encoding."""
        client = mock_client
        content = "dn: cn=test,dc=example,dc=com\n"

        result = client.normalize_encoding(content)

        assert result.is_success
        assert result.unwrap() == content

    def test_normalize_encoding_invalid_characters(self, mock_client: FlextLdifClient) -> None:
        """Test normalization failure with invalid characters for target encoding."""
        client = mock_client
        # Unicode characters not representable in ASCII
        content = "dn: cn=José,dc=example,dc=com\n"

        result = client.normalize_encoding(content, "ascii")

        assert result.is_failure
        assert result.error is not None
        assert "not representable in ascii" in result.error.lower()

    def test_normalize_empty_content(self, mock_client: FlextLdifClient) -> None:
        """Test normalization of empty content."""
        client = mock_client
        content = ""

        result = client.normalize_encoding(content, "utf-8")

        assert result.is_success
        assert not result.unwrap()

    def test_normalize_unicode_content(self, mock_client: FlextLdifClient) -> None:
        """Test normalization with Unicode characters."""
        client = mock_client
        content = "dn: cn=日本語テスト,dc=example,dc=com\n"

        result = client.normalize_encoding(content, "utf-8")

        assert result.is_success
        assert result.unwrap() == content


class TestValidateLdifSyntax:
    """Test LDIF syntax validation."""

    def test_validate_valid_single_entry(self, mock_client: FlextLdifClient) -> None:
        """Test validation of valid single entry LDIF."""
        client = mock_client
        ldif_content = "dn: cn=test,dc=example,dc=com\ncn: test\n"

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_valid_multiple_entries(self, mock_client: FlextLdifClient) -> None:
        """Test validation of valid multiple entry LDIF."""
        client = mock_client
        ldif_content = (
            "dn: cn=test1,dc=example,dc=com\n"
            "cn: test1\n\n"
            "dn: cn=test2,dc=example,dc=com\n"
            "cn: test2\n"
        )

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_empty_content(self, mock_client: FlextLdifClient) -> None:
        """Test validation of empty content returns False."""
        client = mock_client
        ldif_content = ""

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is False

    def test_validate_whitespace_only(self, mock_client: FlextLdifClient) -> None:
        """Test validation of whitespace-only content returns False."""
        client = mock_client
        ldif_content = "   \n  \t  \n"

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is False

    def test_validate_missing_dn_line(self, mock_client: FlextLdifClient) -> None:
        """Test validation fails when no dn: line present."""
        client = mock_client
        ldif_content = "cn: test\nobjectClass: person\n"

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is False

    def test_validate_case_insensitive_dn(self, mock_client: FlextLdifClient) -> None:
        """Test validation accepts DN: (uppercase)."""
        client = mock_client
        ldif_content = "DN: cn=test,dc=example,dc=com\ncn: test\n"

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_dn_with_spaces(self, mock_client: FlextLdifClient) -> None:
        """Test validation with DN containing spaces."""
        client = mock_client
        ldif_content = "dn: cn=John Smith,ou=People,dc=example,dc=com\ncn: John Smith\n"

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_dn_with_special_chars(self, mock_client: FlextLdifClient) -> None:
        """Test validation with DN containing special characters."""
        client = mock_client
        ldif_content = r"dn: cn=Smith\, John,ou=People,dc=example,dc=com" + "\ncn: Smith, John\n"

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_minimal_ldif(self, mock_client: FlextLdifClient) -> None:
        """Test validation with minimal valid LDIF (just dn:)."""
        client = mock_client
        ldif_content = "dn: dc=example,dc=com\n"

        result = client.validate_ldif_syntax(ldif_content)

        assert result.is_success
        assert result.unwrap() is True


class TestCountLdifEntries:
    """Test LDIF entry counting."""

    def test_count_single_entry(self, mock_client: FlextLdifClient) -> None:
        """Test counting single LDIF entry."""
        client = mock_client
        ldif_content = "dn: cn=test,dc=example,dc=com\ncn: test\n"

        result = client.count_ldif_entries(ldif_content)

        assert result.is_success
        assert result.unwrap() == 1

    def test_count_multiple_entries(self, mock_client: FlextLdifClient) -> None:
        """Test counting multiple LDIF entries."""
        client = mock_client
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

    def test_count_empty_content(self, mock_client: FlextLdifClient) -> None:
        """Test counting empty content returns 0."""
        client = mock_client
        ldif_content = ""

        result = client.count_ldif_entries(ldif_content)

        assert result.is_success
        assert result.unwrap() == 0

    def test_count_whitespace_only(self, mock_client: FlextLdifClient) -> None:
        """Test counting whitespace-only content returns 0."""
        client = mock_client
        ldif_content = "   \n  \t  \n"

        result = client.count_ldif_entries(ldif_content)

        assert result.is_success
        assert result.unwrap() == 0

    def test_count_entries_no_blank_lines(self, mock_client: FlextLdifClient) -> None:
        """Test counting entries without blank line separators."""
        client = mock_client
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

    def test_count_case_insensitive_dn(self, mock_client: FlextLdifClient) -> None:
        """Test counting with uppercase DN:."""
        client = mock_client
        ldif_content = (
            "DN: cn=test1,dc=example,dc=com\n"
            "cn: test1\n\n"
            "dn: cn=test2,dc=example,dc=com\n"
            "cn: test2\n"
        )

        result = client.count_ldif_entries(ldif_content)

        assert result.is_success
        assert result.unwrap() == 2

    def test_count_entries_with_comments(self, mock_client: FlextLdifClient) -> None:
        """Test counting entries with LDIF comments."""
        client = mock_client
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

    def test_count_large_number_of_entries(self, mock_client: FlextLdifClient) -> None:
        """Test counting large number of entries."""
        client = mock_client
        # Generate 100 entries
        entries = [
            f"dn: cn=test{i},dc=example,dc=com\ncn: test{i}\n\n"
            for i in range(100)
        ]
        ldif_content = "".join(entries)

        result = client.count_ldif_entries(ldif_content)

        assert result.is_success
        assert result.unwrap() == 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
