"""Unit tests for FlextLdifClient - LDIF/Encoding Utility Methods.

Tests the integrated LDIF and encoding utility methods in FlextLdifClient.

NOTE: Due to pre-existing FlextLdifClient initialization issues (FlextLdifQuirksRegistry
Pydantic model not fully defined), these tests use mocking to test the new utility methods
without requiring full client initialization. The methods themselves are tested in isolation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import cast
from unittest.mock import patch

import pytest

from flext_ldif.client import FlextLdifClient


@pytest.fixture
def mock_client() -> FlextLdifClient:
    """Create a FlextLdifClient with mocked initialization.

    Bypasses the pre-existing initialization issues to test utility methods in isolation.
    """
    with patch.object(FlextLdifClient, "model_post_init", return_value=None):
        # Initialize only what's needed for utility methods (nothing)
        return cast("FlextLdifClient", object.__new__(FlextLdifClient))


class TestDetectEncoding:
    """Test encoding detection from raw bytes."""

    def test_detect_utf8_encoding(self, mock_client: FlextLdifClient) -> None:
        """Test detection of UTF-8 encoded content."""
        client = mock_client
        utf8_content = "dn: cn=José,dc=example,dc=com\n".encode()

        result = client.detect_encoding(utf8_content)

        assert result.is_success
        assert result.unwrap() == "utf-8"

    def test_detect_latin1_encoding_fallback(
        self, mock_client: FlextLdifClient
    ) -> None:
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

    def test_detect_encoding_ascii_compatible(
        self, mock_client: FlextLdifClient
    ) -> None:
        """Test ASCII content (UTF-8 compatible)."""
        client = mock_client
        ascii_content = b"dn: cn=test,dc=example,dc=com\n"

        result = client.detect_encoding(ascii_content)

        assert result.is_success
        assert result.unwrap() == "utf-8"

    def test_detect_encoding_unicode_characters(
        self, mock_client: FlextLdifClient
    ) -> None:
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

    def test_normalize_encoding_default_utf8(
        self, mock_client: FlextLdifClient
    ) -> None:
        """Test normalization with default UTF-8 encoding."""
        client = mock_client
        content = "dn: cn=test,dc=example,dc=com\n"

        result = client.normalize_encoding(content)

        assert result.is_success
        assert result.unwrap() == content

    def test_normalize_encoding_invalid_characters(
        self, mock_client: FlextLdifClient
    ) -> None:
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

    def test_validate_valid_multiple_entries(
        self, mock_client: FlextLdifClient
    ) -> None:
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
        ldif_content = (
            r"dn: cn=Smith\, John,ou=People,dc=example,dc=com" + "\ncn: Smith, John\n"
        )

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
            f"dn: cn=test{i},dc=example,dc=com\ncn: test{i}\n\n" for i in range(100)
        ]
        ldif_content = "".join(entries)

        result = client.count_ldif_entries(ldif_content)

        assert result.is_success
        assert result.unwrap() == 100


class TestParseLdif:
    """Test LDIF parsing from files and content strings."""

    def test_parse_ldif_from_content_string(self, mock_client: FlextLdifClient) -> None:
        """Test parsing LDIF from content string."""
        from unittest.mock import MagicMock, PropertyMock

        from flext_core import FlextCore

        from flext_ldif.models import FlextLdifModels
        from flext_ldif.rfc.rfc_ldif_parser import FlextLdifRfcLdifParser

        client = mock_client
        ldif_content = "dn: cn=test,dc=example,dc=com\ncn: test\n"

        # Create mock entry
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"]},
        )
        mock_entry = entry_result.unwrap()

        # Mock parser
        mock_parser = MagicMock(spec=FlextLdifRfcLdifParser)
        mock_parser.parse_content.return_value = FlextCore.Result[
            list[FlextLdifModels.Entry]
        ].ok([mock_entry])

        # Mock container
        mock_container = MagicMock()
        mock_container.get.return_value = FlextCore.Result[FlextLdifRfcLdifParser].ok(
            mock_parser
        )

        # Mock the container property
        with patch.object(
            type(client), "container", new_callable=PropertyMock
        ) as mock_prop:
            mock_prop.return_value = mock_container

            result = client.parse_ldif(ldif_content)

            assert result.is_success
            entries = result.unwrap()
            assert len(entries) == 1
            assert entries[0].dn.value == "cn=test,dc=example,dc=com"
            mock_parser.parse_content.assert_called_once_with(ldif_content)

    def test_parse_ldif_from_path_object(self, mock_client: FlextLdifClient) -> None:
        """Test parsing LDIF from Path object."""
        from pathlib import Path
        from unittest.mock import MagicMock, PropertyMock

        from flext_core import FlextCore

        from flext_ldif.models import FlextLdifModels
        from flext_ldif.rfc.rfc_ldif_parser import FlextLdifRfcLdifParser

        client = mock_client
        test_path = Path("/tmp/test.ldif")

        # Create mock entry
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"]},
        )
        mock_entry = entry_result.unwrap()

        # Mock parser
        mock_parser = MagicMock(spec=FlextLdifRfcLdifParser)
        mock_parser.parse_ldif_file.return_value = FlextCore.Result[
            list[FlextLdifModels.Entry]
        ].ok([mock_entry])

        # Mock container
        mock_container = MagicMock()
        mock_container.get.return_value = FlextCore.Result[FlextLdifRfcLdifParser].ok(
            mock_parser
        )

        # Mock the container property
        with patch.object(
            type(client), "container", new_callable=PropertyMock
        ) as mock_prop:
            mock_prop.return_value = mock_container

            result = client.parse_ldif(test_path)

            assert result.is_success
            entries = result.unwrap()
            assert len(entries) == 1
            mock_parser.parse_ldif_file.assert_called_once_with(test_path)

    def test_parse_ldif_parser_not_available(
        self, mock_client: FlextLdifClient
    ) -> None:
        """Test parse_ldif fails when parser not available."""
        from unittest.mock import MagicMock, PropertyMock

        from flext_core import FlextCore

        client = mock_client

        # Mock container returning failure
        mock_container = MagicMock()
        mock_container.get.return_value = FlextCore.Result[object].fail(
            "Parser not found"
        )

        # Mock the container property
        with patch.object(
            type(client), "container", new_callable=PropertyMock
        ) as mock_prop:
            mock_prop.return_value = mock_container

            result = client.parse_ldif("dn: cn=test,dc=example,dc=com\n")

            assert result.is_failure
            assert result.error is not None
            assert "Failed to get RFC parser" in result.error


class TestWriteLdif:
    """Test LDIF writing to files and strings."""

    def test_write_ldif_to_string(self, mock_client: FlextLdifClient) -> None:
        """Test writing LDIF to string (output_path=None)."""
        from unittest.mock import MagicMock, PropertyMock

        from flext_core import FlextCore

        from flext_ldif.models import FlextLdifModels
        from flext_ldif.rfc.rfc_ldif_writer import FlextLdifRfcLdifWriter

        client = mock_client

        # Create test entry
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"], "objectClass": ["person"]},
        )
        entries = [entry_result.unwrap()]

        expected_ldif = (
            "dn: cn=test,dc=example,dc=com\ncn: test\nobjectClass: person\n\n"
        )

        # Mock writer
        mock_writer = MagicMock(spec=FlextLdifRfcLdifWriter)
        mock_writer.write_entries_to_string.return_value = FlextCore.Result[str].ok(
            expected_ldif
        )

        # Mock container
        mock_container = MagicMock()
        mock_container.get.return_value = FlextCore.Result[FlextLdifRfcLdifWriter].ok(
            mock_writer
        )

        # Mock the container property
        with patch.object(
            type(client), "container", new_callable=PropertyMock
        ) as mock_prop:
            mock_prop.return_value = mock_container

            result = client.write_ldif(entries, output_path=None)

            assert result.is_success
            ldif_content = result.unwrap()
            assert ldif_content == expected_ldif
            mock_writer.write_entries_to_string.assert_called_once_with(entries)

    def test_write_ldif_writer_not_available(
        self, mock_client: FlextLdifClient
    ) -> None:
        """Test write_ldif fails when writer not available."""
        from unittest.mock import MagicMock, PropertyMock

        from flext_core import FlextCore

        from flext_ldif.models import FlextLdifModels

        client = mock_client

        # Create test entry
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"]},
        )
        entries = [entry_result.unwrap()]

        # Mock container returning failure
        mock_container = MagicMock()
        mock_container.get.return_value = FlextCore.Result[object].fail(
            "Writer not found"
        )

        # Mock the container property
        with patch.object(
            type(client), "container", new_callable=PropertyMock
        ) as mock_prop:
            mock_prop.return_value = mock_container

            result = client.write_ldif(entries)

            assert result.is_failure
            assert result.error is not None
            assert "Failed to get RFC writer" in result.error


class TestValidateEntries:
    """Test LDIF entry validation."""

    def test_validate_entries_all_valid(self, mock_client: FlextLdifClient) -> None:
        """Test validation with all valid entries."""
        from unittest.mock import MagicMock, PropertyMock

        from flext_core import FlextCore

        from flext_ldif.models import FlextLdifModels
        from flext_ldif.schema.validator import FlextLdifSchemaValidator

        client = mock_client

        # Create test entries
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"], "objectClass": ["person"]},
        )
        entries = [entry_result.unwrap()]

        # Mock validation result
        mock_validation = MagicMock()
        mock_validation.is_valid = True
        mock_validation.errors = []

        # Mock validator
        mock_validator = MagicMock(spec=FlextLdifSchemaValidator)
        mock_validator.validate_entries.return_value = FlextCore.Result[object].ok(
            mock_validation
        )

        # Mock container
        mock_container = MagicMock()
        mock_container.get.return_value = FlextCore.Result[FlextLdifSchemaValidator].ok(
            mock_validator
        )

        # Mock the container property
        with patch.object(
            type(client), "container", new_callable=PropertyMock
        ) as mock_prop:
            mock_prop.return_value = mock_container

            result = client.validate_entries(entries)

            assert result.is_success
            report = result.unwrap()
            assert report["is_valid"] is True
            assert report["total_entries"] == 1
            assert report["valid_entries"] == 1
            assert report["invalid_entries"] == 0
            assert len(cast("list[str]", report["errors"])) == 0

    def test_validate_entries_validator_not_available(
        self, mock_client: FlextLdifClient
    ) -> None:
        """Test validate_entries fails when validator not available."""
        from unittest.mock import MagicMock, PropertyMock

        from flext_core import FlextCore

        from flext_ldif.models import FlextLdifModels

        client = mock_client

        # Create test entry
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"]},
        )
        entries = [entry_result.unwrap()]

        # Mock container returning failure
        mock_container = MagicMock()
        mock_container.get.return_value = FlextCore.Result[object].fail(
            "Validator not found"
        )

        # Mock the container property
        with patch.object(
            type(client), "container", new_callable=PropertyMock
        ) as mock_prop:
            mock_prop.return_value = mock_container

            result = client.validate_entries(entries)

            assert result.is_failure
            assert result.error is not None
            assert "Failed to get schema validator" in result.error


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
