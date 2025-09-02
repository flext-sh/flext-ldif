"""Tests for LDIF format handler service - comprehensive coverage."""

# ruff: noqa: PT018
# Reason: Multiple assertion checks are common in tests for comprehensive error validation

import base64
import unittest.mock
from collections import UserString
from typing import Never
from unittest.mock import Mock

import pytest

import flext_ldif.format_handler_service as fh
from flext_ldif.format_handler_service import (
    FlextLDIFFormatHandler,
    FlextLDIFParser,
    FlextLDIFWriter,
)
from flext_ldif.models import FlextLDIFEntry


class TestFlextLDIFFormatHandler:
    """Test FlextLDIFFormatHandler class methods."""

    def test_parse_ldif_basic(self) -> None:
        """Test basic LDIF parsing through class method."""
        ldif_content = """dn: cn=John Doe,ou=people,dc=example,dc=com
cn: John Doe
sn: Doe
objectClass: person

dn: cn=Jane Smith,ou=people,dc=example,dc=com
cn: Jane Smith
sn: Smith
objectClass: person
"""
        result = FlextLDIFFormatHandler.parse_ldif(ldif_content)
        assert result.is_success
        entries = result.value
        assert len(entries) == 2
        assert isinstance(entries[0], FlextLDIFEntry)
        assert str(entries[0].dn) == "cn=John Doe,ou=people,dc=example,dc=com"

    def test_write_ldif_basic(self) -> None:
        """Test basic LDIF writing through class method."""
        entry = FlextLDIFEntry(
            dn="cn=Test User,ou=people,dc=example,dc=com",
            attributes={"cn": ["Test User"], "sn": ["User"], "objectClass": ["person"]},
        )

        result = FlextLDIFFormatHandler.write_ldif([entry])
        assert result.is_success
        ldif_output = result.value
        assert "dn: cn=Test User,ou=people,dc=example,dc=com" in ldif_output
        assert "cn: Test User" in ldif_output

    def test_parse_ldif_empty_content(self) -> None:
        """Test parsing empty LDIF content."""
        result = FlextLDIFFormatHandler.parse_ldif("")
        assert result.is_success
        entries = result.value
        assert len(entries) == 0

    def test_write_ldif_empty_entries(self) -> None:
        """Test writing empty entry list."""
        result = FlextLDIFFormatHandler.write_ldif([])
        assert result.is_success
        ldif_output = result.value
        assert ldif_output == ""


class TestInternalFunctions:
    """Test internal functions through the module."""

    def test_validate_url_scheme_valid(self) -> None:
        """Test URL scheme validation with valid schemes."""
        # Access internal function through module

        # Test valid schemes
        fh._validate_url_scheme("https://example.com/file.ldif")
        fh._validate_url_scheme("http://example.com/file.ldif")
        # Should not raise exception

    def test_validate_url_scheme_invalid(self) -> None:
        """Test URL scheme validation with invalid schemes."""
        with pytest.raises(ValueError, match="URL scheme 'ftp' not allowed"):
            fh._validate_url_scheme("ftp://example.com/file.ldif")

    def test_safe_url_fetch_success(self) -> None:
        """Test successful URL fetching with mock response."""
        # Mock urllib3 PoolManager to avoid actual HTTP requests
        with unittest.mock.patch(
            "flext_ldif.format_handler_service.urllib3.PoolManager"
        ) as mock_pool:
            # Create mock response
            mock_response = Mock()
            mock_response.status = HTTP_OK
            mock_response.data = b"dn: cn=test,dc=example,dc=com\nobjectClass: person"

            # Configure mock to return our response
            mock_http = mock_pool.return_value
            mock_http.request.return_value = mock_response

            result = fh._safe_url_fetch("https://example.com/test.ldif")

            assert result == "dn: cn=test,dc=example,dc=com\nobjectClass: person"
            mock_http.request.assert_called_once_with(
                "GET", "https://example.com/test.ldif"
            )

    def test_safe_url_fetch_http_error(self) -> None:
        """Test URL fetching with HTTP error response."""
        with unittest.mock.patch(
            "flext_ldif.format_handler_service.urllib3.PoolManager"
        ) as mock_pool:
            # Create mock response with error status
            mock_response = Mock()
            mock_response.status = 404

            mock_http = mock_pool.return_value
            mock_http.request.return_value = mock_response

            with pytest.raises(ValueError, match="HTTP 404: Failed to fetch"):
                fh._safe_url_fetch("https://example.com/nonexistent.ldif")

    def test_safe_url_fetch_network_error(self) -> None:
        """Test URL fetching with network errors."""
        with unittest.mock.patch(
            "flext_ldif.format_handler_service.urllib3.PoolManager"
        ) as mock_pool:
            # Mock network error
            mock_http = mock_pool.return_value
            mock_http.request.side_effect = OSError("Network unreachable")

            with pytest.raises(
                ValueError, match="urllib3 fetch error for.*Network unreachable"
            ):
                fh._safe_url_fetch("https://example.com/test.ldif")

    def test_safe_url_fetch_invalid_url_scheme(self) -> None:
        """Test URL fetching with invalid URL scheme."""
        with pytest.raises(ValueError, match="URL scheme 'ftp' not allowed"):
            fh._safe_url_fetch("ftp://example.com/test.ldif")

    def test_safe_url_fetch_encoding_error(self) -> None:
        """Test URL fetching with encoding issues."""
        with unittest.mock.patch(
            "flext_ldif.format_handler_service.urllib3.PoolManager"
        ) as mock_pool:
            # Create mock response with invalid encoding
            mock_response = Mock()
            mock_response.status = HTTP_OK
            mock_response.data = b"\xff\xfe invalid utf-8"

            mock_http = mock_pool.return_value
            mock_http.request.return_value = mock_response

            with pytest.raises(ValueError, match="urllib3 fetch error for"):
                fh._safe_url_fetch("https://example.com/test.ldif", encoding="utf-8")

    def test_safe_url_fetch_custom_encoding(self) -> None:
        """Test URL fetching with custom encoding."""
        with unittest.mock.patch(
            "flext_ldif.format_handler_service.urllib3.PoolManager"
        ) as mock_pool:
            # Create mock response with latin-1 encoded content
            content = "dn: cn=José,dc=example,dc=com"
            mock_response = Mock()
            mock_response.status = HTTP_OK
            mock_response.data = content.encode("latin-1")

            mock_http = mock_pool.return_value
            mock_http.request.return_value = mock_response

            result = fh._safe_url_fetch(
                "https://example.com/test.ldif", encoding="latin-1"
            )

            assert result == content


class TestFlextLDIFWriter:
    """Test LDIF writer functionality."""

    def test_writer_initialization_default(self) -> None:
        """Test writer initialization with defaults."""
        writer = FlextLDIFWriter()
        assert writer._cols == 76
        assert writer._line_sep == "\n"
        assert writer._encoding == "utf-8"
        assert writer.records_written == 0

    def test_writer_initialization_custom(self) -> None:
        """Test writer with custom parameters."""
        writer = FlextLDIFWriter(
            cols=80, line_sep="\r\n", base64_attrs=["userCertificate"], encoding="utf-8"
        )
        assert writer._cols == 80
        assert writer._line_sep == "\r\n"
        assert "usercertificate" in writer._base64_attrs  # Should be lowercased
        assert writer._encoding == "utf-8"

    def test_needs_base64_encoding_safe_string(self) -> None:
        """Test base64 encoding detection with safe string."""
        writer = FlextLDIFWriter()
        assert writer._needs_base64_encoding("cn", "John Doe") is False
        assert writer._needs_base64_encoding("mail", "john@example.com") is False

    def test_needs_base64_encoding_unsafe_string(self) -> None:
        """Test base64 encoding detection with unsafe string."""
        writer = FlextLDIFWriter()
        # String starting with space
        assert (
            writer._needs_base64_encoding("description", " starts with space") is True
        )
        # String with non-ASCII characters
        assert writer._needs_base64_encoding("cn", "José María") is True

    def test_needs_base64_encoding_forced_attrs(self) -> None:
        """Test base64 encoding for forced attributes."""
        writer = FlextLDIFWriter(base64_attrs=["userCertificate"])
        assert writer._needs_base64_encoding("userCertificate", "safe value") is True
        assert writer._needs_base64_encoding("cn", "safe value") is False

    def test_get_output_empty(self) -> None:
        """Test getting output from empty writer."""
        writer = FlextLDIFWriter()
        output = writer.get_output()
        assert output == ""

    def test_unparse_simple_entry(self) -> None:
        """Test unparsing a simple entry."""
        writer = FlextLDIFWriter()
        dn = "cn=John Doe,ou=people,dc=example,dc=com"
        record = {"cn": ["John Doe"], "objectClass": ["person"]}
        writer.unparse(dn, record)
        output = writer.get_output()

        assert f"dn: {dn}" in output
        assert "cn: John Doe" in output
        assert "objectClass: person" in output
        assert writer.records_written == 1

    def test_unparse_entry_with_base64(self) -> None:
        """Test unparsing entry with base64 encoded values."""
        writer = FlextLDIFWriter()
        dn = "cn=José María,ou=people,dc=example,dc=com"
        record = {"cn": ["José María"], "description": [" starts with space"]}
        writer.unparse(dn, record)
        output = writer.get_output()

        assert "dn::" in output  # DN is base64 encoded due to special characters
        assert "cn:: " in output  # Should be base64 encoded
        assert "description:: " in output  # Should be base64 encoded

    def test_unparse_multiple_entries(self) -> None:
        """Test unparsing multiple entries."""
        writer = FlextLDIFWriter()

        writer.unparse(
            "dc=example,dc=com", {"objectClass": ["dcObject"], "dc": ["example"]}
        )
        writer.unparse(
            "ou=people,dc=example,dc=com",
            {"objectClass": ["organizationalUnit"], "ou": ["people"]},
        )

        output = writer.get_output()
        assert writer.records_written == 2
        assert "dn: dc=example,dc=com" in output
        assert "dn: ou=people,dc=example,dc=com" in output

    def test_unparse_with_line_wrapping(self) -> None:
        """Test unparsing entries with long lines that require wrapping."""
        writer = FlextLDIFWriter(cols=40)  # Short line length to force wrapping

        # Create entry with very long description to trigger line wrapping
        long_description = "A" * 100  # 100 character description
        dn = "cn=test,dc=example,dc=com"
        record = {
            "cn": ["test"],
            "description": [long_description],
            "objectClass": ["person"],
        }

        writer.unparse(dn, record)
        output = writer.get_output()

        # Check that long lines are wrapped with leading spaces
        lines = output.split("\n")
        wrapped_lines = [line for line in lines if line.startswith(" ")]
        assert len(wrapped_lines) > 0, "Expected wrapped lines with leading spaces"

        # Verify content is preserved despite wrapping
        assert "description:" in output
        assert long_description[:20] in output  # First part should be present

    def test_unparse_with_line_wrapping_exact_boundary(self) -> None:
        """Test line wrapping at exact column boundary."""
        writer = FlextLDIFWriter(cols=76)  # Standard LDIF line length

        # Create an attribute value that exactly fills the line
        exact_length_value = "A" * (76 - len("description: "))  # Exact fit
        dn = "cn=test,dc=example,dc=com"
        record = {"description": [exact_length_value]}

        writer.unparse(dn, record)
        output = writer.get_output()

        # Should not wrap if it fits exactly
        lines = output.split("\n")
        description_line = next(
            line for line in lines if line.startswith("description:")
        )
        assert len(description_line) <= 76

    def test_unparse_with_line_wrapping_over_boundary(self) -> None:
        """Test line wrapping when exceeding column boundary."""
        writer = FlextLDIFWriter(cols=30)  # Short to force wrapping

        # Create an attribute value that exceeds the line length
        long_value = "B" * 50  # Will exceed 30 character limit
        dn = "cn=test,dc=example,dc=com"
        record = {"description": [long_value]}

        writer.unparse(dn, record)
        output = writer.get_output()

        lines = output.split("\n")
        # Find lines that start with description or continuation
        desc_lines = [line for line in lines if line.startswith(("description:", " "))]

        # Should have multiple lines due to wrapping
        assert len(desc_lines) > 1, "Expected line wrapping for long value"

        # Continuation lines should start with space
        continuation_lines = [line for line in desc_lines if line.startswith(" ")]
        assert len(continuation_lines) > 0, (
            "Expected continuation lines with leading space"
        )


class TestFlextLDIFParser:
    """Test LDIF parser functionality."""

    def test_parser_initialization_simple(self) -> None:
        """Test parser initialization."""
        ldif_content = "dn: dc=example,dc=com\nobjectClass: dcObject\n\n"
        parser = FlextLDIFParser(ldif_content)
        assert parser._encoding == "utf-8"
        assert parser._ignored_attr_types == []

    def test_parser_initialization_with_ignored_attrs(self) -> None:
        """Test parser with ignored attributes."""
        ldif_content = "dn: dc=example,dc=com\nobjectClass: dcObject\n\n"
        parser = FlextLDIFParser(
            ldif_content, ignored_attr_types=["modifiersName", "modifyTimestamp"]
        )
        assert "modifiersname" in parser._ignored_attr_types  # lowercased by lower_list
        assert "modifytimestamp" in parser._ignored_attr_types

    def test_parse_simple_entry(self) -> None:
        """Test parsing simple entry."""
        ldif_content = """dn: dc=example,dc=com
objectClass: dcObject
dc: example

"""
        parser = FlextLDIFParser(ldif_content)
        entries = list(parser.parse())

        assert len(entries) == 1
        dn, record = entries[0]
        assert dn == "dc=example,dc=com"
        assert record["objectClass"] == ["dcObject"]
        assert record["dc"] == ["example"]

    def test_parse_multiple_entries(self) -> None:
        """Test parsing multiple entries."""
        ldif_content = """dn: dc=example,dc=com
objectClass: dcObject
dc: example

dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people

"""
        parser = FlextLDIFParser(ldif_content)
        entries = list(parser.parse())

        assert len(entries) == 2

        dn1, record1 = entries[0]
        assert dn1 == "dc=example,dc=com"
        assert record1["objectClass"] == ["dcObject"]

        dn2, record2 = entries[1]
        assert dn2 == "ou=people,dc=example,dc=com"
        assert record2["objectClass"] == ["organizationalUnit"]

    def test_parse_entry_with_multivalue_attrs(self) -> None:
        """Test parsing entry with multi-value attributes."""
        ldif_content = """dn: cn=John Doe,ou=people,dc=example,dc=com
cn: John Doe
objectClass: person
objectClass: inetOrgPerson
mail: john@example.com
mail: johndoe@example.com

"""
        parser = FlextLDIFParser(ldif_content)
        entries = list(parser.parse())

        assert len(entries) == 1
        _dn, record = entries[0]
        assert record["objectClass"] == ["person", "inetOrgPerson"]
        assert record["mail"] == ["john@example.com", "johndoe@example.com"]

    def test_parse_entry_with_base64_values(self) -> None:
        """Test parsing entry with base64 encoded values."""
        # Create base64 encoded value
        original_value = "José María"
        encoded_value = base64.b64encode(original_value.encode("utf-8")).decode("ascii")

        ldif_content = f"""dn: cn=José María,ou=people,dc=example,dc=com
cn:: {encoded_value}
objectClass: person

"""
        parser = FlextLDIFParser(ldif_content)
        entries = list(parser.parse())

        assert len(entries) == 1
        _dn, record = entries[0]
        assert record["cn"] == [original_value]

    def test_parse_with_folded_lines(self) -> None:
        """Test parsing LDIF with folded lines."""
        ldif_content = """dn: cn=very long name that needs
 to be folded across multiple lines,ou=people,dc=example,dc=com
cn: very long name that needs to be folded across multiple lines
objectClass: person

"""
        parser = FlextLDIFParser(ldif_content)
        entries = list(parser.parse())

        assert len(entries) == 1
        dn, record = entries[0]
        # Check that DN contains the key parts (folded lines may have formatting differences)
        assert "very long name that needs" in dn
        assert "ou=people,dc=example,dc=com" in dn
        assert (
            "very long name that needs to be folded across multiple lines"
            in record["cn"][0]
        )

    def test_parse_with_ignored_attributes(self) -> None:
        """Test parsing with ignored attributes."""
        ldif_content = """dn: cn=John Doe,ou=people,dc=example,dc=com
cn: John Doe
objectClass: person
modifiersName: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com
modifyTimestamp: 20230101120000Z

"""
        parser = FlextLDIFParser(
            ldif_content, ignored_attr_types=["modifiersName", "modifyTimestamp"]
        )
        entries = list(parser.parse())

        assert len(entries) == 1
        _dn, record = entries[0]
        assert record["cn"] == ["John Doe"]
        assert record["objectClass"] == ["person"]
        assert "modifiersName" not in record
        assert "modifyTimestamp" not in record

    def test_parse_base64_decode_error(self) -> None:
        """Test parsing LDIF with invalid base64 values."""
        # Invalid base64 content
        ldif_content = """dn: cn=test,dc=example,dc=com
cn:: invalid-base64-!@#$%
objectClass: person

"""
        parser = FlextLDIFParser(ldif_content)

        # Should raise ValueError for base64 decode error
        with pytest.raises(ValueError, match="Base64 decode error"):
            list(parser.parse())

    def test_parse_url_reference(self) -> None:
        """Test parsing LDIF with URL references."""
        # Mock _safe_url_fetch to avoid actual HTTP requests

        with unittest.mock.patch.object(fh, "_safe_url_fetch") as mock_fetch:
            mock_fetch.return_value = "Test User"

            ldif_content = """dn: cn=test,dc=example,dc=com
cn:< https://example.com/name.txt
objectClass: person

"""
            parser = FlextLDIFParser(ldif_content)
            entries = list(parser.parse())

            assert len(entries) == 1
            _dn, record = entries[0]
            assert record["cn"] == ["Test User"]
            mock_fetch.assert_called_once_with("https://example.com/name.txt", "utf-8")

    def test_parse_url_reference_fetch_error(self) -> None:
        """Test parsing LDIF with URL reference fetch error."""
        # Mock _safe_url_fetch to raise error
        with unittest.mock.patch.object(fh, "_safe_url_fetch") as mock_fetch:
            mock_fetch.side_effect = ValueError("Network error")

            ldif_content = """dn: cn=test,dc=example,dc=com
cn:< https://example.com/name.txt
objectClass: person

"""
            parser = FlextLDIFParser(ldif_content)

            # Should raise ValueError for URL fetch error
            with pytest.raises(ValueError, match="URL fetch error"):
                list(parser.parse())

    def test_parse_strict_mode_utf8_validation(self) -> None:
        """Test parser in strict mode with UTF-8 validation."""
        # Create parser with strict mode
        ldif_content = """dn: cn=José,dc=example,dc=com
cn: José María
objectClass: person

"""
        parser = FlextLDIFParser(ldif_content, strict=True)
        entries = list(parser.parse())

        assert len(entries) == 1
        _dn, record = entries[0]
        assert record["cn"] == ["José María"]

    def test_parse_multiple_dn_entries_error(self) -> None:
        """Test parsing LDIF with multiple DN entries in one record."""
        ldif_content = """dn: cn=test,dc=example,dc=com
dn: cn=duplicate,dc=example,dc=com
objectClass: person

"""
        parser = FlextLDIFParser(ldif_content)

        # Should raise error for multiple DN lines
        with pytest.raises(ValueError, match="Multiple dn: lines in one record"):
            list(parser.parse())

    def test_parse_invalid_dn_format_error(self) -> None:
        """Test parsing LDIF with invalid DN format."""
        ldif_content = """dn: invalid_dn_format
objectClass: person

"""
        parser = FlextLDIFParser(ldif_content)

        # Should raise error for invalid DN format
        with pytest.raises(ValueError, match="Invalid distinguished name format"):
            list(parser.parse())

    def test_parse_attribute_before_dn_error(self) -> None:
        """Test parsing LDIF with attribute before DN."""
        ldif_content = """objectClass: person
dn: cn=test,dc=example,dc=com

"""
        parser = FlextLDIFParser(ldif_content)

        # Should raise error for attribute before DN
        with pytest.raises(ValueError, match="Attribute before dn: line"):
            list(parser.parse())

    def test_parse_version_line_handling(self) -> None:
        """Test parsing LDIF with version line."""
        ldif_content = """version: 1
dn: cn=test,dc=example,dc=com
objectClass: person
cn: test

"""
        parser = FlextLDIFParser(ldif_content)
        entries = list(parser.parse())

        # Should skip version line and parse the entry normally
        assert len(entries) == 1
        dn, record = entries[0]
        assert dn == "cn=test,dc=example,dc=com"
        assert record["objectClass"] == ["person"]

    def test_parse_strip_line_functionality(self) -> None:
        """Test parsing LDIF with line stripping functionality."""
        # Create simple content to test the _strip_line_sep method
        ldif_content = "dn: cn=test,dc=example,dc=com\nobjectClass: person\n\n"
        parser = FlextLDIFParser(ldif_content)

        # Test the _strip_line_sep method directly
        test_line = "test line\r\n"
        stripped = parser._strip_line_sep(test_line)
        assert stripped == "test line"

        # Test normal parsing works
        entries = list(parser.parse())
        assert len(entries) == 1

    def test_parse_line_counter_functionality(self) -> None:
        """Test that parser tracks line numbers correctly."""
        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test

"""
        parser = FlextLDIFParser(ldif_content)
        entries = list(parser.parse())

        # Should parse correctly and track lines
        assert len(entries) == 1
        dn, record = entries[0]
        assert dn == "cn=test,dc=example,dc=com"
        assert record["objectClass"] == ["person"]
        assert record["cn"] == ["test"]
        assert parser.line_counter > 0  # Should have processed some lines
        assert parser.records_read == 1  # Should have read one record

    def test_parse_invalid_line_format(self) -> None:
        """Test parsing LDIF with invalid line format (no colon)."""
        ldif_content = """dn: cn=test,dc=example,dc=com
invalid_line_without_colon
objectClass: person

"""
        parser = FlextLDIFParser(ldif_content)

        # Should raise ValueError for invalid line format
        with pytest.raises(ValueError, match="Invalid LDIF line format"):
            list(parser.parse())

    def test_parse_error_handling_strict_mode(self) -> None:
        """Test error handling in strict mode."""
        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person

"""
        parser = FlextLDIFParser(ldif_content, strict=True)

        # Test that _error raises ValueError in strict mode
        with pytest.raises(ValueError, match="Test error in strict mode"):
            parser._error("Test error in strict mode")

    def test_parse_error_handling_non_strict_mode(self) -> None:
        """Test error handling in non-strict mode (warning only)."""
        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person

"""
        parser = FlextLDIFParser(ldif_content, strict=False)

        # Test that _error logs warning in non-strict mode
        with unittest.mock.patch(
            "flext_ldif.format_handler_service.logger"
        ) as mock_logger:
            parser._error("Test warning message")
            mock_logger.warning.assert_called_once_with(
                "LDIF parsing warning: %s", "Test warning message"
            )

    def test_parse_dn_utf8_validation_strict_mode(self) -> None:
        """Test DN UTF-8 validation in strict mode."""
        # Create parser in strict mode
        parser = FlextLDIFParser("", strict=True)

        # Create a mock string object that raises UnicodeError on encode
        class MockString(UserString):
            def encode(
                self, encoding: str | None = "utf-8", errors: str | None = "strict"
            ) -> Never:
                msg = "Invalid UTF-8"
                raise UnicodeError(msg)

        mock_str = MockString("test value with invalid utf-8")

        # This should raise ValueError for invalid UTF-8 in strict mode
        with pytest.raises(ValueError, match="Invalid UTF-8"):
            parser._decode_value("dn", mock_str)

    def test_parse_dn_utf8_validation_non_strict_mode(self) -> None:
        """Test DN UTF-8 validation in non-strict mode."""
        # Create parser in non-strict mode
        parser = FlextLDIFParser("", strict=False)

        # Create a mock string object that raises UnicodeError on encode
        class MockString(UserString):
            def encode(
                self, encoding: str | None = "utf-8", errors: str | None = "strict"
            ) -> Never:
                msg = "Invalid UTF-8"
                raise UnicodeError(msg)

        mock_str = MockString("test value")

        # Should not raise error in non-strict mode, just return the value
        result = parser._decode_value("dn", mock_str)
        assert result == ("dn", mock_str)


class TestModernizedFunctions:
    """Test modernized LDIF functions."""

    def test_modernized_ldif_parse_simple(self) -> None:
        """Test modernized parse function."""
        ldif_content = """dn: dc=example,dc=com
objectClass: dcObject
dc: example

"""
        result = modernized_ldif_parse(ldif_content)
        assert result.is_success
        entries = result.value
        assert len(entries) == 1

        dn, record = entries[0]
        assert dn == "dc=example,dc=com"
        assert record["objectClass"] == ["dcObject"]
        assert record["dc"] == ["example"]

    def test_modernized_ldif_parse_with_params(self) -> None:
        """Test modernized parse function with parameters."""
        ldif_content = """dn: cn=John Doe,ou=people,dc=example,dc=com
cn: John Doe
modifiersName: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com
objectClass: person

"""
        result = modernized_ldif_parse(ldif_content)
        assert result.is_success
        entries = result.value

        assert len(entries) == 1
        dn, record = entries[0]
        assert dn == "cn=John Doe,ou=people,dc=example,dc=com"
        assert "cn" in record
        assert "objectClass" in record

    def test_modernized_ldif_write_simple(self) -> None:
        """Test modernized write function."""
        entries = [
            ("dc=example,dc=com", {"objectClass": ["dcObject"], "dc": ["example"]}),
            (
                "ou=people,dc=example,dc=com",
                {"objectClass": ["organizationalUnit"], "ou": ["people"]},
            ),
        ]

        result = modernized_ldif_write(entries)
        assert result.is_success
        ldif_output = result.value

        assert "dn: dc=example,dc=com" in ldif_output
        assert "objectClass: dcObject" in ldif_output
        assert "dc: example" in ldif_output
        assert "dn: ou=people,dc=example,dc=com" in ldif_output
        assert "objectClass: organizationalUnit" in ldif_output
        assert "ou: people" in ldif_output

    def test_modernized_ldif_write_with_params(self) -> None:
        """Test modernized write function with custom parameters."""
        entries = [
            (
                "cn=Test,dc=example,dc=com",
                {"cn": ["Test"], "description": [" starts with space"]},
            )
        ]

        result = modernized_ldif_write(entries)
        assert result.is_success
        ldif_output = result.value

        assert "dn: cn=Test,dc=example,dc=com" in ldif_output
        assert "cn: Test" in ldif_output
        assert "description:: " in ldif_output  # Should be base64 encoded

    def test_modernized_ldif_write_none_entries(self) -> None:
        """Test modernized write function with None entries."""
        result = modernized_ldif_write(None)
        assert result.is_failure
        assert (
            result.error is not None
            and "entries cannot be none" in result.error.lower()
        )

    def test_modernized_ldif_roundtrip(self) -> None:
        """Test that parse -> write -> parse produces same result."""
        original_ldif = """dn: dc=example,dc=com
objectClass: dcObject
dc: example

dn: cn=John Doe,ou=people,dc=example,dc=com
cn: John Doe
objectClass: person
mail: john@example.com

"""

        # Parse original
        parse_result = modernized_ldif_parse(original_ldif)
        assert parse_result.is_success
        entries = parse_result.value

        # Write back
        write_result = modernized_ldif_write(entries)
        assert write_result.is_success
        written_ldif = write_result.value

        # Parse again
        reparse_result = modernized_ldif_parse(written_ldif)
        assert reparse_result.is_success
        reparsed_entries = reparse_result.value

        # Should have same number of entries
        assert len(entries) == len(reparsed_entries)

        # Check that DNs match
        original_dns = [dn for dn, _ in entries]
        reparsed_dns = [dn for dn, _ in reparsed_entries]
        assert original_dns == reparsed_dns

    def test_modernized_ldif_parse_error_handling(self) -> None:
        """Test error handling in modernized_ldif_parse function."""
        # Mock FlextLDIFParser to raise an error
        with unittest.mock.patch(
            "flext_ldif.format_handler_service.FlextLDIFParser"
        ) as mock_parser_class:
            mock_parser_class.side_effect = ValueError("Parser initialization failed")

            result = modernized_ldif_parse("invalid content")

            assert result.is_failure
            assert (
                result.error is not None
                and "Modernized LDIF parse failed" in result.error
            )

    def test_modernized_ldif_write_error_handling(self) -> None:
        """Test error handling in modernized_ldif_write function."""
        # Mock FlextLDIFWriter to raise an error
        with unittest.mock.patch(
            "flext_ldif.format_handler_service.FlextLDIFWriter"
        ) as mock_writer_class:
            mock_writer_class.side_effect = ValueError("Writer initialization failed")

            entries = [("dn: cn=test,dc=example,dc=com", {"objectClass": ["person"]})]
            result = modernized_ldif_write(entries)

            assert result.is_failure
            assert (
                result.error is not None
                and "Modernized LDIF write failed" in result.error
            )

    def test_modernized_ldif_parse_unicode_error(self) -> None:
        """Test Unicode error handling in modernized_ldif_parse."""
        # Mock the parser to raise UnicodeError during parsing
        with unittest.mock.patch(
            "flext_ldif.format_handler_service.FlextLDIFParser"
        ) as mock_parser_class:
            mock_parser = mock_parser_class.return_value
            mock_parser.parse.side_effect = UnicodeError("UTF-8 decode error")

            result = modernized_ldif_parse("content with encoding issues")

            assert result.is_failure
            assert (
                result.error is not None
                and "Modernized LDIF parse failed" in result.error
            )

    def test_modernized_ldif_write_unicode_error(self) -> None:
        """Test Unicode error handling in modernized_ldif_write."""
        # Mock the writer to raise UnicodeError during writing
        with unittest.mock.patch(
            "flext_ldif.format_handler_service.FlextLDIFWriter"
        ) as mock_writer_class:
            mock_writer = mock_writer_class.return_value
            mock_writer.unparse.side_effect = UnicodeError("UTF-8 encode error")

            entries = [("cn=test,dc=example,dc=com", {"objectClass": ["person"]})]
            result = modernized_ldif_write(entries)

            assert result.is_failure
            assert (
                result.error is not None
                and "Modernized LDIF write failed" in result.error
            )

    def test_process_line_attribute_empty_line_coverage(self) -> None:
        """Test _process_line_attribute with empty line (line 447)."""
        parser = FlextLDIFParser("")
        dn = "cn=test,dc=example,dc=com"
        entry: dict[str, list[str]] = {}

        # Test empty line handling - this should return the DN unchanged
        result = parser._process_line_attribute("   ", dn, entry)
        assert result == dn

        # Test completely empty line
        result = parser._process_line_attribute("", dn, entry)
        assert result == dn

    def test_parse_entry_record_missing_dn_coverage(self) -> None:
        """Test _parse_entry_record with missing DN (lines 475-476)."""
        parser = FlextLDIFParser("")

        # Create lines that are ignored by processing but don't set DN
        # This will cause dn to remain None and trigger lines 475-476
        lines_without_dn = [
            "",  # Empty line - ignored in line 447
            "   ",  # Whitespace line - ignored in line 447
            "  \n",  # Whitespace line - ignored in line 447
        ]

        # This should raise ValueError on lines 475-476 because dn remains None
        with pytest.raises(ValueError) as exc_info:
            parser._parse_entry_record(lines_without_dn)

        # Check that it's the specific error from lines 475-476
        assert (
            "missing" in str(exc_info.value).lower()
            and "dn" in str(exc_info.value).lower()
        )

    def test_comment_lines_branch_coverage(self) -> None:
        """Test parsing with comment lines to cover branch 284->272."""
        ldif_with_comments = """# This is a comment at the start
dn: cn=test,dc=example,dc=com
objectClass: person
# Comment in the middle
cn: test
sn: user
# Comment at the end
"""

        # Test via modernized_ldif_parse to ensure we hit the branch
        result = modernized_ldif_parse(ldif_with_comments)
        assert result.is_success
        assert len(result.value) == 1

        dn, attributes = result.value[0]
        assert dn == "cn=test,dc=example,dc=com"
        assert "person" in attributes["objectClass"]

    def test_empty_lines_branch_coverage(self) -> None:
        """Test parsing with empty lines to cover branch 294->291."""
        # Test LDIF starting with empty lines (lines=[] when empty line hit)
        ldif_empty_start = """

dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
"""

        result = modernized_ldif_parse(ldif_empty_start)
        assert result.is_success
        assert len(result.value) == 1

        # Test LDIF with multiple consecutive empty lines between entries
        ldif_multiple_empty = """dn: cn=test1,dc=example,dc=com
objectClass: person



dn: cn=test2,dc=example,dc=com
objectClass: person
"""

        result2 = modernized_ldif_parse(ldif_multiple_empty)
        assert result2.is_success
        assert len(result2.value) == 2

    def test_empty_blocks_branch_coverage(self) -> None:
        """Test parsing with empty blocks to cover branch 489->488."""
        # Test LDIF with comment-only block that becomes empty after filtering
        ldif_comment_block = """dn: cn=test1,dc=example,dc=com
objectClass: person

# This block contains only comments
# Another comment line
# Yet another comment

dn: cn=test2,dc=example,dc=com
objectClass: person
"""

        result = modernized_ldif_parse(ldif_comment_block)
        assert result.is_success
        assert len(result.value) == 2

        # Test LDIF ending with trailing empty lines
        ldif_trailing_empty = """dn: cn=test,dc=example,dc=com
objectClass: person



"""

        result2 = modernized_ldif_parse(ldif_trailing_empty)
        assert result2.is_success
        assert len(result2.value) == 1

    def test_space_only_blocks_branch_coverage(self) -> None:
        """Test parsing with space-only lines to cover branch 489->488."""
        # Test LDIF that contains only spaces (may create empty blocks)
        ldif_only_spaces = """    \n  \n    \n"""

        result = modernized_ldif_parse(ldif_only_spaces)
        assert result.is_success
        assert len(result.value) == 0  # No entries expected

        # Test LDIF with space-only lines between entries
        ldif_spaces_between = """dn: cn=test1,dc=example,dc=com
objectClass: person

    \n\ndn: cn=test2,dc=example,dc=com
objectClass: person
"""

        result2 = modernized_ldif_parse(ldif_spaces_between)
        assert result2.is_success
        assert len(result2.value) == 2
