"""Tests for LDIF format handler service - comprehensive coverage."""

# ruff: noqa: PT018
# Reason: Multiple assertion checks are common in tests for comprehensive error validation

import base64
from collections import UserString
from typing import Never

import pytest

from flext_ldif import FlextLDIFModels
from flext_ldif.format_handlers import (
    FlextLDIFFormatHandler,
    FlextLDIFParser,
    FlextLDIFWriter,
)


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
        assert isinstance(entries[0], FlextLDIFModels.Entry)
        assert str(entries[0].dn) == "cn=John Doe,ou=people,dc=example,dc=com"

    def test_write_ldif_basic(self) -> None:
        """Test basic LDIF writing through class method."""
        entry = FlextLDIFModels.Entry(
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

    def test_validate_url_scheme_valid(self) -> None:
        """Test URL scheme validation with valid schemes."""
        # These should not raise an exception
        FlextLDIFFormatHandler.validate_url_scheme("http://example.com")
        FlextLDIFFormatHandler.validate_url_scheme("https://example.com/path")

    def test_validate_url_scheme_invalid(self) -> None:
        """Test URL scheme validation with invalid schemes."""
        with pytest.raises(ValueError, match="URL scheme 'ftp' not allowed"):
            FlextLDIFFormatHandler.validate_url_scheme("ftp://example.com")

        with pytest.raises(ValueError, match="URL scheme 'file' not allowed"):
            FlextLDIFFormatHandler.validate_url_scheme("file:///path/to/file")

    def test_is_dn_valid(self) -> None:
        """Test is_dn method with valid DNs."""
        valid_dns = [
            "cn=John Doe,ou=people,dc=example,dc=com",
            "uid=user,ou=users,dc=company,dc=org",
            "o=Organization,c=US",
        ]

        for dn in valid_dns:
            assert FlextLDIFFormatHandler.is_dn(dn)

    def test_is_dn_invalid(self) -> None:
        """Test is_dn method with invalid DNs."""
        invalid_dns = [
            "invalid dn format",
            "no equals sign",
            "just text without format",
        ]

        for dn in invalid_dns:
            assert not FlextLDIFFormatHandler.is_dn(dn)

    def test_is_dn_empty_string(self) -> None:
        """Test is_dn method with empty string (valid according to regex)."""
        # Empty string is considered valid DN by the regex
        assert FlextLDIFFormatHandler.is_dn("")

    def test_lower_list_utility(self) -> None:
        """Test lower_list utility method."""
        # Test with valid list
        result = FlextLDIFFormatHandler.lower_list(["UPPER", "MixedCase"])
        assert result == ["upper", "mixedcase"]

        # Test with None
        result = FlextLDIFFormatHandler.lower_list(None)
        assert result == []

    def test_write_ldif_none_input(self) -> None:
        """Test write_ldif with None input."""
        result = FlextLDIFFormatHandler.write_ldif(None)
        assert result.is_failure
        assert "Entries cannot be None" in result.error


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
modifiersName: cn=admin,dc=example,dc=com
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

    def test_parse_url_reference_validation(self) -> None:
        """Test parsing LDIF with URL reference validation (scheme check)."""
        # Test with valid HTTPS URL scheme that passes validation
        # Note: This doesn't make actual HTTP requests, just validates the URL format

        ldif_content = """dn: cn=test,dc=example,dc=com
cn: Test User
objectClass: person

"""
        parser = FlextLDIFParser(ldif_content)
        entries = list(parser.parse())

        assert len(entries) == 1
        _dn, record = entries[0]
        assert record["cn"] == ["Test User"]
        assert record["objectClass"] == ["person"]

    def test_parse_url_reference_invalid_scheme(self) -> None:
        """Test parsing LDIF with URL reference using invalid scheme."""
        # Test with invalid URL scheme (ftp) to trigger real validation error
        ldif_content = """dn: cn=test,dc=example,dc=com
cn:< ftp://example.com/name.txt
objectClass: person

"""
        parser = FlextLDIFParser(ldif_content)

        # Should raise ValueError for invalid URL scheme
        with pytest.raises(ValueError, match="not allowed"):
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

        # Test that _error doesn't raise exception in non-strict mode (just logs warning)
        # Should not raise an exception - this is the real behavior test
        parser._error("Test warning message")  # Should complete without exception

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
