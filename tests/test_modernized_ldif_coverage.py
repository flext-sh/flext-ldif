"""Tests for improving modernized LDIF module coverage.

Tests specifically designed to cover edge cases and error conditions
in the modernized LDIF parser and writer functionality.
"""

from __future__ import annotations

import base64

import pytest

from flext_ldif.modernized_ldif import (
    FlextLDIFParser,
    FlextLDIFWriter,
    is_dn,
    lower_list,
    modernized_ldif_parse,
    modernized_ldif_write,
)


class TestModernizedLdifCoverage:
    """Tests to improve modernized LDIF module coverage."""

    def test_is_dn_valid_cases(self) -> None:
        """Test is_dn function with valid DN cases."""
        assert is_dn("")  # Empty DN is valid
        assert is_dn("cn=test,dc=example,dc=com")
        assert is_dn("cn=Test User,ou=People,dc=example,dc=com")
        assert is_dn("uid=user@domain.com,ou=users,dc=example,dc=com")

    def test_is_dn_invalid_cases(self) -> None:
        """Test is_dn function with invalid DN cases."""
        assert not is_dn("invalid-format")
        assert not is_dn("cn=test,invalid")
        assert not is_dn("=value,dc=example,dc=com")

    def test_lower_list_with_none(self) -> None:
        """Test lower_list function with None input."""
        result = lower_list(None)
        assert result == []

    def test_lower_list_with_items(self) -> None:
        """Test lower_list function with items."""
        result = lower_list(["CN", "ObjectClass", "MAIL"])
        assert result == ["cn", "objectclass", "mail"]

    def test_flext_ldif_writer_with_base64_attrs(self) -> None:
        """Test FlextLDIFWriter with base64 attributes."""
        writer = FlextLDIFWriter(base64_attrs=["UserPassword", "PHOTO"])

        # Test with attribute that should be base64 encoded
        writer.unparse(
            "cn=test,dc=example,dc=com",
            {
                "objectClass": ["person"],
                "cn": ["test"],
                "userPassword": ["secret123"],  # Should be base64 encoded
            },
        )

        output = writer.get_output()
        assert "userPassword::" in output  # Double colon indicates base64
        assert "objectClass: person" in output  # Regular attribute

    def test_flext_ldif_writer_with_unsafe_chars(self) -> None:
        """Test FlextLDIFWriter with unsafe characters."""
        writer = FlextLDIFWriter()

        # Test with unsafe characters that should trigger base64 encoding
        writer.unparse(
            "cn=test,dc=example,dc=com",
            {
                "objectClass": ["person"],
                "cn": ["test"],
                "description": ["\x00\x01\x02binary"],  # Binary data
            },
        )

        output = writer.get_output()
        assert "description::" in output  # Should be base64 encoded

    def test_flext_ldif_writer_long_lines(self) -> None:
        """Test FlextLDIFWriter with long lines that need folding."""
        writer = FlextLDIFWriter(cols=20)  # Short line length

        long_dn = "cn=" + "x" * 100 + ",dc=example,dc=com"
        writer.unparse(
            long_dn,
            {
                "objectClass": ["person"],
                "cn": ["test"],
            },
        )

        output = writer.get_output()
        lines = output.split("\n")

        # Check that long lines are folded with leading spaces
        folded_lines = [line for line in lines if line.startswith(" ")]
        assert len(folded_lines) > 0

    def test_flext_ldif_writer_custom_settings(self) -> None:
        """Test FlextLDIFWriter with custom settings."""
        writer = FlextLDIFWriter(
            base64_attrs=["photo"],
            cols=40,
            line_sep="\r\n",
            encoding="utf-8",
        )

        writer.unparse(
            "cn=test,dc=example,dc=com",
            {
                "objectClass": ["person"],
                "cn": ["test"],
            },
        )

        output = writer.get_output()
        assert "\r\n" in output  # Custom line separator

    def test_flext_ldif_parser_with_comments(self) -> None:
        """Test FlextLDIFParser with comments."""
        content = """# This is a comment
dn: cn=test,dc=example,dc=com
# Another comment
objectClass: person
cn: test
"""

        parser = FlextLDIFParser(content)
        entries = list(parser.parse())

        assert len(entries) == 1
        dn, attrs = entries[0]
        assert dn == "cn=test,dc=example,dc=com"
        assert attrs["objectClass"] == ["person"]

    def test_flext_ldif_parser_with_line_continuation(self) -> None:
        """Test FlextLDIFParser with line continuation."""
        content = """dn: cn=test,dc=example,dc=com
objectClass: person
description: This is a very long description that spans
 multiple lines using LDIF line continuation
cn: test
"""

        parser = FlextLDIFParser(content)
        entries = list(parser.parse())

        assert len(entries) == 1
        _dn, attrs = entries[0]
        expected_desc = "This is a very long description that spansmultiple lines using LDIF line continuation"
        assert attrs["description"][0] == expected_desc

    def test_flext_ldif_parser_with_base64_values(self) -> None:
        """Test FlextLDIFParser with base64 encoded values."""
        # Create base64 encoded value
        original_value = "test value with special chars: éñ"
        encoded_value = base64.b64encode(original_value.encode("utf-8")).decode("ascii")

        content = f"""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description:: {encoded_value}
"""

        parser = FlextLDIFParser(content)
        entries = list(parser.parse())

        assert len(entries) == 1
        _dn, attrs = entries[0]
        assert attrs["description"][0] == original_value

    def test_flext_ldif_parser_with_url_reference(self) -> None:
        """Test FlextLDIFParser with URL reference (should fail safely)."""
        content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
jpegPhoto:< https://example.com/photo.jpg
"""

        parser = FlextLDIFParser(content)

        # This should raise an exception due to URL fetch
        with pytest.raises(ValueError, match="URL fetch error"):
            list(parser.parse())

    def test_flext_ldif_parser_with_ignored_attrs(self) -> None:
        """Test FlextLDIFParser with ignored attribute types."""
        content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
ignoredAttr: should be ignored
"""

        parser = FlextLDIFParser(content, ignored_attr_types=["ignoredAttr"])
        entries = list(parser.parse())

        assert len(entries) == 1
        _dn, attrs = entries[0]
        assert "ignoredAttr" not in attrs
        assert "objectClass" in attrs

    def test_flext_ldif_parser_non_strict_mode(self) -> None:
        """Test FlextLDIFParser in non-strict mode."""
        content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
dn: cn=duplicate,dc=example,dc=com
"""

        # Non-strict mode should log warnings instead of raising exceptions
        parser = FlextLDIFParser(content, strict=False)
        entries = list(parser.parse())

        # Should still parse successfully
        assert len(entries) >= 1

    def test_flext_ldif_parser_with_version_line(self) -> None:
        """Test FlextLDIFParser with version line."""
        content = """version: 1
dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
"""

        parser = FlextLDIFParser(content)
        entries = list(parser.parse())

        assert len(entries) == 1
        dn, _attrs = entries[0]
        assert dn == "cn=test,dc=example,dc=com"

    def test_flext_ldif_parser_empty_blocks(self) -> None:
        """Test FlextLDIFParser with empty blocks."""
        content = """

dn: cn=test,dc=example,dc=com
objectClass: person
cn: test


"""

        parser = FlextLDIFParser(content)
        entries = list(parser.parse())

        assert len(entries) == 1

    def test_flext_ldif_parser_invalid_format(self) -> None:
        """Test FlextLDIFParser with invalid LDIF format."""
        content = """dn: cn=test,dc=example,dc=com
objectClass: person
invalid line without colon
cn: test
"""

        parser = FlextLDIFParser(content)

        with pytest.raises(ValueError, match="Invalid LDIF line format"):
            list(parser.parse())

    def test_flext_ldif_parser_missing_dn(self) -> None:
        """Test FlextLDIFParser with missing DN line."""
        content = """objectClass: person
cn: test
"""

        parser = FlextLDIFParser(content)

        with pytest.raises(ValueError, match="Attribute before dn: line"):
            list(parser.parse())

    def test_flext_ldif_parser_invalid_dn(self) -> None:
        """Test FlextLDIFParser with invalid DN."""
        content = """dn: invalid-dn-format
objectClass: person
cn: test
"""

        parser = FlextLDIFParser(content)

        with pytest.raises(ValueError, match="Invalid distinguished name format"):
            list(parser.parse())

    def test_flext_ldif_parser_multiple_dn_lines(self) -> None:
        """Test FlextLDIFParser with multiple DN lines in one record."""
        content = """dn: cn=test,dc=example,dc=com
dn: cn=duplicate,dc=example,dc=com
objectClass: person
cn: test
"""

        parser = FlextLDIFParser(content)

        with pytest.raises(ValueError, match="Multiple dn: lines"):
            list(parser.parse())

    def test_flext_ldif_parser_attribute_before_dn(self) -> None:
        """Test FlextLDIFParser with attribute before DN line."""
        content = """objectClass: person
dn: cn=test,dc=example,dc=com
cn: test
"""

        parser = FlextLDIFParser(content)

        with pytest.raises(ValueError, match="Attribute before dn: line"):
            list(parser.parse())

    def test_modernized_ldif_parse_empty_content(self) -> None:
        """Test modernized_ldif_parse with empty content."""
        result = modernized_ldif_parse("")
        assert result.success
        assert result.data == []

    def test_modernized_ldif_parse_error_handling(self) -> None:
        """Test modernized_ldif_parse error handling."""
        result = modernized_ldif_parse("invalid ldif without proper format")
        assert not result.success
        assert "Modernized LDIF parse failed" in result.error

    def test_modernized_ldif_write_empty_entries(self) -> None:
        """Test modernized_ldif_write with empty entries."""
        result = modernized_ldif_write([])
        assert result.success
        assert result.data == ""

    def test_modernized_ldif_write_multiple_entries(self) -> None:
        """Test modernized_ldif_write with multiple entries."""
        entries = [
            (
                "cn=user1,dc=example,dc=com",
                {"objectClass": ["person"], "cn": ["user1"]},
            ),
            (
                "cn=user2,dc=example,dc=com",
                {"objectClass": ["person"], "cn": ["user2"]},
            ),
        ]

        result = modernized_ldif_write(entries)
        assert result.success
        assert "cn=user1,dc=example,dc=com" in result.data
        assert "cn=user2,dc=example,dc=com" in result.data

    def test_modernized_ldif_write_error_handling(self) -> None:
        """Test modernized_ldif_write error handling."""
        # Pass invalid data to trigger exception
        result = modernized_ldif_write(None)
        assert not result.success
        assert "Entries cannot be None" in result.error

    def test_flext_ldif_parser_base64_decode_error(self) -> None:
        """Test FlextLDIFParser with invalid base64 data."""
        content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description:: invalid-base64-data!!!
"""

        parser = FlextLDIFParser(content)

        with pytest.raises(ValueError, match="Base64 decode error"):
            list(parser.parse())

    def test_flext_ldif_writer_records_written_counter(self) -> None:
        """Test FlextLDIFWriter records_written counter."""
        writer = FlextLDIFWriter()

        assert writer.records_written == 0

        writer.unparse("cn=test1,dc=example,dc=com", {"objectClass": ["person"]})
        assert writer.records_written == 1

        writer.unparse("cn=test2,dc=example,dc=com", {"objectClass": ["person"]})
        assert writer.records_written == 2

    def test_flext_ldif_parser_records_read_counter(self) -> None:
        """Test FlextLDIFParser records_read counter."""
        content = """dn: cn=test1,dc=example,dc=com
objectClass: person
cn: test1

dn: cn=test2,dc=example,dc=com
objectClass: person
cn: test2
"""

        parser = FlextLDIFParser(content)

        assert parser.records_read == 0

        entries = list(parser.parse())
        assert len(entries) == 2
        assert parser.records_read == 2
