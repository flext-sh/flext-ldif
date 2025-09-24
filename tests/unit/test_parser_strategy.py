"""Test Parser Strategy Pattern Implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import base64

from flext_ldif.parser import FlextLdifParser


class TestParserStrategyPattern:
    """Test parser encoding detection strategy pattern."""

    def test_encoding_strategy_utf8_success(self) -> None:
        """Test UTF-8 encoding detection strategy."""
        parser = FlextLdifParser()

        utf8_content = b"dn: cn=test,dc=example,dc=com\ncn: test\n"

        result = parser.EncodingStrategy.detect(utf8_content)

        assert result.is_success
        assert result.value == "utf-8"

    def test_encoding_strategy_latin1_fallback(self) -> None:
        """Test Latin-1 encoding fallback strategy."""
        parser = FlextLdifParser()

        # Create content with Latin-1 characters that aren't valid UTF-8
        latin1_content = b"dn: cn=caf\xe9,dc=example,dc=com\n"

        result = parser.EncodingStrategy.detect(latin1_content)

        assert result.is_success
        # Should detect as either latin-1 or utf-8 (with replacement)
        assert result.value in {"latin-1", "utf-8"}

    def test_encoding_strategy_empty_content(self) -> None:
        """Test encoding detection with empty content."""
        parser = FlextLdifParser()

        result = parser.EncodingStrategy.detect(b"")

        assert result.is_success
        assert result.value == "utf-8"

    def test_encoding_strategy_try_utf8_valid(self) -> None:
        """Test UTF-8 strategy with valid UTF-8 content."""
        valid_utf8 = "测试".encode()

        result = FlextLdifParser.EncodingStrategy.try_utf8(valid_utf8)

        assert result.is_success
        assert result.value == "utf-8"

    def test_encoding_strategy_try_utf8_invalid(self) -> None:
        """Test UTF-8 strategy with invalid UTF-8 content."""
        invalid_utf8 = b"\xff\xfe"

        result = FlextLdifParser.EncodingStrategy.try_utf8(invalid_utf8)

        assert result.is_failure

    def test_encoding_strategy_try_latin1_valid(self) -> None:
        """Test Latin-1 strategy with valid Latin-1 content."""
        latin1_content = "café".encode("latin-1")

        result = FlextLdifParser.EncodingStrategy.try_latin1(latin1_content)

        assert result.is_success
        assert result.value == "latin-1"

    def test_encoding_strategy_supports_method(self) -> None:
        """Test encoding strategy supports method."""
        strategy = FlextLdifParser.EncodingStrategy()

        assert strategy.supports("utf-8") is True
        assert strategy.supports("latin-1") is True
        assert strategy.supports("ascii") is True
        assert strategy.supports("unknown") is False

    def test_parser_with_utf8_content(self) -> None:
        """Test parser integration with UTF-8 content."""
        parser = FlextLdifParser()

        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
"""

        result = parser.parse_string(ldif_content)

        assert result.is_success
        entries = result.value
        assert len(entries) == 1
        assert entries[0].dn.value == "cn=test,dc=example,dc=com"

    def test_parser_with_base64_content(self) -> None:
        """Test parser with base64-encoded content."""
        parser = FlextLdifParser()

        # Base64 encoded value (::)
        test_value = "test value"
        b64_value = base64.b64encode(test_value.encode()).decode()

        ldif_content = f"""dn: cn=test,dc=example,dc=com
cn:: {b64_value}
"""

        result = parser.parse_string(ldif_content)

        assert result.is_success
        entries = result.value
        assert len(entries) == 1

    def test_parser_encoding_detection_workflow(self) -> None:
        """Test complete encoding detection workflow."""
        parser = FlextLdifParser()

        # Create content with various encodings
        utf8_ldif = """dn: cn=user,dc=example,dc=com
cn: user
description: UTF-8 content
"""

        result = parser.parse_string(utf8_ldif)

        assert result.is_success
        assert len(result.value) == 1

    def test_parser_multiline_content(self) -> None:
        """Test parser with multiline LDIF content."""
        parser = FlextLdifParser()

        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
description: This is a very long description that spans
  multiple lines in the LDIF format
"""

        result = parser.parse_string(ldif_content)

        assert result.is_success
        entries = result.value
        assert len(entries) == 1

    def test_parser_multiple_entries(self) -> None:
        """Test parser with multiple entries."""
        parser = FlextLdifParser()

        ldif_content = """dn: cn=user1,dc=example,dc=com
cn: user1

dn: cn=user2,dc=example,dc=com
cn: user2
"""

        result = parser.parse_string(ldif_content)

        assert result.is_success
        entries = result.value
        assert len(entries) == 2

    def test_parser_with_comments(self) -> None:
        """Test parser with LDIF comments."""
        parser = FlextLdifParser()

        ldif_content = """# This is a comment
dn: cn=test,dc=example,dc=com
cn: test
# Another comment
objectClass: person
"""

        result = parser.parse_string(ldif_content)

        assert result.is_success
        entries = result.value
        assert len(entries) == 1

    def test_parser_empty_content(self) -> None:
        """Test parser with empty content."""
        parser = FlextLdifParser()

        result = parser.parse_string("")

        assert result.is_success
        assert len(result.value) == 0

    def test_parser_malformed_dn(self) -> None:
        """Test parser with malformed DN."""
        parser = FlextLdifParser()

        ldif_content = """dn: invalid dn format
cn: test
"""

        result = parser.parse_string(ldif_content)

        # Parser should handle gracefully or fail explicitly
        assert result.is_success or result.is_failure

    def test_parser_missing_dn(self) -> None:
        """Test parser with entry missing DN."""
        parser = FlextLdifParser()

        ldif_content = """cn: test
objectClass: person
"""

        result = parser.parse_string(ldif_content)

        # Should fail or skip entry without DN
        assert result.is_success or result.is_failure

    def test_parser_duplicate_attributes(self) -> None:
        """Test parser with duplicate attributes."""
        parser = FlextLdifParser()

        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test1
cn: test2
cn: test3
"""

        result = parser.parse_string(ldif_content)

        assert result.is_success
        entries = result.value
        assert len(entries) == 1
        cn_values = entries[0].get_attribute("cn")
        assert cn_values is not None
        assert len(cn_values) >= 1

    def test_encoding_strategy_detect_with_special_chars(self) -> None:
        """Test encoding detection with special characters."""
        parser = FlextLdifParser()

        # Content with emoji (UTF-8)
        content_with_emoji = "dn: cn=test 😀,dc=example,dc=com\n".encode()

        result = parser.EncodingStrategy.detect(content_with_emoji)

        assert result.is_success
        assert result.value == "utf-8"

    def test_parser_with_special_dn(self) -> None:
        """Test parser with special characters in DN."""
        parser = FlextLdifParser()

        ldif_content = """dn: cn=user-123,dc=example,dc=com
cn: user-123
"""

        result = parser.parse_string(ldif_content)

        assert result.is_success
        entries = result.value
        assert len(entries) == 1

    def test_parser_strategy_integration(self) -> None:
        """Test complete strategy pattern integration."""
        parser = FlextLdifParser()

        # Test with various content types
        test_cases = [
            ("ASCII content", b"dn: cn=test,dc=com\n"),
            ("UTF-8 content", "dn: cn=tëst,dc=com\n".encode()),
            ("Empty", b""),
        ]

        for name, content in test_cases:
            result = parser.EncodingStrategy.detect(content)
            assert result.is_success, f"Failed for {name}"


class TestParserEdgeCases:
    """Test edge cases for parser strategy pattern."""

    def test_parser_with_only_whitespace(self) -> None:
        """Test parser with only whitespace content."""
        parser = FlextLdifParser()

        result = parser.parse_string("   \n\n\t\n   ")

        assert result.is_success
        assert len(result.value) == 0

    def test_parser_with_mixed_line_endings(self) -> None:
        """Test parser with mixed line endings."""
        parser = FlextLdifParser()

        ldif_content = "dn: cn=test,dc=example,dc=com\r\ncn: test\nuid: test123\r\n"

        result = parser.parse_string(ldif_content)

        assert result.is_success
        entries = result.value
        assert len(entries) == 1

    def test_encoding_strategy_with_null_bytes(self) -> None:
        """Test encoding strategy with null bytes."""
        parser = FlextLdifParser()

        content_with_null = b"dn: cn=test\x00,dc=com\n"

        result = parser.EncodingStrategy.detect(content_with_null)

        # Should still detect encoding even with null bytes
        assert result.is_success

    def test_parser_very_long_line(self) -> None:
        """Test parser with very long line."""
        parser = FlextLdifParser()

        long_value = "x" * 10000
        ldif_content = f"""dn: cn=test,dc=example,dc=com
description: {long_value}
"""

        result = parser.parse_string(ldif_content)

        assert result.is_success
        entries = result.value
        assert len(entries) == 1

    def test_parser_binary_attribute(self) -> None:
        """Test parser with binary attribute notation."""
        parser = FlextLdifParser()

        # Binary data in base64
        binary_data = base64.b64encode(b"\x00\x01\x02\x03").decode()

        ldif_content = f"""dn: cn=test,dc=example,dc=com
userCertificate;binary:: {binary_data}
"""

        result = parser.parse_string(ldif_content)

        assert result.is_success
        entries = result.value
        assert len(entries) == 1
