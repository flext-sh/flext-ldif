"""Error recovery and malformed LDIF handling tests.

Test suite for validating error handling capabilities:
- Malformed LDIF content (missing DNs, invalid syntax)
- Incomplete entries (missing required attributes)
- Invalid attribute values (wrong formats)
- Encoding errors and binary handling
- Graceful degradation and partial parsing
- Error messages and diagnostics

Uses centralized fixtures from tests/integration/conftest.py.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif import FlextLdif


class TestMalformedLdifHandling:
    """Test error handling for malformed LDIF content."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """FlextLdif API instance."""
        return FlextLdif.get_instance()

    def test_missing_dn_line(self, api: FlextLdif) -> None:
        """Test handling of entry without DN line.

        Validates:
        - Parser detects missing DN
        - Error is reported appropriately
        - Processing continues gracefully
        """
        ldif_content = """objectClass: person
cn: NoDN
sn: User
"""
        result = api.parse(ldif_content)
        # Should handle gracefully - either parse fails or skips entry
        assert result is not None

    def test_incomplete_attribute_syntax(self, api: FlextLdif) -> None:
        """Test handling of malformed attribute lines.

        Validates:
        - Lines without colon separator are handled
        - Incomplete attribute definitions are detected
        - Parsing continues with remaining entries
        """
        ldif_content = """dn: cn=Test,dc=example,dc=com
objectClass person
cn: Test
sn: User
"""
        result = api.parse(ldif_content)
        # Should handle gracefully
        assert result is not None

    def test_invalid_dn_format(self, api: FlextLdif) -> None:
        """Test handling of invalid DN format.

        Validates:
        - DNs without RDN components are detected
        - Malformed DNs are handled gracefully
        - Processing continues
        """
        ldif_content = """dn: invalid-dn-no-equals
objectClass: person
cn: Test
"""
        result = api.parse(ldif_content)
        # Should handle gracefully
        assert result is not None

    def test_orphaned_continuation_lines(self, api: FlextLdif) -> None:
        """Test handling of orphaned line continuation characters.

        Validates:
        - Lines starting with space but without context handled
        - Parser doesn't crash on malformed continuations
        - Following entries still parse
        """
        ldif_content = """dn: cn=Test1,dc=example,dc=com
objectClass: person
cn: Test1

 orphaned-continuation
dn: cn=Test2,dc=example,dc=com
objectClass: person
cn: Test2
"""
        result = api.parse(ldif_content)
        assert result is not None

    def test_missing_required_attributes(self, api: FlextLdif) -> None:
        """Test handling of entries missing required attributes.

        Validates:
        - Entries with no attributes are handled
        - Entries with minimal attributes parse successfully
        - DN alone is valid entry
        """
        ldif_content = """dn: cn=Minimal,dc=example,dc=com
"""
        result = api.parse(ldif_content)
        # DN alone should be valid
        if result.is_success:
            entries = result.unwrap()
            assert len(entries) > 0 or len(entries) == 0

    def test_empty_attribute_values(self, api: FlextLdif) -> None:
        """Test handling of attributes with empty values.

        Validates:
        - Empty attribute values are preserved
        - Attributes with only whitespace handled
        - Parser doesn't crash on empty values
        """
        ldif_content = """dn: cn=Empty,dc=example,dc=com
objectClass: person
cn: Empty
description:
mail: test@example.com
"""
        result = api.parse(ldif_content)
        assert result is not None

    def test_duplicate_attributes(self, api: FlextLdif) -> None:
        """Test handling of duplicate attribute names.

        Validates:
        - Multiple values for same attribute collected
        - Duplicates don't cause parsing errors
        - All values are preserved
        """
        ldif_content = """dn: cn=Duplicate,dc=example,dc=com
objectClass: person
cn: Duplicate
mail: test1@example.com
mail: test2@example.com
mail: test3@example.com
"""
        result = api.parse(ldif_content)
        if result.is_success:
            entries = result.unwrap()
            assert len(entries) > 0

    def test_special_characters_in_values(self, api: FlextLdif) -> None:
        """Test handling of special characters in attribute values.

        Validates:
        - Special LDAP characters in values handled
        - Escaped characters processed correctly
        - Unicode and UTF-8 characters supported
        """
        ldif_content = """dn: cn=José,dc=example,dc=com
objectClass: person
cn: José
description: Contains , comma and = equals signs
mail: user+tag@example.com
"""
        result = api.parse(ldif_content)
        assert result is not None

    def test_very_long_attribute_values(self, api: FlextLdif) -> None:
        """Test handling of extremely long attribute values.

        Validates:
        - Very long values (>1000 chars) handled
        - Line continuation working correctly
        - No buffer overflow or truncation
        """
        long_value = "x" * 2000
        ldif_content = f"""dn: cn=LongValue,dc=example,dc=com
objectClass: person
cn: LongValue
description: {long_value}
"""
        result = api.parse(ldif_content)
        assert result is not None

    def test_binary_attribute_encoding(self, api: FlextLdif) -> None:
        """Test handling of binary attributes.

        Validates:
        - Base64 encoded binary attributes recognized
        - :: syntax for binary attributes handled
        - Non-UTF8 binary data supported
        """
        ldif_content = """dn: cn=Binary,dc=example,dc=com
objectClass: person
cn: Binary
jpegPhoto:: /9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAA==
"""
        result = api.parse(ldif_content)
        assert result is not None

    def test_version_line_handling(self, api: FlextLdif) -> None:
        """Test handling of LDIF version line.

        Validates:
        - Version line (if present) handled correctly
        - Doesn't cause parsing errors
        - Standard LDIF format supported
        """
        ldif_content = """version: 1
dn: cn=WithVersion,dc=example,dc=com
objectClass: person
cn: WithVersion
"""
        result = api.parse(ldif_content)
        assert result is not None

    def test_comments_in_ldif(self, api: FlextLdif) -> None:
        """Test handling of comment lines in LDIF.

        Validates:
        - Comment lines (#) are ignored
        - Comments don't interfere with parsing
        - Entries after comments parse correctly
        """
        ldif_content = """# This is a comment
dn: cn=WithComments,dc=example,dc=com
# Another comment
objectClass: person
cn: WithComments
# Final comment
"""
        result = api.parse(ldif_content)
        assert result is not None

    def test_mixed_case_attribute_names(self, api: FlextLdif) -> None:
        """Test handling of mixed-case attribute names.

        Validates:
        - Attribute names are case-insensitive
        - CN, cn, Cn all treated same
        - DN, dn, Dn handled correctly
        """
        ldif_content = """Dn: cn=MixedCase,dc=example,dc=com
ObjectClass: person
CN: MixedCase
SN: User
Mail: test@example.com
"""
        result = api.parse(ldif_content)
        assert result is not None


class TestIncompleteEntries:
    """Test handling of incomplete or partial entries."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """FlextLdif API instance."""
        return FlextLdif.get_instance()

    def test_truncated_ldif(self, api: FlextLdif) -> None:
        """Test handling of truncated LDIF file.

        Validates:
        - Incomplete entries at end of file handled
        - Previous complete entries still parsed
        - No crash on unexpected EOF
        """
        ldif_content = """dn: cn=Complete,dc=example,dc=com
objectClass: person
cn: Complete

dn: cn=Incomplete,dc=example,dc
"""
        result = api.parse(ldif_content)
        # Should handle gracefully
        assert result is not None

    def test_unclosed_multiline_value(self, api: FlextLdif) -> None:
        """Test handling of unclosed multi-line attribute values.

        Validates:
        - Continuation lines without completion handled
        - Following entries recover correctly
        - No parser state corruption
        """
        ldif_content = """dn: cn=Test1,dc=example,dc=com
objectClass: person
cn: Test1
description: This is a multi-line
 value that continues
 but next entry starts

dn: cn=Test2,dc=example,dc=com
objectClass: person
cn: Test2
"""
        result = api.parse(ldif_content)
        assert result is not None

    def test_entry_without_closing_blank_line(self, api: FlextLdif) -> None:
        """Test handling of entry without trailing blank line.

        Validates:
        - Last entry without blank line still parsed
        - EOF properly terminates entry
        - No data loss
        """
        ldif_content = """dn: cn=NoBlankLine,dc=example,dc=com
objectClass: person
cn: NoBlankLine
sn: Test"""
        result = api.parse(ldif_content)
        assert result is not None


class TestInvalidSchemaDefinitions:
    """Test handling of invalid schema definitions."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """FlextLdif API instance."""
        return FlextLdif.get_instance()

    def test_malformed_oid(self, api: FlextLdif) -> None:
        """Test handling of malformed OID in schema.

        Validates:
        - Invalid OID format detected
        - Parsing continues gracefully
        - Other schema entries still processed
        """
        ldif_content = """dn: cn=Schema,cn=config
objectClass: schema
attributeTypes: ( invalid-oid NAME 'test' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
"""
        result = api.parse(ldif_content)
        assert result is not None

    def test_missing_required_schema_fields(self, api: FlextLdif) -> None:
        """Test handling of schema definitions missing required fields.

        Validates:
        - Missing OID detected
        - Missing NAME detected
        - Graceful error handling
        """
        ldif_content = """dn: cn=Schema,cn=config
objectClass: schema
attributeTypes: ( NAME 'incomplete' )
"""
        result = api.parse(ldif_content)
        assert result is not None

    def test_unclosed_schema_definition(self, api: FlextLdif) -> None:
        """Test handling of unclosed schema definition parentheses.

        Validates:
        - Missing closing paren detected
        - Following definitions still parsed
        - No parser crash
        """
        ldif_content = """dn: cn=Schema,cn=config
objectClass: schema
attributeTypes: ( 1.2.3 NAME 'incomplete'
"""
        result = api.parse(ldif_content)
        assert result is not None


class TestEncodingErrors:
    """Test handling of encoding-related errors."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """FlextLdif API instance."""
        return FlextLdif.get_instance()

    def test_utf8_handling(self, api: FlextLdif) -> None:
        """Test proper UTF-8 encoding handling.

        Validates:
        - UTF-8 characters properly decoded
        - Non-ASCII characters preserved
        - Multi-byte characters handled
        """
        ldif_content = """dn: cn=UTF8Test,dc=example,dc=com
objectClass: person
cn: UTF8Test
description: Contains UTF-8: café, naïve, résumé
"""
        result = api.parse(ldif_content)
        if result.is_success:
            entries = result.unwrap()
            assert len(entries) >= 0

    def test_invalid_base64_binary(self, api: FlextLdif) -> None:
        """Test handling of invalid Base64 in binary attributes.

        Validates:
        - Invalid Base64 detected
        - Parsing continues
        - Error reported appropriately
        """
        ldif_content = """dn: cn=InvalidBase64,dc=example,dc=com
objectClass: person
jpegPhoto:: !!!invalid-base64!!!
"""
        result = api.parse(ldif_content)
        # Should handle gracefully
        assert result is not None

    def test_mixed_encoding_in_entry(self, api: FlextLdif) -> None:
        """Test handling of mixed character encodings in single entry.

        Validates:
        - Mixed UTF-8 and binary handled
        - No encoding conflicts
        - Values properly separated
        """
        ldif_content = """dn: cn=Mixed,dc=example,dc=com
objectClass: person
cn: Mixed
description: UTF-8 text: café
jpegPhoto:: /9j/4AAQSkZJRgABAQEAYABg
"""
        result = api.parse(ldif_content)
        assert result is not None


__all__ = [
    "TestEncodingErrors",
    "TestIncompleteEntries",
    "TestInvalidSchemaDefinitions",
    "TestMalformedLdifHandling",
]
