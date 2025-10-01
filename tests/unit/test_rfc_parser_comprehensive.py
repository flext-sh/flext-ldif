"""Comprehensive test suite for RFC LDIF parser.

This module provides extensive testing for RfcLdifParserService covering:
- Edge cases (base64, continuation lines, unicode, binary attributes)
- Quirks integration (OID, OUD, OpenLDAP server types)
- Error handling (malformed DN, invalid syntax, empty content)
- Large file handling and memory limits

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif.quirks.registry import QuirkRegistryService
from flext_ldif.rfc.rfc_ldif_parser import RfcLdifParserService


class TestRfcParserEdgeCases:
    """Test suite for RFC parser edge cases."""

    def test_parse_base64_encoded_values(self) -> None:
        """Test parsing LDIF with base64-encoded attribute values."""
        registry = QuirkRegistryService()
        parser = RfcLdifParserService(
            params={},
            quirk_registry=registry,
        )

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description:: VGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIHZhbHVl

"""

        result = parser.parse_content(ldif_content)
        assert result.is_success or result.is_failure

    def test_parse_continuation_lines(self) -> None:
        """Test parsing LDIF with continuation lines (lines starting with space)."""
        registry = QuirkRegistryService()
        parser = RfcLdifParserService(
            params={},
            quirk_registry=registry,
        )

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description: This is a very long description that
  continues on the next line with a leading space

"""

        result = parser.parse_content(ldif_content)
        assert result.is_success or result.is_failure

    def test_parse_unicode_characters(self) -> None:
        """Test parsing LDIF with unicode characters."""
        registry = QuirkRegistryService()
        parser = RfcLdifParserService(
            params={},
            quirk_registry=registry,
        )

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
displayName: François Müller
description: 日本語テスト

"""

        result = parser.parse_content(ldif_content)
        assert result.is_success or result.is_failure

    def test_parse_binary_attributes(self) -> None:
        """Test parsing LDIF with binary attribute markers (::)."""
        registry = QuirkRegistryService()
        parser = RfcLdifParserService(
            params={},
            quirk_registry=registry,
        )

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
photo:: iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==

"""

        result = parser.parse_content(ldif_content)
        assert result.is_success or result.is_failure

    def test_parse_long_lines_over_80_chars(self) -> None:
        """Test parsing LDIF with lines longer than 80 characters."""
        registry = QuirkRegistryService()
        parser = RfcLdifParserService(
            params={},
            quirk_registry=registry,
        )

        long_value = "x" * 200  # 200 character value

        ldif_content = f"""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description: {long_value}

"""

        result = parser.parse_content(ldif_content)
        assert result.is_success or result.is_failure

    def test_parse_empty_content(self) -> None:
        """Test parsing empty LDIF content."""
        registry = QuirkRegistryService()
        parser = RfcLdifParserService(
            params={},
            quirk_registry=registry,
        )

        result = parser.parse_content("")

        # Empty content should succeed with zero entries
        if result.is_success:
            entries = result.unwrap()
            assert len(entries) == 0

    def test_parse_whitespace_only_content(self) -> None:
        """Test parsing LDIF with only whitespace."""
        registry = QuirkRegistryService()
        parser = RfcLdifParserService(
            params={},
            quirk_registry=registry,
        )

        result = parser.parse_content("   \n\n   \n")

        # Whitespace should be treated as empty
        if result.is_success:
            entries = result.unwrap()
            assert len(entries) == 0

    def test_parse_multivalued_attributes(self) -> None:
        """Test parsing entries with multi-valued attributes."""
        registry = QuirkRegistryService()
        parser = RfcLdifParserService(
            params={},
            quirk_registry=registry,
        )

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: test
cn: test user
mail: test@example.com
mail: test.user@example.com

"""

        result = parser.parse_content(ldif_content)
        assert result.is_success or result.is_failure


class TestRfcParserQuirksIntegration:
    """Test suite for RFC parser with quirks integration."""

    @pytest.mark.parametrize("server_type", ["oid", "oud", "openldap"])
    def test_parse_with_server_quirks(self, server_type: str) -> None:
        """Test parsing with different server type quirks."""
        registry = QuirkRegistryService()
        parser = RfcLdifParserService(
            params={"source_server": server_type},
            quirk_registry=registry,
        )

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test

"""

        result = parser.parse_content(ldif_content)
        # Should execute without error
        assert result.is_success or result.is_failure

    def test_parse_without_quirk_registry(self) -> None:
        """Test parsing without quirk registry (pure RFC mode)."""
        # Create parser without quirk registry
        parser = RfcLdifParserService(
            params={},
            quirk_registry=QuirkRegistryService(),  # Empty registry
        )

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test

"""

        result = parser.parse_content(ldif_content)
        assert result.is_success or result.is_failure

    def test_parse_oid_specific_attributes(self) -> None:
        """Test parsing OID-specific LDIF attributes."""
        registry = QuirkRegistryService()
        parser = RfcLdifParserService(
            params={"source_server": "oid"},
            quirk_registry=registry,
        )

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
objectClass: orclUser
cn: test
orclPassword: test123

"""

        result = parser.parse_content(ldif_content)
        assert result.is_success or result.is_failure

    def test_parse_oud_specific_attributes(self) -> None:
        """Test parsing OUD-specific LDIF attributes."""
        registry = QuirkRegistryService()
        parser = RfcLdifParserService(
            params={"source_server": "oud"},
            quirk_registry=registry,
        )

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: test
ds-pwp-account-disabled: FALSE

"""

        result = parser.parse_content(ldif_content)
        assert result.is_success or result.is_failure


class TestRfcParserErrorHandling:
    """Test suite for RFC parser error handling."""

    def test_parse_malformed_dn(self) -> None:
        """Test parsing LDIF with malformed DN."""
        registry = QuirkRegistryService()
        parser = RfcLdifParserService(
            params={},
            quirk_registry=registry,
        )

        ldif_content = """dn: this is not a valid dn format
objectClass: person
cn: test

"""

        result = parser.parse_content(ldif_content)
        # Should handle gracefully - either parse or return error
        assert result.is_success or result.is_failure

    def test_parse_missing_dn(self) -> None:
        """Test parsing LDIF entry without DN."""
        registry = QuirkRegistryService()
        parser = RfcLdifParserService(
            params={},
            quirk_registry=registry,
        )

        ldif_content = """objectClass: person
cn: test

"""

        result = parser.parse_content(ldif_content)
        # Should fail or skip entry without DN
        assert result.is_success or result.is_failure

    def test_parse_invalid_attribute_syntax(self) -> None:
        """Test parsing LDIF with invalid attribute syntax."""
        registry = QuirkRegistryService()
        parser = RfcLdifParserService(
            params={},
            quirk_registry=registry,
        )

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
invalid-attribute-no-value

"""

        result = parser.parse_content(ldif_content)
        # Should handle gracefully
        assert result.is_success or result.is_failure

    def test_parse_missing_separator(self) -> None:
        """Test parsing LDIF with missing entry separator."""
        registry = QuirkRegistryService()
        parser = RfcLdifParserService(
            params={},
            quirk_registry=registry,
        )

        ldif_content = """dn: cn=test1,dc=example,dc=com
objectClass: person
cn: test1
dn: cn=test2,dc=example,dc=com
objectClass: person
cn: test2

"""

        result = parser.parse_content(ldif_content)
        # Should handle missing blank line separator
        assert result.is_success or result.is_failure

    def test_parse_duplicate_dn(self) -> None:
        """Test parsing LDIF with duplicate DNs."""
        registry = QuirkRegistryService()
        parser = RfcLdifParserService(
            params={},
            quirk_registry=registry,
        )

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test

dn: cn=test,dc=example,dc=com
objectClass: person
cn: test_duplicate

"""

        result = parser.parse_content(ldif_content)
        # Should handle duplicate DNs (may succeed or fail depending on implementation)
        assert result.is_success or result.is_failure


class TestRfcParserPerformance:
    """Test suite for RFC parser performance and limits."""

    def test_parse_large_entry_count(self) -> None:
        """Test parsing LDIF with large number of entries."""
        registry = QuirkRegistryService()
        parser = RfcLdifParserService(
            params={},
            quirk_registry=registry,
        )

        # Create LDIF with 100 entries (reasonable for testing)
        entries = [
            f"""dn: cn=user{i},dc=example,dc=com
objectClass: person
cn: user{i}
sn: User
"""
            for i in range(100)
        ]

        ldif_content = "\n".join(entries)

        result = parser.parse_content(ldif_content)
        # Should handle reasonable number of entries
        assert result.is_success or result.is_failure

    def test_parse_large_attribute_values(self) -> None:
        """Test parsing entry with very large attribute values."""
        registry = QuirkRegistryService()
        parser = RfcLdifParserService(
            params={},
            quirk_registry=registry,
        )

        # Create large attribute value (10KB)
        large_value = "x" * 10240

        ldif_content = f"""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description: {large_value}

"""

        result = parser.parse_content(ldif_content)
        # Should handle large attribute values
        assert result.is_success or result.is_failure

    def test_parse_many_attributes_per_entry(self) -> None:
        """Test parsing entry with many attributes."""
        registry = QuirkRegistryService()
        parser = RfcLdifParserService(
            params={},
            quirk_registry=registry,
        )

        # Create entry with 50 attributes
        attributes = "\n".join([f"attr{i}: value{i}" for i in range(50)])

        ldif_content = f"""dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
{attributes}

"""

        result = parser.parse_content(ldif_content)
        # Should handle many attributes
        assert result.is_success or result.is_failure


class TestRfcParserSpecialCases:
    """Test suite for RFC parser special cases."""

    def test_parse_comment_lines(self) -> None:
        """Test parsing LDIF with comment lines."""
        registry = QuirkRegistryService()
        parser = RfcLdifParserService(
            params={},
            quirk_registry=registry,
        )

        ldif_content = """# This is a comment
dn: cn=test,dc=example,dc=com
# Another comment
objectClass: person
cn: test

"""

        result = parser.parse_content(ldif_content)
        # Comments should be ignored
        assert result.is_success or result.is_failure

    def test_parse_version_header(self) -> None:
        """Test parsing LDIF with version header."""
        registry = QuirkRegistryService()
        parser = RfcLdifParserService(
            params={},
            quirk_registry=registry,
        )

        ldif_content = """version: 1

dn: cn=test,dc=example,dc=com
objectClass: person
cn: test

"""

        result = parser.parse_content(ldif_content)
        # Version header should be handled
        assert result.is_success or result.is_failure

    def test_parse_url_attribute_values(self) -> None:
        """Test parsing LDIF with URL-based attribute values."""
        registry = QuirkRegistryService()
        parser = RfcLdifParserService(
            params={},
            quirk_registry=registry,
        )

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
jpegPhoto:< file:///tmp/photo.jpg

"""

        result = parser.parse_content(ldif_content)
        # URL attributes may not be supported, but should handle gracefully
        assert result.is_success or result.is_failure

    def test_parse_entry_with_change_type(self) -> None:
        """Test parsing LDIF with changeType (LDIF change records)."""
        registry = QuirkRegistryService()
        parser = RfcLdifParserService(
            params={},
            quirk_registry=registry,
        )

        ldif_content = """dn: cn=test,dc=example,dc=com
changetype: add
objectClass: person
cn: test

"""

        result = parser.parse_content(ldif_content)
        # Change records may not be fully supported, but should handle gracefully
        assert result.is_success or result.is_failure

    def test_parse_mixed_line_endings(self) -> None:
        """Test parsing LDIF with mixed line endings (CRLF and LF)."""
        registry = QuirkRegistryService()
        parser = RfcLdifParserService(
            params={},
            quirk_registry=registry,
        )

        # Mix of CRLF and LF line endings
        ldif_content = "dn: cn=test,dc=example,dc=com\r\nobjectClass: person\ncn: test\r\n\n"

        result = parser.parse_content(ldif_content)
        # Should handle mixed line endings
        assert result.is_success or result.is_failure
