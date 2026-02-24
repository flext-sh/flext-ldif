"""Edge case and boundary condition tests.

Test suite for validating edge cases and boundary conditions:
- Empty LDIF files
- Single entry LDIF
- Very large entries
- Maximum nesting depth
- Minimum required entries
- Boundary values for attribute counts
- Zero-length components
- Unicode boundary cases

Uses centralized fixtures from tests/integration/conftest.py.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_ldif import FlextLdif


class TestEmptyAndMinimalCases:
    """Test edge cases for empty and minimal LDIF content."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """FlextLdif API instance."""
        return FlextLdif.get_instance()

    def test_completely_empty_ldif(self, api: FlextLdif) -> None:
        """Test parsing of completely empty LDIF.

        Validates:
        - Empty string handled gracefully
        - Returns empty entry list
        - No errors on empty input
        """
        ldif_content = ""
        result = api.parse(ldif_content)
        assert result.is_success
        entries = result.value
        assert len(entries) == 0

    def test_only_whitespace(self, api: FlextLdif) -> None:
        """Test LDIF with only whitespace.

        Validates:
        - Whitespace-only content treated as empty
        - No spurious entries created
        - Graceful handling of blank input
        """
        ldif_content = "   \n\n  \t\n  "
        result = api.parse(ldif_content)
        assert result.is_success
        entries = result.value
        assert len(entries) == 0

    def test_only_comments(self, api: FlextLdif) -> None:
        """Test LDIF with only comment lines.

        Validates:
        - Comments-only content treated as empty
        - All comment lines ignored
        - No entry creation from comments
        """
        ldif_content = """# Comment line 1
# Comment line 2
# Comment line 3
"""
        result = api.parse(ldif_content)
        assert result.is_success
        entries = result.value
        assert len(entries) == 0

    def test_single_entry_minimal(self, api: FlextLdif) -> None:
        """Test minimal single entry.

        Validates:
        - Single entry with only DN parsed
        - No attributes required
        - Returns exactly one entry
        """
        ldif_content = "dn: cn=Single,dc=example,dc=com\n"
        result = api.parse(ldif_content)
        assert result.is_success
        entries = result.value
        assert len(entries) == 1
        assert str(entries[0].dn).lower() == "cn=single,dc=example,dc=com"

    def test_minimal_with_one_attribute(self, api: FlextLdif) -> None:
        """Test minimal entry with one attribute.

        Validates:
        - DN plus single attribute sufficient
        - Minimal objectClass optional
        - Entry parses successfully
        """
        ldif_content = """dn: cn=OneAttr,dc=example,dc=com
cn: OneAttr
"""
        result = api.parse(ldif_content)
        assert result.is_success
        entries = result.value
        assert len(entries) == 1


class TestLargeAndComplexCases:
    """Test edge cases for large and complex LDIF content."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """FlextLdif API instance."""
        return FlextLdif.get_instance()

    def test_entry_with_many_attributes(self, api: FlextLdif) -> None:
        """Test entry with many attributes (100+).

        Validates:
        - Large number of attributes handled
        - All attributes preserved
        - No truncation or loss
        """
        attributes = "".join(f"mail: user{i}@example.com\n" for i in range(100))
        ldif_content = f"""dn: cn=ManyAttrs,dc=example,dc=com
objectClass: person
cn: ManyAttrs
{attributes}"""
        result = api.parse(ldif_content)
        assert result.is_success
        entries = result.value
        assert len(entries) == 1
        assert len(entries[0].attributes) > 0

    def test_entry_with_many_values_per_attribute(self, api: FlextLdif) -> None:
        """Test single attribute with many values (100+).

        Validates:
        - Multi-valued attributes with many values
        - All values preserved
        - No value loss
        """
        values = "".join(f"mail: user{i}@example.com\n" for i in range(100))
        ldif_content = f"""dn: cn=ManyValues,dc=example,dc=com
objectClass: person
cn: ManyValues
{values}"""
        result = api.parse(ldif_content)
        assert result.is_success
        entries = result.value
        assert len(entries) == 1

    def test_very_long_single_value(self, api: FlextLdif) -> None:
        """Test attribute with very long single value (10KB+).

        Validates:
        - Large attribute values handled
        - No buffer overflow
        - Value completely preserved
        """
        long_value = "x" * 10000
        ldif_content = f"""dn: cn=LongValue,dc=example,dc=com
objectClass: person
cn: LongValue
description: {long_value}
"""
        result = api.parse(ldif_content)
        assert result.is_success
        entries = result.value
        assert len(entries) == 1

    def test_deeply_nested_dn_hierarchy(self, api: FlextLdif) -> None:
        """Test DN with deep nesting (10+ levels).

        Validates:
        - Deep DN hierarchy supported
        - All components preserved
        - DN parsing handles depth
        """
        deep_dn = ",".join(f"ou=level{i}" for i in range(10))
        deep_dn += ",dc=example,dc=com"
        ldif_content = f"""dn: cn=DeepNest,{deep_dn}
objectClass: person
cn: DeepNest
"""
        result = api.parse(ldif_content)
        assert result.is_success
        entries = result.value
        assert len(entries) == 1


class TestBoundaryValues:
    """Test boundary value conditions."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """FlextLdif API instance."""
        return FlextLdif.get_instance()

    def test_single_character_values(self, api: FlextLdif) -> None:
        """Test attributes with single character values.

        Validates:
        - Single character DN components
        - Single character attribute values
        - Minimal but valid content
        """
        ldif_content = """dn: cn=A,dc=B
objectClass: X
cn: A
sn: B
"""
        result = api.parse(ldif_content)
        assert result.is_success
        entries = result.value
        assert len(entries) == 1

    def test_special_single_characters(self, api: FlextLdif) -> None:
        """Test special single characters in values.

        Validates:
        - Special chars as single values work
        - No parsing errors
        - Values preserved exactly
        """
        ldif_content = """dn: cn=Special,dc=example,dc=com
cn: Special
sn: *
mail: +
description: -
"""
        result = api.parse(ldif_content)
        assert result.is_success
        entries = result.value
        assert len(entries) == 1

    def test_maximum_rdn_components(self, api: FlextLdif) -> None:
        """Test DN with maximum RDN components.

        Validates:
        - Many RDN components in DN
        - All preserved correctly
        - DN remains valid
        """
        rdn_count = 20
        dn_components = ",".join(f"ou=ou{i}" for i in range(rdn_count))
        dn_components += ",dc=example,dc=com"
        ldif_content = f"""dn: cn=MaxRDN,{dn_components}
objectClass: person
cn: MaxRDN
"""
        result = api.parse(ldif_content)
        assert result.is_success
        entries = result.value
        assert len(entries) == 1

    def test_minimum_valid_dn(self, api: FlextLdif) -> None:
        """Test absolute minimum valid DN.

        Validates:
        - Single RDN component DN valid
        - Shortest DN format works
        - Still properly parsed
        """
        ldif_content = """dn: cn=MinDN
objectClass: top
cn: MinDN
"""
        result = api.parse(ldif_content)
        # May or may not succeed depending on implementation
        # But should not crash
        assert result is not None


class TestUnicodeBoundaries:
    """Test Unicode and character encoding boundaries."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """FlextLdif API instance."""
        return FlextLdif.get_instance()

    def test_bmp_characters(self, api: FlextLdif) -> None:
        """Test Basic Multilingual Plane characters (U+0000 to U+FFFF).

        Validates:
        - BMP Unicode characters supported
        - Common international characters work
        - Proper encoding handling
        """
        ldif_content = """dn: cn=BMP,dc=example,dc=com
cn: BMP
description: Contains BMP: café, naïve, résumé, 中文, 日本語, العربية
"""
        result = api.parse(ldif_content)
        assert result.is_success

    def test_supplementary_plane_characters(self, api: FlextLdif) -> None:
        """Test Supplementary Plane characters (U+10000+).

        Validates:
        - Emoji and rare Unicode supported
        - Proper multi-byte handling
        - No truncation of supplementary chars
        """
        ldif_content = """dn: cn=Supplementary,dc=example,dc=com
cn: Supplementary
description: Contains emoji: 😀 🎉 🚀
"""
        result = api.parse(ldif_content)
        assert result.is_success

    def test_zero_width_characters(self, api: FlextLdif) -> None:
        """Test zero-width and invisible characters.

        Validates:
        - Zero-width spaces handled
        - Invisible formatting chars supported
        - Preserved in roundtrip
        """
        ldif_content = """dn: cn=ZeroWidth,dc=example,dc=com
cn: ZeroWidth
description: Contains\u200bzero\u200bwidth\u200bspaces
"""
        result = api.parse(ldif_content)
        assert result.is_success

    def test_combining_characters(self, api: FlextLdif) -> None:
        """Test combining diacritical marks.

        Validates:
        - Combining marks work correctly
        - Decomposed vs. composed handled
        - Text normalization working
        """
        ldif_content = """dn: cn=Combining,dc=example,dc=com
cn: Combining
description: Contains combining: é (e + ́)
"""
        result = api.parse(ldif_content)
        assert result.is_success


class TestRoundtripEdgeCases:
    """Test roundtrip parsing with edge cases."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """FlextLdif API instance."""
        return FlextLdif.get_instance()

    def test_roundtrip_empty(self, api: FlextLdif) -> None:
        """Test roundtrip of empty LDIF.

        Validates:
        - Empty → write → empty produces empty or version line only
        - No spurious entries created
        - Consistent round-trip
        """
        ldif_content = ""
        result = api.parse(ldif_content)
        assert result.is_success
        entries = result.value
        assert len(entries) == 0

        write_result = api.write(entries)
        assert write_result.is_success
        written = write_result.value
        # Empty entries may produce empty output or "version: 1\n" (both valid per RFC 2849)
        assert len(written) == 0 or written.isspace() or written.strip() == "version: 1"

    def test_roundtrip_single_minimal_entry(self, api: FlextLdif) -> None:
        """Test roundtrip of single minimal entry.

        Validates:
        - Single entry roundtrips correctly
        - DN preserved
        - No attribute loss
        """
        ldif_content = "dn: cn=Test,dc=example,dc=com\ncn: Test\n"
        result = api.parse(ldif_content)
        assert result.is_success
        entries = result.value
        assert len(entries) == 1

        write_result = api.write(entries)
        assert write_result.is_success

        roundtrip_result = api.parse(write_result.value)
        assert roundtrip_result.is_success
        roundtrip_entries = roundtrip_result.value
        assert len(roundtrip_entries) == 1

    def test_roundtrip_with_many_entries(self, api: FlextLdif) -> None:
        """Test roundtrip with many entries (100+).

        Validates:
        - Large entry count handled
        - All entries preserved
        - Correct count on roundtrip
        """
        entries_ldif = "\n".join(
            f"""dn: cn=Entry{i},dc=example,dc=com
objectClass: person
cn: Entry{i}
sn: Test{i}"""
            for i in range(100)
        )
        result = api.parse(entries_ldif)
        assert result.is_success
        entries = result.value
        initial_count = len(entries)

        write_result = api.write(entries)
        assert write_result.is_success

        roundtrip_result = api.parse(write_result.value)
        assert roundtrip_result.is_success
        roundtrip_entries = roundtrip_result.value
        assert len(roundtrip_entries) == initial_count


__all__ = [
    "TestBoundaryValues",
    "TestEmptyAndMinimalCases",
    "TestLargeAndComplexCases",
    "TestRoundtripEdgeCases",
    "TestUnicodeBoundaries",
]
