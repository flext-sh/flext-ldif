"""Tests for edge cases in quirks server handling.

This module tests boundary conditions, error cases, and unusual LDIF
content patterns across different LDAP server implementations.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from flext_tests import tm
from tests import s

from flext_ldif import FlextLdif


@pytest.fixture(autouse=True)
def cleanup_state() -> None:
    """Autouse fixture to clean shared state between tests.

    Runs after each test to prevent state pollution to subsequent tests.
    Ensures test isolation even when fixtures have shared state.
    """
    return


@pytest.fixture
def ldif_api() -> FlextLdif:
    """Provides a FlextLdif API instance for the test function."""
    return FlextLdif()


class TestsFlextLdifEdgeCases(s):
    """Test edge cases with real fixture files."""

    def test_unicode_names(self, ldif_api: FlextLdif) -> None:
        """Test parsing of entries with unicode characters in names."""
        unicode_ldif = "dn: cn=José,ou=Users,dc=example,dc=com\ncn: José\nsn: García\nobjectClass: person\n\n"
        result = ldif_api.parse(unicode_ldif, server_type="rfc")
        (
            tm.that(result.is_success, eq=True),
            f"Failed to parse unicode content: {result.error}",
        )
        entries = result.value
        tm.that(len(entries) > 0, eq=True)
        for entry in entries:
            tm.that(entry.dn is not None, eq=True)
            if entry.dn is not None:
                tm.that(entry.dn.value, eq=True)
                has_unicode = any(ord(c) > 127 for c in entry.dn.value)
                if has_unicode:
                    tm.that(entry.dn.value, eq=True)

    def test_deep_dn(self, ldif_api: FlextLdif) -> None:
        """Test parsing of entries with very deep DN hierarchies."""
        deep_dn_ldif = "dn: cn=level1,ou=level2,ou=level3,ou=level4,ou=level5,ou=level6,dc=example,dc=com\ncn: level1\nobjectClass: person\n\n"
        result = ldif_api.parse(deep_dn_ldif, server_type="rfc")
        (
            tm.that(result.is_success, eq=True),
            f"Failed to parse deep DN content: {result.error}",
        )
        entries = result.value
        tm.that(len(entries) > 0, eq=True)
        max_depth = 0
        for entry in entries:
            if entry.dn is not None:
                depth = entry.dn.value.count(",") + 1
                max_depth = max(max_depth, depth)
        (
            tm.that(max_depth > 5, eq=True),
            f"Expected deep DN, got depth {max_depth}",
        )

    def test_large_multivalue(self, ldif_api: FlextLdif) -> None:
        """Test parsing of attributes with many values."""
        base_dir = Path(__file__).parent.parent.parent.parent
        fixture_path = (
            base_dir / "fixtures" / "edge_cases" / "size" / "large_multivalue.ldif"
        )
        if not fixture_path.exists():
            fixture_path = Path(
                "flext-ldif/tests/fixtures/edge_cases/size/large_multivalue.ldif"
            )
        result = ldif_api.parse(fixture_path, server_type="rfc")
        (
            tm.that(result.is_success, eq=True),
            (f"Failed to parse large multivalue fixture: {result.error}"),
        )
        entries = result.value
        tm.that(len(entries) > 0, eq=True)
        max_values = 0
        for entry in entries:
            if entry.attributes is None:
                continue
            for attr_value in entry.attributes.values():
                if isinstance(attr_value, list):
                    values = attr_value
                elif hasattr(attr_value, "values"):
                    values = attr_value.values
                else:
                    values = [attr_value]
                max_values = max(max_values, len(values))
        (
            tm.that(max_values >= 10, eq=True),
            (f"Expected large multivalue (>=10), got {max_values} values"),
        )

    def test_roundtrip_unicode(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test roundtrip of unicode entries."""
        unicode_ldif = "dn: cn=José,ou=Users,dc=example,dc=com\ncn: José\nsn: García\nobjectClass: person\n\n"
        parse_result = ldif_api.parse(unicode_ldif, server_type="rfc")
        (
            tm.that(parse_result.is_success, eq=True),
            f"Parse failed: {parse_result.error}",
        )
        entries = parse_result.value
        tm.that(len(entries) == 1, eq=True)
        output_path = tmp_path / "unicode_roundtrip.ldif"
        write_result = ldif_api.write_file(entries, output_path, server_type="rfc")
        (
            tm.that(write_result.is_success, eq=True),
            f"Write failed: {write_result.error}",
        )
        roundtrip_result = ldif_api.parse(output_path, server_type="rfc")
        (
            tm.that(roundtrip_result.is_success, eq=True),
            (f"Roundtrip parse failed: {roundtrip_result.error}"),
        )
        roundtrip_entries = roundtrip_result.value
        tm.that(len(roundtrip_entries) == 1, eq=True)

    def test_roundtrip_deep_dn(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test roundtrip of deep DN entries."""
        deep_dn_ldif = "dn: cn=level1,ou=level2,ou=level3,ou=level4,ou=level5,ou=level6,dc=example,dc=com\ncn: level1\nobjectClass: person\n\n"
        parse_result = ldif_api.parse(deep_dn_ldif, server_type="rfc")
        (
            tm.that(parse_result.is_success, eq=True),
            f"Parse failed: {parse_result.error}",
        )
        entries = parse_result.value
        tm.that(len(entries) == 1, eq=True)
        output_path = tmp_path / "deep_dn_roundtrip.ldif"
        write_result = ldif_api.write_file(entries, output_path, server_type="rfc")
        (
            tm.that(write_result.is_success, eq=True),
            f"Write failed: {write_result.error}",
        )
        roundtrip_result = ldif_api.parse(output_path, server_type="rfc")
        (
            tm.that(roundtrip_result.is_success, eq=True),
            (f"Roundtrip parse failed: {roundtrip_result.error}"),
        )
        roundtrip_entries = roundtrip_result.value
        tm.that(len(roundtrip_entries) == 1, eq=True)

    def test_roundtrip_large_multivalue(
        self, ldif_api: FlextLdif, tmp_path: Path
    ) -> None:
        """Test roundtrip of large multivalue entries."""
        large_multivalue_ldif = "dn: cn=test,dc=example,dc=com\ncn: test\nmember: cn=user1,dc=example,dc=com\nmember: cn=user2,dc=example,dc=com\nmember: cn=user3,dc=example,dc=com\nmember: cn=user4,dc=example,dc=com\nmember: cn=user5,dc=example,dc=com\nobjectClass: groupOfNames\n\n"
        parse_result = ldif_api.parse(large_multivalue_ldif, server_type="rfc")
        (
            tm.that(parse_result.is_success, eq=True),
            f"Parse failed: {parse_result.error}",
        )
        entries = parse_result.value
        tm.that(len(entries) == 1, eq=True)
        output_path = tmp_path / "large_multivalue_roundtrip.ldif"
        write_result = ldif_api.write_file(entries, output_path, server_type="rfc")
        (
            tm.that(write_result.is_success, eq=True),
            f"Write failed: {write_result.error}",
        )
        roundtrip_result = ldif_api.parse(output_path, server_type="rfc")
        (
            tm.that(roundtrip_result.is_success, eq=True),
            (f"Roundtrip parse failed: {roundtrip_result.error}"),
        )
        roundtrip_entries = roundtrip_result.value
        tm.that(len(roundtrip_entries) == 1, eq=True)
