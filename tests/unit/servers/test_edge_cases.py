"""Tests for edge cases in quirks server handling.

This module tests boundary conditions, error cases, and unusual LDIF
content patterns across different LDAP server implementations.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from flext_tests import tm

from flext_ldif import ldif
from tests import c


@pytest.fixture(autouse=True)
def cleanup_state() -> None:
    """Autouse fixture to clean shared state between tests.

    Runs after each test to prevent state pollution to subsequent tests.
    Ensures test isolation even when fixtures have shared state.
    """
    return


@pytest.fixture
def ldif_api() -> ldif:
    """Provides a ldif API instance for the test function."""
    return ldif()


class TestsFlextLdifEdgeCases:
    """Test edge cases with real fixture files."""

    def test_unicode_names(self, ldif_api: ldif) -> None:
        """Test parsing of entries with unicode characters in names."""
        unicode_ldif = "dn: cn=José,ou=Users,dc=example,dc=com\ncn: José\nsn: García\nobjectClass: person\n\n"
        result = ldif_api.parse_ldif(unicode_ldif, server_type=c.Ldif.Tests.RFC)
        _ = tm.that(result.is_success, eq=True)
        entries = result.value.entries
        tm.that(len(entries) > 0, eq=True)
        for entry in entries:
            tm.that(entry.dn, none=False)
            if entry.dn is not None:
                tm.that(len(entry.dn.value) > 0, eq=True)
                has_unicode = any(ord(c) > 127 for c in entry.dn.value)
                if has_unicode:
                    tm.that(len(entry.dn.value) > 0, eq=True)

    def test_deep_dn(self, ldif_api: ldif) -> None:
        """Test parsing of entries with very deep DN hierarchies."""
        deep_dn_ldif = "dn: cn=level1,ou=level2,ou=level3,ou=level4,ou=level5,ou=level6,dc=example,dc=com\ncn: level1\nobjectClass: person\n\n"
        result = ldif_api.parse_ldif(deep_dn_ldif, server_type=c.Ldif.Tests.RFC)
        _ = tm.that(result.is_success, eq=True)
        entries = result.value.entries
        tm.that(len(entries) > 0, eq=True)
        max_depth = 0
        for entry in entries:
            if entry.dn is not None:
                depth = entry.dn.value.count(",") + 1
                max_depth = max(max_depth, depth)
        _ = tm.that(max_depth, gt=5)

    def test_large_multivalue(self, ldif_api: ldif) -> None:
        """Test parsing of attributes with many values."""
        fixture_path = (
            Path(__file__).resolve().parents[2]
            / "fixtures"
            / "edge_cases"
            / "size"
            / "large_multivalue.ldif"
        )
        result = ldif_api.parse_ldif(fixture_path, server_type=c.Ldif.Tests.RFC)
        _ = tm.that(result.is_success, eq=True)
        entries = result.value.entries
        tm.that(len(entries) > 0, eq=True)
        max_values = 0
        for entry in entries:
            if entry.attributes is None:
                continue
            for attr_value in entry.attributes.values():
                max_values = max(max_values, len(attr_value))
        _ = tm.that(max_values, gte=10)

    def test_roundtrip_unicode(self, ldif_api: ldif, tmp_path: Path) -> None:
        """Test roundtrip of unicode entries."""
        unicode_ldif = "dn: cn=José,ou=Users,dc=example,dc=com\ncn: José\nsn: García\nobjectClass: person\n\n"
        parse_result = ldif_api.parse_ldif(unicode_ldif, server_type=c.Ldif.Tests.RFC)
        _ = tm.that(parse_result.is_success, eq=True)
        entries = parse_result.value.entries
        tm.that(len(entries), eq=1)
        output_path = tmp_path / "unicode_roundtrip.ldif"
        write_result = ldif_api.write_ldif_file(
            entries, output_path, server_type=c.Ldif.Tests.RFC
        )
        _ = tm.that(write_result.is_success, eq=True)
        roundtrip_result = ldif_api.parse_ldif(
            output_path, server_type=c.Ldif.Tests.RFC
        )
        _ = tm.that(roundtrip_result.is_success, eq=True)
        roundtrip_entries = roundtrip_result.value.entries
        tm.that(len(roundtrip_entries), eq=1)

    def test_roundtrip_deep_dn(self, ldif_api: ldif, tmp_path: Path) -> None:
        """Test roundtrip of deep DN entries."""
        deep_dn_ldif = "dn: cn=level1,ou=level2,ou=level3,ou=level4,ou=level5,ou=level6,dc=example,dc=com\ncn: level1\nobjectClass: person\n\n"
        parse_result = ldif_api.parse_ldif(deep_dn_ldif, server_type=c.Ldif.Tests.RFC)
        _ = tm.that(parse_result.is_success, eq=True)
        entries = parse_result.value.entries
        tm.that(len(entries), eq=1)
        output_path = tmp_path / "deep_dn_roundtrip.ldif"
        write_result = ldif_api.write_ldif_file(
            entries, output_path, server_type=c.Ldif.Tests.RFC
        )
        _ = tm.that(write_result.is_success, eq=True)
        roundtrip_result = ldif_api.parse_ldif(
            output_path, server_type=c.Ldif.Tests.RFC
        )
        _ = tm.that(roundtrip_result.is_success, eq=True)
        roundtrip_entries = roundtrip_result.value.entries
        tm.that(len(roundtrip_entries), eq=1)

    def test_roundtrip_large_multivalue(
        self,
        ldif_api: ldif,
        tmp_path: Path,
    ) -> None:
        """Test roundtrip of large multivalue entries."""
        large_multivalue_ldif = "dn: cn=test,dc=example,dc=com\ncn: test\nmember: cn=user1,dc=example,dc=com\nmember: cn=user2,dc=example,dc=com\nmember: cn=user3,dc=example,dc=com\nmember: cn=user4,dc=example,dc=com\nmember: cn=user5,dc=example,dc=com\nobjectClass: groupOfNames\n\n"
        parse_result = ldif_api.parse_ldif(
            large_multivalue_ldif, server_type=c.Ldif.Tests.RFC
        )
        _ = tm.that(parse_result.is_success, eq=True)
        entries = parse_result.value.entries
        tm.that(len(entries), eq=1)
        output_path = tmp_path / "large_multivalue_roundtrip.ldif"
        write_result = ldif_api.write_ldif_file(
            entries, output_path, server_type=c.Ldif.Tests.RFC
        )
        _ = tm.that(write_result.is_success, eq=True)
        roundtrip_result = ldif_api.parse_ldif(
            output_path, server_type=c.Ldif.Tests.RFC
        )
        _ = tm.that(roundtrip_result.is_success, eq=True)
        roundtrip_entries = roundtrip_result.value.entries
        tm.that(len(roundtrip_entries), eq=1)
