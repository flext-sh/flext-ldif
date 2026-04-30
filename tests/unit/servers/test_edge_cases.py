"""Tests for edge cases in quirks server handling.

This module tests boundary conditions, error cases, and unusual LDIF
content patterns across different LDAP server implementations.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from flext_tests import tm

from flext_ldif import FlextLdif, ldif
from tests import c


@pytest.fixture(autouse=True)
def cleanup_state() -> None:
    """Autouse fixture to clean shared state between tests.

    Runs after each test to prevent state pollution to subsequent tests.
    Ensures test isolation even when fixtures have shared state.
    """
    return


@pytest.fixture
def ldif_api() -> FlextLdif:
    """Provides a ldif API instance for the test function."""
    return ldif()


class TestsFlextLdifEdgeCases:
    """Test edge cases with real fixture files."""

    @pytest.mark.parametrize(
        (
            "ldif_content",
            "expected_entry_count",
            "expected_min_depth",
            "expect_non_ascii",
        ),
        list(c.Ldif.Tests.EDGE_CASE_INLINE_PARSE_RULES.values()),
        ids=list(c.Ldif.Tests.EDGE_CASE_INLINE_PARSE_RULES.keys()),
    )
    def test_parse_inline_edge_cases(
        self,
        ldif_api: FlextLdif,
        ldif_content: str,
        expected_entry_count: int,
        expected_min_depth: int,
        expect_non_ascii: bool,
    ) -> None:
        """Test inline edge-case parsing rules using centralized datasets."""
        result = ldif_api.parse_ldif(ldif_content, server_type=c.Ldif.Tests.RFC)
        _ = tm.that(result.success, eq=True)
        entries = result.value.entries
        tm.that(len(entries), gte=expected_entry_count)
        max_depth = 0
        has_non_ascii = False
        for entry in entries:
            tm.that(entry.dn, none=False)
            if entry.dn is not None:
                depth = entry.dn.value.count(",") + 1
                max_depth = max(max_depth, depth)
                if c.Ldif.Tests.EDGE_CASE_NON_ASCII_REGEX.search(entry.dn.value):
                    has_non_ascii = True
        if expected_min_depth > 0:
            _ = tm.that(max_depth, gte=expected_min_depth)
        tm.that(has_non_ascii, eq=expect_non_ascii)

    def test_large_multivalue(self, ldif_api: FlextLdif) -> None:
        """Test parsing of attributes with many values."""
        fixture_path = (
            c.Ldif.Tests.FIXTURES_DIR
            / c.Ldif.Tests.EDGE_CASE_LARGE_MULTIVALUE_FIXTURE_RELATIVE
        )
        result = ldif_api.parse_ldif(fixture_path, server_type=c.Ldif.Tests.RFC)
        _ = tm.that(result.success, eq=True)
        entries = result.value.entries
        tm.that(len(entries) > 0, eq=True)
        max_values = 0
        for entry in entries:
            if entry.attributes is None:
                continue
            for attr_value in entry.attributes.values():
                max_values = max(max_values, len(attr_value))
        _ = tm.that(max_values, gte=c.Ldif.Tests.EDGE_CASE_MIN_MULTIVALUE_COUNT)

    @pytest.mark.parametrize(
        ("ldif_content", "output_name"),
        list(c.Ldif.Tests.EDGE_CASE_ROUNDTRIP_CASES.values()),
        ids=list(c.Ldif.Tests.EDGE_CASE_ROUNDTRIP_CASES.keys()),
    )
    def test_roundtrip_inline_edge_cases(
        self,
        ldif_api: FlextLdif,
        tmp_path: Path,
        ldif_content: str,
        output_name: str,
    ) -> None:
        """Test roundtrip of inline edge-case LDIF payloads."""
        parse_result = ldif_api.parse_ldif(
            ldif_content,
            server_type=c.Ldif.Tests.RFC,
        )
        _ = tm.that(parse_result.success, eq=True)
        entries = parse_result.value.entries
        tm.that(len(entries), eq=1)
        output_path = tmp_path / output_name
        write_result = ldif_api.write_ldif_file(
            entries, output_path, server_type=c.Ldif.Tests.RFC
        )
        _ = tm.that(write_result.success, eq=True)
        roundtrip_result = ldif_api.parse_ldif(
            output_path, server_type=c.Ldif.Tests.RFC
        )
        _ = tm.that(roundtrip_result.success, eq=True)
        roundtrip_entries = roundtrip_result.value.entries
        tm.that(len(roundtrip_entries), eq=1)
