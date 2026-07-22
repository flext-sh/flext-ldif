"""Tests for edge cases in servers server handling.

This module tests boundary conditions, error cases, and unusual LDIF
content patterns across different LDAP server implementations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flext_ldif import ldif
from flext_tests import tm
from tests import c

if TYPE_CHECKING:
    from pathlib import Path

    from tests import p


@pytest.fixture
def ldif_api() -> p.Ldif.LdifClient:
    """Provide a ldif API instance for the test function."""
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
        list(c.Tests.EDGE_CASE_INLINE_PARSE_RULES.values()),
        ids=list(c.Tests.EDGE_CASE_INLINE_PARSE_RULES.keys()),
    )
    def test_parse_inline_edge_cases(
        self,
        ldif_api: p.Ldif.LdifClient,
        ldif_content: str,
        expected_entry_count: int,
        expected_min_depth: int,
        expect_non_ascii: bool,
    ) -> None:
        """Test inline edge-case parsing rules using centralized datasets."""
        entries = tm.ok(
            ldif_api.parse_ldif(ldif_content, server_type=c.Tests.RFC)
        ).entries
        tm.that(len(entries), gte=expected_entry_count)
        max_depth = 0
        has_non_ascii = False
        for entry in entries:
            tm.that(entry.dn, none=False)
            if entry.dn is not None:
                depth = entry.dn.value.count(",") + 1
                max_depth = max(max_depth, depth)
                if c.Tests.EDGE_CASE_NON_ASCII_REGEX.search(entry.dn.value):
                    has_non_ascii = True
        if expected_min_depth > 0:
            tm.that(max_depth, gte=expected_min_depth)
        tm.that(has_non_ascii, eq=expect_non_ascii)

    def test_large_multivalue(self, ldif_api: p.Ldif.LdifClient) -> None:
        """Test parsing of attributes with many values."""
        fixture_path = (
            c.Tests.FIXTURES_DIR / c.Tests.EDGE_CASE_LARGE_MULTIVALUE_FIXTURE_RELATIVE
        )
        entries = tm.ok(
            ldif_api.parse_ldif(fixture_path, server_type=c.Tests.RFC)
        ).entries
        tm.that(len(entries), gt=0)
        max_values = 0
        for entry in entries:
            if entry.attributes is None:
                continue
            for attr_value in entry.attributes.values():
                max_values = max(max_values, len(attr_value))
        tm.that(max_values, gte=c.Tests.EDGE_CASE_MIN_MULTIVALUE_COUNT)

    @pytest.mark.parametrize(
        ("ldif_content", "output_name"),
        list(c.Tests.EDGE_CASE_ROUNDTRIP_CASES.values()),
        ids=list(c.Tests.EDGE_CASE_ROUNDTRIP_CASES.keys()),
    )
    def test_roundtrip_inline_edge_cases(
        self,
        ldif_api: p.Ldif.LdifClient,
        tmp_path: Path,
        ldif_content: str,
        output_name: str,
    ) -> None:
        """Roundtrip must preserve DN and attribute values (idempotence).

        Parsing, writing, and re-parsing an edge-case payload (unicode DNs,
        deep DNs, large multi-value attributes) yields an entry whose public
        contract -- distinguished name and every attribute value list -- is
        identical to the original parse. This is the observable roundtrip
        guarantee, stronger than merely counting entries.
        """
        entries = tm.ok(
            ldif_api.parse_ldif(ldif_content, server_type=c.Tests.RFC)
        ).entries
        tm.that(len(entries), eq=1)
        original = entries[0]
        tm.that(original.dn, none=False)
        tm.that(original.attributes, none=False)

        output_path = tmp_path / output_name
        tm.ok(ldif_api.write_ldif_file(entries, output_path, server_type=c.Tests.RFC))
        roundtrip_entries = tm.ok(
            ldif_api.parse_ldif(output_path, server_type=c.Tests.RFC)
        ).entries
        tm.that(len(roundtrip_entries), eq=1)
        roundtrip = roundtrip_entries[0]
        tm.that(roundtrip.dn, none=False)
        tm.that(roundtrip.attributes, none=False)

        if (
            original.dn is not None
            and roundtrip.dn is not None
            and original.attributes is not None
            and roundtrip.attributes is not None
        ):
            tm.that(roundtrip.dn.value, eq=original.dn.value)
            original_attrs = dict(original.attributes.items())
            roundtrip_attrs = dict(roundtrip.attributes.items())
            tm.that(roundtrip_attrs, eq=original_attrs)
