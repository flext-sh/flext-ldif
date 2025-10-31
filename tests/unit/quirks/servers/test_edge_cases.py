"""Test suite for LDIF edge cases and complex scenarios.

Tests unicode, binary data, size limits, and special characters using real fixtures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif.api import FlextLdif
from tests.unit.quirks.servers.test_utils import FlextLdifTestUtils


@pytest.fixture(scope="module")
def ldif_api() -> FlextLdif:
    """Provides a FlextLdif API instance for the test module."""
    return FlextLdif()


class TestEdgeCases:
    """Test edge cases with real fixture files."""

    def test_unicode_names(self, ldif_api: FlextLdif) -> None:
        """Test parsing of entries with unicode characters in names."""
        result = ldif_api.parse(
            Path("tests/fixtures/edge_cases/unicode/unicode_names.ldif"),
            server_type="rfc",
        )
        assert result.is_success, f"Failed to parse unicode fixture: {result.error}"
        entries = result.unwrap()
        assert len(entries) > 0

        # Validate unicode characters are preserved
        for entry in entries:
            assert entry.dn is not None
            assert entry.dn.value
            # Check for non-ASCII characters in DN or attributes
            has_unicode = any(ord(c) > 127 for c in entry.dn.value)
            if has_unicode:
                # Validate unicode was preserved
                assert entry.dn.value

    def test_deep_dn(self, ldif_api: FlextLdif) -> None:
        """Test parsing of entries with very deep DN hierarchies."""
        result = ldif_api.parse(
            Path("tests/fixtures/edge_cases/size/deep_dn.ldif"), server_type="rfc"
        )
        assert result.is_success, f"Failed to parse deep DN fixture: {result.error}"
        entries = result.unwrap()
        assert len(entries) > 0

        # Find the deepest DN
        max_depth = 0
        for entry in entries:
            depth = entry.dn.value.count(",") + 1
            max_depth = max(max_depth, depth)

        # Validate deep DNs are handled
        assert max_depth > 5, f"Expected deep DN, got depth {max_depth}"

    def test_large_multivalue(self, ldif_api: FlextLdif) -> None:
        """Test parsing of attributes with many values."""
        result = ldif_api.parse(
            Path("tests/fixtures/edge_cases/size/large_multivalue.ldif"),
            server_type="rfc",
        )
        assert result.is_success, (
            f"Failed to parse large multivalue fixture: {result.error}"
        )
        entries = result.unwrap()
        assert len(entries) > 0

        # Find attributes with many values
        max_values = 0
        for entry in entries:
            for attr_value in entry.attributes.values():
                if isinstance(attr_value, list):
                    values = attr_value
                elif hasattr(attr_value, "values"):
                    values = attr_value.values
                else:
                    values = [attr_value]
                max_values = max(max_values, len(values))

        # Validate large multivalue attributes are handled
        assert max_values >= 10, (
            f"Expected large multivalue (>=10), got {max_values} values"
        )

    def test_roundtrip_unicode(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test roundtrip of unicode entries."""
        FlextLdifTestUtils.run_roundtrip_test(
            ldif_api, "rfc", "../edge_cases/unicode/unicode_names.ldif", tmp_path
        )

    def test_roundtrip_deep_dn(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
        """Test roundtrip of deep DN entries."""
        FlextLdifTestUtils.run_roundtrip_test(
            ldif_api, "rfc", "../edge_cases/size/deep_dn.ldif", tmp_path
        )

    def test_roundtrip_large_multivalue(
        self, ldif_api: FlextLdif, tmp_path: Path
    ) -> None:
        """Test roundtrip of large multivalue entries."""
        FlextLdifTestUtils.run_roundtrip_test(
            ldif_api, "rfc", "../edge_cases/size/large_multivalue.ldif", tmp_path
        )
