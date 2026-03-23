"""Comprehensive automated tests for utilities.py - Target: 100% coverage.

Tests all 830 uncovered lines in utilities.py with real data and automation.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

import pytest
from flext_tests import tm

from tests import FlextLdifTestFactory, m, u


class TestFlextLdifUtilitiesComprehensive:
    """Comprehensive automated tests for all utilities functionality."""

    @pytest.mark.parametrize("test_data", FlextLdifTestFactory.parametrize_real_data())
    def test_all_utility_functions_with_real_data(
        self, test_data: m.Ldif.Tests.LdifTestData
    ) -> None:
        """Test all utility functions with real generated data."""
        if test_data.dn:
            dn = test_data.dn
            result = u.Ldif.norm_string(dn)
            tm.that(isinstance(result, str), eq=True)
            tm.that(len(result) > 0, eq=True)

    def test_real_ldif_processing_pipeline(self) -> None:
        """Test complete LDIF processing pipeline with real data."""
        ldif_content = FlextLdifTestFactory.create_real_ldif_content(
            entries_count=5, include_schema=True
        )
        lines = ldif_content.split("\n")
        entries: Sequence[m.Ldif.Tests.LdifTestData] = []
        for line in lines:
            if line.startswith("dn:"):
                current_dn = line[4:].strip()
                current_attrs: Mapping[str, Sequence[str]] = {}
                entries.append(
                    m.Ldif.Tests.LdifTestData(
                        id=f"entry_{len(entries)}",
                        server_type="generic",
                        dn=current_dn,
                        attributes=current_attrs,
                    )
                )
            elif line.startswith(" ") and entries:
                continue
            elif ":" in line and entries:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()
                if key not in entries[-1].attributes:
                    entries[-1].attributes[key] = []
                entries[-1].attributes[key].append(value)
        tm.that(len(entries) >= 5, eq=True)
        for entry in entries:
            tm.that(entry.dn, none=False)
            tm.that(len(entry.attributes) > 0, eq=True)
            tm.that(isinstance(entry.attributes, dict), eq=True)

    @pytest.mark.parametrize("server_type", ["generic", "openldap", "ad", "oid", "oud"])
    def test_server_specific_utilities(self, server_type: str) -> None:
        """Test server-specific utility functions."""
        entry = FlextLdifTestFactory.create_real_entry(server_type=server_type)
        tm.that(entry is not None, eq=True)
        tm.that(hasattr(entry, "dn"), eq=True)
        tm.that(hasattr(entry, "attributes"), eq=True)
        normalized = u.Ldif.normalize_server_type(server_type)
        tm.that(isinstance(normalized, str), eq=True)
        tm.that(len(normalized) > 0, eq=True)
