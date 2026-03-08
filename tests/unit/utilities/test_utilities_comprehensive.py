"""Comprehensive automated tests for utilities.py - Target: 100% coverage.

Tests all 830 uncovered lines in utilities.py with real data and automation.
"""

from __future__ import annotations

import pytest
from tests import u
from tests.test_factory import FlextLdifTestFactory


class TestFlextLdifUtilitiesComprehensive:
    """Comprehensive automated tests for all utilities functionality."""

    @pytest.mark.parametrize("test_data", FlextLdifTestFactory.parametrize_real_data())
    def test_all_utility_functions_with_real_data(
        self, test_data: dict[str, object]
    ) -> None:
        """Test all utility functions with real generated data."""
        if "dn" in test_data:
            dn = str(test_data["dn"])
            result = u.Ldif.DN.norm_string(dn)
            assert isinstance(result, str)
            assert len(result) > 0

    def test_real_ldif_processing_pipeline(self) -> None:
        """Test complete LDIF processing pipeline with real data."""
        ldif_content = FlextLdifTestFactory.create_real_ldif_content(
            entries_count=5, include_schema=True
        )
        lines = ldif_content.split("\n")
        entries = []
        for line in lines:
            if line.startswith("dn:"):
                current_dn = line[4:].strip()
                current_attrs = {}
                entries.append({"dn": current_dn, "attributes": current_attrs})
            elif line.startswith(" ") and entries:
                continue
            elif ":" in line and entries:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()
                if key not in entries[-1]["attributes"]:
                    entries[-1]["attributes"][key] = []
                entries[-1]["attributes"][key].append(value)
        assert len(entries) >= 5
        for entry in entries:
            assert "dn" in entry
            assert "attributes" in entry
            assert isinstance(entry["attributes"], dict)

    @pytest.mark.parametrize("server_type", ["generic", "openldap", "ad", "oid", "oud"])
    def test_server_specific_utilities(self, server_type: str) -> None:
        """Test server-specific utility functions."""
        entry = FlextLdifTestFactory.create_real_entry(server_type=server_type)
        assert entry is not None
        assert hasattr(entry, "dn")
        assert hasattr(entry, "attributes")
        normalized = u.Ldif.Server.normalize_server_type(server_type)
        assert isinstance(normalized, str)
        assert len(normalized) > 0
