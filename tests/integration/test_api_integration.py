"""Comprehensive API integration tests for flext-ldif.

Tests the complete ldif facade with all major operations:
- Parsing LDIF files with different servers
- Building entries with unified API
- Configuration and quirks integration

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif import FlextLdifStatistics, ldif
from tests import c, m


class TestFlextLdifAPIIntegration:
    """Comprehensive API integration tests for ldif facade.

    Uses advanced Python 3.13 patterns:
    - StrEnum for test scenarios
    - Mapping for immutable test data
    - Parametrized dynamic tests
    - Factory pattern for test data creation
    - Builder pattern for complex test setup
    """

    @pytest.mark.parametrize(
        ("scenario", "ldif_content", "expected_entries"),
        [
            (
                c.Ldif.Tests.API_SCENARIOS.SIMPLE_LDIF,
                c.Ldif.Tests.Rfc.SAMPLE_LDIF_BASIC,
                1,
            ),
            (
                c.Ldif.Tests.API_SCENARIOS.MULTIPLE_INSTANCES,
                c.Ldif.Tests.Rfc.SAMPLE_LDIF_MULTIPLE,
                2,
            ),
        ],
    )
    def test_parse_ldif_scenarios(
        self,
        scenario: str,
        ldif_content: str,
        expected_entries: int,
    ) -> None:
        """Test parsing LDIF content across different scenarios."""
        api = ldif()
        result = api.parse_ldif(ldif_content)
        assert result.is_success
        entries = result.value.entries
        assert len(entries) == expected_entries
        for entry in entries:
            assert entry.dn is not None
            assert entry.attributes is not None
            assert entry.dn.value
            assert entry.attributes.attributes

    def test_build_entry_programmatic(self) -> None:
        """Test building entries programmatically using models."""
        test_dn = c.Ldif.Tests.Rfc.TEST_DN
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=test_dn),
            attributes=m.Ldif.Attributes(
                attributes={
                    c.Ldif.Tests.Names.CN: [c.Ldif.Tests.General.ATTR_VALUE_TEST],
                    c.Ldif.Tests.Names.SN: [c.Ldif.Tests.General.ATTR_VALUE_USER],
                    c.Ldif.Tests.Names.OBJECTCLASS: [c.Ldif.Tests.Names.PERSON],
                },
                attribute_metadata={},
            ),
        )
        assert entry.dn is not None
        assert entry.attributes is not None
        assert entry.dn.value == test_dn
        assert c.Ldif.Tests.Names.CN in entry.attributes.attributes
        assert entry.attributes.attributes[c.Ldif.Tests.Names.CN] == [
            c.Ldif.Tests.General.ATTR_VALUE_TEST
        ]

    def test_validate_entries_workflow(self) -> None:
        """Test complete validation workflow."""
        api = ldif()
        parse_result = api.parse_ldif(c.Ldif.Tests.Rfc.SAMPLE_LDIF_BASIC)
        assert parse_result.is_success
        entries = parse_result.value.entries
        validate_result = api.validate_entries(entries)
        assert validate_result.is_success

    def test_multiple_instances_independence(self) -> None:
        """Test that multiple ldif instances work independently."""
        ldif1 = ldif()
        ldif2 = ldif()
        result1 = ldif1.parse_ldif(c.Ldif.Tests.Rfc.SAMPLE_LDIF_BASIC)
        result2 = ldif2.parse_ldif(c.Ldif.Tests.Rfc.SAMPLE_LDIF_BASIC)
        assert result1.is_success
        assert result2.is_success
        entries1 = result1.value.entries
        entries2 = result2.value.entries
        assert len(entries1) == len(entries2) == 1
        assert entries1[0].dn is not None
        assert entries2[0].dn is not None
        assert entries1[0].dn.value == entries2[0].dn.value

    def test_api_facade_property_access(self) -> None:
        """Test facade operations with the canonical LDIF model namespace."""
        api = ldif()
        create_result = m.Ldif.Entry.create(
            dn="cn=namespace-check,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": ["namespace-check"],
                "sn": ["check"],
            },
        )
        assert create_result.is_success
        created = create_result.value
        assert created is not None
        assert isinstance(created, m.Ldif.Entry)
        assert api.validate_entries([created]).is_success

    def test_end_to_end_workflow_complete(self) -> None:
        """Test complete end-to-end workflow from parse to filter."""
        api = ldif()
        parse_result = api.parse_ldif(c.Ldif.Tests.Rfc.SAMPLE_LDIF_BASIC)
        assert parse_result.is_success
        entries = parse_result.value.entries
        analyze_result = FlextLdifStatistics().calculate_for_entries(entries)
        assert analyze_result.is_success
        stats = analyze_result.value
        assert stats.total_entries == 1
        validate_result = api.validate_entries(entries)
        assert validate_result.is_success


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
