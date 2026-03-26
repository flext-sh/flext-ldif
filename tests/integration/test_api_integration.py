"""Comprehensive API integration tests for flext-ldif.

Tests the complete ldif facade with all major operations:
- Parsing LDIF files with different servers
- Building entries with unified API
- Configuration and quirks integration

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum, unique
from typing import Final

import pytest

from flext_ldif import FlextLdifStatistics, ldif, m
from tests import c


@unique
class APIScenarios(StrEnum):
    """Test scenarios for API integration testing."""

    SIMPLE_LDIF = "simple_ldif"
    BUILD_ENTRY = "build_entry"
    VALIDATE_ENTRIES = "validate_entries"
    MULTIPLE_INSTANCES = "multiple_instances"
    API_FACADE_PROPERTIES = "api_facade_properties"
    END_TO_END_WORKFLOW = "end_to_end_workflow"


class TestData:
    """Test data constants for API integration tests."""

    SIMPLE_LDIF: Final[str] = c.Ldif.RFC.SAMPLE_LDIF_BASIC
    MULTI_ENTRY_LDIF: Final[str] = c.Ldif.RFC.SAMPLE_LDIF_MULTIPLE


class TestFlextLdifAPIIntegration:
    """Comprehensive API integration tests for ldif facade.

    Uses advanced Python 3.13 patterns:
    - StrEnum for test scenarios
    - Mapping for immutable test data
    - Parametrized dynamic tests
    - Factory pattern for test data creation
    - Builder pattern for complex test setup
    """

    _SIMPLE_LDIF: Final[str] = c.Ldif.RFC.SAMPLE_LDIF_BASIC

    @pytest.mark.parametrize(
        ("scenario", "ldif_content", "expected_entries"),
        [
            (APIScenarios.SIMPLE_LDIF, TestData.SIMPLE_LDIF, 1),
            (APIScenarios.MULTIPLE_INSTANCES, TestData.MULTI_ENTRY_LDIF, 2),
        ],
    )
    def test_parse_ldif_scenarios(
        self,
        scenario: APIScenarios,
        ldif_content: str,
        expected_entries: int,
    ) -> None:
        """Test parsing LDIF content across different scenarios."""
        api = ldif()
        result = api.parse_ldif(ldif_content)
        assert result.is_success
        entries = result.value
        assert len(entries) == expected_entries
        for entry in entries:
            assert hasattr(entry, "dn") and hasattr(entry, "attributes")
            assert entry.dn is not None
            assert entry.attributes is not None
            assert entry.dn.value
            assert entry.attributes.attributes

    def test_build_entry_programmatic(self) -> None:
        """Test building entries programmatically using models."""
        test_dn = c.Ldif.RFC.TEST_DN
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=test_dn),
            attributes=m.Ldif.Attributes(
                attributes={
                    c.Ldif.Names.CN: [c.Ldif.General.ATTR_VALUE_TEST],
                    c.Ldif.Names.SN: [c.Ldif.General.ATTR_VALUE_USER],
                    c.Ldif.Names.OBJECTCLASS: [c.Ldif.Names.PERSON],
                },
                attribute_metadata={},
            ),
        )
        assert entry.dn is not None
        assert entry.attributes is not None
        assert entry.dn.value == test_dn
        assert c.Ldif.Names.CN in entry.attributes.attributes
        assert entry.attributes.attributes[c.Ldif.Names.CN] == [
            c.Ldif.General.ATTR_VALUE_TEST
        ]

    def test_validate_entries_workflow(self) -> None:
        """Test complete validation workflow."""
        api = ldif()
        parse_result = api.parse_ldif(self._SIMPLE_LDIF)
        assert parse_result.is_success
        entries = parse_result.value
        validate_result = api.validate_entries(entries)
        assert validate_result.is_success

    def test_multiple_instances_independence(self) -> None:
        """Test that multiple ldif instances work independently."""
        ldif1 = ldif()
        ldif2 = ldif()
        result1 = ldif1.parse_ldif(self._SIMPLE_LDIF)
        result2 = ldif2.parse_ldif(self._SIMPLE_LDIF)
        assert result1.is_success
        assert result2.is_success
        entries1 = result1.value
        entries2 = result2.value
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
        parse_result = api.parse_ldif(self._SIMPLE_LDIF)
        assert parse_result.is_success
        entries = parse_result.value
        analyze_result = FlextLdifStatistics().calculate_for_entries(entries)
        assert analyze_result.is_success
        stats = analyze_result.value
        assert stats.total_entries == 1
        validate_result = api.validate_entries(entries)
        assert validate_result.is_success


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
