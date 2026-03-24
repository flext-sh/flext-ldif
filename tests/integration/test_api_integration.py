"""Comprehensive API integration tests for flext-ldif.

Tests the complete FlextLdif facade with all major operations:
- Parsing LDIF files with different servers
- Filtering entries across multiple criteria
- Building entries with unified API
- Configuration and quirks integration

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum, unique
from typing import Final

import pytest

from flext_ldif import FlextLdif, FlextLdifStatistics, m
from tests import c


@unique
class APIScenarios(StrEnum):
    """Test scenarios for API integration testing."""

    SIMPLE_LDIF = "simple_ldif"
    FILTER_BY_OBJECTCLASS = "filter_by_objectclass"
    FILTER_BY_DN_PATTERN = "filter_by_dn_pattern"
    BUILD_ENTRY = "build_entry"
    VALIDATE_ENTRIES = "validate_entries"
    MULTIPLE_INSTANCES = "multiple_instances"
    FILTER_MULTIPLE_CRITERIA = "filter_multiple_criteria"
    API_FACADE_PROPERTIES = "api_facade_properties"
    END_TO_END_WORKFLOW = "end_to_end_workflow"


class TestData:
    """Test data constants for API integration tests."""

    SIMPLE_LDIF: Final[str] = c.RFC.SAMPLE_LDIF_BASIC
    MULTI_ENTRY_LDIF: Final[str] = c.RFC.SAMPLE_LDIF_MULTIPLE
    COMPLEX_LDIF: Final[str] = (
        f"{c.RFC.SAMPLE_LDIF_MULTIPLE}\ndn: cn=Admin1,ou=Admins,dc=example,dc=com\ncn: Admin1\nmail: REDACTED_LDAP_BIND_PASSWORD1@example.com\nobjectClass: person\n\ndn: cn=Admin2,ou=Admins,dc=example,dc=com\ncn: Admin2\nmail: REDACTED_LDAP_BIND_PASSWORD2@example.com\nobjectClass: person\n"
    )
    FILTER_TEST_DATA: Final[Mapping[str, t.StrMapping]] = {
        "person": {"objectclass": "person", "expected_count": "2"},
        "organizationalPerson": {
            "objectclass": "organizationalPerson",
            "expected_count": "0",
        },
        "nonexistent": {"objectclass": "nonexistent", "expected_count": "0"},
    }
    DN_PATTERN_DATA: Final[Mapping[str, t.StrMapping]] = {
        "dc=example": {"pattern": "dc=example", "expected_count": "4"},
        "cn=user1": {"pattern": "cn=user1", "expected_count": "1"},
        "nonexistent": {"pattern": "ou=NonExistent", "expected_count": "0"},
    }


class TestFlextLdifAPIIntegration:
    """Comprehensive API integration tests for FlextLdif facade.

    Uses advanced Python 3.13 patterns:
    - StrEnum for test scenarios
    - Mapping for immutable test data
    - Parametrized dynamic tests
    - Factory pattern for test data creation
    - Builder pattern for complex test setup
    """

    _SIMPLE_LDIF: Final[str] = c.RFC.SAMPLE_LDIF_BASIC
    _MULTI_ENTRY_LDIF: Final[str] = c.RFC.SAMPLE_LDIF_MULTIPLE
    _COMPLEX_LDIF: Final[str] = TestData.COMPLEX_LDIF

    @pytest.mark.parametrize(
        ("scenario", "ldif_content", "expected_entries"),
        [
            (APIScenarios.SIMPLE_LDIF, TestData.SIMPLE_LDIF, 1),
            (APIScenarios.MULTIPLE_INSTANCES, TestData.MULTI_ENTRY_LDIF, 2),
        ],
    )
    def test_parse_ldif_scenarios(
        self, scenario: APIScenarios, ldif_content: str, expected_entries: int
    ) -> None:
        """Test parsing LDIF content across different scenarios."""
        ldif = FlextLdif()
        result = ldif.parse(ldif_content)
        assert result.is_success
        entries = result.value
        assert len(entries) == expected_entries
        for entry in entries:
            assert hasattr(entry, "dn") and hasattr(entry, "attributes")
            assert entry.dn is not None
            assert entry.attributes is not None
            assert entry.dn.value
            assert entry.attributes.attributes

    @pytest.mark.parametrize(
        ("test_name", "objectclass", "expected_count"),
        [
            (name, data["objectclass"], int(data["expected_count"]))
            for name, data in TestData.FILTER_TEST_DATA.items()
        ],
    )
    def test_filter_by_objectclass_dynamic(
        self, test_name: str, objectclass: str, expected_count: int
    ) -> None:
        """Dynamically test filtering by different objectClass values."""
        ldif = FlextLdif()
        parse_result = ldif.parse(self._MULTI_ENTRY_LDIF)
        assert parse_result.is_success
        entries = parse_result.value
        result = ldif.filter(entries, objectclass=objectclass)
        assert result.is_success
        filtered = result.value
        assert len(filtered) == expected_count

    @pytest.mark.parametrize(
        ("test_name", "dn_pattern", "expected_count"),
        [
            (name, data["pattern"], int(data["expected_count"]))
            for name, data in TestData.DN_PATTERN_DATA.items()
        ],
    )
    def test_filter_by_dn_pattern_dynamic(
        self, test_name: str, dn_pattern: str, expected_count: int
    ) -> None:
        """Dynamically test filtering by different DN patterns."""
        ldif = FlextLdif()
        parse_result = ldif.parse(self._COMPLEX_LDIF)
        assert parse_result.is_success
        entries = parse_result.value
        result = ldif.filter(entries, dn_pattern=dn_pattern)
        assert result.is_success
        filtered = result.value
        assert len(filtered) == expected_count

    def test_build_entry_programmatic(self) -> None:
        """Test building entries programmatically using models."""
        test_dn = c.RFC.TEST_DN
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=test_dn),
            attributes=m.Ldif.Attributes(
                attributes={
                    c.Names.CN: [c.General.ATTR_VALUE_TEST],
                    c.Names.SN: [c.General.ATTR_VALUE_USER],
                    c.Names.OBJECTCLASS: [c.Names.PERSON],
                }
            ),
        )
        assert entry.dn is not None
        assert entry.attributes is not None
        assert entry.dn.value == test_dn
        assert c.Names.CN in entry.attributes.attributes
        assert entry.attributes.attributes[c.Names.CN] == [c.General.ATTR_VALUE_TEST]

    def test_validate_entries_workflow(self) -> None:
        """Test complete validation workflow."""
        ldif = FlextLdif()
        parse_result = ldif.parse(self._SIMPLE_LDIF)
        assert parse_result.is_success
        entries = parse_result.value
        validate_result = ldif.validate_entries(entries)
        assert validate_result.is_success

    def test_multiple_instances_independence(self) -> None:
        """Test that multiple FlextLdif instances work independently."""
        ldif1 = FlextLdif()
        ldif2 = FlextLdif()
        result1 = ldif1.parse(self._SIMPLE_LDIF)
        result2 = ldif2.parse(self._SIMPLE_LDIF)
        assert result1.is_success
        assert result2.is_success
        entries1 = result1.value
        entries2 = result2.value
        assert len(entries1) == len(entries2) == 1
        assert entries1[0].dn is not None
        assert entries2[0].dn is not None
        assert entries1[0].dn.value == entries2[0].dn.value

    def test_filter_multiple_criteria_combined(self) -> None:
        """Test filtering with combined DN and attribute criteria."""
        ldif = FlextLdif()
        parse_result = ldif.parse(self._COMPLEX_LDIF)
        assert parse_result.is_success
        entries = parse_result.value
        result = ldif.filter(
            entries, dn_pattern="ou=Admins", attributes={c.Names.MAIL: ""}
        )
        assert result.is_success
        filtered = result.value
        assert len(filtered) == 2

    def test_api_facade_property_access(self) -> None:
        """Test accessing facade properties and models."""
        ldif = FlextLdif()
        models = ldif.models
        assert models is not None
        assert hasattr(models, "Ldif")
        assert hasattr(models.Ldif, "Entry")

    def test_end_to_end_workflow_complete(self) -> None:
        """Test complete end-to-end workflow from parse to filter."""
        ldif = FlextLdif()
        parse_result = ldif.parse(self._SIMPLE_LDIF)
        assert parse_result.is_success
        entries = parse_result.value
        analyze_result = FlextLdifStatistics().calculate_for_entries(entries)
        assert analyze_result.is_success
        stats = analyze_result.value
        assert stats.total_entries == 1
        validate_result = ldif.validate_entries(entries)
        assert validate_result.is_success
        filter_result = ldif.filter(entries, objectclass=c.Names.PERSON)
        assert filter_result.is_success
        filtered = filter_result.value
        assert len(filtered) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
