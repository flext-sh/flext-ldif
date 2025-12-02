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
from enum import StrEnum
from typing import Final

import pytest
from flext_tests import FlextTestsFactories  # Mocked in conftest

from flext_ldif import FlextLdif, FlextLdifModels
from tests.fixtures.constants import RFC, DNs, Names, Values


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

    SIMPLE_LDIF: Final[str] = RFC.SAMPLE_LDIF_BASIC
    MULTI_ENTRY_LDIF: Final[str] = RFC.SAMPLE_LDIF_MULTIPLE
    COMPLEX_LDIF: Final[str] = f"""{RFC.SAMPLE_LDIF_MULTIPLE}
dn: cn=Admin1,ou=Admins,dc=example,dc=com
cn: Admin1
mail: REDACTED_LDAP_BIND_PASSWORD1@example.com
objectClass: person

dn: cn=Admin2,ou=Admins,dc=example,dc=com
cn: Admin2
mail: REDACTED_LDAP_BIND_PASSWORD2@example.com
objectClass: person
"""

    FILTER_TEST_DATA: Final[Mapping[str, Mapping[str, str]]] = {
        "person": {
            "objectclass": "person",
            "expected_count": "2",
        },  # Both entries have person
        "organizationalPerson": {
            "objectclass": "organizationalPerson",
            "expected_count": "0",
        },  # Neither has this
        "nonexistent": {"objectclass": "nonexistent", "expected_count": "0"},
    }

    DN_PATTERN_DATA: Final[Mapping[str, Mapping[str, str]]] = {
        "dc=example": {
            "pattern": "dc=example",
            "expected_count": "4",
        },  # All entries match
        "cn=user1": {"pattern": "cn=user1", "expected_count": "1"},  # Only first entry
        "nonexistent": {"pattern": "ou=NonExistent", "expected_count": "0"},
    }


class TestFlextLdifAPIIntegration(FlextTestsFactories):
    """Comprehensive API integration tests for FlextLdif facade.

    Uses advanced Python 3.13 patterns:
    - StrEnum for test scenarios
    - Mapping for immutable test data
    - Parametrized dynamic tests
    - Factory pattern for test data creation
    - Builder pattern for complex test setup
    """

    # Test data constants
    _SIMPLE_LDIF: Final[str] = RFC.SAMPLE_LDIF_BASIC
    _MULTI_ENTRY_LDIF: Final[str] = RFC.SAMPLE_LDIF_MULTIPLE
    _COMPLEX_LDIF: Final[str] = TestData.COMPLEX_LDIF

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
        ldif = FlextLdif()

        result = ldif.parse(ldif_content)
        assert result.is_success

        entries = result.unwrap()
        assert len(entries) == expected_entries

        # Validate entry structure
        for entry in entries:
            assert isinstance(entry, FlextLdifModels.Entry)
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
        self,
        test_name: str,
        objectclass: str,
        expected_count: int,
    ) -> None:
        """Dynamically test filtering by different objectClass values."""
        ldif = FlextLdif()

        # Parse multi-entry content
        parse_result = ldif.parse(self._MULTI_ENTRY_LDIF)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        # Filter by objectclass
        result = ldif.filter(entries, objectclass=objectclass)
        assert result.is_success

        filtered = result.unwrap()
        assert len(filtered) == expected_count

    @pytest.mark.parametrize(
        ("test_name", "dn_pattern", "expected_count"),
        [
            (name, data["pattern"], int(data["expected_count"]))
            for name, data in TestData.DN_PATTERN_DATA.items()
        ],
    )
    def test_filter_by_dn_pattern_dynamic(
        self,
        test_name: str,
        dn_pattern: str,
        expected_count: int,
    ) -> None:
        """Dynamically test filtering by different DN patterns."""
        ldif = FlextLdif()

        # Parse complex content with REDACTED_LDAP_BIND_PASSWORDs and people
        parse_result = ldif.parse(self._COMPLEX_LDIF)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        # Filter by DN pattern
        result = ldif.filter(entries, dn_pattern=dn_pattern)
        assert result.is_success

        filtered = result.unwrap()
        assert len(filtered) == expected_count

    def test_build_entry_programmatic(self) -> None:
        """Test building entries programmatically using models."""
        # Create entry using Entry model directly
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=DNs.TEST_USER),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    Names.CN: [Values.TEST],
                    Names.SN: [Values.TEST],
                    Names.OBJECTCLASS: [Names.PERSON],
                },
            ),
        )

        assert entry.dn.value == DNs.TEST_USER
        assert Names.CN in entry.attributes.attributes
        assert entry.attributes.attributes[Names.CN] == [Values.TEST]

    def test_validate_entries_workflow(self) -> None:
        """Test complete validation workflow."""
        ldif = FlextLdif()

        parse_result = ldif.parse(self._SIMPLE_LDIF)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        validate_result = ldif.validate_entries(entries)
        assert validate_result.is_success

    def test_multiple_instances_independence(self) -> None:
        """Test that multiple FlextLdif instances work independently."""
        ldif1 = FlextLdif()
        ldif2 = FlextLdif()

        result1 = ldif1.parse(self._SIMPLE_LDIF)
        result2 = ldif2.parse(self._SIMPLE_LDIF)

        assert result1.is_success and result2.is_success

        entries1 = result1.unwrap()
        entries2 = result2.unwrap()

        assert len(entries1) == len(entries2) == 1
        assert entries1[0].dn.value == entries2[0].dn.value

    def test_filter_multiple_criteria_combined(self) -> None:
        """Test filtering with combined DN and attribute criteria."""
        ldif = FlextLdif()

        parse_result = ldif.parse(self._COMPLEX_LDIF)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        # Filter by DN pattern AND attributes
        result = ldif.filter(
            entries,
            dn_pattern="ou=Admins",
            attributes={Names.MAIL: None},  # Has mail attribute
        )
        assert result.is_success

        filtered = result.unwrap()
        assert len(filtered) == 2  # Both REDACTED_LDAP_BIND_PASSWORDs have mail

    def test_api_facade_property_access(self) -> None:
        """Test accessing facade properties and models."""
        ldif = FlextLdif()

        # Verify models accessibility
        models = ldif.models
        assert models is not None
        assert hasattr(models, "Entry")

        # Verify config accessibility
        config = ldif.config
        assert config is not None

    def test_end_to_end_workflow_complete(self) -> None:
        """Test complete end-to-end workflow from parse to filter."""
        ldif = FlextLdif()

        # Step 1: Parse
        parse_result = ldif.parse(self._SIMPLE_LDIF)
        assert parse_result.is_success
        entries = parse_result.unwrap()

        # Step 2: Analyze
        analyze_result = ldif.analyze(entries)
        assert analyze_result.is_success
        stats = analyze_result.unwrap()
        assert stats.total_entries == 1

        # Step 3: Validate
        validate_result = ldif.validate_entries(entries)
        assert validate_result.is_success

        # Step 4: Filter
        filter_result = ldif.filter(entries, objectclass=Names.PERSON)
        assert filter_result.is_success
        filtered = filter_result.unwrap()
        assert len(filtered) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
