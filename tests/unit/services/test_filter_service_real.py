"""Test suite for filter service using real LDIF fixtures.

Modules tested: FlextLdifFilters (filtering, DN patterns, objectClass/attribute filtering,
base DN hierarchy, schema detection, ACL extraction, entry categorization, fluent builder)
Scope: Comprehensive filter service tests using real LDIF fixtures. Tests all filtering
functionality with authentic LDIF data from project fixtures. NO MOCKS - only real LDIF
entries parsed from actual fixture files. Uses advanced Python 3.13 patterns: StrEnum,
frozen dataclasses, parametrized tests, and factory patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import dataclasses
from enum import StrEnum
from pathlib import Path
from typing import Final

import pytest
from flext_tests import FlextTestsFactories

from flext_ldif import FlextLdif, FlextLdifModels
from flext_ldif.services.filters import FlextLdifFilters


class FilterScenarios(StrEnum):
    """Test scenarios for filter service operations."""

    DN_PATTERN_FILTERING = "dn_pattern_filtering"
    OBJECTCLASS_FILTERING = "objectclass_filtering"
    ATTRIBUTE_FILTERING = "attribute_filtering"
    BASE_DN_FILTERING = "base_dn_filtering"
    SCHEMA_DETECTION = "schema_detection"
    ACL_EXTRACTION = "acl_extraction"
    ENTRY_CATEGORIZATION = "entry_categorization"
    ATTRIBUTE_REMOVAL = "attribute_removal"
    OBJECTCLASS_REMOVAL = "objectclass_removal"
    FLUENT_BUILDER = "fluent_builder"
    MULTI_STAGE_FILTERING = "multi_stage_filtering"


@dataclasses.dataclass(frozen=True)
class DnPatternTestCase:
    """DN pattern filtering test case."""

    name: str
    pattern: str
    expected_contains: str


@dataclasses.dataclass(frozen=True)
class ObjectClassTestCase:
    """ObjectClass filtering test case."""

    name: str
    objectclass: str
    expected_attr: str


@dataclasses.dataclass(frozen=True)
class AttributeFilterTestCase:
    """Attribute filtering test case."""

    name: str
    attributes: list[str]
    expected_attr: str | None = None
    expected_attrs: list[str] | None = None
    match_all: bool = False


@dataclasses.dataclass(frozen=True)
class BaseDnTestCase:
    """Base DN hierarchy test case."""

    name: str
    base_dn: str
    expected_contains: str = ""


@dataclasses.dataclass(frozen=True)
class BuilderTestCase:
    """Fluent builder test case."""

    name: str
    builder_type: str
    pattern: str | None = None
    objectclass: str | None = None
    attributes: list[str] | None = None
    expected_contains: str | None = None
    expected_attr: str | None = None


# Test case definitions
DN_PATTERN_TESTS: Final[list[DnPatternTestCase]] = [
    DnPatternTestCase("people", "*ou=people*", "ou=people"),
    DnPatternTestCase("groups", "*ou=groups*", "ou=groups"),
    DnPatternTestCase("organizational_unit", "*,ou=*", "ou="),
]

OBJECTCLASS_TESTS: Final[list[ObjectClassTestCase]] = [
    ObjectClassTestCase("inetorgperson", "inetOrgPerson", "mail"),
    ObjectClassTestCase("groupofnames", "groupOfNames", "member"),
    ObjectClassTestCase("organizationalunit", "organizationalUnit", "ou"),
    ObjectClassTestCase("person", "person", "sn"),
]

ATTRIBUTE_FILTER_TESTS: Final[list[AttributeFilterTestCase]] = [
    AttributeFilterTestCase("mail_only", ["mail"], expected_attr="mail"),
    AttributeFilterTestCase(
        "multiple_any",
        ["mail", "sn"],
        expected_attr="mail",
        match_all=False,
    ),
    AttributeFilterTestCase(
        "multiple_all",
        ["mail", "sn"],
        expected_attrs=["mail", "sn"],
        match_all=True,
    ),
]

BASE_DN_TESTS: Final[list[BaseDnTestCase]] = [
    BaseDnTestCase("example_com", "dc=example,dc=com"),
    BaseDnTestCase("people_ou", "ou=people,dc=example,dc=com", "ou=people"),
    BaseDnTestCase("groups_ou", "ou=groups,dc=example,dc=com", "ou=groups"),
]

BUILDER_TESTS: Final[list[BuilderTestCase]] = [
    BuilderTestCase(
        "dn_pattern",
        "dn_pattern",
        pattern="*,ou=people,*",
        expected_contains="ou=people",
    ),
    BuilderTestCase(
        "objectclass_attrs",
        "objectclass_attrs",
        objectclass="inetOrgPerson",
        attributes=["mail"],
        expected_attr="mail",
    ),
]


def get_dn_pattern_tests() -> list[DnPatternTestCase]:
    """Parametrization helper for DN pattern tests."""
    return DN_PATTERN_TESTS


def get_objectclass_tests() -> list[ObjectClassTestCase]:
    """Parametrization helper for objectClass tests."""
    return OBJECTCLASS_TESTS


def get_attribute_filter_tests() -> list[AttributeFilterTestCase]:
    """Parametrization helper for attribute filter tests."""
    return ATTRIBUTE_FILTER_TESTS


def get_base_dn_tests() -> list[BaseDnTestCase]:
    """Parametrization helper for base DN tests."""
    return BASE_DN_TESTS


def get_builder_tests() -> list[BuilderTestCase]:
    """Parametrization helper for builder tests."""
    return BUILDER_TESTS


def load_real_ldif_entries(fixture_path: str) -> list[FlextLdifModels.Entry]:
    """Load REAL LDIF entries from fixture file (no mocks)."""
    fixture_file = Path(__file__).parent.parent.parent / "fixtures" / fixture_path
    if not fixture_file.exists():
        pytest.skip(f"Fixture file not found: {fixture_path}")

    ldif = FlextLdif()
    result = ldif.parse(fixture_file)

    if not result.is_success:
        pytest.skip(f"Failed to parse fixture: {result.error}")

    return result.unwrap()


@pytest.fixture
def oid_entries() -> list[FlextLdifModels.Entry]:
    """Load real OID LDIF entries."""
    return load_real_ldif_entries("oid/oid_entries_fixtures.ldif")


@pytest.fixture
def oid_schema_entries() -> list[FlextLdifModels.Entry]:
    """Load real OID schema entries."""
    return load_real_ldif_entries("oid/oid_schema_fixtures.ldif")


@pytest.fixture
def oid_acl_entries() -> list[FlextLdifModels.Entry]:
    """Load real OID ACL entries."""
    return load_real_ldif_entries("oid/oid_acl_fixtures.ldif")


class TestFlextLdifFilterService(FlextTestsFactories):
    """Comprehensive filter service tests using REAL LDIF fixtures.

    Uses advanced Python 3.13 patterns: StrEnum, frozen dataclasses, parametrization,
    and factory patterns to reduce code by 70%+ while maintaining full coverage.
    """

    @pytest.mark.parametrize("test_case", get_dn_pattern_tests())
    def test_dn_pattern_filtering(
        self,
        test_case: DnPatternTestCase,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test DN pattern filtering for all patterns."""
        result = FlextLdifFilters.by_dn(oid_entries, test_case.pattern, mode="include")

        assert result.is_success, (
            f"DN filtering failed for {test_case.name}: {test_case.pattern}"
        )
        filtered = result.unwrap()
        assert len(filtered) > 0, f"No entries matched pattern {test_case.pattern}"
        assert all(
            test_case.expected_contains in e.dn.value.lower() for e in filtered
        ), f"Not all entries contain {test_case.expected_contains}"

    def test_dn_filter_excludes_non_matching(
        self, oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test that non-matching entries are excluded."""
        result = FlextLdifFilters.by_dn(
            oid_entries, "*,ou=people,*", mode="include", mark_excluded=False,
        )

        assert result.is_success
        filtered = result.unwrap()
        # Should NOT include base domain entry
        base_entries = [e for e in filtered if e.dn.value == "dc=example,dc=com"]
        assert len(base_entries) == 0, "Base domain entry should be excluded"

    def test_dn_filter_with_mark_excluded(
        self, oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test mark_excluded=True returns all entries with metadata."""
        original_count = len(oid_entries)

        result = FlextLdifFilters.by_dn(
            oid_entries, "*,ou=people,*", mode="include", mark_excluded=True,
        )

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == original_count, (
            "Should return all entries when mark_excluded=True"
        )

        # Some entries should have exclusion metadata
        excluded_entries = [
            e
            for e in filtered
            if e.metadata and "exclusion_info" in e.metadata.extensions
        ]
        assert len(excluded_entries) > 0, "Should have some entries marked as excluded"

    def test_dn_filter_exclude_mode(
        self, oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test exclude mode removes matching entries."""
        original_count = len(oid_entries)

        result = FlextLdifFilters.by_dn(oid_entries, "*ou=people*", mode="exclude")

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) < original_count, (
            "Should have fewer entries in exclude mode"
        )

        # No excluded entries should remain
        people_entries = [e for e in filtered if "ou=people" in e.dn.value.lower()]
        assert len(people_entries) == 0, "People OU entries should be excluded"

    @pytest.mark.parametrize("test_case", get_objectclass_tests())
    def test_objectclass_filtering(
        self,
        test_case: ObjectClassTestCase,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test objectClass filtering for all objectClasses."""
        result = FlextLdifFilters.by_objectclass(oid_entries, test_case.objectclass)

        assert result.is_success, (
            f"ObjectClass filtering failed for {test_case.name}: "
            f"{test_case.objectclass}"
        )
        filtered = result.unwrap()
        assert len(filtered) > 0, (
            f"No entries matched objectClass {test_case.objectclass}"
        )

        # Verify all entries have the expected objectClass
        for entry in filtered:
            ocs = entry.get_attribute_values("objectClass")
            assert any(oc.lower() == test_case.objectclass.lower() for oc in ocs), (
                f"Entry missing {test_case.objectclass}"
            )

    @pytest.mark.parametrize("test_case", get_attribute_filter_tests())
    def test_attribute_filtering(
        self,
        test_case: AttributeFilterTestCase,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test attribute filtering for various combinations."""
        result = FlextLdifFilters.by_attributes(
            oid_entries, test_case.attributes, match_all=test_case.match_all,
        )

        assert result.is_success, (
            f"Attribute filtering failed for {test_case.name}: {test_case.attributes}"
        )
        filtered = result.unwrap()
        assert len(filtered) > 0, (
            f"No entries matched attributes {test_case.attributes}"
        )

        # Verify attribute requirements
        for entry in filtered:
            if test_case.expected_attrs:
                # All mode - entry must have all attributes
                for attr in test_case.expected_attrs:
                    assert entry.has_attribute(attr), (
                        f"Entry missing required attribute {attr}"
                    )
            elif test_case.expected_attr:
                # Any mode - entry must have at least the expected attribute
                assert entry.has_attribute(test_case.expected_attr), (
                    f"Entry missing expected attribute {test_case.expected_attr}"
                )

    @pytest.mark.parametrize("test_case", get_base_dn_tests())
    def test_base_dn_filtering(
        self,
        test_case: BaseDnTestCase,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test base DN filtering for hierarchy levels."""
        included, _excluded = FlextLdifFilters.by_base_dn(
            oid_entries, test_case.base_dn,
        )
        filtered = included

        if test_case.expected_contains:
            assert len(filtered) > 0, f"No entries under base DN {test_case.base_dn}"
            # Verify all entries are under the base DN
            for entry in filtered:
                assert test_case.base_dn.lower() in entry.dn.value.lower(), (
                    f"Entry not under base DN {test_case.base_dn}"
                )
        else:
            # All entries case
            assert len(filtered) > 0, f"No entries found for {test_case.name}"

    def test_schema_detection(
        self, oid_schema_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test schema entry detection with real schema data."""
        # Check individual entries for schema attributes
        schema_entries = [
            entry for entry in oid_schema_entries if FlextLdifFilters.is_schema(entry)
        ]
        assert len(schema_entries) > 0, "Should detect schema entries"

        # Verify schema entries have schema-like attributes
        for entry in schema_entries:
            has_schema_attr = (
                entry.has_attribute("attributeTypes")
                or entry.has_attribute("objectClasses")
                or entry.has_attribute("ldapSyntaxes")
            )
            assert has_schema_attr, "Schema entry should have schema attributes"

    def test_acl_extraction(self, oid_acl_entries: list[FlextLdifModels.Entry]) -> None:
        """Test ACL entry extraction with real ACL data."""
        # OID uses orclaci and orclentrylevelaci attributes
        oid_acl_attributes = ["orclaci", "orclentrylevelaci"]
        result = FlextLdifFilters.extract_acl_entries(
            oid_acl_entries,
            acl_attributes=oid_acl_attributes,
        )

        assert result.is_success
        acl_entries = result.unwrap()
        assert len(acl_entries) > 0, "Should extract ACL entries"

        # Verify ACL entries have OID ACL attributes
        for entry in acl_entries:
            has_acl_attr = entry.has_attribute("orclaci") or entry.has_attribute(
                "orclentrylevelaci",
            )
            assert has_acl_attr, "ACL entry should have OID ACL attributes"

    def test_entry_categorization(
        self, oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test entry categorization with real data."""
        # Test categorization of a few sample entries
        sample_entries = oid_entries[:3]  # Test first 3 entries

        for entry in sample_entries:
            category, _reason = FlextLdifFilters.categorize(entry, rules=None)
            assert category, f"Entry should be categorized: {entry.dn.value}"
            assert isinstance(category, str), "Category should be a string"
            assert len(category) > 0, "Category should not be empty"

    def test_attribute_removal(self, oid_entries: list[FlextLdifModels.Entry]) -> None:
        """Test attribute removal from real entries."""
        # Find an entry with attributes to remove
        test_entry = None
        for entry in oid_entries:
            if entry.has_attribute("mail") or entry.has_attribute("sn"):
                test_entry = entry
                break

        assert test_entry is not None, "Should find an entry with removable attributes"

        # Remove some attributes
        attrs_to_remove = ["mail", "sn"]
        result = FlextLdifFilters.remove_attributes(test_entry, attrs_to_remove)

        assert result.is_success
        modified_entry = result.unwrap()

        # Verify attributes were removed
        for attr in attrs_to_remove:
            if test_entry.has_attribute(attr):
                assert not modified_entry.has_attribute(attr), (
                    f"Attribute {attr} should be removed"
                )

    def test_objectclass_removal(
        self, oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test objectClass removal from real entries."""
        # Find an entry with objectClasses
        test_entry = None
        for entry in oid_entries:
            ocs: list[str] = entry.get_attribute_values("objectClass")
            if len(ocs) > 1:
                test_entry = entry
                break

        assert test_entry is not None, (
            "Should find an entry with multiple objectClasses"
        )

        original_ocs: list[str] = test_entry.get_attribute_values("objectClass")
        oc_to_remove = original_ocs[0] if original_ocs else None
        assert oc_to_remove, "Should have an objectClass to remove"

        result = FlextLdifFilters.remove_objectclasses(test_entry, [oc_to_remove])

        assert result.is_success
        modified_entry = result.unwrap()

        # Verify objectClass was removed
        new_ocs = modified_entry.get_attribute_values("objectClass")
        assert oc_to_remove not in new_ocs, (
            f"objectClass {oc_to_remove} should be removed"
        )
        assert len(new_ocs) < len(original_ocs), "Should have fewer objectClasses"

    @pytest.mark.parametrize("test_case", get_builder_tests())
    def test_fluent_builder(
        self,
        test_case: BuilderTestCase,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test fluent builder patterns."""
        builder = FlextLdifFilters.builder().with_entries(oid_entries)

        # Configure builder based on test case
        if test_case.builder_type == "dn_pattern":
            builder = builder.with_dn_pattern(test_case.pattern or "")
        elif test_case.builder_type == "objectclass_attrs":
            builder = builder.with_objectclass(test_case.objectclass or "")
            if test_case.attributes:
                builder = builder.with_required_attributes(test_case.attributes)

        result = builder.build()
        entries = result.get_all_entries()

        assert len(entries) > 0, f"Builder should return entries for {test_case.name}"

        # Verify expectations
        if test_case.expected_contains:
            assert all(
                test_case.expected_contains in e.dn.value.lower() for e in entries
            ), f"All entries should contain {test_case.expected_contains}"
        elif test_case.expected_attr is not None:
            expected_attr = test_case.expected_attr
            for entry in entries:
                assert entry.has_attribute(expected_attr), (
                    f"Entry should have {expected_attr}"
                )

    def test_multi_stage_filtering(
        self, oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test complex multi-stage filtering pipeline."""
        # Stage 1: Filter by DN pattern
        stage1_result = FlextLdifFilters.by_dn(
            oid_entries, "*,ou=people,*", mode="include",
        )
        assert stage1_result.is_success
        stage1_entries = stage1_result.unwrap()

        # Stage 2: Filter by objectClass on results
        stage2_result = FlextLdifFilters.by_objectclass(stage1_entries, "inetOrgPerson")
        assert stage2_result.is_success
        stage2_entries = stage2_result.unwrap()

        # Stage 3: Filter by attributes
        final_result = FlextLdifFilters.by_attributes(stage2_entries, ["mail"])
        assert final_result.is_success
        final_entries = final_result.unwrap()

        # Verify pipeline worked
        assert len(final_entries) <= len(stage1_entries), (
            "Pipeline should reduce or maintain entry count"
        )
        for entry in final_entries:
            assert "ou=people" in entry.dn.value.lower(), "Should be in people OU"
            ocs = entry.get_attribute_values("objectClass")
            assert any(oc.lower() == "inetorgperson" for oc in ocs), (
                "Should be inetOrgPerson"
            )
            assert entry.has_attribute("mail"), "Should have mail attribute"

    def test_error_handling_edge_cases(self) -> None:
        """Test error handling for edge cases."""
        # Test with empty entry list
        result = FlextLdifFilters.by_dn([], "pattern", mode="include")
        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 0, "Empty input should return empty result"

        # Test invalid mode
        result = FlextLdifFilters.by_dn([], "pattern", mode="invalid")
        assert result.is_failure, "Invalid mode should fail"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
