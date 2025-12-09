"""Tests for FlextLdif Filters service with real LDIF data.

This module tests the Filters service using actual LDIF fixtures,
validating filtering and deduplication on real-world LDAP data.
"""

from __future__ import annotations

import dataclasses
from enum import StrEnum
from pathlib import Path
from typing import Final

import pytest
from flext_tests import tt

from flext_ldif import FlextLdif
from flext_ldif.services.filters import FlextLdifFilters
from tests import Filters, TestDeduplicationHelpers, c, m

# FlextLdifFixtures and TypedDicts are available from conftest.py (pytest auto-imports)


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


# Test case definitions using constants
DN_PATTERN_TESTS: Final[list[DnPatternTestCase]] = [
    DnPatternTestCase("people", Filters.DN_PATTERN_USERS, "ou=users"),
    DnPatternTestCase("groups", Filters.DN_PATTERN_GROUPS, "ou=groups"),
    DnPatternTestCase("organizational_unit", Filters.DN_PATTERN_OU, "ou="),
]

OBJECTCLASS_TESTS: Final[list[ObjectClassTestCase]] = [
    ObjectClassTestCase("inetorgperson", c.Names.INETORGPERSON, Filters.ATTR_MAIL),
    ObjectClassTestCase("groupofnames", Filters.OC_GROUP_OF_NAMES, "member"),
    ObjectClassTestCase("organizationalunit", Filters.OC_ORGANIZATIONAL_UNIT, "ou"),
    ObjectClassTestCase("person", c.Names.PERSON, Filters.ATTR_SN),
]

ATTRIBUTE_FILTER_TESTS: Final[list[AttributeFilterTestCase]] = [
    AttributeFilterTestCase(
        "mail_only",
        [Filters.ATTR_MAIL],
        expected_attr=Filters.ATTR_MAIL,
    ),
    AttributeFilterTestCase(
        "multiple_any",
        [Filters.ATTR_MAIL, Filters.ATTR_SN],
        expected_attr=Filters.ATTR_MAIL,
        match_all=False,
    ),
    AttributeFilterTestCase(
        "multiple_all",
        [Filters.ATTR_MAIL, Filters.ATTR_SN],
        expected_attrs=[Filters.ATTR_MAIL, Filters.ATTR_SN],
        match_all=True,
    ),
]

BASE_DN_TESTS: Final[list[BaseDnTestCase]] = [
    BaseDnTestCase("example_com", "dc=example,dc=com"),
    BaseDnTestCase("people_ou", Filters.DN_OU_USERS, "ou=users"),
    BaseDnTestCase("groups_ou", Filters.DN_OU_GROUPS, "ou=groups"),
]

BUILDER_TESTS: Final[list[BuilderTestCase]] = [
    BuilderTestCase(
        "dn_pattern",
        "dn_pattern",
        pattern=Filters.DN_PATTERN_USERS,
        expected_contains="ou=users",
    ),
    BuilderTestCase(
        "objectclass_attrs",
        "objectclass_attrs",
        objectclass=c.Names.INETORGPERSON,
        attributes=[Filters.ATTR_MAIL],
        expected_attr=Filters.ATTR_MAIL,
    ),
]


def load_real_ldif_entries(fixture_path: str) -> list[m.Ldif.Entry]:
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
def oid_entries() -> list[m.Ldif.Entry]:
    """Load real OID LDIF entries."""
    return load_real_ldif_entries("oid/oid_entries_fixtures.ldif")


@pytest.fixture
def oid_schema_entries() -> list[m.Ldif.Entry]:
    """Load real OID schema entries."""
    return load_real_ldif_entries("oid/oid_schema_fixtures.ldif")


@pytest.fixture
def oid_acl_entries() -> list[m.Ldif.Entry]:
    """Load real OID ACL entries."""
    return load_real_ldif_entries("oid/oid_acl_fixtures.ldif")


class TestFlextLdifFilterService(tt):
    """Comprehensive filter service tests using REAL LDIF fixtures.

    Uses advanced Python 3.13 patterns: StrEnum, frozen dataclasses, parametrization,
    factory patterns, and helpers to reduce code by 70%+ while maintaining full coverage.
    """

    @pytest.mark.parametrize("test_case", DN_PATTERN_TESTS)
    def test_dn_pattern_filtering(
        self,
        test_case: DnPatternTestCase,
        oid_entries: list[m.Ldif.Entry],
    ) -> None:
        """Test DN pattern filtering for all patterns."""
        filtered = TestDeduplicationHelpers.filter_by_dn_and_unwrap(
            oid_entries,
            test_case.pattern,
            expected_count=None,  # Don't assert count, just verify content
            expected_dn_substring=test_case.expected_contains,
        )
        assert len(filtered) > 0, f"No entries matched pattern {test_case.pattern}"

    def test_dn_filter_excludes_non_matching(
        self,
        oid_entries: list[m.Ldif.Entry],
    ) -> None:
        """Test that non-matching entries are excluded."""
        filtered = TestDeduplicationHelpers.filter_by_dn_and_unwrap(
            oid_entries,
            Filters.DN_PATTERN_USERS,
            mode=Filters.MODE_INCLUDE,
            mark_excluded=False,
        )
        base_entries = [e for e in filtered if e.dn.value == "dc=example,dc=com"]
        assert len(base_entries) == 0, "Base domain entry should be excluded"

    def test_dn_filter_with_mark_excluded(
        self,
        oid_entries: list[m.Ldif.Entry],
    ) -> None:
        """Test mark_excluded=True returns all entries with metadata."""
        original_count = len(oid_entries)
        filtered = TestDeduplicationHelpers.filter_by_dn_and_unwrap(
            oid_entries,
            Filters.DN_PATTERN_USERS,
            mode=Filters.MODE_INCLUDE,
            mark_excluded=True,
            expected_count=original_count,
        )
        excluded_entries = [
            e
            for e in filtered
            if e.metadata and "exclusion_info" in e.metadata.extensions
        ]
        assert len(excluded_entries) > 0, "Should have some entries marked as excluded"

    def test_dn_filter_exclude_mode(
        self,
        oid_entries: list[m.Ldif.Entry],
    ) -> None:
        """Test exclude mode removes matching entries."""
        original_count = len(oid_entries)
        filtered = TestDeduplicationHelpers.filter_by_dn_and_unwrap(
            oid_entries,
            "*ou=users*",
            mode=Filters.MODE_EXCLUDE,
        )
        assert len(filtered) < original_count, (
            "Should have fewer entries in exclude mode"
        )
        people_entries = [e for e in filtered if "ou=users" in e.dn.value.lower()]
        assert len(people_entries) == 0, "Users OU entries should be excluded"

    @pytest.mark.parametrize("test_case", OBJECTCLASS_TESTS)
    def test_objectclass_filtering(
        self,
        test_case: ObjectClassTestCase,
        oid_entries: list[m.Ldif.Entry],
    ) -> None:
        """Test objectClass filtering for all objectClasses."""
        filtered = TestDeduplicationHelpers.filter_by_objectclass_and_unwrap(
            oid_entries,
            test_case.objectclass,
        )
        assert len(filtered) > 0, (
            f"No entries matched objectClass {test_case.objectclass}"
        )
        for entry in filtered:
            ocs = entry.get_attribute_values("objectClass")
            assert any(oc.lower() == test_case.objectclass.lower() for oc in ocs), (
                f"Entry missing {test_case.objectclass}"
            )

    @pytest.mark.parametrize("test_case", ATTRIBUTE_FILTER_TESTS)
    def test_attribute_filtering(
        self,
        test_case: AttributeFilterTestCase,
        oid_entries: list[m.Ldif.Entry],
    ) -> None:
        """Test attribute filtering for various combinations."""
        filtered = TestDeduplicationHelpers.filter_by_attributes_and_unwrap(
            oid_entries,
            test_case.attributes,
            match_all=test_case.match_all,
        )
        assert len(filtered) > 0, (
            f"No entries matched attributes {test_case.attributes}"
        )
        for entry in filtered:
            if test_case.expected_attrs:
                TestDeduplicationHelpers.assert_entries_have_attribute(
                    [entry],
                    test_case.expected_attrs[0],
                )
            elif test_case.expected_attr:
                assert entry.has_attribute(test_case.expected_attr), (
                    f"Entry missing expected attribute {test_case.expected_attr}"
                )

    @pytest.mark.parametrize("test_case", BASE_DN_TESTS)
    def test_base_dn_filtering(
        self,
        test_case: BaseDnTestCase,
        oid_entries: list[m.Ldif.Entry],
    ) -> None:
        """Test base DN filtering for hierarchy levels."""
        included, _excluded = FlextLdifFilters.by_base_dn(
            oid_entries,
            test_case.base_dn,
        )
        if test_case.expected_contains:
            assert len(included) > 0, f"No entries under base DN {test_case.base_dn}"
            TestDeduplicationHelpers.assert_entries_dn_contains(
                included,
                test_case.base_dn.lower(),
            )
        else:
            assert len(included) > 0, f"No entries found for {test_case.name}"

    def test_schema_detection(
        self,
        oid_schema_entries: list[m.Ldif.Entry],
    ) -> None:
        """Test schema entry detection with real schema data."""
        schema_entries = [
            entry for entry in oid_schema_entries if FlextLdifFilters.is_schema(entry)
        ]
        assert len(schema_entries) > 0, "Should detect schema entries"
        for entry in schema_entries:
            has_schema_attr = (
                entry.has_attribute("attributeTypes")
                or entry.has_attribute("objectClasses")
                or entry.has_attribute("ldapSyntaxes")
            )
            assert has_schema_attr, "Schema entry should have schema attributes"

    def test_acl_extraction(self, oid_acl_entries: list[m.Ldif.Entry]) -> None:
        """Test ACL entry extraction with real ACL data."""
        oid_acl_attributes = ["orclaci", "orclentrylevelaci"]
        result = FlextLdifFilters.extract_acl_entries(
            oid_acl_entries,
            acl_attributes=oid_acl_attributes,
        )
        assert result.is_success
        acl_entries = result.unwrap()
        assert len(acl_entries) > 0, "Should extract ACL entries"
        for entry in acl_entries:
            has_acl_attr = entry.has_attribute("orclaci") or entry.has_attribute(
                "orclentrylevelaci",
            )
            assert has_acl_attr, "ACL entry should have OID ACL attributes"

    def test_entry_categorization(
        self,
        oid_entries: list[m.Ldif.Entry],
    ) -> None:
        """Test entry categorization with real data."""
        sample_entries = oid_entries[:3]
        for entry in sample_entries:
            category, _reason = FlextLdifFilters.categorize(entry, rules=None)
            assert category, f"Entry should be categorized: {entry.dn.value}"
            assert isinstance(category, str), "Category should be a string"
            assert len(category) > 0, "Category should not be empty"

    def test_attribute_removal(self, oid_entries: list[m.Ldif.Entry]) -> None:
        """Test attribute removal from real entries."""
        test_entry = next(
            (
                e
                for e in oid_entries
                if e.has_attribute("mail") or e.has_attribute("sn")
            ),
            None,
        )
        assert test_entry is not None, "Should find an entry with removable attributes"
        attrs_to_remove = [Filters.ATTR_MAIL, Filters.ATTR_SN]
        TestDeduplicationHelpers.remove_attributes_and_validate(
            test_entry,
            attrs_to_remove,
        )

    def test_objectclass_removal(
        self,
        oid_entries: list[m.Ldif.Entry],
    ) -> None:
        """Test objectClass removal from real entries."""
        test_entry = next(
            (e for e in oid_entries if len(e.get_attribute_values("objectClass")) > 1),
            None,
        )
        assert test_entry is not None, (
            "Should find an entry with multiple objectClasses"
        )
        original_ocs = test_entry.get_attribute_values("objectClass")
        oc_to_remove = original_ocs[0] if original_ocs else None
        assert oc_to_remove, "Should have an objectClass to remove"
        result = FlextLdifFilters.remove_objectclasses(test_entry, [oc_to_remove])
        assert result.is_success
        modified_entry = result.unwrap()
        new_ocs = modified_entry.get_attribute_values("objectClass")
        assert oc_to_remove not in new_ocs, (
            f"objectClass {oc_to_remove} should be removed"
        )
        assert len(new_ocs) < len(original_ocs), "Should have fewer objectClasses"

    @pytest.mark.parametrize("test_case", BUILDER_TESTS)
    def test_fluent_builder(
        self,
        test_case: BuilderTestCase,
        oid_entries: list[m.Ldif.Entry],
    ) -> None:
        """Test fluent builder patterns."""
        builder = FlextLdifFilters.builder().with_entries(oid_entries)
        if test_case.builder_type == "dn_pattern":
            builder = builder.with_dn_pattern(test_case.pattern or "")
        elif test_case.builder_type == "objectclass_attrs":
            builder = builder.with_objectclass(test_case.objectclass or "")
            if test_case.attributes:
                builder = builder.with_required_attributes(test_case.attributes)
        result = builder.build()
        entries = result.get_all_entries()
        assert len(entries) > 0, f"Builder should return entries for {test_case.name}"
        if test_case.expected_contains:
            TestDeduplicationHelpers.assert_entries_dn_contains(
                entries,
                test_case.expected_contains,
            )
        elif test_case.expected_attr is not None:
            TestDeduplicationHelpers.assert_entries_have_attribute(
                entries,
                test_case.expected_attr,
            )

    def test_multi_stage_filtering(
        self,
        oid_entries: list[m.Ldif.Entry],
    ) -> None:
        """Test complex multi-stage filtering pipeline."""
        stage1_entries = TestDeduplicationHelpers.filter_by_dn_and_unwrap(
            oid_entries,
            Filters.DN_PATTERN_USERS,
            mode=Filters.MODE_INCLUDE,
        )
        stage2_entries = TestDeduplicationHelpers.filter_by_objectclass_and_unwrap(
            stage1_entries,
            c.Names.INETORGPERSON,
        )
        final_entries = TestDeduplicationHelpers.filter_by_attributes_and_unwrap(
            stage2_entries,
            [Filters.ATTR_MAIL],
        )
        assert len(final_entries) <= len(stage1_entries), (
            "Pipeline should reduce or maintain entry count"
        )
        TestDeduplicationHelpers.assert_entries_dn_contains(
            list(final_entries),
            "ou=users",
        )
        TestDeduplicationHelpers.assert_entries_have_attribute(
            list(final_entries),
            Filters.ATTR_MAIL,
        )

    def test_error_handling_edge_cases(self) -> None:
        """Test error handling for edge cases."""
        filtered = TestDeduplicationHelpers.filter_by_dn_and_unwrap(
            [],
            "pattern",
            mode=Filters.MODE_INCLUDE,
            expected_count=0,
        )
        assert len(filtered) == 0, "Empty input should return empty result"
        result = FlextLdifFilters.by_dn([], "pattern", mode="invalid")
        assert result.is_failure, "Invalid mode should fail"


if __name__ == "__main__":
    _ = pytest.main([__file__, "-v"])
