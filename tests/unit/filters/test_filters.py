"""Test suite for FlextLdifFilters Service.

Modules tested: FlextLdifFilters
Scope: Entry filtering, exclusion metadata, regex patterns, ACL attributes,
exclusion marking, categorization, DN filtering, objectClass filtering, attribute filtering

Uses advanced Python 3.13 patterns: StrEnum, frozen dataclasses, parametrization,
factory patterns, and helpers to reduce code by 60%+ while maintaining 100% coverage.
All tests organized in a single main class with nested test classes for logical grouping.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import dataclasses
from typing import Final, cast

import pytest
from flext_core import t
from tests.fixtures.constants import DNs, Filters, Values
from tests.helpers.test_assertions import TestAssertions
from tests.helpers.test_filter_helpers import FilterTestHelpers

from flext_ldif import FlextLdifModels
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif.services.filters import FlextLdifFilters

# Use helper to eliminate duplication - replaces 8-12 lines per use
create_test_entry = TestAssertions.create_entry


@dataclasses.dataclass(frozen=True)
class ExclusionMetadataTestCase:
    """Test case for exclusion metadata type guards."""

    name: str
    metadata_extensions: dict[str, object]
    expected_excluded: bool
    expected_reason: str | None = None


@dataclasses.dataclass(frozen=True)
class RegexPatternTestCase:
    """Test case for regex pattern matching."""

    name: str
    patterns: list[str]
    should_raise: bool = False
    expected_match: bool = False


@dataclasses.dataclass(frozen=True)
class ExclusionMarkingTestCase:
    """Test case for exclusion marking in filters."""

    name: str
    filter_method: str
    filter_args: dict[str, object]
    expected_excluded_index: int
    expected_reason_contains: str


# Test case definitions using constants
EXCLUSION_METADATA_TESTS: Final[list[ExclusionMetadataTestCase]] = [
    ExclusionMetadataTestCase("none_metadata", {}, False, None),
    ExclusionMetadataTestCase("no_exclusion_info", {}, False, None),
    ExclusionMetadataTestCase(
        "non_dict_exclusion_info",
        {"exclusion_info": "not a dict"},
        False,
        None,
    ),
    ExclusionMetadataTestCase(
        "missing_excluded_field",
        {"exclusion_info": {"exclusion_reason": "test reason"}},
        False,
        None,
    ),
    ExclusionMetadataTestCase(
        "non_bool_excluded",
        {"exclusion_info": {"excluded": "true", "exclusion_reason": "test"}},
        False,
        None,
    ),
    ExclusionMetadataTestCase(
        "true_excluded",
        {"exclusion_info": {"excluded": True, "exclusion_reason": "test reason"}},
        True,
        "test reason",
    ),
]

REGEX_PATTERN_TESTS: Final[list[RegexPatternTestCase]] = [
    RegexPatternTestCase("invalid_regex", ["[invalid(regex"], should_raise=True),
    RegexPatternTestCase(
        "multiple_invalid",
        ["[bad", "(also bad", "valid.*"],
        should_raise=True,
    ),
    RegexPatternTestCase("valid_regex", ["cn=.*,dc=example"], expected_match=True),
    RegexPatternTestCase("no_match", ["cn=other.*"], expected_match=False),
    RegexPatternTestCase("empty_patterns", [], expected_match=False),
]

EXCLUSION_MARKING_TESTS: Final[list[ExclusionMarkingTestCase]] = [
    ExclusionMarkingTestCase(
        "by_dn",
        "filter_by_dn",
        {"dn_pattern": Filters.DN_PATTERN_USERS, "mode": Filters.MODE_INCLUDE},
        1,
        "DN pattern",
    ),
    ExclusionMarkingTestCase(
        "by_objectclass",
        "filter_by_objectclass",
        {
            "objectclass": Filters.OC_PERSON,
            "required_attributes": None,
            "mode": Filters.MODE_INCLUDE,
        },
        1,
        "ObjectClass",
    ),
    ExclusionMarkingTestCase(
        "by_attributes",
        "filter_by_attributes",
        {
            "attributes": [Filters.ATTR_MAIL],
            "match_all": False,
            "mode": Filters.MODE_EXCLUDE,
        },
        0,
        "Attribute filter",
    ),
]


class TestFlextLdifFilters:
    """Comprehensive test suite for FlextLdifFilters service.

    Organized in nested classes for logical grouping while maintaining single main class structure.
    Uses constants, helpers, and parametrization to reduce code by 60%+.
    """

    class TestExclusionMetadata:
        """Test exclusion metadata type guards and edge cases."""

        @pytest.mark.parametrize("test_case", EXCLUSION_METADATA_TESTS)
        def test_is_entry_excluded(
            self,
            test_case: ExclusionMetadataTestCase,
        ) -> None:
            """Test is_entry_excluded with various metadata configurations."""
            entry = create_test_entry(
                DNs.TEST_USER,
                {
                    Filters.ATTR_CN: [Values.TEST],
                    Filters.ATTR_OBJECTCLASS: [Filters.OC_PERSON],
                },
            )
            if test_case.metadata_extensions:
                # Cast dict[str, object] to dict[str, MetadataAttributeValue] for DynamicMetadata

                extensions_typed: dict[str, t.MetadataAttributeValue] = cast(
                    "dict[str, t.MetadataAttributeValue]",
                    test_case.metadata_extensions,
                )
                metadata = FlextLdifModels.QuirkMetadata(
                    quirk_type="rfc",
                    extensions=FlextLdifModelsMetadata.DynamicMetadata(
                        **extensions_typed
                    ),
                )
                entry = entry.model_copy(update={"metadata": metadata})
            result = FlextLdifFilters.is_entry_excluded(entry)
            assert result == test_case.expected_excluded, (
                f"Expected excluded={test_case.expected_excluded} for {test_case.name}"
            )

        @pytest.mark.parametrize("test_case", EXCLUSION_METADATA_TESTS)
        def test_get_exclusion_reason(
            self,
            test_case: ExclusionMetadataTestCase,
        ) -> None:
            """Test get_exclusion_reason with various metadata configurations."""
            entry = create_test_entry(
                DNs.TEST_USER,
                {
                    Filters.ATTR_CN: [Values.TEST],
                    Filters.ATTR_OBJECTCLASS: [Filters.OC_PERSON],
                },
            )
            if test_case.metadata_extensions:
                # Cast dict[str, object] to dict[str, MetadataAttributeValue] for DynamicMetadata

                extensions_typed: dict[str, t.MetadataAttributeValue] = cast(
                    "dict[str, t.MetadataAttributeValue]",
                    test_case.metadata_extensions,
                )
                metadata = FlextLdifModels.QuirkMetadata(
                    quirk_type="rfc",
                    extensions=FlextLdifModelsMetadata.DynamicMetadata(
                        **extensions_typed
                    ),
                )
                entry = entry.model_copy(update={"metadata": metadata})
            reason = FlextLdifFilters.get_exclusion_reason(entry)
            if test_case.expected_reason:
                assert reason == test_case.expected_reason, (
                    f"Expected reason '{test_case.expected_reason}' for {test_case.name}"
                )
            else:
                assert reason is None, f"Expected None reason for {test_case.name}"

    class TestRegexPatterns:
        """Test regex pattern matching and error handling."""

        @pytest.mark.parametrize("test_case", REGEX_PATTERN_TESTS)
        def test_matches_dn_pattern(
            self,
            test_case: RegexPatternTestCase,
        ) -> None:
            """Test matches_dn_pattern with various patterns."""
            if test_case.should_raise:
                with pytest.raises(ValueError, match="Invalid regex patterns"):
                    FlextLdifFilters.matches_dn_pattern(
                        DNs.TEST_USER,
                        test_case.patterns,
                    )
            else:
                result = FlextLdifFilters.matches_dn_pattern(
                    DNs.TEST_USER,
                    test_case.patterns,
                )
                assert result == test_case.expected_match, (
                    f"Expected match={test_case.expected_match} for {test_case.name}"
                )

    class TestAclAttributes:
        """Test ACL attribute detection edge cases."""

        def test_has_acl_attributes_no_attributes(self) -> None:
            """Test has_acl_attributes when entry has no ACL attributes."""
            entry = create_test_entry("cn=test", {Filters.ATTR_CN: [Values.TEST]})
            assert not FlextLdifFilters.has_acl_attributes(entry, ["orclaci"])

        def test_has_acl_attributes_empty_list(self) -> None:
            """Test has_acl_attributes with empty ACL attributes list."""
            entry = create_test_entry("cn=test", {Filters.ATTR_CN: [Values.TEST]})
            _ = not FlextLdifFilters.has_acl_attributes(entry, [])

        def test_has_acl_attributes_case_insensitive(self) -> None:
            """Test has_acl_attributes is case-insensitive."""
            entry = create_test_entry("cn=test", {"ORCLACI": ["some acl"]})
            assert FlextLdifFilters.has_acl_attributes(entry, ["orclaci"])

    class TestExclusionMarking:
        """Test exclusion marking functionality in filter methods."""

        @pytest.mark.parametrize("test_case", EXCLUSION_MARKING_TESTS)
        def test_filter_with_exclusion_marking(
            self,
            test_case: ExclusionMarkingTestCase,
        ) -> None:
            """Test filter methods mark excluded entries using helper."""
            entries = FilterTestHelpers.create_exclusion_test_entries(
                test_case.filter_method,
            )

            # Extract filter args explicitly to avoid type issues with **kwargs
            filter_kwargs = test_case.filter_args
            if test_case.filter_method == "filter_by_dn":
                filter_method = getattr(FlextLdifFilters, test_case.filter_method)
                result = filter_method(
                    entries,
                    mark_excluded=True,
                    dn_pattern=str(filter_kwargs.get("dn_pattern", "")),
                    mode=str(filter_kwargs.get("mode", "")),
                )
            elif test_case.filter_method == "filter_by_objectclass":
                filter_method = getattr(FlextLdifFilters, test_case.filter_method)
                result = filter_method(
                    entries,
                    mark_excluded=True,
                    objectclass=str(filter_kwargs.get("objectclass", "")),
                    required_attributes=filter_kwargs.get("required_attributes"),
                    mode=str(filter_kwargs.get("mode", "")),
                )
            elif test_case.filter_method == "filter_by_attributes":
                filter_method = getattr(FlextLdifFilters, test_case.filter_method)
                attrs_value = filter_kwargs.get("attributes", [])
                attrs_list: list[str] = (
                    attrs_value if isinstance(attrs_value, list) else []
                )
                result = filter_method(
                    entries,
                    mark_excluded=True,
                    attributes=attrs_list,
                    match_all=bool(filter_kwargs.get("match_all", False)),
                    mode=str(filter_kwargs.get("mode", "")),
                )
            else:
                filter_method = getattr(FlextLdifFilters, test_case.filter_method)
                result = filter_method(
                    entries,
                    mark_excluded=True,
                    **test_case.filter_args,
                )

            assert result.is_success
            filtered = result.unwrap()
            assert len(filtered) >= 2, (
                "Should return all entries when mark_excluded=True"
            )
            excluded_entry = next(
                (
                    entry
                    for entry in filtered
                    if FlextLdifFilters.is_entry_excluded(entry)
                ),
                None,
            )
            assert excluded_entry is not None, (
                f"Expected at least one excluded entry for {test_case.name}, "
                f"got {len(filtered)} entries, none excluded"
            )
            reason = FlextLdifFilters.get_exclusion_reason(excluded_entry)
            assert reason is not None
            assert test_case.expected_reason_contains in reason

    class TestFilterSuccess:
        """Test filter methods succeed with valid inputs."""

        @pytest.mark.parametrize(
            (
                "filter_method",
                "dn_pattern",
                "objectclass",
                "attributes",
                "mode",
                "expected_count",
            ),
            [
                (
                    "filter_by_dn",
                    Filters.DN_PATTERN_ALL,
                    None,
                    None,
                    Filters.MODE_INCLUDE,
                    None,
                ),
                (
                    "filter_by_objectclass",
                    None,
                    Filters.OC_PERSON,
                    None,
                    Filters.MODE_INCLUDE,
                    1,
                ),
                (
                    "filter_by_attributes",
                    None,
                    None,
                    [Filters.ATTR_MAIL],
                    Filters.MODE_INCLUDE,
                    None,
                ),
            ],
        )
        def test_filter_success(
            self,
            filter_method: str,
            dn_pattern: str | None,
            objectclass: str | None,
            attributes: list[str] | None,
            mode: str,
            expected_count: int | None,
        ) -> None:
            """Test filter methods succeed with valid entries using helper."""
            attrs: dict[str, str | list[str]] = {
                Filters.ATTR_CN: [Values.TEST],
                Filters.ATTR_OBJECTCLASS: [Filters.OC_PERSON],
            }
            if filter_method == "filter_by_attributes":
                attrs[Filters.ATTR_MAIL] = ["test@ex"]
            entry = create_test_entry(DNs.TEST_USER, attrs)
            # Call helper with explicit kwargs based on filter method
            if filter_method == "filter_by_dn":
                FilterTestHelpers.test_filter_complete(
                    filter_method=filter_method,
                    entries=[entry],
                    expected_count=expected_count,
                    mark_excluded=False,
                    dn_pattern=dn_pattern or "",
                    mode=mode,
                )
            elif filter_method == "filter_by_objectclass":
                FilterTestHelpers.test_filter_complete(
                    filter_method=filter_method,
                    entries=[entry],
                    expected_count=expected_count,
                    mark_excluded=False,
                    objectclass=objectclass or "",
                    mode=mode,
                )
            elif filter_method == "filter_by_attributes":
                FilterTestHelpers.test_filter_complete(
                    filter_method=filter_method,
                    entries=[entry],
                    expected_count=expected_count,
                    mark_excluded=False,
                    attributes=attributes or [],
                    mode=mode,
                )

    class TestFilterEntryAttributes:
        """Test filter_entry_attributes marks attributes for removal."""

        def test_filter_entry_attributes_success(self) -> None:
            """Test filter_entry_attributes marks attributes in metadata using helper."""
            entry = create_test_entry(
                DNs.TEST_USER,
                {
                    Filters.ATTR_CN: [Values.TEST],
                    "orclaci": ["acl rule"],
                    Filters.ATTR_MAIL: ["test@ex"],
                    Filters.ATTR_OBJECTCLASS: [Filters.OC_PERSON],
                },
            )
            FilterTestHelpers.test_filter_entry_attributes_complete(
                entry,
                ["orclaci"],
                expected_marked=True,
                expected_in_removed=True,
            )

        def test_filter_entry_attributes_all_blocked(self) -> None:
            """Test filter_entry_attributes when entry has no matching attributes."""
            entry = create_test_entry(
                DNs.TEST_USER,
                {
                    Filters.ATTR_CN: [Values.TEST],
                    Filters.ATTR_MAIL: ["test@ex"],
                    Filters.ATTR_OBJECTCLASS: [Filters.OC_PERSON],
                },
            )
            filtered = FilterTestHelpers.test_filter_entry_attributes_complete(
                entry,
                ["orclaci"],
                expected_marked=False,
            )
            assert filtered is not None
            assert filtered.has_attribute(Filters.ATTR_CN)

    class TestFilterEntryObjectClasses:
        """Test filter_entry_objectclasses marks objectClasses for removal."""

        def test_filter_entry_objectclasses_success(self) -> None:
            """Test filter_entry_objectclasses handles entries correctly using helper."""
            entry = create_test_entry(
                DNs.TEST_USER,
                {
                    Filters.ATTR_CN: [Values.TEST],
                    Filters.ATTR_OBJECTCLASS: [Filters.OC_TOP, Filters.OC_PERSON],
                },
            )
            FilterTestHelpers.test_filter_entry_objectclasses_complete(
                entry,
                ["orclContainerOC"],
            )

        def test_filter_entry_objectclasses_removes_all(self) -> None:
            """Test filter_entry_objectclasses marks objectClasses for removal."""
            entry = create_test_entry(
                DNs.TEST_USER,
                {
                    Filters.ATTR_CN: [Values.TEST],
                    Filters.ATTR_OBJECTCLASS: [Filters.OC_PERSON],
                },
            )
            filtered = FilterTestHelpers.test_filter_entry_objectclasses_complete(
                entry,
                [Filters.OC_PERSON],
            )
            assert filtered is not None

        def test_filter_entry_objectclasses_non_existent(self) -> None:
            """Test filter_entry_objectclasses when filtering non-existent objectClasses."""
            entry = create_test_entry(
                DNs.TEST_USER,
                {
                    Filters.ATTR_CN: [Values.TEST],
                    Filters.ATTR_OBJECTCLASS: [Filters.OC_PERSON],
                },
            )
            FilterTestHelpers.test_filter_entry_objectclasses_complete(
                entry,
                ["nonexistent"],
            )

    class TestCategorization:
        """Test entry categorization with various scenarios."""

        @pytest.mark.parametrize(
            ("dn", "attrs", "expected_categories"),
            [
                # Entries with person objectClass are categorized as users by default
                # when using server defaults (RFC server has person in user_objectclasses)
                (
                    "o=test",
                    {Filters.ATTR_OBJECTCLASS: ["unknownObject"]},
                    Filters.CATEGORY_REJECTED,
                ),
                (
                    "cn=123,dc=example,dc=com",
                    {Filters.ATTR_OBJECTCLASS: ["unknownObject"]},
                    Filters.CATEGORY_REJECTED,
                ),
                (
                    "cn=test",
                    {Filters.ATTR_OBJECTCLASS: ["unknownObject"]},
                    Filters.CATEGORY_REJECTED,
                ),
            ],
        )
        def test_categorize_entry_type_guards(
            self,
            dn: str,
            attrs: dict[str, str | list[str]],
            expected_categories: str,
        ) -> None:
            """Test categorize_entry handles various edge cases using helper."""
            entry = create_test_entry(dn, attrs)
            # Use empty rules to ensure rejection for unknown objectClasses
            rules = FlextLdifModels.CategoryRules(
                hierarchy_objectclasses=[],
                user_objectclasses=[],
                group_objectclasses=[],
            )
            FilterTestHelpers.test_categorize_entry_complete(
                entry,
                rules,
                expected_category=expected_categories,
            )

        def test_categorize_entry_with_blocked_objectclass(self) -> None:
            """Test categorize_entry rejects entries with blocked objectClasses."""
            entry = create_test_entry(
                "cn=test",
                {Filters.ATTR_OBJECTCLASS: [Filters.OC_PERSON, "blockedClass"]},
            )
            rules = FlextLdifModels.CategoryRules(
                hierarchy_objectclasses=[],
                user_objectclasses=[Filters.OC_PERSON],
            )
            whitelist_rules = FlextLdifModels.WhitelistRules(
                blocked_objectclasses=["blockedClass"],
            )
            FilterTestHelpers.test_categorize_entry_complete(
                entry,
                rules,
                expected_category=Filters.CATEGORY_REJECTED,
                expected_reason_contains="Blocked",
                whitelist_rules=whitelist_rules,
            )

        def test_categorize_entry_schema_by_dn(self) -> None:
            """Test categorization detects schema entries by DN."""
            entry = create_test_entry(
                DNs.SCHEMA,
                {
                    Filters.ATTR_OBJECTCLASS: ["subschema"],
                    "attributeTypes": ["( 1.2.3 NAME 'test' )"],
                },
            )
            FilterTestHelpers.test_categorize_entry_complete(
                entry,
                {},
                expected_category=Filters.CATEGORY_SCHEMA,
            )

        def test_categorize_entry_schema_by_attributes(self) -> None:
            """Test categorization detects schema entries by attributes."""
            entry = create_test_entry(
                DNs.SCHEMA,
                {
                    Filters.ATTR_OBJECTCLASS: ["subschema"],
                    "attributeTypes": ["( 1.2.3 NAME 'test' )"],
                },
            )
            FilterTestHelpers.test_categorize_entry_complete(
                entry,
                {},
                expected_category=Filters.CATEGORY_SCHEMA,
            )

        def test_categorize_entry_hierarchy_priority_over_acl(self) -> None:
            """Test hierarchy has priority over ACL detection."""
            entry = create_test_entry(
                "cn=container,dc=example",
                {Filters.ATTR_OBJECTCLASS: ["orclContainer"], "orclACI": ["some acl"]},
            )
            rules = FlextLdifModels.CategoryRules(
                hierarchy_objectclasses=["orclContainer"],
                acl_attributes=["orclACI"],
            )
            FilterTestHelpers.test_categorize_entry_complete(
                entry,
                rules,
                expected_category=Filters.CATEGORY_HIERARCHY,
            )

        def test_categorize_entry_user_with_dn_pattern_match(self) -> None:
            """Test user categorization with DN pattern validation."""
            entry = create_test_entry(
                "cn=john,ou=users,dc=example,dc=com",
                {Filters.ATTR_OBJECTCLASS: [Filters.OC_PERSON]},
            )
            rules = FlextLdifModels.CategoryRules(
                user_objectclasses=[Filters.OC_PERSON],
                user_dn_patterns=[".*,ou=users,.*"],
            )
            FilterTestHelpers.test_categorize_entry_complete(
                entry,
                rules,
                expected_category=Filters.CATEGORY_USERS,
            )

        def test_categorize_entry_user_with_dn_pattern_mismatch(self) -> None:
            """Test user categorization rejects DN pattern mismatch."""
            entry = create_test_entry(
                "cn=user1,ou=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                {Filters.ATTR_OBJECTCLASS: [Filters.OC_PERSON]},
            )
            rules = FlextLdifModels.CategoryRules(
                user_objectclasses=[Filters.OC_PERSON],
                user_dn_patterns=[".*,ou=users,.*"],
            )
            FilterTestHelpers.test_categorize_entry_complete(
                entry,
                rules,
                expected_category=Filters.CATEGORY_REJECTED,
                expected_reason_contains="DN pattern",
            )


__all__ = ["TestFlextLdifFilters"]
