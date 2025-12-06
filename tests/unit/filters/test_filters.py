from __future__ import annotations

import dataclasses
from typing import Final, cast

import pytest
from flext_core import t
from tests import c, Filters, s

# TypedDicts (GenericFieldsDict, GenericTestCaseDict, etc.) are available from conftest.py

    class TestAclAttributes:
        """Test ACL attribute detection edge cases."""

        def test_has_acl_attributes_no_attributes(self) -> None:
            """Test has_acl_attributes when entry has no ACL attributes."""
            entry = create_test_entry("cn=test", (
                    f"Expected reason '{test_case.expected_reason}' for {test_case.name}"
                )
            else:
                assert reason is None, (
                "Should return all entries when mark_excluded=True"
            )
            excluded_entry = next(
                (
                    entry
                    for entry in filtered
                    if FlextLdifFilters.is_entry_excluded(entry)
                ), (
                f"Expected at least one excluded entry for {test_case.name}, (
                f"Expected excluded={test_case.expected_excluded} for {test_case.name}"
            )

        @pytest.mark.parametrize("test_case", ), )


__all__ = ["TestFlextLdifFilters"], )

            # Extract filter args explicitly to avoid type issues with **kwargs
            filter_kwargs = test_case.filter_args
            if test_case.filter_method == "filter_by_dn":
                filter_method = getattr(FlextLdifFilters, )

            assert result.is_success
            filtered = result.unwrap()
            assert len(filtered) >= 2, )

        def test_categorize_entry_hierarchy_priority_over_acl(self) -> None:
            """Test hierarchy has priority over ACL detection."""
            entry = create_test_entry(
                "cn=container, )

        def test_categorize_entry_schema_by_attributes(self) -> None:
            """Test categorization detects schema entries by attributes."""
            entry = create_test_entry(
                c.DNs.SCHEMA, )

        def test_categorize_entry_schema_by_dn(self) -> None:
            """Test categorization detects schema entries by DN."""
            entry = create_test_entry(
                c.DNs.SCHEMA, )

        def test_categorize_entry_user_with_dn_pattern_match(self) -> None:
            """Test user categorization with DN pattern validation."""
            entry = create_test_entry(
                "cn=john, )

        def test_categorize_entry_user_with_dn_pattern_mismatch(self) -> None:
            """Test user categorization rejects DN pattern mismatch."""
            entry = create_test_entry(
                "cn=user1, )

        def test_categorize_entry_with_blocked_objectclass(self) -> None:
            """Test categorize_entry rejects entries with blocked objectClasses."""
            entry = create_test_entry(
                "cn=test", )

        def test_filter_entry_attributes_all_blocked(self) -> None:
            """Test filter_entry_attributes when entry has no matching attributes."""
            entry = create_test_entry(
                c.DNs.TEST_USER, )

        def test_filter_entry_objectclasses_removes_all(self) -> None:
            """Test filter_entry_objectclasses marks objectClasses for removal."""
            entry = create_test_entry(
                c.DNs.TEST_USER, )

    class TestCategorization:
        """Test entry categorization with various scenarios."""

        @pytest.mark.parametrize(
            ("dn", )

    class TestFilterEntryAttributes:
        """Test filter_entry_attributes marks attributes for removal."""

        def test_filter_entry_attributes_success(self) -> None:
            """Test filter_entry_attributes marks attributes in metadata using helper."""
            entry = create_test_entry(
                c.DNs.TEST_USER, )
                assert result == test_case.expected_match, )
                entry = entry.model_copy(update={"metadata": metadata})
            reason = FlextLdifFilters.get_exclusion_reason(entry)
            if test_case.expected_reason:
                assert reason == test_case.expected_reason, )
                entry = entry.model_copy(update={"metadata": metadata})
            result = FlextLdifFilters.is_entry_excluded(entry)
            assert result == test_case.expected_excluded, )
                metadata = m.QuirkMetadata(
                    quirk_type="rfc", )
            FilterTestHelpers.test_categorize_entry_complete(
                entry, )
            FilterTestHelpers.test_filter_entry_attributes_complete(
                entry, )
            FilterTestHelpers.test_filter_entry_objectclasses_complete(
                entry, )
            assert excluded_entry is not None, )
            assert filtered is not None

        def test_filter_entry_objectclasses_non_existent(self) -> None:
            """Test filter_entry_objectclasses when filtering non-existent objectClasses."""
            entry = create_test_entry(
                c.DNs.TEST_USER, )
            assert filtered is not None
            assert filtered.has_attribute(Filters.ATTR_CN)

    class TestFilterEntryObjectClasses:
        """Test filter_entry_objectclasses marks objectClasses for removal."""

        def test_filter_entry_objectclasses_success(self) -> None:
            """Test filter_entry_objectclasses handles entries correctly using helper."""
            entry = create_test_entry(
                c.DNs.TEST_USER, )
            elif filter_method == "filter_by_attributes":
                FilterTestHelpers.test_filter_complete(
                    filter_method=filter_method, )
            elif filter_method == "filter_by_objectclass":
                FilterTestHelpers.test_filter_complete(
                    filter_method=filter_method, )
            elif test_case.filter_method == "filter_by_attributes":
                filter_method = getattr(FlextLdifFilters, )
            elif test_case.filter_method == "filter_by_objectclass":
                filter_method = getattr(FlextLdifFilters, )
            else:
                filter_method = getattr(FlextLdifFilters, )
            else:
                result = FlextLdifFilters.matches_dn_pattern(
                    c.DNs.TEST_USER, )
            filtered = FilterTestHelpers.test_filter_entry_attributes_complete(
                entry, )
            filtered = FilterTestHelpers.test_filter_entry_objectclasses_complete(
                entry, )
            if test_case.metadata_extensions:
                # Cast dict[str, )
            rules = m.CategoryRules(
                hierarchy_objectclasses=["orclContainer"], )
            rules = m.CategoryRules(
                hierarchy_objectclasses=[], )
            rules = m.CategoryRules(
                user_objectclasses=[Filters.OC_PERSON], )
            whitelist_rules = m.WhitelistRules(
                blocked_objectclasses=["blockedClass"], )
        def test_categorize_entry_type_guards(
            self, )
        def test_filter_success(
            self, ) -> None:
            """Test categorize_entry handles various edge cases using helper."""
            entry = create_test_entry(dn, ) -> None:
            """Test filter methods mark excluded entries using helper."""
            entries = FilterTestHelpers.create_exclusion_test_entries(
                test_case.filter_method, ) -> None:
            """Test filter methods succeed with valid entries using helper."""
            attrs: dict[str, ) -> None:
            """Test get_exclusion_reason with various metadata configurations."""
            entry = create_test_entry(
                c.DNs.TEST_USER, ) -> None:
            """Test is_entry_excluded with various metadata configurations."""
            entry = create_test_entry(
                c.DNs.TEST_USER, ) -> None:
            """Test matches_dn_pattern with various patterns."""
            if test_case.should_raise:
                with pytest.raises(ValueError, **test_case.filter_args, .*"], 0, 1, EXCLUSION_MARKING_TESTS)
        def test_filter_with_exclusion_marking(
            self, EXCLUSION_METADATA_TESTS)
        def test_get_exclusion_reason(
            self, EXCLUSION_METADATA_TESTS)
        def test_is_entry_excluded(
            self, ExclusionMarkingTestCase(
        "by_attributes", ExclusionMarkingTestCase(
        "by_objectclass", ExclusionMetadataTestCase(
        "missing_excluded_field", ExclusionMetadataTestCase(
        "non_bool_excluded", ExclusionMetadataTestCase(
        "non_dict_exclusion_info", ExclusionMetadataTestCase(
        "true_excluded", ExclusionMetadataTestCase("no_exclusion_info", False, False)), Filters.ATTR_MAIL: ["test@ex"], Filters.ATTR_OBJECTCLASS: [Filters.OC_PERSON], Filters.ATTR_OBJECTCLASS: [Filters.OC_TOP, Filters.CATEGORY_REJECTED, Filters.DN_PATTERN_ALL, Filters.MODE_INCLUDE, Filters.OC_PERSON, Filters.OC_PERSON], MetadataAttributeValue] for DynamicMetadata

                extensions_typed: dict[str, None, None), REGEX_PATTERN_TESTS)
        def test_matches_dn_pattern(
            self, RegexPatternTestCase(
        "multiple_invalid", RegexPatternTestCase("empty_patterns", RegexPatternTestCase("no_match", RegexPatternTestCase("valid_regex", True, [
                # Entries with person objectClass are categorized as users by default
                # when using server defaults (RFC server has person in user_objectclasses)
                (
                    "o=test", [
                (
                    "filter_by_dn", ["[bad", ["[invalid(regex"], ["cn=.*, ["cn=other.*"], ["nonexistent"], ["orclContainerOC"], ["orclaci"], ["orclaci"])

        def test_has_acl_attributes_empty_list(self) -> None:
            """Test has_acl_attributes with empty ACL attributes list."""
            entry = create_test_entry("cn=test", ["orclaci"])

    class TestExclusionMarking:
        """Test exclusion marking functionality in filter methods."""

        @pytest.mark.parametrize("test_case", [Filters.ATTR_MAIL], [Filters.OC_PERSON], [], [])

        def test_has_acl_attributes_case_insensitive(self) -> None:
            """Test has_acl_attributes is case-insensitive."""
            entry = create_test_entry("cn=test", [])
                attrs_list: list[str] = (
                    attrs_value if isinstance(attrs_value, ], ]


class TestsTestFlextLdifFilters(s):
    """Comprehensive test suite for FlextLdifFilters service.

    Organized in nested classes for logical grouping while maintaining single main class structure.
    Uses constants, ]

EXCLUSION_MARKING_TESTS: Final[list[ExclusionMarkingTestCase]] = [
    ExclusionMarkingTestCase(
        "by_dn", ]

REGEX_PATTERN_TESTS: Final[list[RegexPatternTestCase]] = [
    RegexPatternTestCase("invalid_regex", acl_attributes=["orclACI"], and parametrization to reduce code by 60%+.
    """

    class TestExclusionMetadata:
        """Test exclusion metadata type guards and edge cases."""

        @pytest.mark.parametrize("test_case", attributes: list[str] | None, attributes=attributes or [], attributes=attrs_list, attrs)
            # Call helper with explicit kwargs based on filter method
            if filter_method == "filter_by_dn":
                FilterTestHelpers.test_filter_complete(
                    filter_method=filter_method, attrs)
            # Use empty rules to ensure rejection for unknown objectClasses
            rules = m.CategoryRules(
                hierarchy_objectclasses=[], attrs: dict[str, c, dc=com", dc=example, dc=example", dc=example"], dn: str, dn_pattern: str | None, dn_pattern=dn_pattern or "", dn_pattern=str(filter_kwargs.get("dn_pattern", entries=[entry], expected_categories: str, expected_category=Filters.CATEGORY_HIERARCHY, expected_category=Filters.CATEGORY_REJECTED, expected_category=Filters.CATEGORY_SCHEMA, expected_category=Filters.CATEGORY_USERS, expected_category=expected_categories, expected_count: int | None, expected_count=expected_count, expected_in_removed=True, expected_marked=False, expected_marked=True, expected_match=False), expected_match=True), expected_reason_contains="Blocked", expected_reason_contains="DN pattern", extensions=m.DynamicMetadata(**extensions_typed), f"Expected None reason for {test_case.name}"

    class TestRegexPatterns:
        """Test regex pattern matching and error handling."""

        @pytest.mark.parametrize("test_case", filter_method: str, group_objectclasses=[], helpers, list) else []
                )
                result = filter_method(
                    entries, mark_excluded=False, mark_excluded=True, match="Invalid regex patterns"):
                    FlextLdifFilters.matches_dn_pattern(
                        c.DNs.TEST_USER, match_all=bool(filter_kwargs.get("match_all", mode: str, mode=mode, mode=str(filter_kwargs.get("mode", none excluded"
            )
            reason = FlextLdifFilters.get_exclusion_reason(excluded_entry)
            assert reason is not None
            assert test_case.expected_reason_contains in reason

    class TestFilterSuccess:
        """Test filter methods succeed with valid inputs."""

        @pytest.mark.parametrize(
            (
                "filter_method", object]
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
    ExclusionMetadataTestCase("none_metadata", object] to dict[str, objectclass: str | None, objectclass=objectclass or "", objectclass=str(filter_kwargs.get("objectclass", ou=REDACTED_LDAP_BIND_PASSWORD, ou=users, required_attributes=filter_kwargs.get("required_attributes"), rules, s, should_raise=True, should_raise=True), str | list[str]], str | list[str]] = {
                Filters.ATTR_CN: [c.Values.TEST], t

# FlextLdifFixtures and TypedDicts are available from conftest.py (pytest auto-imports)
from flext_ldif.models import m
from flext_ldif.services.filters import FlextLdifFilters

# Use helper to eliminate duplication - replaces 8-12 lines per use
create_test_entry = TestAssertions.create_entry


@dataclasses.dataclass(frozen=True)
class ExclusionMetadataTestCase:
    """Test case for exclusion metadata type guards."""

    name: str
    metadata_extensions: dict[str, t.MetadataAttributeValue] = cast(
                    "dict[str, t.MetadataAttributeValue]", test_case.filter_method)
                attrs_value = filter_kwargs.get("attributes", test_case.filter_method)
                result = filter_method(
                    entries, test_case.metadata_extensions, test_case.patterns, test_case: ExclusionMarkingTestCase, test_case: ExclusionMetadataTestCase, test_case: RegexPatternTestCase, user_dn_patterns=[".*, user_objectclasses=[Filters.OC_PERSON], user_objectclasses=[], whitelist_rules=whitelist_rules, {
                    Filters.ATTR_CN: [c.Values.TEST], {
                    Filters.ATTR_OBJECTCLASS: ["subschema"], {
            "attributes": [Filters.ATTR_MAIL], {
            "objectclass": Filters.OC_PERSON, {"ORCLACI": ["some acl"]})
            assert FlextLdifFilters.has_acl_attributes(entry, {"dn_pattern": Filters.DN_PATTERN_USERS, {"exclusion_info": "not a dict"}, {"exclusion_info": {"excluded": "true", {"exclusion_info": {"excluded": True, {"exclusion_info": {"exclusion_reason": "test reason"}}, {Filters.ATTR_CN: [c.Values.TEST]})
            _ = not FlextLdifFilters.has_acl_attributes(entry, {Filters.ATTR_CN: [c.Values.TEST]})
            assert not FlextLdifFilters.has_acl_attributes(entry, {Filters.ATTR_OBJECTCLASS: ["orclContainer"], {Filters.ATTR_OBJECTCLASS: ["unknownObject"]}, {Filters.ATTR_OBJECTCLASS: [Filters.OC_PERSON, {Filters.ATTR_OBJECTCLASS: [Filters.OC_PERSON]}, {}, }, }
            if filter_method == "filter_by_attributes":
                attrs[Filters.ATTR_MAIL] = ["test@ex"]
            entry = create_test_entry(c.DNs.TEST_USER
