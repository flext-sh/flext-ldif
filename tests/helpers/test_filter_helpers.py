"""Filter test helpers to eliminate massive code duplication.

Provides high-level methods that replace entire test functions with single calls.
Each method replaces 10-20+ lines of duplicated test code.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import FlextLdifModels
from flext_ldif.services.filters import FlextLdifFilters
from tests.fixtures.typing import GenericFieldsDict

from .test_assertions import TestAssertions


class FilterTestHelpers:
    """High-level filter test helpers that replace entire test functions."""

    @staticmethod
    def test_filter_complete(
        filter_method: str,
        entries: list[FlextLdifModels.Entry],
        *,
        expected_count: int | None = None,
        expected_excluded_count: int | None = None,
        mark_excluded: bool = False,
        should_succeed: bool = True,
        **filter_kwargs: object,
    ) -> list[FlextLdifModels.Entry] | None:
        """Complete filter test - replaces 10-15 lines of test code."""
        method = getattr(FlextLdifFilters, filter_method)
        result = method(entries, mark_excluded=mark_excluded, **filter_kwargs)

        if should_succeed:
            filtered: list[FlextLdifModels.Entry] = TestAssertions.assert_success(
                result,
            )
            if expected_count is not None:
                assert len(filtered) == expected_count
            if expected_excluded_count is not None:
                excluded = [
                    entry
                    for entry in filtered
                    if FlextLdifFilters.is_entry_excluded(entry)
                ]
                assert len(excluded) == expected_excluded_count
            return filtered
        TestAssertions.assert_failure(result)
        return None

    @staticmethod
    def test_filter_with_exclusion_marking_complete(
        filter_method: str,
        entries: list[FlextLdifModels.Entry],
        *,
        expected_reason_contains: str,
        mark_excluded: bool = True,
        expected_count: int | None = None,
        expected_excluded_count: int | None = None,
        should_succeed: bool = True,
        **filter_kwargs: object,
    ) -> list[FlextLdifModels.Entry]:
        """Complete filter with exclusion marking test - replaces 15-20 lines."""
        result = FilterTestHelpers.test_filter_complete(
            filter_method=filter_method,
            entries=entries,
            expected_count=expected_count,
            expected_excluded_count=expected_excluded_count,
            mark_excluded=mark_excluded,
            should_succeed=should_succeed,
            **filter_kwargs,
        )
        assert result is not None

        excluded_entry = next(
            (entry for entry in result if FlextLdifFilters.is_entry_excluded(entry)),
            None,
        )
        assert excluded_entry is not None
        reason = FlextLdifFilters.get_exclusion_reason(excluded_entry)
        assert reason is not None
        assert expected_reason_contains in reason
        return result

    @staticmethod
    def test_filter_entry_attributes_complete(
        entry: FlextLdifModels.Entry,
        attributes_to_filter: list[str],
        *,
        expected_marked: bool = True,
        expected_in_removed: bool = True,
        should_succeed: bool = True,
    ) -> FlextLdifModels.Entry | None:
        """Complete filter_entry_attributes test - replaces 10-15 lines."""
        result = FlextLdifFilters.filter_entry_attributes(
            entry,
            attributes_to_remove=attributes_to_filter,
        )

        if should_succeed:
            filtered = TestAssertions.assert_success(result)
            if expected_marked:
                for attr in attributes_to_filter:
                    if entry.has_attribute(attr):
                        assert filtered.has_attribute(attr)
            if expected_in_removed and filtered.metadata:
                for attr in attributes_to_filter:
                    if entry.has_attribute(attr):
                        assert attr in filtered.metadata.removed_attributes
            return filtered
        TestAssertions.assert_failure(result)
        return None

    @staticmethod
    def test_filter_entry_objectclasses_complete(
        entry: FlextLdifModels.Entry,
        objectclasses_to_filter: list[str],
        *,
        should_succeed: bool = True,
    ) -> FlextLdifModels.Entry | None:
        """Complete filter_entry_objectclasses test - replaces 8-12 lines."""
        result = FlextLdifFilters.filter_entry_objectclasses(
            entry,
            objectclasses_to_remove=objectclasses_to_filter,
        )

        if should_succeed:
            return TestAssertions.assert_success(result)
        TestAssertions.assert_failure(result)
        return None

    @staticmethod
    def test_categorize_entry_complete(
        entry: FlextLdifModels.Entry,
        rules: FlextLdifModels.CategoryRules | GenericFieldsDict,
        *,
        expected_category: str | None = None,
        expected_reason_contains: str | None = None,
        whitelist_rules: FlextLdifModels.WhitelistRules | None = None,
        validate_category: bool = True,
    ) -> tuple[str, str | None]:
        """Complete categorize_entry test - replaces 10-15 lines."""
        if isinstance(rules, dict):
            rules_obj = FlextLdifModels.CategoryRules.model_validate(rules)
        else:
            rules_obj = rules
        category, reason = FlextLdifFilters.categorize_entry(
            entry,
            rules=rules_obj,
            whitelist_rules=whitelist_rules,
        )

        if expected_category:
            assert category == expected_category
        if expected_reason_contains:
            assert reason is not None
            assert expected_reason_contains in reason

        if validate_category:
            valid_categories = {
                "users",
                "groups",
                "hierarchy",
                "schema",
                "acl",
                "rejected",
            }
            assert category in valid_categories

        return (category, reason)

    @staticmethod
    def create_exclusion_test_entries(
        filter_method: str,
    ) -> list[FlextLdifModels.Entry]:
        """Create test entries for exclusion marking tests.

        Replaces 30-40 lines of repetitive entry creation code.

        Args:
            filter_method: Filter method name to determine entry setup

        Returns:
            List of test entries configured for exclusion testing

        """
        base_entries = [
            TestAssertions.create_entry(
                "cn=user1,ou=users,dc=example,dc=com",
                {
                    "cn": ["user1"],
                    "objectClass": ["person"],
                },
            ),
            TestAssertions.create_entry(
                "cn=user2,ou=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                {
                    "cn": ["user2"],
                    "objectClass": ["person"],
                },
            ),
        ]

        if filter_method == "filter_by_attributes":
            base_entries[0] = TestAssertions.create_entry(
                "cn=user1,dc=example,dc=com",
                {
                    "cn": ["user1"],
                    "mail": ["user1@example.com"],
                    "objectClass": ["person"],
                },
            )
            base_entries[1] = TestAssertions.create_entry(
                "cn=user2,ou=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                {
                    "cn": ["user2"],
                    "objectClass": ["person"],
                },
            )
            # Remove mail attribute if factory added it
            if (
                base_entries[1].attributes
                and "mail" in base_entries[1].attributes.attributes
            ):
                attrs_dict = dict(base_entries[1].attributes.attributes)
                attrs_dict.pop("mail", None)
                base_entries[1] = base_entries[1].model_copy(
                    update={
                        "attributes": FlextLdifModels.LdifAttributes(
                            attributes=attrs_dict,
                        ),
                    },
                )
        elif filter_method == "filter_by_objectclass":
            base_entries[1] = TestAssertions.create_entry(
                "cn=group1,dc=example,dc=com",
                {
                    "cn": ["group1"],
                    "objectClass": ["groupOfNames"],
                },
            )

        return base_entries


__all__ = ["FilterTestHelpers"]
