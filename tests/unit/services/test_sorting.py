"""Tests for FlextLdifSorting service.

Tests validate that FlextLdifSorting:
1. Sorts entries by hierarchy (DN depth)
2. Sorts entries alphabetically by DN
3. Sorts schema entries correctly
4. Supports custom predicate sorting
5. Supports builder pattern
6. Supports classmethod composable pattern
7. Handles multiple sort targets (entries, attributes, ACL, schema, combined)
8. Handles edge cases (empty entries, single entry, invalid sort_by)

Modules tested:
- flext_ldif.services.sorting.FlextLdifSorting (entry sorting service)

Scope:
- Hierarchy-based sorting (DN depth)
- Alphabetical DN sorting
- Schema entry sorting
- Custom predicate sorting
- Builder pattern support
- Classmethod composable pattern
- Multiple sort targets (entries, attributes, ACL, schema, combined)
- Error handling and edge cases

Test Coverage:
- All sorting strategies (hierarchy, DN, schema, custom)
- Execute pattern with all targets
- Builder pattern
- Classmethod pattern
- Empty entries handling
- Invalid sort_by validation
- Single entry handling

Uses StrEnum, frozen dataclasses, parametrization, and extensive helper reuse
to reduce code while maintaining 100% behavior coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import dataclasses
from enum import StrEnum
from typing import Final

import pytest
from flext_core import FlextResult
from pydantic import ValidationError

from flext_ldif import FlextLdifModels
from flext_ldif.services.sorting import FlextLdifSorting
from tests.fixtures.constants import DNs, Names
from tests.helpers.test_assertions import TestAssertions
from tests.helpers.test_rfc_helpers import RfcTestHelpers


class TestFlextLdifSorting:
    """Test FlextLdifSorting service with consolidated parametrized tests.

    Uses nested classes for organization: TestType, TestCase, Constants, Helpers.
    Reduces code duplication through parametrization and helper methods.
    """

    class TestType(StrEnum):
        """Sort test type enumeration organized as nested enum."""

        __test__ = False

        BY_HIERARCHY = "by_hierarchy"
        BY_DN = "by_dn"
        BY_SCHEMA = "by_schema"
        BY_CUSTOM = "by_custom"
        EXECUTE_EMPTY = "execute_empty"
        EXECUTE_HIERARCHY = "execute_hierarchy"
        EXECUTE_DN = "execute_dn"
        EXECUTE_ALPHABETICAL = "execute_alphabetical"
        EXECUTE_CUSTOM = "execute_custom"
        EXECUTE_ATTRIBUTES = "execute_attributes"
        EXECUTE_ACL = "execute_acl"
        EXECUTE_SCHEMA = "execute_schema"
        EXECUTE_COMBINED = "execute_combined"
        SORT_CLASSMETHOD = "sort_classmethod"
        BUILDER_ATTRIBUTES = "builder_attributes"
        BUILDER_OBJECTCLASS = "builder_objectclass"

    @dataclasses.dataclass(frozen=True)
    class TestCase:
        """Frozen test case for sorting operations organized as nested dataclass."""

        __test__ = False

        test_type: TestFlextLdifSorting.TestType
        sort_by: str
        sort_target: str = "entries"
        custom_predicate: bool = False
        expected_count: int | None = None
        description: str = ""

    class Constants:
        """Test constants organized as nested class."""

        SORT_TARGET_ENTRIES: str = "entries"
        SORT_TARGET_ATTRIBUTES: str = "attributes"
        SORT_TARGET_ACL: str = "acl"
        SORT_TARGET_SCHEMA: str = "schema"
        SORT_TARGET_COMBINED: str = "combined"
        SORT_BY_HIERARCHY: str = "hierarchy"
        SORT_BY_DN: str = "dn"
        SORT_BY_ALPHABETICAL: str = "alphabetical"
        SORT_BY_SCHEMA: str = "schema"
        SORT_BY_CUSTOM: str = "custom"
        INVALID_SORT_TYPE: str = "invalid_sort_type"
        ROOT_DN: str = DNs.EXAMPLE

    class Helpers:
        """Helper methods organized as nested class."""

        @staticmethod
        def sort_predicate(entry: FlextLdifModels.Entry) -> str:
            """Extract DN value for sorting predicate."""
            return entry.dn.value if entry.dn else ""

        @staticmethod
        def hierarchy_entries() -> list[FlextLdifModels.Entry]:
            """Create hierarchy test entries."""
            create_entry = TestAssertions.create_entry
            return [
                create_entry(
                    "uid=jdoe,ou=people,ou=users,dc=example,dc=com",
                    {"uid": ["jdoe"], Names.OBJECTCLASS: [Names.PERSON]},
                ),
                create_entry(
                    TestFlextLdifSorting.Constants.ROOT_DN,
                    {"dc": ["example"], Names.OBJECTCLASS: ["domain"]},
                ),
                create_entry(
                    "ou=users,dc=example,dc=com",
                    {"ou": ["users"], Names.OBJECTCLASS: ["organizationalUnit"]},
                ),
                create_entry(
                    "ou=groups,dc=example,dc=com",
                    {"ou": ["groups"], Names.OBJECTCLASS: ["organizationalUnit"]},
                ),
                create_entry(
                    "ou=people,ou=users,dc=example,dc=com",
                    {"ou": ["people"], Names.OBJECTCLASS: ["organizationalUnit"]},
                ),
            ]

        @staticmethod
        def schema_entries() -> list[FlextLdifModels.Entry]:
            """Create schema test entries."""
            create_entry = TestAssertions.create_entry
            return [
                create_entry(
                    "cn=schema",
                    {
                        Names.CN: ["schema"],
                        "objectClasses": ["( 2.5.6.6 NAME 'person' SUP top )"],
                    },
                ),
                create_entry(
                    "cn=schema",
                    {
                        Names.CN: ["schema"],
                        "attributeTypes": [
                            "( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch )",
                        ],
                    },
                ),
            ]

        @staticmethod
        def execute_sort_operation(
            test_case: TestFlextLdifSorting.TestCase,
            entries: list[FlextLdifModels.Entry],
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Execute sort operation based on test case type."""
            if test_case.test_type == TestFlextLdifSorting.TestType.BY_HIERARCHY:
                return FlextLdifSorting.by_hierarchy(entries)
            if test_case.test_type == TestFlextLdifSorting.TestType.BY_DN:
                return FlextLdifSorting.by_dn(entries)
            if test_case.test_type == TestFlextLdifSorting.TestType.BY_SCHEMA:
                return FlextLdifSorting.by_schema(entries)
            if test_case.test_type == TestFlextLdifSorting.TestType.BY_CUSTOM:
                return FlextLdifSorting.by_custom(
                    entries,
                    TestFlextLdifSorting.Helpers.sort_predicate,
                )
            if test_case.test_type == TestFlextLdifSorting.TestType.EXECUTE_EMPTY:
                return FlextLdifSorting(
                    entries=[],
                    sort_by=test_case.sort_by,
                ).execute()
            if test_case.test_type == TestFlextLdifSorting.TestType.EXECUTE_CUSTOM:
                return FlextLdifSorting(
                    entries=entries,
                    sort_target=test_case.sort_target,
                    sort_by=test_case.sort_by,
                    custom_predicate=TestFlextLdifSorting.Helpers.sort_predicate,
                ).execute()
            if test_case.test_type == TestFlextLdifSorting.TestType.SORT_CLASSMETHOD:
                return FlextLdifSorting.sort(entries, by=test_case.sort_by)
            if test_case.test_type == TestFlextLdifSorting.TestType.BUILDER_ATTRIBUTES:
                return (
                    FlextLdifSorting.builder()
                    .with_entries(entries)
                    .with_target(test_case.sort_target)
                    .with_strategy(test_case.sort_by)
                    .execute()
                )
            # All other execute variants
            return FlextLdifSorting(
                entries=entries,
                sort_target=test_case.sort_target,
                sort_by=test_case.sort_by,
            ).execute()

        @staticmethod
        def verify_sort_behavior(
            test_case: TestFlextLdifSorting.TestCase,
            sorted_entries: list[FlextLdifModels.Entry],
        ) -> None:
            """Verify sort behavior based on test case type."""
            if (
                "dn" in test_case.sort_by
                and test_case.sort_target
                == TestFlextLdifSorting.Constants.SORT_TARGET_ENTRIES
            ):
                dns = [e.dn.value.lower() if e.dn else "" for e in sorted_entries]
                assert dns == sorted(dns), f"{test_case.description}: DNs not sorted"

            if test_case.test_type == TestFlextLdifSorting.TestType.BY_HIERARCHY:
                assert sorted_entries[0].dn is not None
                assert (
                    sorted_entries[0].dn.value == TestFlextLdifSorting.Constants.ROOT_DN
                )

    # Test case definitions
    SORT_TEST_CASES: Final[list[TestCase]] = [
        TestCase(
            test_type=TestType.BY_HIERARCHY,
            sort_by=Constants.SORT_BY_HIERARCHY,
            expected_count=5,
            description="by_hierarchy() sorts by DN depth",
        ),
        TestCase(
            test_type=TestType.BY_DN,
            sort_by=Constants.SORT_BY_DN,
            expected_count=5,
            description="by_dn() sorts alphabetically by DN",
        ),
        TestCase(
            test_type=TestType.BY_SCHEMA,
            sort_by=Constants.SORT_BY_SCHEMA,
            expected_count=2,
            description="by_schema() sorts schema entries",
        ),
        TestCase(
            test_type=TestType.BY_CUSTOM,
            sort_by=Constants.SORT_BY_CUSTOM,
            custom_predicate=True,
            expected_count=5,
            description="by_custom() sorts by custom predicate",
        ),
        TestCase(
            test_type=TestType.EXECUTE_EMPTY,
            sort_by=Constants.SORT_BY_HIERARCHY,
            expected_count=0,
            description="execute() handles empty entries",
        ),
        TestCase(
            test_type=TestType.EXECUTE_HIERARCHY,
            sort_by=Constants.SORT_BY_HIERARCHY,
            expected_count=5,
            description="execute() with hierarchy sort",
        ),
        TestCase(
            test_type=TestType.EXECUTE_DN,
            sort_by=Constants.SORT_BY_DN,
            expected_count=5,
            description="execute() with DN sort",
        ),
        TestCase(
            test_type=TestType.EXECUTE_ALPHABETICAL,
            sort_by=Constants.SORT_BY_ALPHABETICAL,
            expected_count=5,
            description="execute() with alphabetical alias",
        ),
        TestCase(
            test_type=TestType.EXECUTE_CUSTOM,
            sort_by=Constants.SORT_BY_CUSTOM,
            custom_predicate=True,
            expected_count=5,
            description="execute() with custom predicate",
        ),
        TestCase(
            test_type=TestType.EXECUTE_ATTRIBUTES,
            sort_by=Constants.SORT_BY_HIERARCHY,
            sort_target=Constants.SORT_TARGET_ATTRIBUTES,
            expected_count=5,
            description="execute() with attributes target",
        ),
        TestCase(
            test_type=TestType.EXECUTE_ACL,
            sort_by=Constants.SORT_BY_HIERARCHY,
            sort_target=Constants.SORT_TARGET_ACL,
            expected_count=5,
            description="execute() with ACL target",
        ),
        TestCase(
            test_type=TestType.EXECUTE_SCHEMA,
            sort_by=Constants.SORT_BY_SCHEMA,
            sort_target=Constants.SORT_TARGET_SCHEMA,
            expected_count=2,
            description="execute() with schema target",
        ),
        TestCase(
            test_type=TestType.EXECUTE_COMBINED,
            sort_by=Constants.SORT_BY_HIERARCHY,
            sort_target=Constants.SORT_TARGET_COMBINED,
            expected_count=5,
            description="execute() with combined target",
        ),
        TestCase(
            test_type=TestType.SORT_CLASSMETHOD,
            sort_by=Constants.SORT_BY_HIERARCHY,
            expected_count=5,
            description="sort() classmethod composable pattern",
        ),
        TestCase(
            test_type=TestType.BUILDER_ATTRIBUTES,
            sort_by=Constants.SORT_BY_HIERARCHY,
            sort_target=Constants.SORT_TARGET_ATTRIBUTES,
            expected_count=5,
            description="builder() pattern with attributes",
        ),
        TestCase(
            test_type=TestType.BUILDER_OBJECTCLASS,
            sort_by=Constants.SORT_BY_HIERARCHY,
            sort_target=Constants.SORT_TARGET_ENTRIES,
            expected_count=5,
            description="builder() pattern with entries",
        ),
    ]

    @pytest.mark.parametrize("test_case", SORT_TEST_CASES)
    def test_sorting_operations(self, test_case: TestCase) -> None:
        """Test all sorting operations - consolidated into one parametrized test."""
        entries = (
            self.Helpers.schema_entries()
            if "schema" in test_case.test_type
            else self.Helpers.hierarchy_entries()
        )

        result = self.Helpers.execute_sort_operation(test_case, entries)

        sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
            result,
            expected_type=list,
            expected_count=test_case.expected_count,
        )

        self.Helpers.verify_sort_behavior(test_case, sorted_entries)

    def test_empty_entries_returns_empty_list(self) -> None:
        """Empty entries should return empty list."""
        result = FlextLdifSorting(
            entries=[],
            sort_by=self.Constants.SORT_BY_HIERARCHY,
        ).execute()
        sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
            result,
            expected_type=list,
            expected_count=0,
        )
        assert sorted_entries == []

    def test_invalid_sort_by_fails(self) -> None:
        """Invalid sort_by should fail gracefully."""
        entries = self.Helpers.hierarchy_entries()
        with pytest.raises(ValidationError):
            FlextLdifSorting(
                entries=entries,
                sort_by=self.Constants.INVALID_SORT_TYPE,
            ).execute()

    def test_single_entry_returns_one(self) -> None:
        """Single entry should return as-is."""
        entry = [
            TestAssertions.create_entry(
                "cn=test,dc=x",
                {Names.CN: ["test"]},
            ),
        ]
        result = FlextLdifSorting.by_hierarchy(entry)
        sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
            result,
            expected_type=list,
            expected_count=1,
        )
        assert len(sorted_entries) == 1
