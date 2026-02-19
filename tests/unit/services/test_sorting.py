"""Tests for LDIF entry sorting service.

This module tests the FlextLdifSorting service with consolidated parametrized
tests covering sorting by hierarchy, DN, schema, custom criteria, and direct
method execution with various entry configurations and organizational modes.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from enum import StrEnum
from typing import Final

import pytest
from flext_core import FlextResult
from flext_ldif.services.sorting import FlextLdifSorting
from pydantic import ValidationError

from tests import RfcTestHelpers, c, p, s


class TestsTestFlextLdifSorting(s):
    """Test FlextLdifSorting service with consolidated parametrized tests.

    Uses nested classes for organization: TestType, TestCase, Constants, Helpers.
    Reduces code duplication through parametrization and helper methods.
    Uses factories and constants extensively for maximum code reduction.
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

        test_type: TestsTestFlextLdifSorting.TestType
        sort_by: str
        sort_target: str = "entries"
        custom_predicate: bool = False
        expected_count: int | None = None
        description: str = ""

    class Constants:
        """Test constants organized as nested class using constants from fixtures."""

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
        ROOT_DN: str = c.DNs.EXAMPLE

    class Helpers:
        """Helper methods organized as nested class using factories and constants."""

        __test__ = False

        @staticmethod
        def sort_predicate(entry: p.Entry) -> str:
            """Extract DN value for sorting predicate."""
            return entry.dn.value if entry.dn else ""

        @staticmethod
        def hierarchy_entries() -> list[p.Entry]:
            """Create hierarchy test entries using factories and constants."""
            return [
                TestsTestFlextLdifSorting.create_entry(
                    dn="uid=jdoe,ou=people,ou=users,dc=example,dc=com",
                    attributes={"uid": ["jdoe"], c.Names.OBJECTCLASS: [c.Names.PERSON]},
                ),
                TestsTestFlextLdifSorting.create_entry(
                    dn=c.DNs.EXAMPLE,
                    attributes={"dc": ["example"], c.Names.OBJECTCLASS: ["domain"]},
                ),
                TestsTestFlextLdifSorting.create_entry(
                    dn="ou=users,dc=example,dc=com",
                    attributes={
                        "ou": ["users"],
                        c.Names.OBJECTCLASS: ["organizationalUnit"],
                    },
                ),
                TestsTestFlextLdifSorting.create_entry(
                    dn="ou=groups,dc=example,dc=com",
                    attributes={
                        "ou": ["groups"],
                        c.Names.OBJECTCLASS: ["organizationalUnit"],
                    },
                ),
                TestsTestFlextLdifSorting.create_entry(
                    dn="ou=people,ou=users,dc=example,dc=com",
                    attributes={
                        "ou": ["people"],
                        c.Names.OBJECTCLASS: ["organizationalUnit"],
                    },
                ),
            ]

        @staticmethod
        def schema_entries() -> list[p.Entry]:
            """Create schema test entries using factories."""
            return [
                TestsTestFlextLdifSorting.create_entry(
                    dn="cn=schema",
                    attributes={
                        c.Names.CN: ["schema"],
                        "objectClasses": ["( 2.5.6.6 NAME 'person' SUP top )"],
                    },
                ),
                TestsTestFlextLdifSorting.create_entry(
                    dn="cn=schema",
                    attributes={
                        c.Names.CN: ["schema"],
                        "attributeTypes": [
                            "( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch )",
                        ],
                    },
                ),
            ]

        @staticmethod
        def execute_sort_operation(
            test_case: TestsTestFlextLdifSorting.TestCase,
            entries: list[p.Entry],
        ) -> FlextResult[list[p.Entry]]:
            """Execute sort operation based on test case type using mapping."""
            operation_map: dict[
                TestsTestFlextLdifSorting.TestType,
                Callable[[], FlextResult[list[p.Entry]]],
            ] = {
                TestsTestFlextLdifSorting.TestType.BY_HIERARCHY: lambda: (
                    FlextLdifSorting.by_hierarchy(
                        entries,
                    )
                ),
                TestsTestFlextLdifSorting.TestType.BY_DN: lambda: (
                    FlextLdifSorting.by_dn(
                        entries,
                    )
                ),
                TestsTestFlextLdifSorting.TestType.BY_SCHEMA: lambda: (
                    FlextLdifSorting.by_schema(
                        entries,
                    )
                ),
                TestsTestFlextLdifSorting.TestType.BY_CUSTOM: lambda: (
                    FlextLdifSorting.by_custom(
                        entries,
                        TestsTestFlextLdifSorting.Helpers.sort_predicate,
                    )
                ),
                TestsTestFlextLdifSorting.TestType.EXECUTE_EMPTY: lambda: (
                    FlextLdifSorting(
                        entries=[],
                        sort_by=test_case.sort_by,
                    ).execute()
                ),
                TestsTestFlextLdifSorting.TestType.EXECUTE_CUSTOM: lambda: (
                    FlextLdifSorting(
                        entries=entries,
                        sort_target=test_case.sort_target,
                        sort_by=test_case.sort_by,
                        custom_predicate=TestsTestFlextLdifSorting.Helpers.sort_predicate,
                    ).execute()
                ),
                TestsTestFlextLdifSorting.TestType.SORT_CLASSMETHOD: lambda: (
                    FlextLdifSorting.sort(
                        entries=entries,
                        by=test_case.sort_by,
                    )
                ),
                TestsTestFlextLdifSorting.TestType.BUILDER_ATTRIBUTES: lambda: (
                    FlextLdifSorting
                    .builder()
                    .with_entries(entries)
                    .with_target(test_case.sort_target)
                    .with_strategy(test_case.sort_by)
                    .execute()
                ),
            }

            if test_case.test_type in operation_map:
                return operation_map[test_case.test_type]()

            # Default: execute pattern
            return FlextLdifSorting(
                entries=entries,
                sort_target=test_case.sort_target,
                sort_by=test_case.sort_by,
            ).execute()

        @staticmethod
        def verify_sort_behavior(
            test_case: TestsTestFlextLdifSorting.TestCase,
            sorted_entries: list[p.Entry],
        ) -> None:
            """Verify sort behavior based on test case type."""
            if (
                "dn" in test_case.sort_by
                and test_case.sort_target
                == TestsTestFlextLdifSorting.Constants.SORT_TARGET_ENTRIES
            ):
                dns = [e.dn.value.lower() if e.dn else "" for e in sorted_entries]
                assert dns == sorted(dns), f"{test_case.description}: DNs not sorted"

            if test_case.test_type == TestsTestFlextLdifSorting.TestType.BY_HIERARCHY:
                assert sorted_entries[0].dn is not None
                assert (
                    sorted_entries[0].dn.value
                    == TestsTestFlextLdifSorting.Constants.ROOT_DN
                )

    # Test case definitions using constants and factories
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
            _ = FlextLdifSorting(
                entries=entries,
                sort_by=self.Constants.INVALID_SORT_TYPE,
            ).execute()

    def test_single_entry_returns_one(self) -> None:
        """Single entry should return as-is."""
        entry = [
            self.create_entry(
                "cn=test,dc=x",
                {c.Names.CN: ["test"]},
            ),
        ]
        result = FlextLdifSorting.by_hierarchy(entry)
        sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
            result,
            expected_type=list,
            expected_count=1,
        )
        assert len(sorted_entries) == 1

    def test_duplicate_dns(self) -> None:
        """Test sorting with duplicate c.DNs."""
        entries = [
            self.create_entry(
                "cn=test,dc=example,dc=com",
                {c.Names.CN: ["test1"]},
            ),
            self.create_entry(
                "cn=test,dc=example,dc=com",
                {c.Names.CN: ["test2"]},
            ),
        ]
        result = FlextLdifSorting.by_hierarchy(entries)
        sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
            result,
            expected_type=list,
            expected_count=2,
        )
        assert len(sorted_entries) == 2

    def test_unicode_dns(self) -> None:
        """Test sorting with Unicode characters in c.DNs."""
        entries = [
            self.create_entry(
                "cn=日本語,dc=example,dc=com",
                {c.Names.CN: ["日本語"]},
            ),
            self.create_entry(
                "cn=English,dc=example,dc=com",
                {c.Names.CN: ["English"]},
            ),
        ]
        result = FlextLdifSorting.by_hierarchy(entries)
        sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
            result,
            expected_type=list,
            expected_count=2,
        )
        assert len(sorted_entries) == 2

    def test_invalid_sort_target(self) -> None:
        """Test invalid sort_target raises validation error."""
        entries = [
            self.create_entry(
                "cn=test,dc=example,dc=com",
                {c.Names.CN: ["test"]},
            ),
        ]
        with pytest.raises(
            ValidationError,
            match=r"Invalid sort_target.*Valid:.*acl.*attributes.*combined.*entries.*schema",
        ):
            _ = FlextLdifSorting(
                entries=entries,
                sort_target="invalid_target",
            )

    def test_custom_without_predicate(self) -> None:
        """Test custom sort_by without predicate raises validation error."""
        entries = [
            self.create_entry(
                "cn=test,dc=example,dc=com",
                {c.Names.CN: ["test"]},
            ),
        ]
        with pytest.raises(ValidationError, match="custom_predicate required"):
            _ = FlextLdifSorting(
                entries=entries,
                sort_by="custom",
                custom_predicate=None,
            )

    def test_invalid_traversal_raises_error(self) -> None:
        """Test invalid traversal mode raises ValueError."""
        entries = self.Helpers.hierarchy_entries()
        with pytest.raises(ValueError, match="Invalid traversal"):
            _ = FlextLdifSorting(
                entries=entries,
                sort_by=self.Constants.SORT_BY_HIERARCHY,
                traversal="invalid_traversal",
            )

    def test_builder_with_attribute_order(self) -> None:
        """Test builder with custom attribute order."""
        entries = [
            self.create_entry(
                "cn=test,dc=example,dc=com",
                {"zzz": ["z"], "cn": ["test"], "aaa": ["a"]},
            ),
        ]
        result = (
            FlextLdifSorting
            .builder()
            .with_entries(entries)
            .with_strategy(self.Constants.SORT_BY_HIERARCHY)
            .with_target(self.Constants.SORT_TARGET_COMBINED)
            .with_attribute_sorting(order=["cn", "zzz"])
            .execute()
        )
        sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
            result,
            expected_type=list,
            expected_count=1,
        )
        assert sorted_entries[0].attributes is not None
        attrs = sorted_entries[0].attributes.attributes
        attr_names = list(attrs.keys())
        # Verify cn comes before zzz in the sorted order (ignoring other attrs)
        cn_idx = attr_names.index("cn")
        zzz_idx = attr_names.index("zzz")
        assert cn_idx < zzz_idx, f"cn should come before zzz: {attr_names}"

    def test_sort_attributes_in_entries_classmethod(self) -> None:
        """Test sort_attributes_in_entries classmethod."""
        entry = self.create_entry(
            "cn=test,dc=example,dc=com",
            {"zzz": ["z"], "cn": ["test"], "aaa": ["a"]},
        )
        result = FlextLdifSorting.sort_attributes_in_entries(
            [entry],
            order=["cn", "zzz"],
        )
        sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
            result,
            expected_type=list,
            expected_count=1,
        )
        assert sorted_entries[0].attributes is not None
        attrs = sorted_entries[0].attributes.attributes
        attr_names = list(attrs.keys())
        # Verify cn comes before zzz in the sorted order (ignoring other attrs)
        cn_idx = attr_names.index("cn")
        zzz_idx = attr_names.index("zzz")
        assert cn_idx < zzz_idx, f"cn should come before zzz: {attr_names}"

    def test_sort_acl_in_entries_classmethod(self) -> None:
        """Test sort_acl_in_entries classmethod."""
        entry = self.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "acl": ["zzz-rule", "aaa-rule"]},
        )
        result = FlextLdifSorting.sort_acl_in_entries([entry], acl_attrs=["acl"])
        sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
            result,
            expected_type=list,
            expected_count=1,
        )
        assert sorted_entries[0].attributes is not None
        acl_values = sorted_entries[0].attributes.attributes.get("acl", [])
        assert acl_values == sorted(acl_values, key=str.lower)

    def test_by_dn_method(self) -> None:
        """Test _by_dn method via execute."""
        entries = [
            self.create_entry(
                "cn=zzz,dc=example,dc=com",
                {"cn": ["zzz"]},
            ),
            self.create_entry(
                "cn=aaa,dc=example,dc=com",
                {"cn": ["aaa"]},
            ),
        ]
        result = FlextLdifSorting(
            entries=entries,
            sort_by=self.Constants.SORT_BY_DN,
        ).execute()
        sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
            result,
            expected_type=list,
            expected_count=2,
        )
        dns = [e.dn.value.lower() if e.dn else "" for e in sorted_entries]
        assert dns == sorted(dns)

    def test_level_order_traversal(self) -> None:
        """Test hierarchy sorting with level-order traversal."""
        entries = self.Helpers.hierarchy_entries()
        result = FlextLdifSorting(
            entries=entries,
            sort_by=self.Constants.SORT_BY_HIERARCHY,
            traversal="level-order",
        ).execute()
        sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
            result,
            expected_type=list,
        )
        assert len(sorted_entries) == len(entries)

    def test_sort_with_acl_attributes_parameter(self) -> None:
        """Test sort classmethod with ACL attributes parameter."""
        entry = self.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "acl": ["zzz-rule", "aaa-rule"]},
        )
        result = FlextLdifSorting.sort(
            entries=[entry],
            by=self.Constants.SORT_BY_HIERARCHY,
            target=self.Constants.SORT_TARGET_ACL,
            acl_attributes=["acl"],
        )
        sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
            result,
            expected_type=list,
            expected_count=1,
        )
        assert sorted_entries[0].attributes is not None
        acl_values = sorted_entries[0].attributes.attributes.get("acl", [])
        assert acl_values == sorted(acl_values, key=str.lower)

    def test_sort_acl_with_entry_no_attributes(self) -> None:
        """Test ACL sorting with entry that has no attributes."""
        entry = self.create_entry(
            "cn=test,dc=example,dc=com",
            {},
        )
        result = FlextLdifSorting.sort_acl_in_entries([entry], acl_attrs=["acl"])
        sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
            result,
            expected_type=list,
            expected_count=1,
        )
        assert len(sorted_entries) == 1

    def test_sort_attributes_by_order_with_no_order(self) -> None:
        """Test _sort_entry_attributes_by_order with no attribute_order falls back to alphabetical."""
        entry = self.create_entry(
            "cn=test,dc=example,dc=com",
            {"zzz": ["z"], "aaa": ["a"]},
        )
        sorting = FlextLdifSorting(
            entries=[entry],
            sort_target=self.Constants.SORT_TARGET_ATTRIBUTES,
            attribute_order=None,
        )
        result = sorting.execute()
        sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
            result,
            expected_type=list,
            expected_count=1,
        )
        assert sorted_entries[0].attributes is not None
        attrs = sorted_entries[0].attributes.attributes
        attr_names = list(attrs.keys())
        assert attr_names == sorted(attr_names, key=str.lower)

    def test_sort_attributes_by_order_with_no_attributes(self) -> None:
        """Test _sort_entry_attributes_by_order with entry that has no attributes."""
        entry = self.create_entry(
            "cn=test,dc=example,dc=com",
            {},
        )
        sorting = FlextLdifSorting(
            entries=[entry],
            sort_target=self.Constants.SORT_TARGET_ATTRIBUTES,
            attribute_order=["cn"],
        )
        result = sorting.execute()
        sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
            result,
            expected_type=list,
            expected_count=1,
        )
        assert len(sorted_entries) == 1

    def test_hierarchy_with_empty_entries(self) -> None:
        """Test hierarchy sorting with empty entries list."""
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

    def test_hierarchy_with_entry_no_dn(self) -> None:
        """Test hierarchy sorting handles entry without DN (filtered out)."""
        entry = self.create_entry(
            "cn=test,dc=example,dc=com",
            {c.Names.CN: ["test"]},
        )
        # Create entry without DN by manipulating it
        entry_no_dn = entry.model_copy(update={"dn": None})
        result = FlextLdifSorting(
            entries=[entry_no_dn],
            sort_by=self.Constants.SORT_BY_HIERARCHY,
        ).execute()
        sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
            result,
            expected_type=list,
        )
        # Entries without DN are filtered out during tree building
        assert len(sorted_entries) == 0
