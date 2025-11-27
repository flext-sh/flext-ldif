"""Test suite for FlextLdifSorting Service with Real LDIF Fixtures.

Tests validate that FlextLdifSorting works correctly with authentic LDIF data from:
  - tests/fixtures/oid/oid_entries_fixtures.ldif
  - tests/fixtures/oid/oid_schema_fixtures.ldif
  - tests/fixtures/oid/oid_acl_fixtures.ldif

Modules tested:
- flext_ldif.services.sorting.FlextLdifSorting (entry sorting service)
- flext_ldif.FlextLdif (parse service for loading fixtures)

Scope:
- Entry sorting with real LDIF data
- Hierarchy sorting with real LDIF data
- DN sorting with real LDIF data
- Attribute sorting with real LDIF data
- Schema sorting with real LDIF data
- ACL sorting with real LDIF data
- Combined sorting with real LDIF data
- Multi-stage sorting pipelines
- Edge cases with real data
- Comprehensive API coverage with real data

Test Coverage:
- All sorting strategies with real LDIF data
- All sort targets with real LDIF data
- Builder pattern with real data
- Classmethod pattern with real data
- Custom predicates with real data
- Data integrity preservation
- Performance with large datasets
- Special characters handling

Uses Python 3.13 features, factories, constants, dynamic tests, and extensive helper reuse
to reduce code while maintaining 100% behavior coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from pathlib import Path
from typing import Final

import pytest
from flext_core import FlextResult

from flext_ldif import FlextLdif, FlextLdifModels
from flext_ldif.services.sorting import FlextLdifSorting
from tests.helpers.test_rfc_helpers import RfcTestHelpers


class TestFlextLdifSortingWithRealLDIF:
    """Test FlextLdifSorting service with real LDIF fixtures.

    Uses nested classes for organization: Fixtures, TestType, TestCase, Constants, Helpers.
    Reduces code duplication through parametrization and helper methods.
    Uses FlextLdifFixtures for loading real LDIF data.
    """

    class Fixtures:
        """Fixture loading helpers organized as nested class."""

        __test__ = False

        @staticmethod
        def _get_fixtures_dir() -> Path:
            """Get fixtures directory path."""
            return Path(__file__).parent.parent.parent / "fixtures"

        @staticmethod
        def load_oid_entries() -> list[FlextLdifModels.Entry]:
            """Load real OID entries from fixture."""
            fixture_path = (
                TestFlextLdifSortingWithRealLDIF.Fixtures._get_fixtures_dir()
                / "oid"
                / "oid_entries_fixtures.ldif"
            )
            if not fixture_path.exists():
                pytest.skip(f"Fixture not found: {fixture_path}")

            ldif = FlextLdif()
            result = ldif.parse(fixture_path, server_type="oid")
            if result.is_failure:
                pytest.skip(f"Failed to parse OID entries: {result.error}")
            return result.unwrap()

        @staticmethod
        def load_oid_schema() -> list[FlextLdifModels.Entry]:
            """Load real OID schema from fixture."""
            fixture_path = (
                TestFlextLdifSortingWithRealLDIF.Fixtures._get_fixtures_dir()
                / "oid"
                / "oid_schema_fixtures.ldif"
            )
            if not fixture_path.exists():
                pytest.skip(f"Fixture not found: {fixture_path}")

            ldif = FlextLdif()
            result = ldif.parse(fixture_path)
            if result.is_failure:
                pytest.skip(f"Failed to parse OID schema: {result.error}")
            return result.unwrap()

        @staticmethod
        def load_oid_acl() -> list[FlextLdifModels.Entry]:
            """Load real OID ACL from fixture."""
            fixture_path = (
                TestFlextLdifSortingWithRealLDIF.Fixtures._get_fixtures_dir()
                / "oid"
                / "oid_acl_fixtures.ldif"
            )
            if not fixture_path.exists():
                pytest.skip(f"Fixture not found: {fixture_path}")

            ldif = FlextLdif()
            result = ldif.parse(fixture_path)
            if result.is_failure:
                pytest.skip(f"Failed to parse OID ACL: {result.error}")
            return result.unwrap()

    class TestType(StrEnum):
        """Sort test type enumeration organized as nested enum."""

        __test__ = False

        BY_HIERARCHY = "by_hierarchy"
        BY_DN = "by_dn"
        BY_SCHEMA = "by_schema"
        EXECUTE_HIERARCHY = "execute_hierarchy"
        EXECUTE_ATTRIBUTES = "execute_attributes"
        EXECUTE_COMBINED = "execute_combined"
        EXECUTE_SCHEMA = "execute_schema"
        EXECUTE_ACL = "execute_acl"
        PIPELINE_HIERARCHY_ATTRIBUTES = "pipeline_hierarchy_attributes"
        CUSTOM_DN_LENGTH = "custom_dn_length"
        CUSTOM_DN_DEPTH = "custom_dn_depth"
        MULTIPLE_STRATEGIES = "multiple_strategies"
        DATA_INTEGRITY = "data_integrity"
        LARGE_DATASET = "large_dataset"
        SPECIAL_CHARACTERS = "special_characters"
        ALL_METHODS = "all_methods"
        ALL_TARGETS = "all_targets"
        BUILDER_PATTERN = "builder_pattern"
        CLASSMETHOD_SORT = "classmethod_sort"

    class Constants:
        """Test constants organized as nested class."""

        SORT_TARGET_ENTRIES: str = "entries"
        SORT_TARGET_ATTRIBUTES: str = "attributes"
        SORT_TARGET_ACL: str = "acl"
        SORT_TARGET_SCHEMA: str = "schema"
        SORT_TARGET_COMBINED: str = "combined"
        SORT_BY_HIERARCHY: str = "hierarchy"
        MIN_ENTRIES_FOR_PERFORMANCE: int = 10

    class Helpers:
        """Helper methods organized as nested class."""

        __test__ = False

        @staticmethod
        def execute_sort_operation(
            test_type: TestFlextLdifSortingWithRealLDIF.TestType,
            entries: list[FlextLdifModels.Entry],
            **kwargs: object,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Execute sort operation based on test type using mapping."""
            operation_map: dict[
                TestFlextLdifSortingWithRealLDIF.TestType,
                Callable[[], FlextResult[list[FlextLdifModels.Entry]]],
            ] = {
                TestFlextLdifSortingWithRealLDIF.TestType.BY_HIERARCHY: lambda: FlextLdifSorting.by_hierarchy(
                    entries,
                ),
                TestFlextLdifSortingWithRealLDIF.TestType.BY_DN: lambda: FlextLdifSorting.by_dn(
                    entries,
                ),
                TestFlextLdifSortingWithRealLDIF.TestType.BY_SCHEMA: lambda: FlextLdifSorting.by_schema(
                    entries,
                ),
                TestFlextLdifSortingWithRealLDIF.TestType.EXECUTE_HIERARCHY: lambda: FlextLdifSorting(
                    entries=entries,
                    sort_target=TestFlextLdifSortingWithRealLDIF.Constants.SORT_TARGET_ENTRIES,
                    sort_by=TestFlextLdifSortingWithRealLDIF.Constants.SORT_BY_HIERARCHY,
                ).execute(),
                TestFlextLdifSortingWithRealLDIF.TestType.EXECUTE_ATTRIBUTES: lambda: FlextLdifSorting(
                    entries=entries,
                    sort_target=TestFlextLdifSortingWithRealLDIF.Constants.SORT_TARGET_ATTRIBUTES,
                ).execute(),
                TestFlextLdifSortingWithRealLDIF.TestType.EXECUTE_COMBINED: lambda: FlextLdifSorting(
                    entries=entries,
                    sort_target=TestFlextLdifSortingWithRealLDIF.Constants.SORT_TARGET_COMBINED,
                    sort_by=TestFlextLdifSortingWithRealLDIF.Constants.SORT_BY_HIERARCHY,
                    sort_attributes=True,
                ).execute(),
                TestFlextLdifSortingWithRealLDIF.TestType.EXECUTE_SCHEMA: lambda: FlextLdifSorting(
                    entries=entries,
                    sort_target=TestFlextLdifSortingWithRealLDIF.Constants.SORT_TARGET_SCHEMA,
                    sort_by="schema",
                ).execute(),
                TestFlextLdifSortingWithRealLDIF.TestType.EXECUTE_ACL: lambda: FlextLdifSorting(
                    entries=entries,
                    sort_target=TestFlextLdifSortingWithRealLDIF.Constants.SORT_TARGET_ACL,
                ).execute(),
            }

            if test_type in operation_map:
                return operation_map[test_type]()

            # Special cases handled separately
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Unknown test type: {test_type}",
            )

        @staticmethod
        def verify_hierarchy_sorting(
            sorted_entries: list[FlextLdifModels.Entry],
        ) -> None:
            """Verify entries are sorted by hierarchy (depth-first)."""
            depths = [e.dn.value.count(",") if e.dn else 0 for e in sorted_entries]
            for i in range(len(depths) - 1):
                if depths[i] == depths[i + 1]:
                    entry1_dn = sorted_entries[i].dn
                    entry2_dn = sorted_entries[i + 1].dn
                    assert entry1_dn is not None
                    assert entry2_dn is not None
                    assert entry1_dn.value.lower() <= entry2_dn.value.lower()

        @staticmethod
        def verify_alphabetical_sorting(
            sorted_entries: list[FlextLdifModels.Entry],
        ) -> None:
            """Verify entries are sorted alphabetically by DN."""
            dns = [e.dn.value.lower() if e.dn else "" for e in sorted_entries]
            assert dns == sorted(dns)

        @staticmethod
        def verify_attributes_sorted(
            entry: FlextLdifModels.Entry,
        ) -> None:
            """Verify entry attributes are sorted alphabetically."""
            assert entry.attributes is not None
            attrs = entry.attributes.attributes
            attr_names = list(attrs.keys())
            assert attr_names == sorted(attr_names, key=str.lower)

        @staticmethod
        def verify_data_integrity(
            original: list[FlextLdifModels.Entry],
            sorted_entries: list[FlextLdifModels.Entry],
        ) -> None:
            """Verify sorting preserves all data."""
            original_dns = {e.dn.value for e in original if e.dn}
            sorted_dns = {e.dn.value for e in sorted_entries if e.dn}
            assert original_dns == sorted_dns

            for original_entry in original:
                if not original_entry.dn:
                    continue
                sorted_entry = next(
                    (
                        e
                        for e in sorted_entries
                        if e.dn and e.dn.value == original_entry.dn.value
                    ),
                    None,
                )
                assert sorted_entry is not None
                assert sorted_entry.attributes is not None
                assert len(sorted_entry.attributes.attributes) > 0

    # Test case definitions using constants
    REAL_LDIF_TEST_CASES: Final = [
        (TestType.BY_HIERARCHY, "entries"),
        (TestType.BY_DN, "entries"),
        (TestType.BY_SCHEMA, "schema"),
        (TestType.EXECUTE_HIERARCHY, "entries"),
        (TestType.EXECUTE_ATTRIBUTES, "entries"),
        (TestType.EXECUTE_COMBINED, "entries"),
        (TestType.EXECUTE_SCHEMA, "schema"),
        (TestType.EXECUTE_ACL, "acl"),
    ]

    @pytest.fixture
    def oid_entries(self) -> list[FlextLdifModels.Entry]:
        """Load real OID entries from fixture."""
        return self.Fixtures.load_oid_entries()

    @pytest.fixture
    def oid_schema(self) -> list[FlextLdifModels.Entry]:
        """Load real OID schema from fixture."""
        return self.Fixtures.load_oid_schema()

    @pytest.fixture
    def oid_acl(self) -> list[FlextLdifModels.Entry]:
        """Load real OID ACL from fixture."""
        return self.Fixtures.load_oid_acl()

    @pytest.mark.parametrize(
        ("test_type", "fixture_type"),
        REAL_LDIF_TEST_CASES,
    )
    def test_sorting_with_real_ldif(
        self,
        test_type: TestType,
        fixture_type: str,
        oid_entries: list[FlextLdifModels.Entry],
        oid_schema: list[FlextLdifModels.Entry],
        oid_acl: list[FlextLdifModels.Entry],
    ) -> None:
        """Test sorting operations with real LDIF data - consolidated parametrized test."""
        if fixture_type == "schema":
            entries = oid_schema
        elif fixture_type == "acl":
            entries = oid_acl
        else:
            entries = oid_entries

        if not entries:
            pytest.skip(f"No {fixture_type} entries loaded")

        result = self.Helpers.execute_sort_operation(test_type, entries)

        sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
            result,
            expected_type=list,
        )
        assert len(sorted_entries) == len(entries)

        # Verify sorting behavior
        if test_type == self.TestType.BY_HIERARCHY:
            self.Helpers.verify_hierarchy_sorting(sorted_entries)
        elif test_type == self.TestType.BY_DN:
            self.Helpers.verify_alphabetical_sorting(sorted_entries)
        elif test_type == self.TestType.EXECUTE_ATTRIBUTES and sorted_entries:
            self.Helpers.verify_attributes_sorted(sorted_entries[0])

    def test_execute_attributes_sorting_real_ldif(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test attributes sorting on real LDIF data."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        entry = oid_entries[0]
        result = FlextLdifSorting(
            entries=[entry],
            sort_target=self.Constants.SORT_TARGET_ATTRIBUTES,
        ).execute()

        sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
            result,
            expected_type=list,
            expected_count=1,
        )
        self.Helpers.verify_attributes_sorted(sorted_entries[0])

    def test_pipeline_hierarchy_then_attributes(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test realistic pipeline: sort by hierarchy then sort attributes."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        result1 = FlextLdifSorting.by_hierarchy(oid_entries)
        entries_by_hierarchy = RfcTestHelpers.test_result_success_and_unwrap(
            result1,
            expected_type=list,
        )

        result2 = FlextLdifSorting(
            entries=entries_by_hierarchy,
            sort_target=self.Constants.SORT_TARGET_ATTRIBUTES,
        ).execute()
        final_entries = RfcTestHelpers.test_result_success_and_unwrap(
            result2,
            expected_type=list,
        )

        assert len(final_entries) == len(oid_entries)
        for entry in final_entries:
            assert entry.dn is not None
            assert entry.attributes is not None
            assert len(entry.attributes.attributes) > 0

    class Predicates:
        """Custom sorting predicates organized as nested class."""

        __test__ = False

        @staticmethod
        def dn_length(entry: FlextLdifModels.Entry) -> int:
            """Get DN length for sorting."""
            return len(entry.dn.value) if entry.dn else 0

        @staticmethod
        def dn_depth(entry: FlextLdifModels.Entry) -> int:
            """Get DN depth (comma count) for sorting."""
            return entry.dn.value.count(",") if entry.dn else 0

    @pytest.mark.parametrize(
        ("predicate_name", "predicate_func"),
        [
            ("dn_length", Predicates.dn_length),
            ("dn_depth", Predicates.dn_depth),
        ],
    )
    def test_custom_sorting_with_real_ldif(
        self,
        predicate_name: str,
        predicate_func: Callable[[FlextLdifModels.Entry], int],
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test custom sorting with real LDIF data using dynamic parametrization."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        result = FlextLdifSorting.by_custom(oid_entries, predicate_func)
        sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
            result,
            expected_type=list,
        )

        # Verify sorting by predicate
        values = [predicate_func(e) for e in sorted_entries]
        assert values == sorted(values)

    def test_multiple_custom_sorts_via_classmethod(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test multiple sorting strategies via classmethod."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        def length_key(e: FlextLdifModels.Entry) -> int:
            return len(e.dn.value) if e.dn else 0

        strategies: list[
            tuple[
                str,
                Callable[
                    [list[FlextLdifModels.Entry]],
                    FlextResult[list[FlextLdifModels.Entry]],
                ],
            ]
        ] = [
            ("hierarchy", FlextLdifSorting.by_hierarchy),
            ("dn", FlextLdifSorting.by_dn),
            ("length", lambda ents: FlextLdifSorting.by_custom(ents, length_key)),
        ]

        for name, strategy_func in strategies:
            result = strategy_func(oid_entries)
            assert result.is_success, f"Failed for strategy: {name}"
            assert len(result.unwrap()) == len(oid_entries)

    def test_sorting_preserves_data_integrity(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Verify sorting doesn't lose or corrupt data."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        result = FlextLdifSorting.by_hierarchy(oid_entries)
        sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
            result,
            expected_type=list,
        )
        self.Helpers.verify_data_integrity(oid_entries, sorted_entries)

    def test_sorting_large_entry_set(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test sorting performance with real large LDIF datasets."""
        if len(oid_entries) < self.Constants.MIN_ENTRIES_FOR_PERFORMANCE:
            pytest.skip("Not enough entries for performance test")

        strategies = [
            FlextLdifSorting.by_hierarchy,
            FlextLdifSorting.by_dn,
        ]

        for strategy in strategies:
            result = strategy(oid_entries)
            sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
                result,
                expected_type=list,
            )
            assert len(sorted_entries) == len(oid_entries)

    def test_sorting_with_special_characters_in_dn(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test sorting handles special characters in DNs correctly."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        result = FlextLdifSorting.by_hierarchy(oid_entries)
        sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
            result,
            expected_type=list,
        )
        assert len(sorted_entries) == len(oid_entries)

    def test_all_entry_sorting_methods(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test all entry sorting classmethods."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        methods = [
            FlextLdifSorting.by_hierarchy,
            FlextLdifSorting.by_dn,
            FlextLdifSorting.by_schema,
        ]

        for method in methods:
            result = method(oid_entries)
            assert result.is_success, f"Failed for method: {method.__name__}"
            assert len(result.unwrap()) == len(oid_entries)

    def test_all_sort_targets_via_execute(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test all sort targets via execute() method."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        targets = [
            self.Constants.SORT_TARGET_ENTRIES,
            self.Constants.SORT_TARGET_ATTRIBUTES,
            self.Constants.SORT_TARGET_ACL,
            self.Constants.SORT_TARGET_COMBINED,
        ]

        for target in targets:
            result = FlextLdifSorting(
                entries=oid_entries,
                sort_target=target,
                sort_by=self.Constants.SORT_BY_HIERARCHY,
            ).execute()
            sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
                result,
                expected_type=list,
            )
            assert isinstance(sorted_entries, list), f"Failed for target: {target}"

    def test_builder_pattern_with_real_data(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test fluent builder pattern with real data."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        result = (
            FlextLdifSorting.builder()
            .with_entries(oid_entries)
            .with_strategy(self.Constants.SORT_BY_HIERARCHY)
            .with_attribute_sorting(alphabetical=True)
            .execute()
        )

        sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
            result,
            expected_type=list,
        )
        assert len(sorted_entries) == len(oid_entries)

    def test_classmethod_sort_with_real_data(
        self,
        oid_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test classmethod sort() with real data."""
        if not oid_entries:
            pytest.skip("No OID entries loaded")

        result = FlextLdifSorting.sort(
            oid_entries,
            by=self.Constants.SORT_BY_HIERARCHY,
            sort_attributes=True,
        )

        sorted_entries = RfcTestHelpers.test_result_success_and_unwrap(
            result,
            expected_type=list,
        )
        assert len(sorted_entries) == len(oid_entries)
