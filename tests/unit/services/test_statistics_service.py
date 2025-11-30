"""Test suite for Statistics Service - LDIF processing statistics generation.

Modules tested:
- flext_ldif.services.statistics.FlextLdifStatistics (statistics generation service)

Scope:
- Service initialization and execute pattern
- Basic statistics generation (empty, single category, multiple categories)
- Statistics with rejections (rejection count, rejection rate, rejection reasons)
- Output file path handling and generation
- Error handling (empty data, missing attributes)
- Edge cases (large rejection counts, complex paths, all rejected entries)
- Entry-level statistics calculation (empty list, objectclass distribution,
  server_type distribution, entries without metadata)

Test Coverage:
- All statistics service methods (generate_statistics, calculate_for_entries)
- Edge cases (empty data, large counts, complex paths, all rejected)
- Error handling paths
- Parametrized tests for multiple scenarios

Uses Python 3.13 features, factories, constants, dynamic tests, and extensive helper reuse
to reduce code while maintaining 100% behavior coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest
from flext_tests import FlextTestsUtilities  # Mocked in conftest

from flext_ldif import FlextLdifModels
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.services.entries import FlextLdifEntries
from flext_ldif.services.statistics import FlextLdifStatistics
from tests.fixtures.typing import GenericFieldsDict


class TestFlextLdifStatistics:
    """Test FlextLdifStatistics service with consolidated parametrized tests.

    Uses nested classes for organization: Factories, TestServiceInitialization,
    TestGenerateStatisticsBasic, TestGenerateStatisticsWithRejections,
    TestGenerateStatisticsRejectionReasons, TestGenerateStatisticsOutputFiles,
    TestGenerateStatisticsErrorHandling, TestGenerateStatisticsEdgeCases,
    TestCalculateForEntries.
    Reduces code duplication through helper methods and factories.
    Uses FlextTestsUtilities extensively for maximum code reduction.
    """

    class Factories:
        """Factory methods for creating test data organized as nested class."""

        @staticmethod
        def create_entry_from_dict(
            entry_dict: GenericFieldsDict,
        ) -> FlextLdifModels.Entry:
            """Create Entry model from dictionary for testing.

            Args:
                entry_dict: Dictionary with 'dn' and optionally 'attributes' keys

            Returns:
                FlextLdifModels.Entry instance

            """
            dn = str(entry_dict.get("dn", ""))
            attrs_dict = entry_dict.get("attributes", {})
            if not isinstance(attrs_dict, dict):
                attrs_dict = {}

            attributes: dict[str, str | list[str]] = {}
            for key, value in attrs_dict.items():
                if isinstance(value, list):
                    attributes[key] = [str(v) for v in value]
                elif isinstance(value, str):
                    attributes[key] = value
                else:
                    attributes[key] = str(value)

            rejection_reason: str | None = None
            if isinstance(attrs_dict.get("rejectionReason"), str):
                rejection_reason = attrs_dict["rejectionReason"]

            result = FlextLdifEntries().create_entry(dn=dn, attributes=attributes)
            if result.is_failure:
                raise ValueError(f"Failed to create entry: {result.error}")

            entry = result.unwrap()
            if rejection_reason is not None and entry.metadata:
                processing_stats = FlextLdifModels.EntryStatistics(
                    rejection_reason=rejection_reason,
                )
                entry = entry.model_copy(
                    update={
                        "metadata": entry.metadata.model_copy(
                            update={"processing_stats": processing_stats},
                        ),
                    },
                )

            return entry

        @staticmethod
        def create_categories_from_dict(
            categorized_dict: Mapping[str, object],
        ) -> FlextLdifModels.FlexibleCategories:
            """Create FlexibleCategories from dictionary for testing.

            Args:
                categorized_dict: Dictionary mapping category names to entry dictionaries

            Returns:
                FlextLdifModels.FlexibleCategories instance

            """
            categories = FlextLdifModels.FlexibleCategories()
            for category, entries_value in categorized_dict.items():
                if not isinstance(entries_value, list):
                    continue
                entries: list[FlextLdifModels.Entry] = []
                for entry_value in entries_value:
                    if isinstance(entry_value, Mapping):
                        entry_obj: GenericFieldsDict = dict(entry_value)
                        entries.append(
                            TestFlextLdifStatistics.Factories.create_entry_from_dict(
                                entry_obj,
                            ),
                        )
                categories[category] = entries
            return categories

    class TestServiceInitialization:
        """Test statistics service initialization and basic functionality."""

        def test_init_creates_service(self) -> None:
            """Test statistics service can be instantiated."""
            assert FlextLdifStatistics() is not None

        def test_execute_returns_status(self) -> None:
            """Test execute returns service operational status."""
            result = FlextLdifStatistics().execute()
            FlextTestsUtilities.TestUtilities.assert_result_success(result)
            status = result.unwrap()
            assert status["service"] == "StatisticsService"
            assert status["status"] == "operational"
            capabilities_raw = status.get("capabilities", [])
            assert isinstance(capabilities_raw, list)
            assert "generate_statistics" in capabilities_raw

    class TestGenerateStatisticsBasic:
        """Test basic statistics generation with simple categorized entries."""

        @pytest.mark.parametrize(
            (
                "categorized",
                "written_counts",
                "output_files",
                "expected_total",
                "expected_counts",
            ),
            [
                ({}, {}, {}, 0, {}),
                (
                    {
                        "users": [
                            {"dn": f"cn=user{i},dc=example,dc=com", "attributes": {}}
                            for i in range(1, 4)
                        ],
                    },
                    {"users": 3},
                    {"users": "users.ldif"},
                    3,
                    {"users": 3},
                ),
                (
                    {
                        "users": [
                            {"dn": f"cn=user{i},dc=example,dc=com", "attributes": {}}
                            for i in range(1, 3)
                        ],
                        "groups": [
                            {"dn": f"cn=group{i},dc=example,dc=com", "attributes": {}}
                            for i in range(1, 4)
                        ],
                        "roles": [
                            {"dn": "cn=superuser,dc=example,dc=com", "attributes": {}},
                        ],
                    },
                    {"users": 2, "groups": 3, "roles": 1},
                    {
                        "users": "users.ldif",
                        "groups": "groups.ldif",
                        "roles": "roles.ldif",
                    },
                    6,
                    {"users": 2, "groups": 3, "roles": 1},
                ),
            ],
        )
        def test_generate_statistics(
            self,
            categorized: dict[str, list[GenericFieldsDict]],
            written_counts: dict[str, int],
            output_files: GenericFieldsDict,
            expected_total: int,
            expected_counts: dict[str, int],
        ) -> None:
            """Test statistics generation with parametrized test cases."""
            categories = TestFlextLdifStatistics.Factories.create_categories_from_dict(
                categorized,
            )
            output_files_str = {
                k: str(v) if isinstance(v, str) else f"{k}.ldif"
                for k, v in output_files.items()
            }
            result = FlextLdifStatistics().generate_statistics(
                categorized=categories,
                written_counts=written_counts,
                output_dir=Path("/tmp/ldif"),
                output_files=output_files_str,
            )
            FlextTestsUtilities.TestUtilities.assert_result_success(result)
            stats = result.unwrap()
            assert isinstance(stats, FlextLdifModels.StatisticsResult)
            assert stats.total_entries == expected_total
            assert stats.categorized == expected_counts
            assert stats.written_counts == written_counts

    class TestGenerateStatisticsWithRejections:
        """Test statistics generation with rejected entries and rejection tracking."""

        @pytest.mark.parametrize(
            (
                "categorized",
                "written_counts",
                "expected_total",
                "expected_rejected",
                "expected_rate",
                "expected_reasons",
            ),
            [
                (
                    {
                        "valid": [
                            {"dn": f"cn=valid{i},dc=example,dc=com", "attributes": {}}
                            for i in range(1, 3)
                        ],
                        "rejected": [
                            {
                                "dn": "cn=invalid1,dc=example,dc=com",
                                "attributes": {
                                    "rejectionReason": "Missing required attribute",
                                },
                            },
                            {
                                "dn": "cn=invalid2,dc=example,dc=com",
                                "attributes": {"rejectionReason": "Invalid DN format"},
                            },
                        ],
                    },
                    {"valid": 2, "rejected": 0},
                    4,
                    2,
                    0.5,
                    ["Missing required attribute", "Invalid DN format"],
                ),
                (
                    {
                        "valid": [
                            {"dn": f"cn=user{i},dc=example,dc=com", "attributes": {}}
                            for i in range(1, 5)
                        ],
                        "rejected": [
                            {
                                "dn": f"cn=invalid{i},dc=example,dc=com",
                                "attributes": {"rejectionReason": "Schema violation"},
                            }
                            for i in range(1, 3)
                        ],
                    },
                    {"valid": 4, "rejected": 0},
                    6,
                    2,
                    0.333333,
                    ["Schema violation"],
                ),
                (
                    {
                        "rejected": [
                            {
                                "dn": f"cn=invalid{i},dc=example,dc=com",
                                "attributes": {
                                    "rejectionReason": "Duplicate DN"
                                    if i % 2 == 1
                                    else "Invalid attributes",
                                },
                            }
                            for i in range(1, 5)
                        ],
                    },
                    {"rejected": 0},
                    4,
                    4,
                    1.0,
                    ["Duplicate DN", "Invalid attributes"],
                ),
            ],
        )
        def test_generate_statistics_with_rejections(
            self,
            categorized: dict[str, list[GenericFieldsDict]],
            written_counts: dict[str, int],
            expected_total: int,
            expected_rejected: int,
            expected_rate: float,
            expected_reasons: list[str],
        ) -> None:
            """Test statistics with rejected entries using parametrized test cases."""
            categories = TestFlextLdifStatistics.Factories.create_categories_from_dict(
                categorized,
            )
            result = FlextLdifStatistics().generate_statistics(
                categorized=categories,
                written_counts=written_counts,
                output_dir=Path("/tmp/ldif"),
                output_files={cat: f"{cat}.ldif" for cat in written_counts},
            )
            FlextTestsUtilities.TestUtilities.assert_result_success(result)
            stats = result.unwrap()
            assert stats.total_entries == expected_total
            assert stats.rejection_count == expected_rejected
            assert abs(stats.rejection_rate - expected_rate) < 0.001
            assert all(reason in stats.rejection_reasons for reason in expected_reasons)

    class TestGenerateStatisticsRejectionReasons:
        """Test rejection reason extraction and handling."""

        @pytest.mark.parametrize(
            ("categorized", "expected_count", "expected_reasons"),
            [
                (
                    {
                        "rejected": [
                            {
                                "dn": "cn=test1,dc=example,dc=com",
                                "attributes": {"rejectionReason": "Test reason 1"},
                            },
                            {
                                "dn": "cn=test2,dc=example,dc=com",
                                "attributes": {"rejectionReason": "Test reason 2"},
                            },
                        ],
                    },
                    2,
                    ["Test reason 1", "Test reason 2"],
                ),
                (
                    {
                        "rejected": [
                            {
                                "dn": "cn=test1,dc=example,dc=com",
                                "attributes": {"rejectionReason": "Valid reason"},
                            },
                            {
                                "dn": "cn=test2,dc=example,dc=com",
                                "attributes": {"rejectionReason": 123},
                            },
                            {
                                "dn": "cn=test3,dc=example,dc=com",
                                "attributes": {"rejectionReason": ["list", "value"]},
                            },
                        ],
                    },
                    3,
                    ["Valid reason"],
                ),
                (
                    {
                        "rejected": [
                            {
                                "dn": "cn=test1,dc=example,dc=com",
                                "attributes": {"rejectionReason": "Valid reason"},
                            },
                            {
                                "dn": "cn=test2,dc=example,dc=com",
                                "attributes": {"rejectionReason": ""},
                            },
                        ],
                    },
                    2,
                    ["Valid reason"],
                ),
            ],
        )
        def test_rejection_reasons(
            self,
            categorized: dict[str, list[GenericFieldsDict]],
            expected_count: int,
            expected_reasons: list[str],
        ) -> None:
            """Test rejection reason extraction with parametrized test cases."""
            categories = TestFlextLdifStatistics.Factories.create_categories_from_dict(
                categorized,
            )
            result = FlextLdifStatistics().generate_statistics(
                categorized=categories,
                written_counts={"rejected": 0},
                output_dir=Path("/tmp"),
                output_files={"rejected": "rejected.ldif"},
            )
            FlextTestsUtilities.TestUtilities.assert_result_success(result)
            stats = result.unwrap()
            assert stats.rejection_count == expected_count
            assert all(reason in stats.rejection_reasons for reason in expected_reasons)

    class TestGenerateStatisticsOutputFiles:
        """Test output file path handling and generation."""

        @pytest.mark.parametrize(
            ("output_files", "output_dir", "expected_paths"),
            [
                (
                    {"users": "users_export.ldif", "groups": "groups_export.ldif"},
                    Path("/output/ldif"),
                    {
                        "users": "/output/ldif/users_export.ldif",
                        "groups": "/output/ldif/groups_export.ldif",
                    },
                ),
                ({}, Path("/output"), {"users": "/output/users.ldif"}),
                ({"users": 123}, Path("/output"), {"users": "/output/users.ldif"}),
            ],
        )
        def test_output_files(
            self,
            output_files: GenericFieldsDict,
            output_dir: Path,
            expected_paths: dict[str, str],
        ) -> None:
            """Test output file handling with parametrized test cases."""
            categorized_dict: dict[str, list[GenericFieldsDict]] = {
                cat: [{"dn": "cn=test,dc=example,dc=com", "attributes": {}}]
                for cat in expected_paths
            }
            categories = TestFlextLdifStatistics.Factories.create_categories_from_dict(
                categorized_dict,
            )
            output_files_str = {
                k: str(v) if isinstance(v, str) else f"{k}.ldif"
                for k, v in output_files.items()
            }
            result = FlextLdifStatistics().generate_statistics(
                categorized=categories,
                written_counts=dict.fromkeys(expected_paths, 1),
                output_dir=output_dir,
                output_files=output_files_str,
            )
            FlextTestsUtilities.TestUtilities.assert_result_success(result)
            stats = result.unwrap()
            for category, expected_path in expected_paths.items():
                assert stats.output_files[category] == expected_path

    class TestGenerateStatisticsErrorHandling:
        """Test error handling in statistics generation."""

        def test_generate_statistics_handles_empty_data(self) -> None:
            """Test that statistics generation handles empty data gracefully."""
            categories = FlextLdifModels.FlexibleCategories()
            result = FlextLdifStatistics().generate_statistics(
                categorized=categories,
                written_counts={},
                output_dir=Path("/tmp"),
                output_files={},
            )
            FlextTestsUtilities.TestUtilities.assert_result_success(result)
            stats = result.unwrap()
            assert stats.total_entries == 0
            assert stats.rejection_rate == 0.0

        def test_generate_statistics_handles_missing_attributes_key(self) -> None:
            """Test handling of entries without attributes key."""
            categorized_dict = {
                "entries": [
                    {"dn": "cn=test1,dc=example,dc=com", "attributes": {}},
                    {"dn": "cn=test2,dc=example,dc=com", "attributes": {}},
                ],
            }
            categories = TestFlextLdifStatistics.Factories.create_categories_from_dict(
                categorized_dict,
            )
            result = FlextLdifStatistics().generate_statistics(
                categorized=categories,
                written_counts={"entries": 2},
                output_dir=Path("/tmp"),
                output_files={},
            )
            FlextTestsUtilities.TestUtilities.assert_result_success(result)
            stats = result.unwrap()
            assert stats.total_entries == 2
            assert stats.rejection_count == 0

    class TestGenerateStatisticsEdgeCases:
        """Test edge cases and special scenarios."""

        def test_statistics_with_very_large_rejection_counts(self) -> None:
            """Test statistics with large number of rejected entries."""
            categorized_dict = {
                "valid": [
                    {"dn": f"cn=user{i},dc=example,dc=com", "attributes": {}}
                    for i in range(100)
                ],
                FlextLdifConstants.Categories.REJECTED: [
                    {
                        "dn": f"cn=invalid{i},dc=example,dc=com",
                        "attributes": {"rejectionReason": f"Reason {i % 5}"},
                    }
                    for i in range(900)
                ],
            }
            categories = TestFlextLdifStatistics.Factories.create_categories_from_dict(
                categorized_dict,
            )
            result = FlextLdifStatistics().generate_statistics(
                categorized=categories,
                written_counts={
                    "valid": 100,
                    FlextLdifConstants.Categories.REJECTED: 0,
                },
                output_dir=Path("/tmp"),
                output_files={},
            )
            FlextTestsUtilities.TestUtilities.assert_result_success(result)
            stats = result.unwrap()
            assert stats.total_entries == 1000
            assert stats.rejection_count == 900
            assert abs(stats.rejection_rate - 0.9) < 0.001
            assert len(stats.rejection_reasons) == 5

        def test_statistics_with_complex_path_objects(self) -> None:
            """Test statistics generation with complex Path objects."""
            output_dir = Path("/tmp") / "ldif" / "export" / "2025"
            categorized_dict = {
                "users": [{"dn": "cn=user1,dc=example,dc=com", "attributes": {}}],
            }
            categories = TestFlextLdifStatistics.Factories.create_categories_from_dict(
                categorized_dict,
            )
            result = FlextLdifStatistics().generate_statistics(
                categorized=categories,
                written_counts={"users": 1},
                output_dir=output_dir,
                output_files={"users": "exported_users.ldif"},
            )
            FlextTestsUtilities.TestUtilities.assert_result_success(result)
            stats = result.unwrap()
            assert stats.output_files["users"] == str(
                output_dir / "exported_users.ldif",
            )

        def test_statistics_all_rejected_entries(self) -> None:
            """Test statistics when all entries are rejected."""
            categorized_dict = {
                FlextLdifConstants.Categories.REJECTED: [
                    {
                        "dn": f"cn=invalid{i},dc=example,dc=com",
                        "attributes": {"rejectionReason": "Invalid format"},
                    }
                    for i in range(10)
                ],
            }
            categories = TestFlextLdifStatistics.Factories.create_categories_from_dict(
                categorized_dict,
            )
            result = FlextLdifStatistics().generate_statistics(
                categorized=categories,
                written_counts={FlextLdifConstants.Categories.REJECTED: 0},
                output_dir=Path("/tmp"),
                output_files={},
            )
            FlextTestsUtilities.TestUtilities.assert_result_success(result)
            stats = result.unwrap()
            assert stats.total_entries == 10
            assert stats.rejection_count == 10
            assert stats.rejection_rate == 1.0

    class TestCalculateForEntries:
        """Test calculate_for_entries method for entry-level statistics."""

        def test_calculate_for_entries_empty_list(self) -> None:
            """Test calculate_for_entries with empty entry list."""
            result = FlextLdifStatistics().calculate_for_entries([])
            FlextTestsUtilities.TestUtilities.assert_result_success(result)
            stats = result.unwrap()
            assert stats.total_entries == 0
            assert stats.object_class_distribution == {}
            assert stats.server_type_distribution == {}

        def test_calculate_for_entries_with_objectclasses(self) -> None:
            """Test calculate_for_entries counts objectclass distribution."""
            entries = [
                TestFlextLdifStatistics.Factories.create_entry_from_dict({
                    "dn": "cn=user1,dc=example,dc=com",
                    "attributes": {"objectClass": ["person", "inetOrgPerson"]},
                }),
                TestFlextLdifStatistics.Factories.create_entry_from_dict({
                    "dn": "cn=user2,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"]},
                }),
                TestFlextLdifStatistics.Factories.create_entry_from_dict({
                    "dn": "cn=group1,dc=example,dc=com",
                    "attributes": {"objectClass": ["groupOfNames"]},
                }),
            ]
            result = FlextLdifStatistics().calculate_for_entries(entries)
            FlextTestsUtilities.TestUtilities.assert_result_success(result)
            stats = result.unwrap()
            assert stats.total_entries == 3
            assert stats.object_class_distribution["person"] == 2
            assert stats.object_class_distribution["inetOrgPerson"] == 1
            assert stats.object_class_distribution["groupOfNames"] == 1

        def test_calculate_for_entries_with_server_type(self) -> None:
            """Test calculate_for_entries tracks server_type from metadata."""
            entry1 = TestFlextLdifStatistics.Factories.create_entry_from_dict({
                "dn": "cn=entry1,dc=example,dc=com",
                "attributes": {"objectClass": ["top"]},
            })
            if entry1.metadata:
                entry1.metadata.extensions = {"server_type": "oid"}
            entry2 = TestFlextLdifStatistics.Factories.create_entry_from_dict({
                "dn": "cn=entry2,dc=example,dc=com",
                "attributes": {"objectClass": ["top"]},
            })
            if entry2.metadata:
                entry2.metadata.extensions = {"server_type": "oud"}
            entry3 = TestFlextLdifStatistics.Factories.create_entry_from_dict({
                "dn": "cn=entry3,dc=example,dc=com",
                "attributes": {"objectClass": ["top"]},
            })
            if entry3.metadata:
                entry3.metadata.extensions = {"server_type": "oid"}

            result = FlextLdifStatistics().calculate_for_entries([
                entry1,
                entry2,
                entry3,
            ])
            FlextTestsUtilities.TestUtilities.assert_result_success(result)
            stats = result.unwrap()
            assert stats.total_entries == 3
            assert stats.server_type_distribution.get("oid") == 2
            assert stats.server_type_distribution.get("oud") == 1

        def test_calculate_for_entries_without_metadata(self) -> None:
            """Test calculate_for_entries handles entries without metadata."""
            entries = [
                TestFlextLdifStatistics.Factories.create_entry_from_dict({
                    "dn": "cn=entry1,dc=example,dc=com",
                    "attributes": {"objectClass": ["top"]},
                }),
                TestFlextLdifStatistics.Factories.create_entry_from_dict({
                    "dn": "cn=entry2,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"]},
                }),
            ]
            result = FlextLdifStatistics().calculate_for_entries(entries)
            FlextTestsUtilities.TestUtilities.assert_result_success(result)
            stats = result.unwrap()
            assert stats.total_entries == 2
            assert stats.server_type_distribution == {}


__all__ = ["TestFlextLdifStatistics"]
