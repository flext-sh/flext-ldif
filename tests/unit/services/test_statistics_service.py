"""Test suite for Statistics Service - LDIF processing statistics generation.

Modules tested: FlextLdifStatistics
Scope: Statistics generation, categorized entries, rejections, output files,
error handling, edge cases

Tests statistics generation for categorized and migrated LDIF entries
with comprehensive coverage of all calculation and reporting functionality.
Uses parametrized tests and factory patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path

import pytest
from flext_tests import FlextTestsUtilities

from flext_ldif import FlextLdifModels
from flext_ldif.services.statistics import FlextLdifStatistics


class TestStatisticsServiceInitialization:
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
                {"users": "users.ldif", "groups": "groups.ldif", "roles": "roles.ldif"},
                6,
                {"users": 2, "groups": 3, "roles": 1},
            ),
        ],
    )
    def test_generate_statistics(
        self,
        categorized: dict[str, list[dict[str, object]]],
        written_counts: dict[str, int],
        output_files: dict[str, object],
        expected_total: int,
        expected_counts: dict[str, int],
    ) -> None:
        """Test statistics generation with parametrized test cases."""
        result = FlextLdifStatistics().generate_statistics(
            categorized=categorized,
            written_counts=written_counts,
            output_dir=Path("/tmp/ldif"),
            output_files=output_files,
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
        categorized: dict[str, list[dict[str, object]]],
        written_counts: dict[str, int],
        expected_total: int,
        expected_rejected: int,
        expected_rate: float,
        expected_reasons: list[str],
    ) -> None:
        """Test statistics with rejected entries using parametrized test cases."""
        result = FlextLdifStatistics().generate_statistics(
            categorized=categorized,
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
                ["Valid reason", ""],
            ),
        ],
    )
    def test_rejection_reasons(
        self,
        categorized: dict[str, list[dict[str, object]]],
        expected_count: int,
        expected_reasons: list[str],
    ) -> None:
        """Test rejection reason extraction with parametrized test cases."""
        result = FlextLdifStatistics().generate_statistics(
            categorized=categorized,
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
        output_files: dict[str, object],
        output_dir: Path,
        expected_paths: dict[str, str],
    ) -> None:
        """Test output file handling with parametrized test cases."""
        categorized: dict[str, list[dict[str, object]]] = {
            cat: [{"dn": "cn=test,dc=example,dc=com", "attributes": {}}]
            for cat in expected_paths
        }
        result = FlextLdifStatistics().generate_statistics(
            categorized=categorized,
            written_counts=dict.fromkeys(expected_paths, 1),
            output_dir=output_dir,
            output_files=output_files,
        )
        FlextTestsUtilities.TestUtilities.assert_result_success(result)
        stats = result.unwrap()
        for category, expected_path in expected_paths.items():
            assert stats.output_files[category] == expected_path


class TestGenerateStatisticsErrorHandling:
    """Test error handling in statistics generation."""

    def test_generate_statistics_handles_empty_data(self) -> None:
        """Test that statistics generation handles empty data gracefully."""
        result = FlextLdifStatistics().generate_statistics(
            categorized={},
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
        result = FlextLdifStatistics().generate_statistics(
            categorized={
                "entries": [
                    {"dn": "cn=test1,dc=example,dc=com"},
                    {"dn": "cn=test2,dc=example,dc=com", "attributes": {}},
                ],
            },
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
        result = FlextLdifStatistics().generate_statistics(
            categorized={
                "valid": [
                    {"dn": f"cn=user{i},dc=example,dc=com", "attributes": {}}
                    for i in range(100)
                ],
                "rejected": [
                    {
                        "dn": f"cn=invalid{i},dc=example,dc=com",
                        "attributes": {"rejectionReason": f"Reason {i % 5}"},
                    }
                    for i in range(900)
                ],
            },
            written_counts={"valid": 100, "rejected": 0},
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
        result = FlextLdifStatistics().generate_statistics(
            categorized={
                "users": [{"dn": "cn=user1,dc=example,dc=com", "attributes": {}}],
            },
            written_counts={"users": 1},
            output_dir=output_dir,
            output_files={"users": "exported_users.ldif"},
        )
        FlextTestsUtilities.TestUtilities.assert_result_success(result)
        stats = result.unwrap()
        assert stats.output_files["users"] == str(output_dir / "exported_users.ldif")

    def test_statistics_all_rejected_entries(self) -> None:
        """Test statistics when all entries are rejected."""
        result = FlextLdifStatistics().generate_statistics(
            categorized={
                "rejected": [
                    {
                        "dn": f"cn=invalid{i},dc=example,dc=com",
                        "attributes": {"rejectionReason": "Invalid format"},
                    }
                    for i in range(10)
                ],
            },
            written_counts={"rejected": 0},
            output_dir=Path("/tmp"),
            output_files={},
        )
        FlextTestsUtilities.TestUtilities.assert_result_success(result)
        stats = result.unwrap()
        assert stats.total_entries == 10
        assert stats.rejection_count == 10
        assert stats.rejection_rate == 1.0


__all__ = [
    "TestGenerateStatisticsBasic",
    "TestGenerateStatisticsEdgeCases",
    "TestGenerateStatisticsErrorHandling",
    "TestGenerateStatisticsOutputFiles",
    "TestGenerateStatisticsRejectionReasons",
    "TestGenerateStatisticsWithRejections",
    "TestStatisticsServiceInitialization",
]
