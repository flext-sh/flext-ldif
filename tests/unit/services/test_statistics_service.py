"""Unit tests for Statistics Service - LDIF processing statistics generation.

Tests statistics generation for categorized and migrated LDIF entries
with comprehensive coverage of all calculation and reporting functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path

from flext_ldif.statistics_service import FlextLdifStatisticsService


class TestStatisticsServiceInitialization:
    """Test statistics service initialization and basic functionality."""

    def test_init_creates_service(self) -> None:
        """Test statistics service can be instantiated."""
        service = FlextLdifStatisticsService()
        assert service is not None

    def test_execute_returns_status(self) -> None:
        """Test execute returns service operational status."""
        service = FlextLdifStatisticsService()
        result = service.execute()

        assert result.is_success
        status = result.unwrap()
        assert status["service"] == "StatisticsService"
        assert status["status"] == "operational"
        assert "capabilities" in status
        capabilities = status.get("capabilities", [])
        assert isinstance(capabilities, list)
        assert "generate_statistics" in capabilities
        assert "count_entries" in capabilities
        assert "analyze_rejections" in capabilities


class TestGenerateStatisticsBasic:
    """Test basic statistics generation with simple categorized entries."""

    def test_generate_statistics_empty_categorized(self) -> None:
        """Test statistics for empty categorized entries."""
        service = FlextLdifStatisticsService()
        categorized: dict[str, list[dict[str, object]]] = {}
        written_counts: dict[str, int] = {}
        output_dir = Path("/tmp/ldif")
        output_files: dict[str, object] = {}

        result = service.generate_statistics(
            categorized=categorized,
            written_counts=written_counts,
            output_dir=output_dir,
            output_files=output_files,
        )

        assert result.is_success
        stats = result.unwrap()
        assert isinstance(stats, dict)
        assert stats["total_entries"] == 0
        assert stats["categorized"] == {}
        assert stats["rejection_count"] == 0
        assert stats["rejection_rate"] == 0.0
        assert stats["rejection_reasons"] == []

    def test_generate_statistics_single_category(self) -> None:
        """Test statistics for single category with entries."""
        service = FlextLdifStatisticsService()
        categorized: dict[str, list[dict[str, object]]] = {
            "users": [
                {"dn": "cn=user1,dc=example,dc=com", "attributes": {}},
                {"dn": "cn=user2,dc=example,dc=com", "attributes": {}},
                {"dn": "cn=user3,dc=example,dc=com", "attributes": {}},
            ]
        }
        written_counts: dict[str, int] = {"users": 3}
        output_dir = Path("/tmp/ldif")
        output_files: dict[str, object] = {"users": "users.ldif"}

        result = service.generate_statistics(
            categorized=categorized,
            written_counts=written_counts,
            output_dir=output_dir,
            output_files=output_files,
        )

        assert result.is_success
        stats = result.unwrap()
        assert isinstance(stats, dict)
        assert stats["total_entries"] == 3
        categorized_field = stats.categorized
        assert isinstance(categorized_field, dict)
        assert categorized_field.users == 3
        written_counts_val = stats.written_counts
        assert isinstance(written_counts_val, dict)
        assert written_counts_val["users"] == 3
        assert stats["rejection_count"] == 0
        assert stats["rejection_rate"] == 0.0
        output_files_val = stats.output_files
        assert isinstance(output_files_val, dict)
        assert output_files_val["users"] == str(output_dir / "users.ldif")

    def test_generate_statistics_multiple_categories(self) -> None:
        """Test statistics for multiple categories with different sizes."""
        service = FlextLdifStatisticsService()
        categorized: dict[str, list[dict[str, object]]] = {
            "users": [
                {"dn": "cn=user1,dc=example,dc=com", "attributes": {}},
                {"dn": "cn=user2,dc=example,dc=com", "attributes": {}},
            ],
            "groups": [
                {"dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "attributes": {}},
                {"dn": "cn=staff,dc=example,dc=com", "attributes": {}},
                {"dn": "cn=guests,dc=example,dc=com", "attributes": {}},
            ],
            "roles": [
                {"dn": "cn=superuser,dc=example,dc=com", "attributes": {}},
            ],
        }
        written_counts: dict[str, int] = {"users": 2, "groups": 3, "roles": 1}
        output_dir = Path("/output")
        output_files: dict[str, object] = {
            "users": "users.ldif",
            "groups": "groups.ldif",
            "roles": "roles.ldif",
        }

        result = service.generate_statistics(
            categorized=categorized,
            written_counts=written_counts,
            output_dir=output_dir,
            output_files=output_files,
        )

        assert result.is_success
        stats = result.unwrap()
        assert isinstance(stats, dict)
        assert stats["total_entries"] == 6
        categorized_field = stats.categorized
        assert isinstance(categorized_field, dict)
        assert categorized_field.users == 2
        assert categorized_field.groups == 3
        assert categorized_field.roles == 1
        written_counts_val = stats.written_counts
        assert isinstance(written_counts_val, dict)
        assert written_counts_val["users"] == 2
        assert written_counts_val["groups"] == 3
        assert written_counts_val["roles"] == 1
        assert stats["rejection_count"] == 0


class TestGenerateStatisticsWithRejections:
    """Test statistics generation with rejected entries and rejection tracking."""

    def test_generate_statistics_with_rejected_entries(self) -> None:
        """Test statistics with rejected entries."""
        service = FlextLdifStatisticsService()
        categorized: dict[str, list[dict[str, object]]] = {
            "valid": [
                {"dn": "cn=valid1,dc=example,dc=com", "attributes": {}},
                {"dn": "cn=valid2,dc=example,dc=com", "attributes": {}},
            ],
            "rejected": [
                {
                    "dn": "cn=invalid1,dc=example,dc=com",
                    "attributes": {"rejectionReason": "Missing required attribute"},
                },
                {
                    "dn": "cn=invalid2,dc=example,dc=com",
                    "attributes": {"rejectionReason": "Invalid DN format"},
                },
            ],
        }
        written_counts: dict[str, int] = {"valid": 2, "rejected": 0}
        output_dir = Path("/tmp/ldif")
        output_files: dict[str, object] = {
            "valid": "valid.ldif",
            "rejected": "rejected.ldif",
        }

        result = service.generate_statistics(
            categorized=categorized,
            written_counts=written_counts,
            output_dir=output_dir,
            output_files=output_files,
        )

        assert result.is_success
        stats = result.unwrap()
        assert isinstance(stats, dict)
        assert stats["total_entries"] == 4
        assert stats["rejection_count"] == 2
        assert stats["rejection_rate"] == 0.5  # 2 out of 4
        rejection_reasons = stats.rejection_reasons
        assert isinstance(rejection_reasons, list)
        assert len(rejection_reasons) == 2
        assert "Missing required attribute" in rejection_reasons
        assert "Invalid DN format" in rejection_reasons

    def test_generate_statistics_rejection_rate_calculation(self) -> None:
        """Test rejection rate calculation with various entry counts."""
        service = FlextLdifStatisticsService()
        categorized: dict[str, list[dict[str, object]]] = {
            "valid": [
                {"dn": "cn=user1,dc=example,dc=com", "attributes": {}},
                {"dn": "cn=user2,dc=example,dc=com", "attributes": {}},
                {"dn": "cn=user3,dc=example,dc=com", "attributes": {}},
                {"dn": "cn=user4,dc=example,dc=com", "attributes": {}},
            ],
            "rejected": [
                {
                    "dn": "cn=invalid1,dc=example,dc=com",
                    "attributes": {"rejectionReason": "Schema violation"},
                },
                {
                    "dn": "cn=invalid2,dc=example,dc=com",
                    "attributes": {"rejectionReason": "Schema violation"},
                },
            ],
        }
        written_counts: dict[str, int] = {"valid": 4, "rejected": 0}
        output_dir = Path("/tmp/ldif")
        output_files: dict[str, object] = {
            "valid": "valid.ldif",
            "rejected": "rejected.ldif",
        }

        result = service.generate_statistics(
            categorized=categorized,
            written_counts=written_counts,
            output_dir=output_dir,
            output_files=output_files,
        )

        assert result.is_success
        stats = result.unwrap()
        assert isinstance(stats, dict)
        assert stats["total_entries"] == 6
        assert stats["rejection_count"] == 2
        rejection_rate = stats.rejection_rate
        assert isinstance(rejection_rate, (int, float))
        assert abs(rejection_rate - 0.333333) < 0.001  # 2 out of 6

    def test_generate_statistics_unique_rejection_reasons(self) -> None:
        """Test that rejection reasons are deduplicated."""
        service = FlextLdifStatisticsService()
        categorized: dict[str, list[dict[str, object]]] = {
            "rejected": [
                {
                    "dn": "cn=invalid1,dc=example,dc=com",
                    "attributes": {"rejectionReason": "Duplicate DN"},
                },
                {
                    "dn": "cn=invalid2,dc=example,dc=com",
                    "attributes": {"rejectionReason": "Duplicate DN"},
                },
                {
                    "dn": "cn=invalid3,dc=example,dc=com",
                    "attributes": {"rejectionReason": "Invalid attributes"},
                },
                {
                    "dn": "cn=invalid4,dc=example,dc=com",
                    "attributes": {"rejectionReason": "Duplicate DN"},
                },
            ]
        }
        written_counts: dict[str, int] = {"rejected": 0}
        output_dir = Path("/tmp/ldif")
        output_files: dict[str, object] = {"rejected": "rejected.ldif"}

        result = service.generate_statistics(
            categorized=categorized,
            written_counts=written_counts,
            output_dir=output_dir,
            output_files=output_files,
        )

        assert result.is_success
        stats = result.unwrap()
        assert isinstance(stats, dict)
        assert stats["rejection_count"] == 4
        # Only unique reasons should be in the list
        rejection_reasons = stats.rejection_reasons
        assert isinstance(rejection_reasons, list)
        assert len(rejection_reasons) == 2
        assert "Duplicate DN" in rejection_reasons
        assert "Invalid attributes" in rejection_reasons


class TestGenerateStatisticsRejectionReasons:
    """Test rejection reason extraction and handling."""

    def test_rejection_reasons_with_dict_attributes(self) -> None:
        """Test extraction of rejection reasons from dict attributes."""
        service = FlextLdifStatisticsService()
        categorized: dict[str, list[dict[str, object]]] = {
            "rejected": [
                {
                    "dn": "cn=test1,dc=example,dc=com",
                    "attributes": {"rejectionReason": "Test reason 1"},
                },
                {
                    "dn": "cn=test2,dc=example,dc=com",
                    "attributes": {"rejectionReason": "Test reason 2"},
                },
            ]
        }
        written_counts: dict[str, int] = {"rejected": 0}
        output_dir = Path("/tmp")
        output_files: dict[str, object] = {"rejected": "rejected.ldif"}

        result = service.generate_statistics(
            categorized=categorized,
            written_counts=written_counts,
            output_dir=output_dir,
            output_files=output_files,
        )

        assert result.is_success
        stats = result.unwrap()
        assert isinstance(stats, dict)
        assert stats["rejection_count"] == 2
        rejection_reasons = stats.rejection_reasons
        assert isinstance(rejection_reasons, list)
        assert "Test reason 1" in rejection_reasons
        assert "Test reason 2" in rejection_reasons

    def test_rejection_reasons_skips_non_string_values(self) -> None:
        """Test that non-string rejection reason values are skipped."""
        service = FlextLdifStatisticsService()
        categorized: dict[str, list[dict[str, object]]] = {
            "rejected": [
                {
                    "dn": "cn=test1,dc=example,dc=com",
                    "attributes": {"rejectionReason": "Valid reason"},
                },
                {
                    "dn": "cn=test2,dc=example,dc=com",
                    "attributes": {"rejectionReason": 123},  # Non-string value
                },
                {
                    "dn": "cn=test3,dc=example,dc=com",
                    "attributes": {
                        "rejectionReason": ["list", "value"]
                    },  # Non-string value
                },
            ]
        }
        written_counts: dict[str, int] = {"rejected": 0}
        output_dir = Path("/tmp")
        output_files: dict[str, object] = {}

        result = service.generate_statistics(
            categorized=categorized,
            written_counts=written_counts,
            output_dir=output_dir,
            output_files=output_files,
        )

        assert result.is_success
        stats = result.unwrap()
        assert isinstance(stats, dict)
        # Only the valid string reason should be included
        assert stats["rejection_count"] == 3
        rejection_reasons = stats.rejection_reasons
        assert isinstance(rejection_reasons, list)
        assert len(rejection_reasons) == 1
        assert "Valid reason" in rejection_reasons

    def test_rejection_reasons_includes_empty_string(self) -> None:
        """Test that empty string rejection reasons are included (not filtered)."""
        service = FlextLdifStatisticsService()
        categorized: dict[str, list[dict[str, object]]] = {
            "rejected": [
                {
                    "dn": "cn=test1,dc=example,dc=com",
                    "attributes": {"rejectionReason": "Valid reason"},
                },
                {
                    "dn": "cn=test2,dc=example,dc=com",
                    "attributes": {"rejectionReason": ""},  # Empty string is included
                },
            ]
        }
        written_counts: dict[str, int] = {"rejected": 0}
        output_dir = Path("/tmp")
        output_files: dict[str, object] = {}

        result = service.generate_statistics(
            categorized=categorized,
            written_counts=written_counts,
            output_dir=output_dir,
            output_files=output_files,
        )

        assert result.is_success
        stats = result.unwrap()
        assert isinstance(stats, dict)
        assert stats["rejection_count"] == 2
        # Both reasons are included (even the empty string)
        rejection_reasons = stats.rejection_reasons
        assert isinstance(rejection_reasons, list)
        assert len(rejection_reasons) == 2
        assert "Valid reason" in rejection_reasons
        assert "" in rejection_reasons


class TestGenerateStatisticsOutputFiles:
    """Test output file path handling and generation."""

    def test_output_files_with_explicit_filenames(self) -> None:
        """Test output files with explicit filenames."""
        service = FlextLdifStatisticsService()
        categorized: dict[str, list[dict[str, object]]] = {
            "users": [{"dn": "cn=user1,dc=example,dc=com", "attributes": {}}],
            "groups": [{"dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "attributes": {}}],
        }
        written_counts: dict[str, int] = {"users": 1, "groups": 1}
        output_dir = Path("/output/ldif")
        output_files: dict[str, object] = {
            "users": "users_export.ldif",
            "groups": "groups_export.ldif",
        }

        result = service.generate_statistics(
            categorized=categorized,
            written_counts=written_counts,
            output_dir=output_dir,
            output_files=output_files,
        )

        assert result.is_success
        stats = result.unwrap()
        assert isinstance(stats, dict)
        output_files_val = stats.output_files
        assert isinstance(output_files_val, dict)
        assert output_files_val["users"] == str(output_dir / "users_export.ldif")
        assert output_files_val["groups"] == str(output_dir / "groups_export.ldif")

    def test_output_files_default_names_when_not_provided(self) -> None:
        """Test default output filenames when not provided."""
        service = FlextLdifStatisticsService()
        categorized: dict[str, list[dict[str, object]]] = {
            "users": [{"dn": "cn=user1,dc=example,dc=com", "attributes": {}}],
        }
        written_counts: dict[str, int] = {"users": 1}
        output_dir = Path("/output")
        output_files: dict[str, object] = {}  # No explicit filenames provided

        result = service.generate_statistics(
            categorized=categorized,
            written_counts=written_counts,
            output_dir=output_dir,
            output_files=output_files,
        )

        assert result.is_success
        stats = result.unwrap()
        assert isinstance(stats, dict)
        # Should use default filename: category.ldif
        output_files_val = stats.output_files
        assert isinstance(output_files_val, dict)
        assert output_files_val["users"] == str(output_dir / "users.ldif")

    def test_output_files_non_string_values_converted_to_default(self) -> None:
        """Test that non-string output file values are converted to defaults."""
        service = FlextLdifStatisticsService()
        categorized: dict[str, list[dict[str, object]]] = {
            "users": [{"dn": "cn=user1,dc=example,dc=com", "attributes": {}}],
        }
        written_counts: dict[str, int] = {"users": 1}
        output_dir = Path("/output")
        output_files: dict[str, object] = {"users": 123}  # Non-string value

        result = service.generate_statistics(
            categorized=categorized,
            written_counts=written_counts,
            output_dir=output_dir,
            output_files=output_files,
        )

        assert result.is_success
        stats = result.unwrap()
        assert isinstance(stats, dict)
        # Should fall back to default: users.ldif
        output_files_val = stats.output_files
        assert isinstance(output_files_val, dict)
        assert output_files_val["users"] == str(output_dir / "users.ldif")


class TestGenerateStatisticsErrorHandling:
    """Test error handling in statistics generation."""

    def test_generate_statistics_handles_exception(self) -> None:
        """Test that exceptions in statistics generation are handled gracefully."""
        service = FlextLdifStatisticsService()
        # Pass invalid types to trigger an exception
        categorized: dict[str, list[dict[str, object]]] = {}
        written_counts: dict[str, int] = {}
        output_dir = Path("/tmp")
        output_files: dict[str, object] = {}

        result = service.generate_statistics(
            categorized=categorized,
            written_counts=written_counts,
            output_dir=output_dir,
            output_files=output_files,
        )

        assert result.is_failure
        error_msg = result.error
        assert error_msg is not None
        assert "Failed to generate statistics" in error_msg

    def test_generate_statistics_handles_missing_attributes_key(self) -> None:
        """Test handling of entries without attributes key."""
        service = FlextLdifStatisticsService()
        categorized: dict[str, list[dict[str, object]]] = {
            "entries": [
                {"dn": "cn=test1,dc=example,dc=com"},  # No attributes key
                {"dn": "cn=test2,dc=example,dc=com", "attributes": {}},
            ]
        }
        written_counts: dict[str, int] = {"entries": 2}
        output_dir = Path("/tmp")
        output_files: dict[str, object] = {}

        result = service.generate_statistics(
            categorized=categorized,
            written_counts=written_counts,
            output_dir=output_dir,
            output_files=output_files,
        )

        assert result.is_success
        stats = result.unwrap()
        assert isinstance(stats, dict)
        assert stats["total_entries"] == 2
        assert stats["rejection_count"] == 0


class TestGenerateStatisticsEdgeCases:
    """Test edge cases and special scenarios."""

    def test_statistics_with_very_large_rejection_counts(self) -> None:
        """Test statistics with large number of rejected entries."""
        service = FlextLdifStatisticsService()
        categorized: dict[str, list[dict[str, object]]] = {
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
        }
        written_counts: dict[str, int] = {"valid": 100, "rejected": 0}
        output_dir = Path("/tmp")
        output_files: dict[str, object] = {}

        result = service.generate_statistics(
            categorized=categorized,
            written_counts=written_counts,
            output_dir=output_dir,
            output_files=output_files,
        )

        assert result.is_success
        stats = result.unwrap()
        assert isinstance(stats, dict)
        assert stats["total_entries"] == 1000
        assert stats["rejection_count"] == 900
        rejection_rate = stats.rejection_rate
        assert isinstance(rejection_rate, (int, float))
        assert abs(rejection_rate - 0.9) < 0.001
        # Should have 5 unique reasons (0-4)
        rejection_reasons = stats.rejection_reasons
        assert isinstance(rejection_reasons, list)
        assert len(rejection_reasons) == 5

    def test_statistics_with_complex_path_objects(self) -> None:
        """Test statistics generation with complex Path objects."""
        service = FlextLdifStatisticsService()
        categorized: dict[str, list[dict[str, object]]] = {
            "users": [{"dn": "cn=user1,dc=example,dc=com", "attributes": {}}],
        }
        written_counts: dict[str, int] = {"users": 1}
        output_dir = Path("/tmp") / "ldif" / "export" / "2025"
        output_files: dict[str, object] = {"users": "exported_users.ldif"}

        result = service.generate_statistics(
            categorized=categorized,
            written_counts=written_counts,
            output_dir=output_dir,
            output_files=output_files,
        )

        assert result.is_success
        stats = result.unwrap()
        assert isinstance(stats, dict)
        expected_path = str(output_dir / "exported_users.ldif")
        output_files_val = stats.output_files
        assert isinstance(output_files_val, dict)
        assert output_files_val["users"] == expected_path

    def test_statistics_all_rejected_entries(self) -> None:
        """Test statistics when all entries are rejected."""
        service = FlextLdifStatisticsService()
        categorized: dict[str, list[dict[str, object]]] = {
            "rejected": [
                {
                    "dn": f"cn=invalid{i},dc=example,dc=com",
                    "attributes": {"rejectionReason": "Invalid format"},
                }
                for i in range(10)
            ]
        }
        written_counts: dict[str, int] = {"rejected": 0}
        output_dir = Path("/tmp")
        output_files: dict[str, object] = {}

        result = service.generate_statistics(
            categorized=categorized,
            written_counts=written_counts,
            output_dir=output_dir,
            output_files=output_files,
        )

        assert result.is_success
        stats = result.unwrap()
        assert isinstance(stats, dict)
        assert stats["total_entries"] == 10
        assert stats["rejection_count"] == 10
        assert stats["rejection_rate"] == 1.0  # 100% rejection


__all__ = [
    "TestGenerateStatisticsBasic",
    "TestGenerateStatisticsEdgeCases",
    "TestGenerateStatisticsErrorHandling",
    "TestGenerateStatisticsOutputFiles",
    "TestGenerateStatisticsRejectionReasons",
    "TestGenerateStatisticsWithRejections",
    "TestStatisticsServiceInitialization",
]
