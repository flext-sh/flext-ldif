"""Unit tests for FlextLdifCategorizedMigrationPipeline output writing.

Tests for Phase 2 Day 3 Afternoon: Output writing, statistics, and rejection tracking.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

from flext_core import FlextCore

from flext_ldif import FlextLdifCategorizedMigrationPipeline


class TestOutputWriting:
    """Test categorized output writing."""

    def test_write_category_file_success(self, tmp_path: Path) -> None:
        """Test successful writing of category file."""
        rules: FlextCore.Types.Dict = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        # Create output directory
        category_path = tmp_path / "output" / "02-users"
        category_path.mkdir(parents=True)

        entries: list[FlextCore.Types.Dict] = [
            {
                "dn": "uid=jdoe,dc=example,dc=com",
                "objectClass": ["top", "person", "inetOrgPerson"],
                "attributes": {
                    "cn": "John Doe",
                    "sn": "Doe",
                    "mail": "jdoe@example.com",
                },
            },
            {
                "dn": "uid=asmith,dc=example,dc=com",
                "objectClass": ["top", "person"],
                "attributes": {"cn": "Alice Smith", "sn": "Smith"},
            },
        ]

        result = pipeline._write_category_file("users", entries, "02-users")

        assert result.is_success
        count = result.unwrap()
        assert count == 2

        # Verify file was created
        output_file = category_path / "users.ldif"
        assert output_file.exists()

        # Verify file content
        content = output_file.read_text()
        assert "dn: uid=jdoe,dc=example,dc=com" in content
        assert "objectClass: top" in content
        assert "objectClass: person" in content
        assert "cn: John Doe" in content
        assert "dn: uid=asmith,dc=example,dc=com" in content

    def test_write_category_file_empty_entries(self, tmp_path: Path) -> None:
        """Test writing empty category returns zero count."""
        rules: FlextCore.Types.Dict = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        # Create output directory
        category_path = tmp_path / "output" / "03-groups"
        category_path.mkdir(parents=True)

        entries: list[FlextCore.Types.Dict] = []

        result = pipeline._write_category_file("groups", entries, "03-groups")

        assert result.is_success
        count = result.unwrap()
        assert count == 0

    def test_write_category_file_missing_dn(self, tmp_path: Path) -> None:
        """Test writing entries with missing DN skips those entries."""
        rules: FlextCore.Types.Dict = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        # Create output directory
        category_path = tmp_path / "output" / "02-users"
        category_path.mkdir(parents=True)

        entries: list[FlextCore.Types.Dict] = [
            {
                "dn": "uid=jdoe,dc=example,dc=com",
                "objectClass": ["person"],
                "attributes": {"cn": "John Doe"},
            },
            {
                "dn": "",  # Empty DN
                "objectClass": ["person"],
                "attributes": {"cn": "Invalid"},
            },
            {
                "objectClass": ["person"],
                "attributes": {"cn": "No DN"},
            },
        ]

        result = pipeline._write_category_file("users", entries, "02-users")

        assert result.is_success
        count = result.unwrap()
        assert count == 3  # Returns total entries, but only writes valid ones

        # Verify only valid entry was written
        output_file = category_path / "users.ldif"
        content = output_file.read_text()
        assert "uid=jdoe" in content
        assert "Invalid" not in content
        assert "No DN" not in content

    def test_write_categorized_output_all_categories(self, tmp_path: Path) -> None:
        """Test writing all categories to output directories."""
        rules: FlextCore.Types.Dict = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        # Create output directories
        pipeline._create_output_directories()

        categorized: dict[str, list[FlextCore.Types.Dict]] = {
            "schema": [
                {
                    "dn": "cn=schema",
                    "objectClass": ["subschema"],
                    "attributes": {},
                },
            ],
            "hierarchy": [
                {
                    "dn": "ou=users,dc=example,dc=com",
                    "objectClass": ["organizationalUnit"],
                    "attributes": {"ou": "users"},
                },
            ],
            "users": [
                {
                    "dn": "uid=jdoe,dc=example,dc=com",
                    "objectClass": ["person"],
                    "attributes": {"cn": "John Doe"},
                },
            ],
            "groups": [
                {
                    "dn": "cn=admins,dc=example,dc=com",
                    "objectClass": ["groupOfNames"],
                    "attributes": {"cn": "admins"},
                },
            ],
            "acl": [
                {
                    "dn": "dc=example,dc=com",
                    "objectClass": ["domain"],
                    "attributes": {"aci": "(targetattr=*)"},
                },
            ],
            "rejected": [],
        }

        result = pipeline._write_categorized_output(categorized)

        assert result.is_success
        written_counts = result.unwrap()

        assert written_counts["schema"] == 1
        assert written_counts["hierarchy"] == 1
        assert written_counts["users"] == 1
        assert written_counts["groups"] == 1
        assert written_counts["acl"] == 1
        assert written_counts["rejected"] == 0

        # Verify files were created
        output_dir = tmp_path / "output"
        assert (output_dir / "00-schema" / "schema.ldif").exists()
        assert (output_dir / "01-hierarchy" / "hierarchy.ldif").exists()
        assert (output_dir / "02-users" / "users.ldif").exists()
        assert (output_dir / "03-groups" / "groups.ldif").exists()
        assert (output_dir / "04-acl" / "acl.ldif").exists()

    def test_write_categorized_output_failure_propagation(self, tmp_path: Path) -> None:
        """Test write failure propagates correctly."""
        rules: FlextCore.Types.Dict = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        # Don't create output directories to force failure
        categorized: dict[str, list[FlextCore.Types.Dict]] = {
            "schema": [],
            "hierarchy": [],
            "users": [
                {
                    "dn": "uid=jdoe,dc=example,dc=com",
                    "objectClass": ["person"],
                    "attributes": {},
                },
            ],
            "groups": [],
            "acl": [],
            "rejected": [],
        }

        result = pipeline._write_categorized_output(categorized)

        assert result.is_failure
        error_msg = result.error
        assert isinstance(error_msg, str)
        assert "Failed to write" in error_msg


class TestStatisticsGeneration:
    """Test statistics generation."""

    def test_generate_statistics_comprehensive(self, tmp_path: Path) -> None:
        """Test comprehensive statistics generation."""
        rules: FlextCore.Types.Dict = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        categorized: dict[str, list[FlextCore.Types.Dict]] = {
            "schema": [{"dn": "cn=schema", "objectClass": [], "attributes": {}}],
            "hierarchy": [
                {
                    "dn": "ou=users,dc=example,dc=com",
                    "objectClass": [],
                    "attributes": {},
                },
                {
                    "dn": "ou=groups,dc=example,dc=com",
                    "objectClass": [],
                    "attributes": {},
                },
            ],
            "users": [
                {
                    "dn": "uid=jdoe,dc=example,dc=com",
                    "objectClass": [],
                    "attributes": {},
                },
            ],
            "groups": [
                {
                    "dn": "cn=admins,dc=example,dc=com",
                    "objectClass": [],
                    "attributes": {},
                },
            ],
            "acl": [],
            "rejected": [],
        }

        written_counts = {
            "schema": 1,
            "hierarchy": 2,
            "users": 1,
            "groups": 1,
            "acl": 0,
            "rejected": 0,
        }

        stats = pipeline._generate_statistics(categorized, written_counts)

        assert stats["total_entries"] == 5

        categorized_counts = stats["categorized_counts"]
        assert isinstance(categorized_counts, dict)
        assert categorized_counts["schema"] == 1
        assert categorized_counts["hierarchy"] == 2
        assert categorized_counts["users"] == 1
        assert categorized_counts["groups"] == 1

        assert stats["rejection_count"] == 0
        assert stats["rejection_rate"] == 0.0
        assert stats["source_server"] == "oracle_oid"
        assert stats["target_server"] == "oracle_oud"

    def test_generate_statistics_with_rejections(self, tmp_path: Path) -> None:
        """Test statistics with rejection tracking."""
        rules: FlextCore.Types.Dict = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        categorized: dict[str, list[FlextCore.Types.Dict]] = {
            "schema": [],
            "hierarchy": [],
            "users": [
                {
                    "dn": "uid=jdoe,dc=example,dc=com",
                    "objectClass": [],
                    "attributes": {},
                },
            ],
            "groups": [],
            "acl": [],
            "rejected": [
                {
                    "dn": "cn=unknown,dc=example,dc=com",
                    "objectClass": ["unknownClass"],
                    "attributes": {
                        "rejectionReason": "No matching category for objectClasses: ['unknownClass']"
                    },
                },
                {
                    "dn": "cn=invalid,dc=example,dc=com",
                    "objectClass": ["person"],
                    "attributes": {
                        "rejectionReason": "User entry DN does not match expected patterns"
                    },
                },
            ],
        }

        written_counts = {
            "schema": 0,
            "hierarchy": 0,
            "users": 1,
            "groups": 0,
            "acl": 0,
            "rejected": 2,
        }

        stats = pipeline._generate_statistics(categorized, written_counts)

        assert stats["total_entries"] == 3
        assert stats["rejection_count"] == 2
        assert stats["rejection_rate"] == 2 / 3  # 66.67%

        rejection_reasons = stats["rejection_reasons"]
        assert isinstance(rejection_reasons, list)
        assert len(rejection_reasons) == 2
        assert isinstance(rejection_reasons[0], str)
        assert isinstance(rejection_reasons[1], str)
        assert "No matching category" in rejection_reasons[0]
        assert "does not match expected patterns" in rejection_reasons[1]

    def test_generate_statistics_output_directories(self, tmp_path: Path) -> None:
        """Test output directories info in statistics."""
        rules: FlextCore.Types.Dict = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        categorized: dict[str, list[FlextCore.Types.Dict]] = {
            "schema": [{"dn": "cn=schema", "objectClass": [], "attributes": {}}],
            "hierarchy": [],
            "users": [],
            "groups": [],
            "acl": [],
            "rejected": [],
        }

        written_counts = {
            "schema": 1,
            "hierarchy": 0,
            "users": 0,
            "groups": 0,
            "acl": 0,
            "rejected": 0,
        }

        stats = pipeline._generate_statistics(categorized, written_counts)

        assert "output_directories" in stats
        output_dirs = stats["output_directories"]
        assert isinstance(output_dirs, dict)
        assert "schema" in output_dirs
        schema_dir = output_dirs["schema"]
        assert isinstance(schema_dir, str)
        assert "00-schema" in schema_dir
        assert str(tmp_path / "output") in schema_dir

    def test_generate_statistics_empty_categorized(self, tmp_path: Path) -> None:
        """Test statistics with no entries."""
        rules: FlextCore.Types.Dict = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        categorized: dict[str, list[FlextCore.Types.Dict]] = {
            "schema": [],
            "hierarchy": [],
            "users": [],
            "groups": [],
            "acl": [],
            "rejected": [],
        }

        written_counts = {
            "schema": 0,
            "hierarchy": 0,
            "users": 0,
            "groups": 0,
            "acl": 0,
            "rejected": 0,
        }

        stats = pipeline._generate_statistics(categorized, written_counts)

        assert stats["total_entries"] == 0
        assert stats["rejection_count"] == 0
        assert stats["rejection_rate"] == 0.0
        assert stats["rejection_reasons"] == []


class TestRejectionTracking:
    """Test rejection reason tracking."""

    def test_rejection_reasons_extracted(self, tmp_path: Path) -> None:
        """Test rejection reasons are properly extracted."""
        rules: FlextCore.Types.Dict = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        categorized: dict[str, list[FlextCore.Types.Dict]] = {
            "schema": [],
            "hierarchy": [],
            "users": [],
            "groups": [],
            "acl": [],
            "rejected": [
                {
                    "dn": "cn=test1,dc=example,dc=com",
                    "objectClass": [],
                    "attributes": {"rejectionReason": "Reason A"},
                },
                {
                    "dn": "cn=test2,dc=example,dc=com",
                    "objectClass": [],
                    "attributes": {"rejectionReason": "Reason B"},
                },
                {
                    "dn": "cn=test3,dc=example,dc=com",
                    "objectClass": [],
                    "attributes": {"rejectionReason": "Reason A"},  # Duplicate
                },
            ],
        }

        written_counts = {
            "schema": 0,
            "hierarchy": 0,
            "users": 0,
            "groups": 0,
            "acl": 0,
            "rejected": 3,
        }

        stats = pipeline._generate_statistics(categorized, written_counts)

        # Should only have 2 unique reasons
        rejection_reasons = stats["rejection_reasons"]
        assert isinstance(rejection_reasons, list)
        assert len(rejection_reasons) == 2
        assert "Reason A" in rejection_reasons
        assert "Reason B" in rejection_reasons

    def test_rejection_rate_calculation(self, tmp_path: Path) -> None:
        """Test rejection rate calculation accuracy."""
        rules: FlextCore.Types.Dict = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        # Test case: 2 rejected out of 10 total = 20% rejection rate
        categorized: dict[str, list[FlextCore.Types.Dict]] = {
            "schema": [
                {"dn": f"cn=schema{i}", "objectClass": [], "attributes": {}}
                for i in range(2)
            ],
            "hierarchy": [
                {
                    "dn": f"ou=test{i},dc=example,dc=com",
                    "objectClass": [],
                    "attributes": {},
                }
                for i in range(3)
            ],
            "users": [
                {
                    "dn": f"uid=user{i},dc=example,dc=com",
                    "objectClass": [],
                    "attributes": {},
                }
                for i in range(3)
            ],
            "groups": [],
            "acl": [],
            "rejected": [
                {
                    "dn": f"cn=rejected{i},dc=example,dc=com",
                    "objectClass": [],
                    "attributes": {"rejectionReason": f"Reason {i}"},
                }
                for i in range(2)
            ],
        }

        written_counts = {
            "schema": 2,
            "hierarchy": 3,
            "users": 3,
            "groups": 0,
            "acl": 0,
            "rejected": 2,
        }

        stats = pipeline._generate_statistics(categorized, written_counts)

        assert stats["total_entries"] == 10
        assert stats["rejection_count"] == 2
        assert stats["rejection_rate"] == 0.2  # 20%


class TestOutputWritingEdgeCases:
    """Test edge cases in output writing."""

    def test_write_category_file_unicode_content(self, tmp_path: Path) -> None:
        """Test writing entries with Unicode characters."""
        rules: FlextCore.Types.Dict = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        # Create output directory
        category_path = tmp_path / "output" / "02-users"
        category_path.mkdir(parents=True)

        entries: list[FlextCore.Types.Dict] = [
            {
                "dn": "uid=josé,dc=example,dc=com",
                "objectClass": ["person"],
                "attributes": {"cn": "José García", "description": "ñoño"},
            },
        ]

        result = pipeline._write_category_file("users", entries, "02-users")

        assert result.is_success
        count = result.unwrap()
        assert count == 1

        # Verify Unicode content
        output_file = category_path / "users.ldif"
        content = output_file.read_text(encoding="utf-8")
        assert "José García" in content
        assert "ñoño" in content

    def test_write_categorized_output_partial_empty_categories(
        self, tmp_path: Path
    ) -> None:
        """Test writing with some empty and some populated categories."""
        rules: FlextCore.Types.Dict = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        # Create output directories
        pipeline._create_output_directories()

        categorized: dict[str, list[FlextCore.Types.Dict]] = {
            "schema": [],  # Empty
            "hierarchy": [
                {
                    "dn": "ou=users,dc=example,dc=com",
                    "objectClass": ["organizationalUnit"],
                    "attributes": {},
                },
            ],
            "users": [],  # Empty
            "groups": [],  # Empty
            "acl": [],  # Empty
            "rejected": [],  # Empty
        }

        result = pipeline._write_categorized_output(categorized)

        assert result.is_success
        written_counts = result.unwrap()

        # Only hierarchy should have entries
        assert written_counts["schema"] == 0
        assert written_counts["hierarchy"] == 1
        assert written_counts["users"] == 0
        assert written_counts["groups"] == 0
        assert written_counts["acl"] == 0
        assert written_counts["rejected"] == 0


class TestQuirksIntegration:
    """Test quirks application in pipeline."""

    def test_transform_categories_placeholder(self, tmp_path: Path) -> None:
        """Test transformation placeholder returns unchanged categories."""
        rules: FlextCore.Types.Dict = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        categorized: dict[str, list[FlextCore.Types.Dict]] = {
            "schema": [
                {"dn": "cn=schema", "objectClass": ["subschema"], "attributes": {}}
            ],
            "hierarchy": [
                {
                    "dn": "ou=test",
                    "objectClass": ["organizationalUnit"],
                    "attributes": {},
                }
            ],
            "users": [],
            "groups": [],
            "acl": [],
            "rejected": [],
        }

        result = pipeline._transform_categories(categorized)

        assert result.is_success
        transformed = result.unwrap()

        # Should be unchanged (placeholder implementation)
        assert len(transformed["schema"]) == 1
        assert transformed["schema"][0]["dn"] == "cn=schema"
        assert len(transformed["hierarchy"]) == 1
        assert transformed["hierarchy"][0]["dn"] == "ou=test"

    def test_transform_categories_preserves_structure(self, tmp_path: Path) -> None:
        """Test transformation preserves category structure."""
        rules: FlextCore.Types.Dict = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        categorized: dict[str, list[FlextCore.Types.Dict]] = {
            "schema": [],
            "hierarchy": [],
            "users": [
                {
                    "dn": "uid=user1,dc=example,dc=com",
                    "objectClass": ["person"],
                    "attributes": {},
                },
                {
                    "dn": "uid=user2,dc=example,dc=com",
                    "objectClass": ["person"],
                    "attributes": {},
                },
            ],
            "groups": [
                {
                    "dn": "cn=group1,dc=example,dc=com",
                    "objectClass": ["groupOfNames"],
                    "attributes": {},
                },
            ],
            "acl": [],
            "rejected": [],
        }

        result = pipeline._transform_categories(categorized)

        assert result.is_success
        transformed = result.unwrap()

        # All categories should be present
        assert "schema" in transformed
        assert "hierarchy" in transformed
        assert "users" in transformed
        assert "groups" in transformed
        assert "acl" in transformed
        assert "rejected" in transformed

        # Entry counts should be preserved
        assert len(transformed["users"]) == 2
        assert len(transformed["groups"]) == 1
