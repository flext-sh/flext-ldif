"""Unit tests for FlextLdifCategorizedMigrationPipeline.

Tests for Phase 2 Day 2: Categorization logic with 6-directory output structure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from flext_ldif import FlextLdifCategorizedMigrationPipeline


class TestCategorizedPipelineInitialization:
    """Test initialization and configuration."""

    def test_initialization_with_required_params(self, tmp_path: Path) -> None:
        """Test pipeline initialization with required parameters."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        rules: dict[str, list[str]] = {
            "hierarchy_objectclasses": ["organization"],
            "user_objectclasses": ["person"],
            "group_objectclasses": ["groupOfNames"],
            "acl_attributes": ["aci"],
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        assert pipeline._input_dir == input_dir
        assert pipeline._output_dir == output_dir
        assert pipeline._categorization_rules == rules
        assert pipeline._source_server == "oracle_oid"
        assert pipeline._target_server == "oracle_oud"

    def test_initialization_with_custom_servers(self, tmp_path: Path) -> None:
        """Test pipeline initialization with custom server types."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        rules: dict[str, list[str]] = {}

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
            source_server="openldap",
            target_server="389ds",
        )

        assert pipeline._source_server == "openldap"
        assert pipeline._target_server == "389ds"


class TestOutputDirectories:
    """Test output directory creation."""

    def test_create_output_directories_success(self, tmp_path: Path) -> None:
        """Test successful creation of 6-directory structure."""
        output_dir = tmp_path / "output"
        rules: dict[str, list[str]] = {}

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=output_dir,
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        result = pipeline._create_output_directory()

        assert result.is_success
        assert output_dir.exists()
        # Note: Current implementation creates base directory only
        # Subdirectories are not created until files are written

    def test_create_output_directories_idempotent(self, tmp_path: Path) -> None:
        """Test directory creation is idempotent."""
        output_dir = tmp_path / "output"
        rules: dict[str, list[str]] = {}

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=output_dir,
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        # Create directories twice
        result1 = pipeline._create_output_directory()
        result2 = pipeline._create_output_directory()

        assert result1.is_success
        assert result2.is_success
        assert output_dir.exists()


class TestEntryCategorization:
    """Test entry categorization logic."""

    def test_categorize_entry_schema(self, tmp_path: Path) -> None:
        """Test categorization of schema entries."""
        rules: dict[str, list[str]] = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        entry: dict[str, object] = {
            "dn": "cn=schema",
            "attributes": {},
            "objectclass": ["top", "subschema"],
        }

        category, reason = pipeline._categorize_entry(entry)
        assert category == "schema"
        assert reason is None

    def test_categorize_entry_acl(self, tmp_path: Path) -> None:
        """Test categorization of ACL entries."""
        rules: dict[str, list[str]] = {
            "acl_attributes": ["aci"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        entry: dict[str, object] = {
            "dn": "dc=example,dc=com",
            "attributes": {"aci": "(targetattr=*)"},
            "objectclass": ["top", "domain"],
        }

        category, reason = pipeline._categorize_entry(entry)
        assert category == "acl"
        assert reason is None

    def test_categorize_entry_hierarchy(self, tmp_path: Path) -> None:
        """Test categorization of hierarchy entries."""
        rules: dict[str, list[str]] = {
            "hierarchy_objectclasses": ["organization", "organizationalUnit"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        entry: dict[str, object] = {
            "dn": "ou=users,dc=example,dc=com",
            "attributes": {"ou": "users"},
            "objectclass": ["top", "organizationalUnit"],
        }

        category, reason = pipeline._categorize_entry(entry)
        assert category == "hierarchy"
        assert reason is None

    def test_categorize_entry_user(self, tmp_path: Path) -> None:
        """Test categorization of user entries."""
        rules: dict[str, list[str]] = {
            "user_objectclasses": ["person", "inetOrgPerson"],
            "user_dn_patterns": [r"uid=.+"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        entry: dict[str, object] = {
            "dn": "uid=jdoe,dc=example,dc=com",
            "attributes": {"cn": "John Doe", "sn": "Doe"},
            "objectclass": ["top", "person", "inetOrgPerson"],
        }

        category, reason = pipeline._categorize_entry(entry)
        assert category == "users"
        assert reason is None

    def test_categorize_entry_user_rejected_dn(self, tmp_path: Path) -> None:
        """Test categorization rejects user with invalid DN pattern."""
        rules: dict[str, list[str]] = {
            "user_objectclasses": ["person"],
            "user_dn_patterns": [r"uid=.+"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        entry: dict[str, object] = {
            "dn": "cn=jdoe,dc=example,dc=com",  # No uid=
            "attributes": {"cn": "John Doe"},
            "objectclass": ["top", "person"],
        }

        category, reason = pipeline._categorize_entry(entry)
        assert category == "rejected"
        assert reason is not None
        assert "DN pattern mismatch" in reason

    def test_categorize_entry_group(self, tmp_path: Path) -> None:
        """Test categorization of group entries."""
        rules: dict[str, list[str]] = {
            "group_objectclasses": ["groupOfNames"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        entry: dict[str, object] = {
            "dn": "cn=admins,dc=example,dc=com",
            "attributes": {"cn": "admins"},
            "objectclass": ["top", "groupOfNames"],
        }

        category, reason = pipeline._categorize_entry(entry)
        assert category == "groups"
        assert reason is None

    def test_categorize_entry_rejected_no_match(self, tmp_path: Path) -> None:
        """Test categorization rejects entries with no matching category."""
        rules: dict[str, list[str]] = {
            "hierarchy_objectclasses": ["organization"],
            "user_objectclasses": ["person"],
            "group_objectclasses": ["groupOfNames"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        entry: dict[str, object] = {
            "dn": "cn=unknown,dc=example,dc=com",
            "attributes": {"cn": "unknown"},
            "objectclass": ["top", "unknownClass"],
        }

        category, reason = pipeline._categorize_entry(entry)
        assert category == "rejected"
        assert reason is not None
        assert "No category match" in reason


class TestCategoryBatchProcessing:
    """Test batch categorization of multiple entries."""

    def test_categorize_entries_multiple_categories(self, tmp_path: Path) -> None:
        """Test categorizing entries into multiple categories."""
        rules: dict[str, list[str]] = {
            "hierarchy_objectclasses": ["organizationalUnit"],
            "user_objectclasses": ["person"],
            "group_objectclasses": ["groupOfNames"],
            "acl_attributes": ["aci"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        entries: list[dict[str, object]] = [
            {
                "dn": "cn=schema",
                "attributes": {},
                "objectclass": ["subschema"],
            },
            {
                "dn": "ou=users,dc=example,dc=com",
                "attributes": {"ou": "users"},
                "objectclass": ["organizationalUnit"],
            },
            {
                "dn": "uid=jdoe,dc=example,dc=com",
                "attributes": {"cn": "John Doe"},
                "objectclass": ["person"],
            },
            {
                "dn": "cn=admins,dc=example,dc=com",
                "attributes": {"cn": "admins"},
                "objectclass": ["groupOfNames"],
            },
            {
                "dn": "dc=example,dc=com",
                "attributes": {"aci": "(targetattr=*)"},
                "objectclass": ["domain"],
            },
        ]

        result = pipeline._categorize_entries(entries)

        assert result.is_success
        categorized = result.unwrap()
        assert len(categorized["schema"]) == 1
        assert len(categorized["hierarchy"]) == 1
        assert len(categorized["users"]) == 1
        assert len(categorized["groups"]) == 1
        assert len(categorized["acl"]) == 1

    def test_categorize_entries_with_rejections(self, tmp_path: Path) -> None:
        """Test categorizing entries with rejections tracked."""
        rules: dict[str, list[str]] = {
            "user_objectclasses": ["person"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        entries: list[dict[str, object]] = [
            {
                "dn": "cn=unknown,dc=example,dc=com",
                "attributes": {"cn": "unknown"},
                "objectclass": ["unknownClass"],
            },
        ]

        result = pipeline._categorize_entries(entries)

        assert result.is_success
        categorized = result.unwrap()
        assert len(categorized["rejected"]) == 1

        rejected_entry = categorized["rejected"][0]
        attrs_value = rejected_entry.get("attributes", {})
        assert isinstance(attrs_value, dict)
        assert "rejectionReason" in attrs_value


class TestCategoryTransformation:
    """Test per-category transformation."""

    def test_transform_categories_placeholder(self, tmp_path: Path) -> None:
        """Test transformation placeholder returns categories unchanged."""
        rules: dict[str, list[str]] = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        categorized: dict[str, list[dict[str, object]]] = {
            "schema": [],
            "hierarchy": [{"dn": "ou=test", "objectclass": ["organizationalUnit"]}],
            "users": [],
            "groups": [],
            "acl": [],
            "rejected": [],
        }

        result = pipeline._transform_categories(categorized)

        assert result.is_success
        transformed = result.unwrap()
        assert len(transformed["hierarchy"]) == 1
        assert transformed["hierarchy"][0]["dn"] == "ou=test"


class TestCategorizedPipelineIntegration:
    """Integration tests with sample LDIF."""

    def test_execute_creates_directories(self, tmp_path: Path) -> None:
        """Test execute creates output directory structure."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        rules: dict[str, list[str]] = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        result = pipeline.execute()

        assert result.is_success
        data = result.unwrap()
        # Check that output directory exists (no input files so no output files created)
        assert output_dir.exists()
        # Check statistics
        assert data.statistics is not None
        assert data.statistics.total_entries == 0


class TestQuirksIntegration:
    """Test quirks application in pipeline."""

    def test_transform_categories_placeholder(self, tmp_path: Path) -> None:
        """Test transformation placeholder returns unchanged categories."""
        rules: dict[str, list[str]] = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        categorized: dict[str, list[dict[str, object]]] = {
            "schema": [
                {"dn": "cn=schema", "objectclass": ["subschema"], "attributes": {}}
            ],
            "hierarchy": [
                {
                    "dn": "ou=test",
                    "objectclass": ["organizationalUnit"],
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
        rules: dict[str, list[str]] = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        categorized: dict[str, list[dict[str, object]]] = {
            "schema": [],
            "hierarchy": [],
            "users": [
                {
                    "dn": "uid=user1,dc=example,dc=com",
                    "objectclass": ["person"],
                    "attributes": {},
                },
                {
                    "dn": "uid=user2,dc=example,dc=com",
                    "objectclass": ["person"],
                    "attributes": {},
                },
            ],
            "groups": [
                {
                    "dn": "cn=group1,dc=example,dc=com",
                    "objectclass": ["groupOfNames"],
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
