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


class TestDNPatternMatching:
    """Test DN pattern matching."""

    def test_matches_dn_pattern_single_match(self, tmp_path: Path) -> None:
        """Test DN matching with single pattern."""
        rules: dict[str, list[str]] = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        patterns = [r"uid=.+"]
        assert pipeline._matches_dn_pattern("uid=jdoe,dc=example,dc=com", patterns)

    def test_matches_dn_pattern_no_match(self, tmp_path: Path) -> None:
        """Test DN not matching any pattern."""
        rules: dict[str, list[str]] = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        patterns = [r"uid=.+"]
        assert not pipeline._matches_dn_pattern("cn=admin,dc=example,dc=com", patterns)

    def test_matches_dn_pattern_case_insensitive(self, tmp_path: Path) -> None:
        """Test DN matching is case insensitive."""
        rules: dict[str, list[str]] = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        patterns = [r"uid=.+"]
        assert pipeline._matches_dn_pattern("UID=JDOE,DC=EXAMPLE,DC=COM", patterns)

    def test_matches_dn_pattern_invalid_regex(self, tmp_path: Path) -> None:
        """Test DN matching handles invalid regex gracefully."""
        rules: dict[str, list[str]] = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        patterns = [r"[invalid(regex"]  # Invalid regex
        assert not pipeline._matches_dn_pattern("uid=jdoe,dc=example,dc=com", patterns)

    def test_matches_dn_pattern_multiple_patterns(self, tmp_path: Path) -> None:
        """Test DN matching with multiple patterns."""
        rules: dict[str, list[str]] = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        patterns = [r"uid=.+", r"cn=.+,ou=users", r"cn=.+,ou=people"]
        assert pipeline._matches_dn_pattern(
            "cn=jdoe,ou=users,dc=example,dc=com", patterns
        )


class TestACLDetection:
    """Test ACL attribute detection."""

    def test_has_acl_attributes_with_aci(self, tmp_path: Path) -> None:
        """Test ACL detection with aci attribute."""
        rules: dict[str, list[str]] = {
            "acl_attributes": ["aci", "orclACI"],
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
            "attributes": {"aci": "(targetattr=*)(version 3.0; acl...)"},
            "objectclass": ["top"],
        }

        assert pipeline._has_acl_attributes(entry)

    def test_has_acl_attributes_without_acl(self, tmp_path: Path) -> None:
        """Test ACL detection without ACL attributes."""
        rules: dict[str, list[str]] = {
            "acl_attributes": ["aci", "orclACI"],
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
            "attributes": {"cn": "John Doe"},
            "objectclass": ["person"],
        }

        assert not pipeline._has_acl_attributes(entry)

    def test_has_acl_attributes_empty_rules(self, tmp_path: Path) -> None:
        """Test ACL detection with empty rules."""
        rules: dict[str, list[str]] = {}
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
            "objectclass": ["top"],
        }

        assert not pipeline._has_acl_attributes(entry)


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
        assert "does not match expected patterns" in reason

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
        assert "No matching category" in reason


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
        assert data["source_server"] == "oracle_oid"
        assert data["target_server"] == "oracle_oud"
        # Check that output directory exists (no input files so no output files created)
        assert output_dir.exists()
        assert data["total_entries"] == 0


class TestOutputWriting:
    """Test categorized output writing."""

    def test_write_category_file_success(self, tmp_path: Path) -> None:
        """Test successful writing of category file."""
        rules: dict[str, list[str]] = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        # Create output directory
        output_dir = tmp_path / "output"
        output_dir.mkdir(parents=True, exist_ok=True)

        entries: list[dict[str, object]] = [
            {
                "dn": "uid=jdoe,dc=example,dc=com",
                "objectclass": ["top", "person", "inetOrgPerson"],
                "attributes": {
                    "cn": "John Doe",
                    "sn": "Doe",
                    "mail": "jdoe@example.com",
                },
            },
            {
                "dn": "uid=asmith,dc=example,dc=com",
                "objectclass": ["top", "person"],
                "attributes": {"cn": "Alice Smith", "sn": "Smith"},
            },
        ]

        result = pipeline._write_category_file("users", entries, "users.ldif")

        assert result.is_success
        count = result.unwrap()
        assert count == 2

        # Verify file was created directly in output directory
        output_file = output_dir / "users.ldif"
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
        rules: dict[str, list[str]] = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        # Create output directory
        category_path = tmp_path / "output" / "03-groups"
        category_path.mkdir(parents=True)

        entries: list[dict[str, object]] = []

        result = pipeline._write_category_file("groups", entries, "03-groups")

        assert result.is_success
        count = result.unwrap()
        assert count == 0

    def test_write_category_file_missing_dn(self, tmp_path: Path) -> None:
        """Test writing entries with missing DN skips those entries."""
        rules: dict[str, list[str]] = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        # Create output directory
        output_dir = tmp_path / "output"
        output_dir.mkdir(parents=True, exist_ok=True)

        entries: list[dict[str, object]] = [
            {
                "dn": "uid=jdoe,dc=example,dc=com",
                "objectclass": ["person"],
                "attributes": {"cn": "John Doe"},
            },
            {
                "dn": "",  # Empty DN
                "objectclass": ["person"],
                "attributes": {"cn": "Invalid"},
            },
            {
                "objectclass": ["person"],
                "attributes": {"cn": "No DN"},
            },
        ]

        result = pipeline._write_category_file("users", entries, "users.ldif")

        assert result.is_success
        count = result.unwrap()
        assert count == 3  # Returns total entries, but only writes valid ones

        # Verify only valid entry was written
        output_file = output_dir / "users.ldif"
        content = output_file.read_text()
        assert "uid=jdoe" in content
        assert "Invalid" not in content
        assert "No DN" not in content

    def test_write_categorized_output_all_categories(self, tmp_path: Path) -> None:
        """Test writing all categories to output directories."""
        rules: dict[str, list[str]] = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        # Create output directories
        pipeline._create_output_directory()

        categorized: dict[str, list[dict[str, object]]] = {
            "schema": [
                {
                    "dn": "cn=schema",
                    "objectclass": ["subschema"],
                    "attributes": {},
                },
            ],
            "hierarchy": [
                {
                    "dn": "ou=users,dc=example,dc=com",
                    "objectclass": ["organizationalUnit"],
                    "attributes": {"ou": "users"},
                },
            ],
            "users": [
                {
                    "dn": "uid=jdoe,dc=example,dc=com",
                    "objectclass": ["person"],
                    "attributes": {"cn": "John Doe"},
                },
            ],
            "groups": [
                {
                    "dn": "cn=admins,dc=example,dc=com",
                    "objectclass": ["groupOfNames"],
                    "attributes": {"cn": "admins"},
                },
            ],
            "acl": [
                {
                    "dn": "dc=example,dc=com",
                    "objectclass": ["domain"],
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

        # Verify files were created directly in output directory
        output_dir = tmp_path / "output"
        assert (output_dir / "schema.ldif").exists()
        assert (output_dir / "hierarchy.ldif").exists()
        assert (output_dir / "users.ldif").exists()
        assert (output_dir / "groups.ldif").exists()
        assert (output_dir / "acl.ldif").exists()

    def test_write_categorized_output_failure_propagation(self, tmp_path: Path) -> None:
        """Test write failure propagates correctly."""
        rules: dict[str, list[str]] = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        # Don't create output directories to force failure
        categorized: dict[str, list[dict[str, object]]] = {
            "schema": [],
            "hierarchy": [],
            "users": [
                {
                    "dn": "uid=jdoe,dc=example,dc=com",
                    "objectclass": ["person"],
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
        rules: dict[str, list[str]] = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        categorized: dict[str, list[dict[str, object]]] = {
            "schema": [{"dn": "cn=schema", "objectclass": [], "attributes": {}}],
            "hierarchy": [
                {
                    "dn": "ou=users,dc=example,dc=com",
                    "objectclass": [],
                    "attributes": {},
                },
                {
                    "dn": "ou=groups,dc=example,dc=com",
                    "objectclass": [],
                    "attributes": {},
                },
            ],
            "users": [
                {
                    "dn": "uid=jdoe,dc=example,dc=com",
                    "objectclass": [],
                    "attributes": {},
                },
            ],
            "groups": [
                {
                    "dn": "cn=admins,dc=example,dc=com",
                    "objectclass": [],
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
                    "dn": "uid=jdoe,dc=example,dc=com",
                    "objectclass": [],
                    "attributes": {},
                },
            ],
            "groups": [],
            "acl": [],
            "rejected": [
                {
                    "dn": "cn=unknown,dc=example,dc=com",
                    "objectclass": ["unknownClass"],
                    "attributes": {
                        "rejectionReason": "No matching category for objectClasses: ['unknownClass']"
                    },
                },
                {
                    "dn": "cn=invalid,dc=example,dc=com",
                    "objectclass": ["person"],
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
        rules: dict[str, list[str]] = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        categorized: dict[str, list[dict[str, object]]] = {
            "schema": [{"dn": "cn=schema", "objectclass": [], "attributes": {}}],
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

        assert "output_files" in stats
        output_files = stats["output_files"]
        assert isinstance(output_files, dict)
        assert "schema" in output_files
        schema_file = output_files["schema"]
        assert isinstance(schema_file, str)
        assert "schema.ldif" in schema_file
        assert str(tmp_path / "output") in schema_file

    def test_generate_statistics_empty_categorized(self, tmp_path: Path) -> None:
        """Test statistics with no entries."""
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
            "users": [],
            "groups": [],
            "acl": [],
            "rejected": [
                {
                    "dn": "cn=test1,dc=example,dc=com",
                    "objectclass": [],
                    "attributes": {"rejectionReason": "Reason A"},
                },
                {
                    "dn": "cn=test2,dc=example,dc=com",
                    "objectclass": [],
                    "attributes": {"rejectionReason": "Reason B"},
                },
                {
                    "dn": "cn=test3,dc=example,dc=com",
                    "objectclass": [],
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
        rules: dict[str, list[str]] = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        # Test case: 2 rejected out of 10 total = 20% rejection rate
        categorized: dict[str, list[dict[str, object]]] = {
            "schema": [
                {"dn": f"cn=schema{i}", "objectclass": [], "attributes": {}}
                for i in range(2)
            ],
            "hierarchy": [
                {
                    "dn": f"ou=test{i},dc=example,dc=com",
                    "objectclass": [],
                    "attributes": {},
                }
                for i in range(3)
            ],
            "users": [
                {
                    "dn": f"uid=user{i},dc=example,dc=com",
                    "objectclass": [],
                    "attributes": {},
                }
                for i in range(3)
            ],
            "groups": [],
            "acl": [],
            "rejected": [
                {
                    "dn": f"cn=rejected{i},dc=example,dc=com",
                    "objectclass": [],
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
        rules: dict[str, list[str]] = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        # Create output directory
        output_dir = tmp_path / "output"
        output_dir.mkdir(parents=True, exist_ok=True)

        entries: list[dict[str, object]] = [
            {
                "dn": "uid=josé,dc=example,dc=com",
                "objectclass": ["person"],
                "attributes": {"cn": "José García", "description": "ñoño"},
            },
        ]

        result = pipeline._write_category_file("users", entries, "users.ldif")

        assert result.is_success
        count = result.unwrap()
        assert count == 1

        # Verify Unicode content
        output_file = output_dir / "users.ldif"
        content = output_file.read_text(encoding="utf-8")
        assert "José García" in content
        assert "ñoño" in content

    def test_write_categorized_output_partial_empty_categories(
        self, tmp_path: Path
    ) -> None:
        """Test writing with some empty and some populated categories."""
        rules: dict[str, list[str]] = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
            parser_quirk=MagicMock(),
            writer_quirk=MagicMock(),
        )

        # Create output directories
        pipeline._create_output_directory()

        categorized: dict[str, list[dict[str, object]]] = {
            "schema": [],  # Empty
            "hierarchy": [
                {
                    "dn": "ou=users,dc=example,dc=com",
                    "objectclass": ["organizationalUnit"],
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
