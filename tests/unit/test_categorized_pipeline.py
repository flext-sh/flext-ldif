"""Unit tests for FlextLdifCategorizedMigrationPipeline.

Tests for Phase 2 Day 2: Categorization logic with 6-directory output structure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

from flext_core import FlextCore

from flext_ldif import FlextLdifCategorizedMigrationPipeline


class TestCategorizedPipelineInitialization:
    """Test initialization and configuration."""

    def test_initialization_with_required_params(self, tmp_path: Path) -> None:
        """Test pipeline initialization with required parameters."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        rules: FlextCore.Types.Dict = {
            "hierarchy_objectclasses": ["organization"],
            "user_objectclasses": ["person"],
            "group_objectclasses": ["groupOfNames"],
            "acl_attributes": ["aci"],
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules=rules,
        )

        assert pipeline._input_dir == input_dir
        assert pipeline._output_dir == output_dir
        assert pipeline._rules == rules
        assert pipeline._source_server == "oracle_oid"
        assert pipeline._target_server == "oracle_oud"

    def test_initialization_with_custom_servers(self, tmp_path: Path) -> None:
        """Test pipeline initialization with custom server types."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        rules: FlextCore.Types.Dict = {}

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules=rules,
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
        rules: FlextCore.Types.Dict = {}

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=output_dir,
            categorization_rules=rules,
        )

        result = pipeline._create_output_directories()

        assert result.is_success
        assert output_dir.exists()
        assert (output_dir / "00-schema").exists()
        assert (output_dir / "01-hierarchy").exists()
        assert (output_dir / "02-users").exists()
        assert (output_dir / "03-groups").exists()
        assert (output_dir / "04-acl").exists()
        assert (output_dir / "05-rejected").exists()

    def test_create_output_directories_idempotent(self, tmp_path: Path) -> None:
        """Test directory creation is idempotent."""
        output_dir = tmp_path / "output"
        rules: FlextCore.Types.Dict = {}

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=output_dir,
            categorization_rules=rules,
        )

        # Create directories twice
        result1 = pipeline._create_output_directories()
        result2 = pipeline._create_output_directories()

        assert result1.is_success
        assert result2.is_success
        assert (output_dir / "00-schema").exists()


class TestDNPatternMatching:
    """Test DN pattern matching."""

    def test_matches_dn_pattern_single_match(self, tmp_path: Path) -> None:
        """Test DN matching with single pattern."""
        rules: FlextCore.Types.Dict = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        patterns = [r"uid=.+"]
        assert pipeline._matches_dn_pattern("uid=jdoe,dc=example,dc=com", patterns)

    def test_matches_dn_pattern_no_match(self, tmp_path: Path) -> None:
        """Test DN not matching any pattern."""
        rules: FlextCore.Types.Dict = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        patterns = [r"uid=.+"]
        assert not pipeline._matches_dn_pattern("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", patterns)

    def test_matches_dn_pattern_case_insensitive(self, tmp_path: Path) -> None:
        """Test DN matching is case insensitive."""
        rules: FlextCore.Types.Dict = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        patterns = [r"uid=.+"]
        assert pipeline._matches_dn_pattern("UID=JDOE,DC=EXAMPLE,DC=COM", patterns)

    def test_matches_dn_pattern_invalid_regex(self, tmp_path: Path) -> None:
        """Test DN matching handles invalid regex gracefully."""
        rules: FlextCore.Types.Dict = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        patterns = [r"[invalid(regex"]  # Invalid regex
        assert not pipeline._matches_dn_pattern("uid=jdoe,dc=example,dc=com", patterns)

    def test_matches_dn_pattern_multiple_patterns(self, tmp_path: Path) -> None:
        """Test DN matching with multiple patterns."""
        rules: FlextCore.Types.Dict = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        patterns = [r"uid=.+", r"cn=.+,ou=users", r"cn=.+,ou=people"]
        assert pipeline._matches_dn_pattern(
            "cn=jdoe,ou=users,dc=example,dc=com", patterns
        )


class TestACLDetection:
    """Test ACL attribute detection."""

    def test_has_acl_attributes_with_aci(self, tmp_path: Path) -> None:
        """Test ACL detection with aci attribute."""
        rules: FlextCore.Types.Dict = {
            "acl_attributes": ["aci", "orclACI"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        entry: FlextCore.Types.Dict = {
            "dn": "dc=example,dc=com",
            "attributes": {"aci": "(targetattr=*)(version 3.0; acl...)"},
            "objectClass": ["top"],
        }

        assert pipeline._has_acl_attributes(entry)

    def test_has_acl_attributes_without_acl(self, tmp_path: Path) -> None:
        """Test ACL detection without ACL attributes."""
        rules: FlextCore.Types.Dict = {
            "acl_attributes": ["aci", "orclACI"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        entry: FlextCore.Types.Dict = {
            "dn": "uid=jdoe,dc=example,dc=com",
            "attributes": {"cn": "John Doe"},
            "objectClass": ["person"],
        }

        assert not pipeline._has_acl_attributes(entry)

    def test_has_acl_attributes_empty_rules(self, tmp_path: Path) -> None:
        """Test ACL detection with empty rules."""
        rules: FlextCore.Types.Dict = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        entry: FlextCore.Types.Dict = {
            "dn": "dc=example,dc=com",
            "attributes": {"aci": "(targetattr=*)"},
            "objectClass": ["top"],
        }

        assert not pipeline._has_acl_attributes(entry)


class TestEntryCategorization:
    """Test entry categorization logic."""

    def test_categorize_entry_schema(self, tmp_path: Path) -> None:
        """Test categorization of schema entries."""
        rules: FlextCore.Types.Dict = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        entry: FlextCore.Types.Dict = {
            "dn": "cn=schema",
            "attributes": {},
            "objectClass": ["top", "subschema"],
        }

        category, reason = pipeline._categorize_entry(entry)
        assert category == "schema"
        assert reason is None

    def test_categorize_entry_acl(self, tmp_path: Path) -> None:
        """Test categorization of ACL entries."""
        rules: FlextCore.Types.Dict = {
            "acl_attributes": ["aci"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        entry: FlextCore.Types.Dict = {
            "dn": "dc=example,dc=com",
            "attributes": {"aci": "(targetattr=*)"},
            "objectClass": ["top", "domain"],
        }

        category, reason = pipeline._categorize_entry(entry)
        assert category == "acl"
        assert reason is None

    def test_categorize_entry_hierarchy(self, tmp_path: Path) -> None:
        """Test categorization of hierarchy entries."""
        rules: FlextCore.Types.Dict = {
            "hierarchy_objectclasses": ["organization", "organizationalUnit"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        entry: FlextCore.Types.Dict = {
            "dn": "ou=users,dc=example,dc=com",
            "attributes": {"ou": "users"},
            "objectClass": ["top", "organizationalUnit"],
        }

        category, reason = pipeline._categorize_entry(entry)
        assert category == "hierarchy"
        assert reason is None

    def test_categorize_entry_user(self, tmp_path: Path) -> None:
        """Test categorization of user entries."""
        rules: FlextCore.Types.Dict = {
            "user_objectclasses": ["person", "inetOrgPerson"],
            "user_dn_patterns": [r"uid=.+"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        entry: FlextCore.Types.Dict = {
            "dn": "uid=jdoe,dc=example,dc=com",
            "attributes": {"cn": "John Doe", "sn": "Doe"},
            "objectClass": ["top", "person", "inetOrgPerson"],
        }

        category, reason = pipeline._categorize_entry(entry)
        assert category == "users"
        assert reason is None

    def test_categorize_entry_user_rejected_dn(self, tmp_path: Path) -> None:
        """Test categorization rejects user with invalid DN pattern."""
        rules: FlextCore.Types.Dict = {
            "user_objectclasses": ["person"],
            "user_dn_patterns": [r"uid=.+"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        entry: FlextCore.Types.Dict = {
            "dn": "cn=jdoe,dc=example,dc=com",  # No uid=
            "attributes": {"cn": "John Doe"},
            "objectClass": ["top", "person"],
        }

        category, reason = pipeline._categorize_entry(entry)
        assert category == "rejected"
        assert reason is not None
        assert "does not match expected patterns" in reason

    def test_categorize_entry_group(self, tmp_path: Path) -> None:
        """Test categorization of group entries."""
        rules: FlextCore.Types.Dict = {
            "group_objectclasses": ["groupOfNames"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        entry: FlextCore.Types.Dict = {
            "dn": "cn=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com",
            "attributes": {"cn": "REDACTED_LDAP_BIND_PASSWORDs"},
            "objectClass": ["top", "groupOfNames"],
        }

        category, reason = pipeline._categorize_entry(entry)
        assert category == "groups"
        assert reason is None

    def test_categorize_entry_rejected_no_match(self, tmp_path: Path) -> None:
        """Test categorization rejects entries with no matching category."""
        rules: FlextCore.Types.Dict = {
            "hierarchy_objectclasses": ["organization"],
            "user_objectclasses": ["person"],
            "group_objectclasses": ["groupOfNames"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        entry: FlextCore.Types.Dict = {
            "dn": "cn=unknown,dc=example,dc=com",
            "attributes": {"cn": "unknown"},
            "objectClass": ["top", "unknownClass"],
        }

        category, reason = pipeline._categorize_entry(entry)
        assert category == "rejected"
        assert reason is not None
        assert "No matching category" in reason


class TestCategoryBatchProcessing:
    """Test batch categorization of multiple entries."""

    def test_categorize_entries_multiple_categories(self, tmp_path: Path) -> None:
        """Test categorizing entries into multiple categories."""
        rules: FlextCore.Types.Dict = {
            "hierarchy_objectclasses": ["organizationalUnit"],
            "user_objectclasses": ["person"],
            "group_objectclasses": ["groupOfNames"],
            "acl_attributes": ["aci"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        entries: list[FlextCore.Types.Dict] = [
            {
                "dn": "cn=schema",
                "attributes": {},
                "objectClass": ["subschema"],
            },
            {
                "dn": "ou=users,dc=example,dc=com",
                "attributes": {"ou": "users"},
                "objectClass": ["organizationalUnit"],
            },
            {
                "dn": "uid=jdoe,dc=example,dc=com",
                "attributes": {"cn": "John Doe"},
                "objectClass": ["person"],
            },
            {
                "dn": "cn=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com",
                "attributes": {"cn": "REDACTED_LDAP_BIND_PASSWORDs"},
                "objectClass": ["groupOfNames"],
            },
            {
                "dn": "dc=example,dc=com",
                "attributes": {"aci": "(targetattr=*)"},
                "objectClass": ["domain"],
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
        rules: FlextCore.Types.Dict = {
            "user_objectclasses": ["person"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        entries: list[FlextCore.Types.Dict] = [
            {
                "dn": "cn=unknown,dc=example,dc=com",
                "attributes": {"cn": "unknown"},
                "objectClass": ["unknownClass"],
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
        rules: FlextCore.Types.Dict = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=tmp_path / "input",
            output_dir=tmp_path / "output",
            categorization_rules=rules,
        )

        categorized: dict[str, list[FlextCore.Types.Dict]] = {
            "schema": [],
            "hierarchy": [{"dn": "ou=test", "objectClass": ["organizationalUnit"]}],
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

        rules: FlextCore.Types.Dict = {}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules=rules,
        )

        result = pipeline.execute()

        assert result.is_success
        data = result.unwrap()
        assert data["source_server"] == "oracle_oid"
        assert data["target_server"] == "oracle_oud"
        assert (output_dir / "00-schema").exists()
        assert (output_dir / "05-rejected").exists()
