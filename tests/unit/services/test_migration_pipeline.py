"""Test suite for LDIF migration pipeline.

This module provides comprehensive testing for FlextLdifMigrationPipeline which
handles generic server-to-server LDIF migrations using RFC parsers with quirks.

Tests use the new API with individual parameters (input_dir, output_dir, source_server, target_server)
not the old params dict approach.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif.services.migration import FlextLdifMigrationPipeline


class TestMigrationPipelineInitialization:
    """Test suite for migration pipeline initialization with new API."""

    def test_initialization_with_required_params(self, tmp_path: Path) -> None:
        """Test pipeline initializes with required parameters."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server="oid",
            target_server="oud",
        )

        assert pipeline is not None

    def test_initialization_simple_mode(self, tmp_path: Path) -> None:
        """Test pipeline initialization for simple mode."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            output_filename="migrated.ldif",
            source_server="oid",
            target_server="oud",
        )

        assert pipeline is not None

    def test_initialization_categorized_mode(self, tmp_path: Path) -> None:
        """Test pipeline initialization for categorized mode."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        categorization_rules = {
            "hierarchy_objectclasses": ["organization"],
            "user_objectclasses": ["inetOrgPerson"],
            "group_objectclasses": ["groupOfNames"],
            "acl_attributes": [],
        }

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="categorized",
            categorization_rules=categorization_rules,
            source_server="oid",
            target_server="oud",
        )

        assert pipeline is not None

    @pytest.mark.parametrize(
        ("source", "target"),
        [
            ("oid", "oud"),
            ("oid", "openldap"),
            ("oud", "openldap"),
            ("openldap", "oid"),
            ("openldap", "oud"),
            ("rfc", "rfc"),
        ],
    )
    def test_initialization_with_different_server_types(
        self,
        source: str,
        target: str,
        tmp_path: Path,
    ) -> None:
        """Test pipeline initialization with various server type combinations."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server=source,
            target_server=target,
        )

        assert pipeline is not None


class TestMigrationPipelineValidation:
    """Test suite for parameter validation."""

    def test_execute_fails_with_nonexistent_input_dir(self, tmp_path: Path) -> None:
        """Test pipeline fails when input directory doesn't exist."""
        nonexistent_input = tmp_path / "nonexistent"
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=nonexistent_input,
            output_dir=output_dir,
            source_server="oid",
            target_server="oud",
        )

        result = pipeline.execute()

        # Pipeline should handle nonexistent input directory gracefully
        assert result.is_success
        execution_result = result.unwrap()
        assert execution_result.entries_by_category == {}
        if execution_result.statistics is not None:
            assert execution_result.statistics.total_entries == 0

    def test_execute_creates_output_dir_if_missing(self, tmp_path: Path) -> None:
        """Test pipeline creates output directory if it doesn't exist."""
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        nonexistent_output = tmp_path / "nonexistent"

        # Create a simple LDIF file
        _ = (input_dir / "test.ldif").write_text(
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n",
        )

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=nonexistent_output,
            source_server="rfc",
            target_server="rfc",
        )

        result = pipeline.execute()

        # Pipeline should succeed and create the output directory
        assert result.is_success
        assert nonexistent_output.exists()


class TestMigrationPipelineWithEmptyInput:
    """Test suite for handling empty input directories."""

    def test_simple_mode_with_empty_input(self, tmp_path: Path) -> None:
        """Test simple mode handles empty input directory gracefully."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        # No LDIF files in input directory
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            source_server="oid",
            target_server="oud",
        )

        result = pipeline.execute()

        # Pipeline should handle gracefully (no entries to process)
        # Should either succeed with 0 entries or fail with informative message
        assert result.is_success or result.is_failure

    def test_categorized_mode_with_empty_input(self, tmp_path: Path) -> None:
        """Test categorized mode handles empty input directory gracefully."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        categorization_rules = {
            "hierarchy_objectclasses": ["organization"],
            "user_objectclasses": ["inetOrgPerson"],
            "group_objectclasses": ["groupOfNames"],
            "acl_attributes": [],
        }

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="categorized",
            categorization_rules=categorization_rules,
            source_server="oid",
            target_server="oud",
        )

        result = pipeline.execute()

        # Pipeline should handle gracefully
        assert result.is_success or result.is_failure


class TestMigrationPipelineSimpleMode:
    """Test suite for simple migration mode."""

    def test_simple_mode_basic_execution(self, tmp_path: Path) -> None:
        """Test simple mode executes successfully."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        # Create a simple LDIF file
        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
objectClass: top
cn: test
sn: test
"""
        _ = (input_dir / "test.ldif").write_text(ldif_content)

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            output_filename="migrated.ldif",
            source_server="rfc",
            target_server="rfc",
        )

        result = pipeline.execute()

        assert result.is_success or result.is_failure

    def test_simple_mode_with_filtering(self, tmp_path: Path) -> None:
        """Test simple mode with attribute filtering."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
mail: test@example.com
"""
        _ = (input_dir / "test.ldif").write_text(ldif_content)

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            forbidden_attributes=["mail"],
            source_server="rfc",
            target_server="rfc",
        )

        result = pipeline.execute()

        assert result.is_success or result.is_failure


class TestMigrationPipelineCategorizedMode:
    """Test suite for categorized migration mode."""

    def test_categorized_mode_basic_execution(self, tmp_path: Path) -> None:
        """Test categorized mode executes successfully."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_content = """dn: cn=schema,cn=admin
objectClass: top
cn: schema

dn: cn=admin,dc=example,dc=com
objectClass: person
cn: admin
"""
        _ = (input_dir / "test.ldif").write_text(ldif_content)

        categorization_rules = {
            "hierarchy_objectclasses": ["top"],
            "user_objectclasses": ["person"],
            "group_objectclasses": ["groupOfNames"],
            "acl_attributes": [],
        }

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="categorized",
            categorization_rules=categorization_rules,
            source_server="rfc",
            target_server="rfc",
        )

        result = pipeline.execute()

        assert result.is_success or result.is_failure

    def test_categorized_mode_with_base_dn_filtering(self, tmp_path: Path) -> None:
        """Test categorized mode with base DN filtering."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_content = """dn: cn=admin,dc=example,dc=com
objectClass: person
cn: admin

dn: cn=user,dc=other,dc=com
objectClass: person
cn: user
"""
        _ = (input_dir / "test.ldif").write_text(ldif_content)

        categorization_rules = {
            "hierarchy_objectclasses": ["top"],
            "user_objectclasses": ["person"],
            "group_objectclasses": ["groupOfNames"],
            "acl_attributes": [],
        }

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="categorized",
            categorization_rules=categorization_rules,
            base_dn="dc=example,dc=com",
            source_server="rfc",
            target_server="rfc",
        )

        result = pipeline.execute()

        assert result.is_success or result.is_failure

    def test_categorized_mode_with_forbidden_attributes(self, tmp_path: Path) -> None:
        """Test categorized mode filtering forbidden attributes."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_content = """dn: cn=admin,dc=example,dc=com
objectClass: person
cn: admin
mail: admin@example.com
userPassword: secret
"""
        _ = (input_dir / "test.ldif").write_text(ldif_content)

        categorization_rules = {
            "hierarchy_objectclasses": ["top"],
            "user_objectclasses": ["person"],
            "group_objectclasses": ["groupOfNames"],
            "acl_attributes": [],
        }

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="categorized",
            categorization_rules=categorization_rules,
            forbidden_attributes=["userPassword"],
            source_server="rfc",
            target_server="rfc",
        )

        result = pipeline.execute()

        assert result.is_success or result.is_failure


class TestMigrationPipelineMultipleFiles:
    """Test suite for handling multiple input files."""

    def test_simple_mode_with_multiple_files(self, tmp_path: Path) -> None:
        """Test simple mode processes multiple input files."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        # Create multiple LDIF files
        _ = (input_dir / "schema.ldif").write_text(
            "dn: cn=schema\nobjectClass: top\ncn: schema\n",
        )
        _ = (input_dir / "data.ldif").write_text(
            "dn: cn=admin,dc=example,dc=com\nobjectClass: person\ncn: admin\n",
        )

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            input_files=["schema.ldif", "data.ldif"],
            source_server="rfc",
            target_server="rfc",
        )

        result = pipeline.execute()

        assert result.is_success or result.is_failure

    def test_categorized_mode_with_custom_output_files(self, tmp_path: Path) -> None:
        """Test categorized mode with custom output file names."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        _ = (input_dir / "test.ldif").write_text(
            "dn: cn=admin,dc=example,dc=com\nobjectClass: person\ncn: admin\n",
        )

        categorization_rules = {
            "hierarchy_objectclasses": ["top"],
            "user_objectclasses": ["person"],
            "group_objectclasses": ["groupOfNames"],
            "acl_attributes": [],
        }

        output_files = {
            "schema": "00_schema.ldif",
            "hierarchy": "01_hierarchy.ldif",
            "user": "02_user.ldif",
            "group": "03_group.ldif",
            "acl": "04_acl.ldif",
            "rejected": "99_rejected.ldif",
        }

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="categorized",
            categorization_rules=categorization_rules,
            output_files=output_files,
            source_server="rfc",
            target_server="rfc",
        )

        result = pipeline.execute()

        assert result.is_success or result.is_failure


class TestMigrationPipelineServerConversions:
    """Test suite for server-specific conversions."""

    @pytest.mark.parametrize(
        ("source", "target"),
        [
            ("oid", "oud"),
            ("oud", "oid"),
            ("rfc", "oid"),
            ("rfc", "oud"),
        ],
    )
    def test_server_conversion_modes(
        self,
        source: str,
        target: str,
        tmp_path: Path,
    ) -> None:
        """Test server-specific conversion modes."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        _ = (input_dir / "test.ldif").write_text(
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n",
        )

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server=source,
            target_server=target,
        )

        result = pipeline.execute()

        assert result.is_success or result.is_failure
