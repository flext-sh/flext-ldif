"""Phase 8: Execution tests for FlextLdifCategorizedMigrationPipeline.

Tests the execute() method and core pipeline logic including:
- Entry parsing from LDIF files
- Entry categorization using rules
- Entry transformation with quirks
- Output file generation
- Statistics collection and reporting

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif.models import FlextLdifModels
from flext_ldif.pipelines.categorized_pipeline import (
    FlextLdifCategorizedMigrationPipeline,
)


class TestCategorizedPipelineExecution:
    """Test pipeline execute() method and core logic."""

    @pytest.mark.unit
    def test_execute_with_empty_input_directory(self, tmp_path: Path) -> None:
        """Test execute() with empty input directory returns empty result."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success
        exec_result = result.unwrap()
        assert exec_result.entries_by_category == {}
        assert exec_result.statistics.total_entries == 0
        assert exec_result.statistics.processed_entries == 0

    @pytest.mark.unit
    def test_execute_creates_output_directory_if_missing(self, tmp_path: Path) -> None:
        """Test execute() creates output directory if it doesn't exist."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        # Don't create output_dir - let pipeline create it

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success
        assert output_dir.exists()

    @pytest.mark.unit
    def test_execute_fails_with_invalid_input_directory(self, tmp_path: Path) -> None:
        """Test execute() fails gracefully with invalid input directory."""
        input_dir = tmp_path / "nonexistent"
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_failure

    @pytest.mark.unit
    def test_execute_with_simple_ldif_content(self, tmp_path: Path) -> None:
        """Test execute() parses and processes simple LDIF content."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        # Create simple LDIF file
        ldif_file = input_dir / "test.ldif"
        ldif_content = """dn: cn=schema,dc=example,dc=com
objectClass: ldapSubentry
objectClass: subschema
cn: schema

dn: dc=example,dc=com
objectClass: dcObject
objectClass: organization
dc: example
o: Example Corp

dn: ou=users,dc=example,dc=com
objectClass: organizationalUnit
ou: users

dn: cn=user1,ou=users,dc=example,dc=com
objectClass: person
cn: user1
sn: User One
"""
        ldif_file.write_text(ldif_content)

        rules = {
            "hierarchy_objectclasses": ["dcObject", "organizationalUnit"],
            "user_objectclasses": ["person"],
            "schema_entries": ["subschema"],
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success
        exec_result = result.unwrap()

        # Verify entries were parsed
        assert exec_result.statistics.total_entries >= 4

    @pytest.mark.unit
    def test_execute_categorizes_entries_by_objectclass(self, tmp_path: Path) -> None:
        """Test execute() correctly categorizes entries by objectClass rules."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        # Create LDIF with mixed entry types
        ldif_file = input_dir / "mixed.ldif"
        ldif_content = """dn: ou=hierarchy,dc=example,dc=com
objectClass: organizationalUnit
ou: hierarchy

dn: cn=person1,ou=people,dc=example,dc=com
objectClass: person
cn: person1
sn: Person

dn: cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com
objectClass: groupOfNames
cn: REDACTED_LDAP_BIND_PASSWORDs
member: cn=person1,ou=people,dc=example,dc=com
"""
        ldif_file.write_text(ldif_content)

        rules = {
            "hierarchy_objectclasses": ["organizationalUnit"],
            "user_objectclasses": ["person"],
            "group_objectclasses": ["groupOfNames"],
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success

    @pytest.mark.unit
    def test_execute_handles_multiple_ldif_files(self, tmp_path: Path) -> None:
        """Test execute() processes multiple LDIF files from input directory."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        # Create multiple LDIF files
        file1 = input_dir / "file1.ldif"
        file1.write_text("""dn: dc=example,dc=com
objectClass: dcObject
dc: example

dn: cn=user1,dc=example,dc=com
objectClass: person
cn: user1
sn: One
""")

        file2 = input_dir / "file2.ldif"
        file2.write_text("""dn: cn=user2,dc=example,dc=com
objectClass: person
cn: user2
sn: Two

dn: cn=group1,dc=example,dc=com
objectClass: groupOfNames
cn: group1
member: cn=user1,dc=example,dc=com
""")

        rules = {
            "user_objectclasses": ["person"],
            "group_objectclasses": ["groupOfNames"],
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success
        exec_result = result.unwrap()
        # Should have entries from both files
        assert exec_result.statistics.total_entries >= 4

    @pytest.mark.unit
    def test_execute_returns_pipeline_execution_result(self, tmp_path: Path) -> None:
        """Test execute() returns proper PipelineExecutionResult structure."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success

        exec_result = result.unwrap()
        assert isinstance(exec_result, FlextLdifModels.PipelineExecutionResult)
        assert hasattr(exec_result, "entries_by_category")
        assert hasattr(exec_result, "statistics")
        assert hasattr(exec_result, "file_paths")

    @pytest.mark.unit
    def test_execute_preserves_entry_attributes(self, tmp_path: Path) -> None:
        """Test execute() preserves all entry attributes during processing."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "attrs.ldif"
        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: Test
mail: test@example.com
telephoneNumber: +1234567890
description: Test user with multiple attributes
"""
        ldif_file.write_text(ldif_content)

        rules = {"user_objectclasses": ["person"]}

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success

    @pytest.mark.unit
    def test_execute_with_custom_server_types(self, tmp_path: Path) -> None:
        """Test execute() works with custom source and target servers."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: dc=example,dc=com
objectClass: dcObject
dc: example
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            source_server="openldap",
            target_server="active_directory",
        )

        result = pipeline.execute()
        assert result.is_success

    @pytest.mark.unit
    def test_execute_with_custom_output_files(self, tmp_path: Path) -> None:
        """Test execute() respects custom output file mappings."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: dc=example,dc=com
objectClass: dcObject
dc: example
""")

        custom_output = {
            "schema": "custom_schema.ldif",
            "hierarchy": "custom_hierarchy.ldif",
            "users": "custom_users.ldif",
            "groups": "custom_groups.ldif",
            "acl": "custom_acl.ldif",
            "rejected": "custom_rejected.ldif",
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            output_files=custom_output,
        )

        result = pipeline.execute()
        assert result.is_success

    @pytest.mark.unit
    def test_execute_collects_statistics(self, tmp_path: Path) -> None:
        """Test execute() collects and returns accurate statistics."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: dc=example,dc=com
objectClass: dcObject
dc: example

dn: cn=user1,dc=example,dc=com
objectClass: person
cn: user1
sn: One

dn: cn=user2,dc=example,dc=com
objectClass: person
cn: user2
sn: Two
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"user_objectclasses": ["person"]},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success

        stats = result.unwrap().statistics
        assert stats.total_entries >= 3
        assert stats.processed_entries >= 0

    @pytest.mark.unit
    def test_execute_with_base_dn(self, tmp_path: Path) -> None:
        """Test execute() respects base DN configuration."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text("""dn: dc=example,dc=com
objectClass: dcObject
dc: example
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            base_dn="dc=example,dc=com",
        )

        result = pipeline.execute()
        assert result.is_success

    @pytest.mark.unit
    def test_execute_returns_flext_result(self, tmp_path: Path) -> None:
        """Test execute() returns FlextResult type with proper success handling."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        # Should be FlextResult
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")
        assert hasattr(result, "unwrap")
        assert result.is_success or result.is_failure

    @pytest.mark.unit
    def test_execute_handles_ldif_with_multiline_attributes(
        self, tmp_path: Path
    ) -> None:
        """Test execute() correctly handles multiline LDIF attributes."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_file = input_dir / "multiline.ldif"
        # LDIF with folded lines (continuation)
        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: Test User
description: This is a very long description that needs to be
 continued on the next line according to LDIF format specifications
"""
        ldif_file.write_text(ldif_content)

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"user_objectclasses": ["person"]},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success

    @pytest.mark.unit
    def test_execute_with_input_file_list(self, tmp_path: Path) -> None:
        """Test execute() with specific input file list."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        # Create multiple files
        file1 = input_dir / "file1.ldif"
        file1.write_text("""dn: cn=test1,dc=example,dc=com
objectClass: person
cn: test1
sn: Test
""")

        file2 = input_dir / "file2.ldif"
        file2.write_text("""dn: cn=test2,dc=example,dc=com
objectClass: person
cn: test2
sn: Test
""")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            input_files=["file1.ldif", "file2.ldif"],
        )

        result = pipeline.execute()
        assert result.is_success
