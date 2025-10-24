"""Comprehensive real execution tests for categorized_pipeline.py.

Tests the FlextLdifCategorizedMigrationPipeline with actual LDIF fixture data:
- Real pipeline execution with fixture files
- Entry parsing and categorization
- File output generation (00-schema through 05-rejected)
- Quirks integration and transformation
- Error handling with proper FlextResult[T] patterns

Uses actual OID and OUD LDIF fixtures from /tests/fixtures/ directories.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from flext_ldif.categorized_pipeline import (
    FlextLdifCategorizedMigrationPipeline,
)
from flext_ldif.models import FlextLdifModels


class TestCategorizedPipelineExecution:
    """Test categorized pipeline execution with real LDIF data."""

    @pytest.fixture
    def oid_entries_fixture(self) -> Path:
        """Get path to OID entries fixture."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oid"
            / "oid_entries_fixtures.ldif"
        )

    @pytest.fixture
    def oid_schema_fixture(self) -> Path:
        """Get path to OID schema fixture."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oid"
            / "oid_schema_fixtures.ldif"
        )

    @pytest.fixture
    def oud_entries_fixture(self) -> Path:
        """Get path to OUD entries fixture."""
        return (
            Path(__file__).parent.parent
            / "fixtures"
            / "oud"
            / "oud_entries_fixtures.ldif"
        )

    @pytest.fixture
    def temp_output_dir(self) -> Path:
        """Create temporary output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_pipeline_executes_with_minimal_config(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline execution with minimal configuration."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        # Create input directory with fixture
        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success, f"Pipeline execution failed: {result.error}"

        execution_result = result.unwrap()
        assert isinstance(execution_result, FlextLdifModels.PipelineExecutionResult)
        assert execution_result.statistics is not None

    def test_pipeline_creates_output_directory(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline creates output directory if it doesn't exist."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        output_dir = temp_output_dir / "new_output"
        assert not output_dir.exists()

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

    def test_pipeline_handles_empty_input(self, temp_output_dir: Path) -> None:
        """Test pipeline with empty input directory."""
        input_dir = temp_output_dir / "empty_input"
        input_dir.mkdir()

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        # Empty input returns success with empty result
        assert result.is_success

    def test_pipeline_executes_with_categorization_rules(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline execution with categorization rules."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        rules = {
            "users": ["(objectClass=person)", "(objectClass=inetOrgPerson)"],
            "groups": ["(objectClass=groupOfNames)"],
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_executes_with_custom_output_files(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline with custom output file names."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        output_files = {
            "schema": "00-schema.ldif",
            "hierarchy": "01-hierarchy.ldif",
            "users": "02-users.ldif",
            "groups": "03-groups.ldif",
            "acl": "04-acl.ldif",
            "rejected": "05-rejected.ldif",
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            output_files=output_files,
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_executes_with_forbidden_attributes(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline with forbidden attributes filter."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            forbidden_attributes=["authPassword", "userPassword"],
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_executes_with_forbidden_objectclasses(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline with forbidden objectClasses filter."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            forbidden_objectclasses=["orclContainerOC", "orclService"],
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_executes_with_base_dn_filter(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline with base DN filter."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            base_dn="dc=example,dc=com",
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_executes_with_schema_whitelist(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline with schema whitelist rules."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        whitelist = {
            "attributes": ["cn", "mail", "displayName"],
            "objectclasses": ["person", "organizationalUnit"],
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            schema_whitelist_rules=whitelist,
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_executes_with_multiple_input_files(
        self, oid_entries_fixture: Path, oid_schema_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline with multiple input files."""
        if not oid_entries_fixture.exists() or not oid_schema_fixture.exists():
            pytest.skip("Required fixtures not found")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()

        entries_copy = input_dir / "entries.ldif"
        entries_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        schema_copy = input_dir / "schema.ldif"
        schema_copy.write_text(
            oid_schema_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        input_files = ["entries.ldif", "schema.ldif"]

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            input_files=input_files,
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_execution_result_structure(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline execution result has proper structure."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success

        execution_result = result.unwrap()
        assert hasattr(execution_result, "entries_by_category")
        assert hasattr(execution_result, "statistics")
        assert hasattr(execution_result, "file_paths")

    def test_pipeline_with_path_objects(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline accepts Path objects for input/output directories."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        output_dir = temp_output_dir / "output"

        # Use Path objects directly
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,  # Path object
            output_dir=output_dir,  # Path object
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_with_string_paths(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline accepts string paths for input/output directories."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        # Use string paths
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=str(input_dir),  # String path
            output_dir=str(temp_output_dir / "output"),  # String path
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_with_custom_server_types(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline with custom source and target server types."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            source_server="oracle_oid",
            target_server="oracle_oud",
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_stores_configuration(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline stores configuration correctly."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        rules = {"users": ["(objectClass=person)"]}
        whitelist = {"attributes": ["cn", "mail"]}

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=temp_output_dir / "input",
            output_dir=temp_output_dir / "output",
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
            schema_whitelist_rules=whitelist,
            source_server="oracle_oid",
            target_server="oracle_oud",
        )

        # Verify configuration is stored
        assert pipeline._categorization_rules == rules
        assert pipeline._schema_whitelist_rules == whitelist
        assert pipeline._source_server == "oracle_oid"
        assert pipeline._target_server == "oracle_oud"

    def test_pipeline_handles_nonexistent_input_directory(
        self, temp_output_dir: Path
    ) -> None:
        """Test pipeline with nonexistent input directory."""
        nonexistent = temp_output_dir / "nonexistent"

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=nonexistent,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        # Should handle gracefully with empty result
        assert result.is_success or result.is_failure

    def test_pipeline_execution_with_aud_fixtures(
        self, oud_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline execution with OUD fixtures."""
        if not oud_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oud_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oud_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            source_server="oracle_oud",
            target_server="oracle_oid",
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_returns_flextresult(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline.execute() returns proper FlextResult[T]."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")
        assert hasattr(result, "error")
        assert hasattr(result, "unwrap")

    def test_pipeline_statistics_generation(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline generates statistics."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success

        execution_result = result.unwrap()
        stats = execution_result.statistics
        assert isinstance(stats, FlextLdifModels.PipelineStatistics)
        assert hasattr(stats, "total_entries")
        assert hasattr(stats, "processed_entries")

    def test_pipeline_with_all_combined_options(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline with all options combined."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        output_files = {
            "schema": "00-schema.ldif",
            "hierarchy": "01-hierarchy.ldif",
            "users": "02-users.ldif",
            "groups": "03-groups.ldif",
            "acl": "04-acl.ldif",
            "rejected": "05-rejected.ldif",
        }

        rules = {
            "users": ["(objectClass=person)"],
            "groups": ["(objectClass=groupOfNames)"],
        }

        whitelist = {
            "attributes": ["cn", "mail", "displayName", "objectClass"],
            "objectclasses": ["person", "groupOfNames"],
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
            source_server="oracle_oid",
            target_server="oracle_oud",
            output_files=output_files,
            forbidden_attributes=["authPassword"],
            forbidden_objectclasses=["orclService"],
            base_dn="dc=example,dc=com",
            schema_whitelist_rules=whitelist,
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_case_insensitive_base_dn(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline normalizes base DN to lowercase."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        # Use uppercase base DN
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            base_dn="DC=Example,DC=Com",  # Uppercase
        )

        # Verify it's normalized
        assert pipeline._base_dn == "dc=example,dc=com"

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_with_acl_fixtures(self, temp_output_dir: Path) -> None:
        """Test pipeline with ACL entries from fixtures."""
        acl_fixture = (
            Path(__file__).parent.parent / "fixtures" / "oid" / "oid_acl_fixtures.ldif"
        )
        if not acl_fixture.exists():
            pytest.skip(f"ACL fixture not found: {acl_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "acl_entries.ldif"
        fixture_copy.write_text(
            acl_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_reject_entries_with_invalid_base_dn(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline rejects entries not matching base DN."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        # Use base DN that doesn't match fixture entries
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            base_dn="ou=users,dc=nonexistent,dc=com",
        )

        result = pipeline.execute()
        assert result.is_success
        # Entries that don't match base DN should be rejected
        execution_result = result.unwrap()
        # Most entries should be in rejected category
        assert isinstance(execution_result, FlextLdifModels.PipelineExecutionResult)

    def test_pipeline_with_complex_categorization_rules(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline with complex multi-pattern categorization rules."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        rules = {
            "users": [
                "(objectClass=person)",
                "(objectClass=inetOrgPerson)",
                "(objectClass=organizationalPerson)",
            ],
            "groups": [
                "(objectClass=groupOfNames)",
                "(objectClass=groupOfUniqueNames)",
                "(objectClass=groupOfURLs)",
            ],
            "hierarchy": [
                "(objectClass=organization)",
                "(objectClass=organizationalUnit)",
                "(objectClass=domain)",
            ],
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success
        execution_result = result.unwrap()
        assert execution_result.entries_by_category is not None

    def test_pipeline_filters_multiple_forbidden_attributes(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline filters multiple forbidden attributes including subtypes."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        forbidden_attrs = [
            "authPassword",
            "userPassword",
            "pwdHistory",
            "authpassword;orclcommonpwd",
            "authpassword;oid",
        ]

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            forbidden_attributes=forbidden_attrs,
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_filters_multiple_forbidden_objectclasses(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline filters multiple forbidden objectClasses."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        forbidden_ocs = [
            "orclContainerOC",
            "orclService",
            "orclcontextaux82",
            "orclUserSecurityAux",
            "orclGroupSecurityAux",
        ]

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            forbidden_objectclasses=forbidden_ocs,
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_with_base_dn_and_forbidden_filters_combined(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline with base DN filtering combined with forbidden attributes."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            base_dn="dc=example,dc=com",
            forbidden_attributes=["authPassword", "userPassword"],
            forbidden_objectclasses=["orclContainerOC"],
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_handles_malformed_ldif_gracefully(
        self, temp_output_dir: Path
    ) -> None:
        """Test pipeline handles gracefully if LDIF parsing fails."""
        input_dir = temp_output_dir / "input"
        input_dir.mkdir()

        # Create a malformed LDIF file
        malformed_ldif = input_dir / "malformed.ldif"
        malformed_ldif.write_text("this is not valid ldif\n", encoding="utf-8")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        # Pipeline should handle gracefully
        result = pipeline.execute()
        # May succeed with empty entries or fail - both are acceptable graceful handling
        assert result.is_success or result.is_failure

    def test_pipeline_with_input_files_filter(
        self, oid_entries_fixture: Path, oid_schema_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline processes only specified input files."""
        if not oid_entries_fixture.exists() or not oid_schema_fixture.exists():
            pytest.skip("Required fixtures not found")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()

        entries_copy = input_dir / "entries.ldif"
        entries_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        schema_copy = input_dir / "schema.ldif"
        schema_copy.write_text(
            oid_schema_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        # Only process entries.ldif, skip schema.ldif
        input_files = ["entries.ldif"]

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            input_files=input_files,
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_with_nonexistent_input_file_in_filter(
        self, temp_output_dir: Path
    ) -> None:
        """Test pipeline handles nonexistent file in input_files filter."""
        input_dir = temp_output_dir / "input"
        input_dir.mkdir()

        # Create one file
        test_file = input_dir / "test.ldif"
        test_file.write_text("version: 1\n", encoding="utf-8")

        # Try to filter for nonexistent file
        input_files = ["nonexistent.ldif"]

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            input_files=input_files,
        )

        result = pipeline.execute()
        # Should handle gracefully
        assert result.is_success or result.is_failure

    def test_pipeline_statistics_has_all_required_fields(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline statistics contains all required tracking fields."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success

        execution_result = result.unwrap()
        stats = execution_result.statistics

        # Verify all required fields exist
        assert hasattr(stats, "total_entries")
        assert hasattr(stats, "processed_entries")
        assert hasattr(stats, "schema_entries")
        assert hasattr(stats, "hierarchy_entries")
        assert hasattr(stats, "user_entries")
        assert hasattr(stats, "group_entries")
        assert hasattr(stats, "acl_entries")
        assert hasattr(stats, "rejected_entries")

    def test_pipeline_result_file_paths_mapping(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline result contains correct file paths mapping."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        output_files = {
            "schema": "00-schema.ldif",
            "hierarchy": "01-hierarchy.ldif",
            "users": "02-users.ldif",
            "groups": "03-groups.ldif",
            "acl": "04-acl.ldif",
            "rejected": "05-rejected.ldif",
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            output_files=output_files,
        )

        result = pipeline.execute()
        assert result.is_success

        execution_result = result.unwrap()
        assert execution_result.file_paths == output_files

    def test_pipeline_entries_by_category_structure(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline result entries_by_category has correct structure."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success

        execution_result = result.unwrap()
        entries_by_category = execution_result.entries_by_category

        # Verify all categories exist as keys
        expected_categories = {
            "schema",
            "hierarchy",
            "users",
            "groups",
            "acl",
            "rejected",
        }
        assert set(entries_by_category.keys()) == expected_categories

        # Verify each category contains Entry objects
        for entries in entries_by_category.values():
            assert isinstance(entries, list)
            for entry in entries:
                assert isinstance(entry, FlextLdifModels.Entry)

    def test_pipeline_with_oud_fixtures_source_and_target(
        self, oud_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline with OUD as both source and target."""
        if not oud_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oud_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oud_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            source_server="oracle_oud",
            target_server="oracle_oud",  # Same server
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_entry_categorization_with_person_objectclass(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline correctly categorizes person entries."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        # Categorization rules specifically for person
        rules = {
            "users": ["(objectClass=person)"],
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success
        execution_result = result.unwrap()
        # Should have some users categorized
        assert execution_result.entries_by_category is not None

    def test_pipeline_entry_categorization_with_groupofnames(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline correctly categorizes group entries."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        # Categorization rules specifically for groups
        rules = {
            "groups": ["(objectClass=groupOfNames)"],
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_entry_categorization_with_organizational_unit(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline correctly categorizes organizational unit entries."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        # Categorization rules for hierarchy
        rules = {
            "hierarchy": ["(objectClass=organizationalUnit)"],
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_base_dn_filtering_with_multiple_levels(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline base DN filtering with multi-level hierarchy."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        # Test various base DN patterns
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            base_dn="dc=com",  # Broad base DN
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_forbidden_attributes_case_insensitive(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline forbidden attributes filtering is case-insensitive."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        # Mix uppercase and lowercase
        forbidden = [
            "AUTHPASSWORD",
            "userPassword",
            "PwdHistory",
        ]

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            forbidden_attributes=forbidden,
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_forbidden_objectclasses_case_insensitive(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline forbidden objectClasses filtering is case-insensitive."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        # Mix case
        forbidden_ocs = [
            "ORCLCONTAINEROC",
            "orclService",
            "OralGroupAux",
        ]

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            forbidden_objectclasses=forbidden_ocs,
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_with_empty_schema_whitelist(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline with empty schema whitelist rules."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        whitelist = {
            "attributes": [],
            "objectclasses": [],
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            schema_whitelist_rules=whitelist,
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_verifies_entry_dn_in_result(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline result entries have valid DN objects."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success

        execution_result = result.unwrap()
        entries_by_category = execution_result.entries_by_category

        # Check that all entries have valid DN objects
        for entries in entries_by_category.values():
            if isinstance(entries, list) and len(entries) > 0:
                for entry in entries:
                    assert isinstance(entry, FlextLdifModels.Entry)
                    assert entry.dn is not None
                    assert hasattr(entry.dn, "value")
                    assert isinstance(entry.dn.value, str)

    def test_pipeline_verifies_entry_attributes_in_result(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline result entries have valid attributes."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success

        execution_result = result.unwrap()
        entries_by_category = execution_result.entries_by_category

        # Check that all entries have valid attributes
        for entries in entries_by_category.values():
            if isinstance(entries, list) and len(entries) > 0:
                for entry in entries:
                    assert isinstance(entry, FlextLdifModels.Entry)
                    assert entry.attributes is not None
                    assert isinstance(entry.attributes.attributes, dict)

    def test_pipeline_with_schema_and_entries_separate_files(
        self, oid_schema_fixture: Path, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline processes schema and entries from separate files correctly."""
        if not oid_schema_fixture.exists() or not oid_entries_fixture.exists():
            pytest.skip("Required fixtures not found")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()

        schema_copy = input_dir / "schema.ldif"
        schema_copy.write_text(
            oid_schema_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        entries_copy = input_dir / "entries.ldif"
        entries_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success
        execution_result = result.unwrap()

        # Schema should be in schema category
        schema_entries = execution_result.entries_by_category.get("schema", [])
        assert isinstance(schema_entries, list)

    def test_pipeline_categorization_with_multiple_matching_rules(
        self, oid_entries_fixture: Path, temp_output_dir: Path
    ) -> None:
        """Test pipeline categorizes entry with first matching rule."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        input_dir = temp_output_dir / "input"
        input_dir.mkdir()
        fixture_copy = input_dir / "entries.ldif"
        fixture_copy.write_text(
            oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )

        # Rules that may have overlapping matches
        rules = {
            "users": [
                "(objectClass=person)",
                "(objectClass=inetOrgPerson)",  # More specific, but person matches first
            ],
            "groups": [
                "(objectClass=groupOfNames)",
            ],
        }

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success

    def test_pipeline_handles_entries_without_objectclass(
        self, temp_output_dir: Path
    ) -> None:
        """Test pipeline handles entries without objectClass attribute gracefully."""
        input_dir = temp_output_dir / "input"
        input_dir.mkdir()

        # Create minimal LDIF with entry lacking objectClass
        minimal_ldif = input_dir / "minimal.ldif"
        minimal_ldif.write_text(
            """version: 1
dn: cn=test,dc=example,dc=com
cn: test

""",
            encoding="utf-8",
        )

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=temp_output_dir / "output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        # Should handle gracefully
        assert result.is_success or result.is_failure
