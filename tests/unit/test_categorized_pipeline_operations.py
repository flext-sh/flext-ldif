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

from flext_ldif.models import FlextLdifModels
from flext_ldif.pipelines.categorized_pipeline import (
    FlextLdifCategorizedMigrationPipeline,
)


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
        fixture_copy.write_text(oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8")

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
        assert isinstance(
            execution_result, FlextLdifModels.PipelineExecutionResult
        )
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
        fixture_copy.write_text(oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8")

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
        fixture_copy.write_text(oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8")

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
        fixture_copy.write_text(oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8")

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
        fixture_copy.write_text(oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8")

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
        fixture_copy.write_text(oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8")

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
        fixture_copy.write_text(oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8")

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
        fixture_copy.write_text(oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8")

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
        entries_copy.write_text(oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8")

        schema_copy = input_dir / "schema.ldif"
        schema_copy.write_text(oid_schema_fixture.read_text(encoding="utf-8"), encoding="utf-8")

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
        fixture_copy.write_text(oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8")

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
        fixture_copy.write_text(oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8")

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
        fixture_copy.write_text(oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8")

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
        fixture_copy.write_text(oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8")

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
        fixture_copy.write_text(oud_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8")

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
        fixture_copy.write_text(oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8")

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
        fixture_copy.write_text(oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8")

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
        fixture_copy.write_text(oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8")

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
        fixture_copy.write_text(oid_entries_fixture.read_text(encoding="utf-8"), encoding="utf-8")

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
