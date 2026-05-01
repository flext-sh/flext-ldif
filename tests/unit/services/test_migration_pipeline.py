"""Tests for LDIF migration pipeline orchestration.

This module tests the migration pipeline that handles transforming LDIF
data between different LDAP server types, including initialization,
validation, and execution with various server type combinations.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from flext_tests import tm

from flext_ldif import FlextLdifMigrationPipeline, FlextLdifProcessingPipeline
from tests import c, m


class TestsTestFlextLdifMigrationPipeline:
    """Consolidated test suite for LDIF migration pipeline.

    Tests initialization, validation, execution with different server types.
    """

    def test_initialization_with_required_params(self, tmp_path: Path) -> None:
        """Test pipeline initializes with required parameters."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type=c.Tests.OID,
            target_server_type=c.Tests.OUD,
        )
        tm.that(pipeline, none=False)
        tm.that(pipeline.input_dir, eq=input_dir)
        tm.that(pipeline.output_dir, eq=output_dir)
        tm.that(pipeline.source_server_type, eq=c.Tests.OID)
        tm.that(pipeline.target_server_type, eq=c.Tests.OUD)

    def test_initialization_with_defaults(self, tmp_path: Path) -> None:
        """Test pipeline initialization with default server types."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
        )
        tm.that(pipeline, none=False)
        tm.that(pipeline.source_server_type, eq=c.Tests.RFC)
        tm.that(pipeline.target_server_type, eq=c.Tests.RFC)

    @pytest.mark.parametrize(
        ("source", "target"),
        [
            (c.Tests.OID, c.Tests.OUD),
            (c.Tests.OID, c.Tests.OPENLDAP),
            (c.Tests.OUD, c.Tests.OPENLDAP),
            (c.Tests.OPENLDAP, c.Tests.OID),
            (c.Tests.OPENLDAP, c.Tests.OUD),
            (c.Tests.RFC, c.Tests.RFC),
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
            source_server_type=source,
            target_server_type=target,
        )
        tm.that(pipeline, none=False)
        tm.that(pipeline.source_server_type, eq=source)
        tm.that(pipeline.target_server_type, eq=target)

    def test_execute_fails_with_no_input_dir(self) -> None:
        """Test pipeline fails when input directory is not specified."""
        pipeline = FlextLdifMigrationPipeline(
            source_server_type=c.Tests.OID,
            target_server_type=c.Tests.OUD,
        )
        result = pipeline.execute()
        tm.that(result.failure, eq=True)
        tm.that(str(result.error).lower(), has="input_dir")

    def test_execute_fails_with_no_output_dir(self, tmp_path: Path) -> None:
        """Test pipeline fails when output directory is not specified."""
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            source_server_type=c.Tests.OID,
            target_server_type=c.Tests.OUD,
        )
        result = pipeline.execute()
        tm.that(result.failure, eq=True)
        tm.that(str(result.error).lower(), has="output_dir")

    def test_execute_fails_with_nonexistent_input_dir(self, tmp_path: Path) -> None:
        """Test pipeline fails when input directory doesn't exist."""
        nonexistent_input = tmp_path / "nonexistent"
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        pipeline = FlextLdifMigrationPipeline(
            input_dir=nonexistent_input,
            output_dir=output_dir,
            source_server_type=c.Tests.OID,
            target_server_type=c.Tests.OUD,
        )
        result = pipeline.execute()
        tm.that(result.failure, eq=True)
        tm.that(str(result.error).lower(), has="not found")

    def test_execute_creates_output_dir_if_missing(self, tmp_path: Path) -> None:
        """Test pipeline creates output directory if it doesn't exist."""
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        nonexistent_output = tmp_path / "nonexistent"
        (input_dir / "test.ldif").write_text(
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n",
        )
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=nonexistent_output,
            source_server_type=c.Tests.RFC,
            target_server_type=c.Tests.RFC,
        )
        result = pipeline.execute()
        tm.that(result.success, eq=True)
        _ = tm.that(nonexistent_output.exists(), eq=True)

    def test_execute_with_empty_input(self, tmp_path: Path) -> None:
        """Test pipeline handles empty input directory gracefully."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        pipeline: FlextLdifMigrationPipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
        )
        result = pipeline.execute()
        tm.that(result.success, eq=True)
        migration_result: m.Ldif.MigrationPipelineResult = result.value
        tm.that(migration_result.stats.total_entries, eq=0)

    def test_basic_execution_rfc_to_rfc(self, tmp_path: Path) -> None:
        """Test basic migration from RFC to c.RFC."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        ldif_content = c.Tests.RFC_SAMPLE_LDIF_BASIC
        (input_dir / "test.ldif").write_text(ldif_content)
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type=c.Tests.RFC,
            target_server_type=c.Tests.RFC,
        )
        result = pipeline.execute()
        tm.that(result.success, eq=True)
        migration_result: m.Ldif.MigrationPipelineResult = result.value
        tm.that(migration_result.stats.processed_entries, gte=1)

    def test_migrate_entries_method(self, tmp_path: Path) -> None:
        """Test migrate_entries method directly."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type=c.Tests.RFC,
            target_server_type=c.Tests.RFC,
        )
        entries = [
            m.Ldif.Entry(
                dn=m.Ldif.DN(value=c.Tests.DN_TEST),
                attributes=m.Ldif.Attributes(
                    attributes={"cn": ["test"], "objectClass": ["person"]},
                    attribute_metadata={},
                ),
            ),
        ]
        result = pipeline.migrate_entries(entries)
        tm.that(result.success, eq=True)
        migrated = result.value
        tm.that(len(migrated), eq=1)

    def test_migrate_file_method(self, tmp_path: Path) -> None:
        """Test migrate_file method directly."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        ldif_content = c.Tests.CONFIG_BASIC_ENTRY
        input_file = input_dir / "test.ldif"
        input_file.write_text(ldif_content)
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type=c.Tests.RFC,
            target_server_type=c.Tests.RFC,
        )
        result = pipeline.migrate_file(input_file)
        tm.that(result.success, eq=True)
        migration_result = result.value
        tm.that(migration_result.stats.total_entries, gte=1)

    def test_execute_with_multiple_files(self, tmp_path: Path) -> None:
        """Test pipeline processes multiple input files."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        (input_dir / "schema.ldif").write_text(
            "dn: cn=schema\nobjectClass: top\ncn: schema\n",
        )
        (input_dir / "data.ldif").write_text(
            "dn: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com\nobjectClass: person\ncn: REDACTED_LDAP_BIND_PASSWORD\n",
        )
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type=c.Tests.RFC,
            target_server_type=c.Tests.RFC,
        )
        result = pipeline.execute()
        tm.that(result.success, eq=True)
        migration_result: m.Ldif.MigrationPipelineResult = result.value
        tm.that(migration_result.stats.total_entries, gte=2)

    def test_migrate_file_not_found(self, tmp_path: Path) -> None:
        """Test migrate_file handles non-existent file gracefully."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type=c.Tests.RFC,
            target_server_type=c.Tests.RFC,
        )
        nonexistent_file = input_dir / "nonexistent.ldif"
        result = pipeline.migrate_file(nonexistent_file)
        tm.that(result.failure, eq=True)
        tm.that(str(result.error).lower(), has="not found")

    def test_migrate_entries_empty_list(self, tmp_path: Path) -> None:
        """Test migrate_entries handles empty list gracefully."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type=c.Tests.RFC,
            target_server_type=c.Tests.RFC,
        )
        result = pipeline.migrate_entries([])
        tm.that(result.success, eq=True)
        migrated = result.value
        tm.that(not migrated, eq=True)

    @pytest.mark.parametrize(
        ("raw_server", "expected_server"),
        list(c.Tests.MIGRATION_COERCE_CASES.values()),
        ids=list(c.Tests.MIGRATION_COERCE_CASES.keys()),
    )
    def test_coerce_server_type_cases(
        self,
        raw_server: str,
        expected_server: str,
    ) -> None:
        """Lines 117-121: coercion keeps known values and falls back on unknown input."""
        result = FlextLdifMigrationPipeline._coerce_server_type(raw_server)
        if raw_server == c.Tests.MIGRATION_UNKNOWN_SERVER:
            tm.that(result, eq=FlextLdifMigrationPipeline._DEFAULT_SERVER)
            return
        tm.that(result, eq=c.Ldif.ServerTypes(expected_server))

    def test_execute_with_file_that_fails_parse(self, tmp_path: Path) -> None:
        """Line 185: migration file that fails logs warning and execute continues."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        (input_dir / "bad.ldif").write_bytes(c.Tests.WRITER_INVALID_UTF8_BYTES)
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type=c.Tests.RFC,
            target_server_type=c.Tests.RFC,
        )

        result = pipeline.execute()
        tm.that(result.success, eq=True)
        migration_result: m.Ldif.MigrationPipelineResult = result.value
        tm.that(migration_result.stats.total_entries, eq=0)

    def test_migrate_file_returns_fail_when_writer_fails(self, tmp_path: Path) -> None:
        """Line 281: migrate_file returns fail when writer reports failure."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        input_file = input_dir / c.Tests.MIGRATION_INPUT_FILENAME
        input_file.write_text(c.Tests.MIGRATION_SINGLE_ENTRY_LDIF)
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type=c.Tests.RFC,
            target_server_type=c.Tests.RFC,
        )

        output_as_directory = output_dir / "existing_dir"
        output_as_directory.mkdir()

        result = pipeline.migrate_file(input_file, output_file=output_as_directory)
        tm.that(result.failure, eq=True)
        tm.that(str(result.error), has="Write failed")

    def test_migrate_file_returns_fail_when_read_raises(self, tmp_path: Path) -> None:
        """Lines 292-304: migrate_file catches decoding/type errors from IO stage."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        input_file = input_dir / c.Tests.MIGRATION_INPUT_FILENAME
        input_file.write_bytes(c.Tests.WRITER_INVALID_UTF8_BYTES)
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type=c.Tests.RFC,
            target_server_type=c.Tests.RFC,
        )

        result = pipeline.migrate_file(input_file)
        tm.that(result.failure, eq=True)
        tm.that(str(result.error), has="File migration failed")

    def test_migrate_file_with_no_output_dir_or_file_fails(
        self, tmp_path: Path
    ) -> None:
        """Line 269: migrate_file with no output_dir and no output_file fails."""
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        ldif_content = c.Tests.RFC_SAMPLE_LDIF_BASIC
        input_file = input_dir / "test.ldif"
        input_file.write_text(ldif_content)
        # Pipeline with no output_dir and no output_file
        pipeline = FlextLdifMigrationPipeline(
            source_server_type=c.Tests.RFC,
            target_server_type=c.Tests.RFC,
        )
        result = pipeline.migrate_file(input_file, output_file=None)
        tm.that(result.failure, eq=True)


class TestsFlextLdifProcessingPipeline:
    """Tests for FlextLdifProcessingPipeline service."""

    def test_execute_without_entries_fails(self) -> None:
        """Line 93: execute with no entries and no entries_input fails."""
        pipeline = FlextLdifProcessingPipeline(transform_config=None)
        result = pipeline.execute(None)
        tm.that(result.failure, eq=True)
        tm.that("No entries provided" in (result.error or ""), eq=True)

    def test_execute_with_entries_succeeds(self) -> None:
        """Line 94-95: execute with entries returns success."""
        entry = m.Ldif.Entry(
            dn=c.Tests.ANALYSIS_DN_VALID,
            attributes=m.Ldif.Attributes(attributes={}),
        )
        pipeline = FlextLdifProcessingPipeline(transform_config=None)
        result = pipeline.execute([entry])
        tm.that(result.success, eq=True)

    def test_build_pipeline_with_normalize_dns_and_process_config(self) -> None:
        """Lines 102-115: normalize_dns=True with process_config triggers dn normalization."""
        transform_config = m.Ldif.TransformConfig(
            normalize_dns=True,
            process_config=m.Ldif.ProcessConfig(
                source_server=c.Tests.RFC,
                target_server=c.Tests.RFC,
            ),
        )
        pipeline = FlextLdifProcessingPipeline(transform_config=transform_config)
        result = pipeline.execute([])
        tm.that(result.success, eq=True)

    def test_build_pipeline_with_normalize_attrs_and_process_config(self) -> None:
        """Lines 124-128: normalize_attrs=True with process_config triggers attr normalization."""
        transform_config = m.Ldif.TransformConfig(
            normalize_attrs=True,
            process_config=m.Ldif.ProcessConfig(
                source_server=c.Tests.RFC,
                target_server=c.Tests.RFC,
            ),
        )
        pipeline = FlextLdifProcessingPipeline(transform_config=transform_config)
        result = pipeline.execute([])
        tm.that(result.success, eq=True)
